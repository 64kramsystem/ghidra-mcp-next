# Data Regions: Well-Known Datatype Fallback — Design

## Problem

`apply_data_regions` resolves `type_name` only through the target program's
`DataTypeManager`. Split pointer tables also call that resolver internally for
the literal type name `byte`.

A pristine `6502:LE:16:default` program does not necessarily register
Ghidra's `ByteDataType` in its program datatype manager. Consequently, a valid
split-pointer request fails before planning:

```text
Failed to apply data regions: datatype not found: byte
```

The existing Ghidra fixture tests do not expose this because their shared
setup constructs and installs a structure containing `ByteDataType`, which
incidentally registers `byte` before every split-pointer test runs.

Other GhidraMCP-next datatype consumers already expose
`ServiceUtils.resolveWellKnownType`, which maps stable names such as `byte`,
`word`, `uint8`, and `uint16` to Ghidra built-in datatype instances without
requiring prior registration in the program.

## Goal

Make fixed data regions and split pointer tables work in a pristine program
when they use a supported well-known fixed datatype, while preserving
program-defined datatype precedence for caller-supplied `type_name` values,
target-program data-organization semantics, and all existing placeability
checks.

## Non-goals

- Do not change the `apply_data_regions` endpoint schema or response shape.
- Do not add a caller-selectable datatype to split pointer tables; their
  source halves remain byte arrays.
- Do not auto-install built-ins into the program datatype manager.
- Do not broaden accepted dynamic, factory, undefined, bit-field, pointer, or
  zero-length types.
- Do not change ambiguity handling for program-defined datatype names.
- Do not consolidate the separate legacy well-known-type map in
  `GhidraMCPPlugin`; that duplication is unrelated to data-region correctness.

## Selected design

### Caller-supplied contiguous-region types

Keep `DataRegionCore.resolveFixedType`'s existing program lookup order:

1. exact program datatype-manager lookup;
2. root-category lookup;
3. unique program datatype-manager name search.

Only when those searches find no program datatype, call
`ServiceUtils.resolveWellKnownType(name)`. Clone a well-known fallback into
the target program's `DataTypeManager` before inspecting its length:

```java
wellKnown.clone(program.getDataTypeManager())
```

`DataType.clone(manager)` binds the instance to the target data organization
without adding a named definition to that manager. This is required because
architecture-sensitive built-ins such as `int`, `long`, and `char` can have
different sizes under the built-in manager and the target compiler
specification. Planning and `Listing.createData` must use the same effective
width.

Pass either the program-defined result or the bound fallback through the
existing `requireFixedPlaceable` validation.

This ordering is deliberate. A program-local datatype named `byte` retains
the meaning already established by that program when the caller explicitly
requests `type_name="byte"`. The well-known map is a fallback for absent
definitions, not an override.

This precedence intentionally differs from the older
`ServiceUtils.resolveDataType`, which checks well-known aliases before
program-defined types for sibling endpoints. Changing those endpoints is
outside this focused repair.

### Split pointer source bytes

Split pointer tables do not accept a caller-supplied source datatype. Their
two halves are byte cells by contract. Resolve
`ByteDataType.dataType.clone(program.getDataTypeManager())` directly in
`planSplit`.

Do not route the hard-coded internal `byte` requirement through
program-defined name lookup. A program-local wider or ambiguous datatype named
`byte` must not change or break the split-pointer representation. The existing
one-byte length assertion becomes unnecessary once the concrete built-in is
used.

If the program already defines a non-equivalent datatype at `/byte`, Ghidra
may conflict-rename the built-in element type when `Listing.createData`
resolves the split array into the program datatype manager. The committed
listing's actual datatype path is authoritative and may therefore be
`/byte.conflict[...]` even though the plan describes the requested built-in as
`/byte[...]`. The response renders the planned `/byte[...]` path while the
listing may hold `/byte.conflict[...]`; accepting that response/listing name
difference avoids mutating the program datatype manager during preview.
Structural equivalence and repeat-preview idempotency are required.

## Compatibility details

- Well-known fallback names are case-insensitive because
  `resolveWellKnownType` lowercases its input. Thus `BYTE` and `Word` become
  accepted when no exact program-defined datatype of those names exists.
- A rejected well-known but non-placeable name such as `void` changes from
  `datatype not found` to the more precise `datatype must be fixed and
  placeable` error.
- Unknown names still report `datatype not found`.
- Exact and uniquely resolved program-defined names retain current precedence,
  ambiguity behavior, and case sensitivity.
- Split-pointer source halves now always use Ghidra's one-byte built-in,
  independent of a program-defined datatype named `byte`. The former
  `program byte datatype is not one byte` failure is removed. When a
  non-equivalent `/byte` already exists, Ghidra may conflict-rename the
  committed built-in datatype as described above.

## Tests

### Ghidra fixture coverage

Add regressions to `DataRegionServiceGhidraTest`. Every additional
`ProgramBuilder` must be disposed in the test's `finally` block because the
class teardown owns only the shared fixture builder.

1. Use separate pristine `6502:LE:16:default` programs for the split and
   contiguous sub-cases. Map memory, and do not add a structure or built-in
   datatype to either manager. Immediately before each sub-case, assert that
   direct program datatype-manager lookup and name search cannot find the
   relevant `byte` or `word`, so future fixture changes cannot silently
   invalidate the regression.

   - Preview a two-entry `split_low_high` table with reference creation and
     target validation.
   - Assert that `/byte` is still absent after preview,
     proving fallback cloning does not install a datatype during dry run.
   - Commit the request.
   - Verify against the committed listing that both source halves are
     two-element arrays whose element datatype is one byte, and verify the
     expected references.
   - Preview the same request again. Compare stable plan fields with the first
     preview and require both data actions to be `unchanged`.
   - Preview a contiguous `word` region, proving caller-supplied well-known
     fallback works independently of the internal split-byte path.
   - Assert that `/word` is still absent after preview, then commit. Repeat
     the preview after commit, compare stable plan fields, and require an
     unchanged data action.

2. In another disposable 6502 program, register a program-local datatype named
   `byte` whose length is two bytes.

   - A contiguous region with `type_name="byte"` must plan and commit using
     the program-local two-byte datatype, proving caller-supplied precedence.
   - A split pointer table in the same program must still plan and commit with
     one-byte built-in arrays, proving internal representation is independent
     of program name shadowing. Assert the committed array element length and
     pin its observed actual datatype path (`/byte` or the conflict-renamed
     path) in the regression rather than assuming it remains `/byte`.
   - Repeat-preview the split request, compare stable plan fields, and require
     unchanged actions. This pins structural equivalence even if Ghidra
     conflict-renamed the committed built-in.

3. Create a pristine `x86:LE:16:Real Mode` program whose compiler
   specification uses a two-byte integer. Assert `/int` is absent before the
   sub-case, then preview and commit a contiguous `int` region. The planned
   `data_length`, committed `Data.getLength()`, and default stride must all be
   two, proving the fallback was cloned into the target program's data
   organization before planning. Avoid assertions on normalized address
   strings because this language uses segmented addresses.

4. Confirm an unknown datatype still reports `datatype not found`, `void`
   reports `fixed and placeable`, a mixed-case well-known name succeeds, and
   program-defined `/a/word` and `/b/word` definitions with no root `/word`
   still report `ambiguous datatype name` before well-known fallback.

### Always-on unit coverage

Add focused `DataRegionCoreTest` assertions that
`requireFixedPlaceable` accepts the fixed `ByteDataType` and rejects
`VoidDataType`. These do not replace the program-bound fixture regressions,
but keep the placeability boundary exercised in the default Maven test run.

Before the implementation change, the focused Ghidra fixture test must fail
with `datatype not found: byte`. After the fallback is added, run:

```bash
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
  -Dtest=DataRegionServiceGhidraTest
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC
mvn clean compile -q
mvn test
uv run pytest tests/unit/ -v --no-cov
mvn clean package assembly:single -DskipTests
git diff --check
```

No endpoint catalog regeneration is required because the public contract does
not change.

## Documentation

Record under `CHANGELOG.md` Unreleased/Fixed that `apply_data_regions` now
resolves supported well-known fixed datatypes even when a pristine program
has not registered them, specifically restoring split pointer tables on
6502/C64 programs.
