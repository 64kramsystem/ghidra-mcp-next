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

Before returning the clone, inspect the canonical path of that target-bound
candidate in the program datatype manager. If the path is occupied:

- reuse the existing datatype when it is structurally equivalent to the
  candidate in either direction (`existing.isEquivalent(candidate)` or
  `candidate.isEquivalent(existing)`);
- reject the request during planning when it is non-equivalent, with
  an actionable contiguous-region error of the form
  `well-known datatype path conflicts: type_name=uint8, canonical_path=/byte,
  occupant_length=2; rename or remove the program datatype at /byte`.
  When the occupant is fixed, placeable, and the same width as the candidate,
  append `or request the existing program datatype with type_name=byte`;
  otherwise do not suggest the semantically different existing type.

This preflight is necessary even though fallback happens after program-name
lookup. The well-known map is case-insensitive while program lookup remains
case-sensitive, so `type_name="BYTE"` can reach the fallback in a program
that owns a non-equivalent lowercase `/byte`. It is also an alias map:
`uint8`, `uint8_t`, and other names can resolve to a different canonical path
such as `/byte`. Any requested well-known name whose target-bound canonical
path is occupied by a non-equivalent datatype is a collision route.

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
two halves are byte cells by contract. Call the well-known collision helper
directly with the literal `"byte"` to obtain a target-bound built-in
`ByteDataType`. Do not call `resolveFixedType`, because that would restore
program-defined name precedence to this internal representation.
Wrap this fixed-name result in `Objects.requireNonNull` so the internal
contract remains explicit if the shared well-known map ever changes.

The split call supplies an internal-use discriminator so its error reads
`requested=byte, usage=split_pointer_source` rather than `type_name=byte`.
`type_name` is not part of the split request schema and must not be suggested
as a remediation. The error identifies the canonical path and tells the user
to rename or remove the conflicting program datatype.

Do not route the hard-coded internal `byte` requirement through
program-defined name lookup. A program-local wider or ambiguous datatype named
`byte` must not silently change the split-pointer representation. If `/byte`
is non-equivalent to the required built-in but is itself fixed, placeable, and
exactly one byte wide, reuse that program-owned occupant for split source
cells. This preserves the endpoint's pre-repair support for legitimate
one-byte typedefs and other byte-cell representations without resolving the
built-in or mutating the datatype manager. Wider, undefined, dynamic, factory,
bit-field, or otherwise non-placeable occupants still reject before any
listing or datatype-manager mutation.

These reuse and rejection rules are deliberately conservative. The local
Ghidra source at `~/code/ghidra` confirms that `CodeManager.createCodeUnit`
clones the datatype, then `DataTypeManagerDB.getResolvedID` calls `resolve`;
`resolveBuiltIn` gives canonical paths to built-ins independently of the
caller's generic conflict handler by renaming the existing occupant before
creating the built-in. A live fixture using that current implicit
`Listing.createData` path left only `/byte=1` and `/byte[2]=2`; the original
two-byte `/byte` disappeared and no conflict-renamed copy remained. Calling
`DataTypeManager.resolve(..., DEFAULT_HANDLER)` explicitly therefore does not
make this safe. Collision preflight introduces only two behaviors: reuse of a
safe existing datatype and rejection before mutation. Conflict renaming,
datatype restoration, and a new internal datatype family are outside scope.

## Compatibility details

- Well-known fallback names are case-insensitive because
  `resolveWellKnownType` lowercases its input. Thus `BYTE` and `Word` become
  accepted when no exact program-defined datatype of those names or
  non-equivalent datatype at the canonical built-in path exists.
- A rejected well-known but non-placeable name such as `void` changes from
  `datatype not found` to the more precise `datatype must be fixed and
  placeable` error.
- Unknown names still report `datatype not found`.
- Exact and uniquely resolved program-defined names retain current precedence,
  ambiguity behavior, and case sensitivity.
- Split-pointer source halves use Ghidra's one-byte built-in unless `/byte`
  is occupied by a fixed, placeable, one-byte program datatype, which is
  reused instead. Wider or non-placeable occupants produce an explicit
  canonical-path collision error, and a program definition is never
  replaced.
- Collision preflight applies only to target-bound well-known candidates.
  Exact and uniquely found program-owned datatypes never enter that path.
  In the normal fallback case the canonical path is absent. Collision routes
  include case variants such as `BYTE` meeting `/byte` and textual aliases
  such as `uint8` resolving to an occupied `/byte`. Preview remains
  mutation-free.

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

2. In another disposable 6502 program, register a realistic program-local
   datatype named `byte` whose length is two bytes.

   - A contiguous region with `type_name="byte"` must plan and commit using
     the program-local two-byte datatype and preserve the `/byte` path,
     proving caller-supplied precedence.
   - Preview and commit a split pointer table. Both must reject with
     `well-known datatype path conflicts`; neither may define source data or
     alter the original `/byte`.
   - Preview and commit a contiguous `type_name="BYTE"` request. Both must
     reject for the same canonical-path collision, leave the destination
     undefined, and preserve the original `/byte`. This covers the
     case-insensitive fallback route.
   - Repeat with `type_name="uint8"` to cover an alias whose requested text
     differs from the canonical `/byte` path.
   - Capture the program datatype count before rejected requests and require
     it to remain unchanged after every preview and commit rejection.
   - Require contiguous collision errors to identify `type_name`,
     `canonical_path`, and `occupant_length`. Require the split error to
     identify `requested=byte`, `usage=split_pointer_source`, the same path
     and length, and the rename/remove remediation.

3. In a separate disposable 6502 program, install a one-byte typedef at
   `/byte` whose base type has a different canonical name.

   - Split preview and commit must succeed by reusing that exact
     program-owned typedef as both array element types.
   - The typedef at `/byte` must retain its identity and one-byte length.
   - Repeat preview must report both data actions unchanged.
   - A contiguous `type_name="uint8"` request remains strict and rejects the
     non-equivalent typedef, but its error must identify
     `type_name=byte` as the safe way to request the existing compatible
     program datatype.

4. In another disposable 6502 program, install a one-byte `/byte` typedef
   around `undefined1`. Split preview must reject with the canonical collision
   error, identify `occupant_length=1`, and define neither source half. A
   contiguous `type_name="uint8"` preview must also reject with the canonical
   collision error and omit the existing-type alternative because the
   occupant is not placeable. Both paths must preserve the typedef identity
   and datatype-manager count.

5. Create a pristine `x86:LE:16:Real Mode` program whose compiler
   specification uses a two-byte integer. Assert `/int` is absent before the
   sub-case, then preview and commit a contiguous `int` region. The planned
   `data_length`, committed `Data.getLength()`, and default stride must all be
   two, proving the fallback was cloned into the target program's data
   organization before planning. Avoid assertions on normalized address
   strings because this language uses segmented addresses.

6. Confirm an unknown datatype still reports `datatype not found`, `void`
   reports `fixed and placeable`, a collision-free mixed-case well-known name
   succeeds with the expected width, and program-defined `/a/word` and
   `/b/word` definitions with no root `/word` still report
   `ambiguous datatype name` before well-known fallback.

The built-in placeability checks remain in the initialized Ghidra fixture
suite. Do not load static built-in datatype singletons from
`DataRegionCoreTest`: without Ghidra application initialization that triggers
`UniversalIdGenerator` diagnostics and creates noisy pseudo-coverage.
Every regression for this repair is therefore gated by
`ghidra.test.install.dir`; the default `mvn test` and current CI workflow skip
them. The required local Ghidra fixture gate below is authoritative.

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
