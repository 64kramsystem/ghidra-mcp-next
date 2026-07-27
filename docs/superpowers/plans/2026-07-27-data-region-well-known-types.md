# Data-Region Well-Known Types Implementation Plan

> **For Codex:** Implement task by task with
> `superpowers:test-driven-development`; invoke
> `superpowers:systematic-debugging` for any unexpected failure.

**Goal:** Make `apply_data_regions` resolve fixed built-in datatypes correctly
in pristine programs, including split pointer tables on 6502/C64 and
architecture-dependent types on non-default data organizations.

**Architecture:** Preserve program-first lookup for caller-supplied
contiguous-region types, then fall back to the shared well-known map and clone
the result into the target program datatype manager before planning. Preflight
the target-bound candidate's canonical path so Ghidra cannot replace a
non-equivalent program datatype during built-in resolution. Give split-pointer
source halves their contractually fixed built-in byte through the same
preflight.

**Tech stack:** Java 21, Ghidra 12.1.2 APIs, JUnit 4, Maven.

---

## Task 1: Reproduce and repair pristine split-pointer byte resolution

**Files:**

- Modify: `src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java`
- Modify: `src/main/java/com/xebyte/core/DataRegionCore.java`

### Step 1: Add a pristine 6502 split-table regression

Create a test-owned `ProgramBuilder` for `6502:LE:16:default`, map sufficient
RAM, and do not register any datatypes. Dispose it in `finally`.

Assert that neither exact/root lookup nor name search finds `byte`. Seed two
low bytes and two high bytes that decode to valid mapped targets. Build a
two-entry `split_low_high` request with target validation and reference
creation.

Preview first. Assert:

- the request succeeds;
- `/byte` is still absent after preview.

Commit and assert:

- both source halves are committed two-element arrays;
- each array element length is one;
- the expected target references exist.

Preview again, compare the non-action plan fields with the first preview
through a dedicated stable-fields helper, and require both data actions to
be `unchanged`. Do not compare `created_data` wholesale: before commit its
actions are `create`, while after commit they must be `unchanged`.

### Step 2: Run the focused test and prove the existing failure

Run:

```bash
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
  -Dtest=DataRegionServiceGhidraTest#pristineSplitTableUsesBuiltinByte
```

Expected: fail with `datatype not found: byte`.

### Step 3: Bind the internal split byte directly

In `planSplit`, replace `resolveFixedType(program, "byte")` and the one-byte
guard with:

```java
DataType byteType = ByteDataType.dataType.clone(
    program.getDataTypeManager());
```

Import `ByteDataType`. Do not add the clone to the program datatype manager.

### Step 4: Re-run the focused regression

Run the Step 2 command.

Expected: pass, including post-commit repeat-preview idempotency.

### Step 5: Commit

```bash
git add src/main/java/com/xebyte/core/DataRegionCore.java \
  src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java
git commit -m "Fix split data regions in pristine programs"
```

## Task 2: Add program-bound fallback for caller-supplied built-ins

**Files:**

- Modify: `src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java`
- Modify: `src/main/java/com/xebyte/core/DataRegionCore.java`

### Step 1: Add a pristine 6502 contiguous-word regression

Use a separate test-owned pristine 6502 program. Assert `word` is absent by
exact/root lookup and name search.

Preview a contiguous region whose `type_name` is `word`. Assert preview
succeeds and `/word` remains absent. Commit, verify two-byte data in the
listing, then repeat-preview and require stable plan fields plus an
`unchanged` action.

### Step 2: Add an x86-16 data-organization regression

Use a separate `x86:LE:16:Real Mode` program with compiler spec `default`.
Assert `/int` is absent. Preview and commit a contiguous `int` region without
trailing bytes.

Assert:

- planned `data_length` is two;
- default stride is two;
- committed `Data.getLength()` is two.

Do not assert normalized segmented address strings.

### Step 3: Run the two tests and prove both fail

Run:

```bash
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
  -Dtest='DataRegionServiceGhidraTest#pristineContiguousWordUsesWellKnownFallback+wellKnownIntUsesTargetDataOrganization'
```

Expected: both fail with `datatype not found`.

### Step 4: Add target-bound well-known fallback

At the end of `resolveFixedType`'s existing program datatype-manager search,
when no program type was found:

```java
DataType wellKnown = ServiceUtils.resolveWellKnownType(name);
if (wellKnown != null) {
    type = wellKnown.clone(program.getDataTypeManager());
}
```

Keep `requireFixedPlaceable(type, name)` as the final gate. Do not reorder
program-defined lookup and do not call `DataTypeManager.addDataType`.

### Step 5: Re-run the focused regressions

Run the Step 3 command.

Expected: both pass; x86-16 proves planning uses the target program's
two-byte integer size.

### Step 6: Commit

```bash
git add src/main/java/com/xebyte/core/DataRegionCore.java \
  src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java
git commit -m "Resolve data-region builtins for target programs"
```

## Task 3: Pin precedence, shadowing, and negative behavior

**Files:**

- Modify: `src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java`
- Modify: `src/main/java/com/xebyte/core/DataRegionCore.java`

### Step 1: Add canonical-path collision coverage

In a disposable 6502 program, register a program-local datatype named `byte`
with a concrete two-byte length.

Assert:

- a caller-supplied contiguous `type_name="byte"` plans and commits at length
  two and the listing datatype path remains `/byte`;
- split-table preview rejects with `well-known datatype path conflicts` before
  mutation;
- mixed-case contiguous `type_name="BYTE"` preview rejects for the same
  canonical-path collision;
- aliased contiguous `type_name="uint8"` preview rejects because its
  target-bound canonical path is also `/byte`;
- commit attempts for all rejected requests also leave destinations
  undefined and preserve the original two-byte `/byte`;
- datatype-manager count remains unchanged across every rejected preview and
  commit;
- contiguous errors identify `type_name`, `canonical_path`, and
  `occupant_length`;
- the split error identifies `requested=byte`,
  `usage=split_pointer_source`, the canonical path and occupant length, and
  tells the caller to rename or remove the conflicting program datatype.

Add a separate program with a one-byte typedef at `/byte`. Pin the previous
compatibility behavior: split preview and commit succeed, both source arrays
use that exact program-owned typedef as their one-byte element, and repeat
preview is unchanged. In that program, a contiguous `type_name="uint8"`
request remains strict but its error points to
`type_name=byte` as the safe existing-type alternative. Compare the typedef's
universal ID across commit instead of relying on datatype DB object identity.

Add a second one-byte typedef around `undefined1`. It is not placeable, so
split preview must return the canonical collision error, must not suggest the
existing-type alternative, and must leave both source halves undefined.

Run the focused test before implementation. Expected: fail because split
preview currently succeeds. Do not let the red test reach the destructive
commit path.

### Step 2: Add collision-safe well-known cloning

Add a private helper in `DataRegionCore` that:

1. resolves a name through `ServiceUtils.resolveWellKnownType`;
2. clones a match into the target program datatype manager;
3. looks up the target-bound candidate's canonical `getPathName()`;
4. returns the existing occupant when either direction of
   `isEquivalent` reports structural equivalence;
5. for split-source usage only, returns a non-equivalent existing occupant
   when its length is exactly one and `requireFixedPlaceable` accepts it;
6. throws `well-known datatype path conflicts` for every other
   non-equivalent occupant;
7. otherwise returns the mutation-free clone.

Implement the placeability probe with a small `try`/`catch` around
`requireFixedPlaceable`. A one-byte non-placeable occupant follows step 6 and
returns the collision error, not the internal validation exception. When a
contiguous collision occupant is fixed, placeable, and the same width as the
candidate, append
`request the existing program datatype with type_name=<occupant name>` to the
remediation; do not offer that alternative for a width mismatch or a
non-placeable occupant. Verify the non-placeable branch with a contiguous
`type_name="uint8"` request against the `undefined1` typedef, because split
errors never offer `type_name` remediation regardless of placeability.

Use the helper from both the fallback branch of `resolveFixedType` and
`planSplit`. Give it enough context to render `type_name=<name>` for
contiguous requests and `requested=byte, usage=split_pointer_source` for the
internal split call. `planSplit` must call it directly with the literal
`"byte"`, wrap the result in `Objects.requireNonNull`, and must not route
through `resolveFixedType`. Do not call
`DataTypeManager.resolve` or `DataTypeManager.addDataType` during preview.

Format collision errors as:

```text
well-known datatype path conflicts: type_name=uint8, canonical_path=/byte, occupant_length=2
```

Append `rename or remove the program datatype at /byte`. The split form
replaces `type_name=...` with
`requested=byte, usage=split_pointer_source`.

Ghidra 12.1.2 fixture evidence for the current commit path is
`[/byte=1, /byte[2]=2]`: the original two-byte `/byte` disappears and no
conflict-renamed copy survives. The local source at `~/code/ghidra` shows the
path from `CodeManager.createCodeUnit` through
`DataTypeManagerDB.getResolvedID` to `resolveBuiltIn`; the latter handles the
canonical built-in name before its generic conflict handler, so an explicit
`DEFAULT_HANDLER` is not a fix.

### Step 3: Add compatibility-negative coverage

Cover:

- an unknown name still reports `datatype not found`;
- `void` reports `fixed and placeable`;
- a collision-free mixed-case well-known fallback such as `WoRd` succeeds
  with `data_length == 2`;
- program-defined `/a/word` and `/b/word`, with no root `/word`, still report
  `ambiguous datatype name`.

### Step 4: Run the focused tests

Run:

```bash
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
  -Dtest=DataRegionServiceGhidraTest
```

Expected: all pass. The collision tests must prove that both dry-run and
commit requests preserve the original two-byte `/byte`.

### Step 5: Commit

```bash
git add src/main/java/com/xebyte/core/DataRegionCore.java \
  src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java \
  docs/superpowers/specs/2026-07-27-data-region-well-known-types-design.md \
  docs/superpowers/plans/2026-07-27-data-region-well-known-types.md
git commit -m "Cover data-region builtin compatibility"
```

## Task 4: Document the repair

**Files:**

- Modify: `CHANGELOG.md`

### Step 1: Add an Unreleased/Fixed entry

Document that `apply_data_regions` now:

- works with well-known fixed datatypes absent from a pristine program's
  datatype manager;
- binds architecture-sensitive types to the target data organization;
- uses an internal one-byte built-in for split pointer source halves;
- reuses compatible fixed one-byte program occupants for split sources;
- rejects canonical built-in path collisions before Ghidra can replace a
  non-equivalent program datatype.

### Step 2: Verify and commit

Run:

```bash
git diff --check
```

Then:

```bash
git add CHANGELOG.md
git commit -m "Document data-region builtin resolution"
```

## Task 5: Run full gates and Claude implementation review

### Step 1: Run every repository gate

```bash
mvn clean compile -q
mvn test
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC
uv run pytest tests/unit/ -v --no-cov
mvn clean package assembly:single -DskipTests
git diff --check
```

Confirm the known `ControlFlowServiceGhidraTest` jump-table flake against the
clean baseline if it appears.

### Step 2: Confirm contract scope

Verify no `@McpTool`/`@Param` registration changed and
`tests/endpoints.json` is untouched. Endpoint catalog regeneration is not
required.

### Step 3: Request Claude implementation review

Resume the GhidraMCP-next Claude session and review correctness, test coverage,
program data-organization behavior, and compatibility against the committed
design. Exclude deployment mechanics. Resolve concrete findings test-first
and repeat all relevant gates.

### Step 4: Deploy and verify the original failure

Build and deploy through the repository's existing setup command, restart
Ghidra if required to load the new extension, reopen the Alter Ego project,
and re-run the original `apply_data_regions` split-pointer request.

Expected: both 256-byte table halves are typed, 256 decoded targets are
validated, references and labels are created, and repeat application is
idempotent.
