# Data-Region Well-Known Types Implementation Plan

> **For Codex:** Implement task by task with
> `superpowers:test-driven-development`; invoke
> `superpowers:systematic-debugging` for any unexpected failure.

**Goal:** Make `apply_data_regions` resolve fixed built-in datatypes correctly
in pristine programs, including split pointer tables on 6502/C64 and
architecture-dependent types on non-default data organizations.

**Architecture:** Preserve program-first lookup for caller-supplied
contiguous-region types, then fall back to the shared well-known map and clone
the result into the target program datatype manager before planning. Give
split-pointer source halves their contractually fixed built-in byte directly,
independent of program-local name shadowing.

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

Preview again, compare stable plan fields with the first preview through the
existing `assertPlanFieldsEqual` helper, and require both data actions to be
`unchanged`.

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
- Modify: `src/test/java/com/xebyte/core/DataRegionCoreTest.java`

### Step 1: Add program-local shadowing coverage

In a disposable 6502 program, register a program-local datatype named `byte`
with a two-byte length.

Assert:

- a caller-supplied contiguous `type_name="byte"` plans and commits at length
  two;
- a split table in the same program still commits one-byte source elements;
- the committed split datatype path is pinned to the path observed from
  Ghidra's conflict resolution;
- repeat preview has stable plan fields and unchanged actions.

### Step 2: Add compatibility-negative coverage

Cover:

- an unknown name still reports `datatype not found`;
- `void` reports `fixed and placeable`;
- a mixed-case well-known fallback such as `WoRd` succeeds;
- program-defined `/a/word` and `/b/word`, with no root `/word`, still report
  `ambiguous datatype name`.

### Step 3: Add always-on placeability coverage

In `DataRegionCoreTest`, assert:

```java
assertSame(
    ByteDataType.dataType,
    DataRegionCore.requireFixedPlaceable(
        ByteDataType.dataType, "byte"));
assertThrows(
    IllegalArgumentException.class,
    () -> DataRegionCore.requireFixedPlaceable(
        VoidDataType.dataType, "void"));
```

### Step 4: Run the focused tests

Run:

```bash
mvn test \
  -Dghidra.test.install.dir=/Users/saverio/local/ghidra_12.1.2_PUBLIC \
  -Dtest=DataRegionServiceGhidraTest
mvn test -Dtest=DataRegionCoreTest
```

Expected: all pass. If Ghidra conflict-renames the shadowed built-in, use the
observed committed path as the exact regression expectation and keep the
response/listing name difference documented.

### Step 5: Commit

```bash
git add src/test/java/com/xebyte/core/DataRegionServiceGhidraTest.java \
  src/test/java/com/xebyte/core/DataRegionCoreTest.java
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
- uses an internal one-byte built-in for split pointer source halves.

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

