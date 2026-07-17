# Warning-Free Java Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate all Java compiler and Maven test-runtime warnings, migrate to supported Ghidra 12.1 APIs, and enforce a zero-warning build.

**Architecture:** Preserve existing services and endpoint schemas while migrating warning-producing call sites in risk order. Resource-sensitive program imports use explicit `LoadResults` ownership, and both emulation endpoints share a bounded `PcodeEmulator` session abstraction. Maven enables `-Xlint:all -Werror` only after source and tests are clean.

**Tech Stack:** Java 21, Ghidra 12.1.2 APIs, Maven Compiler Plugin 3.15.0, Maven Surefire 3.5.6, Gson 2.14.0, Mockito 5.23.0, JUnit 4, Python 3.13, pytest, uv.

## Global Constraints

- Target Ghidra 12.1.x only; Ghidra 12.0 and older are unsupported.
- Preserve every MCP endpoint path, HTTP method, parameter/default, and response field.
- Eliminate all 96 current main-source `-Xlint:all` warnings and keep test-source warnings at zero.
- Do not use blanket warning suppressions or rewrite unrelated JSON responses.
- Close every `LoadResults` and make every retained `Program` consumer explicit.
- Keep emulation finite: return, fault, or a maximum of 100,000 steps.
- Run `uv run pytest tests/unit/ -v --no-cov` and the Maven build before completion.

---

### Task 1: Add migration regression contracts

**Files:**
- Create: `src/test/java/com/xebyte/offline/Ghidra121ApiMigrationTest.java`
- Modify: `tests/unit/test_build_surface.py`

**Interfaces:**
- Consumes: maintained sources below `src/main/java` and Maven configuration in `pom.xml`.
- Produces: source-level guards for removed Ghidra/project APIs and build-level guards for strict lint and the Mockito agent.

- [ ] **Step 1: Add a failing source migration test**

Create `Ghidra121ApiMigrationTest` using the same `Files.walk` pattern as
`ArchitectureBoundaryTest`. Add separate tests asserting maintained Java source
does not contain these tokens:

```java
List.of(
    "CodeUnit.PRE_COMMENT",
    "CodeUnit.EOL_COMMENT",
    "CodeUnit.PLATE_COMMENT",
    "AutoImporter",
    "getPrimaryDomainObject()",
    "EmulatorHelper",
    "ServiceUtils.escapeJson",
    "ServiceUtils.serializeListToJson",
    "ServiceUtils.serializeMapToJson"
)
```

Allow the `Ghidra121ApiMigrationTest.java` file itself to contain the token list
by scanning only `src/main/java`.

- [ ] **Step 2: Add failing Maven ratchet assertions**

Extend `test_build_surface.py` with:

```python
def test_maven_enforces_warning_free_java_build():
    pom = (ROOT / "pom.xml").read_text(encoding="utf-8")
    assert "<showWarnings>true</showWarnings>" in pom
    assert "<arg>-Xlint:all</arg>" in pom
    assert "<arg>-Werror</arg>" in pom


def test_mockito_is_loaded_as_a_test_agent():
    pom = (ROOT / "pom.xml").read_text(encoding="utf-8")
    assert "-javaagent:" in pom
    assert "mockito-core" in pom
```

- [ ] **Step 3: Verify the new tests fail for the expected reasons**

Run:

```bash
mvn -q -Dtest=Ghidra121ApiMigrationTest test
uv run pytest tests/unit/test_build_surface.py -v --no-cov
```

Expected: Java failures list the legacy source tokens; Python failures report
the absent strict compiler and Mockito-agent configuration.

- [ ] **Step 4: Record the executable compiler red state**

Run the direct JDK compile with `-Xlint:all -Werror` and the Maven dependency
classpath. Expected: non-zero exit caused by warnings, with 96 diagnostics when
rerun without `-Werror`.

- [ ] **Step 5: Commit the red tests**

```bash
git add src/test/java/com/xebyte/offline/Ghidra121ApiMigrationTest.java tests/unit/test_build_surface.py
git commit -m "test: guard Ghidra 12.1 warning migrations"
```

### Task 2: Migrate comments, datatypes, scripts, and ordinary Java lint

**Files:**
- Modify: `src/main/java/com/xebyte/core/CommentService.java`
- Modify: `src/main/java/com/xebyte/core/FunctionService.java`
- Modify: `src/main/java/com/xebyte/core/DataTypeService.java`
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java`
- Modify: `src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java`
- Modify: `src/main/java/com/xebyte/core/ProgramScriptService.java`
- Modify: `src/main/java/com/xebyte/GhidraMCPPlugin.java`
- Modify: `src/main/java/com/xebyte/core/BinaryComparisonService.java`
- Modify: `src/main/java/com/xebyte/headless/HeadlessProgramProvider.java`

**Interfaces:**
- Consumes: Ghidra 12.1 `CommentType`, `DataTypeManager.remove(DataType)`, and `ScriptControls`.
- Produces: behavior-equivalent comment/script/datatype operations and warning-free ordinary Java constructs.

- [ ] **Step 1: Run focused comment and schema tests before edits**

```bash
mvn -q -Dtest=CommentServiceValidationTest,GuiTransportSchemaParityTest,EndpointsJsonParityTest test
```

Expected: PASS, establishing the behavioral baseline.

- [ ] **Step 2: Replace integer comment types**

Change `CommentService.setCommentAtAddress` to accept `CommentType`. Replace
`CodeUnit.PRE_COMMENT`, `EOL_COMMENT`, and `PLATE_COMMENT` with
`CommentType.PRE`, `EOL`, and `PLATE`. Use the `Listing` overloads that accept
`CommentType` in all five affected source files.

- [ ] **Step 3: Replace drop-in Ghidra APIs**

Use `dtm.remove(dataType)` at the three datatype deletion sites. Construct:

```java
new ScriptControls(scriptPrintWriter, scriptPrintWriter, scriptMonitor)
```

and pass it to `script.set(scriptState, controls)`.

- [ ] **Step 4: Fix non-API Java lint findings**

Perform these behavior-neutral changes:

```java
private static final long serialVersionUID = 1L;
```

in both private exception classes; remove three redundant integer casts; replace
the generic `List<Instruction>[]` tuple with a private record:

```java
private record InstructionParts(
        List<Instruction> prologue,
        List<Instruction> body,
        List<Instruction> epilogue) {}
```

Move `liveInstances.add(this)` to the last constructor statement, after all
final services, transports, and menu actions are initialized. Keep
`instanceCount` consistent by incrementing at the same publication point.

- [ ] **Step 5: Run focused and full Java tests**

```bash
mvn -q -Dtest=CommentServiceValidationTest,BinaryComparisonServiceTest,RunGhidraScriptProgramPropagationTest test
mvn test
```

Expected: PASS with the comment and ordinary-lint diagnostics removed.

- [ ] **Step 6: Commit the low-risk migration**

```bash
git add src/main/java
git commit -m "refactor: adopt low-risk Ghidra 12.1 APIs"
```

### Task 3: Retire deprecated JSON helpers and remove unchecked Gson use

**Files:**
- Modify: `src/main/java/com/xebyte/core/JsonHelper.java`
- Modify: `src/main/java/com/xebyte/core/ServiceUtils.java`
- Modify: `src/main/java/com/xebyte/core/AnnotationScanner.java`
- Modify: `src/main/java/com/xebyte/core/EndpointRegistry.java`
- Modify: `src/main/java/com/xebyte/core/EndpointDef.java`
- Modify: `src/main/java/com/xebyte/headless/HeadlessManagementService.java`
- Modify: `src/main/java/com/xebyte/GhidraMCPPlugin.java`
- Test: existing endpoint/schema tests and `Ghidra121ApiMigrationTest`

**Interfaces:**
- Consumes: `JsonHelper.toJson(Object)` and Gson `TypeToken`.
- Produces: the same JSON structures and escaping without deprecated helpers or unchecked conversions.

- [ ] **Step 1: Add JSON escaping characterization cases**

Extend an existing offline JSON/endpoint test or add focused cases to
`AnnotationScannerOfflineTest` for quotes, backslashes, newlines, tabs, and a
Unicode code point. Assert parsed values, not formatting whitespace.

- [ ] **Step 2: Verify characterization tests pass before refactoring**

```bash
mvn -q -Dtest=AnnotationScannerOfflineTest,GuiTransportSchemaParityTest test
```

Expected: PASS.

- [ ] **Step 3: Use typed Gson deserialization**

Add a static generic type:

```java
private static final Type STRING_OBJECT_MAP_TYPE =
        new TypeToken<LinkedHashMap<String, Object>>() {}.getType();
```

Use it in `parseBody`, `parseJson`, and the `JsonElement` map conversion so no
unchecked assignment or method-level suppression remains.

- [ ] **Step 4: Replace only warning-producing JSON helper calls**

Use `JsonHelper.toJson(list)` and `toJson(map)` in scanner/registry code. For
manual string builders, append the complete Gson-produced string literal rather
than adding quotes around escaped content. Convert the four small headless
management responses to `JsonHelper.mapOf` plus `toJson`. Remove the deprecated
`escapeJson`, `serializeListToJson`, and `serializeMapToJson` methods once no
maintained caller remains; implement `programNotFoundError` with `JsonHelper`.

- [ ] **Step 5: Run schema and migration tests**

```bash
mvn -q -Dtest=AnnotationScannerOfflineTest,GuiTransportSchemaParityTest,EndpointsJsonParityTest,Ghidra121ApiMigrationTest test
```

Expected: PASS; no deprecated project JSON helper token remains in main source.

- [ ] **Step 6: Commit the JSON cleanup**

```bash
git add src/main/java src/test/java
git commit -m "refactor: centralize warning-free JSON encoding"
```

### Task 4: Migrate program loading with explicit ownership

**Files:**
- Modify: `src/main/java/com/xebyte/core/ProgramScriptService.java`
- Modify: `src/main/java/com/xebyte/headless/HeadlessProgramProvider.java`
- Modify: `src/test/java/com/xebyte/offline/ArchitectureBoundaryTest.java`
- Test: `src/test/java/com/xebyte/offline/FrontEndProgramProviderEvictionTest.java`
- Test: `src/test/java/com/xebyte/offline/ProgramScriptServiceValidationTest.java`

**Interfaces:**
- Consumes: `ghidra.app.util.importer.ProgramLoader.Builder`, `LoadResults<Program>`, and `Program.release(Object)`.
- Produces: imported programs with one explicit long-lived consumer and no unclosed loader results.

- [ ] **Step 1: Add loader ownership source contracts**

Assert maintained source contains no `AutoImporter` or zero-argument
`getPrimaryDomainObject()`, and that every file containing `ProgramLoader.builder()`
also contains try-with-resources over `LoadResults<Program>`.

- [ ] **Step 2: Verify the ownership contract fails**

```bash
mvn -q -Dtest=Ghidra121ApiMigrationTest test
```

Expected: FAIL on `AutoImporter` and unsafe primary-object access.

- [ ] **Step 3: Migrate headless best-guess loading**

Use:

```java
try (LoadResults<Program> results = ProgramLoader.builder()
        .source(file)
        .project(project)
        .projectFolderPath("/")
        .log(log)
        .monitor(monitor)
        .load(this)) {
    if (project != null) results.save(monitor);
    program = results.getPrimaryDomainObject(this);
}
```

Register the returned program after the results close. The provider retains the
explicit `this` consumer until its existing close/release path.

- [ ] **Step 4: Migrate explicit raw-binary loading**

Use the same builder with:

```java
.loaders(BinaryLoader.class)
.language(language)
.compiler(compilerSpec)
```

Save before closing results and retain the provider consumer exactly once.

- [ ] **Step 5: Migrate GUI imports**

Build and save the results identically, obtain the program with
`getPrimaryDomainObject(this)`, then close results. Wrap subsequent analysis and
`ProgramManager.openProgram` work in `try/finally`; release the service consumer
in the `finally` after `ProgramManager` has acquired its own reference. Release
it on all early errors as well.

- [ ] **Step 6: Run import and lifecycle tests**

```bash
mvn -q -Dtest=GarArchiveRestoreTest,GzfExportImportTest,FrontEndProgramProviderEvictionTest,ProgramScriptServiceValidationTest,Ghidra121ApiMigrationTest test
```

Expected: PASS with no `AutoImporter`, unsafe primary access, or loader leaks.

- [ ] **Step 7: Commit the loader migration**

```bash
git add src/main/java src/test/java
git commit -m "refactor: make Ghidra program loading ownership explicit"
```

### Task 5: Migrate emulation to PcodeEmulator with bounded execution

**Files:**
- Modify: `src/main/java/com/xebyte/core/EmulationService.java`
- Modify: `src/test/java/com/xebyte/offline/EmulationServiceValidationTest.java`
- Modify: `tests/integration/test_phase4_advanced.py`

**Interfaces:**
- Consumes: `PcodeEmulator`, `PcodeThread<byte[]>`, `EmulatorUtilities`, and `RegisterValue`.
- Produces: private session operations `writeRegister`, `readRegister`, `writeMemory`, `counter`, and `step`, shared by both emulation endpoints.

- [ ] **Step 1: Add bounded-batch and schema characterization**

Add source/contract assertions that `emulate_hash_batch` uses `MAX_STEPS` and no
unbounded `run(...)`. Preserve assertions for the existing single-response keys:
`success`, `steps_executed`, `max_steps`, `stop_reason`, `final_pc`,
`hit_return`, and `registers`.

- [ ] **Step 2: Verify the bounded-batch guard fails**

```bash
mvn -q -Dtest=EmulationServiceValidationTest,Ghidra121ApiMigrationTest test
```

Expected: FAIL because the batch path still invokes unbounded legacy emulation.

- [ ] **Step 3: Introduce a private modern emulator session**

The session constructs `PcodeEmulator(program.getLanguage())`, calls
`EmulatorUtilities.loadProgram`, creates one `PcodeThread<byte[]>`, and calls
`EmulatorUtilities.initializeRegisters(thread, program, entry)`. Implement
register writes via `RegisterValue`, register reads via
`thread.getState().inspectRegisterValue`, memory writes via
`emulator.getSharedState().setConcrete`, PC reads via `thread.getCounter`, and
steps via `thread.stepInstruction()`.

- [ ] **Step 4: Migrate single-function emulation**

Apply stack and caller overrides after official register initialization. Keep
the current effective max-step calculation, result fields, optional-register
behavior, return sentinel, and fault text.

- [ ] **Step 5: Migrate batch emulation**

Create a fresh session per candidate as before. Load program memory, apply stack,
candidate, string-register, and extra-register values, then step until the return
sentinel, a fault, or `MAX_STEPS`. Read the hash only after a successful return;
surface a bounded batch error instead of hanging.

- [ ] **Step 6: Run focused tests and compile**

```bash
mvn -q -Dtest=EmulationServiceValidationTest,Ghidra121ApiMigrationTest test
mvn clean compile
```

Expected: PASS and no `EmulatorHelper` diagnostic.

- [ ] **Step 7: Run live emulation integration when a compatible server is available**

Use the existing phase-4 integration test against Ghidra 12.1.2. If no live
server is configured, record that the live gate was unavailable and rely on the
official Ghidra API source, compile gate, and offline contracts.

- [ ] **Step 8: Commit the emulator migration**

```bash
git add src/main/java/com/xebyte/core/EmulationService.java src/test tests/integration
git commit -m "refactor: migrate emulation to Ghidra 12.1 p-code APIs"
```

### Task 6: Enable strict Maven warnings and remove test-runtime warning noise

**Files:**
- Modify: `pom.xml`
- Modify: `tests/unit/test_build_surface.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: warning-free main/test source from Tasks 2-5.
- Produces: `mvn` compilation with `-Xlint:all -Werror` and static Mockito agent loading.

- [ ] **Step 1: Confirm direct lint is clean before changing Maven**

Run direct `javac --release 21 -Xlint:all -Werror` for main and test sources.
Expected: exit 0 and no diagnostics.

- [ ] **Step 2: Configure compiler warning enforcement**

Set `<showWarnings>true</showWarnings>` and add:

```xml
<compilerArgs>
    <arg>-Xlint:all</arg>
    <arg>-Werror</arg>
</compilerArgs>
```

to the Maven Compiler Plugin.

- [ ] **Step 3: Configure Mockito as a startup agent**

Extract `mockito.version` into a Maven property and append the Mockito core jar
as `-javaagent` in Surefire `argLine`, preserving JaCoCo's late-bound
`@{argLine}` and Byte Buddy experimental mode. Run the focused Mockito-heavy
tests and confirm the self-attach/dynamic-agent warnings disappear.

- [ ] **Step 4: Document the user-visible migration**

Add a CHANGELOG entry describing the Ghidra 12.1 API migration, explicit loader
ownership, bounded modern emulator, warning-as-error gate, and dropped pre-12.1
source compatibility.

- [ ] **Step 5: Run ratchet tests**

```bash
uv run pytest tests/unit/test_build_surface.py -v --no-cov
mvn -q -Dtest=Ghidra121ApiMigrationTest test
```

Expected: PASS.

- [ ] **Step 6: Commit build enforcement**

```bash
git add pom.xml tests/unit/test_build_surface.py CHANGELOG.md
git commit -m "build: fail Maven compilation on Java warnings"
```

### Task 7: Review and final verification

**Files:**
- Inspect: all changed files
- Modify: only files required by concrete review findings

**Interfaces:**
- Consumes: completed warning cleanup and test evidence.
- Produces: reviewed, distributable, warning-free branch.

- [ ] **Step 1: Run Claude implementation review**

Use the requested `/claude` workflow on the complete diff. Resolve every
concrete current finding and resume the same review mailbox until none remain.

- [ ] **Step 2: Run full verification**

```bash
mvn clean test
uv run pytest tests/unit/ -v --no-cov
mvn clean package assembly:single -DskipTests
git status --short
```

Expected: both suites pass; the package build reports `BUILD SUCCESS`; no Java
compiler or Mockito dynamic-agent warnings appear; only intentional skipped-test
reporting remains.

- [ ] **Step 3: Recount compiler diagnostics independently**

Run direct main and test `javac --release 21 -Xlint:all -Werror` commands.
Expected: zero diagnostics and exit 0 for both.

- [ ] **Step 4: Run Claude final-result review**

Resume the Claude mailbox with final verification evidence. Resolve any concrete
finding and repeat verification if code changes.

- [ ] **Step 5: Review branch history and diff**

```bash
git log --oneline main..HEAD
git diff --check main...HEAD
git status --short
```

Expected: focused commits, no whitespace errors, and a clean worktree.
