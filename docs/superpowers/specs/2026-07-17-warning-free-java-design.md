# Warning-Free Java Build Design

## Goal

Make the maintained Java source and test code warning-free under JDK 21
`-Xlint:all`, remove the runtime warning noise emitted by Mockito during the
Maven test phase, and make warnings fail the build so the codebase stays clean.

The project targets Ghidra 12.1.x directly. Ghidra 12.0 and older are not
supported by this refactoring.

## Baseline

The direct JDK 21 lint compile reports 96 warnings in main sources and zero in
test sources:

- 62 `removal`
- 26 `deprecation`
- 3 `cast`
- 2 `serial`
- 1 `rawtypes`
- 1 `this-escape`
- 1 `unchecked`

The normal Maven build compresses those findings into three notes because the
compiler plugin currently sets `showWarnings` to false. The baseline test suites
pass: 284 Java tests with one skipped, and 416 Python unit tests with seven
skipped.

## Scope

The refactoring will:

1. Replace integer comment types and legacy comment accessors with Ghidra 12.1
   `CommentType` APIs across GUI and headless services.
2. Replace `AutoImporter` with `ProgramLoader`, explicitly transfer the primary
   `Program` to the correct long-lived consumer, and close every `LoadResults`.
3. Replace deprecated `GhidraScript.set(state, monitor, writer)` with
   `ScriptControls`.
4. Replace the legacy `DataTypeManager.remove(dataType, monitor)` overload.
5. Replace `EmulatorHelper` with `PcodeEmulator`, `PcodeThread`, and
   `EmulatorUtilities`, preserving bounded execution and response schemas.
6. Retire external use of deprecated hand-written JSON helpers without
   rewriting unrelated response construction.
7. Fix all ordinary JDK lint findings with typed data structures, typed Gson
   deserialization, explicit serialization IDs, and safe plugin publication.
8. Configure Mockito as a startup Java agent during tests.
9. Enable `-Xlint:all` and `-Werror` for main and test compilation.

## Compatibility and behavioral constraints

- All MCP endpoint paths, methods, parameters, defaults, and response field
  names remain unchanged.
- JSON work is limited to warning-producing helper call sites. It must not
  perform a repository-wide response-schema rewrite.
- Loader migration is a resource-ownership change, not a rename. A retained
  program receives an explicit consumer before `LoadResults.close()` releases
  the loader-owned reference.
- GUI imports release the service's temporary consumer after `ProgramManager`
  has opened the program. Headless imports retain the provider consumer until
  `closeProgram` or `closeAllPrograms`.
- Emulation loads initialized program memory into the new emulator, initializes
  processor context at the function entry, applies caller register/memory
  overrides afterward, and stops on return, fault, or the existing step cap.
- The batch emulator gains the same finite step cap as the single-function path
  so a non-returning candidate cannot hang the request indefinitely.
- No blanket `@SuppressWarnings` annotations are permitted. A narrow suppression
  is acceptable only if a warning is intrinsic and documented; the planned
  implementation instead removes the current `this` escape by publishing the
  plugin instance only after construction finishes.

## Architecture

The work remains within existing service boundaries. Comment, datatype, script,
and Java-lint migrations are direct local substitutions. Program-loading code
continues to live in `ProgramScriptService` and `HeadlessProgramProvider`, but
uses structured try-with-resources ownership. Emulation uses a small private
session abstraction inside `EmulationService` to keep register, memory, and
stepping operations consistent between the single and batch endpoints.

The strict compiler configuration is applied last. This makes the final Maven
build the permanent regression test for all warning categories rather than
forcing temporary suppressions during intermediate stages.

## Error handling

- Loader failures retain the existing endpoint-level error messages and import
  logs. All temporary program consumers are released on early returns and
  exceptions.
- P-code execution exceptions become the existing `fault: ...` stop reason in
  single-function responses and a bounded batch failure instead of escaping or
  hanging.
- Missing architecture-specific registers remain ignored where the existing
  code already treats them as optional.
- Unsupported or invalid caller-specified registers continue to produce the
  existing endpoint error behavior.

## Verification

Verification is layered:

1. Source-contract tests reject reintroduction of the migrated Ghidra APIs and
   deprecated project JSON helpers.
2. Existing focused Java tests cover endpoint registration, schemas, comments,
   imports, and graceful emulation errors.
3. A direct JDK compile proves the warning count moves from 96 to zero before
   the Maven ratchet is enabled.
4. `mvn test` proves the strict compiler gate and Java suite.
5. `uv run pytest tests/unit/ -v --no-cov` proves bridge/build-surface parity.
6. `mvn clean package assembly:single -DskipTests` proves the distributable
   extension build is warning-free.
7. Claude reviews the completed implementation and the final verified result at
   the major checkpoints requested by the user.

## Out of scope

- Rewriting every hand-built JSON response.
- Redesigning endpoint routing or service decomposition.
- Supporting Ghidra 12.0 or earlier.
- Changing endpoint schemas to expose new emulator diagnostics.
- Introducing broad warning suppressions.
