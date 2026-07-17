# Ghidra Scripts

This directory is an explicit allowlist of generic scripts that run inside
Ghidra. They supplement the native MCP endpoints without encoding a particular
application, address layout, or repository workflow.

## Security gate

`run_ghidra_script` and `run_script_inline` execute code inside the Ghidra
process and are disabled by default. Set `GHIDRA_MCP_ALLOW_SCRIPTS=1` only for a
trusted local workflow that needs them. The same files can be run interactively
from Ghidra's Script Manager without using MCP.

## Retained scripts

### BSim

- `BSimTestConnection.java` checks a configured database.
- `BSimIngestProgram.java` ingests the current analyzed program.
- `BSimQueryFunction.java` queries one function and returns matches without
  applying names, comments, or other metadata.
- `BSimBulkQuery.java` queries default-named functions in one program.

Every BSim script requires a caller-supplied URL. For example,
`file:/absolute/path/to/local-bsim` illustrates a local database; the actual URL
must be supported by the BSim client in the installed Ghidra version. GUI runs
prompt for the URL when it is omitted. Headless and MCP runs return
`BSim URL is required` instead of selecting a server implicitly.

### Repair and disassembly

- `ClearAndDisasm.java`
- `ClearCallReturnOverrides.java`
- `DeleteFunctionAt.java`
- `FindFunctionsAfterPadding.java`
- `FindFunctionsAfterPaddingAllPrograms.java`
- `FindFunctionsAtINT3.java`
- `ProperSizeStringsScript.java`
- `RemoveOrphanedFunctions.java`

### Comment cleanup

- `ClearAllComments.java`
- `ClearFunctionComments.java`
- `ClearPrePostComments.java`
- `RemoveDecompilerComments.java`

### Datatype and symbol utilities

- `ApplyDWORD.java`
- `ArgumentsUnifier.py`
- `ConvertNamespaceToClass.java`
- `CreateFunctionsFromArray.py`
- `FixIATExternalFunctionAddresses.java`
- `RestoreLibraryFunctionNamesFromPlateComments.java`
- `namespacer.py`

### Local project maintenance

- `UpgradeAllPrograms.java`

## Running from Ghidra

Open **Window > Script Manager**, add this directory through **Manage Script
Directories**, refresh, and run the selected script. Java scripts use Ghidra's
bundled Java APIs. Python scripts require Ghidra's optional Jython extension,
which uses Python 2.7 syntax.
