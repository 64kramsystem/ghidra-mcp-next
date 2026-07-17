# User-installable Ghidra scripts

These scripts are optional helpers used directly from Ghidra's Script Manager.
They are separate from the allowlisted scripts exposed through the MCP
`run_ghidra_script` endpoint in [`../../ghidra_scripts/`](../../ghidra_scripts/).

Copy a script into the Ghidra user script directory and refresh the Script
Manager:

| Platform | Directory |
|---|---|
| Windows | `%USERPROFILE%\\ghidra_scripts\\` |
| macOS/Linux | `~/ghidra_scripts/` |

## `ImportMSDLPDB.java`

Downloads the matching PDB for the current PE program from Microsoft's symbol
server and applies it through Ghidra's PDB Universal Analyzer.

Configure `https://msdl.microsoft.com/download/symbols` and a local cache in
Ghidra under **Edit > Symbol Server Config**. The script exits without changing
the program when the PE has no `PdbInformation` record.
