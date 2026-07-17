# Local Workflow Data

This directory is reserved for optional analyst-owned workflow inputs, such as
local community symbol tables. Ghidra MCP does not require it for the Java
extension, Python bridge, local project lifecycle, TraceRMI, or BSim.

Keep binary-specific state, target addresses, credentials, and generated
analysis output out of version control. Reusable functionality should be added
to a tested service endpoint or to the reviewed generic `ghidra_scripts/`
allowlist instead of being embedded in a target-specific workflow file.
