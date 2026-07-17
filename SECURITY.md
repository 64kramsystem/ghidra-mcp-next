# Security Policy

## Reporting a vulnerability

Please use GitHub's private security-advisory flow for vulnerabilities. Include
the affected version, deployment mode, reproduction steps, expected impact,
and any proposed mitigation. Do not publish an exploitable issue before the
maintainers have had a reasonable opportunity to respond.

## Deployment model

Ghidra MCP is designed for a trusted single-user workstation. Keep both the
Ghidra HTTP service and the Python bridge on loopback unless you have explicitly
secured every client and transport.

The supported project model is a local project. Treat imported binaries,
symbols, decompiler output, script output, and model-generated tool arguments as
untrusted data.

## Security controls

| Variable | Purpose |
| --- | --- |
| `GHIDRA_MCP_AUTH_TOKEN` | Requires a bearer token for non-health HTTP requests. |
| `GHIDRA_MCP_FILE_ROOT` | Restricts filesystem endpoints to a canonical directory tree. |
| `GHIDRA_MCP_ALLOW_SCRIPTS` | Enables arbitrary-code script endpoints; disabled by default. |
| `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS` | Prevents program-scoped calls from silently targeting the active tab. |

Use a high-entropy token, avoid logging it, and rotate it if exposure is
suspected. Do not place untrusted inputs inside the allowed file root merely to
bypass a rejected path.

## Script execution

`run_ghidra_script` and `run_script_inline` execute code in the Ghidra process.
Only enable them for trusted local clients, review scripts before execution, and
prefer the native MCP endpoints when possible. The reviewed repository scripts
are an allowlist, not a sandbox.

## Dynamic analysis

TraceRMI debugger operations can control a live process and read its memory.
Confirm the launch offer, target, mapped address, and active trace before a
mutation. Do not expose debugger agents to untrusted networks.

## Supported versions

Security fixes target the current release line. Older releases may contain
known issues and should be upgraded before use in a network-reachable setup.
