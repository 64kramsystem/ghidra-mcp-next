# Security

Report vulnerabilities through GitHub private security advisories.

GhidraMCP-next is for a trusted, single-user workstation. The extension listens on a per-user Unix-domain socket. Optional TCP binds only to loopback and has no authentication; do not expose it through a proxy, port forward, or non-loopback bind.

Imported binaries and recovered strings, symbols, and decompiler output are untrusted data. Tool calls can mutate Ghidra projects, and TraceRMI calls can control a live target. Verify the selected instance, program, trace, and address before a mutation.

Keep projects and analyzed files under directories appropriate for local development. The project does not provide arbitrary Ghidra script execution.
