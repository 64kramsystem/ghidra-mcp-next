# Release documentation

[`../../CHANGELOG.md`](../../CHANGELOG.md) is the canonical version history.
Older changelog entries describe the code that shipped at that time; they are
historical records, not instructions for the current tree.

The current unreleased architecture is local-first:

- 229 cataloged endpoints served by the Ghidra GUI plugin or headless server;
- Maven for Java builds and `uv` for Python packaging and tests;
- local Ghidra projects and explicit multi-program selection;
- Ghidra TraceRMI debugging through the 18 `debugger_*` tools; and
- optional, explicitly configured local BSim plus six local comparison tools.

The repository-server, documentation-propagation, standalone proxy-debugger,
naming-policy, Gradle, Docker, and application-specific automation surfaces
described by some historical releases have been removed.

Use [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) for the current release
runbook and [`../README.md`](../README.md) for the maintained documentation
index.
