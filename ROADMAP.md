# Roadmap

The roadmap focuses on deepening the maintained local-analysis and TraceRMI
stack. Items are not promises until they have implementation, catalog, and test
coverage.

## Near-term priorities

- Maintain GUI/headless parity for local project and program operations.
- Keep `tests/endpoints.json` synchronized with Java registrations.
- Improve multi-program routing and failure reporting without relying on a
  mutable active tab.
- Expand offline tests for Ghidra transaction, address-space, and TraceRMI
  mapping semantics.
- Keep generic local comparison and optional BSim useful for recognizing
  open-source library boundaries.

## Planned TraceRMI additions

- [x] Generic TraceRMI attach using a selected launch offer and PID.
- [x] `debugger_wait_for_stop(timeout_ms)`.
- [x] Process memory-map enumeration.
- [ ] `copy_debugger_memory_to_program`, creating and populating a block from a
  trace range.

Use `debugger_attach` for exact selected-offer native PID attachment, `debugger_wait_for_stop` for bounded event-driven waiting, and `debugger_memory_maps` for current trace-region enumeration. The unchecked item remains unavailable.

## Quality bar

A roadmap feature is complete only when it includes:

- Java GUI registration and deliberate headless behavior;
- endpoint-catalog parity;
- bridge name and schema coverage;
- offline tests for pure semantics where possible;
- live-test instructions for behavior that requires Ghidra; and
- maintained user and developer documentation.
