# Context-analysis tools

These utilities measure the schema cost of the live endpoint catalog in
`tests/endpoints.json`.

```bash
uv run python tools/context_analysis/measure_context.py
uv run python tools/context_analysis/advanced_context_analysis.py
```

`measure_context.py` reports catalog size and per-category cost.
`advanced_context_analysis.py` compares full, minimal, and reduced schema
shapes. Both derive the endpoint count from the catalog instead of assuming a
fixed release count.

If `tiktoken` is unavailable, the scripts fall back to a labeled approximation
of one token per four characters. Install `tiktoken` in a disposable environment
when exact comparisons are useful; it is not a runtime dependency of
ghidra-mcp.

See [`../../docs/Context-Window-Analysis.md`](../../docs/Context-Window-Analysis.md)
for interpretation and maintenance guidance.
