# MCP catalog context analysis

The authoritative catalog is [`../tests/endpoints.json`](../tests/endpoints.json).
It currently contains 232 endpoints. Do not maintain a separate hand-count in
analysis tooling: both context-analysis scripts read the catalog at runtime.

## Reproduce the measurement

```bash
uv run python tools/context_analysis/measure_context.py
uv run python tools/context_analysis/advanced_context_analysis.py
```

Without `tiktoken`, the scripts report a clearly labeled character-based
estimate. With it installed, they use the selected tokenizer for a more precise
estimate. Token counts vary with catalog descriptions and tokenizer versions,
so generated output is evidence for the current checkout rather than a release
contract.

## Interpretation

The complete catalog is compact enough to be practical, but raw token cost is
not the only concern. Lazy registration improves discoverability: call
`list_tool_groups`, load a relevant group once with `load_tool_group`, then use
the returned tool names. This keeps unrelated schemas out of an agent's active
tool surface while leaving all endpoints available on demand.

The 21 TraceRMI endpoints are in the `debugger` group. Static analysis is split
across groups such as `function`, `search`, `xref`, `datatype`, and `script`.

## Maintenance

- Regenerate `tests/endpoints.json` when Java endpoint annotations change.
- Keep the scripts count-driven; never hardcode a catalog size in their output.
- Run the context tools after substantial endpoint or description changes.
- Treat catalog parity tests, not this report, as the correctness gate.
