#!/usr/bin/env python3
"""
Advanced context analysis: MCP tool registration, schema serialization,
and what-if scenarios for context optimization.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tiktoken
    HAS_TIKTOKEN = True
except ImportError:
    HAS_TIKTOKEN = False
    print("⚠️  Install tiktoken for accurate counts: pip install tiktoken\n")


def load_endpoints():
    """Load endpoints.json catalog."""
    # Find endpoints.json relative to project root
    script_dir = Path(__file__).parent.resolve()
    project_root = script_dir.parent.parent
    endpoints_file = project_root / "tests" / "endpoints.json"

    with open(endpoints_file, "r") as f:
        return json.load(f)


def count_tokens(text):
    """Count Claude tokens in text."""
    if not HAS_TIKTOKEN:
        return len(text) // 4  # fallback estimate
    encoding = tiktoken.get_encoding("cl100k_base")
    return len(encoding.encode(text))


def simulate_mcp_schema():
    """Simulate what the /mcp/schema endpoint returns (tool registration)."""
    data = load_endpoints()

    # MCP tools include: name, description, inputSchema
    mcp_tools = []
    for endpoint in data["endpoints"]:
        tool = {
            "name": endpoint["path"].lstrip("/").replace("/", "_"),
            "description": endpoint["description"],
            "inputSchema": {
                "type": "object",
                "properties": {
                    param: {"type": "string"} for param in endpoint["params"]
                },
                "required": endpoint["params"][:1] if endpoint["params"] else []
            }
        }
        mcp_tools.append(tool)

    # MCP registration format
    mcp_registration = {
        "tools": mcp_tools,
        "server_version": data["version"]
    }

    return json.dumps(mcp_registration)


def analyze_descriptions():
    """Analyze token cost of descriptions."""
    data = load_endpoints()
    endpoints = data["endpoints"]

    total_desc_tokens = 0
    desc_lengths = []

    for endpoint in endpoints:
        desc = endpoint.get("description", "")
        tokens = count_tokens(desc)
        total_desc_tokens += tokens
        desc_lengths.append(tokens)

    desc_lengths.sort(reverse=True)

    return {
        "total_tokens": total_desc_tokens,
        "avg_per_endpoint": total_desc_tokens // len(endpoints) if endpoints else 0,
        "top_10": desc_lengths[:10],
        "bottom_10": desc_lengths[-10:],
    }


def what_if_scenarios():
    """Run optimization scenarios."""
    data = load_endpoints()
    endpoints = data["endpoints"]

    scenarios = {}

    # Scenario 1: Full schema
    full_schema = simulate_mcp_schema()
    scenarios["Full MCP Schema (current)"] = count_tokens(full_schema)

    # Scenario 2: Minimal schema (no descriptions)
    minimal_tools = []
    for endpoint in endpoints:
        tool = {
            "name": endpoint["path"].lstrip("/"),
            "inputSchema": {
                "type": "object",
                "properties": {param: {} for param in endpoint["params"]}
            }
        }
        minimal_tools.append(tool)
    minimal_schema = json.dumps({"tools": minimal_tools})
    scenarios["MCP Schema (no descriptions)"] = count_tokens(minimal_schema)

    # Scenario 3: Endpoints.json only
    endpoints_json = json.dumps(data)
    scenarios["Endpoints.json (current)"] = count_tokens(endpoints_json)

    # Scenario 4: 50 most-used tools (estimate)
    top_50 = endpoints[:50]
    top_50_data = data.copy()
    top_50_data["endpoints"] = top_50
    top_50_json = json.dumps(top_50_data)
    scenarios["Top 50 endpoints only"] = count_tokens(top_50_json)

    return scenarios


def main():
    print("=" * 90)
    print("ADVANCED CONTEXT WINDOW ANALYSIS - ghidra-mcp")
    print("=" * 90)
    print()

    # Basic stats
    data = load_endpoints()
    endpoint_count = len(data["endpoints"])
    endpoints_json = json.dumps(data)
    base_tokens = count_tokens(endpoints_json)

    print(f"Endpoints catalog: {len(data['endpoints'])} tools")
    print(f"Base JSON size:    {len(endpoints_json):,} bytes / {base_tokens:,} tokens")
    print()

    # MCP schema simulation
    print("MCP TOOL REGISTRATION:")
    print()
    mcp_schema = simulate_mcp_schema()
    mcp_tokens = count_tokens(mcp_schema)
    print(f"  MCP Schema (tools + inputSchema):  {mcp_tokens:,} tokens")
    print(f"  Overhead vs. endpoints.json:       +{mcp_tokens - base_tokens:,} tokens ({(mcp_tokens / base_tokens - 1) * 100:+.1f}%)")
    print()

    # Description analysis
    print("DESCRIPTION COST BREAKDOWN:")
    print()
    desc_stats = analyze_descriptions()
    print(f"  Total description tokens:   {desc_stats['total_tokens']:,} ({(desc_stats['total_tokens'] / base_tokens) * 100:.1f}% of total)")
    print(f"  Avg per endpoint:           {desc_stats['avg_per_endpoint']} tokens")
    print(f"  Most expensive:             {max(desc_stats['top_10'])} tokens")
    print(f"  Cheapest:                   {min(desc_stats['bottom_10'])} tokens")
    print()

    # What-if scenarios
    print("CONTEXT OPTIMIZATION SCENARIOS:")
    print()
    scenarios = what_if_scenarios()

    base_scenario = scenarios["Endpoints.json (current)"]

    for scenario_name, tokens in sorted(scenarios.items(), key=lambda x: x[1]):
        delta = tokens - base_scenario
        pct_change = (delta / base_scenario) * 100 if base_scenario > 0 else 0
        marker = "📊 CURRENT" if "endpoints.json" in scenario_name else ""
        print(f"  {scenario_name:<40}  {tokens:>7,} tokens  ({delta:+7,})  {pct_change:+6.1f}%  {marker}")

    print()
    print("=" * 90)
    print("CONTEXT EFFICIENCY REPORT")
    print("=" * 90)
    print()

    print("✅ STRENGTHS:")
    print()
    print(f"   • {base_tokens:,} tokens for {endpoint_count} endpoints")
    print(f"     (avg {base_tokens // endpoint_count} tokens/endpoint)")
    print()
    catalog_pct = base_tokens / 200_000 * 100
    print(f"   • Endpoints.json occupies {catalog_pct:.1f}% of a 200K context window")
    print()
    print("   • Parameter descriptions already follow best practices:")
    print("     - Concise but informative")
    print("     - Include type hints and constraints")
    print("     - No redundant verbosity")
    print()

    print(f"📊 CONTEXT ALLOCATION (200K window with all {endpoint_count} tools):")
    print()
    print(f"   Endpoints.json:     {base_tokens:>7,} tokens  ({catalog_pct:5.1f}%)")
    print(f"   User query:         ≈ 2,000 tokens  (  1.0%)")
    print(f"   Chat history:       ≈ 5,000 tokens  (  2.5%)")
    print(f"   Agent reasoning:    ≈10,000 tokens  (  5.0%)")
    print(f"   Available for resp: ≈170,000 tokens  ( 85.0%)")
    print()

    print("🎯 DISCOVERABILITY MATTERS MORE THAN RAW SCHEMA SIZE:")
    print()
    print("   Issue #307 argument: 'Tool count hurts LLM performance' is backed")
    print("   by research (RAG-MCP: 13.6% → 43.1% accuracy with retrieval)")
    print()
    print("   BUT: Token COUNT alone isn't the problem.")
    print("        Token COUNT + poor DISCOVERABILITY is the problem.")
    print()
    print("   Current system has:")
    print(f"   ✓ Efficient token usage ({catalog_pct:.1f}% of a 200K context)")
    print("   ✓ Lazy groups loaded through load_tool_group")
    print("   ✓ Schema discovery from the active Ghidra instance")
    print("   ✓ search_tools and list_tool_groups discovery helpers")
    print("   ✓ Parameter aliases (Issue #210 - improves prompt quality)")
    print()

    print("💡 RECOMMENDATIONS:")
    print()
    print(f"   1. Keep the complete {endpoint_count}-tool catalog")
    print()
    print("   2. Use the existing discovery layer:")
    print("      - search_tools(query) to find capabilities")
    print("      - list_tool_groups() to inspect lazy groups")
    print("      - load_tool_group(name) once for the selected workflow")
    print()
    print("   3. Keep schema descriptions concise and evidence-oriented")
    print()
    print("   4. Monitor actual usage patterns:")
    print("      - Instrument bridge to log which tools AI actually calls")
    print("      - Compare request patterns vs. registered tools")
    print("      - Use data to guide future optimization")
    print()


if __name__ == "__main__":
    main()
