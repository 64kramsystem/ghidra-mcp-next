"""Condense Ghidra instance descriptors for list_instances.

/mcp/instance_info reports every program in a project. Upstream measured ~90KB for 626
programs, past MCP result limits, so list_instances failed precisely when it was connected to
a project worth listing. Nothing downstream reads the roster: connect_instance matches on
project name.
"""

from __future__ import annotations

# A project can hold hundreds of programs; only the open ones are actionable.
MAX_OPEN_PROGRAMS_LISTED = 25


def summarize_instance(inst: dict) -> dict:
    """Replace an instance's program roster with a count and the open programs.

    Roster entries are dicts ({name, path, open}) from /mcp/instance_info, or bare strings
    from /list_open_programs -- where being listed *is* being open. An instance carrying no
    roster is returned unchanged.
    """
    programs = inst.get("programs")
    if not isinstance(programs, list):
        return inst

    summary = {k: v for k, v in inst.items() if k != "programs"}
    open_names = [
        (p.get("path") or p.get("name")) if isinstance(p, dict) else p
        for p in programs
        if not isinstance(p, dict) or p.get("open")
    ]
    summary["program_count"] = len(programs)
    summary["open_programs"] = open_names[:MAX_OPEN_PROGRAMS_LISTED]
    if len(open_names) > MAX_OPEN_PROGRAMS_LISTED:
        summary["open_programs_truncated"] = len(open_names) - MAX_OPEN_PROGRAMS_LISTED
    return summary
