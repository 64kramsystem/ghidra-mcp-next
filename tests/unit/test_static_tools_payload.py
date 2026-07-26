from __future__ import annotations

import asyncio
import dataclasses
import json

import pytest

from ghidra_mcp_bridge import instance_summary, state, static_tools


class TestInstanceSummary:
    """list_instances returned every program in the project.

    /mcp/instance_info lists the whole roster; upstream measured ~90KB for 626 programs, past
    MCP result limits, so the tool failed exactly when connected to a project worth listing.
    Nothing downstream reads the roster -- connect_instance matches on project name.
    """

    def test_roster_collapses_to_a_count_plus_the_open_programs(self):
        summary = instance_summary.summarize_instance(
            {
                "project": "p",
                "programs": [
                    {"name": "a.bin", "path": "/a.bin", "open": False},
                    {"name": "b.bin", "path": "/b.bin", "open": True},
                ],
            }
        )

        assert "programs" not in summary
        assert summary["program_count"] == 2
        assert summary["open_programs"] == ["/b.bin"]
        assert summary["project"] == "p"

    def test_large_rosters_are_truncated_and_say_so(self):
        programs = [
            {"name": f"{i}.bin", "path": f"/{i}.bin", "open": True} for i in range(40)
        ]

        summary = instance_summary.summarize_instance({"programs": programs})

        assert summary["program_count"] == 40
        assert len(summary["open_programs"]) == instance_summary.MAX_OPEN_PROGRAMS_LISTED
        assert summary["open_programs_truncated"] == 40 - instance_summary.MAX_OPEN_PROGRAMS_LISTED

    def test_a_roster_that_fits_is_not_marked_truncated(self):
        summary = instance_summary.summarize_instance(
            {"programs": [{"name": "a", "open": True}]}
        )

        assert "open_programs_truncated" not in summary

    def test_bare_string_entries_count_as_open(self):
        """/list_open_programs returns names, where being listed is being open."""
        summary = instance_summary.summarize_instance({"programs": ["a.bin", "b.bin"]})

        assert summary["program_count"] == 2
        assert summary["open_programs"] == ["a.bin", "b.bin"]

    def test_an_instance_without_a_roster_is_passed_through(self):
        instance = {"project": "p", "pid": 1}

        assert instance_summary.summarize_instance(instance) == instance


class TestCheckToolsWithoutSchema:
    """"not_found" used to mean both "no such tool" and "no schema fetched yet"."""

    @staticmethod
    def _run(monkeypatch: pytest.MonkeyPatch, bundle, tools: str) -> dict:
        monkeypatch.setattr(state, "_connection", bundle)
        return json.loads(asyncio.run(static_tools.check_tools(tools)))

    def test_unconnected_reports_unknown_rather_than_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        empty = state.ConnectionBundle()

        result = self._run(monkeypatch, empty, "rename_or_label")

        entry = result["results"]["rename_or_label"]
        assert entry["status"] == "unknown"
        assert "connect_instance" in entry["fix"]

    def test_static_tools_stay_callable_without_a_schema(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        empty = state.ConnectionBundle()

        result = self._run(monkeypatch, empty, "connect_instance")

        assert result["results"]["connect_instance"]["status"] == "callable"

    def test_a_genuinely_missing_tool_is_still_not_found_when_a_schema_exists(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        bundle = dataclasses.replace(
            state.ConnectionBundle(),
            full_schema=({"name": "rename_or_label", "category": "symbol"},),
            dynamic_names=("rename_or_label",),
        )

        result = self._run(monkeypatch, bundle, "no_such_tool,rename_or_label")

        assert result["results"]["no_such_tool"]["status"] == "not_found"
        assert result["results"]["rename_or_label"]["status"] == "callable"
