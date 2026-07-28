from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .envfile import load_env_file
from .maven import find_maven_command
from .versioning import (
    infer_ghidra_install_meta,
    infer_ghidra_version_from_path,
    read_pom_ghidra_version,
)

REQUIRED_GHIDRA_JARS: tuple[tuple[str, str], ...] = (
    ("Base", "Ghidra/Features/Base/lib/Base.jar"),
    ("Decompiler", "Ghidra/Features/Decompiler/lib/Decompiler.jar"),
    ("Docking", "Ghidra/Framework/Docking/lib/Docking.jar"),
    ("Generic", "Ghidra/Framework/Generic/lib/Generic.jar"),
    ("Project", "Ghidra/Framework/Project/lib/Project.jar"),
    ("SoftwareModeling", "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar"),
    ("Utility", "Ghidra/Framework/Utility/lib/Utility.jar"),
    ("Gui", "Ghidra/Framework/Gui/lib/Gui.jar"),
    ("FileSystem", "Ghidra/Framework/FileSystem/lib/FileSystem.jar"),
    ("Graph", "Ghidra/Framework/Graph/lib/Graph.jar"),
    ("DB", "Ghidra/Framework/DB/lib/DB.jar"),
    ("Emulation", "Ghidra/Framework/Emulation/lib/Emulation.jar"),
    ("PDB", "Ghidra/Features/PDB/lib/PDB.jar"),
    ("FunctionID", "Ghidra/Features/FunctionID/lib/FunctionID.jar"),
    ("Help", "Ghidra/Framework/Help/lib/Help.jar"),
    ("Debugger-api", "Ghidra/Debug/Debugger-api/lib/Debugger-api.jar"),
    (
        "Framework-TraceModeling",
        "Ghidra/Debug/Framework-TraceModeling/lib/Framework-TraceModeling.jar",
    ),
    (
        "Debugger-rmi-trace",
        "Ghidra/Debug/Debugger-rmi-trace/lib/Debugger-rmi-trace.jar",
    ),
    ("ProposedUtils", "Ghidra/Debug/ProposedUtils/lib/ProposedUtils.jar"),
)

PLUGIN_CLASS = "com.xebyte.GhidraMCPPlugin"
PLUGIN_EXTENSION_NAME = "GhidraMCP-next"
DEFAULT_MCP_URL = "http://127.0.0.1:8089"
DEFAULT_MCP_WAIT_SECONDS = 120
DEFAULT_GHIDRA_EXIT_WAIT_SECONDS = 15


def ghidra_user_base_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "ghidra"
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "ghidra"
        return Path.home() / "AppData" / "Roaming" / "ghidra"

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / "ghidra"
    return Path.home() / ".config" / "ghidra"


def _version_sort_key(name: str) -> tuple[int, int, int, int]:
    """Sort key for Ghidra user-config dir names.

    Returns ``(major, minor, patch, explicit_patch)``. The trailing
    flag is 1 when the dir name carried an explicit patch component
    (e.g. ``ghidra_12.1.0_PUBLIC``) and 0 when it didn't
    (``ghidra_12.1_PUBLIC``), so a dir with an explicit patch beats
    an otherwise-equal shorter dir name. Without this tiebreaker the
    sort was non-deterministic across filesystems: Windows' alpha
    glob order put ``ghidra_12.1.0_PUBLIC`` before ``ghidra_12.1_PUBLIC``
    and the test passed; Linux's creation-order glob produced the
    opposite outcome and CI failed.
    """
    match = re.search(r"ghidra_(\d+)\.(\d+)(?:\.(\d+))?", name)
    if not match:
        return (0, 0, 0, 0)
    explicit_patch = 1 if match.group(3) is not None else 0
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
        explicit_patch,
    )


def resolve_ghidra_user_dir(ghidra_path: Path, user_base_dir: Path | None = None) -> Path:
    """Resolve the user-config dir matching a Ghidra install.

    Ghidra writes its per-user state under
    ``%APPDATA%\\ghidra\\ghidra_<version>_<layout>\\``. The dir is
    created lazily on first launch, so for a freshly-installed Ghidra
    it may not exist yet. We therefore prefer to *construct* the
    expected dir name from the install path rather than enumerating
    existing siblings — see #217, where a v5.10→v5.11 deploy targeting
    a freshly-installed ``F:\\ghidra_12.1_PUBLIC`` quietly resolved to
    a leftover ``ghidra_12.1_DEV`` user dir and installed the
    extension where the running Ghidra never looked for it.
    """
    user_base_dir = user_base_dir or ghidra_user_base_dir()
    target_version, target_layout = infer_ghidra_install_meta(ghidra_path)

    # When both version and layout are recoverable from the install
    # path, return the explicit dir unconditionally. The dir does not
    # need to already exist — Ghidra will create it on first launch.
    if target_version and target_layout:
        return user_base_dir / f"ghidra_{target_version}_{target_layout}"

    # Version known but layout couldn't be inferred (e.g. a custom
    # install path with application.properties present). Prefer an
    # existing matching dir, then PUBLIC, then a constructed PUBLIC
    # default.
    if target_version:
        if user_base_dir.is_dir():
            matching_dirs = sorted(
                path
                for path in user_base_dir.glob(f"ghidra_{target_version}*")
                if path.is_dir() and "_location_" not in path.name
            )
            if matching_dirs:
                public_dir = next((path for path in matching_dirs if "PUBLIC" in path.name), None)
                return public_dir or matching_dirs[0]
        return user_base_dir / f"ghidra_{target_version}_PUBLIC"

    # No version metadata at all — last-resort fallback to the
    # newest-looking existing dir so a totally custom install still
    # gets *some* answer instead of an exception.
    if user_base_dir.is_dir():
        version_dirs = sorted(
            (path for path in user_base_dir.glob("ghidra_*") if path.is_dir()),
            key=lambda path: _version_sort_key(path.name),
            reverse=True,
        )
        if version_dirs:
            return version_dirs[0]

    return user_base_dir / "ghidra_unknown_PUBLIC"


def patch_frontend_tool_config(content: str) -> tuple[str, bool]:
    original = content
    updated = content

    for package_name in ("Developer", "GhidraMCP-next"):
        updated = re.sub(
            rf"\s*<PACKAGE NAME=\"{re.escape(package_name)}\"\s*/>\s*",
            "\n",
            updated,
        )
        updated = re.sub(
            rf"(?s)\s*<PACKAGE NAME=\"{re.escape(package_name)}\">\s*.*?</PACKAGE>\s*",
            "\n",
            updated,
        )

    if PLUGIN_CLASS in updated:
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, updated != original

    utility_self_closing = '<PACKAGE NAME="Utility" />'
    if utility_self_closing in updated:
        replacement = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
            "            </PACKAGE>"
        )
        updated = updated.replace(utility_self_closing, replacement, 1)
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, True

    utility_block = '<PACKAGE NAME="Utility">'
    if utility_block in updated:
        replacement = '<PACKAGE NAME="Utility">\n' f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />'
        updated = updated.replace(utility_block, replacement, 1)
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, True

    root_node = "<ROOT_NODE"
    if root_node in updated:
        insertion = (
            '<PACKAGE NAME="Utility">\n'
            f'                <INCLUDE CLASS="{PLUGIN_CLASS}" />\n'
            "            </PACKAGE>\n"
            "<ROOT_NODE"
        )
        updated = updated.replace(root_node, insertion, 1)
        updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
        return updated, True

    updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
    return updated, updated != original


def mark_extension_known_in_tool_config(content: str, extension_name: str) -> str:
    """Record an installed extension as known to suppress Ghidra's first-run plugin dialog."""
    if re.search(
        rf'<EXTENSION\s+(?:[^>]*\s)?NAME="{re.escape(extension_name)}"',
        content,
    ):
        return content

    extension_entry = f'            <EXTENSION NAME="{extension_name}" />\n'
    empty_extensions = re.compile(r"(?m)^([ \t]*)<EXTENSIONS\s*/>\s*$")
    if empty_extensions.search(content):
        return empty_extensions.sub(
            rf"\1<EXTENSIONS>\n{extension_entry}\1</EXTENSIONS>",
            content,
            count=1,
        )

    extensions_open = re.compile(r"(?m)^([ \t]*)<EXTENSIONS>\s*$")
    match = extensions_open.search(content)
    if match:
        insert_at = match.end()
        return content[:insert_at] + "\n" + extension_entry + content[insert_at:]

    if "</TOOL>" not in content:
        return content
    return content.replace(
        "</TOOL>",
        f"        <EXTENSIONS>\n{extension_entry}        </EXTENSIONS>\n    </TOOL>",
        1,
    )


def patch_tool_tcd(content: str) -> tuple[str, bool]:
    original = content
    updated = re.sub(
        rf'\s*<PACKAGE NAME="GhidraMCP-next">\s*<INCLUDE CLASS="{re.escape(PLUGIN_CLASS)}"\s*/>\s*</PACKAGE>',
        "",
        content,
    )
    updated = mark_extension_known_in_tool_config(updated, PLUGIN_EXTENSION_NAME)
    return updated, updated != original


def patch_codebrowser_tcd(content: str) -> tuple[str, bool]:
    return patch_tool_tcd(content)


def _write_text_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="")


def patch_ghidra_user_configs(
    user_base_dir: Path,
    target_user_dir: Path | None = None,
    *,
    dry_run: bool = False,
) -> None:
    """Patch FrontEndTool.xml + tool tcd files under the Ghidra user dir.

    When ``target_user_dir`` is provided, only files inside that directory
    are patched. This is the recommended call shape from
    :func:`deploy_to_ghidra` — a Ghidra 12.1 deploy must NOT touch the
    user-config dirs left over from older Ghidra installs (12.0.4,
    11.4.2, …), because those dirs reference extensions from those older
    Ghidras. Stamping the new plugin's INCLUDE into a sibling version's
    FrontEndTool.xml is exactly the #217 bug: the deploy log this morning
    showed ``Patched FrontEnd config …/ghidra_12.0.4_PUBLIC/…`` even
    though we were targeting 12.1.

    When ``target_user_dir`` is None, falls back to globbing every
    version subdirectory under ``user_base_dir``. Kept for backward
    compatibility (existing tests pass without changes); production
    deploys should always supply ``target_user_dir``.
    """
    if not user_base_dir.is_dir():
        return

    if target_user_dir is not None:
        # #217 fix: restrict the glob to a single subdirectory.
        if not target_user_dir.is_dir():
            return
        front_end_files = sorted(target_user_dir.glob("FrontEndTool.xml"))
        tcd_files = sorted(target_user_dir.glob("tools/*.tcd"))
    else:
        front_end_files = sorted(user_base_dir.glob("*/FrontEndTool.xml"))
        tcd_files = sorted(user_base_dir.glob("*/tools/*.tcd"))

    for front_end_file in front_end_files:
        updated, modified = patch_frontend_tool_config(front_end_file.read_text(encoding="utf-8"))
        if not modified:
            continue
        if dry_run:
            print(f"DRY RUN: patch {front_end_file}")
            continue
        _write_text_file(front_end_file, updated)
        print(f"Patched FrontEnd config {front_end_file}")

    for tcd_file in tcd_files:
        updated, modified = patch_tool_tcd(tcd_file.read_text(encoding="utf-8"))
        if not modified:
            continue
        if dry_run:
            print(f"DRY RUN: patch {tcd_file}")
            continue
        _write_text_file(tcd_file, updated)
        print(f"Patched tool config {tcd_file}")


def _find_plugin_jar(repo_root: Path) -> Path | None:
    target_dir = repo_root / "target"
    jars = sorted(
        target_dir.glob("GhidraMCP-next*.jar"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    return jars[0] if jars else None


def install_user_extension(repo_root: Path, ghidra_path: Path, archive_path: Path, *, dry_run: bool = False) -> Path:
    user_base_dir = ghidra_user_base_dir()
    user_version_dir = resolve_ghidra_user_dir(ghidra_path, user_base_dir)
    user_extensions_base = user_version_dir / "Extensions"
    user_extension_dir = user_extensions_base / "GhidraMCP-next"
    user_lib_dir = user_extension_dir / "lib"

    if dry_run:
        print(f"DRY RUN: ensure directory {user_extensions_base}")
        print(f"DRY RUN: remove stale jars matching {user_lib_dir / 'GhidraMCP-next*.jar'}")
        print(f"DRY RUN: extract {archive_path} -> {user_extensions_base}")
        return user_extension_dir

    user_extensions_base.mkdir(parents=True, exist_ok=True)
    user_lib_dir.mkdir(parents=True, exist_ok=True)
    for stale_jar in user_lib_dir.glob("GhidraMCP-next*.jar"):
        for attempt in range(10):
            try:
                stale_jar.unlink(missing_ok=True)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(1)
        print(f"Removed stale plugin jar {stale_jar}")

    try:
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(user_extensions_base)
        print(f"Installed user extension to {user_extension_dir}")
        return user_extension_dir
    except Exception as exc:
        plugin_jar = _find_plugin_jar(repo_root)
        if plugin_jar is None:
            raise RuntimeError("Extension extraction failed and no fallback plugin jar was found") from exc

        fallback_destination = user_lib_dir / "GhidraMCP-next.jar"
        shutil.copy2(plugin_jar, fallback_destination)
        print(f"Fell back to jar-only install at {fallback_destination}")
        return user_extension_dir


def find_ghidra_executable(ghidra_path: Path) -> Path:
    # Ghidra release zips ship BOTH ghidraRun (shell script) and
    # ghidraRun.bat (Windows batch) regardless of host OS, so picking the
    # right one requires a platform check rather than first-match-found.
    # On Linux/macOS, returning ghidraRun.bat made subprocess.Popen try to
    # exec cmd.exe and fail with FileNotFoundError. See #191.
    if sys.platform == "win32":
        candidates = [
            ghidra_path / "ghidraRun.bat",
            ghidra_path / "ghidraRun",
            ghidra_path / "ghidra",
        ]
    else:
        candidates = [
            ghidra_path / "ghidraRun",
            ghidra_path / "ghidra",
            ghidra_path / "ghidraRun.bat",
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"Unable to find Ghidra launcher under {ghidra_path}")


def find_plugin_archive(repo_root: Path) -> Path:
    target_dir = repo_root / "target"
    archives = sorted(
        target_dir.glob("GhidraMCP-next*.zip"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if archives:
        return archives[0]

    raise FileNotFoundError("No GhidraMCP-next plugin archive found in target/")


def print_command(command: list[str]) -> None:
    print(" ".join(command))


def resolve_mcp_url(repo_root: Path) -> str:
    env_values = load_env_file(repo_root / ".env")
    if env_values.get("GHIDRA_MCP_URL"):
        return env_values["GHIDRA_MCP_URL"].rstrip("/")
    port = env_values.get("GHIDRA_MCP_PORT", "8089").strip() or "8089"
    bind = env_values.get("GHIDRA_MCP_BIND_ADDRESS", "127.0.0.1").strip()
    if not bind or bind in {"0.0.0.0", "::"}:
        bind = "127.0.0.1"
    return f"http://{bind}:{port}".rstrip("/")


def _mcp_headers(repo_root: Path) -> dict[str, str]:
    env_values = load_env_file(repo_root / ".env")
    token = env_values.get("GHIDRA_MCP_AUTH_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _mcp_request(
    repo_root: Path,
    mcp_url: str,
    path: str,
    *,
    method: str = "GET",
    data: dict | None = None,
    params: dict | None = None,
    timeout: int = 10,
) -> tuple[int, object]:
    body = None
    headers = _mcp_headers(repo_root)
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = f"{mcp_url}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        text = response.read().decode("utf-8", errors="replace")
        try:
            parsed: object = json.loads(text)
        except ValueError:
            parsed = text
        return response.status, parsed


def _enumerate_ghidra_processes() -> list[dict[str, object]]:
    """Return every running Ghidra process on this machine, install-agnostic.

    Each entry is {pid, name, command}. The earlier
    _find_matching_ghidra_processes filtered by install path on the same
    pass, which silently missed Ghidras running from a *different*
    install during a version-changing deploy — see the v5.10→v5.11
    Ghidra-12.1 deploy where an old 12.0.4 was still up but went
    undetected. This helper does the cross-platform process scan once;
    callers filter by path themselves.
    """
    if os.name == "nt":
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-CimInstance Win32_Process | "
                "Where-Object { $_.Name -match '^(javaw?|ghidra).*' } | "
                "Select-Object ProcessId,Name,ExecutablePath,CommandLine | "
                "ConvertTo-Json -Compress"
            ),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        raw = json.loads(completed.stdout)
        rows = raw if isinstance(raw, list) else [raw]
        out: list[dict[str, object]] = []
        for row in rows:
            cmd = str(row.get("CommandLine") or "")
            name = str(row.get("Name") or "").lower()
            cmd_lower = cmd.lower()
            is_ghidra = name in {"java.exe", "javaw.exe", "ghidrarun.bat", "ghidrarun"} and (
                "ghidra.ghidra" in cmd_lower or "ghidrarun" in cmd_lower
            )
            if is_ghidra:
                out.append(
                    {
                        "pid": int(row["ProcessId"]),
                        "name": row.get("Name", ""),
                        "command": cmd,
                    }
                )
        return out
    ps = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True, check=False)
    out = []
    for line in ps.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text, _, command = stripped.partition(" ")
        command_lower = command.lower()
        if "ghidra.ghidra" in command_lower or "ghidrarun" in command_lower:
            out.append({"pid": int(pid_text), "name": "process", "command": command})
    return out


def _find_matching_ghidra_processes(ghidra_path: Path) -> list[dict[str, object]]:
    """Ghidra processes whose command-line includes ``ghidra_path``.

    Used by the deploy flow to identify the install we're targeting so
    it can be gracefully shut down before extension replacement. For
    processes that match *other* Ghidra installs, see
    ``_find_mismatched_ghidra_processes`` — those would be warned about
    rather than auto-shut-down, because they may belong to unrelated
    work the operator hasn't agreed to close.
    """
    target = str(ghidra_path.resolve()).lower()
    return [proc for proc in _enumerate_ghidra_processes() if target in str(proc["command"]).lower()]


def _find_mismatched_ghidra_processes(ghidra_path: Path) -> list[dict[str, object]]:
    """Ghidra processes from a DIFFERENT install than ``ghidra_path``.

    Surfaced as a warning at deploy time so a version-mixing scenario
    is visible: an old Ghidra still bound to MCP port 8089 will respond
    to the deploy's post-start smoke checks instead of the just-deployed
    new version, producing confusing "wrong version" failures.
    """
    target = str(ghidra_path.resolve()).lower()
    return [proc for proc in _enumerate_ghidra_processes() if target not in str(proc["command"]).lower()]


def _terminate_process(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False)
    else:
        os.kill(pid, signal.SIGKILL)


def close_running_ghidra_for_deploy(
    repo_root: Path,
    ghidra_path: Path,
    *,
    mcp_url: str,
    dry_run: bool = False,
    wait_seconds: int = DEFAULT_GHIDRA_EXIT_WAIT_SECONDS,
) -> bool:
    # Warn about Ghidras running from a DIFFERENT install. We don't
    # touch them (they may belong to unrelated work the operator hasn't
    # agreed to close), but surfacing them keeps a version-mixing
    # scenario from going undetected: an old Ghidra still bound to MCP
    # port 8089 will respond to the deploy's post-start smoke checks
    # instead of the just-deployed new version, producing confusing
    # "wrong version" failures. This was the v5.10→v5.11 deploy gap
    # the user flagged after the Ghidra 12.0.4 → 12.1 cutover.
    mismatched = _find_mismatched_ghidra_processes(ghidra_path)
    if mismatched:
        print(
            f"WARNING: {len(mismatched)} Ghidra process(es) running from a "
            f"DIFFERENT install than deploy target {ghidra_path}:"
        )
        for proc in mismatched:
            print(f"  PID {proc['pid']}: {proc['command']}")
        print(
            "  These may bind MCP port 8089 and intercept the post-deploy "
            "smoke checks intended for the new install. If the deploy's "
            "version probe reports the wrong version, close the other "
            "Ghidra(s) (save work first) and re-run."
        )

    matches = _find_matching_ghidra_processes(ghidra_path)
    if not matches:
        print("No matching running Ghidra process detected.")
        return False
    for proc in matches:
        print(f"Detected running Ghidra PID {proc['pid']}: {proc['command']}")
    if dry_run:
        print(f"DRY RUN: save all open programs via {mcp_url}/save_all_programs")
        print(f"DRY RUN: graceful exit via {mcp_url}/exit_ghidra")
        for proc in matches:
            print(f"DRY RUN: force-kill PID {proc['pid']} if still running")
        return True

    try:
        _mcp_request(repo_root, mcp_url, "/save_all_programs", timeout=60)
        print("Requested save for all open Ghidra programs.")
    except Exception as exc:
        print(f"WARNING: save_all_programs failed before deploy: {exc}")
        try:
            _mcp_request(repo_root, mcp_url, "/save_program", timeout=60)
            print("Requested fallback Ghidra program save.")
        except Exception as fallback_exc:
            print(f"WARNING: fallback save_program failed before deploy: {fallback_exc}")
    try:
        _mcp_request(repo_root, mcp_url, "/exit_ghidra", timeout=10)
        print("Requested graceful Ghidra exit.")
    except Exception as exc:
        print(f"WARNING: exit_ghidra failed before deploy: {exc}")

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if not _find_matching_ghidra_processes(ghidra_path):
            print("Ghidra exited cleanly.")
            return True
        time.sleep(1)
    for proc in _find_matching_ghidra_processes(ghidra_path):
        print(f"Force-killing Ghidra PID {proc['pid']}.")
        _terminate_process(int(proc["pid"]))
    return True


def wait_for_mcp(
    repo_root: Path,
    mcp_url: str,
    *,
    timeout_seconds: int = DEFAULT_MCP_WAIT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        for path in ("/mcp/health", "/health", "/check_connection"):
            try:
                status, _payload = _mcp_request(repo_root, mcp_url, path, timeout=5)
                if status == 200:
                    print(f"MCP ready at {mcp_url} ({path}).")
                    return
            except Exception as exc:
                last_error = exc
        time.sleep(2)
    raise RuntimeError(f"MCP did not become ready at {mcp_url}: {last_error}")


def wait_for_project(
    repo_root: Path,
    mcp_url: str,
    *,
    timeout_seconds: int = DEFAULT_MCP_WAIT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _status, payload = _mcp_request(
                repo_root,
                mcp_url,
                "/list_project_files",
                params={"folder": "/"},
                timeout=5,
            )
            if isinstance(payload, dict) and "error" not in payload:
                print("Ghidra project is ready.")
                return
            last_error = RuntimeError(payload.get("error", str(payload)) if isinstance(payload, dict) else str(payload))
        except Exception as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"Ghidra project did not become ready: {last_error}")


def _resolve_debugger_python(repo_root: Path) -> Path | None:
    """Find the Python interpreter Ghidra's debugger launchers actually use.

    The Ghidra dbgeng / gdb / lldb launcher .bat / .sh scripts run
    ``"%OPT_PYTHON_EXE%" ...`` (defaulting to ``python``), and the
    GhidraMCP-next plugin propagates ``GHIDRA_DEBUGGER_PYTHON`` from .env into
    that variable when running the debugger live test. So the
    interpreter to install ``ghidratrace`` into is:

      1. ``GHIDRA_DEBUGGER_PYTHON`` from the environment, if set
      2. ``GHIDRA_DEBUGGER_PYTHON`` from ``<repo>/.env``, if set
      3. ``shutil.which("python")`` as the system default

    Returns ``None`` only when no resolvable interpreter is found —
    rare on Windows but possible in headless CI containers.
    """
    candidate = os.environ.get("GHIDRA_DEBUGGER_PYTHON", "").strip()
    if not candidate:
        env_values = load_env_file(repo_root / ".env")
        candidate = env_values.get("GHIDRA_DEBUGGER_PYTHON", "").strip()
    if candidate:
        path = Path(candidate)
        if path.is_file():
            return path
    fallback = shutil.which("python")
    return Path(fallback) if fallback else None


def install_ghidratrace_for_debugger(
    repo_root: Path,
    ghidra_path: Path,
    *,
    dry_run: bool = False,
) -> int:
    """Install the matching ``ghidratrace`` wheel into the launcher Python.

    Why this exists: when Ghidra is upgraded (e.g., 12.0.4 → 12.1), the
    wheel that ships at ``<ghidra>/Ghidra/Debug/Debugger-rmi-trace/pypkg/dist``
    bumps version too. If a stale 12.0 ``ghidratrace`` is still
    pip-installed in the launcher's Python, TraceRmi negotiation fails
    with ``VersionMismatchError: Front-end: 12.1, back-end: 12.0`` —
    observed twice in this release cycle. The wheel lives inside the
    Ghidra install (not on PyPI), so the bridge environment cannot provide it.

    Returns 0 on success / no-op, nonzero on installer failure.
    """
    wheel_dir = ghidra_path / "Ghidra" / "Debug" / "Debugger-rmi-trace" / "pypkg" / "dist"
    wheels = sorted(wheel_dir.glob("ghidratrace-*-py3-none-any.whl"))
    if not wheels:
        print(f"  No ghidratrace wheel found under {wheel_dir} — skipping debugger Python sync")
        return 0
    wheel = wheels[-1]

    debugger_python = _resolve_debugger_python(repo_root)
    if debugger_python is None:
        print("  Could not resolve a debugger Python (set GHIDRA_DEBUGGER_PYTHON) — skipping")
        return 0

    if dry_run:
        print(f"DRY RUN: {debugger_python} -m pip install --force-reinstall {wheel}")
        print(f"DRY RUN: {debugger_python} -m pip install --upgrade 'protobuf>=6.31.0'")
        return 0

    # protobuf>=6.31.0 is gated separately by ghidratrace.setuputils — install
    # it before the wheel so the post-install setuputils check doesn't trip.
    pb = subprocess.run(
        [str(debugger_python), "-m", "pip", "install", "--upgrade", "protobuf>=6.31.0"],
        check=False,
        capture_output=True,
        text=True,
    )
    if pb.returncode != 0:
        print(f"  protobuf install failed: {pb.stderr.strip()[:200]}")
        return pb.returncode

    gt = subprocess.run(
        [str(debugger_python), "-m", "pip", "install", "--force-reinstall", str(wheel)],
        check=False,
        capture_output=True,
        text=True,
    )
    if gt.returncode != 0:
        print(f"  ghidratrace install failed: {gt.stderr.strip()[:200]}")
        return gt.returncode

    print(f"  Installed {wheel.name} into {debugger_python}")
    return 0


def install_ghidra_dependencies(
    repo_root: Path,
    ghidra_path: Path,
    *,
    force: bool = False,
    dry_run: bool = False,
) -> int:
    maven_command = str(find_maven_command())
    ghidra_version = read_pom_ghidra_version(repo_root)
    m2_root = Path.home() / ".m2" / "repository" / "ghidra"

    for artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        if not jar_path.is_file():
            raise FileNotFoundError(f"Missing required Ghidra jar: {jar_path}")

        cached_jar = m2_root / artifact_id / ghidra_version / f"{artifact_id}-{ghidra_version}.jar"
        if cached_jar.is_file() and not force:
            print(f"Skipping already installed dependency: {artifact_id}")
            continue

        command = [
            maven_command,
            "install:install-file",
            f"-Dfile={jar_path}",
            "-DgroupId=ghidra",
            f"-DartifactId={artifact_id}",
            f"-Dversion={ghidra_version}",
            "-Dpackaging=jar",
            "-DgeneratePom=true",
        ]
        if dry_run:
            print("DRY RUN:", end=" ")
            print_command(command)
            continue

        completed = subprocess.run(command, cwd=repo_root, check=False)
        if completed.returncode != 0:
            return completed.returncode

    # Keep the debugger launcher's Python in sync with the installed
    # Ghidra version's ghidratrace wheel. Without this, a Ghidra version
    # bump leaves a stale ghidratrace pip-installed in the launcher's
    # Python and TraceRmi negotiation fails with the back-end reporting
    # the old version. Best-effort: a failure here does NOT block the
    # main JAR-install dependency setup since most users don't use the
    # live debugger.
    install_ghidratrace_for_debugger(repo_root, ghidra_path, dry_run=dry_run)

    return 0


def test_write_access(path_to_test: Path) -> bool:
    try:
        path_to_test.mkdir(parents=True, exist_ok=True)
        probe = path_to_test / ".ghidra-mcp-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def collect_preflight_issues(
    repo_root: Path,
    ghidra_path: Path,
    *,
    strict: bool = False,
    user_base_dir: Path | None = None,
) -> list[str]:
    from .requirements import ensure_uv_available

    issues: list[str] = []

    try:
        ensure_uv_available()
    except FileNotFoundError as exc:
        issues.append(str(exc))

    if shutil.which("java") is None:
        issues.append("Java not found on PATH (JDK 21 recommended).")

    try:
        find_ghidra_executable(ghidra_path)
    except FileNotFoundError:
        issues.append(f"Ghidra executable not found at: {ghidra_path}")
        return issues

    for _artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        if not jar_path.is_file():
            issues.append(f"Missing required Ghidra dependency: {jar_path}")

    extensions_dir = ghidra_path / "Extensions" / "Ghidra"
    if not test_write_access(extensions_dir):
        issues.append(f"No write access to Ghidra extensions directory: {extensions_dir}")

    user_extension_dir = resolve_ghidra_user_dir(ghidra_path, user_base_dir) / "Extensions"
    if not test_write_access(user_extension_dir):
        issues.append(f"No write access to user extension directory: {user_extension_dir}")

    if strict:
        for url in ("https://repo.maven.apache.org", "https://pypi.org"):
            try:
                request = urllib.request.Request(url, method="HEAD")
                with urllib.request.urlopen(request, timeout=10):
                    pass
            except Exception:
                issues.append(f"Network check failed: {url}")

    return issues


def build_bridge_wheel(repo_root: Path, *, dry_run: bool = False) -> Path | None:
    """Build the bridge wheel with ``uv build`` and return its path.

    The Python bridge ships as a wheel (``ghidra_mcp_bridge-*.whl``) rather than
    a loose ``ghidra_mcp_bridge.py`` script. Returns the newest built wheel, or
    None on a dry run / when no wheel is produced.
    """
    from .requirements import ensure_uv_available

    dist_dir = repo_root / "dist"
    if dry_run:
        print(f"DRY RUN: uv build --wheel (-> {dist_dir})")
        return None
    uv = ensure_uv_available()
    subprocess.run([uv, "build", "--wheel"], check=True, cwd=str(repo_root))
    wheels = sorted(dist_dir.glob("ghidra_mcp_bridge-*.whl"), key=lambda p: p.stat().st_mtime)
    return wheels[-1] if wheels else None


def deploy_to_ghidra(
    repo_root: Path,
    ghidra_path: Path,
    *,
    dry_run: bool = False,
) -> int:
    archive_path = find_plugin_archive(repo_root)
    extensions_dir = ghidra_path / "Extensions" / "Ghidra"
    destination_archive = extensions_dir / archive_path.name
    dotenv_source = repo_root / ".env"
    user_base_dir = ghidra_user_base_dir()
    mcp_url = resolve_mcp_url(repo_root)
    close_running_ghidra_for_deploy(repo_root, ghidra_path, mcp_url=mcp_url, dry_run=dry_run)

    if dry_run:
        print(f"DRY RUN: ensure directory {extensions_dir}")
        print(f"DRY RUN: remove existing archives matching {extensions_dir / 'GhidraMCP-next*.zip'}")
        print(f"DRY RUN: copy {archive_path} -> {destination_archive}")
        build_bridge_wheel(repo_root, dry_run=True)
        print(f"DRY RUN: copy built bridge wheel -> {ghidra_path}")
        if dotenv_source.is_file():
            print(f"DRY RUN: copy {dotenv_source} -> {ghidra_path / dotenv_source.name}")
        install_user_extension(repo_root, ghidra_path, archive_path, dry_run=True)
        target_user_dir = resolve_ghidra_user_dir(ghidra_path, user_base_dir)
        patch_ghidra_user_configs(user_base_dir, target_user_dir, dry_run=True)
        start_ghidra(ghidra_path, repo_root=repo_root, dry_run=True)
        print(f"DRY RUN: wait up to {DEFAULT_MCP_WAIT_SECONDS}s for MCP at {mcp_url}")
        print(f"DRY RUN: wait up to {DEFAULT_MCP_WAIT_SECONDS}s for active project")
        return 0

    extensions_dir.mkdir(parents=True, exist_ok=True)
    for existing_archive in extensions_dir.glob("GhidraMCP-next*.zip"):
        existing_archive.unlink()

    shutil.copy2(archive_path, destination_archive)
    print(f"Installed plugin archive to {destination_archive}")

    bridge_wheel = build_bridge_wheel(repo_root)
    if bridge_wheel is not None and bridge_wheel.is_file():
        wheel_destination = ghidra_path / bridge_wheel.name
        wheel_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bridge_wheel, wheel_destination)
        print(f"Copied bridge wheel to {wheel_destination}")

    if dotenv_source.is_file():
        dotenv_destination = ghidra_path / dotenv_source.name
        shutil.copy2(dotenv_source, dotenv_destination)
        print(f"Copied .env to {dotenv_destination}")

    install_user_extension(repo_root, ghidra_path, archive_path)
    target_user_dir = resolve_ghidra_user_dir(ghidra_path, user_base_dir)
    patch_ghidra_user_configs(user_base_dir, target_user_dir)
    start_ghidra(ghidra_path, repo_root=repo_root)
    wait_for_mcp(repo_root, mcp_url, timeout_seconds=DEFAULT_MCP_WAIT_SECONDS)
    wait_for_project(repo_root, mcp_url, timeout_seconds=DEFAULT_MCP_WAIT_SECONDS)

    return 0


def start_ghidra(ghidra_path: Path, *, repo_root: Path | None = None, dry_run: bool = False) -> int:
    executable = find_ghidra_executable(ghidra_path)
    env_root = repo_root if repo_root is not None else Path.cwd()
    env_values = load_env_file(env_root / ".env")
    project_path = env_values.get("GHIDRA_PROJECT_PATH", "").strip()
    if executable.suffix.lower() in {".bat", ".cmd"}:
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/c", str(executable)]
    else:
        command = [str(executable)]
    if project_path:
        command.append(project_path)

    if dry_run:
        print("DRY RUN:", end=" ")
        print_command(command)
        return 0

    subprocess.Popen(
        command,
        cwd=ghidra_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name == "posix",
    )
    print(f"Started Ghidra from {executable}")
    return 0


def clean_all(repo_root: Path, *, dry_run: bool = False) -> int:
    paths_to_remove = [
        repo_root / "target",
        repo_root / ".pytest_cache",
        repo_root / "__pycache__",
    ]

    log_dir = repo_root / "logs"
    log_files = sorted(log_dir.glob("*.log")) if log_dir.is_dir() else []

    for path in paths_to_remove:
        if not path.exists():
            continue
        if dry_run:
            print(f"DRY RUN: remove {path}")
            continue
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)

    for log_file in log_files:
        if dry_run:
            print(f"DRY RUN: remove {log_file}")
            continue
        log_file.unlink(missing_ok=True)

    print("Cleanup completed.")
    return 0
