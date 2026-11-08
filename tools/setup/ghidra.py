from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
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
DEFAULT_MCP_WAIT_SECONDS = 120
DEFAULT_GHIDRA_EXIT_WAIT_SECONDS = 60


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


def resolve_ghidra_user_dir(ghidra_path: Path, user_base_dir: Path | None = None) -> Path:
    """Select exactly the user directory named by the installation metadata."""
    version, release = infer_ghidra_install_meta(ghidra_path)
    if version != "12.2":
        raise ValueError(f"Ghidra 12.2 is required; found {version}")
    return (user_base_dir or ghidra_user_base_dir()) / f"ghidra_{version}_{release}"


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
    target_user_dir: Path,
    *,
    dry_run: bool = False,
) -> None:
    """Patch configuration only in the selected installation's user directory."""
    if not target_user_dir.is_dir():
        return
    front_end_files = sorted(target_user_dir.glob("FrontEndTool.xml"))
    tcd_files = sorted(target_user_dir.glob("tools/*.tcd"))

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

    # Reject an invalid archive before touching an existing installation.
    with zipfile.ZipFile(archive_path) as archive:
        damaged = archive.testzip()
        if damaged:
            raise ValueError(f"Damaged extension archive member: {damaged}")
        metadata = archive.read("GhidraMCP-next/extension.properties").decode("utf-8")
        if "version=12.2" not in metadata.splitlines():
            raise ValueError("The extension archive must target Ghidra 12.2")

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

    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(user_extensions_base)
    print(f"Installed user extension to {user_extension_dir}")
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


def _bridge_modules(repo_root: Path):
    source = str(repo_root / "python")
    if source not in sys.path:
        sys.path.insert(0, source)
    from ghidra_mcp_bridge import discovery, transport
    return discovery, transport


def _target_instances(repo_root: Path, ghidra_path: Path) -> list[dict]:
    discovery, _ = _bridge_modules(repo_root)
    pids = {int(process["pid"]) for process in _find_matching_ghidra_processes(ghidra_path)}
    return [instance for instance in discovery.discover_instances() if instance.get("pid") in pids]


def _mcp_request(repo_root: Path, socket_path: str, path: str, *, params=None, timeout=10):
    _, transport = _bridge_modules(repo_root)
    text, status = transport.request(socket_path, "GET", path, query=params, timeout=timeout)
    return status, json.loads(text)


def _find_matching_ghidra_processes(ghidra_path: Path) -> list[dict[str, object]]:
    ps = subprocess.run(["ps", "-ww", "-eo", "pid=,args="], capture_output=True, text=True, check=True)
    target = str(ghidra_path.resolve())
    matches = []
    for line in ps.stdout.splitlines():
        pid, _, command = line.strip().partition(" ")
        args = command.split()
        if args and Path(args[0]).name in {"java", "javaw"} and "ghidra.GhidraRun" in args and f"{target}/" in command:
            matches.append({"pid": int(pid), "command": command})
    return matches


def close_running_ghidra_for_deploy(repo_root: Path, ghidra_path: Path, *, dry_run: bool = False,
                                    wait_seconds: int = DEFAULT_GHIDRA_EXIT_WAIT_SECONDS) -> bool:
    matches = _find_matching_ghidra_processes(ghidra_path)
    if not matches:
        print("No matching running Ghidra process detected.")
        return False
    instances = _target_instances(repo_root, ghidra_path)
    by_pid = {instance["pid"]: instance for instance in instances}
    if {proc["pid"] for proc in matches} != set(by_pid):
        raise RuntimeError("Cannot identify MCP socket for every target Ghidra process; deployment stopped")
    for proc in matches:
        pid = int(proc["pid"])
        socket_path = by_pid[pid]["socket"]
        if dry_run:
            print(f"DRY RUN: save programs and close Ghidra PID {pid} via {socket_path}")
            continue
        status, payload = _mcp_request(repo_root, socket_path, "/save_all_programs", timeout=60)
        if status != 200 or not isinstance(payload, dict) or payload.get("success") is not True or "error" in payload:
            raise RuntimeError(f"Could not save programs for Ghidra PID {pid}: {payload}")
    for proc in matches:
        pid = int(proc["pid"])
        if dry_run:
            continue
        if sys.platform == "darwin":
            subprocess.run(["osascript", "-e", 'tell application "System Events"',
                            "-e", f"set frontmost of first application process whose unix id is {pid} to true",
                            "-e", "repeat 20 times",
                            "-e", f"if (unix id of (first application process whose frontmost is true)) is {pid} then exit repeat",
                            "-e", "delay 0.1", "-e", "end repeat",
                            "-e", f'if (unix id of (first application process whose frontmost is true)) is not {pid} then error "Ghidra did not become frontmost"',
                            "-e", 'keystroke "q" using command down', "-e", "end tell"], check=True)
        elif sys.platform.startswith("linux"):
            print(f"Close Ghidra PID {pid} using File > Exit; waiting for it to exit.")
        else:
            raise RuntimeError("Ghidra deployment supports Linux and macOS only")
    if dry_run:
        return True
    deadline = time.monotonic() + wait_seconds
    pids = {int(proc["pid"]) for proc in matches}
    while time.monotonic() < deadline:
        for pid in tuple(pids):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pids.remove(pid)
        if not pids:
            print("Ghidra exited cleanly.")
            return True
        time.sleep(1)
    raise RuntimeError("Ghidra did not exit gracefully; deployment stopped")


def wait_for_mcp(repo_root: Path, ghidra_path: Path, *, timeout_seconds: int = DEFAULT_MCP_WAIT_SECONDS) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        instances = _target_instances(repo_root, ghidra_path)
        if len(instances) == 1:
            print(f"MCP ready at {instances[0]['socket']}.")
            return instances[0]["socket"]
        if len(instances) > 1:
            raise RuntimeError("Multiple target Ghidra instances found")
        time.sleep(2)
    raise RuntimeError("Target Ghidra MCP did not become ready")


def wait_for_project(repo_root: Path, socket_path: str, *, timeout_seconds: int = DEFAULT_MCP_WAIT_SECONDS) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            status, payload = _mcp_request(repo_root, socket_path, "/list_project_files", params={"folder": "/"}, timeout=5)
            if status == 200 and isinstance(payload, dict) and "error" not in payload:
                print("Ghidra project is ready.")
                return
            last_error = payload
        except Exception as exc:
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"Ghidra project did not become ready: {last_error}")


def _resolve_debugger_python(repo_root: Path) -> Path | None:
    """Select the standalone Python used for debugger dependencies.

    VICE uses a standalone Python interpreter. GDB uses its own embedded Python,
    which this setup does not provision.
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
    """Install the bundled wheel and protobuf into standalone Python."""
    wheel_dir = ghidra_path / "Ghidra" / "Debug" / "Debugger-rmi-trace" / "pypkg" / "dist"
    wheels = sorted(wheel_dir.glob("ghidratrace-12.2-py3-none-any.whl"))
    if not wheels:
        raise FileNotFoundError(f"No ghidratrace 12.2 wheel found under {wheel_dir}")
    wheel = wheels[-1]

    debugger_python = _resolve_debugger_python(repo_root)
    if debugger_python is None:
        raise RuntimeError("Set GHIDRA_DEBUGGER_PYTHON to a standalone Python interpreter")

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
    installed_version, _ = infer_ghidra_install_meta(ghidra_path)
    if installed_version != ghidra_version:
        raise ValueError(f"Ghidra {ghidra_version} required; found {installed_version}")
    m2_root = Path.home() / ".m2" / "repository" / "ghidra"

    for artifact_id, relative_path in REQUIRED_GHIDRA_JARS:
        jar_path = ghidra_path / relative_path
        if not jar_path.is_file():
            raise FileNotFoundError(f"Missing required Ghidra jar: {jar_path}")

        cached_jar = m2_root / artifact_id / ghidra_version / f"{artifact_id}-{ghidra_version}.jar"
        if cached_jar.is_file() and not force and cached_jar.read_bytes() == jar_path.read_bytes():
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

    return install_ghidratrace_for_debugger(repo_root, ghidra_path, dry_run=dry_run)


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
        issues.append("Java not found on PATH (JDK 25 required).")

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
    close_running_ghidra_for_deploy(repo_root, ghidra_path, dry_run=dry_run)

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
        print(f"DRY RUN: wait up to {DEFAULT_MCP_WAIT_SECONDS}s for target Ghidra MCP")
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
    socket_path = wait_for_mcp(repo_root, ghidra_path, timeout_seconds=DEFAULT_MCP_WAIT_SECONDS)
    wait_for_project(repo_root, socket_path, timeout_seconds=DEFAULT_MCP_WAIT_SECONDS)

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
