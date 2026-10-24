"""Exercise disposable emulators through the real Ghidra 12.2 TraceRMI server."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(predicate, process: subprocess.Popen, label: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited with {process.returncode}")
        try:
            if predicate():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise TimeoutError(label)


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--ghidra", type=Path, default=os.environ.get("GHIDRA_INSTALL_DIR"))
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--stack", choices=("vice", "dos", "both"), default="both")
    parser.add_argument("--vice", default=shutil.which("x64sc"))
    parser.add_argument("--gdb", default=shutil.which("gdb"))
    args = parser.parse_args()
    if args.ghidra is None:
        parser.error("--ghidra or GHIDRA_INSTALL_DIR is required")
    # Ghidra's listener accepts one agent per launch, as the GUI launcher does.
    if args.stack == "both":
        for stack in ("vice", "dos"):
            command = [sys.executable, __file__, "--ghidra", str(args.ghidra),
                       "--workspace", str(args.workspace), "--stack", stack]
            if args.vice:
                command += ["--vice", args.vice]
            if args.gdb:
                command += ["--gdb", args.gdb]
            subprocess.run(command, check=True)
        return
    ghidra = args.ghidra.resolve()
    repo = Path(__file__).resolve().parents[1]
    workspace = args.workspace.resolve()
    logs = Path(tempfile.mkdtemp(prefix="ghidra-122-integration-"))
    print(f"Integration logs: {logs}", flush=True)
    subprocess.run(["mvn", "-q", "-DskipTests", "test-compile", "dependency:build-classpath",
                    "-Dmdep.outputFile=target/test-runtime-classpath.txt"], cwd=repo, check=True)
    dependencies = (repo / "target/test-runtime-classpath.txt").read_text().strip()
    classpath = os.pathsep.join([str(repo / "target/test-classes"), str(repo / "target/classes"),
                                dependencies, *(str(p) for p in (ghidra / "Ghidra").rglob("*.jar"))])
    mockito = next(Path.home().glob(".m2/repository/org/mockito/mockito-core/5.23.0/*.jar"))
    java = Path(os.environ["JAVA_HOME"]) / "bin/java"
    server_log = (logs / "server.log").open("w")
    server = subprocess.Popen([str(java), f"-javaagent:{mockito}", "-Xshare:off",
        "-Dclass.searcher.search.all.jars=true", f"-Dghidra.test.install.dir={ghidra}",
        "-cp", classpath, "com.xebyte.core.DebuggerStackHarness", str(logs)],
        stdout=server_log, stderr=subprocess.STDOUT, start_new_session=True)
    child = emulator = None
    try:
        wait_for(lambda: (logs / "ready.json").exists(), server, "TraceRMI harness")
        addresses = json.loads((logs / "ready.json").read_text())
        sys.path.insert(0, str(workspace / "c64-mcp/src"))
        from c64_mcp.ghidra_client import GhidraClient
        from c64_mcp.vice import ViceSession
        client = GhidraClient(f"http://127.0.0.1:{addresses['http_port']}")
        env = os.environ.copy()
        rmi = ghidra / "Ghidra/Debug/Debugger-rmi-trace"
        env.update(MODULE_Debugger_rmi_trace_HOME=str(rmi),
                   MODULE_Debugger_agent_gdb_HOME=str(ghidra / "Ghidra/Debug/Debugger-agent-gdb"),
                   GHIDRA_TRACE_RMI_HOST="127.0.0.1",
                   GHIDRA_TRACE_RMI_PORT=str(addresses["trace_port"]),
                   GHIDRA_TRACE_RMI_ADDR=f"127.0.0.1:{addresses['trace_port']}",
                   SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy")
        if args.stack in ("vice", "both"):
            if not args.vice:
                parser.error("--vice is required for the VICE stack")
            monitor_port = port()
            emulator = subprocess.Popen([args.vice, "-console", "-sounddev", "dummy",
                "-binarymonitor", "-binarymonitoraddress", f"ip4://127.0.0.1:{monitor_port}"],
                env=env, stdout=(logs / "vice.log").open("w"), stderr=subprocess.STDOUT,
                start_new_session=True)
            env.update(OPT_HOST="127.0.0.1", OPT_PORT=str(monitor_port),
                       OPT_PYTHON_EXE=sys.executable, OPT_LOG_LEVEL="INFO",
                       OPT_LOG_FILE=str(logs / "vice-agent.log"))
            launcher = workspace / "ghidra-vice-connector/data/debugger-launchers/vice-c64.sh"
            agent_output = logs / "vice-launcher.log"
            child = subprocess.Popen(["bash", str(launcher)], env=env,
                stdout=agent_output.open("w"), stderr=subprocess.STDOUT, start_new_session=True)
            wait_for(lambda: (logs / "vice-agent.log").exists() and
                     "Agent ready" in (logs / "vice-agent.log").read_text(), child, "VICE agent")
            session = ViceSession(client)
            connected = session.connect()
            assert connected.get("ok") is True, connected
            watchpoint = client.call_post("/debugger/set_breakpoint", {},
                                          {"address": "RAM:0010", "kind": "RW", "length": 2})
            assert watchpoint.get("status") == "set", watchpoint
            registers = session.get_registers()
            assert registers.get("ok") is True, registers
            memory = session.read_memory(bank_id=0, start=0, end=15, max_bytes=16)
            assert memory.get("ok") is True, memory
            assert memory["result"]["byte_count"] == 16, memory
            session.disconnect()
            print("PASS: c64-mcp -> GhidraMCP-next -> TraceRMI -> VICE registers/memory/watchpoint", flush=True)
            stop(child)
            stop(emulator)
            child = emulator = None
        if args.stack in ("dos", "both"):
            env.update(OPT_DOSBOX_X_PATH=str(workspace / "dosbox-x/src/dosbox-x"),
                       OPT_DOSBOX_X_CONF="", OPT_BOOT_IMAGE="", OPT_HDD_IMAGE="",
                       OPT_HDD_GEOMETRY="512,63,2,520", OPT_EXTRA_DOSBOX_X_ARGS="",
                       OPT_GDB_PATH=args.gdb or "gdb", OPT_GDB_ARGS="-nx",
                       DOSBOX_X_GDB_PORT=str(port()), DOSBOX_X_QMP_PORT=str(port()))
            launcher = workspace / "ghidra-dosbox_x-connector/data/debugger-launchers/dosbox-x-gdb.sh"
            child = subprocess.Popen(["bash", str(launcher)], env=env, stdin=subprocess.PIPE,
                stdout=(logs / "dos-launcher.log").open("w"), stderr=subprocess.STDOUT,
                start_new_session=True)
            def gdb_ready():
                state = client.target_methods()
                return str(state.get("connection_description", "")).startswith("gdb-") and state.get("pc") is not None

            wait_for(gdb_ready, child, "DOS GDB TraceRMI agent")
            registers = client.call_get("/debugger/registers", {})
            assert "error" not in registers, registers
            memory = client.call_get("/debugger/read_memory", {"address": "ffff0", "size": 16})
            assert "error" not in memory, memory
            sys.path.insert(0, str(workspace / "dos-mcp/src"))
            from dos_mcp.qmp import QmpClient
            from dos_mcp.tools import read_memory
            expected = read_memory(QmpClient(int(env["DOSBOX_X_QMP_PORT"]), 5), 0xFFFF0, 16)
            assert memory["size"] == 16 and memory["hex"] == expected["data_hex"], (memory, expected)
            print("PASS: DOSBox-X launcher -> Ghidra 12.2 GDB agent -> registers/memory", flush=True)
            child.stdin.write(b"quit\ny\n")
            child.stdin.flush()
            child.wait(timeout=10)
    finally:
        stop(child)
        stop(emulator)
        (logs / "stop").touch()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            stop(server)
        server_log.close()


if __name__ == "__main__":
    main()
