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


def vice_behavior(session, logs: Path, repo: Path) -> None:
    def result(response):
        assert response.get("ok") is True, response
        return response["result"]

    banks = result(session.list_banks())["banks"]
    ram = next(bank["id"] for bank in banks if bank["name"].lower() == "ram")

    def memory(start, size):
        data = result(session.read_memory(bank_id=ram, start=start, end=start + size - 1,
                                          max_bytes=size))
        assert data["byte_count"] == size, data
        return bytes.fromhex(data["bytes"])

    def registers():
        records = result(session.get_registers())["registers"]
        values = {record["name"]: record["value"] for record in records}
        assert set(values) == {"PC", "A", "X", "Y", "SP", "00", "01", "FL", "LIN", "CYC"}, values
        return values

    def state():
        return (b"".join(memory(start, 0x4000) for start in range(0, 0x10000, 0x4000)),
                registers())

    def checkpoint():
        checkpoints = result(session.list_checkpoints())["checkpoints"]
        assert len(checkpoints) == 1, checkpoints
        return checkpoints[0]

    def resume_to_loop(context):
        count = session.status()["stop_count"]
        result(session.resume())
        stopped = session.wait_for_stop(after_stop_count=count, timeout_ms=3000)
        assert stopped.get("ok") is True, (context, stopped)
        assert stopped["pc"] == 0xC01A, (context, stopped)

    fixture = repo / "tools/fixtures/c64-replay.hex"
    code = bytes.fromhex(" ".join(line.split("#", 1)[0] for line in fixture.read_text().splitlines()))
    result(session.write_memory(bank_id=ram, start=0xC000, bytes=code.hex()))
    result(session.write_memory(bank_id=ram, start=0xC100, bytes="ff0000"))
    result(session.write_memory(bank_id=0, start=0, bytes="2f37", side_effects=True))
    result(session.set_registers(values={"PC": 0xC000, "A": 0, "X": 0, "Y": 0,
                                         "SP": 0xFF, "FL": 0x24}))
    result(session.step(count=9))
    assert registers()["PC"] == 0xC017
    result(session.set_joyport(port=1, value=0xFF))
    assert result(session.list_checkpoints())["checkpoints"] == []
    baseline = state()
    snapshot = str(logs / "c64-baseline.vsf")
    result(session.save_snapshot(filename=snapshot))
    created = result(session.set_checkpoint(start=0xC01A, end=0xC01A))["checkpoint"]
    fields = ("number", "start", "end", "stop_on_hit", "enabled", "operations", "temporary")
    config = {key: created[key] for key in fields}
    previous_hits = created["hit_count"]
    replays = []
    for replay in range(2):
        if replay:
            result(session.load_snapshot(filename=snapshot))
            assert state() == baseline, "snapshot did not restore RAM and registers"
            current = checkpoint()
            assert {key: current[key] for key in fields} == config, current
            assert current["hit_count"] == previous_hits, current
            print("PASS: restored RAM, registers and retained checkpoint configuration/count", flush=True)
            result(session.set_joyport(port=1, value=0xFF))
        resume_to_loop("checkpoint remained listed but did not stop after snapshot load" if replay
                       else "initial checkpoint")
        current = checkpoint()
        assert current["hit_count"] == previous_hits + 1, current
        previous_hits = current["hit_count"]
        stops = [state()]
        for index, value in enumerate((0xFB, 0xFB, 0xFF)):
            if index != 1:
                result(session.set_joyport(port=1, value=value))
            before = memory(0xC100, 1)
            result(session.step())
            regs = registers()
            assert regs["PC"] == 0xC01D and regs["A"] == value, regs
            assert memory(0xC100, 1) == before
            result(session.step())
            assert registers()["PC"] == 0xC020
            assert memory(0xC100, 1) == bytes([value])
            resume_to_loop("loop checkpoint")
            regs = registers()
            assert regs["X"] == index + 1 and memory(0xC102, 1) == bytes([index + 1]), regs
            current = checkpoint()
            assert current["hit_count"] == previous_hits + 1, current
            previous_hits = current["hit_count"]
            stops.append(state())
        current = checkpoint()
        assert {key: current[key] for key in fields} == config, current
        assert current["hit_count"] == previous_hits, current
        replays.append(stops)
        if not replay:
            print("PASS: initial C64 input and exact stop/step sequence", flush=True)
    assert replays[0] == replays[1], "replayed RAM/register states differ"
    result(session.delete_checkpoint(number=created["number"]))
    result(session.set_joyport(port=1, value=0xFF))
    print("PASS: C64 snapshot replay, checkpoint persistence, joystick input and exact stops", flush=True)


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
    socket_dir = tempfile.TemporaryDirectory(prefix="gm-", dir="/tmp")
    socket_path = str(Path(socket_dir.name) / "mcp.sock")
    server_log = (logs / "server.log").open("w")
    server = subprocess.Popen([str(java), f"-javaagent:{mockito}", "-Xshare:off",
        "-Dclass.searcher.search.all.jars=true", f"-Dghidra.test.install.dir={ghidra}",
        "-cp", classpath, "com.xebyte.core.DebuggerStackHarness", str(logs), socket_path],
        stdout=server_log, stderr=subprocess.STDOUT, start_new_session=True)
    child = emulator = None
    try:
        wait_for(lambda: (logs / "ready.json").exists(), server, "TraceRMI harness")
        addresses = json.loads((logs / "ready.json").read_text())
        sys.path.insert(0, str(workspace / "c64-mcp/src"))
        from c64_mcp.ghidra_client import GhidraClient
        from c64_mcp.vice import ViceSession
        client = GhidraClient(socket_path=socket_path)
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
            vice_behavior(session, logs, repo)
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
        socket_dir.cleanup()


if __name__ == "__main__":
    main()
