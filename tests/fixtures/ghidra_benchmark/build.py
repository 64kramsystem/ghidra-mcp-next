"""Build the deterministic Benchmark.dll fixture from src/*.c.

Outputs (all under this fixture's build/ directory):
  Benchmark.dll   — the compiled 32-bit PE DLL, stripped of PDB
  Benchmark.map   — the MSVC map file (function → address)
  Benchmark.lib   — import library (discarded after build but produced as a side-effect)
  Benchmark.exp   — export file (same)

Usage:
    python build.py                         # default toolchain
    python build.py --clean                 # wipe build/ first
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


BENCHMARK_DIR = Path(__file__).resolve().parent
SRC_DIR = BENCHMARK_DIR / "src"
BUILD_DIR = BENCHMARK_DIR / "build"

# Toolchain registry. The live fixture is built with the supported 32-bit
# Visual Studio environment on the self-hosted Windows regression runner.
TOOLCHAINS = {
    "msvc2022": {
        "description": "Visual Studio 2022 Community (32-bit MSVC)",
        "vcvars": r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat",
        "cl_flags": [
            "/nologo",
            "/W3",
            "/O2",
            "/GF",
            "/MT",
            "/GS-",
            "/Gy",
        ],
        "link_flags": [
            "/NOLOGO",
            "/MACHINE:X86",
            "/SUBSYSTEM:WINDOWS,4.00",
            "/OPT:REF",
            "/OPT:ICF",
            "/MAP",
        ],
    },
}


_SENTINEL = "___VCVARS_SENTINEL___"


def _probe_vcvars_env(vcvars_path: str) -> dict[str, str]:
    """Run vcvars32.bat and capture the resulting environment.

    Invokes cmd.exe passing the bat path as a separate argv entry
    (avoiding shell-quoting bugs around the space in the vcvars path),
    then prints a sentinel and dumps `set`. Parses every NAME=VALUE
    pair after the sentinel. vcvars32.bat prints noisy startup banners
    and may warn about missing vswhere.exe — all pre-sentinel noise is
    discarded.
    """
    p = Path(vcvars_path)
    if not p.is_file():
        raise FileNotFoundError(f"vcvars32.bat not found at {vcvars_path}")

    out = subprocess.check_output(
        ["cmd", "/c", "call", str(p), "&&", "echo", _SENTINEL, "&&", "set"],
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    _, _, after = out.partition(_SENTINEL)
    env = {}
    for line in after.splitlines():
        line = line.rstrip()
        if "=" not in line or line.startswith("="):
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v
    if not env:
        raise RuntimeError(
            f"vcvars32.bat produced no environment. Output was:\n{out}"
        )
    return env


def _make_env_for_toolchain(tc: dict) -> dict[str, str]:
    return _probe_vcvars_env(tc["vcvars"])


def _run_command(command: list[str], env: dict[str, str], failure_label: str) -> None:
    print(f"[build][cmd]  {' '.join(command)}")
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"{failure_label} failed (exit {result.returncode}).")


def build(toolchain_name: str, clean: bool = False) -> Path:
    if toolchain_name not in TOOLCHAINS:
        raise ValueError(
            f"Unknown toolchain {toolchain_name!r}. Known: {', '.join(TOOLCHAINS)}"
        )
    tc = TOOLCHAINS[toolchain_name]

    if clean and BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    harness_source = SRC_DIR / "benchmark_debug.c"
    sources = sorted(s for s in SRC_DIR.glob("*.c") if s.name != harness_source.name)
    if not sources:
        raise RuntimeError(f"No .c sources found in {SRC_DIR}")

    env = _make_env_for_toolchain(tc)
    cl = "cl.exe"

    # Resolve cl.exe to an absolute path up front. On Windows, CreateProcess
    # uses the PARENT's PATH (not env["PATH"]) to locate the executable, so
    # a bare "cl.exe" with a doctored env would still fail. Resolve via the
    # probed env's PATH which contains the VS bin dir.
    if not Path(cl).is_absolute():
        resolved = shutil.which(cl, path=env.get("PATH", ""))
        if resolved is None:
            raise RuntimeError(
                f"Could not resolve {cl} via toolchain PATH. "
                f"First PATH entries: {env.get('PATH', '').split(os.pathsep)[:3]}"
            )
        cl = resolved

    out_dll = BUILD_DIR / "Benchmark.dll"
    out_map = BUILD_DIR / "Benchmark.map"

    print(f"[build] toolchain={toolchain_name} ({tc['description']})")

    # --- Step 1: compile every .c to .obj ---
    compile_cmd = [
        cl,
        *tc["cl_flags"],
        "/c",                        # compile only, no link
        f"/Fo{BUILD_DIR}\\",          # .obj output dir (trailing backslash required)
        *[str(s) for s in sources],
    ]
    _run_command(compile_cmd, env, "Compile")

    # --- Step 2: link the .objs into the DLL ---
    objs = sorted(BUILD_DIR.glob("*.obj"))
    if not objs:
        raise RuntimeError(f"No .obj files produced in {BUILD_DIR}")

    link_exe = str(Path(cl).parent / "link.exe")

    link_cmd = [
        link_exe,
        *tc["link_flags"],
        "/DLL",                       # output a DLL (replaces cl.exe's /LD)
        f"/OUT:{out_dll}",
        f"/MAP:{out_map}",
        # The default EntryPoint for a DLL is _DllMainCRTStartup@12;
        # link.exe picks it automatically when /DLL is set. We provide
        # DllMain ourselves in dllmain.c, so the CRT entry point is
        # happy to delegate. No /ENTRY override needed.
        *[str(o) for o in objs],
    ]
    _run_command(link_cmd, env, "Link")
    if not out_dll.is_file():
        raise RuntimeError(f"Link succeeded but {out_dll} not produced")

    out_exe = BUILD_DIR / "BenchmarkDebug.exe"
    if harness_source.is_file():
        exe_cmd = [
            cl,
            "/nologo",
            "/W3",
            "/O2",
            "/GF",
            "/MT",
            "/GS-",
            "/Gy",
            f"/Fe{out_exe}",
            str(harness_source),
            "/link",
            "/NOLOGO",
            "/MACHINE:X86",
            "/SUBSYSTEM:CONSOLE,4.00",
        ]
        _run_command(exe_cmd, env, "Debug harness build")
        if not out_exe.is_file():
            raise RuntimeError(f"Build succeeded but {out_exe} not produced")

    # Write a small manifest so downstream tools can read which toolchain
    # produced the binary — useful for the run record to include and for
    # CI to verify the binary was built with the expected toolchain.
    manifest = {
        "toolchain": toolchain_name,
        "description": tc["description"],
        "sources": [s.name for s in sources],
        "dll": out_dll.name,
        "debug_exe": out_exe.name if out_exe.is_file() else None,
        "map": out_map.name,
    }
    (BUILD_DIR / "build_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"[build] ok — {out_dll} ({out_dll.stat().st_size} bytes)")
    if out_exe.is_file():
        print(f"[build] ok - {out_exe} ({out_exe.stat().st_size} bytes)")
    return out_dll


def main():
    ap = argparse.ArgumentParser(description="Build the Ghidra benchmark fixture DLL")
    ap.add_argument(
        "--toolchain",
        default="msvc2022",
        choices=sorted(TOOLCHAINS.keys()),
        help="Which toolchain to build with (default: msvc2022)",
    )
    ap.add_argument("--clean", action="store_true", help="Wipe build/ before compiling")
    args = ap.parse_args()
    build(args.toolchain, clean=args.clean)


if __name__ == "__main__":
    main()
