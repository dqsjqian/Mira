#!/usr/bin/env python3
"""Run CTest's compiled tests inside an iOS simulator or Android emulator.

Host-side Python interop harnesses are reported as skipped, never as passed.
Contract/death tests retain their exact expected exit status (77). The JSON
report and per-test logs live in the selected build directory.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("ios", "android"), required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--match", default="")
    args = parser.parse_args()
    build = args.build.resolve()
    tests = json.loads(subprocess.check_output(
        ["ctest", "--test-dir", str(build), "--show-only=json-v1"], text=True))["tests"]
    logs = build / "mobile-results"
    logs.mkdir(exist_ok=True)
    remote_root = "/data/local/tmp/mira-tests"
    uploaded: dict[str, str] = {}

    def adb(*words: str, **kwargs):
        return subprocess.run([args.adb, "-s", args.device, *words], check=True, **kwargs)

    def remote(path: str) -> str:
        if path in uploaded:
            return uploaded[path]
        source = Path(path).resolve()
        relative = source.relative_to(build).as_posix()
        target = remote_root + "/" + relative
        adb("shell", "mkdir", "-p", str(Path(target).parent), stdout=subprocess.DEVNULL)
        adb("push", str(source), target, stdout=subprocess.DEVNULL)
        adb("shell", "chmod", "700" if os.access(source, os.X_OK) else "600", target,
            stdout=subprocess.DEVNULL)
        uploaded[path] = target
        return target

    results = []
    for test in tests:
        name = test["name"]
        if args.match and args.match not in name:
            continue
        command = test.get("command", [])
        expected = 0
        if command and Path(command[0]).name.lower().startswith("cmake"):
            program = next((s.removeprefix("-DPROGRAM=") for s in command if s.startswith("-DPROGRAM=")), None)
            mode = next((s.removeprefix("-DMODE=") for s in command if s.startswith("-DMODE=")), None)
            if program and mode and command[-1].endswith("check_terminates.cmake"):
                command = [program, mode]
                expected = 77
        if not command or not Path(command[0]).is_relative_to(build):
            results.append({"test": name, "status": "skipped", "reason": "host-side harness"})
            print(f"SKIP {name}: host-side harness", flush=True)
            continue
        properties = {p["name"]: p["value"] for p in test.get("properties", [])}
        timeout = max(15, int(properties.get("TIMEOUT", 90)))
        # These contract modes install a deliberate exit-73 handler. Do not
        # treat an arbitrary nonzero crash as satisfying CTest WILL_FAIL.
        if properties.get("WILL_FAIL") and "--death" in command:
            expected = 73
        env = os.environ.copy()
        assignments = []
        for item in properties.get("ENVIRONMENT", []):
            key, value = item.split("=", 1)
            if args.platform == "android" and Path(value).is_relative_to(build):
                if Path(value).is_file():
                    value = remote(value)
                elif Path(value).is_dir():
                    value = remote_root + "/" + Path(value).relative_to(build).as_posix()
                    adb("shell", "mkdir", "-p", value, stdout=subprocess.DEVNULL)
            if args.platform == "ios":
                env["SIMCTL_CHILD_" + key] = value
            else:
                assignments.append(key + "=" + value)
        if args.platform == "ios":
            launched = ["xcrun", "simctl", "spawn", args.device, *command]
        else:
            command = [remote(value) if Path(value).is_file() and Path(value).is_relative_to(build)
                       else value for value in command]
            launched = [args.adb, "-s", args.device, "shell", "env", "TMPDIR=/data/local/tmp", *assignments, *command]
        try:
            process = subprocess.run(launched, text=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=timeout, env=env)
            output, code = process.stdout, process.returncode
            status = "passed" if code == expected else "failed"
            if "SKIP_RETURN_CODE" in properties and code == int(properties["SKIP_RETURN_CODE"]):
                status = "skipped"
            if any(re.search(pattern, output) for pattern in properties.get("FAIL_REGULAR_EXPRESSION", [])):
                status = "failed"
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            code, status = None, "timeout"
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        (logs / (safe_name + ".log")).write_text(output, encoding="utf-8")
        results.append({"test": name, "status": status, "exit": code, "expected_exit": expected})
        print(f"{status.upper()} {name}: {code} (expected {expected})", flush=True)
        if status not in ("passed", "skipped"):
            print(output[-4000:], flush=True)
    counts = {state: sum(r["status"] == state for r in results)
              for state in ("passed", "failed", "timeout", "skipped")}
    report = {"platform": args.platform, "execution": "simulator/emulator", "counts": counts, "tests": results}
    (logs / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(counts), flush=True)
    return 1 if counts["failed"] or counts["timeout"] or not counts["passed"] else 0


if __name__ == "__main__":
    sys.exit(main())
