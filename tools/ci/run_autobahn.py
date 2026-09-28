#!/usr/bin/env python3
"""Run official Autobahn cases in both roles; --compression includes RFC7692."""

import argparse
import collections
import contextlib
import fnmatch
import json
from pathlib import Path
import platform
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

IMAGE = "crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
EXCLUDED = ["12.*", "13.*"]
ACCEPTED = {"OK", "NON-STRICT", "INFORMATIONAL"}
# Upstream listenWS does not set an interface; the URL host does not restrict binding.
# Restrict only the listener, leaving official cases, selection and verdicts unchanged.
BOOTSTRAP = r'''
import json, sys
from autobahntestsuite import wstest, fuzzing
if sys.argv[1] == '--catalog':
    import autobahn, autobahntestsuite
    from autobahntestsuite.case import Cases, CaseBasename
    ids = ['.'.join(c.__name__[len(CaseBasename):].split('_')) for c in Cases]
    with open(sys.argv[2], 'w') as f:
        json.dump({'autobahn': autobahn.version,
                   'autobahntestsuite': autobahntestsuite.version,
                   'case_ids': ids}, f, indent=2)
else:
    original_listen = fuzzing.listenWS
    def localhost_listen(factory, contextFactory=None, *args, **kwargs):
        kwargs['interface'] = '127.0.0.1'
        return original_listen(factory, contextFactory, *args, **kwargs)
    fuzzing.listenWS = localhost_listen
    sys.argv[0] = 'wstest'
    wstest.run()
'''


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def case_key(value):
    return tuple(map(int, value.split(".")))


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(process, port):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError("Official fuzzingserver exited before becoming ready; check its log")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Official fuzzingserver startup timed out")


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@contextlib.contextmanager
def process(command, log_path, *, ready=False):
    with log_path.open("w", encoding="utf-8") as log:
        child = subprocess.Popen(command, stdout=subprocess.PIPE if ready else log,
                                 stderr=log, text=True, encoding="utf-8", errors="replace")
        lines = queue.Queue()
        reader = None
        reader_errors = []
        if ready:
            def drain():
                try:
                    for line in child.stdout:
                        log.write(line)
                        log.flush()
                        lines.put(line)
                except (OSError, UnicodeError) as exc:
                    reader_errors.append(exc)
                finally:
                    lines.put(None)
            reader = threading.Thread(target=drain)
            reader.start()
        try:
            yield child, lines
        finally:
            stop_process(child)
            if reader:
                # The harness has no child processes; exiting closes its pipe before the join.
                reader.join()
                child.stdout.close()
                if reader_errors:
                    raise RuntimeError("Failed to read Mira server output: " + str(reader_errors[0]))


def read_ready(lines):
    try:
        line = lines.get(timeout=20)
    except queue.Empty as exc:
        raise RuntimeError("Mira server did not report its listening port") from exc
    if not line or not line.startswith("PORT="):
        raise RuntimeError("Mira server startup failed")
    try:
        port = int(line.strip().split("=", 1)[1])
    except ValueError as exc:
        raise RuntimeError("Mira server reported an invalid listening port") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("Mira server reported an invalid listening port")
    return port


class Runtime:
    def __init__(self, args, directory):
        self.directory = directory
        self.docker = False
        self.image = args.image
        self.containers = []
        python = args.wstest_python
        if not python and args.runtime != "docker":
            wstest = shutil.which("wstest")
            if wstest:
                candidate = Path(wstest).resolve().with_name("python")
                if candidate.is_file():
                    python = str(candidate)
        if python and args.runtime != "docker":
            self.python = str(Path(python).resolve())
        elif args.runtime != "native" and shutil.which("docker"):
            if platform.system() != "Linux":
                raise RuntimeError("Docker mode requires Linux host networking; on other platforms, "
                                   "specify an isolated Python 2 runtime with --wstest-python")
            subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=20)
            self.docker = True
        else:
            raise RuntimeError("Official Autobahn Python 2 runtime or usable Docker not found; "
                               "the official corpus was not executed")

    def path(self, path):
        return "/work/" + str(path.relative_to(self.directory)) if self.docker else str(path)

    def command(self, arguments):
        base = ["python", "-c", BOOTSTRAP] if self.docker else [self.python, "-c", BOOTSTRAP]
        if self.docker:
            name = "mira-autobahn-" + uuid.uuid4().hex[:12]
            self.containers.append(name)
            base = ["docker", "run", "--rm", "--name", name, "--network", "host",
                    "-v", str(self.directory) + ":/work", self.image] + base
        return base + arguments

    def close(self):
        for name in self.containers:
            # Remove only containers created by this invocation, never unrelated user resources.
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20, check=False)


def summarize(report, agent, expected):
    rows = {}
    if report.is_file():
        rows = json.loads(report.read_text(encoding="utf-8")).get(agent, {})
    failed = []
    for case, result in rows.items():
        if result.get("behavior") not in ACCEPTED or result.get("behaviorClose") not in ACCEPTED:
            failed.append({"case": case, "behavior": result.get("behavior"),
                           "behavior_close": result.get("behaviorClose"),
                           "reportfile": result.get("reportfile")})
    missing = sorted(set(expected) - set(rows), key=case_key)
    unexpected = sorted(set(rows) - set(expected), key=case_key)
    non_strict = sum("NON-STRICT" in (r.get("behavior"), r.get("behaviorClose")) for r in rows.values())
    informational = sum("INFORMATIONAL" in (r.get("behavior"), r.get("behaviorClose")) for r in rows.values())
    passed = bool(rows) and not (failed or missing or unexpected)
    return {
        "expected_count": len(expected), "executed_count": len(rows),
        "behavior_counts": dict(collections.Counter(r.get("behavior") for r in rows.values())),
        "close_counts": dict(collections.Counter(r.get("behaviorClose") for r in rows.values())),
        "non_strict_count": non_strict, "informational_count": informational,
        "failed_count": len(failed), "failed": sorted(failed, key=lambda row: case_key(row["case"])),
        "missing_count": len(missing), "missing": missing, "unexpected": unexpected,
        "passed": passed, "strict_passed": passed and not (non_strict or informational),
        "index": str(report),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parents[2] / "build/followup-autobahn")
    parser.add_argument("--runtime", choices=["auto", "native", "docker"], default="auto")
    parser.add_argument("--wstest-python", help="Isolated Python 2 interpreter with the official testsuite installed")
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--case-timeout", type=int, default=300)
    parser.add_argument("--cases", nargs="+", default=["*"], help="Diagnostic subset; the summary is marked partial")
    parser.add_argument("--compression", action="store_true", help="include RFC7692 compression cases 12.* and 13.*")
    args = parser.parse_args()
    excluded_patterns = [] if args.compression else EXCLUDED.copy()
    if not 1 <= args.timeout <= 86400 or not 1 <= args.case_timeout <= 3600:
        parser.error("timeout must be in 1..86400 and case-timeout must be in 1..3600")
    args.server = args.server.resolve()
    args.client = args.client.resolve()
    output = args.output.resolve()
    run_dir = output / (time.strftime("run-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])
    summary = {"status": "blocked", "scope": "full" if args.cases == ["*"] else "partial",
               "suite": "official crossbario/autobahn-testsuite", "run_directory": str(run_dir),
               "case_patterns": args.cases, "accepted_behaviors": sorted(ACCEPTED),
               "compression": args.compression, "excluded_patterns": excluded_patterns,
               "excluded_reason": None if args.compression else "Compression cases require --compression",
               "excluded_count": None, "executed_count": 0, "failed_count": None,
               "non_strict_count": None, "informational_count": None, "strict_passed": False,
               "harness_limits": {"max_frame": 67108864, "max_message": 67108864},
               "network": "127.0.0.1 only; official web UI disabled", "errors": []}
    runtime = None
    try:
        output.mkdir(parents=True, exist_ok=True)
        run_dir.mkdir()
        if not args.server.is_file() or not args.client.is_file():
            raise RuntimeError("Mira Autobahn harness executables not found; build both targets first")
        runtime = Runtime(args, run_dir)
        summary["runtime"] = {"kind": "docker" if runtime.docker else "native",
                              "image": runtime.image if runtime.docker else None}
        catalog_path = run_dir / "catalog.json"
        with (run_dir / "catalog.log").open("w", encoding="utf-8") as log:
            subprocess.run(runtime.command(["--catalog", runtime.path(catalog_path)]),
                           stdout=log, stderr=log, check=True, timeout=180)
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        summary["versions"] = {key: catalog[key] for key in ("autobahn", "autobahntestsuite")}
        all_cases = set(catalog["case_ids"])
        excluded = sorted((c for c in all_cases if any(fnmatch.fnmatchcase(c, p) for p in excluded_patterns)), key=case_key)
        expected = sorted((c for c in all_cases - set(excluded)
                           if any(fnmatch.fnmatchcase(c, p) for p in args.cases)), key=case_key)
        summary.update({"catalog_count": len(all_cases), "excluded_count": len(excluded),
                        "excluded": excluded, "selected_count_per_role": len(expected),
                        "selected": expected, "status": "running"})
        if not expected:
            raise RuntimeError("No official cases selected; refusing an empty passing result")
        common = {"cases": expected, "exclude-cases": excluded_patterns, "exclude-agent-cases": {}}
        server_reports = run_dir / "servers"
        try:
            with process([str(args.server), "0", str(args.timeout)], run_dir / "mira-server.log", ready=True) as (server, lines):
                port = read_ready(lines)
                spec = dict(common, outdir=runtime.path(server_reports),
                            servers=[{"agent": "Mira-server", "url": "ws://127.0.0.1:" + str(port)}])
                spec_path = run_dir / "fuzzingclient.json"
                write_json(spec_path, spec)
                with process(runtime.command(["-m", "fuzzingclient", "-s", runtime.path(spec_path), "-u", "0"]),
                             run_dir / "fuzzingclient.log") as (fuzzer, _):
                    summary["fuzzingclient_exit"] = fuzzer.wait(timeout=args.timeout)
            summary["mira_server_exit"] = server.returncode
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            summary["errors"].append("server: " + str(exc))
        summary["server"] = summarize(server_reports / "index.json", "Mira-server", expected)
        write_json(output / "summary.json", summary)

        client_reports = run_dir / "clients"
        try:
            port = unused_port()
            spec = dict(common, url="ws://127.0.0.1:" + str(port), outdir=runtime.path(client_reports))
            spec_path = run_dir / "fuzzingserver.json"
            write_json(spec_path, spec)
            with process(runtime.command(["-m", "fuzzingserver", "-s", runtime.path(spec_path), "-u", "0"]),
                         run_dir / "fuzzingserver.log") as (fuzzer, _):
                wait_port(fuzzer, port)
                with process([str(args.client), str(port), str(args.case_timeout)],
                             run_dir / "mira-client.log") as (client, _):
                    summary["mira_client_exit"] = client.wait(timeout=args.timeout)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            summary["errors"].append("client: " + str(exc))
        summary["client"] = summarize(client_reports / "index.json", "Mira-client", expected)
        for field in ("executed_count", "failed_count", "non_strict_count", "informational_count"):
            summary[field] = summary["server"][field] + summary["client"][field]
        success = (summary["server"]["passed"] and summary["client"]["passed"] and
                   not summary["errors"] and summary.get("fuzzingclient_exit") == 0 and
                   summary.get("mira_server_exit") == 0 and summary.get("mira_client_exit") == 0)
        summary["status"] = "passed" if success else "failed"
        summary["strict_passed"] = success and summary["server"]["strict_passed"] and summary["client"]["strict_passed"]
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        summary["errors"].append("Autobahn run failed: " + str(exc))
        if summary["status"] == "running":
            summary["status"] = "failed"
    finally:
        if runtime:
            try:
                runtime.close()
            except (OSError, subprocess.SubprocessError) as exc:
                summary["errors"].append("Autobahn runtime cleanup failed: " + str(exc))
                summary["status"] = "failed"
                summary["strict_passed"] = False
        for path in (run_dir / "summary.json", output / "summary.json"):
            try:
                write_json(path, summary)
            except (OSError, UnicodeError) as exc:
                summary["errors"].append("Cannot write Autobahn summary to " + str(path) + ": " + str(exc))
                if summary["status"] == "passed":
                    summary["status"] = "failed"
                summary["strict_passed"] = False
    print(json.dumps({"status": summary["status"], "scope": summary["scope"],
                      "compression": summary["compression"],
                      "executed_count": summary["executed_count"],
                      "non_strict_count": summary["non_strict_count"],
                      "informational_count": summary["informational_count"],
                      "strict_passed": summary["strict_passed"],
                      "excluded_count_per_role": summary["excluded_count"],
                      "summary": str(output / "summary.json"), "errors": summary["errors"]},
                     ensure_ascii=True, indent=2))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
