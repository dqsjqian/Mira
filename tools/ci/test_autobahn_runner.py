#!/usr/bin/env python3
"""Test runner verdicts and process handling without installing or running Autobahn."""

import contextlib
import io
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import run_autobahn as runner


class TemporaryFiles(unittest.TestCase):
    def setUp(self):
        build = Path(__file__).resolve().parents[2] / "build"
        build.mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix="autobahn-runner-test-", dir=build)
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)


class SummaryTests(TemporaryFiles):
    def report(self, rows, expected=("1.1.1",), agent="Mira-server"):
        path = self.directory / "index.json"
        runner.write_json(path, {agent: rows})
        return runner.summarize(path, "Mira-server", expected)

    def test_complete_nonempty_report_passes(self):
        result = self.report({"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}})
        self.assertTrue(result["passed"])
        self.assertTrue(result["strict_passed"])
        self.assertEqual(result["executed_count"], 1)
        self.assertEqual(result["non_strict_count"], 0)

    def test_missing_empty_and_wrong_agent_reports_fail(self):
        missing = runner.summarize(self.directory / "missing.json", "Mira-server", ["1.1.1"])
        for result in (missing, self.report({}), self.report({}, expected=()),
                       self.report({"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}, agent="other")):
            with self.subTest(result=result):
                self.assertFalse(result["passed"])
                self.assertFalse(result["strict_passed"])
                self.assertEqual(result["executed_count"], 0)

    def test_missing_and_unexpected_cases_fail(self):
        rows = {"1.1.1": {"behavior": "OK", "behaviorClose": "OK"}}
        missing = self.report(rows, expected=("1.1.1", "1.1.2", "1.1.10"))
        self.assertFalse(missing["passed"])
        self.assertEqual(missing["missing"], ["1.1.2", "1.1.10"])
        self.assertEqual(missing["missing_count"], 2)
        unexpected = self.report(rows, expected=())
        self.assertFalse(unexpected["passed"])
        self.assertEqual(unexpected["unexpected"], ["1.1.1"])

    def test_failure_and_unknown_verdicts_are_never_accepted(self):
        for field in ("behavior", "behaviorClose"):
            for verdict in ("FAILED", "WRONG CODE", "UNCLEAN", "unknown", None):
                with self.subTest(field=field, verdict=verdict):
                    row = {"behavior": "OK", "behaviorClose": "OK", "reportfile": "case.json"}
                    row[field] = verdict
                    result = self.report({"1.1.1": row})
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["strict_passed"])
                    self.assertEqual(result["failed_count"], 1)
                    self.assertEqual(result["failed"][0]["reportfile"], "case.json")
        self.assertFalse(self.report({"1.1.1": {}})["passed"])

    def test_non_strict_is_accepted_but_counted_separately(self):
        rows = {"1.1.1": {"behavior": "NON-STRICT", "behaviorClose": "NON-STRICT"},
                "1.1.2": {"behavior": "OK", "behaviorClose": "NON-STRICT"}}
        result = self.report(rows, expected=rows)
        self.assertTrue(result["passed"])
        self.assertFalse(result["strict_passed"])
        self.assertEqual(result["non_strict_count"], 2)
        self.assertEqual(result["behavior_counts"]["NON-STRICT"], 1)
        self.assertEqual(result["close_counts"]["NON-STRICT"], 2)

    def test_informational_is_not_a_strict_pass(self):
        result = self.report({"1.1.1": {"behavior": "INFORMATIONAL", "behaviorClose": "OK"}})
        self.assertTrue(result["passed"])
        self.assertFalse(result["strict_passed"])
        self.assertEqual(result["informational_count"], 1)


class MainTests(TemporaryFiles):
    def run_fixture(self, *, cases=None, catalog=("1.1.1", "1.1.2", "12.1.1", "13.1.1"),
                    verdict="OK", omit_client=False):
        output = self.directory / "results"
        binary = self.directory / "harness"
        binary.touch()
        arguments = ["run_autobahn.py", "--server", str(binary), "--client", str(binary),
                     "--output", str(output)]
        if cases is not None:
            arguments += ["--cases", *cases]
        runtime = mock.Mock(docker=False, image=runner.IMAGE)
        runtime.path.side_effect = str
        runtime.command.side_effect = lambda arguments: arguments

        def write_catalog(command, **kwargs):
            self.assertEqual(command[0], "--catalog")
            runner.write_json(Path(command[1]), {"autobahn": "fixture", "autobahntestsuite": "fixture",
                                                 "case_ids": list(catalog)})

        def write_report(spec_path, agent):
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            selected = spec["cases"]
            if agent == "Mira-client" and omit_client:
                selected = selected[:-1]
            reports = Path(spec["outdir"])
            reports.mkdir()
            rows = {case: {"behavior": verdict, "behaviorClose": "OK"} for case in selected}
            runner.write_json(reports / "index.json", {agent: rows})

        @contextlib.contextmanager
        def fake_process(command, log_path, *, ready=False):
            child = mock.Mock(returncode=0)
            child.wait.return_value = 0
            lines = queue.Queue()
            if ready:
                lines.put("PORT=12345\n")
            elif log_path.name == "fuzzingclient.log":
                write_report(Path(command[command.index("-s") + 1]), "Mira-server")
            elif log_path.name == "mira-client.log":
                write_report(log_path.parent / "fuzzingserver.json", "Mira-client")
            yield child, lines

        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", arguments), mock.patch.object(runner, "Runtime", return_value=runtime), \
                mock.patch.object(runner.subprocess, "run", side_effect=write_catalog), \
                mock.patch.object(runner, "process", side_effect=fake_process), \
                mock.patch.object(runner, "wait_port"), mock.patch.object(runner, "unused_port", return_value=12346), \
                contextlib.redirect_stdout(stdout):
            code = runner.main()
        runtime.close.assert_called_once()
        result = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        saved = json.loads((Path(result["run_directory"]) / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(result, saved)
        return code, result, json.loads(stdout.getvalue())

    def test_full_scope_counts_both_roles_and_explicit_exclusions(self):
        code, summary, printed = self.run_fixture()
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["scope"], "full")
        self.assertEqual(summary["executed_count"], 4)
        self.assertEqual(summary["excluded_count"], 2)
        self.assertEqual(summary["selected"], ["1.1.1", "1.1.2"])
        self.assertTrue(printed["strict_passed"])

    def test_failed_verdict_makes_the_run_fail(self):
        code, summary, printed = self.run_fixture(verdict="FAILED")
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["failed_count"], 4)
        self.assertFalse(printed["strict_passed"])

    def test_partial_scope_and_non_strict_counts_are_visible(self):
        code, summary, printed = self.run_fixture(cases=["1.1.1"], verdict="NON-STRICT")
        self.assertEqual(code, 0)
        self.assertEqual(summary["scope"], "partial")
        self.assertEqual(printed["scope"], "partial")
        self.assertEqual(summary["executed_count"], 2)
        self.assertEqual(summary["non_strict_count"], 2)
        self.assertEqual(printed["non_strict_count"], 2)
        self.assertFalse(summary["strict_passed"])
        self.assertFalse(printed["strict_passed"])

    def test_missing_client_case_fails_the_run(self):
        code, summary, printed = self.run_fixture(omit_client=True)
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["client"]["missing"], ["1.1.2"])
        self.assertFalse(printed["strict_passed"])

    def test_empty_selection_fails_without_executing_cases(self):
        code, summary, printed = self.run_fixture(cases=["9.*"])
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["executed_count"], 0)
        self.assertIn("No official cases selected", summary["errors"][0])
        self.assertFalse(printed["strict_passed"])

    def test_unicode_output_path_failure_has_safe_english_diagnostics(self):
        blocker = self.directory / "\u6d4b\u8bd5"
        blocker.touch()
        arguments = ["run_autobahn.py", "--server", "missing", "--client", "missing",
                     "--output", str(blocker / "results")]
        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", arguments), contextlib.redirect_stdout(stdout):
            code = runner.main()
        self.assertEqual(code, 1)
        text = stdout.getvalue()
        self.assertTrue(text.isascii())
        result = json.loads(text)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["executed_count"], 0)
        self.assertIn("Autobahn run failed", result["errors"][0])
        self.assertTrue(any("Cannot write Autobahn summary" in error for error in result["errors"]))


class ProcessTests(TemporaryFiles):
    def test_reader_drains_all_output_before_log_closes(self):
        log_path = self.directory / "\u6d4b\u8bd5.log"
        script = "import sys; sys.stdout.buffer.write(b'PORT=12345\\n' + b'output\\n' * 20000 + b'\\xff\\n')"
        with runner.process([sys.executable, "-c", script], log_path, ready=True) as (child, lines):
            self.assertEqual(runner.read_ready(lines), 12345)
            self.assertEqual(child.wait(timeout=10), 0)
        self.assertTrue(child.stdout.closed)
        text = log_path.read_text(encoding="utf-8")
        self.assertEqual(text.count("output\n"), 20000)
        self.assertTrue(text.endswith("\ufffd\n"))
        while lines.get_nowait() is not None:
            pass
        self.assertTrue(lines.empty())

    def test_reader_reports_eof_when_child_exits_without_port(self):
        with runner.process([sys.executable, "-c", "pass"], self.directory / "empty.log", ready=True) as (_, lines):
            with self.assertRaisesRegex(RuntimeError, "Mira server startup failed"):
                runner.read_ready(lines)

    def test_context_error_reaps_child_and_closes_reader(self):
        script = "import sys; print('PORT=12345', flush=True); sys.stdin.read()"
        # Wait on an owned pipe rather than sleeping; closing the context must terminate the child.
        original = subprocess.Popen
        with mock.patch.object(runner.subprocess, "Popen") as launch:
            launch.side_effect = lambda *args, **kwargs: original(*args, stdin=subprocess.PIPE, **kwargs)
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                with runner.process([sys.executable, "-c", script], self.directory / "stopped.log", ready=True) as (child, lines):
                    self.assertEqual(runner.read_ready(lines), 12345)
                    raise RuntimeError("fixture failure")
        child.stdin.close()
        self.assertIsNotNone(child.poll())
        self.assertTrue(child.stdout.closed)

    def test_invalid_port_diagnostics(self):
        for line in ("PORT=abc\n", "PORT=0\n", "PORT=65536\n"):
            with self.subTest(line=line):
                lines = queue.Queue()
                lines.put(line)
                with self.assertRaisesRegex(RuntimeError, "invalid listening port"):
                    runner.read_ready(lines)


if __name__ == "__main__":
    unittest.main()
