import datetime
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("ios_smoke_runner", pathlib.Path(__file__).with_name("run.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def output(platform="ios-device"):
    lines = [f"MIRA_SMOKE_CASE {name} PASS" for name in sorted(RUNNER.CASES)]
    lines.append("MIRA_DEVICE_SMOKE " + json.dumps(
        {"platform": platform, "backend": "kqueue", "passed": 5, "failed": 0}))
    return "\n".join(lines) + "\n"


class RunnerTests(unittest.TestCase):
    def test_complete_physical_output(self):
        self.assertEqual(RUNNER.parse_smoke(output(), "ios-device")["passed"], 5)

    def test_host_is_not_physical(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke(output("macos"), "ios-device")

    def test_simulator_is_not_physical(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke(output("ios-simulator"), "ios-device")

    def test_compile_and_launch_are_not_passes(self):
        for text in ["BUILD SUCCEEDED\n", "Launched application\n", ""]:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                RUNNER.parse_smoke(text, "ios-device")

    def test_duplicate_summary_is_rejected(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke(output() + output(), "ios-device")

    def test_missing_case_is_rejected(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke("\n".join(output().splitlines()[1:]), "ios-device")

    def test_failed_case_is_rejected(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke(output().replace('"failed": 0', '"failed": 1'), "ios-device")

    def test_watchdog_is_not_a_pass(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke(output() + "MIRA_SMOKE_WATCHDOG FAIL\n", "ios-device")

    def test_extra_failure_is_not_a_pass(self):
        with self.assertRaises(RuntimeError):
            RUNNER.parse_smoke(output() + "MIRA_SMOKE_CASE tcp_loopback FAIL\n", "ios-device")

    def test_no_profile_blocks_without_provisioning(self):
        args = type("Args", (), {"device": "TEST-UDID", "profile": None})()
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            devices = {"result": {"devices": [{"properties": {
                "hardware": {"udid": "TEST-UDID", "reality": "physical", "platform": "iOS"},
                "connection": {"pairingState": "paired"}}}]}}
            (directory / "devices.json").write_text(json.dumps(devices))
            with patch.object(RUNNER, "run") as command, patch.object(
                    RUNNER.subprocess, "check_output") as security:
                with self.assertRaises(RUNNER.Blocked):
                    RUNNER.device_preflight(args, directory)
                self.assertEqual(command.call_count, 1)
                security.assert_not_called()

    def test_simulator_preflight_is_rejected(self):
        args = type("Args", (), {"device": "TEST-UDID", "profile": None})()
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            devices = {"result": {"devices": [{"properties": {
                "hardware": {"udid": "TEST-UDID", "reality": "simulated", "platform": "iOS"},
                "connection": {"pairingState": "paired"}}}]}}
            (directory / "devices.json").write_text(json.dumps(devices))
            with patch.object(RUNNER, "run"), patch.object(RUNNER.subprocess, "check_output") as security:
                with self.assertRaisesRegex(RUNNER.Blocked, "not a physical"):
                    RUNNER.device_preflight(args, directory)
                security.assert_not_called()

    def test_profile_scope_guards(self):
        certificate = b"test-certificate"
        identity = hashlib.sha1(certificate).hexdigest().upper()
        args = type("Args", (), {"device": "TEST-UDID", "profile": pathlib.Path("test.mobileprovision"),
                                "team": "TESTTEAM", "bundle_id": "org.example.smoke",
                                "identity": identity})()
        profile = {
            "UUID": "TEST-PROFILE",
            "TeamIdentifier": ["TESTTEAM"],
            "ApplicationIdentifierPrefix": ["TESTTEAM"],
            "Entitlements": {"application-identifier": "TESTTEAM.org.example.*", "get-task-allow": True},
            "ProvisionedDevices": ["TEST-UDID"],
            "ExpirationDate": datetime.datetime(2999, 1, 1),
            "DeveloperCertificates": [certificate],
        }
        devices = {"result": {"devices": [{"properties": {
            "hardware": {"udid": "TEST-UDID", "reality": "physical", "platform": "iOS"},
            "connection": {"pairingState": "paired"}}}]}}
        cases = [
            ({}, True),
            ({"TeamIdentifier": ["OTHERTEAM"]}, False),
            ({"ProvisionedDevices": ["OTHER-UDID"]}, False),
            ({"ExpirationDate": datetime.datetime(2000, 1, 1)}, False),
            ({"DeveloperCertificates": [b"other-certificate"]}, False),
            ({"Entitlements": {"application-identifier": "TESTTEAM.org.other.app",
                               "get-task-allow": True}}, False),
            ({"Entitlements": {"application-identifier": "TESTTEAM.org.example.*",
                               "get-task-allow": False}}, False),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            (directory / "devices.json").write_text(json.dumps(devices))
            for changed, allowed in cases:
                with self.subTest(changed=changed), patch.object(RUNNER, "run"), patch.object(
                        RUNNER.subprocess, "check_output", side_effect=[
                            plistlib.dumps(profile | changed), identity]):
                    if allowed:
                        self.assertEqual(RUNNER.device_preflight(args, directory), "TEST-PROFILE")
                    else:
                        with self.assertRaises(RUNNER.Blocked):
                            RUNNER.device_preflight(args, directory)


if __name__ == "__main__":
    unittest.main()
