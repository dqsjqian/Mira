#!/usr/bin/env python3
import argparse
import datetime
import fnmatch
import hashlib
import json
import pathlib
import plistlib
import re
import subprocess
import sys

SOURCE = pathlib.Path(__file__).resolve().parent
ROOT = SOURCE.parents[2]
CASES = {
    "tcp_loopback",
    "udp_loopback_and_empty_datagram",
    "http1_keepalive",
    "pending_io_cancellation",
    "accept_deadline",
}


class Blocked(RuntimeError):
    pass


def run(command, directory, name, timeout=180):
    with (directory / (name + ".log")).open("w") as output:
        output.write(json.dumps(command) + "\n")
        output.flush()
        completed = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
    if completed.returncode:
        raise RuntimeError(f"{name} exited {completed.returncode}; see {name}.log")
    return (directory / (name + ".log")).read_text(errors="replace")


def device_preflight(args, directory):
    run(["xcrun", "devicectl", "list", "devices", "--timeout", "30",
         "--json-output", str(directory / "devices.json")], directory, "devices", 45)
    document = json.loads((directory / "devices.json").read_text())
    selected = None
    for device in document["result"]["devices"]:
        properties = device.get("properties", {})
        hardware = properties.get("hardware", device.get("hardwareProperties", {}))
        if args.device == hardware.get("udid"):
            selected = device
            if hardware.get("reality") != "physical" or hardware.get("platform") != "iOS":
                raise Blocked("The selected UDID is not a physical iOS device")
            connection = properties.get("connection", device.get("connectionProperties", {}))
            if connection.get("pairingState") != "paired":
                raise Blocked("The selected physical device is not paired")
            break
    if selected is None:
        raise Blocked("The selected physical device is not in devicectl's device list")
    if not args.profile:
        raise Blocked("Provide an existing development profile with --profile; no profile is created")
    raw = subprocess.check_output(["security", "cms", "-D", "-i", str(args.profile)], timeout=30)
    profile = plistlib.loads(raw)
    entitlements = profile.get("Entitlements", {})
    if args.team not in profile.get("TeamIdentifier", []):
        raise Blocked("The profile does not belong to the explicitly selected team")
    prefixes = profile.get("ApplicationIdentifierPrefix", [])
    application = entitlements.get("application-identifier", "")
    if not any(fnmatch.fnmatchcase(prefix + "." + args.bundle_id, application) for prefix in prefixes):
        raise Blocked("The profile does not authorize this bundle ID")
    if entitlements.get("get-task-allow") is not True:
        raise Blocked("An existing development profile with get-task-allow is required")
    if args.device not in profile.get("ProvisionedDevices", []):
        raise Blocked("The profile does not authorize this physical device")
    expiration = profile["ExpirationDate"].replace(tzinfo=datetime.timezone.utc)
    if expiration <= datetime.datetime.now(datetime.timezone.utc):
        raise Blocked("The supplied profile has expired")
    fingerprints = {hashlib.sha1(cert).hexdigest().upper()
                    for cert in profile.get("DeveloperCertificates", [])}
    if args.identity.upper() not in fingerprints:
        raise Blocked("The profile does not authorize the explicitly selected signing identity")
    identities = subprocess.check_output(["security", "find-identity", "-v", "-p", "codesigning"],
                                         text=True, timeout=30)
    if args.identity.upper() not in identities:
        raise Blocked("The selected valid signing identity/private key is unavailable")
    return profile["UUID"]


def parse_smoke(text, platform):
    markers = re.findall(r"^MIRA_DEVICE_SMOKE (\{[^\n]+\})\s*$", text, re.MULTILINE)
    passed = re.findall(r"^MIRA_SMOKE_CASE (\S+) PASS\s*$", text, re.MULTILINE)
    if (len(markers) != 1 or len(passed) != len(CASES) or set(passed) != CASES or
            re.search(r"^MIRA_SMOKE_(?:CASE .* FAIL|WATCHDOG)", text, re.MULTILINE)):
        raise RuntimeError("Missing, failed or duplicate smoke results; launch/build alone is not a pass")
    result = json.loads(markers[0])
    if (result.get("platform") != platform or result.get("backend") != "kqueue" or
            result.get("passed") != len(CASES) or result.get("failed") != 0):
        raise RuntimeError("Smoke failed or ran on a different platform")
    return result


def execute(args, directory):
    if args.mode == "host":
        build = directory / "host"
        run(["cmake", "-S", str(SOURCE), "-B", str(build), "-G", "Ninja",
             "-DCMAKE_BUILD_TYPE=Release"], directory, "configure")
        run(["cmake", "--build", str(build), "--target", "mira_device_smoke", "-j", "4"],
            directory, "build")
        text = run([str(build / "mira_device_smoke")], directory, "smoke", 30)
        return {"status": "host-pass", "physical_device_run": False,
                "smoke": parse_smoke(text, "macos")}

    run(["xcodebuild", "-version"], directory, "xcode-version", 30)
    run(["xcrun", "devicectl", "device", "install", "app", "--help"],
        directory, "install-help", 30)
    launch_help = run(["xcrun", "devicectl", "device", "process", "launch", "--help"],
                      directory, "launch-help", 30)
    if "--console" not in launch_help or "--json-output" not in launch_help:
        raise Blocked("This devicectl lacks the required bounded console/JSON launch interface")
    profile_uuid = device_preflight(args, directory) if args.mode == "device" else None
    build = directory / "xcode"
    configure = ["cmake", "-S", str(SOURCE), "-B", str(build), "-G", "Xcode",
                 "-DCMAKE_SYSTEM_NAME=iOS", "-DCMAKE_OSX_SYSROOT=iphoneos",
                 "-DCMAKE_OSX_ARCHITECTURES=arm64", "-DCMAKE_OSX_DEPLOYMENT_TARGET=18.0",
                 "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
                 "-DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO",
                 "-DMIRA_SMOKE_BUNDLE_ID=" + args.bundle_id]
    if args.mode == "device":
        configure += ["-DMIRA_SMOKE_TEAM=" + args.team,
                      "-DMIRA_SMOKE_IDENTITY=" + args.identity.upper(),
                      "-DMIRA_SMOKE_PROFILE=" + profile_uuid]
    run(configure, directory, "configure")
    command = ["xcodebuild", "-project", str(build / "MiraDeviceSmoke.xcodeproj"),
               "-target", "mira_device_smoke", "-configuration", "Release", "-sdk", "iphoneos",
               "-jobs", "4", "build"]
    run(command, directory, "build", 240)
    app = build / "Release-iphoneos" / "mira_device_smoke.app"
    executable = app / "mira_device_smoke"
    macho = run(["xcrun", "vtool", "-show-build", str(executable)], directory, "macho", 30)
    if not re.search(r"platform\s+IOS\s", macho):
        raise RuntimeError("The Mach-O platform is not IOS")
    architectures = run(["xcrun", "lipo", "-archs", str(executable)], directory, "architectures", 30)
    if architectures.splitlines()[-1].strip() != "arm64":
        raise RuntimeError("The app is not a single arm64 device binary")
    dependencies = run(["xcrun", "otool", "-L", str(executable)], directory, "dependencies", 30)
    for line in dependencies.splitlines()[2:]:
        if "(compatibility version" in line and not line.lstrip().startswith(
                ("/System/Library/", "/usr/lib/")):
            raise RuntimeError("The smoke app unexpectedly links a non-system dynamic library")
    if args.mode == "compile":
        return {"status": "compile-only", "physical_device_run": False,
                "tls_h2_h3": "not-built", "app": str(app)}
    run(["codesign", "--verify", "--deep", "--strict", str(app)], directory, "codesign", 30)
    embedded = plistlib.loads(subprocess.check_output(
        ["security", "cms", "-D", "-i", str(app / "embedded.mobileprovision")], timeout=30))
    if embedded.get("UUID") != profile_uuid:
        raise RuntimeError("Built app embedded a different profile")
    info = plistlib.loads((app / "Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != args.bundle_id:
        raise RuntimeError("Built app has a different bundle ID")
    run(["xcrun", "devicectl", "device", "install", "app", "--device", args.device,
         "--timeout", "60", "--json-output", str(directory / "install.json"), str(app)],
        directory, "install", 75)
    text = run(["xcrun", "devicectl", "device", "process", "launch", "--device", args.device,
                "--timeout", "40", "--console", "--json-output", str(directory / "launch.json"),
                args.bundle_id], directory, "smoke", 55)
    return {"status": "device-pass", "physical_device_run": True,
            "smoke": parse_smoke(text, "ios-device"), "tls_h2_h3": "not-built"}


def main():
    parser = argparse.ArgumentParser(description="Bounded Mira loopback smoke; no automatic provisioning")
    parser.add_argument("--mode", choices=["host", "compile", "device"], default="compile")
    parser.add_argument("--build-dir", type=pathlib.Path, default=ROOT / "build" / "all-device")
    parser.add_argument("--bundle-id", help="Explicit bundle ID for this test app only")
    parser.add_argument("--device", help="Physical iOS device UDID (never a simulator)")
    parser.add_argument("--team", help="Explicit development team ID")
    parser.add_argument("--identity", help="Explicit SHA-1 fingerprint of an existing signing identity")
    parser.add_argument("--profile", type=pathlib.Path, help="Existing installed development .mobileprovision")
    args = parser.parse_args()
    if args.mode != "host" and (not args.bundle_id or not re.fullmatch(
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", args.bundle_id)):
        parser.error("--bundle-id must explicitly identify the smoke test app")
    if args.mode == "device" and (not args.device or not args.team or not args.identity or
                                 not re.fullmatch(r"[0-9A-Fa-f]{40}", args.identity)):
        parser.error("device mode requires --device, --team, and a SHA-1 --identity")
    directory = args.build_dir.resolve() / ("runner-" + args.mode)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "result.json").write_text(json.dumps(
        {"status": "running", "physical_device_run": False}) + "\n")
    try:
        result = execute(args, directory)
        code = 0
    except Blocked as error:
        result = {"status": "blocked", "physical_device_run": False, "reason": str(error)}
        code = 77
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result = {"status": "failed", "physical_device_run": False, "reason": str(error)}
        code = 1
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
