#!/usr/bin/env python3
"""
Auto-update the fingerprint profile from the internet (OemPorts10T "pif-updater" idea, PC side).

Downloads a profile (Pif-props.json, PIFork/OemPorts pif.json, or KEY=VALUE), validates it and
optionally pushes it to the device through the privileged app.

Usage:
  python tools/update_profile.py
  python tools/update_profile.py --url https://.../custom.json
  python tools/update_profile.py --push
  python tools/update_profile.py --push --keybox path/to/keybox.xml
"""

import argparse
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_URL = ("https://raw.githubusercontent.com/fannndi/Farewell-PIF/main/"
               "reference/profile/Pif-props.json")
DEFAULT_OUT = ROOT / "reference" / "profile" / "Pif-props.json"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Farewell-PIF"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8", "replace")


def parse_profile(text):
    trimmed = text.strip()
    if trimmed.startswith("{"):
        profile = json.loads(trimmed)
    else:
        profile = {}
        for line in trimmed.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#") or clean.startswith("//"):
                continue
            if "=" not in clean:
                continue
            key, value = clean.split("=", 1)
            profile[key.strip()] = value.strip()
    if not profile.get("FINGERPRINT"):
        raise SystemExit("downloaded profile has no FINGERPRINT")
    return profile


def main():
    parser = argparse.ArgumentParser(description="Update the reference fingerprint profile")
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="profile source (default: this repository's reference profile)")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--push", action="store_true",
                        help="push the profile to the device via tools/provision.py")
    parser.add_argument("--keybox", default=None, help="also push this keybox (with --push)")
    parser.add_argument("--adb", default=str(ROOT / "tools" / "platform-tools" / "adb.exe"))
    args = parser.parse_args()

    print("source:", args.url)
    profile = parse_profile(fetch(args.url))
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print("saved : %s" % target)
    print("model : %s" % profile.get("MODEL", "?"))
    print("print : %s" % profile["FINGERPRINT"])

    if args.push:
        command = [sys.executable, str(ROOT / "tools" / "provision.py"),
                   "--adb", args.adb, "--profile", str(target), "--fix"]
        if args.keybox:
            command += ["--keybox", args.keybox]
        print("push  :", " ".join(command))
        subprocess.run(command, check=True)
    else:
        print("push it later with: python tools/provision.py --profile %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
