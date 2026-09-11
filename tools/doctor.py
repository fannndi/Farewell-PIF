#!/usr/bin/env python3
"""
Farewell-PIF doctor: full-stack diagnosis with a fix pointer per module.

Runs the same device matrix as tools/verify.py, then adds local checks (repo artifacts) and a
module hint for every failure, so a broken piece points straight at the file to fix.

Usage:
  python tools/doctor.py
  python tools/doctor.py --skip-gms
  python tools/doctor.py --json out/doctor.json
"""

import argparse
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import verify as verifier  # noqa: E402

HINTS = {
    "device": "tools/platform-tools/adb.exe - connect the phone (USB debugging)",
    "app": "app/ - build_app.py, then adb install -r out/FarewellPIF.apk",
    "config": "config envelope lost - open the app (BootReceiver re-seeds) or provision.py --fix",
    "meta": "hook channel missing - app auto-install / provision.py --fix (HookStore.installHook)",
    "gate": "bootstrap gateAllows + HookStore.gateValue - repack only if bootstrap changed",
    "dex": "chunk channel corrupt - python build.py, then provision.py --fix",
    "diagnose": "impl not loaded - BootReceiver/HookStore channel file; docs/MODULES.md (loader)",
    "attest": "Attestation.KeyParams/buildKeyDescription, Keybox, Bridge.getField (hook/impl)",
    "gms": "bootstrap gate + Runtime.ensureProcessInit; restart/reload GMS and retry",
}


def local_checks():
    checks = []
    framework = ROOT / "out" / "framework.jar"
    if framework.exists():
        checks.append(("framework.jar", True, "%d bytes" % framework.stat().st_size))
    else:
        checks.append(("framework.jar", False, "missing - run python build.py"))

    install = ROOT / "out" / "install"
    jars = install / "system" / "system" / "framework" / "framework.jar"
    native = install / "system" / "system" / "lib64" / "libfarewell.so"
    checks.append(("install tree", jars.exists(),
                   str(jars) if jars.exists() else "missing - rebuild and re-stage"))
    checks.append(("native lib", native.exists(),
                   ("%d bytes (flash to /system/lib64)" % native.stat().st_size)
                   if native.exists() else "missing - native/build.ps1"))

    built_native = ROOT / "build" / "native" / "libfarewell.so"
    checks.append(("native build", built_native.exists(),
                   "ok" if built_native.exists() else "missing - run native/build.ps1"))
    return checks


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF doctor")
    parser.add_argument("--adb", default=str(ROOT / "tools" / "platform-tools" / "adb.exe"))
    parser.add_argument("--skip-gms", action="store_true")
    parser.add_argument("--json", default=None, help="write the report to this path")
    args = parser.parse_args()

    print("Farewell-PIF doctor %s"
          % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("== local artifacts ==")
    local = local_checks()
    for name, ok, detail in local:
        print("%-13s %-4s %s" % (name, "PASS" if ok else "FAIL", detail))

    print("== device matrix ==")
    results = verifier.verify(args.adb, skip_gms=args.skip_gms)
    failed = [row for row in results if not row["ok"]]
    if failed:
        print("== fix pointers ==")
        for row in failed:
            print("  %-9s -> %s" % (row["name"], HINTS.get(row["name"], "docs/MODULES.md")))

    device_passed = sum(1 for row in results if row["ok"])
    local_passed = sum(1 for _, ok, _ in local if ok)
    print("-" * 60)
    print("device %d/%d - local %d/%d"
          % (device_passed, len(results), local_passed, len(local)))

    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "local": [{"name": n, "ok": ok, "detail": d} for n, ok, d in local],
            "device": results,
            "hints": {row["name"]: HINTS.get(row["name"], "") for row in failed},
        }, indent=2), encoding="utf-8")
        print("report:", target)

    return 0 if not failed and local_passed == len(local) else 1


if __name__ == "__main__":
    raise SystemExit(main())
