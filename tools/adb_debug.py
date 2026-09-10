#!/usr/bin/env python3
"""
ADB debugging helper for Farewell-PIF.

Enables USB debugging, turns the framework debug flag on, and collects a single
zip with everything needed to debug over USB (logcat, crash buffer, settings,
props, package dump, and the in-app debug bundles):

  python tools/adb_debug.py --enable-adb --debug-on --clear-logs
  # trigger Play Integrity check on the device, then:
  python tools/adb_debug.py --collect

Output: out/debug/farewell-debug-<timestamp>.zip  (attach it when asking the LLM)
"""

import argparse
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from provision import adb_path, adb, load_config, save_config  # noqa: E402

EXTERNAL_FILES = "/sdcard/Android/data/dev.farewell.pif/files/"
PROPS_OF_INTEREST = (
    "ro.build.fingerprint",
    "ro.build.version.security_patch",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.product.model",
    "ro.product.device",
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.digest",
)


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF adb debug helper")
    parser.add_argument("--adb", default=None)
    parser.add_argument("--enable-adb", action="store_true")
    parser.add_argument("--disable-adb", action="store_true")
    parser.add_argument("--debug-on", action="store_true")
    parser.add_argument("--debug-off", action="store_true")
    parser.add_argument("--clear-logs", action="store_true")
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "out" / "debug"))
    args = parser.parse_args()

    adb_bin = adb_path(args)
    devices = adb(adb_bin, ["devices"], check=False)
    if "\tdevice" not in devices:
        raise SystemExit("no device connected:\n" + devices)

    did_something = False

    if args.enable_adb:
        adb(adb_bin, ["shell", "settings", "put", "global", "adb_enabled", "1"])
        adb(adb_bin, ["shell", "settings", "put", "global",
                      "development_settings_enabled", "1"])
        print("ADB + developer options enabled")
        did_something = True

    if args.disable_adb:
        adb(adb_bin, ["shell", "settings", "put", "global", "adb_enabled", "0"])
        adb(adb_bin, ["shell", "settings", "put", "global",
                      "development_settings_enabled", "0"])
        print("ADB + developer options disabled")
        did_something = True

    if args.debug_on or args.debug_off:
        config = load_config(adb_bin)
        config["dbg"] = 1 if args.debug_on else 0
        save_config(adb_bin, config)
        print("framework debug flag =", config["dbg"])
        did_something = True

    if args.clear_logs:
        adb(adb_bin, ["logcat", "-c"])
        print("logcat cleared")
        did_something = True

    if args.collect:
        collect(adb_bin, Path(args.out))
        did_something = True

    if not did_something:
        parser.print_help()


def collect(adb_bin, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")

    files = {}
    files["logcat-farewell.txt"] = adb(adb_bin, [
        "shell", "logcat", "-d", "-v", "time",
        "-s", "FarewellPIF:V", "AndroidRuntime:E", "*:S"], check=False)
    files["logcat-crash.txt"] = adb(adb_bin, [
        "shell", "logcat", "-d", "-b", "crash", "-v", "time"], check=False)

    envelope = adb(adb_bin, ["shell", "settings", "get", "global",
                             "sys_thermal_profile"], check=False)
    files["settings.txt"] = "\n".join([
        "adb_enabled=" + adb(adb_bin, ["shell", "settings", "get", "global",
                                       "adb_enabled"], check=False),
        "development_settings_enabled=" + adb(adb_bin, [
            "shell", "settings", "get", "global",
            "development_settings_enabled"], check=False),
        "farewell_debug=" + adb(adb_bin, ["shell", "settings", "get", "global",
                                          "farewell_debug"], check=False),
        "sys_thermal_profile=%s%s" % (
            envelope[:120],
            "..." if len(envelope) > 120 else ""),
    ])

    props = adb(adb_bin, ["shell", "getprop"], check=False)
    files["props.txt"] = "\n".join(
        line for line in props.splitlines()
        if any(key in line for key in PROPS_OF_INTEREST))

    files["dumpsys-package.txt"] = adb(adb_bin, [
        "shell", "dumpsys", "package", "dev.farewell.pif"], check=False)[:40000]

    for name, text in files.items():
        (out_dir / (stamp + "-" + name)).write_text(text or "", encoding="utf-8")

    bundle_dir = out_dir / (stamp + "-bundles")
    subprocess.run([adb_bin, "pull", EXTERNAL_FILES, str(bundle_dir)],
                   capture_output=True, text=True)

    zip_path = out_dir / ("farewell-debug-" + stamp + ".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(out_dir.glob(stamp + "-*")):
            if path.is_file():
                archive.write(path, path.name)
            elif path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file():
                        archive.write(child, str(child.relative_to(out_dir)))

    print("debug bundle:", zip_path)
    print("attach this zip when asking the LLM for analysis")


if __name__ == "__main__":
    main()
