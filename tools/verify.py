#!/usr/bin/env python3
"""
End-to-end verification for Farewell-PIF (offline; ADB only, no network).

Checks, in order:
  device    adb works and a device is connected
  app       controller app installed
  config    sys_thermal_profile envelope decodes (en=1)
  meta      sys_perf_dex_meta present ("<sha>:<chunks>:<version>")
  gate      sys_perf_dex_pkgs allows android + app + gms + vending
  dex       chunks reconstruct to the declared sha256
  diagnose  app op selftest -> impl loaded, keyboxes healthy
  attest    app op verify   -> returned chain is keybox-signed (live hook test)
  gms       GMS restart -> logcat shows the hook loaded inside com.google.android.gms

Usage:
  python tools/verify.py
  python tools/verify.py --skip-gms
  python tools/verify.py --json out/verify.json
"""

import argparse
import base64
import datetime
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ADB = ROOT / "tools" / "platform-tools" / "adb.exe"
APP = "dev.farewell.pif"

sys.path.insert(0, str(ROOT / "tools"))
from provision import (  # noqa: E402
    HOOK_CHUNK,
    HOOK_META,
    NEUTRAL_KEY,
    XOR_KEY,
    adb as adb_raw,
    settings_get,
)

TAG = "FarewellPIF"


def adb(binary, args, check=False):
    return adb_raw(binary, args, check=check)


def run_op(binary, op, timeout=20.0):
    """Starts the app op and returns its JSON result parsed from logcat."""
    adb(binary, ["shell", "am", "start", "-n", APP + "/.app.MainActivity",
                 "--es", "op", op])
    pattern = re.compile(r"op %s -> (\{.*\})\s*$" % re.escape(op), re.M)
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = adb(binary, ["logcat", "-d", "-s", TAG])
        matches = pattern.findall(out)
        if matches:
            try:
                return json.loads(matches[-1])
            except Exception:
                return {"raw": matches[-1]}
        time.sleep(1)
    return None


def check(name, ok, detail, results):
    results.append({"name": name, "ok": bool(ok), "detail": detail})
    print("%-9s %-4s %s" % (name, "PASS" if ok else "FAIL", detail))
    return ok


def verify(binary, skip_gms=False):
    results = []

    out = adb(binary, ["devices"])
    if not check("device", "\tdevice" in out, "adb device present", results):
        return results

    out = adb(binary, ["shell", "pm", "path", APP])
    check("app", "package:" in out, APP + " installed", results)

    raw = settings_get(binary, NEUTRAL_KEY)
    config = None
    try:
        data = base64.b64decode(raw[3:]) if raw.startswith("F1:") else b""
        decoded = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))
        config = json.loads(decoded.decode("utf-8"))
    except Exception:
        config = None
    check("config", bool(config) and config.get("en") == 1,
          "envelope decoded, en=%s, flags=%s"
          % (config.get("en") if config else "?", config.get("fl") if config else "?"),
          results)

    meta = settings_get(binary, HOOK_META)
    parts = meta.split(":") if meta and meta != "null" else []
    check("meta", len(parts) >= 2,
          "meta=%s" % (meta if parts else "absent"), results)

    gate = settings_get(binary, "sys_perf_dex_pkgs") or ""
    needed = ["android", APP, "com.google.android.gms", "com.android.vending"]
    missing = [pkg for pkg in needed if ("," + pkg + ",") not in gate]
    check("gate", not missing,
          "missing=%s" % (",".join(missing) if missing else "none"), results)

    rebuilt = bytearray()
    if len(parts) >= 2:
        try:
            for index in range(int(parts[1])):
                encoded = settings_get(binary, HOOK_CHUNK + str(index))
                rebuilt += bytes(
                    b ^ XOR_KEY[i % len(XOR_KEY)]
                    for i, b in enumerate(base64.b64decode(encoded)))
        except Exception as error:
            rebuilt = bytearray()
            print("dex        FAIL decode error: %s" % error)
    sha = hashlib.sha256(bytes(rebuilt)).hexdigest() if rebuilt else ""
    check("dex", bool(rebuilt) and sha == parts[0],
          "sha=%s bytes=%d" % (sha[:16] if sha else "-", len(rebuilt)), results)

    diagnose = run_op(binary, "selftest")
    impl = bool(diagnose) and "attestationVersion" in diagnose
    keyboxes = (diagnose or {}).get("keyboxes") or []
    healthy = [k for k in keyboxes if not k.get("problem")]
    check("diagnose", impl and bool(healthy),
          "impl=%s keyboxes=%d/%d stats=%s"
          % (impl, len(healthy), len(keyboxes), (diagnose or {}).get("stats", "-")),
          results)

    verify_result = run_op(binary, "verify", timeout=60.0)
    forged = bool(verify_result) and verify_result.get("forged") is True
    check("attest", forged,
          "ok=%s forged=%s chain=%s keygen=%s error=%s"
          % ((verify_result or {}).get("ok"),
             (verify_result or {}).get("forged"),
             (verify_result or {}).get("chainLength"),
             (verify_result or {}).get("keygen"),
             (verify_result or {}).get("error", "-")),
          results)

    if skip_gms:
        return results

    adb(binary, ["shell", "am", "force-stop", "com.google.android.gms"])
    adb(binary, ["logcat", "-c"])
    adb(binary, ["shell", "monkey", "-p", "com.android.vending",
                 "-c", "android.intent.category.LAUNCHER", "1"])
    pattern = re.compile(r"dex loaded .*pkg=com\.google\.android\.gms", re.M)
    loaded = False
    deadline = time.time() + 120
    while time.time() < deadline:
        out = adb(binary, ["logcat", "-d", "-s", TAG])
        if pattern.search(out):
            loaded = True
            break
        if re.search(r"gate denied pkg=com\.google\.android\.gms", out):
            break
        time.sleep(2)
    out = adb(binary, ["logcat", "-d", "-s", TAG])
    denied = "gate denied pkg=com.google.android.gms" in out
    check("gms", loaded,
          "hook loaded in GMS" if loaded
          else ("gate denied GMS" if denied else "no load evidence in 120 s"), results)

    return results


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF end-to-end verification")
    parser.add_argument("--adb", default=str(DEFAULT_ADB))
    parser.add_argument("--skip-gms", action="store_true")
    parser.add_argument("--json", default=None, help="write the report to this path")
    args = parser.parse_args()

    if not Path(args.adb).exists():
        raise SystemExit("adb not found: %s" % args.adb)

    print("Farewell-PIF verification %s"
          % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    results = verify(args.adb, skip_gms=args.skip_gms)
    passed = sum(1 for row in results if row["ok"])
    print("-" * 60)
    print("%d/%d checks passed" % (passed, len(results)))

    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "passed": passed,
            "total": len(results),
            "results": results,
        }, indent=2), encoding="utf-8")
        print("report: %s" % target)

    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
