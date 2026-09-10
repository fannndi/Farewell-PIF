#!/usr/bin/env python3
"""
Anchor calibration for a stock framework directory.

Runs every patch function against freshly disassembled target classes and reports which
patches apply as-is and which need anchor adjustments (useful when porting Farewell-PIF to
another ROM or Android version).

Usage:
  python patcher/calibrate.py --stock "C:\\path\\to\\framework" --out out/calibration.json
"""

import argparse
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("farewell_patch", HERE / "farewell_patch.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load farewell_patch.py")
FP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FP)


def class_descriptor(smali_relative):
    return "L" + smali_relative[:-len(".smali")] + ";"


def calibrate_jar(jar_path, work_root):
    stem = Path(jar_path).stem
    patches = FP.FRAMEWORK_PATCHES if stem == "framework" else FP.SERVICES_PATCHES
    work = work_root / stem
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    FP.extract_dexes(jar_path, work)

    results = []
    for dex_name, files in patches.items():
        dex_path = work / "dex" / dex_name
        if not dex_path.exists():
            results.append({"dex": dex_name, "status": "dex-missing"})
            continue
        out_dir = work / "smali" / dex_name
        descriptors = [class_descriptor(name) for name in files]
        try:
            FP.baksmali_dex(dex_path, out_dir, classes=descriptors)
        except FP.PatchError as error:
            results.append({"dex": dex_name, "status": "disassemble-failed",
                            "reason": str(error)})
            continue
        for relative, fn in files.items():
            smali_path = out_dir / relative.replace("/", os.sep)
            entry = {"dex": dex_name, "file": relative}
            if not smali_path.exists():
                entry["status"] = ("optional-missing"
                                   if relative in FP.OPTIONAL_PATCHES else "missing")
                results.append(entry)
                continue
            text = smali_path.read_text(encoding="utf-8")
            if FP.HOOK_DESCRIPTOR in text:
                entry["status"] = "already-patched"
                results.append(entry)
                continue
            try:
                fn(text)
                entry["status"] = "ok"
            except FP.PatchError as error:
                entry["status"] = ("optional-skip"
                                   if relative in FP.OPTIONAL_PATCHES else "anchor-error")
                entry["reason"] = str(error)
            results.append(entry)
    return results


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF anchor calibration")
    parser.add_argument("--stock", required=True,
                        help="directory containing framework.jar / services.jar")
    parser.add_argument("--out", default=str(HERE.parent / "out" / "calibration.json"))
    parser.add_argument("--work", default=str(HERE.parent / "work" / "calibrate"))
    args = parser.parse_args()

    stock = Path(args.stock)
    report = {"stock": str(stock), "sdk": FP.detect_sdk(stock), "jars": {}}
    for name in ("framework.jar", "services.jar"):
        jar = stock / name
        if not jar.exists():
            report["jars"][name] = [{"status": "jar-missing"}]
            continue
        print("calibrating %s ..." % name)
        report["jars"][name] = calibrate_jar(jar, Path(args.work))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("SDK:", report["sdk"] or "unknown")
    failures = 0
    for name, entries in report["jars"].items():
        print(name + ":")
        for entry in entries:
            status = entry.get("status", "?")
            line = "  %-55s %s" % (entry.get("file", entry.get("dex", "?")), status)
            if entry.get("reason"):
                line += "  -> " + entry["reason"]
            print(line)
            if "error" in status or status in ("missing", "disassemble-failed"):
                failures += 1
    print("report:", out_path)
    print("RESULT:", "PORTABLE (no blockers)" if failures == 0
          else "%d anchor(s) need attention" % failures)


if __name__ == "__main__":
    main()
