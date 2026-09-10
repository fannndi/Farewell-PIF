#!/usr/bin/env python3
"""
Deep stock ROM audit for Farewell-PIF.

Checks, in one pass:
  - bootclasspath / systemserverclasspath order (parse classpaths .pb strings)
  - framework jars per partition and which jar/dex DEFINES our hook target classes
    (byte scan + baksmali definition confirmation when tools are available)
  - build.prop facts (tags, debuggable, security patch, privapp control)
  - VINTF keystore HAL version (keymaster HIDL / keymint AIDL)
  - otacerts identity (releasekey vs testkey)
  - AVB/verity configuration from fstab
  - patch anchor presence in the stock dexes (optional, when --anchors)

Usage:
  python tools/audit_rom.py --rom "C:\\path\\to\\ROM" --out out/rom-audit.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SMALI3 = ROOT / "tools" / "smali3"
JAVA = "java"

TARGET_CLASSES = [
    "Landroid/app/Instrumentation;",
    "Landroid/app/ApplicationPackageManager;",
    "Landroid/security/KeyStore2;",
    "Landroid/security/keystore2/AndroidKeyStoreSpi;",
    "Landroid/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi;",
    "Lcom/android/server/SystemServer;",
    "Lcom/android/server/devicepolicy/DevicePolicyCacheImpl;",
    "Lcom/android/server/wm/WindowState;",
    "Lcom/android/server/wm/WindowStateAnimator;",
]

PARTITION_DIRS = [
    "system/system",
    "system_ext",
    "product",
    "system/system/odm",
    "system/odm",
    "vendor",
]

BUILD_PROPS_OF_INTEREST = [
    "ro.build.tags",
    "ro.debuggable",
    "ro.secure",
    "ro.build.version.security_patch",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.product.device",
    "ro.control_privapp_permissions",
    "ro.adb.secure",
]

ANCHOR_FILES = {
    "framework.jar/classes.dex": [
        ("android/app/Instrumentation.smali", "newApplication"),
        ("android/app/ApplicationPackageManager.smali", "hasSystemFeature"),
    ],
    "framework.jar/classes2.dex": [
        ("android/security/KeyStore2.smali", "getKeyEntry"),
        ("android/security/keystore2/AndroidKeyStoreSpi.smali", "engineGetCertificateChain"),
        ("android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi.smali", "generateKeyPair"),
    ],
    "services.jar/classes.dex": [
        ("com/android/server/SystemServer.smali", "startOtherServices"),
        ("com/android/server/devicepolicy/DevicePolicyCacheImpl.smali", "isScreenCaptureAllowed"),
    ],
    "services.jar/classes2.dex": [
        ("com/android/server/wm/WindowState.smali", "isSecureLocked"),
        ("com/android/server/wm/WindowStateAnimator.smali", "setSecureLocked"),
    ],
}


def printable_strings(data, minimum=4):
    return [match.group(0).decode("ascii", "replace")
            for match in re.finditer(rb"[ -~]{%d,}" % minimum, data)]


def safe_exists(path):
    try:
        return Path(path).exists()
    except OSError:
        return False


def safe_isdir(path):
    try:
        return Path(path).is_dir()
    except OSError:
        return False


def read_classpaths(rom, name):
    path = Path(rom) / "system" / "system" / "etc" / "classpaths" / name
    if not safe_exists(path):
        return []
    jars = []
    for text in printable_strings(path.read_bytes()):
        if text.endswith(".jar"):
            if not jars or jars[-1] != text:
                jars.append(text)
    return jars


def read_build_props(rom):
    result = {}
    for partition in PARTITION_DIRS:
        path = Path(rom) / partition / "build.prop"
        if not safe_exists(path):
            continue
        values = {}
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key in BUILD_PROPS_OF_INTEREST:
                    values[key] = value.strip()
        except Exception as error:
            values["__error__"] = str(error)
        if values:
            result[partition] = values
    return result


def scan_target_classes(rom):
    hits = []
    for partition in PARTITION_DIRS:
        jar_dir = Path(rom) / partition / "framework"
        if not safe_isdir(jar_dir):
            continue
        for jar in sorted(jar_dir.glob("*.jar")):
            try:
                with zipfile.ZipFile(jar) as archive:
                    for entry in archive.namelist():
                        if not re.fullmatch(r"classes\d*\.dex", entry):
                            continue
                        data = archive.read(entry)
                        found = [name for name in TARGET_CLASSES if name.encode() in data]
                        if found:
                            hits.append({
                                "partition": partition,
                                "jar": jar.name,
                                "dex": entry,
                                "descriptors": found,
                            })
            except Exception:
                continue
    return hits


def baksmali_definitions(rom, hits, work_dir):
    """Confirm which hit jars actually DEFINE the classes (not just reference them)."""
    if shutil.which(JAVA) is None:
        return {"available": False, "reason": "java not found"}
    jars = sorted({(Path(rom) / hit["partition"] / "framework" / hit["jar"])
                   for hit in hits})
    classpath = os.pathsep.join(sorted(str(jar) for jar in SMALI3.glob("*.jar")))
    if not classpath:
        return {"available": False, "reason": "smali jars not found"}
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)
    definitions = {}
    for jar in jars:
        try:
            with zipfile.ZipFile(jar) as archive:
                for entry in archive.namelist():
                    if not re.fullmatch(r"classes\d*\.dex", entry):
                        continue
                    dex_path = work_dir / (jar.stem + "-" + entry)
                    dex_path.write_bytes(archive.read(entry))
                    out_dir = work_dir / (jar.stem + "-" + entry + "-out")
                    command = [JAVA, "-cp", classpath,
                               "com.android.tools.smali.baksmali.Main", "d",
                               "--classes", ",".join(TARGET_CLASSES),
                               "-o", str(out_dir), str(dex_path)]
                    proc = subprocess.run(command, capture_output=True, text=True)
                    if proc.returncode != 0 and not out_dir.exists():
                        continue
                    for smali in out_dir.rglob("*.smali"):
                        relative = smali.relative_to(out_dir).as_posix()
                        descriptor = "L" + relative[:-len(".smali")] + ";"
                        definitions.setdefault(descriptor, []).append(
                            "%s/%s (%s)" % (jar.name, entry, relative))
        except Exception:
            continue
    return {"available": True, "definitions": definitions}


def scan_vintf(rom):
    paths = [
        Path(rom) / "vendor" / "etc" / "vintf" / "manifest.xml",
        Path(rom) / "odm" / "etc" / "vintf" / "manifest.xml",
        Path(rom) / "system" / "system" / "etc" / "vintf" / "manifest.xml",
    ]
    result = {"keymaster": None, "keymint": None}
    for path in paths:
        if not safe_exists(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        keymaster = re.findall(r"@(\d+\.\d+)::IKeymasterDevice", text)
        if keymaster:
            result["keymaster"] = sorted(set(keymaster))[-1]
        keymint = re.findall(r"<version>(\d+)</version>", text) \
            if "android.hardware.security.keymint" in text else []
        if keymint:
            result["keymint"] = sorted(set(keymint), key=int)[-1]
    return result


def scan_otacerts(rom):
    path = Path(rom) / "system" / "system" / "etc" / "security" / "otacerts.zip"
    if not safe_exists(path):
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    except Exception:
        return []


def scan_fstab(rom):
    lines = []
    for candidate in sorted((Path(rom) / "vendor" / "etc").glob("fstab*")):
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "avb" in line or "verity" in line:
                    lines.append(line)
        except Exception:
            continue
    return lines


def check_anchors(rom, work_dir):
    classpath = os.pathsep.join(sorted(str(jar) for jar in SMALI3.glob("*.jar")))
    results = {}
    if not classpath:
        return results
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)
    for key, entries in ANCHOR_FILES.items():
        jar_name, dex_name = key.split("/")
        jar_path = Path(rom) / "system" / "system" / "framework" / jar_name
        if not jar_path.exists():
            continue
        try:
            with zipfile.ZipFile(jar_path) as archive:
                dex_path = work_dir / (jar_name + "-" + dex_name)
                dex_path.write_bytes(archive.read(dex_name))
                out_dir = work_dir / (jar_name + "-" + dex_name + "-smali")
                subprocess.run([JAVA, "-cp", classpath,
                                "com.android.tools.smali.baksmali.Main", "d",
                                "-o", str(out_dir), str(dex_path)],
                               capture_output=True, text=True)
                for relative, method in entries:
                    smali_path = out_dir / relative.replace("/", os.sep)
                    present = smali_path.exists()
                    contains = False
                    if present:
                        text = smali_path.read_text(encoding="utf-8", errors="replace")
                        contains = method in text
                    results["%s/%s:%s" % (jar_name, dex_name, relative)] = {
                        "class": present, "method": contains}
        except Exception as error:
            results[key] = {"error": str(error)}
    return results


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF stock ROM audit")
    parser.add_argument("--rom", required=True, help="unpacked ROM root")
    parser.add_argument("--out", default=str(ROOT / "out" / "rom-audit.json"))
    parser.add_argument("--work", default=str(ROOT / "work" / "audit"))
    parser.add_argument("--skip-definitions", action="store_true")
    parser.add_argument("--skip-anchors", action="store_true")
    args = parser.parse_args()

    rom = Path(args.rom)
    if not rom.is_dir():
        raise SystemExit("ROM directory not found: %s" % rom)

    report = {
        "rom": str(rom),
        "bootclasspath": read_classpaths(rom, "bootclasspath.pb"),
        "systemserverclasspath": read_classpaths(rom, "systemserverclasspath.pb"),
        "build_props": read_build_props(rom),
        "target_hits": scan_target_classes(rom),
        "vintf": scan_vintf(rom),
        "otacerts": scan_otacerts(rom),
        "fstab_avb": scan_fstab(rom),
    }
    if not args.skip_definitions:
        report["definitions"] = baksmali_definitions(
            rom, report["target_hits"], Path(args.work) / "definitions")
    if not args.skip_anchors:
        report["anchors"] = check_anchors(rom, Path(args.work) / "anchors")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("ROM:", report["rom"])
    print("bootclasspath:", ", ".join(Path(item).name for item in report["bootclasspath"]))
    print("systemserverclasspath:",
          ", ".join(Path(item).name for item in report["systemserverclasspath"]))
    print("VINTF:", report["vintf"])
    print("otacerts:", report["otacerts"])
    print("target hits:")
    for hit in report["target_hits"]:
        print("  %s/%s %s -> %d descriptors" % (
            hit["partition"], hit["jar"], hit["dex"], len(hit["descriptors"])))
    definitions = report.get("definitions", {})
    if definitions.get("available"):
        print("definitions:")
        for descriptor, where in definitions["definitions"].items():
            print("  %s: %s" % (descriptor, ", ".join(where)))
    anchors = report.get("anchors", {})
    if anchors:
        missing = [key for key, value in anchors.items()
                   if not value.get("class", False) or not value.get("method", False)]
        print("anchors: %d checked, %d missing" % (len(anchors), len(missing)))
        for key in missing:
            print("  MISSING", key)
    print("report:", out_path)


if __name__ == "__main__":
    main()
