#!/usr/bin/env python3
"""
Farewell-PIF full build pipeline:
  1. compile hook sources against android-all + BouncyCastle
  2. package classes and run D8 to produce the hook dex
  3. patch stock framework.jar / services.jar

Usage: python build.py [--only framework|services] [--skip-compile]
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BOOTSTRAP_SRC = ROOT / "hook" / "bootstrap"
IMPL_SRC = ROOT / "hook" / "impl"
LIBS = ROOT / "tools" / "libs"
SMALI3 = ROOT / "tools" / "smali3"
R8_CANDIDATES = sorted((ROOT / "tools").glob("r8*.jar"))
R8_JAR = R8_CANDIDATES[0] if R8_CANDIDATES else ROOT / "tools" / "r8.jar"
BUILD = ROOT / "build" / "hook"
PATCHER = ROOT / "patcher" / "farewell_patch.py"


def find_jdk_tool(name):
    found = shutil.which(name)
    if found:
        return found
    candidates = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidates.append(Path(java_home) / "bin" / (name + ".exe"))
    candidates += sorted(Path(r"C:\Program Files\Java").glob("jdk-*/bin/" + name + ".exe"))
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise SystemExit("JDK tool not found: %s" % name)


def run(cmd):
    print("$ " + " ".join(str(part) for part in cmd))
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        raise SystemExit("command failed with exit code %d" % proc.returncode)


def compile_hook():
    javac = find_jdk_tool("javac")
    jar = find_jdk_tool("jar")
    java = find_jdk_tool("java")
    classpath = os.pathsep.join([
        str(LIBS / "android-all-12.jar"),
        str(LIBS / "android-31.jar"),
        str(LIBS / "bcprov-slim.jar"),
    ])

    # 1) bootstrap (tiny shim that goes into framework.jar)
    bootstrap_classes = BUILD / "bootstrap-classes"
    if bootstrap_classes.exists():
        shutil.rmtree(bootstrap_classes)
    bootstrap_classes.mkdir(parents=True)
    run([javac, "--release", "11", "-encoding", "UTF-8", "-cp", classpath,
         "-d", str(bootstrap_classes)]
        + [str(path) for path in BOOTSTRAP_SRC.rglob("*.java")])
    bootstrap_jar = BUILD / "bootstrap.jar"
    run([jar, "--create", "--file", str(bootstrap_jar),
         "-C", str(bootstrap_classes), "."])
    dex_dir = BUILD / "dex"
    if dex_dir.exists():
        shutil.rmtree(dex_dir)
    dex_dir.mkdir(parents=True)
    run([java, "-cp", str(R8_JAR), "com.android.tools.r8.D8",
         "--release", "--min-api", "31", "--output", str(dex_dir),
         str(bootstrap_jar)])
    print("bootstrap dex: " + ", ".join(
        "%s (%.1f KB)" % (dex.name, dex.stat().st_size / 1024)
        for dex in dex_dir.glob("classes*.dex")))

    # 2) impl (the hot-swappable hook dex shipped as an APK asset)
    impl_classes = BUILD / "impl-classes"
    if impl_classes.exists():
        shutil.rmtree(impl_classes)
    impl_classes.mkdir(parents=True)
    run([javac, "--release", "11", "-encoding", "UTF-8", "-cp", classpath,
         "-d", str(impl_classes)]
        + [str(path) for path in IMPL_SRC.rglob("*.java")])
    impl_jar = BUILD / "impl.jar"
    run([jar, "--create", "--file", str(impl_jar), "-C", str(impl_classes), "."])
    impl_dir = BUILD / "impl"
    if impl_dir.exists():
        shutil.rmtree(impl_dir)
    impl_dir.mkdir(parents=True)
    run([java, "-cp", str(R8_JAR), "com.android.tools.r8.D8",
         "--release", "--min-api", "31", "--output", str(impl_dir),
         str(impl_jar), str(LIBS / "bcprov-slim.jar")])
    impl_dex = impl_dir / "classes.dex"
    if not impl_dex.exists():
        raise SystemExit("D8 produced no impl dex")
    target = impl_dir / "hook.dex"
    if target.exists():
        target.unlink()
    impl_dex.rename(target)
    print("impl dex: hook.dex (%.1f KB) -> app asset" % (target.stat().st_size / 1024))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=["framework", "services"], default=None)
    parser.add_argument("--skip-compile", action="store_true")
    parser.add_argument("--hook-only", action="store_true",
                        help="build the hook dex only (no jar patching; useful for CI)")
    parser.add_argument("--lab", action="store_true",
                        help="run the offline attestation lab after patching")
    parser.add_argument("--keybox", default=None,
                        help="keybox path for --lab (default: ../keybox.xml)")
    parser.add_argument("--lab-version", default="100/100",
                        help="attestation/keymaster version tuple for --lab, e.g. 3/4")
    args = parser.parse_args()

    if not args.skip_compile:
        compile_hook()

    if args.hook_only:
        print("hook build complete (hook-only mode)")
        return

    cmd = [sys.executable, str(PATCHER)]
    if args.only:
        cmd += ["--only", args.only]
    run(cmd)

    if args.lab:
        lab = [sys.executable, str(ROOT / "tools" / "attestation_lab.py"),
               "--all", "--loop", "10"]
        if args.keybox:
            lab += ["--keybox", args.keybox]
        if args.lab_version:
            attestation, keymaster = args.lab_version.split("/")
            lab += ["--att-version", attestation, "--km-version", keymaster]
        run(lab)


if __name__ == "__main__":
    main()
