#!/usr/bin/env python3
"""
Build the Farewell-PIF companion APK (no Gradle, no AndroidX).

Steps: javac -> d8 -> aapt2 link -> add classes.dex -> zipalign -> apksigner.
Outputs:
  out/FarewellPIF.apk
  out/privapp/dev.farewell.pif.xml
"""

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
BUILD = ROOT / "build" / "app"
OUT = ROOT / "out"
APP = ROOT / "app"

ANDROID_JAR = TOOLS / "libs" / "android-31.jar"
AAPT2 = TOOLS / "buildtools" / "android-13" / "aapt2.exe"
ZIPALIGN = TOOLS / "buildtools" / "android-13" / "zipalign.exe"
APKSIGNER = TOOLS / "buildtools" / "android-13" / "apksigner.bat"
R8_JAR = TOOLS / "r8-9.4.17.jar"
KEYSTORE = TOOLS / "farewell.keystore"

KEYSTORE_PASS = "farewell"
KEY_ALIAS = "farewell"


def find_jdk_tool(name):
    found = shutil.which(name)
    if found:
        return found
    java_home = os.environ.get("JAVA_HOME")
    candidates = []
    if java_home:
        candidates.append(Path(java_home) / "bin" / (name + ".exe"))
    candidates += sorted(Path(r"C:\Program Files\Java").glob("jdk-*/bin/" + name + ".exe"))
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise SystemExit("JDK tool not found: %s" % name)


def run(cmd):
    print("$ " + " ".join(str(part) for part in cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-3000:])
        print(proc.stderr[-3000:])
        raise SystemExit("command failed: %s" % cmd[0])
    return proc.stdout


def main():
    if BUILD.exists():
        shutil.rmtree(BUILD)
    (BUILD / "classes").mkdir(parents=True)
    (BUILD / "dex").mkdir(parents=True)
    OUT.mkdir(exist_ok=True)
    (OUT / "privapp").mkdir(exist_ok=True)

    javac = find_jdk_tool("javac")
    java = find_jdk_tool("java")
    jar = find_jdk_tool("jar")
    keytool = find_jdk_tool("keytool")

    hook_dex = ROOT / "build" / "hook" / "impl" / "hook.dex"
    if not hook_dex.exists():
        raise SystemExit("hook.dex missing; run build.py first")
    shutil.copy(hook_dex, APP / "assets" / "hook.dex")
    print("hook asset: %.1f KB" % (hook_dex.stat().st_size / 1024))

    default_profile = ROOT / "reference" / "profile" / "Pif-props.json"
    if default_profile.exists():
        shutil.copy(default_profile, APP / "assets" / "default-profile.json")

    sources = [str(path) for path in (APP / "src").rglob("*.java")]
    run([javac, "--release", "11", "-encoding", "UTF-8",
         "-cp", str(ANDROID_JAR), "-d", str(BUILD / "classes")] + sources)

    classes_jar = BUILD / "app-classes.jar"
    run([jar, "--create", "--file", str(classes_jar), "-C", str(BUILD / "classes"), "."])

    run([java, "-cp", str(R8_JAR), "com.android.tools.r8.D8",
         "--release", "--min-api", "31", "--output", str(BUILD / "dex"),
         str(classes_jar)])

    unsigned = BUILD / "unsigned.apk"
    run([str(AAPT2), "link", "-o", str(unsigned), "-I", str(ANDROID_JAR),
         "--manifest", str(APP / "AndroidManifest.xml"),
         "-A", str(APP / "assets"),
         "--min-sdk-version", "31", "--target-sdk-version", "31",
         "--version-code", "14", "--version-name", "1.8.5"])

    with zipfile.ZipFile(unsigned, "a", zipfile.ZIP_DEFLATED) as apk:
        apk.write(BUILD / "dex" / "classes.dex", "classes.dex")

    aligned = BUILD / "aligned.apk"
    run([str(ZIPALIGN), "-f", "-p", "4", str(unsigned), str(aligned)])

    if not KEYSTORE.exists():
        run([keytool, "-genkeypair", "-keystore", str(KEYSTORE),
             "-alias", KEY_ALIAS, "-keyalg", "RSA", "-keysize", "2048",
             "-validity", "10000", "-storepass", KEYSTORE_PASS, "-keypass", KEYSTORE_PASS,
             "-dname", "CN=Farewell PIF, O=Farewell"])

    signed = OUT / "FarewellPIF.apk"
    run([str(APKSIGNER), "sign", "--ks", str(KEYSTORE),
         "--ks-pass", "pass:" + KEYSTORE_PASS, "--key-pass", "pass:" + KEYSTORE_PASS,
         "--out", str(signed), str(aligned)])

    shutil.copy(APP / "permissions" / "dev.farewell.pif.xml",
                OUT / "privapp" / "dev.farewell.pif.xml")

    print("APK: %s (%.2f MB)" % (signed, signed.stat().st_size / 1e6))
    print("privapp XML: %s" % (OUT / "privapp" / "dev.farewell.pif.xml"))


if __name__ == "__main__":
    main()
