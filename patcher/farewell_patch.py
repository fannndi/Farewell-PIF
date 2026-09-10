#!/usr/bin/env python3
"""
Farewell-PIF rootless jar patcher.

Rebuilds framework.jar / services.jar from stock jars by
  1. disassembling every classes*.dex with baksmali 3.x,
  2. injecting FarewellHook calls at the mapped anchor points,
  3. reassembling with smali 3.x,
  4. appending the Farewell-PIF hook dex to framework.jar.

Stock jars are never modified; results land in --out.
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

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
SMALI3 = TOOLS / "smali3"
JAVA = "java"
JAVA_HEAP = "-Xmx4g"

HOOK_DESCRIPTOR = "Ldev/farewell/pif/FarewellHook;"

FRAMEWORK_TARGETS = {
    "classes.dex": [
        "Landroid/app/Instrumentation;",
        "Landroid/app/ApplicationPackageManager;",
    ],
    "classes2.dex": [
        "Landroid/security/KeyStore2;",
        "Landroid/security/keystore2/AndroidKeyStoreSpi;",
        "Landroid/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi;",
        "Landroid/os/SystemProperties;",
    ],
}

SERVICES_TARGETS = {
    "classes.dex": [
        "Lcom/android/server/SystemServer;",
        "Lcom/android/server/devicepolicy/DevicePolicyCacheImpl;",
    ],
    "classes2.dex": [
        "Lcom/android/server/wm/WindowState;",
        "Lcom/android/server/wm/WindowStateAnimator;",
    ],
}

CODE_INIT_CTX_CLASS = (
    "    invoke-static {p1}, Ldev/farewell/pif/FarewellHook;->initContext(Landroid/content/Context;)V\n"
)
CODE_INIT_CTX_LOADER = (
    "    invoke-static {p3}, Ldev/farewell/pif/FarewellHook;->initContext(Landroid/content/Context;)V\n"
)
CODE_HAS_FEATURE = (
    "    invoke-static {p1, p2}, Ldev/farewell/pif/FarewellHook;->hasSystemFeature(Ljava/lang/String;I)Ljava/lang/Boolean;\n"
    "\n"
    "    move-result-object @TEMP@\n"
    "\n"
    "    if-eqz @TEMP@, :cond_farewell\n"
    "\n"
    "    invoke-virtual {@TEMP@}, Ljava/lang/Boolean;->booleanValue()Z\n"
    "\n"
    "    move-result @TEMP@\n"
    "\n"
    "    return @TEMP@\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_GET_KEY_ENTRY = (
    "    invoke-static {v0}, Ldev/farewell/pif/FarewellHook;->getKeyEntry(Landroid/system/keystore2/KeyEntryResponse;)Landroid/system/keystore2/KeyEntryResponse;\n"
    "\n"
    "    move-result-object v0\n"
)
CODE_CERT_CHAIN = (
    "    invoke-static {v3}, Ldev/farewell/pif/FarewellHook;->certificateChainIfNeeded([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;\n"
    "\n"
    "    move-result-object v3\n"
)
CODE_SOFTWARE_KEY = (
    "    invoke-static {p0}, Ldev/farewell/pif/FarewellHook;->softwareKeyPair(Ljava/lang/Object;)Ljava/security/KeyPair;\n"
    "\n"
    "    move-result-object @TEMP@\n"
    "\n"
    "    if-eqz @TEMP@, :cond_farewell\n"
    "\n"
    "    return-object @TEMP@\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_INIT_SYSTEM_SERVER = (
    "    invoke-static {}, Ldev/farewell/pif/FarewellHook;->initSystemServer()V\n"
)
CODE_SECURE_ALLOW = (
    "    invoke-static {}, Ldev/farewell/pif/FarewellHook;->isSecureFlag()Z\n"
    "\n"
    "    move-result @TEMP@\n"
    "\n"
    "    if-eqz @TEMP@, :cond_farewell\n"
    "\n"
    "    const/4 @TEMP@, 0x1\n"
    "\n"
    "    return @TEMP@\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_SECURE_LOCKED = (
    "    invoke-static {}, Ldev/farewell/pif/FarewellHook;->isSecureFlag()Z\n"
    "\n"
    "    move-result @TEMP@\n"
    "\n"
    "    if-eqz @TEMP@, :cond_farewell\n"
    "\n"
    "    const/4 @TEMP@, 0x0\n"
    "\n"
    "    return @TEMP@\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_SECURE_SET = (
    "    invoke-static {}, Ldev/farewell/pif/FarewellHook;->isSecureFlag()Z\n"
    "\n"
    "    move-result @TEMP@\n"
    "\n"
    "    if-eqz @TEMP@, :cond_farewell\n"
    "\n"
    "    return-void\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_CHAIN_FOR_ALIAS = (
    "    invoke-static {p1}, Ldev/farewell/pif/FarewellHook;->certificateChainForAlias(Ljava/lang/String;)[Ljava/security/cert/Certificate;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-nez v0, :cond_farewell\n"
    "\n"
    "    return-object v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_KEY_FOR_ALIAS = (
    "    invoke-static {p1}, Ldev/farewell/pif/FarewellHook;->softwareKeyForAlias(Ljava/lang/String;)Ljava/security/Key;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-nez v0, :cond_farewell\n"
    "\n"
    "    return-object v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_CERT_FOR_ALIAS = (
    "    invoke-static {p1}, Ldev/farewell/pif/FarewellHook;->certificateForAlias(Ljava/lang/String;)Ljava/security/cert/Certificate;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-nez v0, :cond_farewell\n"
    "\n"
    "    return-object v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_PROP_STR = (
    "    invoke-static {p0, p1}, Ldev/farewell/pif/FarewellHook;->property(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-eqz v0, :cond_farewell\n"
    "\n"
    "    return-object v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_PROP_STR_NULL = (
    "    const/4 v0, 0x0\n"
    "\n"
    "    invoke-static {p0, v0}, Ldev/farewell/pif/FarewellHook;->property(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-eqz v0, :cond_farewell\n"
    "\n"
    "    return-object v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_PROP_INT = (
    "    invoke-static {p0, p1}, Ldev/farewell/pif/FarewellHook;->propertyInt(Ljava/lang/String;I)Ljava/lang/Integer;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-eqz v0, :cond_farewell\n"
    "\n"
    "    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I\n"
    "\n"
    "    move-result v0\n"
    "\n"
    "    return v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_PROP_LONG = (
    "    invoke-static {p0, p1, p2}, Ldev/farewell/pif/FarewellHook;->propertyLong(Ljava/lang/String;J)Ljava/lang/Long;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-eqz v0, :cond_farewell\n"
    "\n"
    "    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J\n"
    "\n"
    "    move-result-wide v0\n"
    "\n"
    "    return-wide v0\n"
    "\n"
    "    :cond_farewell\n"
)
CODE_PROP_BOOL = (
    "    invoke-static {p0, p1}, Ldev/farewell/pif/FarewellHook;->propertyBoolean(Ljava/lang/String;Z)Ljava/lang/Boolean;\n"
    "\n"
    "    move-result-object v0\n"
    "\n"
    "    if-eqz v0, :cond_farewell\n"
    "\n"
    "    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z\n"
    "\n"
    "    move-result v0\n"
    "\n"
    "    return v0\n"
    "\n"
    "    :cond_farewell\n"
)


class PatchError(Exception):
    pass


def run(cmd, timeout=3600):
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise PatchError(
            "command failed (%s):\n%s\n%s"
            % (proc.returncode, " ".join(str(c) for c in cmd), proc.stderr[-4000:])
        )
    return proc.stdout


def smali_classpath():
    jars = sorted(str(jar) for jar in SMALI3.glob("*.jar"))
    if not jars:
        raise PatchError("no jars found in %s" % SMALI3)
    return os.pathsep.join(jars)


def baksmali_dex(dex_path, out_dir, classes=None, cp=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [JAVA, JAVA_HEAP, "-cp", cp or smali_classpath(),
           "com.android.tools.smali.baksmali.Main", "d", "-a", "31"]
    if classes:
        cmd += ["--classes", ",".join(classes)]
    cmd += ["-o", str(out_dir), str(dex_path)]
    run(cmd)


def smali_assemble(smali_dir, out_dex, cp=None):
    cmd = [JAVA, JAVA_HEAP, "-cp", cp or smali_classpath(),
           "com.android.tools.smali.smali.Main", "a", "-a", "31",
           "-o", str(out_dex), str(smali_dir)]
    run(cmd)


def method_block(text, signature):
    lines = text.splitlines(keepends=True)
    start = None
    for index, line in enumerate(lines):
        if (line.startswith(".method") and signature in line
                and " native_" not in line):
            start = index
            break
    if start is None:
        raise PatchError("method not found: %s" % signature)
    end = None
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(".end method"):
            end = index
            break
    if end is None:
        raise PatchError("method end not found: %s" % signature)
    return start, end, "".join(lines[start:end + 1])


def modify_method(text, signature, fn):
    start, end, block = method_block(text, signature)
    lines = text.splitlines(keepends=True)
    updated = fn(block)
    return "".join(lines[:start]) + updated + "".join(lines[end + 1:])


REGISTERS_RE = re.compile(r"^(\s*\.(?:registers|locals)\s+)(\d+)[ \t]*$", re.M)


def insert_after_registers(block, template, params, bump=1):
    """Insert code after the .registers directive, allocating one fresh local.

    The fresh register is the last local after bumping (orig - params), which keeps every
    existing vN reference valid because pN remapping is symbolic in smali.
    """
    match = REGISTERS_RE.search(block)
    if not match:
        raise PatchError("no .registers directive found")
    original = int(match.group(2))
    temp = "v%d" % (original - params)
    code = template.replace("@TEMP@", temp)
    bumped = "%s%d" % (match.group(1), original + bump)
    block = block[:match.start()] + bumped + block[match.end():]
    match = REGISTERS_RE.search(block)
    return block[:match.end()] + "\n" + code + block[match.end():]


def insert_after(block, anchor, code, expect=1):
    found = block.count(anchor)
    if found != expect:
        raise PatchError("anchor count %d != %d for %r" % (found, expect, anchor.strip()))
    return block.replace(anchor, anchor + code, 1)


def insert_before(block, anchor, code, expect=1):
    found = block.count(anchor)
    if found != expect:
        raise PatchError("anchor count %d != %d for %r" % (found, expect, anchor.strip()))
    return block.replace(anchor, code + anchor, 1)


def patch_framework_instrumentation(text):
    def class_variant(block):
        return insert_before(block, "    return-object v0", CODE_INIT_CTX_CLASS)

    def loader_variant(block):
        return insert_before(block, "    return-object v0", CODE_INIT_CTX_LOADER)

    text = modify_method(
        text,
        "newApplication(Ljava/lang/Class;Landroid/content/Context;)Landroid/app/Application;",
        class_variant)
    text = modify_method(
        text,
        "newApplication(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)Landroid/app/Application;",
        loader_variant)
    return text


def patch_framework_app_pkg_mgr(text):
    def has_feature(block):
        return insert_after_registers(block, CODE_HAS_FEATURE, params=3)

    return modify_method(text, "hasSystemFeature(Ljava/lang/String;I)Z", has_feature)


def patch_framework_keystore2(text):
    def get_key_entry(block):
        return insert_before(block, "    return-object v0", CODE_GET_KEY_ENTRY)

    return modify_method(
        text,
        "getKeyEntry(Landroid/system/keystore2/KeyDescriptor;)Landroid/system/keystore2/KeyEntryResponse;",
        get_key_entry)


def patch_framework_android_keystore_spi(text):
    def chain(block):
        first = ("    invoke-direct {p0, p1}, Landroid/security/keystore2/AndroidKeyStoreSpi;->"
                 "getKeyMetadata(Ljava/lang/String;)Landroid/system/keystore2/KeyEntryResponse;\n")
        block = insert_before(block, first, CODE_CHAIN_FOR_ALIAS)
        anchor = "    aput-object v2, v3, v4\n"
        if block.count(anchor) == 0:
            raise PatchError("engineGetCertificateChain anchor missing")
        return block.replace(anchor, anchor + CODE_CERT_CHAIN, 1)

    def get_key(block):
        return insert_before(block, "    :try_start_0\n", CODE_KEY_FOR_ALIAS)

    def get_certificate(block):
        first = ("    invoke-direct {p0, p1}, Landroid/security/keystore2/AndroidKeyStoreSpi;->"
                 "getKeyMetadata(Ljava/lang/String;)Landroid/system/keystore2/KeyEntryResponse;\n")
        return insert_before(block, first, CODE_CERT_FOR_ALIAS)

    text = modify_method(
        text,
        "engineGetCertificateChain(Ljava/lang/String;)[Ljava/security/cert/Certificate;",
        chain)
    text = modify_method(text, "engineGetKey(Ljava/lang/String;", get_key)
    text = modify_method(text, "engineGetCertificate(Ljava/lang/String;", get_certificate)
    return text


def patch_framework_key_pair_generator(text):
    def key_pair(block):
        return insert_after_registers(block, CODE_SOFTWARE_KEY, params=1)

    return modify_method(text, "generateKeyPair()Ljava/security/KeyPair;", key_pair)


def patch_services_system_server(text):
    anchor = ("    invoke-direct {v1, v6}, Lcom/android/server/SystemServer;->"
              "startOtherServices(Lcom/android/server/utils/TimingsTraceAndSlog;)V\n")
    if text.count(anchor) != 1:
        raise PatchError("SystemServer startOtherServices anchor missing")
    return text.replace(anchor, CODE_INIT_SYSTEM_SERVER + anchor, 1)


def patch_services_device_policy(text):
    def allow(block):
        return insert_after_registers(block, CODE_SECURE_ALLOW, params=3)

    return modify_method(text, "isScreenCaptureAllowed(", allow)


def patch_services_window_state(text):
    def locked(block):
        return insert_after_registers(block, CODE_SECURE_LOCKED, params=1)

    return modify_method(text, ".method isSecureLocked()Z", locked)


def patch_services_window_state_animator(text):
    def set_locked(block):
        return insert_after_registers(block, CODE_SECURE_SET, params=2)

    return modify_method(text, "setSecureLocked(Z)V", set_locked)


def patch_framework_system_properties(text):
    def get_one(block):
        anchor = ("    invoke-static {p0}, Landroid/os/SystemProperties;->"
                  "native_get(Ljava/lang/String;)Ljava/lang/String;\n")
        return insert_before(block, anchor, CODE_PROP_STR_NULL)

    def get_two(block):
        anchor = ("    invoke-static {p0, p1}, Landroid/os/SystemProperties;->"
                  "native_get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;\n")
        return insert_before(block, anchor, CODE_PROP_STR)

    def get_int(block):
        anchor = ("    invoke-static {p0, p1}, Landroid/os/SystemProperties;->"
                  "native_get_int(Ljava/lang/String;I)I\n")
        return insert_before(block, anchor, CODE_PROP_INT)

    def get_long(block):
        anchor = ("    invoke-static {p0, p1, p2}, Landroid/os/SystemProperties;->"
                  "native_get_long(Ljava/lang/String;J)J\n")
        return insert_before(block, anchor, CODE_PROP_LONG)

    def get_boolean(block):
        anchor = ("    invoke-static {p0, p1}, Landroid/os/SystemProperties;->"
                  "native_get_boolean(Ljava/lang/String;Z)Z\n")
        return insert_before(block, anchor, CODE_PROP_BOOL)

    text = modify_method(text, "get(Ljava/lang/String;)Ljava/lang/String;", get_one)
    text = modify_method(text, "get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                         get_two)
    text = modify_method(text, "getInt(Ljava/lang/String;I)I", get_int)
    text = modify_method(text, "getLong(Ljava/lang/String;J)J", get_long)
    text = modify_method(text, "getBoolean(Ljava/lang/String;Z)Z", get_boolean)
    return text


FRAMEWORK_PATCHES = {
    "classes.dex": {
        "android/app/Instrumentation.smali": patch_framework_instrumentation,
        "android/app/ApplicationPackageManager.smali": patch_framework_app_pkg_mgr,
    },
    "classes2.dex": {
        "android/security/KeyStore2.smali": patch_framework_keystore2,
        "android/security/keystore2/AndroidKeyStoreSpi.smali": patch_framework_android_keystore_spi,
        "android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi.smali": patch_framework_key_pair_generator,
        "android/os/SystemProperties.smali": patch_framework_system_properties,
    },
}

SERVICES_PATCHES = {
    "classes.dex": {
        "com/android/server/SystemServer.smali": patch_services_system_server,
        "com/android/server/devicepolicy/DevicePolicyCacheImpl.smali": patch_services_device_policy,
    },
    "classes2.dex": {
        "com/android/server/wm/WindowState.smali": patch_services_window_state,
        "com/android/server/wm/WindowStateAnimator.smali": patch_services_window_state_animator,
    },
}

# Patches that may legitimately be absent/different on other ROMs or Android versions.
OPTIONAL_PATCHES = {
    "android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi.smali",
    "com/android/server/devicepolicy/DevicePolicyCacheImpl.smali",
    "com/android/server/wm/WindowState.smali",
    "com/android/server/wm/WindowStateAnimator.smali",
}


def dex_sort_key(name):
    match = re.fullmatch(r"classes(\d*)\.dex", name)
    if not match:
        return 0
    return int(match.group(1)) if match.group(1) else 1


def extract_dexes(jar_path, work_dir):
    dexes = {}
    with zipfile.ZipFile(jar_path) as jar:
        for name in jar.namelist():
            if re.fullmatch(r"classes\d*\.dex", name):
                dexes[name] = jar.read(name)
    out_dir = work_dir / "dex"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in dexes.items():
        (out_dir / name).write_bytes(data)
    return sorted(dexes, key=dex_sort_key)


def patch_tree(jar_name, smali_root, patches, targets):
    report = []
    for dex_name in sorted(targets, key=dex_sort_key):
        dex_dir = smali_root / dex_name
        if not dex_dir.exists():
            raise PatchError("%s: smali dir missing for %s" % (jar_name, dex_name))
        for relative, fn in patches.items():
            target = dex_dir / relative
            if not target.exists():
                # class may live in another dex: only patch where present
                continue
            text = target.read_text(encoding="utf-8")
            if HOOK_DESCRIPTOR in text:
                report.append({"file": str(relative), "dex": dex_name, "status": "already"})
                continue
            try:
                updated = fn(text)
            except PatchError as error:
                if str(relative) in OPTIONAL_PATCHES:
                    report.append({"file": str(relative), "dex": dex_name,
                                   "status": "skipped", "reason": str(error)})
                    continue
                raise
            target.write_text(updated, encoding="utf-8")
            report.append({"file": str(relative), "dex": dex_name, "status": "patched"})
    # ensure every expected patch landed
    for relative in patches:
        if str(relative) in OPTIONAL_PATCHES:
            continue
        hit = False
        for dex_name in targets:
            for entry in report:
                if entry["file"] == str(relative):
                    hit = True
        if not hit:
            raise PatchError("%s: patch target never found: %s" % (jar_name, relative))
    return report


def next_dex_names(start_index, count):
    names = []
    for offset in range(count):
        index = start_index + offset
        names.append("classes.dex" if index == 1 else "classes%d.dex" % index)
    return names


def repack(jar_path, out_path, replacements, extra_dexes=None):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    with zipfile.ZipFile(jar_path) as jar:
        existing = [name for name in jar.namelist()
                    if re.fullmatch(r"classes\d*\.dex", name)]
    start_index = max((dex_sort_key(name) for name in existing), default=0) + 1
    extras = {}
    if extra_dexes:
        for name, data in zip(next_dex_names(start_index, len(extra_dexes)), extra_dexes):
            extras[name] = data
    with zipfile.ZipFile(jar_path) as zin, \
            zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            if info.filename in replacements:
                data = replacements[info.filename]
            elif info.filename in extras:
                data = extras.pop(info.filename)
            else:
                data = zin.read(info.filename)
            zout.writestr(info, data)
        for name, data in extras.items():
            zout.writestr(name, data)
    return start_index


def dex_version(data):
    try:
        if data[:4] != b"dex\n" or data[7:8] != b"\x00":
            return None
        return data[4:7]
    except Exception:
        return None


def preserve_dex_version(path, version):
    if not version:
        return
    data = bytearray(path.read_bytes())
    if data[:4] != b"dex\n" or data[7:8] != b"\x00":
        return
    data[4:7] = version
    path.write_bytes(bytes(data))


def process_jar(jar_path, work_root, out_dir, targets, patches, hook_dexes=None):
    jar_name = Path(jar_path).name
    stem = Path(jar_path).stem
    work = work_root / stem
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    dex_names = extract_dexes(jar_path, work)
    print("[%s] dex files: %s" % (jar_name, ", ".join(dex_names)))

    smali_root = work / "smali"
    rebuilt = {}
    rebuilt_paths = {}
    all_report = []
    for dex_name in dex_names:
        original = (work / "dex" / dex_name).read_bytes()
        dex_patches = patches.get(dex_name, {})
        if not dex_patches or dex_name not in targets:
            # No patch target in this dex: pass the original bytes through untouched.
            rebuilt[dex_name] = original
            continue
        print("[%s] disassembling %s ..." % (jar_name, dex_name))
        baksmali_dex(work / "dex" / dex_name, smali_root / dex_name)

        report = patch_tree(jar_name, smali_root, dex_patches, {dex_name: targets[dex_name]})
        for entry in report:
            entry["dex"] = dex_name
        all_report.extend(report)

        print("[%s] assembling %s ..." % (jar_name, dex_name))
        out_dex = work / "out" / dex_name
        out_dex.parent.mkdir(parents=True, exist_ok=True)
        smali_assemble(smali_root / dex_name, out_dex)
        preserve_dex_version(out_dex, dex_version(original))
        rebuilt[dex_name] = out_dex.read_bytes()
        rebuilt_paths[dex_name] = out_dex

    out_jar = out_dir / jar_name
    start_index = repack(Path(jar_path), out_jar, rebuilt, extra_dexes=hook_dexes)
    print("[%s] written %s (hook dex starts at index %d)" % (jar_name, out_jar, start_index))
    return all_report, out_jar, rebuilt_paths


VERIFY_EXPECTATIONS = {
    "framework.jar": {
        "classes.dex": {
            "Landroid/app/Instrumentation;": 2,
            "Landroid/app/ApplicationPackageManager;": 1,
        },
        "classes2.dex": {
            "Landroid/security/KeyStore2;": 1,
            "Landroid/security/keystore2/AndroidKeyStoreSpi;": 4,
            "Landroid/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi;": -1,
            "Landroid/os/SystemProperties;": 5,
        },
    },
    "services.jar": {
        "classes.dex": {
            "Lcom/android/server/SystemServer;": 1,
            "Lcom/android/server/devicepolicy/DevicePolicyCacheImpl;": -1,
        },
        "classes2.dex": {
            "Lcom/android/server/wm/WindowState;": -1,
            "Lcom/android/server/wm/WindowStateAnimator;": -1,
        },
    },
}


def verify_jar(jar_name, rebuilt_paths, work_dir):
    expectations = VERIFY_EXPECTATIONS[jar_name]
    results = {}
    for dex_name, classes in expectations.items():
        dex_path = rebuilt_paths.get(dex_name)
        if dex_path is None:
            raise PatchError("%s: missing rebuilt %s" % (jar_name, dex_name))
        out = work_dir / ("verify-" + dex_name)
        if out.exists():
            shutil.rmtree(out)
        baksmali_dex(dex_path, out, classes=list(classes))
        for class_name, expected in classes.items():
            smali_path = out / (class_name[1:-1].replace("/", os.sep) + ".smali")
            if not smali_path.exists():
                if expected < 0:
                    results[class_name] = {"skipped": True}
                    continue
                raise PatchError("%s: verify missing %s" % (jar_name, class_name))
            text = smali_path.read_text(encoding="utf-8", errors="replace")
            calls = text.count(HOOK_DESCRIPTOR)
            if expected < 0:
                if calls < 1:
                    raise PatchError("%s %s: present but has no hook calls" % (jar_name, class_name))
            elif calls < expected:
                raise PatchError(
                    "%s %s: hook calls %d < %d" % (jar_name, class_name, calls, expected))
            results[class_name] = {"hook_calls": calls,
                                   "cond_labels": text.count(":cond_farewell")}
    return results


def detect_sdk(stock_dir):
    """Best effort SDK level from the sibling build.prop (for portability reporting)."""
    for candidate in (Path(stock_dir).parent / "build.prop",
                      Path(stock_dir) / "build.prop"):
        try:
            if not candidate.exists():
                continue
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("ro.build.version.sdk="):
                    return line.split("=", 1)[1].strip()
        except Exception:
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF jar patcher")
    parser.add_argument("--stock", default=str(ROOT / "rom" / "stock" / "framework"),
                        help="directory containing stock framework.jar/services.jar")
    parser.add_argument("--hook-dex", default=str(ROOT / "build" / "hook" / "dex"),
                        help="directory containing the hook classes*.dex")
    parser.add_argument("--out", default=str(ROOT / "out"), help="output directory")
    parser.add_argument("--work", default=str(ROOT / "work" / "patch"), help="work directory")
    parser.add_argument("--only", choices=["framework", "services"], default=None)
    parser.add_argument("--skip-verify", action="store_true")
    args = parser.parse_args()

    stock = Path(args.stock)
    out_dir = Path(args.out)
    work_root = Path(args.work)
    hook_dir = Path(args.hook_dex)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)

    hook_dexes = []
    if hook_dir.exists():
        hook_dexes = [path.read_bytes() for path in
                      sorted(hook_dir.glob("classes*.dex"), key=lambda p: dex_sort_key(p.name))]
    if not hook_dexes:
        raise PatchError("no hook dex found in %s" % hook_dir)

    summary = {"stock_sdk": detect_sdk(stock)}
    if args.only in (None, "framework"):
        report, out_jar, rebuilt_paths = process_jar(
            stock / "framework.jar", work_root, out_dir,
            FRAMEWORK_TARGETS, FRAMEWORK_PATCHES, hook_dexes=hook_dexes)
        summary["framework.jar"] = {"patches": report, "out": str(out_jar)}
        if not args.skip_verify:
            summary["framework.jar"]["verify"] = verify_jar(
                "framework.jar", rebuilt_paths, work_root / "framework")
    if args.only in (None, "services"):
        report, out_jar, rebuilt_paths = process_jar(
            stock / "services.jar", work_root, out_dir,
            SERVICES_TARGETS, SERVICES_PATCHES, hook_dexes=None)
        summary["services.jar"] = {"patches": report, "out": str(out_jar)}
        if not args.skip_verify:
            summary["services.jar"]["verify"] = verify_jar(
                "services.jar", rebuilt_paths, work_root / "services")

    report_path = out_dir / "patch-report.json"
    report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print("report: %s" % report_path)


if __name__ == "__main__":
    try:
        main()
    except PatchError as error:
        print("PATCH ERROR: %s" % error, file=sys.stderr)
        sys.exit(1)
