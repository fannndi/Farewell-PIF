#!/usr/bin/env python3
"""
Farewell-PIF provisioning over ADB (manual/offline, no network).

Configuration lives in ONE neutral Settings.Global key as an obfuscated envelope:
"F1:" + base64(XOR(json)). Keybox and profile are loaded from local files only.

Examples:
  python provision.py --status
  python provision.py --install-hook
  python provision.py --keybox C:\\path\\Keybox.xml
  python provision.py --profile C:\\path\\Pif-props.json
  python provision.py --fix
  python provision.py --enable --flags props,keybox,secure
  python provision.py --disable
  python provision.py --clear
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ADB = ROOT / "tools" / "platform-tools" / "adb.exe"
DEFAULT_PROFILE = ROOT / "reference" / "profile" / "Pif-props.json"
HOOK_DEX = ROOT / "build" / "hook" / "impl" / "hook.dex"

NEUTRAL_KEY = "sys_thermal_profile"
HOOK_META = "sys_perf_dex_meta"
HOOK_CHUNK = "sys_perf_dex_"
HOOK_MAX_CHUNKS = 32
HOOK_CHUNK_SIZE = 140 * 1024

LEGACY_KEYS = [
    "farewell_enable", "farewell_flags", "farewell_mode", "farewell_profile",
    "farewell_targets", "farewell_keybox", "farewell_keybox_index",
    "farewell_features", "farewell_debug",
]

FLAG_BITS = {"props": 1, "keybox": 2, "secure": 4, "signature": 8, "provider": 16}

XOR_KEY = bytes([
    0x46, 0x61, 0x72, 0x65, 0x77, 0x65, 0x6C, 0x6C,
    0x50, 0x49, 0x46, 0x2D, 0x53, 0x31, 0x21, 0x50,
    0x72, 0x6F, 0x66, 0x69, 0x6C, 0x65, 0x2D, 0x4B,
    0x65, 0x79, 0x62, 0x6F, 0x78, 0x2D, 0x30, 0x31,
])

DEFAULT_CONFIG = {
    "v": 1, "en": 0, "fl": 3, "md": "auto", "dbg": 0,
    "pf": {}, "tg": ["com.google.android.gms:com.google.android.gms.unstable",
                     "com.android.vending"],
    "nb": [], "kb": [], "kbi": -1, "ft": {}, "ap": {},
}


def adb_path(args):
    if args.adb:
        return args.adb
    if DEFAULT_ADB.exists():
        return str(DEFAULT_ADB)
    return "adb"


def adb(adb_bin, extra, check=True):
    proc = subprocess.run([adb_bin] + extra, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit("adb failed: %s\n%s" % (" ".join(proc.args), proc.stderr))
    return proc.stdout.strip()


def settings_put(adb_bin, key, value):
    if len(value) < 8000:
        adb(adb_bin, ["shell", "settings", "put", "global", key, value])
    else:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".value") as handle:
            handle.write(value)
            local = handle.name
        remote = "/data/local/tmp/farewell_" + key + ".value"
        adb(adb_bin, ["push", local, remote])
        adb(adb_bin, ["shell", "settings put global %s \"$(cat %s)\"" % (key, remote)])
        adb(adb_bin, ["shell", "rm", "-f", remote])
        os.unlink(local)


def settings_get(adb_bin, key):
    return adb(adb_bin, ["shell", "settings", "get", "global", key], check=False)


def settings_delete(adb_bin, key):
    adb(adb_bin, ["shell", "settings", "delete", "global", key], check=False)


def decode_envelope(raw):
    if raw is None:
        return None
    raw = raw.strip()
    if not raw or raw == "null":
        return None
    try:
        if raw.startswith("{"):
            return json.loads(raw)
        if raw.startswith("F1:"):
            data = base64.b64decode(raw[3:])
            xored = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))
            return json.loads(xored.decode("utf-8"))
    except Exception as error:
        print("warning: cannot decode envelope: %s" % error)
    return None


def encode_envelope(config):
    data = json.dumps(config, separators=(",", ":")).encode("utf-8")
    xored = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))
    return "F1:" + base64.b64encode(xored).decode("ascii")


def load_config(adb_bin):
    config = decode_envelope(settings_get(adb_bin, NEUTRAL_KEY))
    if config is None:
        config = json.loads(json.dumps(DEFAULT_CONFIG))
    return config


def save_config(adb_bin, config):
    settings_put(adb_bin, NEUTRAL_KEY, encode_envelope(config))
    for legacy in LEGACY_KEYS:
        settings_delete(adb_bin, legacy)


def flags_to_mask(text):
    mask = 0
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if part not in FLAG_BITS:
            raise SystemExit("unknown flag: %s (use %s)" % (part, ", ".join(FLAG_BITS)))
        mask |= FLAG_BITS[part]
    return mask


def force_stop(adb_bin):
    for package in ("com.google.android.gms", "com.google.android.gms.unstable",
                    "com.android.vending"):
        adb(adb_bin, ["shell", "am", "force-stop", package], check=False)


def verify_sideload(dex_path):
    """Offline round-trip: encode chunks exactly like the app, decode, compare SHA-256."""
    path = Path(dex_path)
    if not path.exists():
        raise SystemExit("hook dex not found: %s" % path)
    dex = path.read_bytes()
    sha = hashlib.sha256(dex).hexdigest()
    chunks = (len(dex) + HOOK_CHUNK_SIZE - 1) // HOOK_CHUNK_SIZE
    encoded = []
    for index in range(chunks):
        part = dex[index * HOOK_CHUNK_SIZE:(index + 1) * HOOK_CHUNK_SIZE]
        xored = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(part))
        encoded.append(base64.b64encode(xored).decode("ascii"))
    rebuilt = bytearray()
    for item in encoded:
        xored = base64.b64decode(item)
        rebuilt.extend(bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(xored)))
    rebuilt_sha = hashlib.sha256(bytes(rebuilt)).hexdigest()
    meta = "%s:%d:selftest" % (sha, chunks)
    ok = rebuilt_sha == sha and len(rebuilt) == len(dex)
    print(json.dumps({
        "ok": ok,
        "sha": sha,
        "rebuilt_sha": rebuilt_sha,
        "size": len(dex),
        "chunks": chunks,
        "meta": meta,
    }, indent=2))
    if not ok:
        raise SystemExit("sideload round-trip FAILED")


def app_installed(adb_bin):
    out = adb(adb_bin, ["shell", "pm path dev.farewell.pif"], check=False)
    return "package:" in out


def run_app_op(adb_bin, op, extras=None):
    """MIUI: shell has no WRITE_SECURE_SETTINGS, so settings writes go through the priv-app."""
    cmd = ["shell", "am", "start", "-n", "dev.farewell.pif/.app.MainActivity",
           "--es", "op", op]
    if extras:
        cmd += extras
    return adb(adb_bin, cmd, check=False)


def chunk_extras(prefix, value, size=6000):
    extras = []
    for index in range(0, len(value), size):
        extras += ["--es", "%s%d" % (prefix, index // size), value[index:index + size]]
    return extras


def push_config(adb_bin, config):
    payload = json.dumps(config, separators=(",", ":"))
    if app_installed(adb_bin):
        run_app_op(adb_bin, "set_config", chunk_extras("cfg_", payload))
        return
    settings_put(adb_bin, NEUTRAL_KEY, encode_envelope(config))
    for legacy in LEGACY_KEYS:
        settings_delete(adb_bin, legacy)


def hook_install(adb_bin, dex_path):
    if app_installed(adb_bin):
        run_app_op(adb_bin, "install_hook")
        print("hook install requested via app")
        return
    install_hook(adb_bin, dex_path)


def hook_remove(adb_bin):
    if app_installed(adb_bin):
        run_app_op(adb_bin, "remove_hook")
        print("hook removal requested via app")
        return
    settings_delete(adb_bin, HOOK_META)
    for index in range(HOOK_MAX_CHUNKS):
        settings_delete(adb_bin, HOOK_CHUNK + str(index))
    print("hook removed")


def install_hook(adb_bin, dex_path):
    path = Path(dex_path)
    if not path.exists():
        raise SystemExit("hook dex not found: %s (run build.py first)" % path)
    dex = path.read_bytes()
    sha = hashlib.sha256(dex).hexdigest()
    chunks = (len(dex) + HOOK_CHUNK_SIZE - 1) // HOOK_CHUNK_SIZE
    if chunks > HOOK_MAX_CHUNKS:
        raise SystemExit("hook dex too large (%d chunks)" % chunks)
    for index in range(chunks):
        part = dex[index * HOOK_CHUNK_SIZE:(index + 1) * HOOK_CHUNK_SIZE]
        xored = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(part))
        settings_put(adb_bin, HOOK_CHUNK + str(index),
                     base64.b64encode(xored).decode("ascii"))
    for index in range(chunks, HOOK_MAX_CHUNKS):
        settings_delete(adb_bin, HOOK_CHUNK + str(index))
    settings_put(adb_bin, HOOK_META, "%s:%d:cli" % (sha, chunks))
    print("hook installed: %s (%d bytes, %d chunks)" % (sha[:12], len(dex), chunks))


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF provisioning")
    parser.add_argument("--adb", default=None, help="path to adb")
    parser.add_argument("--status", action="store_true", help="show current configuration")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--clear", action="store_true")
    parser.add_argument("--fix", action="store_true",
                        help="enable, defaults and bundled profile (keybox stays manual)")
    parser.add_argument("--flags", default=None,
                        help="comma list of props,keybox,secure,signature,provider")
    parser.add_argument("--mode", choices=["auto", "leaf", "generate"], default=None)
    parser.add_argument("--profile", default=None, help="path to a PIF profile JSON file")
    parser.add_argument("--targets", default=None,
                        help="comma separated package[:process] list (replaces targets)")
    parser.add_argument("--keybox", default=None, help="path to a keybox XML file")
    parser.add_argument("--keybox-index", type=int, default=None)
    parser.add_argument("--install-hook", nargs="?", const=str(HOOK_DEX), default=None,
                        help="install the built hook dex into Settings.Global (no repack)")
    parser.add_argument("--remove-hook", action="store_true",
                        help="remove the hot-loaded hook (via the app on MIUI)")
    parser.add_argument("--verify-sideload", nargs="?", const=str(HOOK_DEX), default=None,
                        help="local round-trip test of the hook dex chunking (no device)")
    parser.add_argument("--debug", choices=["on", "off"], default=None)
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    if args.verify_sideload is not None:
        verify_sideload(args.verify_sideload)
        return

    adb_bin = adb_path(args)
    version = adb(adb_bin, ["version"], check=False)
    if not version:
        raise SystemExit("adb not found; pass --adb or install platform-tools")
    devices = adb(adb_bin, ["devices"], check=False)
    if "\tdevice" not in devices:
        raise SystemExit("no device connected:\n" + devices)

    if args.status:
        config = load_config(adb_bin)
        display = json.loads(json.dumps(config))
        if display.get("kb"):
            display["kb"] = ["<%d base64 chars>" % len(item) for item in display["kb"]]
        print(json.dumps(display, indent=2))
        meta = settings_get(adb_bin, HOOK_META)
        print("hook:", meta if meta and meta != "null" else "not installed")
        return

    if args.clear:
        if app_installed(adb_bin):
            push_config(adb_bin, json.loads(json.dumps(DEFAULT_CONFIG)))
            hook_remove(adb_bin)
        else:
            settings_delete(adb_bin, NEUTRAL_KEY)
            for legacy in LEGACY_KEYS:
                settings_delete(adb_bin, legacy)
            hook_remove(adb_bin)
        print("cleared configuration and hook")
        if not args.no_restart:
            force_stop(adb_bin)
        return

    config = load_config(adb_bin)
    changed = False

    if args.install_hook is not None:
        hook_install(adb_bin, args.install_hook)
        if not args.no_restart:
            force_stop(adb_bin)

    if args.remove_hook:
        hook_remove(adb_bin)
        if not args.no_restart:
            force_stop(adb_bin)
        return

    if args.fix:
        if not config.get("pf"):
            if not DEFAULT_PROFILE.exists():
                raise SystemExit("bundled profile not found: %s" % DEFAULT_PROFILE)
            config["pf"] = json.loads(DEFAULT_PROFILE.read_text(encoding="utf-8"))
            print("bundled profile applied")
        config["en"] = 1
        if not config.get("fl"):
            config["fl"] = 3
        changed = True

    if args.enable:
        config["en"] = 1
        changed = True
    if args.disable:
        config["en"] = 0
        changed = True
    if args.flags is not None:
        config["fl"] = flags_to_mask(args.flags)
        changed = True
    if args.mode is not None:
        config["md"] = args.mode
        changed = True
    if args.debug is not None:
        config["dbg"] = 1 if args.debug == "on" else 0
        changed = True
    if args.targets is not None:
        config["tg"] = [item for item in args.targets.split(",") if item]
        changed = True
    if args.keybox_index is not None:
        config["kbi"] = args.keybox_index
        changed = True

    if args.profile:
        data = Path(args.profile).read_text(encoding="utf-8")
        config["pf"] = json.loads(data)
        print("profile applied from %s" % args.profile)
        changed = True

    if args.keybox:
        if args.keybox.startswith("http://") or args.keybox.startswith("https://"):
            raise SystemExit("network fetching is disabled; download the keybox yourself")
        data = Path(args.keybox).read_bytes()
        if app_installed(adb_bin):
            encoded = base64.b64encode(data).decode("ascii")
            run_app_op(adb_bin, "set_keybox", chunk_extras("kb_", encoded))
            print("keybox sent to the app (%d bytes)" % len(data))
        else:
            _install_keybox(config, data, args.keybox)
        config["en"] = 1
        if not config.get("fl"):
            config["fl"] = 3
        changed = True

    if changed:
        push_config(adb_bin, config)
        if config.get("en") == 1 and (args.enable or args.fix or args.keybox):
            hook_install(adb_bin, str(HOOK_DEX))
        elif config.get("en") == 0:
            hook_remove(adb_bin)
        if not args.no_restart:
            force_stop(adb_bin)
        print("done")
    elif args.install_hook is None and not args.remove_hook:
        parser.print_help()


def _install_keybox(config, data, source):
    text = data.decode("utf-8", errors="replace")
    if "<Keybox" not in text or "<Key " not in text:
        raise SystemExit("not a keybox XML (missing <Keybox>/<Key>): %s" % source)
    encoded = base64.b64encode(data).decode("ascii")
    keyboxes = config.get("kb") or []
    keyboxes = [encoded] + [item for item in keyboxes if item != encoded]
    config["kb"] = keyboxes[:5]
    print("keybox installed from %s (%d bytes)" % (source, len(data)))


if __name__ == "__main__":
    main()
