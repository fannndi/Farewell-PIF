# Porting to another device / ROM

Farewell-PIF is calibrated for **surya / MIUI 14 / Android 12 (SDK 31)**, but the design is
portable. Anchor calibration tells you in minutes whether your ROM needs changes.

## 1. Prepare local tools

`build.py` expects (fetch them yourself; they are gitignored):

| Tool | Path | Source |
|---|---|---|
| smali/baksmali 3.x + deps | `tools/smali3/*.jar` | Google Maven `com.android.tools.smali` |
| R8 (D8) | `tools/r8-*.jar` | Google Maven `com.android.tools:r8` |
| android-all (A12+) | `tools/libs/android-all-12.jar` | Maven Central `org.robolectric:android-all` |
| public android.jar | `tools/libs/android-31.jar` | Android SDK platform |
| BouncyCastle slim | `tools/libs/bcprov-slim.jar` | Maven Central `org.bouncycastle:bcprov-jdk18on` (asn1+util only) |
| JDK | PATH | JDK 17+ |
| platform-tools | `tools/platform-tools/adb.exe` | Google |

`python build.py --hook-only` only needs JDK + the classpath jars.

## 2. Audit your ROM

```bash
python tools/audit_rom.py --rom /path/to/unpacked/rom --out out/rom-audit.json
```

Reports: bootclasspath order, which jar actually **defines** each target class, VINTF keystore
HAL, otacerts, AVB/verity, and whether all patch anchors are present.

## 3. Calibrate the patcher

```bash
python patcher/calibrate.py --stock /path/to/rom/system/system/framework
```

- `ok` → patch applies as-is.
- `optional-skip` → class/method differs (usually the secure-flag trio on newer Android);
  the build continues without that feature.
- `anchor-error` → the smali shape changed; open the shown method and adjust the anchor in
  `patcher/farewell_patch.py` (each patch is a small function with exact anchors).

## 4. Build and verify

```bash
python build.py                 # bootstrap dex + hook dex + patched jars in out/
python tools/attestation_lab.py --keybox your-keybox.xml --all
python tools/attestation_lab.py --profile your-profile.json
python tools/provision.py --verify-sideload
```

## 5. Repack and install

Follow `REPACK_CHECKLIST.md`. Key points that vary per device:

- **AVB**: modified `system`/`system_ext` need verity disabled or vbmeta re-signed.
- **Privapp**: keep `dev.farewell.pif` in `priv-app` with the shipped permissions XML
  (or set `ro.control_privapp_permissions=` if your ROM enforces an allowlist).
- **Dalvik**: wipe `/data/dalvik-cache` so ART recompiles the boot image.
- **Hook sideload**: after first boot, install the hook from the app
  (**Install / update hook**) or `python tools/provision.py --install-hook` — no repack needed
  for future hook updates.

## 6. Known variations

| Android | Target differences |
|---|---|
| 12 / 12L | reference platform (`AndroidKeyStoreSpi` in `android.security.keystore2`, `SystemProperties` 5 getters, secure-flag trio present) |
| 13+ | generally the same anchors; secure-flag classes may move (optional patches skip); build/verify report tells you what is missing |
| 14/15 | `KeyStore2`/keystore paths unchanged; if `generateKeyPair` moves, the optional patcher skips it and AUTO keeps using the TEE leaf (your keybox chain still applies) |

If a required patch reports `anchor-error`, open an issue with `out/calibration.json` plus the
method's smali; anchors are intentionally small and easy to extend.
