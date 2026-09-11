# Farewell-PIF

**Rootless Play Integrity framework** for Android — patched `framework.jar`/`services.jar`, a
hot-installable hook dex, and a controller app. No root, no Magisk/KernelSU module, no Zygisk,
no daemons, no system property writes, no files.

Farewell-PIF is a rebrand of **Kaori**; the 2.0.0 rework folds in what we learned from
**AlwaysStrong** (full TEESimulator-style attestation record, native prop hiding) and from
**PIF Detector** (key-attestation forgery checks and keybox root anchoring, now a built-in
*Security audit*). See `docs/DETECTION.md`.

**Supported device: POCO X3 NFC (surya), MIUI 14, Android 12 (SDK 31)** — build
`V14.0.1.0.SJGMIXM`, keymaster 4.0. Surya compatibility is the priority: the anchors,
register handling and attestation versions in this repo are calibrated and verified against
that stock ROM (`out/calibration.json`, `out/patch-report.json`).

Other devices are **not supported out of the box**; `docs/PORTING.md` contains notes so the
community can fix/convert them, and `patcher/calibrate.py` reports which anchors need
adjustment. Nothing in the patcher is optimized at the cost of surya.

[![CI](https://github.com/fannndi/Farewell-PIF/actions/workflows/ci.yml/badge.svg)](https://github.com/fannndi/Farewell-PIF/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-GPL--3.0-blue)

---

## Why

Root-based integrity fixes are easy to detect (modules, props, daemons). Farewell-PIF moves the
work into the system framework itself:

- **Keybox attestation** forged at the Java keystore layer (patch + generate modes, VINTF-aware).
- **Play Integrity style property spoofing** applied only inside target processes.
- **Everything is data** — keybox and PIF profile are loaded manually; nothing is fetched.
- **Hook updates without repacking the ROM** (bootstrap + runtime dex).

## Features

- Play Integrity fix: keybox attestation (chain forging, `RootOfTrust`, patch levels, ID tags
   710–717), per-app profiles, target rules `pkg[:process]`, blacklist.
- **Modes**: *PIF profile only* (fingerprint identity, no keybox — keeps app availability like
   KAI Access working), *PIF + Store* (Play Store sees the spoofed device), keybox attestation
   on top when a current keybox is installed.
- **Security audit** (PIF-Detector derived, offline): verifies the forged chain we actually
   serve — links, CA issuers, challenge echo, leaf signature algorithm — and refuses a keybox
   whose root is not one of Google's current/anchored hardware roots.
- **Profile updater** (user initiated, OemPorts10T idea): fetch the latest reference profile
   from the Advanced tab or `python tools/update_profile.py --push`; accepts Pif-props.json and
   PIFork/OemPorts `pif.json` (incl. `FIRST_API_LEVEL`).
- Stealth: one neutral `Settings.Global` key with an XOR-obfuscated envelope; targets default to
   the DroidGuard process + Play Store only; silent by default.
- Rootless `resetprop` subset: `SystemProperties.get/getInt/getLong/getBoolean` spoofed for
   Java readers inside target processes; native `__system_property_get` /
   `__system_property_read_callback` hooked by `libfarewell.so`.
- TEE-broken support: TEE probe + software key generation + best-effort keystore import.
- Secure flag (screenshot) handling, feature overrides, Google Photos preset.
- Controller app (WebView): status, toggles, profile/keybox manager, per-app targeting,
  ADB/developer-options toggles, logcat + debug bundle, framework self-test.
- Offline tooling: ROM audit, anchor calibration, attestation lab, sideload round-trip test.

## Quick start

1. **Port/calibrate** (skip for surya builds):
   ```bash
   python tools/audit_rom.py --rom /path/to/unpacked/rom --out out/rom-audit.json
   python patcher/calibrate.py --stock /path/to/rom/system/system/framework
   ```
2. **Build**: `python build.py` (and `python build_app.py`, `python tools/package.py`).
3. **Repack**: put `out/framework.jar`, `out/services.jar`, the app and the permissions XML into
   the ROM — follow `REPACK_CHECKLIST.md` (AVB/verity is the critical step).
4. **After boot**: open the app → **FIX INTEGRITY NOW** (enables, applies the bundled profile,
   installs the hook dex, restarts GMS) → **Import keybox file**.
5. **Update hook later** without repacking: app → *Install / update hook*, or
   `python tools/provision.py --install-hook`.

No action requires a network connection.

## How it works

```
Settings.Global  sys_thermal_profile  (envelope config, XOR)
                 sys_perf_dex_*       (hook dex chunks, SHA-256 verified)
       │
       ▼
framework.jar    FarewellHook (bootstrap ≈8 KB) → InMemoryDexClassLoader → HookImpl
       ▲
patched smali    Instrumentation · ApplicationPackageManager · KeyStore2 ·
                 AndroidKeyStoreSpi ×3 · KeyPairGeneratorSpi · SystemProperties ×5
services.jar     SystemServer · DevicePolicyCacheImpl · WindowState · WindowStateAnimator
```

Full details in `docs/ARCHITECTURE.md`.

## Repository layout

```
hook/bootstrap     tiny shim compiled into framework.jar (hot-dex loader)
hook/impl          the real hook logic (Config, Keybox, Attestation, Props, ...)
patcher/           smali patcher + anchor calibration
app/               WebView controller (no network, no AndroidX)
tools/             provision, audit_rom, attestation_lab, adb_debug, package
docs/              architecture, porting, debugging
tests/             stdlib unit tests
```

## Tooling

| Command | What it does |
|---|---|
| `python build.py --hook-only` | compile bootstrap + hook dex (CI friendly) |
| `python build.py` | build everything and patch the stock jars |
| `python patcher/calibrate.py --stock <framework>` | anchor compatibility report for a ROM |
| `python tools/audit_rom.py --rom <rom>` | deep ROM audit (bootclasspath, VINTF, AVB, anchors) |
| `python tools/attestation_lab.py --keybox k.xml --all` | offline attestation simulator/verifier |
| `python tools/attestation_lab.py --profile p.json` | validate a PIF profile |
| `python tools/provision.py --install-hook` | sideload the hook dex over ADB |
| `python tools/provision.py --verify-sideload` | local chunking round-trip test |
| `python tools/adb_debug.py --collect` | collect a debug zip from a device |

## Credits

This project is original code, built after studying the excellent work of these projects:

- **[Kaorios Toolbox](https://github.com/Wuang26/Kaorios-Toolbox)** (Wuang26) — architecture
  reference for the rootless framework-patch approach, settings channel and PIF data handling.
- **[AlwaysStrong](https://github.com/KOWX712/AlwaysStrong)** — keybox handling/rotation ideas,
  attestation tag work and Pixel Canary fingerprint fetching concepts.
- **[PlayIntegrityFix](https://github.com/chiteroman/PlayIntegrityFix)** (chiteroman,
  [KOWX712](https://github.com/KOWX712/PlayIntegrityFix), [osm0sis](https://github.com/osm0sis/PlayIntegrityFix)) —
  property spoof semantics, provider/signature spoof and `pif.prop` conventions.
- **[TEESimulator](https://github.com/JingMatrix/TEESimulator)** (JingMatrix) and
  **[TrickyStore](https://github.com/5ec1cff/TrickyStore)** (5ec1cff) — key attestation
  semantics: patch/generate modes, VINTF version reconciliation, root-of-trust encoding.
- **[Specter](https://github.com/dpejoh/specter)** (dpejoh) — inspiration for the controller
  feature set (keybox health, security patch handling, diagnostics).
- **BouncyCastle** — ASN.1/X.509 toolkit used by the hook.
- **AOSP / Android Open Source Project** — reference for the classes we hook and the
  KeyMist/keymaster attestation encoding.

Also thanks to the communities around these projects for documenting device quirks.

## Disclaimer

For personal ROM/device experimentation only. Keyboxes are user-supplied; do not redistribute
them. This project is not affiliated with Google. Use at your own risk — no warranty.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
