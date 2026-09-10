# Contributing to Farewell-PIF

Thanks for helping! This project is a **rootless Play Integrity framework** (patched
`framework.jar`/`services.jar` + a hot-loadable hook dex), originally calibrated on a
POCO X3 NFC (surya) running MIUI 14 / Android 12.

## Ground rules

1. **No proprietary or leaked data.** Never commit keyboxes, certificates with private keys,
   decompiled third-party code, stock ROM jars, or APKs. `.gitignore` enforces this; keep it.
2. **No root/module code.** The whole point is rootless: no `resetprop`, no Zygisk, no daemons.
3. **Fail-safe hooks.** Every hook must fall back to stock behaviour on any error.
4. **Keep it simple.** Features must earn their maintenance cost.

## Development setup

```bash
python -m pip install cryptography
python build.py --hook-only        # compile bootstrap + hook dex (needs tools/, see docs/PORTING.md)
python patcher/calibrate.py --stock /path/to/framework
python tools/attestation_lab.py --profile reference/profile/Pif-props.json
python tools/provision.py --verify-sideload
python -m unittest discover -s tests -v
```

Full build (requires the stock jars, locally):

```bash
python build.py                   # bootstrap + impl + patcher (framework.jar, services.jar)
python build_app.py               # controller APK
python tools/package.py           # distributable zip
```

## Pull requests

- One topic per PR; describe the device/ROM/Android version you tested on.
- For patcher changes: include `out/calibration.json` before/after.
- For hook changes: include the relevant `attestation_lab` output and, if possible, an
  on-device debug bundle (`tools/adb_debug.py --collect`).
- Run the unit tests and `py_compile` first; CI runs them too.

## Porting to another device

See `docs/PORTING.md`. Anchor calibration (`patcher/calibrate.py`) tells you exactly which
patches apply as-is and which need adjustment — most ROMs differ only in the secure-flag
classes, which are marked optional and skipped automatically.

## Credits

See the credits section in `README.md`. If you adapt a behaviour from another project,
add a note there and keep the licence compatible (this project is GPL-3.0).
