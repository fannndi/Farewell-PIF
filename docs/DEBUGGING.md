# Debugging

## In the app (Tools tab)

- **Enable ADB / Disable ADB** — toggles `adb_enabled` and `development_settings_enabled`
  (privileged, no root). Disable again after the session for stealth.
- **Collect logcat** — `FarewellPIF` tag + crashes.
- **Export debug bundle** — writes a zip to
  `/sdcard/Android/data/dev.farewell.pif/files/` with self-test, framework events,
  redacted config, device info and logcat.
- **Framework self-test** — what the hook actually sees: enabled/flags/mode, target match,
  TEE state, attestation/keymaster versions, keybox health.
- **Framework events** — the last 64 hook events (`init`, `tee`, `keygen`, `keyEntry`,
  `chain`, `import`).

## Over USB

```bash
python tools/adb_debug.py --enable-adb --debug-on --clear-logs
# trigger a Play Integrity check on the device, then
python tools/adb_debug.py --collect        # -> out/debug/farewell-debug-<ts>.zip
```

Manual commands:

```bash
adb logcat -s FarewellPIF:V AndroidRuntime:E
adb shell settings get global sys_thermal_profile
adb shell settings get global sys_perf_dex_meta
adb pull /sdcard/Android/data/dev.farewell.pif/files/
```

## Offline lab

```bash
python tools/attestation_lab.py --keybox keybox.xml --all
python tools/attestation_lab.py --keybox keybox.xml --loop 25
python tools/attestation_lab.py --profile Pif-props.json
python tools/provision.py --verify-sideload
```

Use the lab before flashing: it proves the keybox health and the generate-mode encoding
independently of the device.

## Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| Verdict stays BASIC | keybox invalid/revoked or not installed | lab `--verify`, app keybox list |
| No attestation spoofing | hook dex not installed | `settings get global sys_perf_dex_meta`, app *Install hook* |
| Nothing happens after update | GMS not restarted | app *Restart GMS*, or wait for TTL |
| Bootloop after repack | AVB/verity not handled | `REPACK_CHECKLIST.md` step 2 |
| `tee=broken` and generate fails | keystore import unsupported | events log + logcat; fallback cache still serves `engineGetKey` |
| Signature flag does nothing | ROM is release-signed | app *Check ROM signature* (expect `releasekey` on stock) |

## Hook event reference

```
init      <pkg>:<process> target=<bool> mode=<n> flags=<n>
tee       works|broken
keygen    mode=leaf … | auto: TEE works … | generated alias=… alg=EC|RSA
import    keystore import ok alias=…
keyEntry  <alias> forged alg=EC|RSA | no-forward | error …
chain     forged alg=EC|RSA
```
