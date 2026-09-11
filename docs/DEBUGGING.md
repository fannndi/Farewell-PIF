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

## Device sanity check (surya)

Expected values on the supported stock ROM (`V14.0.1.0.SJGMIXM`):

```bash
adb shell getprop ro.build.fingerprint
# POCO/surya_global/surya:12/SKQ1.211019.001/V14.0.1.0.SJGMIXM:user/release-keys
adb shell getprop ro.boot.vbmeta.device_state      # unlocked (authoritative)
adb shell getprop ro.boot.veritymode               # enforcing
adb shell getprop ro.boot.vbmeta.digest            # used for RootOfTrust
adb shell getprop init.svc.keymaster-4-0           # running
adb shell md5sum /system/framework/framework.jar   # compare with stock/patched builds
```

- Stock framework.jar md5 (for reference): `98b43ca56c111d56925142e2ce466873`.
  If it differs, the patched jar is installed.
- Bootloader props: Xiaomi may report `ro.boot.flash.locked=1` / `verifiedbootstate=green`
  even when unlocked — trust **`ro.boot.vbmeta.device_state`**.
- Rootless check: `adb shell id` → `shell`; `/data/adb` must be `Permission denied`.
- Play Store certification **cannot** be read over ADB on MIUI without root (gservices provider
  and `/data/data/com.android.vending` are denied, and `input` injection is blocked unless
  *USB debugging (Security settings)* is enabled). Check it in
  Play Store → profile → Settings → About → *Play Protect certification*, or run a Play
  Integrity checker after installing the patched framework.

### Attestation status on surya (verified on device)

This device's TEE **refuses attestation** while plain key generation still works:

```bash
adb shell keystore_cli_v2 generate --name=probe --seclevel=tee   # GenerateKey: success
adb shell keystore_cli_v2 delete --name=probe
adb logcat -d | grep -E "Attest key send cmd failed|-10003"
# KeyMasterHalDevice: Attest key send cmd failed
# KeyMasterHalDevice: resp->status: -10003   (from DroidGuard key requests)
```

- keystore2 offers only `tee`/`strongbox` (no software level) on this ROM.
- Therefore `mode=auto` correctly falls back to **generate** (software key + keybox chain), and
  the best-effort keystore import targets the TEE level first — which should succeed because
  plain key generation works.

## App processes never loaded the hook (context bug, fixed in 1.8.3)

The 1.8.0-1.8.2 bootstrap read `Settings.Global` through
`ActivityThread.getSystemContext()`. That context reports package `android` while the process UID
is the app's, so SettingsProvider rejects every read:

```
SecurityException: Package android does not belong to 10148
```

Result: `readSetting()` returned null in every app process, the dex never loaded, and GMS/Play
attestation hooks were dead (the chunk writes racing those failed reads also caused the transient
"runtime dex hash mismatch" and ANR storm). System UID processes (system_server, and MIUI Settings
when running as uid 1000) were fine, which masked the bug.

Fix: use the real application context (`initContext` cache, then
`ActivityThread.currentApplication()`, and only then the system context). Requires the 1.8.3
`framework.jar` (the bootstrap lives there); afterwards hook updates are sideload-only again.
Diagnose from the app: `am start ... --es op hookprobe` or `dexprobe`.

## Settings.Global persistence on MIUI (keybox "disappears" after reboot)

MIUI does not persist large (tens of KB) `sys_thermal_profile` writes across reboots: the value
is served from memory for the session and the disk keeps the last small value, so the keybox
vanished on every restart. On top of that, **unknown** keys (`sys_perf_dex_*`) are dropped at
boot entirely.

Mitigation (v1.8.7): the app keeps an authoritative copy of the config, keybox included, in its
private storage (`files/channel.json`) on every write. `readConfig()` falls back to that copy
when the settings value has no keybox, and `BootReceiver` re-seeds Settings.Global on
BOOT_COMPLETED / MY_PACKAGE_REPLACED before installing the hook.

Note: `adb reboot` on this device has twice left it hanging at the boot logo for minutes
(possibly MIUI flush/fsck behaviour). Prefer a manual reboot and verify the boot first.

## Verification matrix (tools/verify.py)

Run after flashing or after any hook/config change:

```bash
python tools/verify.py              # full matrix, includes a GMS restart
python tools/verify.py --skip-gms   # no restart
python tools/verify.py --json out/verify.json
```

Checks: `device`, `app`, `config` (en=1), `meta`, `gate`, `dex` (reconstructed sha256),
`diagnose` (impl loaded + keyboxes healthy), `attest` (live forged chain) and `gms` (logcat shows
`dex loaded ... pkg=com.google.android.gms`).

App ops used by the tool; results land in logcat with tag `FarewellPIF`:

```bash
adb shell am start -n dev.farewell.pif/.app.MainActivity --es op selftest   # diagnose + stats
adb shell am start -n dev.farewell.pif/.app.MainActivity --es op verify     # live attestation test
adb shell am start -n dev.farewell.pif/.app.MainActivity --es op dexprobe   # dex channel + loader
adb shell am start -n dev.farewell.pif/.app.MainActivity --es op hookprobe  # bootstrap internals
```

Bootstrap log lines to watch (`adb logcat -s FarewellPIF`):

```
I FarewellPIF: dex loaded v=1.8.4 pkg=com.google.android.gms
I FarewellPIF: gate denied pkg=com.android.settings       # expected outside the gate
I FarewellPIF: dex hash mismatch pkg=...                  # channel corruption
```

## MIUI provisioning (shell cannot write settings)

MIUI removes `WRITE_SECURE_SETTINGS` from the `shell` user, so `adb shell settings put` fails
with a SecurityException. Provisioning therefore goes through the privileged app:

```bash
python tools/provision.py --fix            # config + hook through the app
python tools/provision.py --keybox keybox.xml
python tools/provision.py --remove-hook
```

Direct app ops (used by the tools):

```bash
adb shell am start -n dev.farewell.pif/.app.MainActivity --es op remove_hook
# ops: install_hook, remove_hook, set_config (cfg_0.. chunks), set_keybox (kb_0..), kill_gms
```

**Important:** only install the hook while the config is enabled. With the hook installed but
`sys_thermal_profile` unset, older builds still loaded the 570 KB dex in every process
(bootstrap had no gate); since v1.8.2 the bootstrap uses `sys_perf_dex_pkgs` so non-target
processes never load it. If the device feels slow after flashing, run `--remove-hook` while
disabled, then enable config + hook together from the app (**FIX INTEGRITY NOW**).

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
