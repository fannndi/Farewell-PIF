# Module map

Where to look when something breaks. Each row names the module, its files and the contract it
owns. Run `python tools/doctor.py` first: every failed check prints the module to inspect.

## Repo layout

```
app/                    Android controller app (priv-app, WebView UI)
  assets/               index.html + app.js + app.css (UI), default-profile.json
  src/dev/farewell/pif/app/
    MainActivity.java   WebView host, JS bridge, op handler, install/remove hook
    HookStore.java      Settings.Global channel: config envelope + dex chunks + gate value
    BootReceiver.java   restores the channel after boot / app update
    Security.java       offline PIF-Detector style audit (chain structure + keybox anchor)
    Updater.java        user-initiated profile fetch (Pif-props.json / pif.json / KEY=VALUE)
  permissions/          privapp allowlist XML
hook/
  bootstrap/FarewellHook.java   boot-classpath shim: gate, dex loader, hidden-API bridge
  impl/dev/farewell/pif/
    HookImpl.java       facade: the exact public methods the patcher calls
    Runtime.java        per-process state: counters, events, TEE probe, lazy init, gates
    Bridge.java         reflective bridge to the boot-classpath shim (hidden API)
    Config.java         config envelope parsing + Snapshot + modes/flags
    Props.java          Build/property/feature spoofing for props targets
    Attestation.java    KeyDescription + leaf forging (AOSP/TEESimulator layout)
    Keybox.java         keybox.xml parsing, selection, chain access
    NativeProps.java    loads libfarewell.so and installs the native spoof table
native/                 "internal zygisk": hook engine + spoof table + JNI
  hook.c                arm64 inline hook (16-byte branch + trampoline)
  props.c               spoof table + __system_property_get/read_callback handlers
  jni.c                 JNI entry points
  farewell.h            shared declarations
patcher/farewell_patch.py   smali patcher (14 framework + 4 services anchors)
patcher/calibrate.py        portability report against a stock ROM
tools/provision.py      config/keybox/hook provisioning over ADB (app ops on MIUI)
tools/verify.py         end-to-end verification matrix (PASS/FAIL)
tools/doctor.py         verify + fix pointers per module + local checks
tools/attestation_lab.py   offline forge/verify lab (no device)
tools/package.py        dist zip (jars, APK, hook.dex, libfarewell.so)
```

## Symptom -> module

| Symptom | Look at |
|---|---|
| Hook never loads in GMS (`gate denied pkg=...`) | `HookStore.gateValue` (app) wrote `sys_perf_dex_pkgs`; `FarewellHook.gateAllows` (bootstrap) checks it. Repack only for bootstrap changes. |
| `dex hash mismatch` in logcat | Chunk channel: `HookStore.installHook` (app) writes chunks+meta; rebuild with `build.py`, sideload with `provision.py --fix`. |
| `{"bootstrap":true,"impl":false}` | Loader: `FarewellHook.loadImpl` / `readSetting` context path (bootstrap); `dexprobe` op shows the channel. |
| `keygen:0`, `forge-null` | Attestation/KeyParams (`Attestation.buildKeyDescription`), field reads via `Bridge.getField`. Check `Config.log` with `dbg=1`. |
| `import ok` missing | `HookImpl.tryKeystoreImport` + `Bridge.callDeclared`/`newKeyDescriptor`. |
| `chain served (4)` but verdict BASIC/[] | Server-side or identity: keybox root generation (`tools/keybox_check.py`, app *Security audit*), fingerprint mode, verbose props (`dbg=2`), rate limit (do not spam checks). |
| Keybox valid locally, server rejects | Root rotated out: `tools/keybox_check.py --online`; app keybox card shows *Root anchor*. |
| Profile outdated / new print needed | *Update profile (online)* in Advanced, or `python tools/update_profile.py --push`. |
| Props not spoofed in DroidGuard | `Runtime.ensureProcessInit` -> `Config.propsFor`; check `props applied ... gms.unstable` in logcat. |
| Native props inactive | `NativeProps.enableFrom` loads `/system/lib64/libfarewell.so`; test with `nativeprobe` op; rebuild with `native/build.ps1`. |
| Play Store app search unchanged | Store mode (`FLAG_VENDING` bit 64) + clear Play Store data once; `Props` applies the profile to `com.android.vending`. |
| Boot wipe lost config | `HookStore` channel file (`files/channel.json`) is authoritative; `BootReceiver` re-seeds settings. |
| Patch anchors fail on another ROM | `patcher/farewell_patch.py` anchor tables; `patcher/calibrate.py --stock` reports portability. |

## Debug levels

`dbg` in the config envelope:

| Value | Effect |
|---|---|
| 0 | silent |
| 1 | errors + key events (`Config.log`) |
| 2 | + every property DroidGuard reads (`prop <name> -> <value>`) |
