# Architecture

## Channels

```
┌──────────────────────── Settings.Global (no files, no root) ────────────────────────┐
│ sys_thermal_profile  = "F1:" + base64(XOR(json))     config envelope                 │
│ sys_perf_dex_meta    = "<sha256>:<chunks>:<version>" hook dex descriptor             │
│ sys_perf_dex_pkgs    = ",android,com.google.android.gms,com.android.vending," gate   │
│ sys_perf_dex_0..N    = base64(XOR(chunk))            hook dex chunks                 │
└─────────────────────────────────────────────────────────────────────────────────────┘
        ▲ writes (app / provision.py)                 │ reads (every process, 3 s TTL)
        │                                             ▼
┌───────────────────────── framework.jar (one tiny dex) ──────────────────────────────┐
│ dev.farewell.pif.FarewellHook  ← bootstrap shim (≈8 KB)                             │
│   • reads sys_perf_dex_*; verifies SHA-256                                           │
│   • InMemoryDexClassLoader → dev.farewell.pif.HookImpl (the real logic)              │
│   • delegates 16 entry points through cached reflection                              │
└─────────────────────────────────────────────────────────────────────────────────────┘
        ▲ static method calls inserted by the patcher
┌───────────────────────── patched smali call sites ───────────────────────────────────┐
│ framework.jar                                                         services.jar    │
│  Instrumentation.newApplication ×2      KeyStore2.getKeyEntry         SystemServer   │
│  ApplicationPackageManager.hasSystemFeature                            DevicePolicy…  │
│  keystore2.AndroidKeyStoreSpi ×3 (chain/getKey/getCertificate)         WindowState…   │
│  keystore2.AndroidKeyStoreKeyPairGeneratorSpi                           WindowStateA…  │
│  SystemProperties.get/getInt/getLong/getBoolean                                       │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

The bootstrap also reads the per-process allowlist `sys_perf_dex_pkgs` before loading the
hook dex. Processes whose package is not listed (plus `android`, required for the
system_server secure-flag hooks) **never load the dex** — critical on low-RAM devices where a
private 570 KB dex per process would create memory pressure and ANRs. The app writes the gate
when it installs the hook and removes it together with the hook.

## Components

| Path | Role |
|---|---|
| `hook/bootstrap` | tiny shim compiled into `framework.jar`; loads the hot dex |
| `hook/impl` | the real hook: `HookImpl`, `Config`, `Keybox`, `Attestation`, `Props`, provider/signature spoof |
| `patcher/farewell_patch.py` | anchor-based smali patcher (skip untouched dexes, preserve dex version) |
| `patcher/calibrate.py` | anchor compatibility report for arbitrary stock ROMs |
| `app/` | WebView controller (Java bridge; no AndroidX, no network) |
| `tools/provision.py` | ADB provisioning + hook sideload + offline sideload test |
| `tools/attestation_lab.py` | offline attestation simulator/verifier + profile validator |
| `tools/audit_rom.py` | deep stock ROM audit (bootclasspath, definitions, VINTF, AVB, anchors) |
| `tools/adb_debug.py` | one-zip device debug collector |

## Hook points and behaviour

| Call site | Hook | Purpose |
|---|---|---|
| `Instrumentation.newApplication` | `initContext` | per-process init; Build/props spoof for target processes |
| `ApplicationPackageManager.hasSystemFeature` | `hasSystemFeature` | per-app feature overrides |
| `KeyStore2.getKeyEntry` | `getKeyEntry` | replace attestation chain with the keybox chain |
| `AndroidKeyStoreSpi.engineGetCertificateChain/GetKey/GetCertificate` | alias caches | generate mode: serve the software key/chain |
| `AndroidKeyStoreKeyPairGeneratorSpi.generateKeyPair` | `softwareKeyPair` | probe TEE; generate software key + import into keystore |
| `SystemProperties.get*` | `property*` | Java-side `ro.*` spoof (rootless resetprop subset) |
| `SystemServer` | `initSystemServer` | prime system_server config |
| `DevicePolicyCacheImpl`, `WindowState`, `WindowStateAnimator` | `isSecureFlag` | secure-flag/screenshot handling |

## Attestation

- **Patch mode**: the genuine TEE leaf is preserved (public key, serial, subject, validity);
  RootOfTrust, OS/vendor/boot patch levels and ID tags `710–717` are rewritten inside the two
  authorization lists (never the untagged meta fields) and the leaf is re-signed with the
  keybox private key, prepended to the keybox chain.
- **Generate mode** (TEE broken): a software key pair is minted; the full `KeyDescription`
  is built per AOSP (`attestationVersion/keymasterVersion` reconciled with the VINTF-declared
  keystore HAL: AIDL KeyMint `N*100` ceiling, HIDL Keymaster exact `@4.0→3`), then imported
  into keystore2 when possible.
- A KeyDescription that fails any step leaves the original keystore behaviour untouched.

## Stealth choices

- No root, module, Zygisk, daemon, `resetprop`, or files anywhere.
- **No native libraries by design.** Kaorios ships `libkousei.so`, but our hook is pure
  Java + BouncyCastle, so nothing has to be loaded into target processes. A `.so` would only
  help for a root/Zygisk module (native property hooks) — explicitly out of scope.
- One neutral settings key + `F1:` XOR envelope instead of many suspicious keys.
- Targets default to the DroidGuard process + Play Store only (per-process matching).
- Keybox parsing rejects DTD/entities and caps input sizes.
- Hooks are silent by default; debug logging is opt-in.

## TEE probe (surya reality)

`mode=auto` probes the TEE with an attested EC key. The probe temporarily bypasses the hook
(`sProbeActive`) so it measures the genuine keystore path, and it is guarded against
re-entering `generateKeyPair`. On surya the probe fails — Qualcomm refuses attest-key
generation (`resp->status: -10003`) while plain key generation succeeds — so the hook selects
**generate** mode (software key + keybox chain). See `docs/DEBUGGING.md` for the on-device
proof and repro commands.
