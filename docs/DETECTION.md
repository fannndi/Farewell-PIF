# Detection surface (study: PIF Detector, GPL-3.0)

Reference: `playIntegrityFixDetector` (Ir0nByte, GPL-3.0) — a detector for PIF, TrickyStore,
TEESimulator, keybox spoofers and root hiders, with a native C++ engine plus two Kotlin
key-attestation probes. This document maps every load-bearing check to the Farewell-PIF design and
records what we must keep true. It is the adversarial counterpart of `MODULES.md`.

## Why an unprivileged detector mostly cannot see us

The detector itself admits this in its README (`SELinux and the privilege boundary`):

- PIF forks gate on the target process and unload elsewhere; a maps scan in the detector's own
  process finds nothing. Zygisk/Magisk/root-hider checks have nothing to match on a rootless ROM
  with no root manager installed.
- Keybox spoofers hook `keystore2`, not the calling app, so the effect only shows in the chains
  they hand back.
- `ro.boot.*`, `/system/build.prop` (0600), `/proc/cmdline` and `/sys/fs/selinux/enforce` are
  unavailable to `untrusted_app`, so boot-state and mount checks fail open.

Farewell-PIF matches this profile by construction: no Zygisk, no module directories, no root, and
every hook is gated per target process. The flags `PIF`, `TRICKYSTORE`, `PIF_STREAM`, `TSEE`,
`PIF_RUST` are unobservable unprivileged on our setup.

## The checks that DO matter, and our posture

| Detector check | What it looks for | Farewell-PIF |
|---|---|---|
| Passive key-attestation probe | Generate an ordinary attested key for the detector and analyse the chain | Only forged for `attestationFor()` targets (GMS stack + configured `tg`). A non-target app gets the genuine Keystore path (which on this device fails attestation → probe returns 0). |
| `chainSignaturesBroken` | Every link must verify | Our forged leaf is signed by the keybox batch key and `kb.chain` follows, so `resignLeaf` output verifies link-by-link (`verify` op: `certDirect=yes keyDirect=yes`). |
| `chainHasNonCaIssuer` | Every issuer cert must have `basicConstraints CA:TRUE` | Real keybox chains: batch, intermediate and root are all CAs. Verified for the user keybox with `tools/keybox_check.py` (`CA=True` on every issuer). |
| `challengeMismatch` (anti-replay) | Attestation must echo the nonce the caller passed | `softwareKeyPair` reads `spec.getAttestationChallenge()` and `buildKeyDescription` writes it into field `[4]`. `certificateChainIfNeeded` replays the challenge captured at generation time. |
| `anchorsToGoogle` (1c) | Chain must terminate at a **current** pinned Google hardware root, unless `attestationSecurityLevel=Software` | **The one place we fail today.** We emit level TEE but the user keybox chains to the retired 2019 RSA root (see below). Fix the keybox, not the code. |
| `authRequirementContradiction` (tag 503) | NO_AUTH_REQUIRED present while 504/505 are absent, for a key that requires auth | `buildKeyDescription` emits tag 503 only `if (params.noAuthRequired)` — matches the TricsyStoreOSS 2026-07-31 fix. |
| `leafSignatureTracksRequestedDigest` | Leaf signed with the digest the caller requested (e.g. SHA-512) | Our leaf is signed with `kb.jcaSigAlg`, fixed by the keybox key (SHA-256 based). It never tracks `KeyGenParameterSpec` digests. |
| `isSelfSignedSingleCert` | Single self-signed cert carrying an attestation extension | Our chain is always `[forged leaf, kb.chain…]`, length ≥ 2. |
| `PURPOSE_ATTEST_KEY` provocation (active) | Request an attest key; a spoofer that lacks a uid gate forges and is caught by anchoring | Our gate is `keyboxApplicable()` → `cfg.attestationFor(currentPackage, process)` on **every** forge entry point, before any `PURPOSE_ATTEST_KEY` arm exists. |
| Bootloader props | `ro.boot.verifiedbootstate/flash.locked/veritymode/vbmeta.device_state` | Not spoofed outside gated processes (by design). A non-target app sees real values; on surya MIUI reports `verifiedbootstate=green`/`flash.locked=1`, and `vbmeta.device_state=unlocked` stays visible. Add the app to `tg`/`ap` if a local property check needs the fake values. |
| Property cross-validation | Scalars vs fingerprint consistency, read timing | Only fires on userdebug/eng ROMs; the target ROM is `user/release-keys`. Inside gated processes the spoofed set is coherent (`Config.expandFingerprint` derives BRAND/PRODUCT/DEVICE/ID/INCREMENTAL/TYPE/TAGS from FINGERPRINT). |
| Signature / debugger / Frida | Own APK digest, `TracerPid`, TCP 27042/3, thread names | Not applicable (no Frida, release-signed ROM, no debugger). |

## The keybox root finding (2026-09-11)

`tools/keybox_check.py` on the user's keybox:

```
== key algorithm: ecdsa / rsa
   [0] batch cert      CA=True  valid 2020-09-28..2030-09-26   (private key matches)
   [1] intermediate    CA=True  valid 2020-09-28..2030-09-26   issuer serial f92009e853b6b045
   [2] root            CA=True  valid 2019-11-22..2034-11-18   self-signed
   link 0->1 signature OK | link 1->2 signature OK
   chain root sha256: 1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc
VERDICT: NOT USABLE for STRONG
```

The chain is locally perfect, but the root is **not** one of Google's current attestation roots.
`https://android.googleapis.com/attestation/root` now returns only:

| Root | Fingerprint | Validity |
|---|---|---|
| Google hardware root RSA-4096 | `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc` | 2022-03-20 .. 2042-03-15 |
| Key Attestation CA1 ECDSA P-384 | `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` | 2025-07-17 .. 2035-07-15 |

Our keybox's root shares the subject `serialNumber=f92009e853b6b045` with the current RSA root but
was issued 2019-11-22 with a different key. The RSA root was rotated in 2022; a 2019-2021 generation
keybox verifies offline and is rejected server-side, which is exactly the symptom observed: forge
pipeline healthy on-device (`keygen`/`import`/`generated` events), server verdicts BASIC/empty.

**Action:** replace the keybox with one that chains to a current root; validate before installing:

```bash
python tools/keybox_check.py keybox.xml --online    # must print VERDICT: OK
```

The detector's revocation check (1d) is the only network check and is orthogonal: "serial not in
Google's revocation list" does not prove the root is current.

## Rules that must never regress

1. Forge entry points stay gated by `keyboxApplicable()` (`attestationFor`), including
   `PURPOSE_ATTEST_KEY` — the TricsyStoreOSS forced-forge bug was a missing uid gate.
2. Tag 503 only when `params.noAuthRequired`; never emit it unconditionally.
3. Leaf signature uses the keybox algorithm, never the caller's requested digest.
4. Echo `attestationChallenge` exactly; `certificateChainIfNeeded` must reuse the generation-time
   challenge.
5. Chains served are always `forged leaf + kb.chain` (length ≥ 2), issuers CA:TRUE.
6. Keybox health must include the **current-root anchor**, not just revocation and signatures
   (`tools/keybox_check.py`; the app/lab health check should embed the two current fingerprints).
7. Keep `attestationSecurityLevel` honest: TEE only for a Google-anchored hardware root. If a
   software keybox must be used, emit `Software` (0) and accept that STRONG cannot pass.

## Why we do NOT copy the init-service + SELinux approach

OemPorts10T ships a solid root implementation: an ELF `pif-updater` (auto-fetches its APK at
boot), an init service with its own SELinux domain (`u:r:pif_updater:s0`), a `sensitiveprops.sh`
run as root at `on fs`, and CIL/file_contexts patches. It is the right shape for a ROM-porting
kit, and the wrong shape for Farewell-PIF:

- Every process would see the fake boot props (their `on fs` resetprop is global). Our design
  spoofs per target process only, which is why PIF Detector's `PIF`/`TRICKYSTORE` checks cannot
  fire against us unprivileged, and why its property cross-validation is inert.
- Their global `ro.build.type`/`ro.*.build.tags` resets are exactly the signals PIF Detector
  looks for (scalars disagreeing with the fingerprint). On surya those properties are already
  `user`/`release-keys`, so there is nothing to gain.
- A running root service, a binary under `/system/bin`, a custom SELinux domain and boot-time
  network traffic are all artifacts a detector or a banking app can enumerate. Farewell-PIF has
  no processes, no daemons and no runtime files.
- The one genuine advantage — properties set before anything reads them — is not needed for Play
  Integrity: the bootstrap loads `HookImpl` in `Instrumentation.newApplication`, i.e. before the
  Application constructor runs and before DroidGuard reads any property. `libfarewell.so` is
  loaded from the same `ensureProcessInit()` path, so native readers in target processes are
  covered too. Apps that check the bootloader locally are handled by adding them to `tg`.

What we did adopt from that kit: the **opt-in profile auto-update** (`Updater.autoUpdate`, run
once from `BootReceiver` when `"au": 1`, only if online and only when the fingerprint changed)
and the extended boot-hiding property set from `sensitiveprops.sh`. No daemon, no init service,
no sepolicy.

## Baseline test on device

Install the detector APK on surya and run it once, unprivileged, with Farewell-PIF active:

- Expect `NOT OBSERVABLE` for PIF/TRICKYSTORE/PIF_STREAM/TSEE/PIF_RUST (no zygisk artifacts).
- Expect `0` from both attestation probes (the detector is not in `tg`, so it meets the genuine
  Keystore path).
- If the detector is temporarily added to `tg` for a red-team pass, the chain-anchor check must
  pass — with a current-generation keybox only.
