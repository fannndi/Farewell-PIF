# REPACK CHECKLIST — Farewell-PIF (POCO X3 NFC / MIUI 14 / Android 12)

Hasil audit ROM `V14.0.1.0.SJGMIXM` (lihat `out/rom-audit.json`).

## 0. Persiapan
- Backup image stok: `system`, `system_ext`, `product`, `vendor`, `vbmeta_system`, `boot`.
- Catat ROM version. **Matikan update OTA** setelah repack (OTA akan menimpa patch).
- Pastikan bootloader unlocked dan tahu cara flash/rollback.

## 1. File yang dimodifikasi
| Path di device | Sumber | Catatan |
|---|---|---|
| `/system/system/framework/framework.jar` | `out/framework.jar` | unsigned, aman diganti |
| `/system/system/framework/services.jar` | `out/services.jar` | |
| `/system_ext/priv-app/FarewellPIF/FarewellPIF.apk` | `out/FarewellPIF.apk` | dir `0755`, file `0644` |
| `/system_ext/etc/permissions/dev.farewell.pif.xml` | `out/privapp/...xml` | wajib, karena `ro.control_privapp_permissions` tidak diset |
| `/system/system/lib64/libfarewell.so` | `out/install/system/system/lib64/libfarewell.so` | md5 `d6a572578ef4974bf4948f04e1ad84d3`; dir `0755`, file `0644` |
| (opsional) `/system/system/build.prop` | — | tambahkan `ro.control_privapp_permissions=` bila boot menolak privapp |

## 2. AVB / dm-verity (KRITIS)
Audit fstab: `system`, `system_ext`, `product` memakai `avb=vbmeta_system` dengan
`avb_keys=/avb/q-gsi.avbpubkey:/avb/r-gsi.avbpubkey:/avb/s-gsi.avbpubkey`.
Artinya system yang dimodifikasi **tidak akan lolos verifikasi** kecuali:
- `fastboot --disable-verity --disable-verification flash vbmeta_system vbmeta_system.img`, atau
- repack tool menangani AVB signing / dm-verity disable.
Bootloop akibat verity biasanya jatuh ke fastboot/recovery — bisa di-rollback.

## 3. Langkah repack
1. Masukkan kedua jar ke path persis seperti tabel (nama & lokasi tidak boleh berubah).
2. Tambahkan app + XML privapp di `system_ext`.
3. Repack image (`super.img`/`system.img`) — jaga ukuran dan permission.
4. Flash. **Wipe dalvik-cache** (`/data/dalvik-cache`) agar ART recompile boot image.
5. Boot pertama lebih lambat (normal).

## 4. Verifikasi setelah boot
1. Buka app → **FIX INTEGRITY NOW** (otomatis: enable + profile bawaan + **install hook** ke
   Settings + restart GMS). Atau via ADB: `python tools/provision.py --install-hook --fix`.
2. Import keybox: app **Import keybox file**, atau `provision.py --keybox <file>`.
3. App → Tools → **Framework self-test**:
   - `attestation=3 keymaster=4` (device ini keymaster@4.0 → exact)
   - `keybox #1 ... ok`, `target=true`
   - `tee` = `broken` bila memang begitu → mode harus `generate` (auto mendeteksi).
4. App → Tools → **Check ROM signature** → harus `releasekey` (signature spoof tidak perlu).
5. Cek native: `adb shell md5sum /system/lib64/libfarewell.so` (harus sama dengan tabel di atas),
   lalu app op `nativeprobe` → `after='hooked' state=1`.
6. Play Integrity API Checker.
7. Bila gagal: **Export debug bundle** → `python tools/adb_debug.py --collect` → kirim zip.

## 4b. Update hook tanpa repack
Setelah boot pertama, update logika hook cukup lewat app (**Install / update hook**) atau
`python tools/provision.py --install-hook [hook.dex]` — **tidak perlu repack/flash lagi**.

## 5. Rollback
- Flash kembali image stok (termasuk `vbmeta_system` stok bila diubah).
- Data user tidak perlu dihapus (cukup dalvik).
- `python tools/provision.py --clear` untuk membersihkan config bila diperlukan.

## 6. Setelah sesi debugging
- App → Tools → **Disable ADB** (stealth).
- Rotasi keybox rutin: tombol **Rotate keybox** / `tools/provision.py --fix`.
