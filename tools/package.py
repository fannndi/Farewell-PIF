#!/usr/bin/env python3
"""Package Farewell-PIF build artifacts into a distributable zip."""

import json
import shutil
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "out"
DIST = ROOT / "dist"

VERSION = "1.8.5"
DEVICE = "surya-a12"
NAME = "Farewell-PIF-%s-%s.zip" % (VERSION, DEVICE)


def main():
    DIST.mkdir(exist_ok=True)
    target = DIST / NAME
    include = [
        OUT / "framework.jar",
        OUT / "services.jar",
        OUT / "FarewellPIF.apk",
        OUT / "privapp" / "dev.farewell.pif.xml",
        OUT / "patch-report.json",
        ROOT / "README.md",
        ROOT / "REPACK_CHECKLIST.md",
        ROOT / "build.py",
        ROOT / "build_app.py",
        ROOT / "tools" / "provision.py",
        ROOT / "tools" / "audit_rom.py",
        ROOT / "tools" / "attestation_lab.py",
        ROOT / "tools" / "adb_debug.py",
        ROOT / "patcher" / "farewell_patch.py",
        ROOT / "reference" / "profile" / "Pif-props.json",
    ]
    optional = [
        OUT / "rom-audit.json",
        OUT / "attestation-lab.json",
        OUT / "hook.dex",
    ]
    present_optional = [path for path in optional if path.exists()]
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in include + present_optional:
            if not path.exists():
                raise SystemExit("missing: %s" % path)
            archive.write(path, path.relative_to(ROOT).as_posix())
        archive.writestr(
            "BUILD-INFO.txt",
            "Farewell-PIF %s (%s)\nbuilt: %s\n" % (VERSION, DEVICE, date.today().isoformat()),
        )
    print("packaged %s (%.2f MB)" % (target, target.stat().st_size / 1e6))


if __name__ == "__main__":
    main()
