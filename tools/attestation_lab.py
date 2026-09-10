#!/usr/bin/env python3
"""
Farewell-PIF Attestation Lab.

Offline simulator + verifier for the rootless attestation path, so the generate-mode
encoding and the keybox can be validated on a PC before flashing:

  --info       keybox metadata (chain, subjects, validity, private key match)
  --verify     pairwise chain verification + Google root anchoring + revocation check
  --simulate   mint a software key, forge a KeyDescription leaf with the keybox,
               parse it back with an independent DER reader and assert every field,
               then verify signatures (leaf, chain, key usage)
  --loop N     run N randomized simulate rounds (property/fuzz test)

Uses the "cryptography" package. Keyboxes never leave the machine.

Examples:
  python tools/attestation_lab.py --keybox C:\\path\\keybox.xml --all
  python tools/attestation_lab.py --keybox keybox.xml --loop 25
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFERENCE_GOOGLE = ROOT / "reference" / "google"
ROOT_URL = "https://android.googleapis.com/attestation/root"
STATUS_URL = "https://android.googleapis.com/attestation/status?encrypted=0"
ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import ObjectIdentifier
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCHLEVEL = 706
TAG_APPLICATION_ID = 709
TAG_ID_BRAND = 710
TAG_ID_DEVICE = 711
TAG_ID_PRODUCT = 712
TAG_ID_MANUFACTURER = 716
TAG_ID_MODEL = 717
TAG_VENDOR_PATCHLEVEL = 718
TAG_BOOT_PATCHLEVEL = 719

DEVICE_PROFILE = {
    "brand": b"google",
    "device": b"blazer",
    "product": b"blazer_beta",
    "manufacturer": b"Google",
    "model": b"Pixel 10 Pro",
}


# --------------------------------------------------------------------- DER ---

def der_len(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag, content):
    return tag + der_len(len(content)) + content


def der_int(value):
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return tlv(b"\x02", body)


def der_enum(value):
    return tlv(b"\x0a", bytes([value & 0xff]))


def der_bool(value):
    return tlv(b"\x01", b"\xff" if value else b"\x00")


def der_octet(value):
    return tlv(b"\x04", value)


def der_seq(parts):
    return tlv(b"\x30", b"".join(parts))


def der_set(parts):
    return tlv(b"\x31", b"".join(parts))


def context_tag(number):
    if number < 0x1F:
        return bytes([0xA0 | number])
    digits = []
    value = number
    while value > 0:
        digits.append(value & 0x7F)
        value >>= 7
    digits.reverse()
    out = bytearray([0xBF])
    for index, digit in enumerate(digits):
        out.append(digit | (0x80 if index < len(digits) - 1 else 0))
    return bytes(out)


def explicit(number, content):
    return tlv(context_tag(number), content)


class DerReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def _read(self, count):
        chunk = self.data[self.offset:self.offset + count]
        if len(chunk) != count:
            raise ValueError("DER truncated")
        self.offset += count
        return chunk

    def read(self):
        start = self.offset
        first_byte = self._read(1)[0]
        if first_byte & 0x1F == 0x1F:
            while True:
                more = self._read(1)[0]
                if not more & 0x80:
                    break
        tag = self.data[start:self.offset]
        first = self._read(1)[0]
        if first & 0x80 == 0:
            length = first
        else:
            count = first & 0x7F
            length = int.from_bytes(self._read(count), "big")
        value = self._read(length)
        return tag, value

    def read_all(self):
        items = []
        while self.offset < len(self.data):
            items.append(self.read())
        return items


def context_number(tag):
    first = tag[0]
    if first & 0xC0 != 0x80:
        return None
    if first & 0x1F != 0x1F:
        return first & 0x1F
    number = 0
    for byte in tag[1:]:
        number = (number << 7) | (byte & 0x7F)
    return number


def as_int(value):
    return int.from_bytes(value, "big", signed=True)


# ------------------------------------------------------------------ keybox ---

class KeyboxEntry:
    def __init__(self, algorithm, private_key, chain):
        self.algorithm = algorithm
        self.private_key = private_key
        self.chain = chain

    @property
    def is_ec(self):
        return self.algorithm.lower().startswith("ec")


def pem_body(text):
    return re.sub(r"-----.*?-----|\s+", "", text)


def load_keybox(path):
    tree = ET.parse(path)
    root = tree.getroot()
    entries = []
    for key in root.iter("Key"):
        algorithm = key.get("algorithm", "")
        private_node = key.find("PrivateKey")
        if private_node is None or not private_node.text:
            continue
        pem = pem_body(private_node.text)
        encoded = base64.b64decode(pem)
        try:
            private_key = serialization.load_der_private_key(encoded, password=None)
        except Exception:
            private_key = serialization.load_pem_private_key(
                private_node.text.encode(), password=None)
        chain = []
        for cert_node in key.iter("Certificate"):
            if cert_node.text and "BEGIN CERTIFICATE" in cert_node.text:
                chain.append(x509.load_pem_x509_certificate(cert_node.text.encode()))
        if chain:
            entries.append(KeyboxEntry(algorithm, private_key, chain))
    if not entries:
        raise SystemExit("no usable <Key> entries in %s" % path)
    return entries


def load_google_roots():
    """Offline only: reads the cached root list (reference/google)."""
    path = REFERENCE_GOOGLE / "google_attestation_root.pem"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    roots = []
    try:
        for pem in json.loads(text):
            roots.append(x509.load_pem_x509_certificate(pem.encode()))
    except Exception:
        for match in re.finditer(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S):
            roots.append(x509.load_pem_x509_certificate(match.group(0).encode()))
    return roots


def load_revocation():
    """Offline only: reads the cached status list (reference/google)."""
    path = REFERENCE_GOOGLE / "revocation_status.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# --------------------------------------------------------------------- ops ---

def verify_signature(issuer, subject):
    public_key = issuer.public_key()
    tbs = subject.tbs_certificate_bytes
    signature = subject.signature
    algorithm = subject.signature_hash_algorithm
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, tbs, ec.ECDSA(algorithm))
    else:
        public_key.verify(signature, tbs, padding.PKCS1v15(), algorithm)


def chain_report(entry, roots):
    problems = []
    for index in range(len(entry.chain) - 1):
        try:
            verify_signature(entry.chain[index + 1], entry.chain[index])
        except Exception as error:
            problems.append("chain[%d] not signed by chain[%d]: %s" % (index, index + 1, error))
    anchored = False
    last = entry.chain[-1]
    for root in roots:
        if last.subject == root.subject and last.fingerprint(hashes.SHA256()) \
                == root.fingerprint(hashes.SHA256()):
            anchored = True
            break
        try:
            verify_signature(root, last)
            anchored = True
            break
        except Exception:
            continue
    if roots and not anchored:
        problems.append("chain does not anchor to a known Google root")
    return problems, anchored


def revocation_state(entry, status):
    if not status:
        return "unknown"
    entries = status.get("entries") or {}
    for cert in entry.chain:
        serial = format(cert.serial_number, "x")
        if serial in entries or serial.upper() in entries:
            return entries.get(serial) or entries.get(serial.upper())
        decimal = str(cert.serial_number)
        if decimal in entries:
            return entries[decimal]
    return "not-revoked"


def build_key_description(challenge, attestation_version, keymaster_version, include_ids):
    application_id = der_seq([
        der_set([der_seq([der_octet(b"com.google.android.gms"), der_int(0)])]),
        der_set([der_octet(hashlib.sha256(b"signature-probe").digest())]),
    ])
    software = der_seq([explicit(TAG_APPLICATION_ID, der_octet(application_id))])

    root_of_trust = der_seq([
        der_octet(hashlib.sha256(b"vbmeta-probe").digest()),
        der_bool(True),
        der_enum(0),
        der_octet(hashlib.sha256(b"vbmeta-probe").digest()),
    ])
    hardware = [
        explicit(TAG_ROOT_OF_TRUST, root_of_trust),
        explicit(TAG_OS_VERSION, der_int(120000)),
        explicit(TAG_OS_PATCHLEVEL, der_int(202608)),
        explicit(TAG_VENDOR_PATCHLEVEL, der_int(20260805)),
        explicit(TAG_BOOT_PATCHLEVEL, der_int(20260805)),
    ]
    if include_ids:
        hardware += [
            explicit(TAG_ID_BRAND, der_octet(DEVICE_PROFILE["brand"])),
            explicit(TAG_ID_DEVICE, der_octet(DEVICE_PROFILE["device"])),
            explicit(TAG_ID_PRODUCT, der_octet(DEVICE_PROFILE["product"])),
            explicit(TAG_ID_MANUFACTURER, der_octet(DEVICE_PROFILE["manufacturer"])),
            explicit(TAG_ID_MODEL, der_octet(DEVICE_PROFILE["model"])),
        ]

    description = der_seq([
        der_int(attestation_version),
        der_enum(1),
        der_int(keymaster_version),
        der_enum(1),
        der_octet(challenge),
        der_octet(b""),
        software,
        der_seq(hardware),
    ])
    return description


def valid_from(cert):
    value = getattr(cert, "not_valid_before_utc", None)
    return value if value is not None else cert.not_valid_before


def valid_until(cert):
    value = getattr(cert, "not_valid_after_utc", None)
    return value if value is not None else cert.not_valid_after


def forge_leaf(entry, description_der, public_key, serial):
    template = entry.chain[0]
    builder = (x509.CertificateBuilder()
               .serial_number(serial)
               .issuer_name(template.subject)
               .subject_name(template.subject)
               .public_key(public_key)
               .not_valid_before(valid_from(template))
               .not_valid_after(valid_until(template))
               .add_extension(
                   x509.UnrecognizedExtension(
                       ObjectIdentifier(ATTESTATION_OID), description_der),
                   critical=False))
    return builder.sign(private_key=entry.private_key, algorithm=hashes.SHA256())


def parse_and_assert(leaf, challenge, attestation_version, keymaster_version, include_ids):
    problems = []
    extension = leaf.extensions.get_extension_for_oid(
        ObjectIdentifier(ATTESTATION_OID)).value
    der = extension.value
    reader = DerReader(der)
    tag, content = reader.read()
    if tag != b"\x30":
        problems.append("KeyDescription is not a SEQUENCE")
        return problems

    fields = DerReader(content).read_all()
    if len(fields) != 8:
        problems.append("KeyDescription has %d fields, expected 8" % len(fields))
        return problems

    expected_meta = [b"\x02", b"\x0a", b"\x02", b"\x0a", b"\x04", b"\x04"]
    for index, expected in enumerate(expected_meta):
        if fields[index][0] != expected:
            problems.append("meta field %d tag %s, expected %s (must be untagged)"
                            % (index, fields[index][0].hex(), expected.hex()))
    if context_number(fields[0][0]) is not None:
        problems.append("meta field 0 unexpectedly context-tagged")

    if as_int(fields[0][1]) != attestation_version:
        problems.append("attestationVersion mismatch")
    if fields[1][1][0] != 1:
        problems.append("attestationSecurityLevel != TEE(1)")
    if as_int(fields[2][1]) != keymaster_version:
        problems.append("keymasterVersion mismatch")
    if fields[3][1][0] != 1:
        problems.append("keymasterSecurityLevel != TEE(1)")
    if fields[4][1] != challenge:
        problems.append("attestationChallenge round-trip mismatch")
    if fields[6][0] != b"\x30" or fields[7][0] != b"\x30":
        problems.append("enforcement lists must be untagged SEQUENCEs")
        return problems

    software = DerReader(fields[6][1]).read_all()
    app_id_found = False
    for tag_bytes, value in software:
        if context_number(tag_bytes) == TAG_APPLICATION_ID:
            app_id_found = True
            octet = DerReader(value).read()
            if octet[0] != b"\x04":
                problems.append("applicationId [709] must wrap an OCTET STRING")
            else:
                outer = DerReader(octet[1]).read_all()
                if len(outer) != 1 or outer[0][0] != b"\x30":
                    problems.append("applicationId must be a SEQUENCE")
                else:
                    sets = DerReader(outer[0][1]).read_all()
                    if len(sets) != 2 or sets[0][0] != b"\x31" or sets[1][0] != b"\x31":
                        problems.append("applicationId must be SEQUENCE{SET,SET}")
                    else:
                        records = DerReader(sets[0][1]).read_all()
                        if not records or records[0][0] != b"\x30":
                            problems.append(
                                "applicationId packageInfoRecords must be SET OF SEQUENCE")
    if not app_id_found:
        problems.append("applicationId [709] missing from softwareEnforced")

    hardware = DerReader(fields[7][1]).read_all()
    found = {}
    for tag_bytes, value in hardware:
        number = context_number(tag_bytes)
        if number is not None:
            found.setdefault(number, value)
    if TAG_ROOT_OF_TRUST not in found:
        problems.append("[704] RootOfTrust missing")
    else:
        rot_sequence = DerReader(found[TAG_ROOT_OF_TRUST]).read()
        if rot_sequence[0] != b"\x30":
            problems.append("RootOfTrust must be a SEQUENCE")
        else:
            rot = DerReader(rot_sequence[1]).read_all()
            if len(rot) < 4:
                problems.append("RootOfTrust has %d fields" % len(rot))
            else:
                if rot[1][1] != b"\xff":
                    problems.append("RootOfTrust deviceLocked is not TRUE")
                if rot[2][1][0] != 0:
                    problems.append("RootOfTrust verifiedBootState is not Verified(0)")
    for tag in (TAG_OS_VERSION, TAG_OS_PATCHLEVEL, TAG_VENDOR_PATCHLEVEL, TAG_BOOT_PATCHLEVEL):
        if tag not in found:
            problems.append("tag [%d] missing" % tag)
    if include_ids:
        for tag in (TAG_ID_BRAND, TAG_ID_DEVICE, TAG_ID_PRODUCT,
                    TAG_ID_MANUFACTURER, TAG_ID_MODEL):
            if tag not in found:
                problems.append("device id tag [%d] missing" % tag)
    return problems


def simulate(entries, args, index=None, challenge=None):
    entry = entries[index] if index is not None else entries[0]
    if challenge is None:
        challenge = os.urandom(16)
    if entry.is_ec:
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    description = build_key_description(
        challenge, args.att_version, args.km_version, not args.no_ids)
    leaf = forge_leaf(entry, description, private_key.public_key(),
                      x509.random_serial_number())

    problems = parse_and_assert(
        leaf, challenge, args.att_version, args.km_version, not args.no_ids)

    try:
        verify_signature(entry.chain[0], leaf)
    except Exception as error:
        problems.append("forged leaf not signed by keybox[0]: %s" % error)

    try:
        probe = b"farewell-attestation-probe"
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(probe, ec.ECDSA(hashes.SHA256()))
            leaf.public_key().verify(signature, probe, ec.ECDSA(hashes.SHA256()))
        else:
            signature = private_key.sign(probe, padding.PKCS1v15(), hashes.SHA256())
            leaf.public_key().verify(signature, probe, padding.PKCS1v15(), hashes.SHA256())
    except Exception as error:
        problems.append("generated key does not match leaf SPKI: %s" % error)

    return {
        "algorithm": entry.algorithm,
        "challenge": challenge.hex(),
        "extension_sha256": hashlib.sha256(description).hexdigest(),
        "leaf_serial": hex(leaf.serial_number),
        "problems": problems,
        "ok": not problems,
    }


def info(entries):
    report = []
    for index, entry in enumerate(entries):
        template = entry.chain[0]
        info_entry = {
            "index": index,
            "algorithm": entry.algorithm,
            "chain_length": len(entry.chain),
            "leaf_subject": template.subject.rfc4514_string(),
            "leaf_issuer": template.issuer.rfc4514_string(),
            "leaf_serial": hex(template.serial_number),
            "leaf_not_before": valid_from(template).isoformat(),
            "leaf_not_after": valid_until(template).isoformat(),
            "root_subject": entry.chain[-1].subject.rfc4514_string(),
        }
        try:
            probe = b"keybox-private-key-probe"
            if entry.is_ec:
                signature = entry.private_key.sign(probe, ec.ECDSA(hashes.SHA256()))
                template.public_key().verify(signature, probe, ec.ECDSA(hashes.SHA256()))
            else:
                signature = entry.private_key.sign(probe, padding.PKCS1v15(), hashes.SHA256())
                template.public_key().verify(signature, probe, padding.PKCS1v15(),
                                             hashes.SHA256())
            info_entry["private_key_matches"] = True
        except Exception as error:
            info_entry["private_key_matches"] = "FAILED: %s" % error
        report.append(info_entry)
    return report


def validate_profile(profile_path):
    """Validate a PIF profile (JSON or pif.prop style) against our spoofing semantics."""
    problems = []
    warnings = []
    try:
        text = Path(profile_path).read_text(encoding="utf-8", errors="replace")
    except Exception as error:
        return {"path": str(profile_path), "ok": False,
                "problems": ["cannot read: %s" % error]}

    profile = {}
    try:
        if text.strip().startswith("{"):
            profile = json.loads(text)
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                profile[key.strip()] = value.strip()
    except Exception as error:
        return {"path": str(profile_path), "ok": False,
                "problems": ["parse error: %s" % error]}

    fingerprint = profile.get("FINGERPRINT")
    expanded = {}
    if not fingerprint:
        problems.append("FINGERPRINT is missing")
    else:
        parts = re.split(r"[/:]", fingerprint)
        keys = ["BRAND", "PRODUCT", "DEVICE", "RELEASE", "ID",
                "INCREMENTAL", "TYPE", "TAGS"]
        if len(parts) != 8:
            problems.append("FINGERPRINT has %d parts, expected 8" % len(parts))
        for index, key in enumerate(keys[:min(len(parts), len(keys))]):
            expanded[key] = parts[index]
        for key in ("TYPE", "TAGS"):
            expected = expanded.get(key)
            value = profile.get(key, expected)
            if expected and value and value != expected:
                warnings.append("%s=%r differs from FINGERPRINT part %r" % (key, value, expected))

    if expanded.get("TYPE") and expanded["TYPE"] != "user":
        warnings.append("TYPE is %r (release builds use 'user')" % expanded["TYPE"])
    if expanded.get("TAGS") and expanded["TAGS"] != "release-keys":
        warnings.append("TAGS is %r (release builds use 'release-keys')" % expanded["TAGS"])
    if profile.get("RELEASE") == "CANARY" or (expanded.get("RELEASE") == "CANARY"):
        warnings.append("RELEASE=CANARY is a canary build (acceptable for PIF)")

    patch = profile.get("SECURITY_PATCH")
    if patch and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(patch)):
        problems.append("SECURITY_PATCH must be YYYY-MM-DD, got %r" % patch)

    sdk = profile.get("DEVICE_INITIAL_SDK_INT")
    if sdk is not None:
        try:
            value = int(str(sdk).strip())
            if value < 21 or value > 40:
                warnings.append("DEVICE_INITIAL_SDK_INT=%d looks unusual" % value)
        except Exception:
            problems.append("DEVICE_INITIAL_SDK_INT is not an integer: %r" % sdk)

    brand = profile.get("BRAND", expanded.get("BRAND"))
    manufacturer = profile.get("MANUFACTURER")
    if brand and manufacturer and brand.lower() != manufacturer.lower():
        warnings.append("BRAND=%r vs MANUFACTURER=%r (can differ, e.g. Google/google)"
                        % (brand, manufacturer))

    model = profile.get("MODEL")
    device = profile.get("DEVICE", expanded.get("DEVICE"))
    result = {
        "path": str(profile_path),
        "ok": not problems,
        "fields": sorted(profile.keys()),
        "expanded": expanded,
        "fingerprint": fingerprint,
        "problems": problems,
        "warnings": warnings,
    }
    return result


def main():
    parser = argparse.ArgumentParser(description="Farewell-PIF attestation lab")
    parser.add_argument("--keybox", default=str(ROOT.parent / "keybox.xml"))
    parser.add_argument("--profile", default=None,
                        help="validate a PIF profile (JSON or pif.prop) instead of a keybox")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--info", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--loop", type=int, default=0,
                        help="run N randomized simulate rounds")
    parser.add_argument("--att-version", type=int, default=100)
    parser.add_argument("--km-version", type=int, default=100)
    parser.add_argument("--no-ids", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "out" / "attestation-lab.json"))
    args = parser.parse_args()

    if not HAVE_CRYPTO:
        raise SystemExit("install the 'cryptography' package: python -m pip install cryptography")

    if args.profile:
        report = validate_profile(args.profile)
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("profile:", report["path"])
        print("ok:", report["ok"])
        for problem in report["problems"]:
            print("  PROBLEM:", problem)
        for warning in report["warnings"]:
            print("  warning:", warning)
        print("expanded:", report.get("expanded"))
        print("report:", out_path)
        return

    keybox_path = Path(args.keybox)
    if not keybox_path.exists():
        raise SystemExit("keybox not found: %s" % keybox_path)

    entries = load_keybox(keybox_path)
    roots = load_google_roots()
    status = load_revocation()

    if not any([args.info, args.verify, args.simulate, args.loop]):
        args.info = args.verify = args.simulate = True

    report = {"keybox": str(keybox_path), "google_roots": len(roots)}

    if args.info or args.all:
        report["info"] = info(entries)
        print("keybox info:")
        for item in report["info"]:
            print("  [%d] %s chain=%d subject=%s" % (
                item["index"], item["algorithm"], item["chain_length"],
                item["leaf_subject"]))
            print("      serial=%s valid=%s..%s key_match=%s" % (
                item["leaf_serial"], item["leaf_not_before"], item["leaf_not_after"],
                item["private_key_matches"]))

    if args.verify or args.all:
        verification = []
        print("verification:")
        for index, entry in enumerate(entries):
            problems, anchored = chain_report(entry, roots)
            revoked = revocation_state(entry, status)
            verification.append({
                "index": index,
                "problems": problems,
                "anchored_to_google_root": anchored,
                "revocation": revoked,
            })
            print("  [%d] %s anchored=%s revocation=%s%s" % (
                index, entry.algorithm, anchored, revoked,
                "" if not problems else " problems=%s" % "; ".join(problems)))
        report["verify"] = verification

    if args.simulate or args.all:
        result = simulate(entries, args)
        report["simulate"] = result
        print("simulate (%s): %s" % (result["algorithm"], "PASS" if result["ok"] else "FAIL"))
        for problem in result["problems"]:
            print("   -", problem)

    if args.loop:
        rounds = []
        failures = 0
        for round_index in range(args.loop):
            random.seed(round_index)
            index = round_index % len(entries)
            challenge = bytes(random.getrandbits(8) for _ in range(16))
            result = simulate(entries, args, index=index, challenge=challenge)
            rounds.append(result)
            if not result["ok"]:
                failures += 1
                print("  round %d FAILED: %s" % (round_index, "; ".join(result["problems"])))
        report["loop"] = {"rounds": args.loop, "failures": failures}
        print("loop: %d rounds, %d failures" % (args.loop, failures))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("report:", out_path)


if __name__ == "__main__":
    main()
