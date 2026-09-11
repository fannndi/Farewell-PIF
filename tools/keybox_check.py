#!/usr/bin/env python3
"""
Offline keybox health check (the check that catches what "not revoked" misses).

A keybox can be internally perfect (every signature verifies, every issuer is a CA, the
private key matches the batch certificate) and still be useless for STRONG integrity: the
chain must terminate at one of Google's CURRENT hardware attestation roots. Google rotated
the RSA root in 2022 and published an ECDSA root in 2025; keyboxes from the 2019-2021 era
chain to a retired root of the same subject, verify locally, and are rejected server-side.

Usage:
  python tools/keybox_check.py keybox.xml
  python tools/keybox_check.py keybox.xml --online   # also fetch the authoritative root list

Exit code 0 when every section is anchored to a current Google root, 1 otherwise.
"""

import argparse
import base64
import hashlib
import re
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.primitives import serialization
except ImportError:
    raise SystemExit("pip install cryptography")

CURRENT_ROOTS = {
    # https://android.googleapis.com/attestation/root (fetched 2026-09)
    "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc":
        "Google hardware root RSA-4096 (2022, valid to 2042)",
    "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0":
        "Google Key Attestation CA1 ECDSA P-384 (2025, valid to 2035)",
}


def pem_body(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "".join(line for line in lines if "BEGIN" not in line and "END" not in line)


def load_pem_cert(text):
    der = base64.b64decode(pem_body(text))
    return x509.load_der_x509_certificate(der), der


def load_pem_key(text):
    match = re.search(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", text, re.S)
    if not match:
        raise ValueError("no PEM private key")
    pem = ("-----BEGIN %s-----\n%s\n-----END %s-----\n"
           % (match.group(1), pem_body(match.group(2)), match.group(1)))
    return serialization.load_pem_private_key(pem.encode(), password=None)


def verify_link(child, issuer):
    public_key = issuer.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(child.signature, child.tbs_certificate_bytes,
                          padding.PKCS1v15(), child.signature_hash_algorithm)
    else:
        public_key.verify(child.signature, child.tbs_certificate_bytes,
                          ec.ECDSA(child.signature_hash_algorithm))


def is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except Exception:
        return False


def check_section(algo, body, online_roots, offline_ok):
    print("== key algorithm: %s" % algo)
    certs = re.findall(r'<Certificate\s+format="pem">(.*?)</Certificate>', body, re.S)
    keys = re.findall(r'<PrivateKey\s+format="pem">(.*?)</PrivateKey>', body, re.S)
    if len(certs) < 2:
        print("   FAIL: chain has fewer than 2 certificates")
        return False

    chain = []
    ok = True
    for index, text in enumerate(certs):
        cert, der = load_pem_cert(text)
        chain.append((cert, der))
        ca = is_ca(cert)
        print("   [%d] %s" % (index, cert.subject.rfc4514_string()[:78]))
        print("       issuer=%s CA=%s valid=%s..%s"
              % (cert.issuer.rfc4514_string()[:60], ca,
                 cert.not_valid_before_utc.date(), cert.not_valid_after_utc.date()))
        if index > 0 and not ca:
            print("       FAIL: issuer certificate is not a CA")
            ok = False

    for index in range(len(chain) - 1):
        try:
            verify_link(chain[index][0], chain[index + 1][0])
            print("   link %d->%d: signature OK" % (index, index + 1))
        except Exception as error:
            print("   link %d->%d: FAIL (%s)" % (index, index + 1, str(error)[:60]))
            ok = False

    if keys:
        try:
            private = load_pem_key(keys[0])
            public_der = private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            chain_der = chain[0][0].public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            if public_der == chain_der:
                print("   private key matches the batch certificate: OK")
            else:
                print("   FAIL: private key does not match the batch certificate")
                ok = False
        except Exception as error:
            print("   private key: could not compare (%s)" % str(error)[:60])

    root_fp = hashlib.sha256(chain[-1][1]).hexdigest()
    print("   chain root sha256: %s" % root_fp)
    if root_fp in CURRENT_ROOTS:
        print("   ANCHORED: %s" % CURRENT_ROOTS[root_fp])
    elif root_fp in online_roots:
        print("   ANCHORED (online list): %s" % online_roots[root_fp])
    elif online_roots:
        print("   FAIL: root is not in the CURRENT online attestation root list")
        ok = False
    else:
        print("   FAIL: root is NOT one of the current pinned Google roots")
        print("         -> STRONG integrity will be rejected server-side, even though the")
        print("            chain verifies locally. Replace the keybox (2019-2021 batches")
        print("            chain to the retired RSA root).")
        ok = False
    return ok


def fetch_online_roots():
    try:
        from urllib.request import urlopen
        blob = urlopen("https://android.googleapis.com/attestation/root",
                       timeout=15).read().decode()
        blob = blob.replace("\\n", "\n")
        pems = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                          blob, re.S)
        roots = {}
        for pem in pems:
            cert, der = load_pem_cert(pem)
            roots[hashlib.sha256(der).hexdigest()] = \
                "online: " + cert.subject.rfc4514_string()[:60]
        return roots
    except Exception as error:
        print("online root fetch failed: %s" % error)
        return {}


def main():
    parser = argparse.ArgumentParser(description="Offline keybox health check")
    parser.add_argument("keybox", help="path to keybox.xml")
    parser.add_argument("--online", action="store_true",
                        help="also fetch Google's current root list")
    args = parser.parse_args()

    xml = open(args.keybox, encoding="utf-8").read()
    sections = re.split(r'<Key\s+algorithm="([^"]+)"', xml)
    if len(sections) < 3:
        raise SystemExit("no <Key> sections found (is this a keybox.xml?)")

    online_roots = fetch_online_roots() if args.online else {}
    all_ok = True
    for index in range(1, len(sections), 2):
        all_ok = check_section(sections[index], sections[index + 1], online_roots,
                               bool(online_roots)) and all_ok

    print("-" * 60)
    print("VERDICT:", "OK - current Google anchor" if all_ok
          else "NOT USABLE for STRONG (root rotated out or chain broken)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
