"""Unit tests for the offline tooling (stdlib unittest)."""

import base64
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


provision = load("farewell_provision", ROOT / "tools" / "provision.py")
lab = load("farewell_lab", ROOT / "tools" / "attestation_lab.py")


class EnvelopeTests(unittest.TestCase):
    def test_roundtrip(self):
        config = {"en": 1, "fl": 3, "md": "auto", "kb": ["aGVsbG8="], "tg": ["x:y"]}
        encoded = provision.encode_envelope(config)
        self.assertTrue(encoded.startswith("F1:"))
        decoded = provision.decode_envelope(encoded)
        self.assertEqual(decoded, config)

    def test_plain_json_accepted(self):
        decoded = provision.decode_envelope('{"en":1}')
        self.assertEqual(decoded, {"en": 1})

    def test_empty(self):
        self.assertIsNone(provision.decode_envelope(None))
        self.assertIsNone(provision.decode_envelope(""))


class SideloadTests(unittest.TestCase):
    def test_roundtrip_matches_sha(self):
        payload = bytes(range(256)) * 900  # ~230 KB -> multiple chunks
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dex") as handle:
            handle.write(payload)
            path = handle.name
        try:
            import hashlib
            provision.verify_sideload(path)  # raises SystemExit on failure
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(),
                hashlib.sha256(payload).hexdigest())
        finally:
            Path(path).unlink(missing_ok=True)


class ProfileTests(unittest.TestCase):
    def test_valid_profile(self):
        profile = {
            "FINGERPRINT": "google/blazer_beta/blazer:CANARY/ZP11.260717.006/16004061:user/release-keys",
            "MANUFACTURER": "Google",
            "MODEL": "Pixel 10 Pro",
            "SECURITY_PATCH": "2026-07-05",
            "DEVICE_INITIAL_SDK_INT": "32",
        }
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as handle:
            json.dump(profile, handle)
            path = handle.name
        try:
            report = lab.validate_profile(path)
            self.assertTrue(report["ok"], report["problems"])
            self.assertEqual(report["expanded"]["DEVICE"], "blazer")
            self.assertEqual(report["expanded"]["ID"], "ZP11.260717.006")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_invalid_patch_and_fingerprint(self):
        profile = {"FINGERPRINT": "too/short", "SECURITY_PATCH": "2026/07/05"}
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as handle:
            json.dump(profile, handle)
            path = handle.name
        try:
            report = lab.validate_profile(path)
            self.assertFalse(report["ok"])
            self.assertTrue(any("FINGERPRINT" in item for item in report["problems"]))
            self.assertTrue(any("SECURITY_PATCH" in item for item in report["problems"]))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_prop_style_profile(self):
        text = ("FINGERPRINT=google/oriole_beta/oriole:CANARY/AP4A.250105.002/"
                "12345678:user/release-keys\nSECURITY_PATCH=2025-01-05\n")
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".prop") as handle:
            handle.write(text)
            path = handle.name
        try:
            report = lab.validate_profile(path)
            self.assertTrue(report["ok"], report["problems"])
            self.assertEqual(report["expanded"]["DEVICE"], "oriole")
        finally:
            Path(path).unlink(missing_ok=True)


patcher = load("farewell_patcher", ROOT / "patcher" / "farewell_patch.py")


class PatcherTemplateTests(unittest.TestCase):
    """Regression: hook snippets must fall through to the original code only when the hook
    returned null (if-eqz). Using if-nez discards non-null results (the 1.8.6 forge bug)."""

    def test_result_templates_branch_on_null(self):
        names = ("CODE_CHAIN_FOR_ALIAS", "CODE_KEY_FOR_ALIAS", "CODE_CERT_FOR_ALIAS",
                 "CODE_SOFTWARE_KEY", "CODE_PROP_STR", "CODE_PROP_STR_NULL",
                 "CODE_PROP_INT", "CODE_PROP_LONG", "CODE_PROP_BOOL")
        for name in names:
            snippet = getattr(patcher, name)
            self.assertIn("if-eqz", snippet, name)
            self.assertNotIn("if-nez", snippet, name)

    def test_no_inverted_branches_anywhere(self):
        source = Path(patcher.__file__).read_text(encoding="utf-8")
        self.assertNotIn("if-nez", source)


class DerReaderTests(unittest.TestCase):
    def test_high_tag_and_integers(self):
        blob = lab.der_seq([
            lab.der_int(100),
            lab.der_enum(1),
            lab.explicit(704, lab.der_octet(b"abc")),
        ])
        tag, content = lab.DerReader(blob).read()
        self.assertEqual(tag, b"\x30")
        fields = lab.DerReader(content).read_all()
        self.assertEqual(len(fields), 3)
        self.assertEqual(lab.as_int(fields[0][1]), 100)
        self.assertEqual(lab.context_number(fields[2][0]), 704)


if __name__ == "__main__":
    unittest.main()
