"""Negative proof oracles for post-crypto verified signed synthetic artifact binding."""
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "witness"
for name in ("hash_claim", "attestation_result"):
    spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
mod = sys.modules["attestation_result"]
canonical = sys.modules["hash_claim"]

GOOD = {
    "schema": "JM_HASH_WITNESS_V1",
    "audience": "olivesoup/jm-gate-witness:pet001",
    "claim_id": "12345678-1234-4234-8234-123456789abc",
    "run_nonce": "N" * 32,
    "created_at": "2026-11-08T02:00:00Z",
    "source_root_sha256": "0" * 64,
    "output_root_sha256": "0" * 64,
    "host_receipt_sha256": "0" * 64,
    "release_set_sha256": "0" * 64,
    "previous_claim_sha256": "0" * 64,
    "sequence": 1,
    "claim_kind": "EVIDENCE_ONLY_NOT_GATE",
}
CLAIM = canonical.canonical_bytes(GOOD)


def good():
    return [{"verificationResult": {
        "signature": {"certificate": {"rawBytes": "placeholder-not-crypto-proof"}},
        "verifiedTimestamps": [{"timestamp": "2026-11-08T02:00:00Z"}],
        "statement": {"subject": [{
            "name": mod.EXPECTED_NAME,
            "digest": {"sha256": hashlib.sha256(CLAIM).hexdigest()},
        }]},
    }}]


class SignedClaimResultChecks(unittest.TestCase):
    def block(self, results, label):
        with self.assertRaisesRegex(mod.AttestationBlocked, label):
            mod.verify_verified_result(results, CLAIM)

    def test_post_crypto_structural_match_not_real_gate(self):
        self.assertEqual(mod.verify_verified_result(good(), CLAIM), hashlib.sha256(CLAIM).hexdigest())

    def test_unverified_certificate_missing(self):
        x = good()
        del x[0]["verificationResult"]["signature"]["certificate"]
        self.block(x, "CERTIFICATE")

    def test_missing_timestamps(self):
        x = good()
        x[0]["verificationResult"]["verifiedTimestamps"] = []
        self.block(x, "TIMESTAMP")

    def test_wrong_subject_name(self):
        x = good()
        x[0]["verificationResult"]["statement"]["subject"][0]["name"] = "private.xml"
        self.block(x, "SUBJECT_NAME")

    def test_wrong_digest(self):
        x = good()
        x[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "a" * 64
        self.block(x, "SHA256")

    def test_extra_subject(self):
        x = good()
        x[0]["verificationResult"]["statement"]["subject"].append(x[0]["verificationResult"]["statement"]["subject"][0])
        self.block(x, "SUBJECT_AMBIGUOUS")

    def test_duplicate_attestation_result(self):
        x = good()
        self.block(x + x, "NOT_UNIQUE")

    def test_empty_result(self):
        self.block([], "NOT_UNIQUE")

    def test_certificate_result_not_verification_dict(self):
        self.block([{"verificationResult": "PASS"}], "CRYPTO_RESULT")

    def test_non_object_timestamp(self):
        x = good()
        x[0]["verificationResult"]["verifiedTimestamps"] = ["2026-11-08T02:00:00Z"]
        self.block(x, "TIMESTAMP_INVALID")

    def test_extra_digest_alg(self):
        x = good()
        x[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha512"] = "x"
        self.block(x, "SHA256")

    def test_noncanonical_private_digest(self):
        altered = dict(GOOD, host_receipt_sha256="a" * 64)
        raw = canonical.canonical_bytes(altered)
        with self.assertRaisesRegex(mod.AttestationBlocked, "NONZERO_HOST_OR_PRODUCT_DIGEST"):
            mod.verify_verified_result(good(), raw)

    def test_source_replay_cannot_fake_digest(self):
        replay = CLAIM.replace(b"2026-11-08T02:00:00Z", b"2026-11-08T03:00:00Z")
        with self.assertRaisesRegex(mod.AttestationBlocked, "SUBJECT_SHA256_MISMATCH"):
            mod.verify_verified_result(good(), replay)


if __name__ == "__main__":
    unittest.main()
