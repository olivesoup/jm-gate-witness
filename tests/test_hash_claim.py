"""Source-only negative tests. No remote signer, checkout, or private data."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "witness" / "hash_claim.py"
spec = importlib.util.spec_from_file_location("hash_claim", path)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

GOOD = {
    "schema": "JM_HASH_WITNESS_V1",
    "audience": "olivesoup/jm-gate-witness:pet001",
    "claim_id": "12345678-1234-4234-8234-123456789abc",
    "run_nonce": "N" * 32,
    "created_at": "2026-11-08T02:00:00Z",
    "source_root_sha256": "a" * 64,
    "output_root_sha256": "b" * 64,
    "host_receipt_sha256": "c" * 64,
    "release_set_sha256": "d" * 64,
    "previous_claim_sha256": "0" * 64,
    "sequence": 1,
    "claim_kind": "EVIDENCE_ONLY_NOT_GATE",
}


class StrictSourceChecks(unittest.TestCase):
    def denies(self, patch, reason):
        x = dict(GOOD, **patch)
        with self.assertRaisesRegex(mod.ClaimRejected, reason):
            mod.validate(x)

    def test_canonical_source_shape_but_not_gate(self):
        self.assertEqual(len(mod.claim_digest(GOOD)), 64)

    def test_canonical_independent_of_order(self):
        self.assertEqual(mod.claim_digest(GOOD), mod.claim_digest(dict(reversed(list(GOOD.items())))))

    def test_canonical_deterministic_newline(self):
        raw = mod.canonical_bytes(GOOD)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertEqual(mod.parse_untrusted(raw), GOOD)

    def test_reject_extension_key(self):
        with self.assertRaisesRegex(mod.ClaimRejected, "EXACT_SCHEMA"):
            mod.validate(dict(GOOD, secret_token="leak"))

    def test_reject_missing_key(self):
        x = dict(GOOD)
        del x["source_root_sha256"]
        with self.assertRaisesRegex(mod.ClaimRejected, "EXACT_SCHEMA"):
            mod.validate(x)

    def test_reject_duplicated_json_keys(self):
        raw = mod.canonical_bytes(GOOD).decode().strip()
        raw = raw[:-1] + ',"schema":"JM_HASH_WITNESS_V1"}'
        with self.assertRaisesRegex(mod.ClaimRejected, "DUPLICATE"):
            mod.parse_untrusted(raw.encode())

    def test_reject_private_repo_name_in_audience(self):
        self.denies({"audience": "olivesoup/java-modernization-transformer"}, "WRONG_SCHEMA")

    def test_reject_authority_pass(self):
        for state in ("REAL_GATE_PASS", "ACTIVATE", "MERGE", True):
            self.denies({"claim_kind": state}, "CLAIM_AUTHORITY_ESCALATION")

    def test_reject_bad_schema(self):
        self.denies({"schema": "AUTHORITY_V1"}, "WRONG_SCHEMA")

    def test_reject_uuid_non_v4(self):
        self.denies({"claim_id": "12345678-1234-1234-1234-123456789abc"}, "CLAIM_UUID")

    def test_reject_uuid_uppercase(self):
        self.denies({"claim_id": GOOD["claim_id"].upper()}, "CLAIM_UUID")

    def test_reject_nonce_short(self):
        self.denies({"run_nonce": "short"}, "RUN_NONCE")

    def test_reject_nonce_path(self):
        self.denies({"run_nonce": "C:\\Private\\" + "x" * 40}, "RUN_NONCE")

    def test_reject_date_offset(self):
        self.denies({"created_at": "2026-11-08T11:00:00+09:00"}, "TIMESTAMP")

    def test_reject_date_malformed(self):
        self.denies({"created_at": "2026-02-30T02:00:00Z"}, "TIMESTAMP")

    def test_reject_digest_non_hex(self):
        self.denies({"host_receipt_sha256": "z" * 64}, "DIGEST")

    def test_reject_digest_length(self):
        self.denies({"source_root_sha256": "a" * 40}, "DIGEST")

    def test_reject_negative_sequence(self):
        for v in (0, -1, True, "1", None):
            self.denies({"sequence": v}, "CAS_SEQUENCE")

    def test_reject_forged_genesis_previous_digest(self):
        self.denies({"previous_claim_sha256": "e" * 64}, "GENESIS_PREVIOUS")

    def test_reject_non_genesis_zero_previous(self):
        self.denies({"sequence": 2}, "NON_GENESIS_PREVIOUS")

    def test_allow_shape_of_second_claim_not_cas_authority(self):
        x = dict(GOOD, sequence=2, previous_claim_sha256="f" * 64)
        self.assertEqual(len(mod.claim_digest(x)), 64)

    def test_reject_invalid_utf8(self):
        with self.assertRaisesRegex(mod.ClaimRejected, "INVALID_JSON"):
            mod.parse_untrusted(b"\xff\xfe")

    def test_reject_bom(self):
        with self.assertRaisesRegex(mod.ClaimRejected, "BOM_DENIED"):
            mod.parse_untrusted(b"\xef\xbb\xbf" + mod.canonical_bytes(GOOD))

    def test_reject_oversized_claim(self):
        with self.assertRaisesRegex(mod.ClaimRejected, "INPUT_SIZE"):
            mod.parse_untrusted(b" " * 4097)

    def test_reject_non_object(self):
        with self.assertRaisesRegex(mod.ClaimRejected, "EXACT_SCHEMA"):
            mod.parse_untrusted(b"[]")

    def test_reject_nonfinite_number(self):
        raw = mod.canonical_bytes(GOOD).decode().replace('"sequence":1', '"sequence":NaN')
        with self.assertRaisesRegex(mod.ClaimRejected, "NONFINITE_NUMBER"):
            mod.parse_untrusted(raw.encode())

    def test_reject_direct_private_payload(self):
        with self.assertRaisesRegex(mod.ClaimRejected, "EXACT_SCHEMA"):
            mod.validate(dict(GOOD, sure_fire_xml="<testsuite/>"))

    def test_digest_makes_no_signed_or_cas_decision(self):
        self.assertFalse(hasattr(mod, "verify_signature"))
        self.assertFalse(hasattr(mod, "commit_ledger"))
        self.assertFalse(hasattr(mod, "authorize_merge"))


if __name__ == "__main__":
    unittest.main()
