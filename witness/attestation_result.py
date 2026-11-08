"""Fail-closed post-crypto assertion over gh attestation verify JSON.

The JSON is trusted ONLY after gh attestation verify has returned exit 0.
This module is not a cryptographic verifier and cannot issue Host/CAS authority.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from hash_claim import parse_untrusted

EXPECTED_NAME = "jm-witness-bootstrap-public-hash-claim.json"
SYNTHETIC_DIGEST_FIELDS = (
    "source_root_sha256", "output_root_sha256",
    "host_receipt_sha256", "release_set_sha256",
)


class AttestationBlocked(ValueError):
    pass


def verify_verified_result(data: object, claim_data: bytes) -> str:
    claim = parse_untrusted(claim_data)
    if claim["claim_kind"] != "EVIDENCE_ONLY_NOT_GATE":
        raise AttestationBlocked("NOT_SYNTHETIC_EVIDENCE_ONLY")
    if any(claim[k] != "0" * 64 for k in SYNTHETIC_DIGEST_FIELDS):
        raise AttestationBlocked("NONZERO_HOST_OR_PRODUCT_DIGEST")
    digest = hashlib.sha256(claim_data).hexdigest()
    if type(data) is not list or len(data) != 1:
        raise AttestationBlocked("ATTESTATION_RESULT_NOT_UNIQUE")
    item = data[0]
    if type(item) is not dict:
        raise AttestationBlocked("RESULT_INVALID")
    verified = item.get("verificationResult")
    if type(verified) is not dict:
        raise AttestationBlocked("CRYPTO_RESULT_ABSENT")
    signature = verified.get("signature")
    if (type(signature) is not dict
            or type(signature.get("certificate")) is not dict
            or not signature["certificate"]):
        raise AttestationBlocked("VERIFIED_CERTIFICATE_MISSING")
    timestamps = verified.get("verifiedTimestamps")
    if type(timestamps) is not list or not timestamps:
        raise AttestationBlocked("SIGNED_TIMESTAMP_MISSING")
    if any(type(t) is not dict or not t for t in timestamps):
        raise AttestationBlocked("SIGNED_TIMESTAMP_INVALID")
    statement = verified.get("statement")
    if type(statement) is not dict:
        raise AttestationBlocked("SIGNED_STATEMENT_MISSING")
    subjects = statement.get("subject")
    if type(subjects) is not list or len(subjects) != 1:
        raise AttestationBlocked("STATEMENT_SUBJECT_AMBIGUOUS")
    subject = subjects[0]
    if type(subject) is not dict or subject.get("name") != EXPECTED_NAME:
        raise AttestationBlocked("SUBJECT_NAME_MISMATCH")
    digest_obj = subject.get("digest")
    if (type(digest_obj) is not dict
            or set(digest_obj) != {"sha256"}
            or digest_obj["sha256"] != digest):
        raise AttestationBlocked("SUBJECT_SHA256_MISMATCH")
    return digest


def run_cli(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("Usage: attestation_result.py VERIFIED_JSON PUBLIC_CLAIM_FILE")
    path, claim_path = [Path(x) for x in argv]
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise SystemExit("VERIFIED_RESULT_INPUT_INVALID")
    if not claim_path.is_file() or claim_path.is_symlink() or claim_path.stat().st_size > 4096:
        raise SystemExit("PUBLIC_CLAIM_INPUT_INVALID")
    try:
        result = json.loads(path.read_bytes())
        digest = verify_verified_result(result, claim_path.read_bytes())
    except (AttestationBlocked, ValueError, TypeError) as exc:
        raise SystemExit("PUBLIC_ATTESTATION_RESULT_DENIED_" + str(exc))
    print("JM_PUBLIC_SYNTHETIC_ATTESTATION_SUBJECT_SHA256=" + digest)
    print("JM_REAL_HOST_CAS_VM_GATE=BLOCK_NOT_ATTESTED")
    return 0


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
