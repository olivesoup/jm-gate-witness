"""Strict public HASH-ONLY claim canonicalizer.

SOURCE-ONLY validation. Neither a valid claim nor a digest means a signed,
globally replay-protected CAS commit or proof of a Windows Sandbox VM teardown.
Never import private code, keys, PR content, Host logs, or arbitrary extensions.
"""
import datetime
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

SCHEMA = "JM_HASH_WITNESS_V1"
AUDIENCE = "olivesoup/jm-gate-witness:pet001"
MAX_BYTES = 4096
HEX = re.compile(r"^[0-9a-f]{64}$")
ALLOWED = frozenset((
    "schema", "audience", "claim_id", "run_nonce", "created_at",
    "source_root_sha256", "output_root_sha256", "host_receipt_sha256",
    "release_set_sha256", "previous_claim_sha256", "sequence",
    "claim_kind",
))


class ClaimRejected(ValueError):
    pass


def _pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            raise ClaimRejected("DUPLICATE_JSON_KEY")
        result[k] = v
    return result


def parse_untrusted(data):
    if not isinstance(data, bytes) or not (0 < len(data) <= MAX_BYTES):
        raise ClaimRejected("INPUT_SIZE")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ClaimRejected("BOM_DENIED")
    try:
        s = data.decode("utf-8", errors="strict")
        x = json.loads(s, object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           ClaimRejected("NONFINITE_NUMBER")))
    except (UnicodeError, json.JSONDecodeError) as e:
        raise ClaimRejected("INVALID_JSON") from e
    return validate(x)


def validate(x):
    if type(x) is not dict or set(x) != ALLOWED:
        raise ClaimRejected("EXACT_SCHEMA_ONLY")
    if x["schema"] != SCHEMA or x["audience"] != AUDIENCE:
        raise ClaimRejected("WRONG_SCHEMA_OR_AUDIENCE")
    if x["claim_kind"] != "EVIDENCE_ONLY_NOT_GATE":
        raise ClaimRejected("CLAIM_AUTHORITY_ESCALATION")
    try:
        token = str(uuid.UUID(x["claim_id"]))
        u = uuid.UUID(token)
        if u.version != 4 or x["claim_id"] != token:
            raise ValueError()
    except (ValueError, AttributeError, TypeError):
        raise ClaimRejected("CLAIM_UUID_INVALID")
    if type(x["run_nonce"]) is not str or not re.fullmatch(
            r"[A-Za-z0-9_-]{32,128}", x["run_nonce"]):
        raise ClaimRejected("RUN_NONCE_INVALID")
    try:
        if type(x["created_at"]) is not str or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", x["created_at"]):
            raise ValueError()
        timestamp = datetime.datetime.strptime(
            x["created_at"], "%Y-%m-%dT%H:%M:%SZ")
        if not (datetime.datetime(2026, 1, 1) <= timestamp <=
                datetime.datetime(2100, 1, 1)):
            raise ValueError()
    except (TypeError, ValueError):
        raise ClaimRejected("TIMESTAMP_INVALID")
    for k in ("source_root_sha256", "output_root_sha256",
              "host_receipt_sha256", "release_set_sha256",
              "previous_claim_sha256"):
        if type(x[k]) is not str or not HEX.fullmatch(x[k]):
            raise ClaimRejected("DIGEST_INVALID_" + k)
    if type(x["sequence"]) is not int or x["sequence"] <= 0:
        raise ClaimRejected("CAS_SEQUENCE_INVALID")
    if x["sequence"] == 1 and x["previous_claim_sha256"] != "0" * 64:
        raise ClaimRejected("GENESIS_PREVIOUS_SHA")
    if x["sequence"] > 1 and x["previous_claim_sha256"] == "0" * 64:
        raise ClaimRejected("NON_GENESIS_PREVIOUS_SHA")
    return x


def canonical_bytes(x):
    validate(x)
    return (json.dumps(x, sort_keys=True, ensure_ascii=True,
                       allow_nan=False, separators=(",", ":")) +
            "\n").encode("utf-8")


def claim_digest(x):
    return hashlib.sha256(canonical_bytes(x)).hexdigest()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "inspect":
        raise SystemExit("Usage: hash_claim.py inspect PATH; SOURCE-ONLY")
    path = Path(args[1])
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise SystemExit("INVALID_CLAIM_PATH_OR_SIZE")
    try:
        claim = parse_untrusted(path.read_bytes())
    except ClaimRejected as exc:
        raise SystemExit("DENIED_" + str(exc))
    # Outputs only the hash, not potentially private content or PASS gate.
    print("JM_WITNESS_SOURCE_ONLY_DIGEST_SHA256=" + claim_digest(claim))
    print("JM_WITNESS_GATE=BLOCK_UNLESS_SIGNED_ISSUER_CAS_VM_ATTESTED")


if __name__ == "__main__":
    main()
