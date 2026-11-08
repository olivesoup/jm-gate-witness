"""GitHub public ref-backed NONCE CAS primitive, not product/Host authority.

Only for already-verified PUBLIC synthetic claims under protected witness master.
No private payloads, no arbitrary repo, no GitHub token in stdout.
"""
from __future__ import annotations

import json
import re
from typing import Callable

REPO = "olivesoup/jm-gate-witness"
RULESET_NAME = "JM-Public-Nonce-CAS-Append-Only"
PREFIX = "jm-cas/v1/"
DIGEST = re.compile(r"^[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
NONCE = re.compile(r"^[a-f0-9]{32}$")


class CasDenied(RuntimeError):
    pass


def validate(nonce: object, claim_sha256: object, master_sha: object):
    if type(nonce) is not str or not NONCE.fullmatch(nonce):
        raise CasDenied("CAS_NONCE_INVALID")
    if type(claim_sha256) is not str or not DIGEST.fullmatch(claim_sha256):
        raise CasDenied("CAS_PUBLIC_CLAIM_DIGEST_INVALID")
    if type(master_sha) is not str or not SHA.fullmatch(master_sha):
        raise CasDenied("CAS_MASTER_SHA_INVALID")


def tag_name(nonce: str):
    if type(nonce) is not str or not NONCE.fullmatch(nonce):
        raise CasDenied("CAS_NONCE_INVALID")
    return PREFIX + nonce


def tag_message(nonce: str, claim_sha256: str, master_sha: str) -> str:
    validate(nonce, claim_sha256, master_sha)
    fields = {
        "schema": "JM_PUBLIC_NONCE_CAS_TAG_V1",
        "issuer": REPO,
        "claim_kind": "EVIDENCE_ONLY_NOT_GATE",
        "nonce": nonce,
        "public_claim_sha256": claim_sha256,
        "protected_master_sha": master_sha,
        "real_gate": False,
    }
    return json.dumps(fields, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False) + "\n"


def _ruleset_ready(rulesets: object) -> None:
    if type(rulesets) is not list:
        raise CasDenied("CAS_RULESETS_UNAVAILABLE")
    matches = [x for x in rulesets if type(x) is dict
               and x.get("name") == RULESET_NAME]
    if len(matches) != 1:
        raise CasDenied("CAS_RULESET_NOT_UNIQUE")
    rule = matches[0]
    if (rule.get("target") != "tag" or rule.get("enforcement") != "active"):
        raise CasDenied("CAS_RULESET_INACTIVE")
    if rule.get("bypass_actors") != []:
        raise CasDenied("CAS_RULESET_BYPASS")
    cond = rule.get("conditions", {}).get("ref_name", {})
    if cond.get("include") != [PREFIX + "*"] or cond.get("exclude") != []:
        raise CasDenied("CAS_REF_TARGET_CHANGED")
    r_types = {r.get("type") for r in rule.get("rules", []) if type(r) is dict}
    if r_types != {"update", "deletion"} or len(rule.get("rules", [])) != 2:
        raise CasDenied("CAS_UPDATE_DELETE_PROTECTION_MISSING")


def commit_synthetic_nonce(transport: Callable, *, nonce: str,
                           claim_sha256: str, master_sha: str) -> dict:
    """transport(method,path,json) returns decoded REST response or raises.

    Request transport is trusted runner code and must NOT use PR-controlled
    code/tokens. Creates a Git object then exclusive tag ref exactly once.
    """
    validate(nonce, claim_sha256, master_sha)
    prefix = "/repos/" + REPO
    rulesets = transport("GET", prefix + "/rulesets", None)
    _ruleset_ready(rulesets)
    active_master = transport("GET", prefix + "/branches/master", None)
    if (type(active_master) is not dict or
        active_master.get("protected") is not True or
        active_master.get("commit", {}).get("sha") != master_sha):
        raise CasDenied("CAS_PROTECTED_MASTER_MOVED_OR_UNTRUSTED")
    name = tag_name(nonce)
    created = transport("POST", prefix + "/git/tags", {
        "tag": name,
        "message": tag_message(nonce, claim_sha256, master_sha),
        "object": master_sha,
        "type": "commit",
    })
    if type(created) is not dict or type(created.get("sha")) is not str or not SHA.fullmatch(created["sha"]):
        raise CasDenied("CAS_ANNOTATED_TAG_OBJECT_NOT_CONFIRMED")
    tag_sha = created["sha"]
    try:
        response = transport("POST", prefix + "/git/refs", {
            "ref": "refs/tags/" + name,
            "sha": tag_sha,
        })
    except Exception as exc:
        raise CasDenied("CAS_NONCE_ALREADY_CONSUMED_OR_REGISTRY_UNAVAILABLE") from exc
    if (type(response) is not dict or
        response.get("ref") != "refs/tags/" + name or
        response.get("object", {}).get("sha") != tag_sha):
        raise CasDenied("CAS_REFERENCE_CREATE_UNVERIFIED")
    observed = transport("GET", prefix + "/git/ref/tags/" + name, None)
    if (type(observed) is not dict or
        observed.get("ref") != "refs/tags/" + name or
        observed.get("object", {}).get("sha") != tag_sha):
        raise CasDenied("CAS_LIVE_REF_READBACK_MISMATCH")
    return {
        "schema": "JM_GITHUB_NONCE_CAS_SYNTHETIC_RECEIPT_V1",
        "nonce": nonce,
        "public_claim_sha256": claim_sha256,
        "tag_object_sha": tag_sha,
        "tag_ref": "refs/tags/" + name,
        "head": master_sha,
        "atomic_ref_create": True,
        "global_nonrollback_proven": False,
        "product_gate": False,
    }
