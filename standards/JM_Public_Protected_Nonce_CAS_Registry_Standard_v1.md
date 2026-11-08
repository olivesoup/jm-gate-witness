# JM Public protected nonce CAS registry — Standard v1

Status: CANDIDATE. GitHub public persistent CAS backend source; **not yet provisioned or authorized as a product Gate**.

## Decision and single-founder cost constraints
- Use existing **public** `olivesoup/jm-gate-witness` Git object/ref storage as the persistent registry, rather than a paid database or a new human account.
- Global namespace within this issuer: `refs/tags/jm-cas/v1/<nonce>`, nonce exactly 32 lowercase hexadecimal characters; **nonce is the entire uniqueness key**. Do not embed claim digest in the ref name or duplicates under one nonce could coexist.
- Each claim is bound to an **annotated Git tag object** with explicit public `JM-CAS-BOUND-V1` canonical metadata: nonce, sha256 of a prior independently verified PUBLIC EVIDENCE_ONLY claim, immutable protected master source SHA and issuer identity. No private Java, logs, paths, host names or secret metadata.
- GitHub `POST /git/refs` on this unique tag name provides exclusive reference creation: one of two racing requests may create the ref; every loser MUST fail-closed. Treat `409` / `422` as DENY, NOT success. No check/Host/merge is published by recording a nonce.
- A **separate ACTIVE tag ruleset** targeting tag pattern `jm-cas/v1/*` must prohibit updates and deletions, with **zero bypass**. It MUST NOT prohibit creations, or legitimate unique nonce registration would deadlock. Admin creates ruleset once through versioned bounded script; exact live REST readback required. Existing protected master Ruleset 26785842 remains unchanged.
- Existing GitHub repository admin could disable the tag ruleset, recover GitHub accounts, delete the repository or roll back external state. Therefore this storage is **not an independent globally nonrollback database under administrator compromise**; independently witnessed Sigstore/Rekor signed checkpoint + separate verification and recheck of tag ref remain mandatory to claim a stronger external transparency property.
- A GitHub signed artifact alone cannot prove the Host ran, VM identity, Guest result, teardown or cross-repo acceptance. The registry may hold **only synthetic bootstrap evidence** until trusted issuer and independent Host receipt exist. Never use a GitHub API token from PR/Guest/Tier-A untrusted candidate code.
- Strong privacy: all refs, tags and messages PUBLIC; the claim must have public scope and four zero digests. No private release set references in plaintext. Logs print only nonce digest and state without GitHub auth tokens.
- No auto merge or activation. Independent Mainline, Adversarial and Judge exact-head review, then explicit sole human MERGE, followed by distinct later ACTIVATE before any privileged `contents:write` production operation.
- Separate scope: a bounded synthetic **CAS test** may be executed after signed-public Witness and tag ruleset are ready; a synthetic success is **not** a product global CAS Gate. Production issuer adapter and independent Check publisher remain BLOCK until complete external proof.

## GitHub REST schema correction after native HTTP 422 (2026-11-08)
- The tag ruleset's `conditions.ref_name.include` MUST be the complete Git ref glob `refs/tags/jm-cas/v1/*`, not the shorter Git tag-name-only glob. Tag creation uses `refs/tags/` in the REST ref endpoint; matching ruleset conditions must be unambiguous.
- The `update` rule MUST provide `parameters.update_allows_fetch_and_merge=false` per GitHub REST ruleset request schema. Missing this required boolean can be rejected with HTTP 422. Deletion rule takes no parameters.
- Readback must independently verify the exact full-ref matcher, single `update` rule and its exact false parameter, deletion rule, active enforcement, no bypass actors, no creation restriction. Never reinterpret a 422 as success.
- This migration is an **administrator policy configuration**, not an issue of GitHub Runner VM permissions or a signed product Gate. No Tag namespace was deployed by the rejected request; owner executes only corrected immutable script after CI.

## Live creation/readback reconciliation (2026-11-08, Ruleset #26789418)

- Actual owner-admin command **successfully CREATED** the tag ruleset before the final PowerShell post-creation readback raised `PropertyNotFoundStrict`; GitHub GET `/repos/olivesoup/jm-gate-witness/rulesets/26789418` independently confirms **active**, tag target, `refs/tags/jm-cas/v1/*`, zero bypass, and exact `update` + `deletion` rules. Master Ruleset 26785842 is unchanged.
- GitHub's returned `update` rule for a **tag** may have no `parameters` field despite the API create request requiring `parameters.update_allows_fetch_and_merge=false`. This boolean applies to branch fetch/merge and has no semantic meaning for tag refs. Do not access `.parameters` under PowerShell StrictMode without first checking for the property. Accept an absent `parameters` only for an otherwise exact *tag* `update` rule; when present, require `update_allows_fetch_and_merge` to be explicit Boolean `false`. Deny any extra or permissive param value.
- The creation path is now **idempotent**: with Ruleset 26789418 present, *read and verify only*; absolutely no second POST, rule replacement, force-push, synthetic tag creation or CAS admission during reconciliation.
- **TAG_RULESET_POLICY_READY** is backed by native independent readback, but **CAS_ATOMIC_LIVE_RACE=UNTESTED**, **ADMIN_NONROLLBACK=UNPROVEN**, and **PRODUCTION_ISSUER_GATE=BLOCK**. Do not reinterpret Ruleset creation or mock tests as a real global CAS acceptance.
