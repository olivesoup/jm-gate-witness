# JM Public Hash-Only Witness Standard v1

Status: STAGED SOURCE ONLY; NOT TRUSTED SIGNING, LEDGER, VM ATTESTATION, REAL GATE, MERGE OR ACTIVATE.

## Threat model and public/private boundary
- Original Java, JUnit, private repository logs, host file paths, names, credentials and secrets MUST remain in the five private Java Modernization repositories. This public repository may only contain SHA-256 digests, protocol versions, public witness workflow identity and narrow nonce/ledger metadata. A SHA-256 digest is public metadata and may indirectly reveal a familiar artifact through dictionary matching. Sigstore/GitHub OIDC certificates and workflow identity are also public.
- An attacker controlling a mutable private Guest result directory can synthesize mutually consistent Surefire XML/JSON/logs and their hashes. A public signature only attests that a trusted issuer signed a digest; it does NOT prove the guest code ran, the VM was destroyed, or the source inputs matched.
- A private PR's content MUST NOT be checked out or executed in the public witness, not even when labeled safe. A public workflow may only sign a canonical hash-only claim that has already passed independently authenticated external Host verification.

## Trust roots and activation prerequisites
1. User/admin must enable ACTIVE PUBLIC GitHub rulesets on `master`: prohibit force pushes and deletion, restrict direct updates, require PR review and a required check (provisioned from stable workflow). A GitHub Free PUBLIC repo supports rulesets, but a no-admin repository connector cannot write them. A ruleset absent or disabled is a **hard BLOCK**.
2. After independent exact-head Mainline + Adversarial + Judge approval, a trusted workflow placed under `.github/workflows/` may issue a Sigstore Fulcio OIDC certificate via `actions/attest` on GitHub-hosted Linux (public zero-paid usage subject to current platform quotas), bind artifact subject SHA256 and GitHub signer repository/workflow/ref/SHA and publish a transparency-backed attestation. Verification MUST validate signer repo, signer workflow/ref and exact pinned workflow commit, signature and public transparency inclusion; never accept a guest-owned signer or unsigned JSON.
3. A trusted issuer with trusted clock must validate canonical JSON, audience, nonce, immutable intended five-repo ref set and Host independent lifecycle verdict. Atomic CAS/nonrollback requires independent append-only registry under ruleset and external transparency witness; concurrent claims, stale head, rollback, duplicate nonce, wrong signer, missing ledger or publisher MUST reject. A regular Git commit hash, repository ruleset, attestation or status alone is not equivalent to an independently proven globally nonrollback CAS.
4. Real Host attestor must independently capture before-run exact config SHA256, new run nonce, unique *trusted hypervisor instance* ID, guest source identities, effective policy and after-run termination/discard event for **that same instance**. Legacy Sandbox process absence cannot satisfy that requirement; if API cannot attest VM identity, use another real disposable backend only with exact security Judge approval. Old PET-001 Guest run cannot gain these facts retrospectively.
5. The five-repo functional Release Set requires separate real integration outputs, native run/check IDs and external Judge decisions, not only the 5 master SHAs. No automatic MERGE or ACTIVATE; independent Human final exact-target MERGE event followed by a distinct later ACTIVATE event.

## Operational stages
- STAGED: only Standard, canonical validator, negative tests, inactive `.staged.yml`; GitHub `master` unchanged.
- POLICY_READY: public ruleset present and exact policy independently read back; never infer from public visibility.
- SIGNER_READY: independent-reviewed workflow accepted on protected `master`, real `actions/attest` run succeeded and external verifier reproduced the certificate+workflow-ref+SHA and transparency inclusion.
- CAS_READY: durable atomic replay exclusion and rollback rejection verified from two competing claims and at least one independent verifier/Check publisher.
- TIERB_READY: true Host lifecycle attestor independently proves fresh disposable VM launch and discard.
- REAL_GATE_PASS: all of the above plus actual current native 3+6 and five-repo functional Release Set under fresh exact Judge authorization. No self-declaration.

## Fail-closed disposition
Any unprovisioned rule, issuer, attestation, verifier, CAS ledger, Check publisher, hypervisor VM ID, exact-head review or human gate is BLOCK. No hosted fallback for private candidate code, no purchase, no forced rule bypass, no direct master write before protected Gate and human merge.
