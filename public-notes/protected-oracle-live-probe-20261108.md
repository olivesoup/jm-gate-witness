# Public protected-base oracle live smoke probe

Scope: ONLY_PUBLIC_SYNTHETIC_POLICY_PROBE, EVIDENCE_ONLY_NOT_PRODUCT_REAL_GATE.

This file exercises an allowed low-trust public-notes/*.md PR against the
independent pull_request_target workflow now installed on protected master.

- No private candidate or credentials.
- No signing, CAS mutation, or Hyper-V VM.
- This PR must NOT be merged. Close it after exact protected-oracle success
  and capture GitHub run identity, protected base and PR HEAD.
- Source bootstrap master Git SHA: f11115ba7b26001812753f325234fbb267d2a85e.
