"""Source tests for protected-base oracle. Never use network or run PR code."""
import importlib.util
import sys
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "witness" / "protected_oracle.py"
spec = importlib.util.spec_from_file_location("protected_oracle", path)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

HEAD = "a" * 40
BASE = "b" * 40
PR = 17


def meta(**overrides):
    d = {
        "number": PR, "state": "open", "changed_files": 1,
        "head": {"sha": HEAD, "repo": {"full_name": mod.REPO}},
        "base": {"sha": BASE, "ref": "master", "repo": {"full_name": mod.REPO}},
    }
    d.update(overrides)
    return d


def files(name="README.md", **kwargs):
    return [dict(filename=name, status="modified", **kwargs)]


class ProtectedOracleChecks(unittest.TestCase):
    def check_block(self, m=None, f=None, reason=""):
        with self.assertRaisesRegex(mod.Blocked, reason):
            mod.assess(m if m is not None else meta(),
                       f if f is not None else files(), pr=PR, head=HEAD, base=BASE)

    def test_public_readme_allowed(self):
        self.assertIn("PASS_NOT_HOST_GATE", mod.assess(meta(), files(), pr=PR, head=HEAD, base=BASE))

    def test_single_public_note_allowed(self):
        self.assertIn("PASS_NOT_HOST_GATE", mod.assess(meta(), files("public-notes/summary-001.md"), pr=PR, head=HEAD, base=BASE))

    def test_source_code_denied(self):
        for name in ("witness/hash_claim.py", "witness/protected_oracle.py", "tests/test_hash_claim.py", "scripts/Set-JM-Witness-Solo-Ruleset.ps1", "standards/JM_Public_Hash_Only_Witness_Standard_v1.md", "automation/staged/jm-hash-witness.staged.yml"):
            with self.subTest(name=name):
                self.check_block(f=files(name), reason="PROTECTED_PATH")

    def test_workflow_replace_with_echo_pass_denied(self):
        self.check_block(f=files(".github/workflows/jm-witness-protected-oracle.yml"), reason="PROTECTED_PATH")

    def test_future_untrusted_test_or_workflow_denied(self):
        self.check_block(f=files(".github/workflows/jm-witness-policy.yml"), reason="PROTECTED_PATH")

    def test_bad_unicode_or_separator(self):
        for name in ("../README.md", "/README.md", "public-notes/../README.md", "public-notes/x\\b.md", "READMEXmd", "public-notes/aXmd", "public-notes/two/deep.md"):
            with self.subTest(name=name):
                self.check_block(f=files(name), reason="PROTECTED_PATH")

    def test_delete_and_rename_denied(self):
        self.check_block(f=[{"filename": "README.md", "status": "removed"}], reason="UNTRUSTED_FILE_CHANGE_TYPE")
        self.check_block(f=files("README.md", previous_filename="README1.md"), reason="RENAME_NOT_ALLOWED")

    def test_exact_head_drift_denied(self):
        self.check_block(m=meta(head={"sha": "c" * 40, "repo": {"full_name": mod.REPO}}), reason="EXACT_HEAD_BASE")

    def test_base_ref_or_sha_drift_denied(self):
        self.check_block(m=meta(base={"sha": BASE, "ref": "other", "repo": {"full_name": mod.REPO}}), reason="EXACT_HEAD_BASE")

    def test_other_repo_fork_denied(self):
        self.check_block(m=meta(head={"sha": HEAD, "repo": {"full_name": "attacker/jm-gate-witness"}}), reason="EXACT_HEAD_BASE")

    def test_wrong_pr_denied(self):
        self.check_block(m=meta(number=18), reason="PR_IDENTITY")

    def test_closed_pr_denied(self):
        self.check_block(m=meta(state="closed"), reason="PR_IDENTITY")

    def test_unbounded_files_denied(self):
        self.check_block(m=meta(changed_files=301), reason="PR_CHANGED_FILE_COUNT")

    def test_partial_response_denied(self):
        self.check_block(m=meta(changed_files=2), reason="PAGINATION")

    def test_duplicate_response_denied(self):
        self.check_block(m=meta(changed_files=2), f=files() + files(), reason="DUPLICATE")

    def test_malformed_response_denied(self):
        self.check_block(m=[], reason="INVALID_REST_PAYLOAD")
        self.check_block(f=[None], reason="FILE_METADATA_INVALID")

    def test_invalid_expected_sha_denied(self):
        with self.assertRaisesRegex(mod.Blocked, "BAD_EXACT_SHA"):
            mod.assess(meta(), files(), pr=PR, head="bad", base=BASE)


if __name__ == "__main__":
    unittest.main()
