"""Regression guard for the solo-founder admin readback contract.

This test never calls gh or mutates GitHub; the live admin operator still verifies
the installed ruleset.  The script is scanned for precheck and readback invariants.
"""
from pathlib import Path
import unittest

SCRIPT = (Path(__file__).resolve().parents[1]
          / "scripts" / "Set-JM-Witness-Solo-Ruleset.ps1")


class AdminReadbackContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")

    def test_idempotent_precheck_includes_stale_dismissal(self):
        pre = self.script.split("if ($pr[0].parameters.required_approving_review_count -eq 0")[0]
        self.assertIn("$pr[0].parameters.dismiss_stale_reviews_on_push -ne $true", pre)

    def test_post_update_readback_is_not_a_noop(self):
        post = self.script.split("$afterRaw = & gh api", 1)[1]
        self.assertIn("SOLO_POLICY_READBACK_MISMATCH", post)
        self.assertIn("$afterPr[0].parameters.dismiss_stale_reviews_on_push -ne $true", post)

    def test_reviewers_and_code_owner_rule_readback(self):
        post = self.script.split("$afterRaw = & gh api", 1)[1]
        self.assertIn("$afterPr[0].parameters.require_code_owner_review -ne $false", post)
        self.assertIn("@($afterPr[0].parameters.required_reviewers).Count -ne 0", post)

    def test_strict_check_cannot_be_skipped_for_new_branch(self):
        post = self.script.split("$afterRaw = & gh api", 1)[1]
        self.assertIn("$afterChecks[0].parameters.do_not_enforce_on_create -eq $true", post)
        self.assertIn("$afterChecks[0].parameters.strict_required_status_checks_policy -ne $true", post)

    def test_rule_target_and_excludes_readback(self):
        post = self.script.split("$afterRaw = & gh api", 1)[1]
        self.assertIn("$after.conditions.ref_name.include[0] -cne '~DEFAULT_BRANCH'", post)
        self.assertIn("@($after.conditions.ref_name.exclude).Count -ne 0", post)

    def test_exact_actions_required_job_still_bound(self):
        post = self.script.split("$afterRaw = & gh api", 1)[1]
        self.assertIn("$afterRequired[0].context -cne $context", post)
        self.assertIn("$afterRequired[0].integration_id -ne $app", post)

    def test_repo_and_ruleset_not_free_text(self):
        self.assertIn("$repo = 'olivesoup/jm-gate-witness'", self.script)
        self.assertIn("$id = 26785842", self.script)

    def test_no_merge_and_no_activation_commands(self):
        for banned in ("gh pr merge", "gh workflow run", "gh api --method DELETE"):
            self.assertNotIn(banned, self.script)


if __name__ == "__main__":
    unittest.main()
