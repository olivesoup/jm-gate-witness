"""Native static security oracle for every GitHub Actions workflow.

Checks true YAML parsing with Ruby Psych (standard Ubuntu hosted runner), and
runs bash -n on EVERY embedded bash run block. No user code is executed here.
"""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1] / ".github" / "workflows"
EXPECTED = {
    "jm-public-hash-attest.yml": {
        "Sigstore OIDC attest PUBLIC bootstrap claim only",
        "Verify synthetic attestation via Sigstore identity and public timestamp",
        "Publish exact public synthetic claim for external independent verification",
        "Report attestation reference as NON-REAL-GATE evidence",
    },
    "jm-public-hash-verify.yml": {
        "Authenticate exact protected master signer run from live API",
        "Download exact signed PUBLIC synthetic claim from signer run",
        "Independently verify public Fulcio/Rekor identity and signed timestamp",
    },
    "jm-witness-policy.yml": {
        "Public canonicalizer source checks",
        "Parse solo-operator policy migration without executing it",
    },
    "jm-witness-protected-oracle.yml": {
        "Classify untrusted PR metadata as data ONLY",
    },
}
STEP = re.compile(r"^      - name: (.+)$")
RUN = re.compile(r"^        run: \|\s*$")


def run_blocks(text):
    """Extract YAML block-scalar 'run: |' scripts without interpreting YAML."""
    lines = text.splitlines()
    blocks = []
    current_step = ""
    for i, line in enumerate(lines):
        hit = STEP.match(line)
        if hit:
            current_step = hit.group(1)
        if not RUN.match(line):
            continue
        script = []
        for later in lines[i + 1:]:
            if later and not later.startswith(" " * 10):
                break
            script.append(later[10:] if later.startswith(" " * 10) else "")
        blocks.append((current_step, "\n".join(script) + "\n"))
    return blocks


class WorkflowStructureChecks(unittest.TestCase):
    def test_every_file_is_parsed_by_real_yaml_parser(self):
        self.assertTrue(shutil.which("ruby"), "GitHub Ubuntu needs Ruby Psych YAML parser")
        self.assertEqual({p.name for p in ROOT.glob("*.yml")}, set(EXPECTED))
        for path in ROOT.glob("*.yml"):
            with self.subTest(path=path.name):
                result = subprocess.run(
                    ["ruby", "-ryaml", "-e",
                     "v=YAML.parse_file(ARGV.fetch(0)); abort('EMPTY_YAML') if v.nil?",
                     str(path)],
                    text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_bash_run_block_syntax(self):
        self.assertTrue(shutil.which("bash"))
        for path in ROOT.glob("*.yml"):
            raw = path.read_text(encoding="utf-8")
            for name, script in run_blocks(raw):
                with self.subTest(workflow=path.name, step=name):
                    self.assertNotIn("        run: |", script)
                    self.assertNotIn("        shell: bash", script)
                    if "shell: pwsh" in raw and name.startswith("Parse solo-operator"):
                        continue
                    result = subprocess.run(["bash", "-n"], input=script,
                                            text=True, capture_output=True,
                                            timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater(len(run_blocks(raw)), 0)

    def test_required_step_boundaries_are_distinct(self):
        for filename, names in EXPECTED.items():
            raw = (ROOT / filename).read_text(encoding="utf-8")
            found = STEP.findall(raw)
            with self.subTest(filename=filename):
                self.assertEqual(len(found), len(set(found)), "Duplicate step")
                self.assertTrue(names <= set(found), "Lost YAML step boundary")
                self.assertFalse(re.search(r"grep -Eq '[^']*$", raw, re.M))

    def test_signer_and_separate_verifier_explicitly_never_host_gate(self):
        for filename in ("jm-public-hash-attest.yml", "jm-public-hash-verify.yml"):
            content = (ROOT / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn("JM_", content)
                self.assertNotIn("REAL_GATE_PASS", content)
                self.assertNotIn("pull_request_target:", content)

    def test_fixture_detects_exact_historical_broken_shell(self):
        broken = """set -euo pipefail
echo "$GITHUB_SHA" | grep -Eq '^[0-9a-f]{40}        shell: bash
env:
  TOKEN: unsafe
"""
        result = subprocess.run(["bash", "-n"], input=broken,
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
