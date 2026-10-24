import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "tools/ci/pr-workflow.sh"


class PrWorkflowTests(unittest.TestCase):
    def test_help_describes_validation_pr_and_opt_in_merge(self):
        result = subprocess.run(
            ["bash", str(WORKFLOW), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--merge", result.stdout)
        self.assertIn("leave the PR open", result.stdout)
        self.assertIn("local software CI suite", result.stdout)

    def test_unknown_option_fails_before_side_effects(self):
        result = subprocess.run(
            ["bash", str(WORKFLOW), "--force"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown option", result.stderr)
        self.assertNotIn("Pushing tested commit", result.stdout)

    def test_gates_precede_create_and_merge_and_no_force_push_or_auto_merge(self):
        script = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('bash tools/ci/local-ci.sh --push', script)
        self.assertIn('gh pr create --base main --head "$BRANCH" --fill', script)
        self.assertIn('gh run watch "$run_id" --exit-status --interval 20', script)
        self.assertIn('gh pr checks "$pr_number" --watch --interval 20', script)
        self.assertIn('gh pr merge "$pr_number" --merge --match-head-commit "$TESTED_HEAD"', script)
        self.assertNotIn('gh pr merge "$pr_number" --auto', script)
        self.assertNotIn('git push --force', script)
        self.assertLess(
            script.index('bash tools/ci/local-ci.sh --push'),
            script.index('gh pr create --base main'),
        )
        self.assertLess(
            script.index('gh pr checks "$pr_number" --watch'),
            script.index('gh pr merge "$pr_number" --merge'),
        )
        self.assertLess(
            script.index('gh pr view "$pr_number" --json headRefOid'),
            script.rindex('gh pr merge "$pr_number" --merge'),
        )


if __name__ == "__main__":
    unittest.main()
