import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/ci/local-ci.sh"


class LocalCiRunnerTests(unittest.TestCase):
    def test_help_documents_full_quick_and_push_modes(self):
        result = subprocess.run(
            ["bash", str(RUNNER), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--quick", result.stdout)
        self.assertIn("--push", result.stdout)
        self.assertIn("Does not create commits or force-push", result.stdout)

    def test_quick_profile_cannot_push(self):
        result = subprocess.run(
            ["bash", str(RUNNER), "--quick", "--push"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot be combined with --quick", result.stderr)
        self.assertNotIn("Pushing tested commit", result.stdout)

    def test_push_mode_only_targets_a_non_default_topic_branch(self):
        script = RUNNER.read_text(encoding="utf-8")
        self.assertIn('gh repo view --json defaultBranchRef', script)
        self.assertIn('"$BRANCH" == "$DEFAULT_BRANCH"', script)
        self.assertIn("non-default", script)
        self.assertNotIn('"$BRANCH" != arena/*', script)

    def test_remote_watch_uses_gh_run_list_supported_fields(self):
        script = RUNNER.read_text(encoding="utf-8")
        self.assertIn('--workflow ci.yml --branch "$BRANCH" --limit 100', script)
        self.assertIn("--json databaseId,event,headSha", script)
        self.assertNotIn('--commit "$HEAD_BEFORE"', script)
        self.assertLess(
            script.index("run_step validate-spdx-3"),
            script.index("git push --set-upstream"),
        )
        self.assertNotIn("git commit", script)
        self.assertNotIn("git push --force", script)

    def test_posix_scripts_and_cargo_lock_are_checked_out_with_lf(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("*.sh text eol=lf", attributes)
        self.assertIn("Cargo.lock text eol=lf", attributes)
        for text_file in (
            ROOT / "tools/ci/local-ci.sh",
            ROOT / "tools/ci/audit-deps.sh",
            ROOT / "Cargo.lock",
        ):
            with self.subTest(path=text_file.relative_to(ROOT)):
                self.assertNotIn(b"\r\n", text_file.read_bytes())

    def test_lock_audit_extracts_names_from_crlf_files(self):
        audit = (ROOT / "tools/ci/audit-deps.sh").read_text(encoding="utf-8")
        self.assertIn("tr -d '\\015'", audit)
        result = subprocess.run(
            [
                "sh",
                "-c",
                "printf 'name = \"aead\"\\r\\n' | tr -d '\\015' | sed 's/^name = \"\\(.*\\)\"$/\\1/'",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stdout.strip(), "aead")

    def test_ci_workflow_exposes_manual_dispatch(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^  workflow_dispatch:\s*$")

    def test_push_ci_covers_new_topic_branches(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r'(?m)^    branches: \["\*\*"\]$')


if __name__ == "__main__":
    unittest.main()
