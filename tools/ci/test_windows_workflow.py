import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOWS_RUNNER = (ROOT / "tools/ci/local-ci-windows.ps1").read_text(encoding="utf-8")
WINDOWS_PR = (ROOT / "tools/ci/pr-workflow.ps1").read_text(encoding="utf-8")
WINDOWS_C_TESTS = (ROOT / "tools/ci/test-driver-packets.ps1").read_text(encoding="utf-8")
DRIVER_PREFLIGHT = (ROOT / "tools/ci/inspect-driver-device.ps1").read_text(encoding="utf-8")
DRIVER_IOCTL_SOURCE = (ROOT / "driver/src/ioctl.c").read_text(encoding="utf-8")


class WindowsWorkflowTests(unittest.TestCase):
    def test_native_runner_explains_missing_msvc_compiler(self):
        self.assertIn('MSVC cl.exe was not found. Open Developer PowerShell', WINDOWS_RUNNER)
        self.assertIn('Desktop development with C++ workload', WINDOWS_RUNNER)

    def test_native_runner_targets_msvc_and_windows_rust_and_wdk(self):
        self.assertIn('x86_64-pc-windows-msvc', WINDOWS_RUNNER)
        self.assertIn("Invoke-NativeChecked 'cargo' @('test', '--workspace', '--all-targets', '--no-fail-fast')", WINDOWS_RUNNER)
        self.assertIn("Invoke-NativeChecked 'cargo' @('build', '--release', '--workspace')", WINDOWS_RUNNER)
        self.assertIn("local-wdk-build.ps1", WINDOWS_RUNNER)
        self.assertIn("test-driver-packets.ps1", WINDOWS_RUNNER)
        self.assertIn("spdx-tools==0.8.5", WINDOWS_RUNNER)
        self.assertIn("spdx3-validate==0.0.7", WINDOWS_RUNNER)

    def test_gh_is_only_required_for_push_and_pr_uses_delimited_interpolation(self):
        self.assertIn("if ($Push) { Require-Command 'gh' }", WINDOWS_RUNNER)
        pr_script = WINDOWS_PR
        self.assertIn('PR #${prNumber}:', pr_script)
        self.assertIn('GitHub CLI (gh) is required for PR automation.', pr_script)

    def test_native_c_tests_use_msvc_and_existing_portable_fixtures(self):
        for source in (
            "test_ip_packet_validation.c",
            "test_mtu_config.c",
            "test_rx_pause_state.c",
            "test_tx_packet_queue.c",
        ):
            self.assertIn(source, WINDOWS_C_TESTS)
        self.assertIn("cl.exe", WINDOWS_C_TESTS)
        self.assertIn("/W4", WINDOWS_C_TESTS)
        self.assertIn("test_oid_contract.py", WINDOWS_C_TESTS)

    def test_pr_merge_follows_local_and_remote_gates_and_pins_head(self):
        self.assertIn("local-ci-windows.ps1", WINDOWS_PR)
        self.assertIn("Wait-GitHubRun -Branch $branch -Sha $testedHead -Event pull_request", WINDOWS_PR)
        self.assertIn("pr', 'checks'", WINDOWS_PR)
        self.assertIn("'--merge', '--match-head-commit', $testedHead", WINDOWS_PR)
        self.assertNotIn("--auto", WINDOWS_PR)
        self.assertLess(
            WINDOWS_PR.index("local-ci-windows.ps1"),
            WINDOWS_PR.index("'pr', 'create'"),
        )
        self.assertLess(
            WINDOWS_PR.index("pr', 'checks'"),
            WINDOWS_PR.index("'pr', 'merge'"),
        )

    def test_driver_device_preflight_is_read_only_and_emits_runtime_evidence(self):
        self.assertIn("$ioctlGetStats = 0x00126004", DRIVER_PREFLIGHT)
        self.assertIn("#define IOCTL_BALANCIFY_GET_STATS CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)", DRIVER_IOCTL_SOURCE)
        self.assertIn(r"$devicePath = '\\.\Balancify'", DRIVER_PREFLIGHT)
        self.assertIn("[uint32]0x80000000, # GENERIC_READ", DRIVER_PREFLIGHT)
        self.assertIn("$statsSize = 48", DRIVER_PREFLIGHT)
        self.assertIn("[DllImport(\"kernel32.dll\", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]", DRIVER_PREFLIGHT)
        self.assertIn("[Out] byte[] outputBuffer", DRIVER_PREFLIGHT)
        self.assertIn("GET_STATS (read-only)", DRIVER_PREFLIGHT)
        self.assertIn("no packet was injected or dequeued", DRIVER_PREFLIGHT)
        self.assertIn(r"$outputDirectory = Join-Path $repoRoot 'target\local-wdk\runtime-checks'", DRIVER_PREFLIGHT)
        self.assertNotIn("IOCTL_BALANCIFY_INJECT_NBL", DRIVER_PREFLIGHT)
        self.assertNotIn("IOCTL_BALANCIFY_DEQUEUE_TX", DRIVER_PREFLIGHT)
        self.assertNotIn("0x0012a008", DRIVER_PREFLIGHT.lower())
        self.assertNotIn("0x00126010", DRIVER_PREFLIGHT.lower())

    def test_docs_make_native_windows_the_primary_workflow(self):
        guide = (ROOT / "docs/local-development-and-ci.md").read_text(encoding="utf-8")
        driver_guide = (ROOT / "driver/README.md").read_text(encoding="utf-8")
        self.assertIn("WSL/Linux is not required", guide)
        self.assertIn("local-ci-windows.ps1", guide)
        self.assertIn("pr-workflow.ps1 -Merge", guide)
        self.assertIn("inspect-driver-device.ps1", driver_guide)


if __name__ == "__main__":
    unittest.main()
