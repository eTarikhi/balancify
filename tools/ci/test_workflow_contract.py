import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class WorkflowContractTests(unittest.TestCase):
    def test_linux_workflows_use_a_pinned_runner_image(self):
        workflows = [
            ROOT / ".github/workflows/ci.yml",
            ROOT / ".github/workflows/static.yml",
        ]
        for workflow in workflows:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                self.assertNotIn("runs-on: ubuntu-latest", text)
                self.assertIn("runs-on: ubuntu-24.04", text)

    def test_pages_actions_use_exact_node24_compatible_releases(self):
        text = (ROOT / ".github/workflows/static.yml").read_text(encoding="utf-8")
        expected = {
            "actions/checkout": "v7.0.1",
            "actions/configure-pages": "v6.0.0",
            "actions/upload-pages-artifact": "v5.0.0",
            "actions/deploy-pages": "v5.0.1",
        }
        for action, version in expected.items():
            with self.subTest(action=action):
                self.assertRegex(text, rf"uses:\s+{re.escape(action)}@{re.escape(version)}\b")

    def test_ci_runs_native_msvc_and_wsl_compatible_entrypoints(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("msvc-native-checks:", workflow)
        msvc_job = workflow.split("msvc-native-checks:", 1)[1].split("core-tests-windows:", 1)[0]
        self.assertIn("runs-on: windows-2022", msvc_job)
        self.assertIn("Microsoft.VisualStudio.Component.VC.Tools.x86.x64", msvc_job)
        self.assertIn("VsDevCmd.bat", msvc_job)
        self.assertIn("local-ci-windows.ps1", msvc_job)
        self.assertIn("-Quick", msvc_job)
        self.assertIn("wsl-parity:", workflow)
        wsl_job = workflow.split("wsl-parity:", 1)[1].split("core-tests-linux:", 1)[0]
        self.assertIn("runs-on: ubuntu-24.04", wsl_job)
        self.assertIn("bash tools/ci/local-ci.sh --quick", wsl_job)
        self.assertIn("not a WSL VM", workflow)

    def test_spdx3_validation_uses_fail_closed_result_wrapper(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        linux_runner = (ROOT / "tools/ci/local-ci.sh").read_text(encoding="utf-8")
        windows_runner = (ROOT / "tools/ci/local-ci-windows.ps1").read_text(encoding="utf-8")
        for source in (workflow, linux_runner, windows_runner):
            with self.subTest(source=source[:40]):
                self.assertIn("tools/ci/validate_spdx3.py", source)
                self.assertNotIn("-m spdx3_validate", source)

    def test_wdk_build_job_pins_tooling_and_builds_x64_driver(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("driver-build-x64:", workflow)
        self.assertIn("runs-on: windows-2022", workflow)
        self.assertIn("version: 10.0.26100.6584", workflow)
        self.assertIn("vs-version: '[17.0,18.0)'", workflow)
        self.assertRegex(
            workflow,
            r"uses:\s+microsoft/windows-drivers-rs/\.github/actions/install-wdk@c4ae6815484398dc9d28fbe97e6c02d44f9f49a8\b",
        )
        self.assertIn("driver\\balancify.vcxproj", workflow)
        self.assertIn("/p:SignMode=Off", workflow)
        self.assertIn("name: balancify-driver-unsigned-x64", workflow)
        self.assertIn("path: driver/x64/Release/balancify.sys", workflow)
        self.assertIn("py -3 tools/ci/verify_driver_pe.py driver/x64/Release/balancify.sys x64", workflow)
        self.assertIn("py -3 tools/ci/verify_driver_pe.py driver/ARM64/Release/balancify.sys ARM64", workflow)
        x64_job = workflow.split("driver-build-x64:", 1)[1].split("driver-build-arm64:", 1)[0]
        self.assertIn("Start-Process -FilePath 'msbuild'", x64_job)
        self.assertIn("-RedirectStandardOutput $stdout -RedirectStandardError $stderr", x64_job)
        project = (ROOT / "driver/balancify.vcxproj").read_text(encoding="utf-8")
        self.assertIn("<WindowsTargetPlatformVersion>10.0.26100.0</WindowsTargetPlatformVersion>", project)
        self.assertIn("<AdditionalOptions>/W4 /WX /Qspectre %(AdditionalOptions)</AdditionalOptions>", project)
        self.assertIn("/integritycheck /DYNAMICBASE /NXCOMPAT", project)
        linker = re.search(r"<Link>.*?</Link>", project, re.S)
        self.assertIsNotNone(linker)
        self.assertNotIn("/Qspectre", linker.group(0))
        self.assertNotIn("$(DDK_LIB_PATH)\\wdf", project)
        self.assertIn("driver-build-arm64:", workflow)
        arm64_job = workflow.split("driver-build-arm64:", 1)[1].split("# Still pending:", 1)[0]
        self.assertIn("name: WDK driver build (ARM64)", arm64_job)
        self.assertIn("target: arm64", arm64_job)
        self.assertIn("/p:Platform=ARM64", arm64_job)
        self.assertIn("name: balancify-driver-unsigned-arm64", arm64_job)
        self.assertIn("Start-Process -FilePath 'msbuild'", arm64_job)
        self.assertIn("-RedirectStandardOutput $stdout -RedirectStandardError $stderr", arm64_job)


if __name__ == "__main__":
    unittest.main()
