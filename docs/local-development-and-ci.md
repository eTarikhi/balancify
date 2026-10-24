# Native Windows 11 development, CI, and PR workflow

This repository contains a Windows NDIS/WDF driver and Rust workspace. **Windows 11 x64 with PowerShell is the recommended local development environment; WSL/Linux is not required.** The native runner uses the MSVC Rust toolchain, runs the Windows Rust test/build, compiles the portable C contract tests with MSVC, validates SBOMs on Windows, and can build both WDK architectures. Git Bash is used only for existing POSIX policy/netem scripts. GitHub Actions remains the independent Linux/Windows CI gate.

## 1. Project and CI overview

- Rust 2021 workspace: control plane, tunnel/crypto, IPC, service, relay, client, lab shell CLI, installer.
- Windows driver: first-party C NDIS/WDF source in `driver/`, built using MSBuild and the WDK.
- Tooling: Python test/SBOM helpers, POSIX shell policy and lab scripts, PowerShell WDK/native-Windows runner.
- GitHub Actions (`.github/workflows/ci.yml`): dependency audit; Linux and Windows Rust tests; native x64 MSVC quick checks (including portable driver C/OID tests); WSL-compatible Ubuntu 24.04 quick validation; release build and SPDX validation; Windows x64 and ARM64 WDK builds and PE checks.
- The WSL parity job runs the same Bash quick-validation entrypoint and Ubuntu 24.04 userland used inside WSL2. GitHub-hosted Ubuntu is not itself a WSL VM, so this validates the Linux/WSL userland path rather than WSL-kernel integration.
- The static Pages deploy workflow is separate and publishes from `main`.
- No Docker/Compose workflow or ML training scripts are present. The app shell is a lab CLI, not the planned production WinUI GUI.

The local Windows runner covers the Windows-native work, but it does not replicate Linux AddressSanitizer/UndefinedBehaviorSanitizer instrumentation. The remote Linux job still runs those instrumented portable C tests. No local or remote build proves driver signing, installation, runtime packet flow, HVCI, or hardware acceptance.

## 2. Windows 11 x64 prerequisites

Use **Developer PowerShell for Visual Studio 2022** so `cl.exe` and `msbuild.exe` are available. A regular Administrator PowerShell window does not automatically configure the MSVC toolchain; launching `powershell.exe` from it will not add `cl.exe` to PATH.

- Rust stable for `x86_64-pc-windows-msvc`, including Cargo. Install `rustfmt` and `clippy` if desired.
- Visual Studio 2022 / Build Tools 17.x with the C++ build tools.
- Windows SDK/WDK target 10.0.26100.0 and WDK 10.0.26100.6584 (the CI pin), including x64 and ARM64 libraries.
- Python 3.10+ via the Windows `py -3` launcher (CI uses Python 3.12).
- Git for Windows (provides `bash.exe`, `sh`, `sed`, `awk`, `grep`, and `find` for the POSIX policy and dry-run lab scripts).
- GitHub CLI (`gh`) and a configured `origin` are needed only for push/PR automation; local-only validation does not require `gh` or GitHub authentication.
- Network access on the first Cargo/Python dependency fetch and SPDX validator install.

### Install/activate Rust on Windows

If `winget install --id Rustlang.Rustup --exact` reports success but `rustup` is still not recognized, run the installed bootstrapper. WinGet may install `rustup-init.exe` without installing the toolchain or updating the current shell's PATH:

```powershell
winget install --id Rustlang.Rustup --exact
$rustupInit = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet" -Filter rustup-init.exe -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $rustupInit) { throw 'rustup-init.exe was not found under the WinGet package directory.' }
& $rustupInit -y --default-toolchain stable --profile minimal
```

Close and reopen Developer PowerShell, then verify/install the toolchain:

```powershell
rustup toolchain install stable --profile minimal
rustup component add rustfmt clippy --toolchain stable
rustc -vV   # host should be x86_64-pc-windows-msvc
cargo --version
```

If the command is still missing in the current shell, add Cargo's bin directory for that session and check again:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
rustup --version
```

The driver build requires the VS C++ workload and WDK in addition to Rust. The WDK helper builds unsigned files only.

### Configure GitHub CLI

Run these in PowerShell (or the native Developer PowerShell):

```powershell
gh auth login
gh auth setup-git
gh auth status
git remote -v
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

Keep credentials in Git/`gh` secure credential storage, not in scripts or repository files.

## 3. Native local validation

Run all commands from the repository root in Developer PowerShell. Before starting, confirm the compiler is available there:

```powershell
Get-Command cl.exe
cl.exe /Bv
```

If `cl.exe` is missing, install/modify Visual Studio 2022 or Build Tools and select **Desktop development with C++** plus the MSVC v143 x64/x86 tools. Then close the regular PowerShell window and launch **Developer PowerShell for VS 2022** from the Start menu. If script execution policy blocks local scripts, use `-ExecutionPolicy Bypass` for that invocation.

### Fast checks

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1 -Quick
```

Quick mode checks dependency policy, Python suites, netem script syntax/safety, and the portable C/OID contracts compiled with MSVC. It does not build Rust, generate SBOMs, or build the WDK driver; it cannot push.

### Full Windows-native suite

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1
```

The full profile performs:

1. Dependency/crypto policy audit using Git Bash.
2. Python lab and CI unit tests.
3. Netem dry-run/safety checks (no live traffic is generated).
4. Portable packet/queue/OID C contract tests compiled and run natively with MSVC.
5. `cargo test --workspace --all-targets --no-fail-fast` using native Windows Rust.
6. `cargo build --release --workspace`.
7. SPDX 2.3 and 3.0.1 generation and validation using an isolated Python venv under ignored `target/local-ci-windows/`. SPDX 3.0.1 checks use `tools/ci/validate_spdx3.py`, which inspects the validator result and fails closed even if the third-party CLI emits schema errors with a zero exit code.
8. x64 and ARM64 WDK build and PE verification with `tools/ci/local-wdk-build.ps1`.

To skip the local WDK build temporarily (remote CI still runs it):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1 -SkipWdk
```

Logs are captured under `target/local-ci-windows/logs/<UTC timestamp>/`. WDK artifacts and logs are under `target/local-wdk/`. The C fixture tests run with strict MSVC warnings on Windows; ASan/UBSan coverage is provided by the remote Ubuntu workflow.

### Individual Windows build/test commands

```powershell
cargo fetch --locked                                      # fetch locked Rust dependencies
cargo test --workspace --all-targets --no-fail-fast       # run all workspace tests on Windows
cargo build --release --workspace                         # optimized Windows workspace build
powershell -ExecutionPolicy Bypass -File tools\ci\test-driver-packets.ps1
powershell -ExecutionPolicy Bypass -File tools\ci\local-wdk-build.ps1
powershell -ExecutionPolicy Bypass -File tools\ci\local-wdk-build.ps1 -Architecture x64
powershell -ExecutionPolicy Bypass -File tools\ci\local-wdk-build.ps1 -Architecture ARM64
```

The WDK helper checks architecture, required mitigation flags, and unsigned status. It does not sign, install, or load the driver.

## 4. Push after validation and automate PR creation

Commit changes on a clean topic branch first. `local-ci-windows.ps1 -Push` runs the full Windows-native suite, checks that the branch is not the repository default branch and that local history contains the remote tip, pushes the exact tested commit without force, then waits for push-triggered GitHub CI:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1 -Push
```

The end-to-end PR orchestrator does the same local validation/push, creates or reuses an open PR targeting `main`, waits for push CI and PR CI, and checks the PR head still matches the validated SHA:

```powershell
# Validate, push, create/reuse PR, and wait for CI; leave the PR open.
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\pr-workflow.ps1

# Same gates, then merge using a merge commit (explicit opt-in).
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\pr-workflow.ps1 -Merge
```

`-Merge` is opt-in; without it the PR remains open. The workflow does not stage or create commits, force-push, or use GitHub auto-merge. It only merges after local validation, push-triggered CI, PR-triggered CI, PR check statuses, and an unchanged validated head SHA. GitHub branch protections still apply. A PR submission runs push CI and PR CI separately, so the remote suite runs twice for that commit.

Manual GitHub commands remain available:

```powershell
gh workflow list
gh run list --workflow ci.yml --branch (git branch --show-current)
gh run watch RUN_ID --exit-status --interval 20
gh pr checks PR_NUMBER --watch
gh pr view PR_NUMBER
```

## 5. Development, debugging, and limits

```powershell
$env:RUST_BACKTRACE = '1'
cargo test --workspace --all-targets --no-fail-fast
py -3 -m unittest discover -s tools\ci -p 'test_*.py' -v
```

Rust panic backtraces are enabled with `RUST_BACKTRACE=1`; repository-wide `RUST_LOG` configuration is not defined. Inspect the PowerShell transcript and per-step output under `target/local-ci-windows/logs/`; WDK build logs are under `target/local-wdk/`.

A passing local or GitHub build does **not** establish signed installation, Driver Verifier, HVCI/VBS runtime, NDIS packet-path behavior, real netem/Rig B throughput, clean-machine install/rollback, or hardware acceptance. Treat those as pending until exercised and evidenced on the designated Windows VM/hardware. The relay's `lab-crypto` mode has no confidentiality and must only be used in an isolated lab. `tools/lab/netem-rig.sh --apply` remains a separately gated Linux lab operation; the Windows local CI runner only runs its safe syntax/dry-run checks.

## 6. Optional Linux parity runner

The older Bash runner is optional and is not required for Windows development. It can still be used by Linux contributors for the Linux-specific ASan/UBSan C fixtures:

```sh
bash tools/ci/local-ci.sh --quick
bash tools/ci/local-ci.sh
bash tools/ci/local-ci.sh --push
```

The Windows-native runner is the recommended path for Windows 11 developers; GitHub Actions remains the cross-platform source of truth for required Linux and Windows jobs.
