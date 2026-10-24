# BalanciFy CLI Cheat Sheet — Windows 11 x64

Windows PowerShell is the primary local workflow for this Windows NDIS/WDF project; **WSL/Linux is not required**. The codebase combines a Rust 2021 workspace, a Windows C/WDK driver, Python test/SBOM helpers, Git Bash scripts, and GitHub Actions. There is no `package.json`, Docker/Compose workflow, production WinUI GUI, or ML training pipeline.

The native Windows runner uses MSVC for portable driver C fixtures and covers Rust, Python, SBOM, and WDK builds. GitHub Actions runs a native MSVC quick-check job plus Ubuntu 24.04 validation of the Bash entrypoint used inside WSL2; hosted Ubuntu validates WSL-compatible userland, not the WSL kernel itself. Linux CI also runs Rust and ASan/UBSan C tests. Build success does not equal driver install/runtime/hardware acceptance.

## 1. Development & setup

### Install and verify Windows tools

Use Developer PowerShell for Visual Studio 2022 for `cl.exe`/`msbuild.exe`. Required for local validation: Rust stable `x86_64-pc-windows-msvc`, Python `py -3` (3.10+), Git for Windows (Git Bash), Visual Studio 2022 C++ tools, and WDK 10.0.26100.6584/SDK 10.0.26100.0 for driver builds. GitHub CLI is optional unless you want push/PR automation.

If WinGet installed the Rust bootstrapper but `rustup` isn't on `PATH`, run `rustup-init.exe` once:

```powershell
winget install --id Rustlang.Rustup --exact
$rustupInit = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet" -Filter rustup-init.exe -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $rustupInit) { throw 'rustup-init.exe not found under WinGet.' }
& $rustupInit -y --default-toolchain stable --profile minimal
```

Reopen Developer PowerShell, then:

```powershell
rustup toolchain install stable --profile minimal
rustup component add rustfmt clippy --toolchain stable
rustc -vV       # verify host: x86_64-pc-windows-msvc
cargo --version
py -3 --version
git --version
gh --version
```

Configure GitHub CLI and Git once:

```powershell
gh auth login
gh auth setup-git
gh auth status
git remote -v
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

Full setup, WDK requirements, logs, and PR flow: [`local-development-and-ci.md`](local-development-and-ci.md).

### Fetch dependencies and inspect workspace

Run in the repository root:

```powershell
cargo fetch --locked                               # fetch the committed Rust dependency graph
cargo metadata --locked --format-version 1         # inspect package/workspace metadata
cargo tree --locked                                # inspect dependencies
```

Dependency policy audit uses a POSIX shell script supplied by Git for Windows; the native runner resolves Git Bash and runs it for you:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1 -Quick
```

### Local runtime configuration

Use a private absolute state directory and do not share development keys:

```powershell
$env:BALANCIFY_STATE_DIR = "$env:LOCALAPPDATA\BalanciFy\dev"
$env:BALANCIFY_IPC_PORT = '5000'                       # loopback-only local IPC
$env:BALANCIFY_RELAY_PUBLIC_KEY = '<64 hex characters>' # pinned relay public identity
$env:BALANCIFY_FORWARD_ADDR = '127.0.0.1:8080'         # optional relay UDP forwarding
$env:BALANCIFY_PER_FLOW = '1'                           # optional client lab toggle
$env:BALANCIFY_SIMULATE_ECN = '1'                       # optional relay ECN simulation
```

### Inspect CLI help and launch local lab components

```powershell
cargo run -p balancify-service -- --help
cargo run -p balancify-client -- --help
cargo run -p balancify-installer -- --help
cargo run -p balancify-app -- 127.0.0.1:5000 home
cargo run -p balancify-app -- 127.0.0.1:5000 diagnostics
```

For a disposable local lab, use separate PowerShell windows. **The `lab-crypto` relay has no confidentiality and binds UDP on `0.0.0.0`; isolate/firewall it and never use it for sensitive/production traffic.** `--insecure-lab` is debug-only and loopback-only.

```powershell
# Window 1: lab-only relay
cargo run -p balancify-relay --features lab-crypto -- 4430,4431

# Window 2: loopback service, with a private state directory
$env:BALANCIFY_STATE_DIR = "$env:LOCALAPPDATA\BalanciFy\lab"
New-Item -ItemType Directory -Force $env:BALANCIFY_STATE_DIR | Out-Null
cargo run -p balancify-service -- --insecure-lab --simulate-app-traffic 127.0.0.1:4430

# Window 3: lab shell CLI over loopback IPC
cargo run -p balancify-app -- 127.0.0.1:5000 home
```

The app is a lab IPC client, not the planned production GUI. The service uses loopback TCP IPC for local testing, not the production ACL-protected named pipe.

## 2. Build processes

### Rust workspace

```powershell
cargo check --workspace
cargo build --workspace
cargo build --release --workspace
cargo build -p balancify-service --bin balancify-service
cargo build -p balancify-relay --features lab-crypto # isolated lab only; no confidentiality
```

Run a selected binary:

```powershell
cargo run -p balancify-service -- --help
cargo run -p balancify-client -- --help
cargo run -p balancify-installer -- --dry-run --journal "$env:TEMP\balancify-install-journal.json"
```

The installer command exercises prototype journal/dry-run logic; it is not a production installer and does not install the kernel driver or GUI.

### Windows driver build

From Developer PowerShell with the VS 2022 C++ workload and WDK installed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-wdk-build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-wdk-build.ps1 -Architecture x64
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-wdk-build.ps1 -Architecture ARM64
```

The helper builds unsigned x64/ARM64 binaries and checks PE architecture, mitigation flags, and empty certificate tables. Outputs/logs are under `target\local-wdk\`. It does not sign, install, or load the driver.

### Software harnesses

```powershell
cargo run -p balancify-service --bin throughput --release # synthetic service-path work, not network throughput
cargo run -p balancify-service --bin soak --release       # simulated harness, not a real 72-hour soak
cargo run -p balancify-service --bin compat --release     # software scenarios, not a Windows compatibility matrix

```

The static Pages site is built/deployed by `.github/workflows/static.yml`, not by the Windows application build.

Harness output is synthetic/software evidence only; it does not demonstrate real network performance or driver behavior.

## 3. Testing & debugging

### Native Windows validation

```powershell
# Quick: policy, Python, shell-safety, and MSVC portable C/OID tests
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1 -Quick

# Full: quick checks + Windows Rust test/release build + SPDX + x64/ARM64 WDK
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1

# Native Windows portable C/OID contracts only
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\test-driver-packets.ps1
```

The MSVC C fixtures use strict warnings. They are not sanitizer-instrumented on Windows; the remote Ubuntu CI job runs the same portable tests under ASan/UBSan.

### Rust and Python tests

```powershell
cargo test --workspace --all-targets --no-fail-fast
cargo test -p balancify-service
cargo test -p balancify-installer installer_cli_dry_run
cargo test -p balancify-service -- --nocapture
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
py -3 -m unittest discover -s tools\lab -p 'test_*.py' -v
py -3 -m unittest discover -s tools\ci -p 'test_*.py' -v
py -3 -m unittest discover -s driver\tests -p 'test_*.py' -v
```

`cargo fmt` and `clippy` are optional local checks; they do not replace the checked-in CI workflow.

### Errors, logs, and driver artifact inspection

```powershell
$env:RUST_BACKTRACE = '1'
cargo test --workspace --all-targets --no-fail-fast
py -3 tools\ci\verify_driver_pe.py target\local-wdk\x64\balancify.sys x64
py -3 tools\ci\verify_driver_pe.py target\local-wdk\ARM64\balancify.sys ARM64
```

PowerShell runner transcripts are stored under `target\local-ci-windows\logs\<UTC timestamp>\`. WDK build diagnostics are under `target\local-wdk\`. No repository-wide `RUST_LOG` logger configuration is defined.

## 4. Deployment & maintenance

### Dependency and SBOM checks

```powershell
py -3 tools\ci\sbom.py 0.1.0
py -3 tools\ci\sbom_v3.py 0.1.0
```

The full Windows runner creates an isolated validator venv under ignored `target\local-ci-windows\` and validates SPDX 2.3 and 3.0.1. Generated SBOMs are ignored build artifacts; the repository does not fabricate VEX claims.

### Push only after local success

Commit intended changes first on a clean non-default topic branch. The native PowerShell runner pushes only after full local validation and waits for push CI:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\local-ci-windows.ps1 -Push
```

### Create a PR and optionally merge after all gates pass

```powershell
# Run full Windows validation, push, create/reuse PR, wait for push + PR CI; leave open:
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\pr-workflow.ps1

# Same gates, then merge with a merge commit (explicit opt-in):
powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\pr-workflow.ps1 -Merge
```

The workflow requires a clean committed topic branch and an authenticated `gh`. It never stages/commits or force-pushes. `-Merge` is opt-in; the PR only merges after local validation, push-triggered CI, PR-triggered CI, PR check statuses, and an unchanged tested head commit. Branch protection/approvals still apply.

Manual GitHub Actions commands:

```powershell
gh workflow list
gh run list --workflow ci.yml --branch (git branch --show-current)
gh run watch RUN_ID --exit-status --interval 20
gh run view RUN_ID
gh pr checks PR_NUMBER --watch
gh pr view PR_NUMBER
```

Static Pages deploy is separate and runs from `main` or manual dispatch. There is no container build/deploy command in this repository.

### Lab network testing (not part of Windows local CI)

`tools/lab/netem-rig.sh` is a Linux `tc`/iperf3 lab runner. Windows local CI runs only its safe syntax/dry-run tests through Git Bash. Live `--apply` requires a dedicated Linux lab host, root, a running iperf3 server, and explicit confirmation; shaped profiles replace root qdiscs and do not restore prior custom qdiscs. Never run against a production/shared network.

## Project acceptance limits

All local and GitHub checks are software/build checks. Driver products are unsigned. Driver signing/attestation, test-signed installation, Driver Verifier, HVCI/VBS runtime, real NDIS packet-path behavior, clean-machine install/rollback, netem/Rig B measurements, and hardware acceptance remain pending until executed and evidenced on the designated Windows VM/hardware.
