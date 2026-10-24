[CmdletBinding()]
param(
    [switch]$Quick,
    [switch]$Push,
    [switch]$SkipWdk
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot

if ($Quick -and $Push) {
    throw '-Quick cannot be combined with -Push.'
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    Write-Host (">> {0} {1}" -f $Command, ($Arguments -join ' '))
    & $Command @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Command failed with exit code ${code}: $Command $($Arguments -join ' ')"
    }
}

function Get-NativeText {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = & $Command @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Command failed with exit code ${code}: $Command $($Arguments -join ' ')`n$($output | Out-String)"
    }
    return (($output | Out-String).Trim())
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    Write-Host "`n===== $Name =====" -ForegroundColor Cyan
    & $Action
    Write-Host "PASS  $Name" -ForegroundColor Green
}

function Wait-GitHubRun {
    param(
        [Parameter(Mandatory = $true)][string]$Branch,
        [Parameter(Mandatory = $true)][string]$Sha,
        [Parameter(Mandatory = $true)][ValidateSet('push', 'pull_request')][string]$Event
    )
    $runId = ''
    $jq = "[.[] | select(.event == `"$Event`" and .headSha == `"$Sha`")][0].databaseId // empty"
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $runId = Get-NativeText 'gh' @(
            'run', 'list', '--workflow', 'ci.yml', '--branch', $Branch, '--limit', '100',
            '--json', 'databaseId,event,headSha', '--jq', $jq
        )
        if ($runId) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $runId) {
        throw "No $Event CI run appeared for $Sha within 10 minutes. Check gh run list --branch '$Branch'."
    }

    Write-Host "Watching GitHub Actions run $runId ($Event, $Sha)."
    $ghPath = (Get-Command gh.exe -ErrorAction Stop).Source
    $watch = Start-Process -FilePath $ghPath -ArgumentList @(
        'run', 'watch', $runId, '--exit-status', '--interval', '20'
    ) -NoNewWindow -PassThru
    $timeoutSeconds = 5400
    if ($env:LOCAL_CI_REMOTE_TIMEOUT_SECONDS) {
        $timeoutSeconds = [int]$env:LOCAL_CI_REMOTE_TIMEOUT_SECONDS
    }
    if (-not $watch.WaitForExit($timeoutSeconds * 1000)) {
        $watch.Kill()
        throw "GitHub Actions run $runId exceeded the ${timeoutSeconds}s timeout."
    }
    if ($watch.ExitCode -ne 0) {
        throw "GitHub Actions run $runId failed (exit $($watch.ExitCode))."
    }
}

Require-Command 'py'
Require-Command 'git'
if ($Push) { Require-Command 'gh' }
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw 'MSVC cl.exe was not found. Open Developer PowerShell for Visual Studio 2022. If it is not installed, add the Desktop development with C++ workload (MSVC v143 x64/x86 tools).'
}
if (-not $Quick) {
    Require-Command 'cargo'
    Require-Command 'rustc'
    if (-not $SkipWdk) { Require-Command 'msbuild' }
}

$bashCommand = Get-Command bash.exe -ErrorAction SilentlyContinue
if (-not $bashCommand) {
    $gitBashCandidates = @(
        @(
            (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe')
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
    )
    if ($gitBashCandidates) {
        $bashPath = $gitBashCandidates[0]
    } else {
        throw 'Git Bash was not found. Install Git for Windows and ensure bash.exe is available.'
    }
} else {
    $bashPath = $bashCommand.Source
}
$bashDirectory = Split-Path -Parent $bashPath
if ($env:PATH -notlike "*$bashDirectory*") {
    $env:PATH = "$bashDirectory;$env:PATH"
}

$pythonVersion = Get-NativeText 'py' @('-3', '-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
$pythonParts = $pythonVersion -split '\.'
if ([int]$pythonParts[0] -lt 3 -or ([int]$pythonParts[0] -eq 3 -and [int]$pythonParts[1] -lt 10)) {
    throw "Python 3.10+ is required; found $pythonVersion."
}
if (-not $Quick) {
    $rustInfo = Get-NativeText 'rustc' @('-vV')
    if ($rustInfo -notmatch '(?m)^host:\s+x86_64-pc-windows-msvc\s*$') {
        throw 'Install the x86_64-pc-windows-msvc Rust toolchain for native Windows builds.'
    }
}

$branch = Get-NativeText 'git' @('branch', '--show-current')
$testedHead = Get-NativeText 'git' @('rev-parse', 'HEAD')
$defaultBranch = ''
if ($Push) {
    if (-not $branch) { throw '-Push requires a named topic branch; detached HEAD is not allowed.' }
    $worktree = Get-NativeText 'git' @('status', '--porcelain', '--untracked-files=all')
    if ($worktree) { throw '-Push requires a clean worktree. Commit changes first; this script does not stage or commit.' }
    $null = Get-NativeText 'git' @('remote', 'get-url', 'origin')
    Invoke-NativeChecked 'gh' @('auth', 'status')
    $defaultBranch = Get-NativeText 'gh' @('repo', 'view', '--json', 'defaultBranchRef', '--jq', '.defaultBranchRef.name')
    if (-not $defaultBranch -or $branch -eq $defaultBranch) {
        throw "-Push is allowed only from a non-default topic branch (default branch: '$defaultBranch')."
    }

    $remoteRefs = & git ls-remote --exit-code --heads origin $branch 2>&1
    $lsRemoteCode = $LASTEXITCODE
    if ($lsRemoteCode -eq 0) {
        Invoke-NativeChecked 'git' @('fetch', '--quiet', 'origin', "+refs/heads/${branch}:refs/remotes/origin/${branch}")
        & git merge-base --is-ancestor "origin/$branch" $testedHead
        if ($LASTEXITCODE -ne 0) {
            throw "Local HEAD does not contain origin/$branch. Integrate remote changes before pushing."
        }
    } elseif ($lsRemoteCode -ne 2) {
        throw "git ls-remote failed (exit $lsRemoteCode): $($remoteRefs | Out-String)"
    }
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$logDirectory = Join-Path $repoRoot "target\local-ci-windows\logs\$stamp"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$transcriptPath = Join-Path $logDirectory 'transcript.txt'
Start-Transcript -Path $transcriptPath -Force | Out-Null
try {
    Write-Host "BalanciFy native Windows CI · branch=$branch · HEAD=$testedHead"
    Write-Host "Logs: $logDirectory"

    Invoke-Step 'dependency-policy' {
        Invoke-NativeChecked $bashPath @('--noprofile', '--norc', '-c', 'sh tools/ci/audit-deps.sh')
    }
    Invoke-Step 'lab-python-tests' {
        Invoke-NativeChecked 'py' @('-3', '-m', 'unittest', 'discover', '-s', 'tools/lab', '-p', 'test_*.py', '-v')
    }
    Invoke-Step 'ci-python-tests' {
        Invoke-NativeChecked 'py' @('-3', '-m', 'unittest', 'discover', '-s', 'tools/ci', '-p', 'test_*.py', '-v')
    }
    Invoke-Step 'netem-syntax-and-safety' {
        Invoke-NativeChecked $bashPath @('--noprofile', '--norc', '-c', 'sh -n tools/lab/netem-rig.sh && sh tools/lab/test_netem_rig.sh')
    }
    Invoke-Step 'portable-driver-tests-msvc' {
        & (Join-Path $PSScriptRoot 'test-driver-packets.ps1')
    }

    if (-not $Quick) {
        Invoke-Step 'rust-workspace-tests' {
            Invoke-NativeChecked 'cargo' @('test', '--workspace', '--all-targets', '--no-fail-fast')
        }
        Invoke-Step 'rust-release-build' {
            Invoke-NativeChecked 'cargo' @('build', '--release', '--workspace')
        }

        $venv = Join-Path $repoRoot 'target\local-ci-windows\venv'
        $venvPython = Join-Path $venv 'Scripts\python.exe'
        if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            Invoke-Step 'python-venv' {
                Invoke-NativeChecked 'py' @('-3', '-m', 'venv', $venv)
            }
        }
        Invoke-Step 'spdx-validator-install' {
            Invoke-NativeChecked $venvPython @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', 'spdx-tools==0.8.5', 'spdx3-validate==0.0.7')
        }
        Invoke-Step 'generate-spdx-2' {
            Invoke-NativeChecked 'py' @('-3', 'tools/ci/sbom.py', '0.1.0')
        }
        Invoke-Step 'validate-spdx-2' {
            Invoke-NativeChecked $venvPython @('-m', 'spdx_tools.spdx.clitools.pyspdxtools', '--infile', 'sbom.spdx.json')
        }
        Invoke-Step 'generate-spdx-3' {
            Invoke-NativeChecked $venvPython @('tools/ci/sbom_v3.py', '0.1.0')
        }
        Invoke-Step 'validate-spdx-3' {
            Invoke-NativeChecked $venvPython @('tools/ci/validate_spdx3.py', 'sbom.spdx3.json')
        }
        if (-not $SkipWdk) {
            Invoke-Step 'wdk-x64-arm64-build-and-pe-check' {
                & (Join-Path $PSScriptRoot 'local-wdk-build.ps1')
            }
        } else {
            Write-Host 'SKIP  WDK build (-SkipWdk); remote Windows CI still gates the PR.'
        }
    } else {
        Write-Host 'SKIP  Rust, release build, SPDX validators, and WDK build (-Quick).'
    }

    if ($Push) {
        if ((Get-NativeText 'git' @('rev-parse', 'HEAD')) -ne $testedHead -or
            (Get-NativeText 'git' @('status', '--porcelain', '--untracked-files=all'))) {
            throw 'Repository state changed during validation; refusing to push.'
        }
        Invoke-Step 'push-tested-head' {
            Invoke-NativeChecked 'git' @('push', '--set-upstream', 'origin', "HEAD:refs/heads/$branch")
        }
        Wait-GitHubRun -Branch $branch -Sha $testedHead -Event push
    }

    Write-Host "Native Windows local validation passed. Summary transcript: $transcriptPath"
} finally {
    Stop-Transcript | Out-Null
}
