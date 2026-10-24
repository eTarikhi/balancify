[CmdletBinding()]
param(
    [switch]$Merge,
    [switch]$SkipWdk
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repoRoot
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI (gh) is required for PR automation. Install it with: winget install --id GitHub.cli --exact'
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

function Wait-GitHubRun {
    param(
        [Parameter(Mandatory = $true)][string]$Branch,
        [Parameter(Mandatory = $true)][string]$Sha,
        [Parameter(Mandatory = $true)][ValidateSet('pull_request')][string]$Event
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

    Write-Host "Watching PR CI run $runId for validated commit $Sha."
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

$branch = Get-NativeText 'git' @('branch', '--show-current')
$testedHead = Get-NativeText 'git' @('rev-parse', 'HEAD')
if (-not $branch -or $branch -eq 'main') {
    throw "Use a named topic branch, not main (current branch: '$branch')."
}
if (Get-NativeText 'git' @('status', '--porcelain', '--untracked-files=all')) {
    throw 'Commit intended changes first; this workflow does not stage or create commits.'
}

$defaultBranch = Get-NativeText 'gh' @('repo', 'view', '--json', 'defaultBranchRef', '--jq', '.defaultBranchRef.name')
if ($defaultBranch -ne 'main') {
    throw "This workflow currently targets main, but the repository default branch is '$defaultBranch'."
}

# Windows-native checks, safe push and push-triggered CI. WDK compile can only
# be skipped explicitly; remote CI still covers x64 and ARM64 WDK builds.
$localCi = Join-Path $PSScriptRoot 'local-ci-windows.ps1'
if ($SkipWdk) {
    & $localCi -Push -SkipWdk
} else {
    & $localCi -Push
}
if ((Get-NativeText 'git' @('rev-parse', 'HEAD')) -ne $testedHead -or
    (Get-NativeText 'git' @('status', '--porcelain', '--untracked-files=all'))) {
    throw 'The tested commit or worktree changed; refusing to create or merge a PR.'
}

$prNumber = Get-NativeText 'gh' @(
    'pr', 'list', '--head', $branch, '--state', 'open', '--json', 'number,baseRefName',
    '--jq', '[.[] | select(.baseRefName == "main")][0].number // empty'
)
if (-not $prNumber) {
    $otherPr = Get-NativeText 'gh' @(
        'pr', 'list', '--head', $branch, '--state', 'open', '--json', 'number,baseRefName',
        '--jq', '.[0].number // empty'
    )
    if ($otherPr) {
        throw "Open PR #$otherPr for $branch does not target main; refusing to create another PR."
    }
    Write-Host "Creating PR from $branch to main."
    Invoke-NativeChecked 'gh' @('pr', 'create', '--base', 'main', '--head', $branch, '--fill')
    $prNumber = Get-NativeText 'gh' @('pr', 'view', $branch, '--json', 'number', '--jq', '.number')
}

$prState = Get-NativeText 'gh' @('pr', 'view', $prNumber, '--json', 'state', '--jq', '.state')
$prBase = Get-NativeText 'gh' @('pr', 'view', $prNumber, '--json', 'baseRefName', '--jq', '.baseRefName')
$prHead = Get-NativeText 'gh' @('pr', 'view', $prNumber, '--json', 'headRefOid', '--jq', '.headRefOid')
if ($prState -ne 'OPEN' -or $prBase -ne 'main' -or $prHead -ne $testedHead) {
    throw "PR #$prNumber does not match the validated open HEAD targeting main; refusing to continue."
}

Wait-GitHubRun -Branch $branch -Sha $testedHead -Event pull_request
$ghPath = (Get-Command gh.exe -ErrorAction Stop).Source
$checks = Start-Process -FilePath $ghPath -ArgumentList @(
    'pr', 'checks', $prNumber, '--watch', '--interval', '20'
) -NoNewWindow -PassThru
$timeoutSeconds = 5400
if ($env:LOCAL_CI_REMOTE_TIMEOUT_SECONDS) {
    $timeoutSeconds = [int]$env:LOCAL_CI_REMOTE_TIMEOUT_SECONDS
}
if (-not $checks.WaitForExit($timeoutSeconds * 1000)) {
    $checks.Kill()
    throw "PR checks exceeded the ${timeoutSeconds}s timeout."
}
if ($checks.ExitCode -ne 0) {
    throw "PR checks failed (exit $($checks.ExitCode)); PR #$prNumber was not merged."
}

$prHead = Get-NativeText 'gh' @('pr', 'view', $prNumber, '--json', 'headRefOid', '--jq', '.headRefOid')
$prState = Get-NativeText 'gh' @('pr', 'view', $prNumber, '--json', 'state', '--jq', '.state')
if ($prHead -ne $testedHead -or $prState -ne 'OPEN') {
    throw "PR #$prNumber changed or closed after validation; refusing to merge."
}

$ownerRepo = Get-NativeText 'gh' @('repo', 'view', '--json', 'nameWithOwner', '--jq', '.nameWithOwner')
Write-Host "Windows local checks and remote CI passed. PR #${prNumber}: https://github.com/$ownerRepo/pull/$prNumber"
if ($Merge) {
    Write-Host "Merging PR #$prNumber with a merge commit."
    Invoke-NativeChecked 'gh' @('pr', 'merge', $prNumber, '--merge', '--match-head-commit', $testedHead)
} else {
    Write-Host "PR #$prNumber is ready for review and remains open. Re-run with -Merge to merge after validation."
}
