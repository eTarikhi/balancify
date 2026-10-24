#!/usr/bin/env bash
# Full local validation -> safe push -> create/reuse PR -> wait for PR CI.
# Merging is explicit opt-in via --merge and only attempted after all checks pass.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

MERGE_AFTER_CHECKS=0
usage() {
    cat <<'EOF'
Usage: tools/ci/pr-workflow.sh [--merge] [--help]

Run the complete local software CI suite, push the tested clean topic-branch HEAD,
create or reuse its open PR targeting main, then wait for push and PR CI.

  (default)  Stop after PR CI succeeds; leave the PR open for review.
  --merge   After all local and remote checks pass, merge the PR with a merge
            commit. The command never uses GitHub auto-merge and never force-pushes.

Requirements: Ubuntu 24.04 / WSL2, Rust/Cargo, Python, C compiler, Git, gh,
and authenticated GitHub CLI. This does not run native WDK or hardware acceptance;
those remain covered by remote Windows CI and separate Windows lab testing.
EOF
}

while (($#)); do
    case "$1" in
        --merge) MERGE_AFTER_CHECKS=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ -z "$BRANCH" || "$BRANCH" == main ]]; then
    echo "PR workflow requires a named topic branch (not main); current branch: ${BRANCH:-detached}." >&2
    exit 2
fi

TESTED_HEAD="$(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "Commit intended changes first; this workflow does not stage or create commits." >&2
    exit 2
fi

# The existing runner enforces the clean worktree, validates the complete local
# software suite, pushes this exact commit, and waits for push-triggered CI.
bash tools/ci/local-ci.sh --push

if [[ "$(git rev-parse HEAD)" != "$TESTED_HEAD" || -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "Repository state changed after local validation; refusing to create/update a PR." >&2
    exit 1
fi

# Reuse an open PR to main for this branch; refuse to silently redirect another PR.
pr_number="$(gh pr list --head "$BRANCH" --state open --json number,baseRefName \
    --jq '[.[] | select(.baseRefName == "main")][0].number // empty')"
if [[ -z "$pr_number" ]]; then
    other_pr="$(gh pr list --head "$BRANCH" --state open --json number,baseRefName \
        --jq '.[0].number // empty')"
    if [[ -n "$other_pr" ]]; then
        echo "Open PR #$other_pr for $BRANCH does not target main; refusing to create another PR." >&2
        exit 1
    fi
    echo "Creating PR from $BRANCH to main."
    gh pr create --base main --head "$BRANCH" --fill
    pr_number="$(gh pr view "$BRANCH" --json number --jq '.number')"
fi

pr_state="$(gh pr view "$pr_number" --json state --jq '.state')"
pr_base="$(gh pr view "$pr_number" --json baseRefName --jq '.baseRefName')"
pr_head="$(gh pr view "$pr_number" --json headRefOid --jq '.headRefOid')"
if [[ "$pr_state" != OPEN || "$pr_base" != main || "$pr_head" != "$TESTED_HEAD" ]]; then
    echo "PR #$pr_number does not match the tested open HEAD targeting main; refusing to continue." >&2
    exit 1
fi

echo "Waiting for pull_request CI for PR #$pr_number at $TESTED_HEAD."
run_id=""
for attempt in $(seq 1 120); do
    run_id="$(gh run list --workflow ci.yml --branch "$BRANCH" --limit 100 \
        --json databaseId,event,headSha \
        --jq "[.[] | select(.event == \"pull_request\" and .headSha == \"$TESTED_HEAD\")][0].databaseId // empty")"
    [[ -n "$run_id" ]] && break
    sleep 5
done
if [[ -z "$run_id" ]]; then
    echo "PR #$pr_number is open, but no pull_request CI run appeared within 10 minutes." >&2
    exit 1
fi

timeout "${LOCAL_CI_REMOTE_TIMEOUT_SECONDS:-5400}" \
    gh run watch "$run_id" --exit-status --interval 20
# Confirm GitHub's PR check view is also green before considering a merge.
gh pr checks "$pr_number" --watch --interval 20

# Re-check the head immediately before any merge; do not merge unvalidated commits.
pr_head="$(gh pr view "$pr_number" --json headRefOid --jq '.headRefOid')"
pr_state="$(gh pr view "$pr_number" --json state --jq '.state')"
if [[ "$pr_head" != "$TESTED_HEAD" || "$pr_state" != OPEN ]]; then
    echo "PR #$pr_number changed or closed after validation; refusing to merge." >&2
    exit 1
fi

echo "Local validation and remote CI passed. PR #$pr_number: https://github.com/$(gh repo view --json nameWithOwner --jq '.nameWithOwner')/pull/$pr_number"
if [[ "$MERGE_AFTER_CHECKS" == 1 ]]; then
    echo "Merging PR #$pr_number with a merge commit."
    gh pr merge "$pr_number" --merge --match-head-commit "$TESTED_HEAD"
else
    echo "PR #$pr_number is validated and ready for review; it was not merged. Re-run with --merge to merge after validation."
fi
