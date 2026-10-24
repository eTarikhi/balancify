#!/usr/bin/env bash
# Run BalanciFy's reproducible Ubuntu CI checks locally; optionally push the
# already-committed branch after local validation and watch its GitHub Actions run.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PROFILE=full
PUSH_AFTER_PASS=0

usage() {
    cat <<'EOF'
Usage: tools/ci/local-ci.sh [--quick] [--push] [--help]

  (default)  Run the Ubuntu CI-equivalent policy, Python, netem-safety, C,
             Rust, release-build, and SPDX checks. WDK builds are Windows-only
             and remain covered by the remote x64/ARM64 jobs.
  --quick    Run policy, Python, safety, and portable-C checks only. Does not
             build Rust/SBOM and cannot be combined with --push.
  --push     Run the full local suite, require a clean committed non-default
             branch, push that tested HEAD to origin, then wait for remote CI.
             Does not create commits or force-push. If remote CI fails, the
             commit remains pushed and the script exits nonzero.
EOF
}

while (($#)); do
    case "$1" in
        --quick) PROFILE=quick ;;
        --push) PUSH_AFTER_PASS=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ "$PUSH_AFTER_PASS" == 1 && "$PROFILE" != full ]]; then
    echo "--push requires the full CI profile; it cannot be combined with --quick." >&2
    exit 2
fi

if [[ "$(uname -s)" != Linux ]]; then
    cat >&2 <<'EOF'
This runner intentionally targets Ubuntu 24.04 / WSL2 Ubuntu 24.04, matching
.github/workflows/ci.yml. Run it inside WSL2 on Windows. Native WDK builds are
available separately with: pwsh -File tools/ci/local-wdk-build.ps1
EOF
    exit 2
fi

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Required command not found: $1" >&2
        exit 2
    fi
}

need python3
need sh
need bash
need cc
need git
if [[ "$PROFILE" == full ]]; then
    need cargo
    need rustc
fi
if [[ "$PUSH_AFTER_PASS" == 1 ]]; then
    need gh
    need timeout
fi

python_version="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
python_major="${python_version%%.*}"
python_minor="${python_version#*.}"
if ((python_major < 3 || (python_major == 3 && python_minor < 10))); then
    echo "Python 3.10+ is required (CI uses Python 3.12); found $python_version." >&2
    exit 2
fi

BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
HEAD_BEFORE="$(git rev-parse HEAD)"
if [[ "$PUSH_AFTER_PASS" == 1 ]]; then
    if [[ -z "$BRANCH" ]]; then
        echo "--push requires a named topic branch; detached HEAD is not allowed." >&2
        exit 2
    fi
    if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        echo "--push requires a clean worktree. Commit intended changes first; this script never stages or commits files." >&2
        exit 2
    fi
    if ! git remote get-url origin >/dev/null 2>&1; then
        echo "Git remote 'origin' is not configured." >&2
        exit 2
    fi
    if ! gh auth status >/dev/null 2>&1; then
        echo "GitHub CLI is not authenticated. Run 'gh auth login' before --push." >&2
        exit 2
    fi
    DEFAULT_BRANCH="$(gh repo view --json defaultBranchRef --jq '.defaultBranchRef.name')"
    if [[ -z "$DEFAULT_BRANCH" || "$BRANCH" == "$DEFAULT_BRANCH" ]]; then
        echo "--push is restricted to a named topic branch, not the default branch '${DEFAULT_BRANCH:-unknown}'." >&2
        exit 2
    fi
    # Refuse a push that would overwrite remote-only work; normal git push is
    # also non-force and remains the final safety check.
    if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
        git fetch --quiet origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"
        if ! git merge-base --is-ancestor "origin/$BRANCH" "$HEAD_BEFORE"; then
            echo "Local HEAD does not contain origin/$BRANCH. Integrate remote changes before pushing." >&2
            exit 2
        fi
    fi
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="$ROOT/target/local-ci/logs/$STAMP"
mkdir -p "$LOG_DIR"

run_step() {
    local name="$1"
    shift
    local log="$LOG_DIR/$name.log"
    printf '\n===== %s =====\n' "$name"
    printf 'Command:'
    printf ' %q' "$@"
    printf '\nLog: %s\n' "$log"
    if "$@" 2>&1 | tee "$log"; then
        printf 'PASS  %s\n' "$name" | tee -a "$LOG_DIR/summary.txt"
    else
        local status=$?
        printf 'FAIL  %s (exit %s)\nLog: %s\n' "$name" "$status" "$log" | tee -a "$LOG_DIR/summary.txt" >&2
        echo "Local CI stopped at '$name'; later steps were not run." >&2
        exit "$status"
    fi
}

printf 'BalanciFy local CI · profile=%s · branch=%s · HEAD=%s\n' \
    "$PROFILE" "${BRANCH:-detached}" "$HEAD_BEFORE" | tee "$LOG_DIR/summary.txt"
printf 'Logs: %s\n' "$LOG_DIR"

run_step dependency-policy sh tools/ci/audit-deps.sh
run_step lab-python-tests python3 -m unittest discover -s tools/lab -p 'test_*.py' -v
run_step ci-python-tests python3 -m unittest discover -s tools/ci -p 'test_*.py' -v
run_step netem-syntax-and-safety bash -c 'sh -n tools/lab/netem-rig.sh && sh tools/lab/test_netem_rig.sh'
run_step portable-driver-tests sh tools/ci/test-driver-packets.sh

if [[ "$PROFILE" == full ]]; then
    run_step rust-workspace-tests cargo test --workspace --all-targets --no-fail-fast
    run_step rust-release-build cargo build --release --workspace

    VENV="$ROOT/target/local-ci/venv"
    if [[ ! -x "$VENV/bin/python" ]]; then
        run_step python-venv python3 -m venv "$VENV"
    fi
    run_step spdx-validator-install "$VENV/bin/python" -m pip install --disable-pip-version-check --no-input spdx-tools==0.8.5 spdx3-validate==0.0.7
    run_step generate-spdx-2 sh tools/ci/sbom.sh 0.1.0
    run_step validate-spdx-2 "$VENV/bin/python" -m spdx_tools.spdx.clitools.pyspdxtools --infile sbom.spdx.json
    run_step generate-spdx-3 "$VENV/bin/python" tools/ci/sbom_v3.py 0.1.0
    run_step validate-spdx-3 "$VENV/bin/python" tools/ci/validate_spdx3.py sbom.spdx3.json
else
    printf 'SKIP  Rust, release build, and SPDX validation (quick profile)\n' | tee -a "$LOG_DIR/summary.txt"
fi

if [[ "$PUSH_AFTER_PASS" == 1 ]]; then
    if [[ "$(git rev-parse HEAD)" != "$HEAD_BEFORE" || -n "$(git status --porcelain --untracked-files=all)" ]]; then
        echo "Repository state changed during validation; refusing to push." >&2
        exit 1
    fi
    echo "Local gates passed. Pushing tested commit $HEAD_BEFORE to origin/$BRANCH."
    git push --set-upstream origin "HEAD:refs/heads/$BRANCH"

    echo "Waiting for GitHub Actions CI for $HEAD_BEFORE. A remote failure will not undo the push."
    run_id=""
    for attempt in $(seq 1 120); do
        run_id="$(gh run list --workflow ci.yml --branch "$BRANCH" --limit 100 \
            --json databaseId,event,headSha --jq "[.[] | select(.event == \"push\" and .headSha == \"$HEAD_BEFORE\")][0].databaseId // empty")"
        [[ -n "$run_id" ]] && break
        sleep 5
    done
    if [[ -z "$run_id" ]]; then
        echo "Pushed successfully, but no CI run appeared within 10 minutes. Check: gh run list --branch '$BRANCH'." >&2
        exit 1
    fi
    run_step remote-ci-watch timeout "${LOCAL_CI_REMOTE_TIMEOUT_SECONDS:-5400}" gh run watch "$run_id" --exit-status --interval 20
    gh run view "$run_id" --json url --jq '.url' | tee "$LOG_DIR/remote-run-url.txt"
fi

printf '\nLocal CI passed. Summary: %s\n' "$LOG_DIR/summary.txt"
if [[ "$PUSH_AFTER_PASS" == 1 ]]; then
    printf 'Push and remote CI passed for %s.\n' "$HEAD_BEFORE"
fi
