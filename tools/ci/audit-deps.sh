#!/bin/sh
# Balancify dependency + crypto policy audit.
#
# Implements the CI test the blueprint promises for criteria C2/C4 (§11.5):
# "Dependency audit in CI (SBOM diff) every release" and ADR-0002's "PassThrough
# crypto is banned from shipped builds by audit".
#
# It is deliberately first-party shell: the audit must not itself introduce the
# third-party tooling it is checking for. Run from the repository root.

set -eu
cd "$(dirname "$0")/../.."

fail=0
note() { printf '  %s\n' "$1"; }
bad() { printf '  POLICY VIOLATION: %s\n' "$1"; fail=1; }

echo "1/6  runtime dependencies are first-party, or vetted and exactly pinned"
# Only [dependencies] and [build-dependencies] are runtime/build inputs of the
# shipped product. [dev-dependencies] are lab/test tooling, which §4.8 treats as
# build-time and therefore external by necessity.
#
# A non-path dependency is a policy exception (§4.8 rule c, ADR-0006): it must be
# on the allowlist AND carry an exact "=x.y.z" pin - either inline or in
# [workspace.dependencies] when the crate inherits it - so a build can never
# silently pick up a new upstream release.
ALLOWLIST=tools/ci/crypto-allowlist.txt
ALLOW_NAMES=$(sed 's/[[:space:]]*#.*$//' "$ALLOWLIST" | sed 's/[[:space:]]//g' | grep -v '^$')
WS_PINNED=$(awk '
    /^\[workspace\.dependencies\]/ { f = 1; next }
    /^\[/ { f = 0 }
    f && /version[[:space:]]*=[[:space:]]*"=/ { split($0, a, "="); gsub(/[[:space:]]/, "", a[1]); print a[1] }
' Cargo.toml)

for manifest in $(find crates -name Cargo.toml | sort); do
    names=$(awk '
        /^[[:space:]]*\[/ { section = $0; next }
        /^[[:space:]]*#/ { next }
        section ~ /^\[(dependencies|build-dependencies)\]/ && /=/ && $0 !~ /path[[:space:]]*=/ {
            split($0, kv, "="); gsub(/[[:space:]]/, "", kv[1]); print kv[1]
        }
    ' "$manifest")
    for name in $names; do
        if ! printf '%s\n' "$ALLOW_NAMES" | grep -qx "$name"; then
            bad "$manifest declares a dependency that is not on $ALLOWLIST: $name"
            continue
        fi
        decl=$(grep "^$name[[:space:]]*=" "$manifest")
        if printf '%s\n' "$decl" | grep -q 'workspace[[:space:]]*=[[:space:]]*true'; then
            if ! printf '%s\n' "$WS_PINNED" | grep -qx "$name"; then
                bad "$name is inherited from [workspace.dependencies] but is not pinned exactly there"
            fi
        elif ! printf '%s\n' "$decl" | grep -q 'version[[:space:]]*=[[:space:]]*"='; then
            bad "$manifest must pin $name exactly (\"=x.y.z\"): $decl"
        fi
    done
done
[ "$fail" -eq 0 ] && note "every non-path dependency is allowlisted and exactly pinned"

echo "2/6  the lock file resolves nothing that is not allowlisted"
# POSIX sh only: this script must not depend on bash.
ALLOW_NAMES=$(sed 's/[[:space:]]*#.*$//' "$ALLOWLIST" | sed 's/[[:space:]]//g' | grep -v '^$')
if [ -f Cargo.lock ]; then
    unknown=0
    for name in $(grep '^name = ' Cargo.lock | tr -d '\015' | sed 's/^name = "\(.*\)"$/\1/' | sort -u); do
        case "$name" in balancify-*) continue ;; esac   # workspace members
        if printf '%s\n' "$ALLOW_NAMES" | grep -qx "$name"; then continue; fi
        bad "Cargo.lock contains a package that is neither a workspace member nor allowlisted: $name"
        unknown=1
    done
    [ "$unknown" -eq 0 ] && note "every locked package is a workspace member or on the allowlist"
else
    note "no Cargo.lock committed yet; regenerate the allowlist with 'cargo tree' once a toolchain is available"
fi

echo "3/6  the null cipher cannot reach a shipped build (ADR-0002)"
TUNNEL=crates/tunnel/src/lib.rs
GATE='cfg(any(test, feature = "lab-crypto"))'
for symbol in "pub struct PassThrough" "impl Crypto for PassThrough"; do
    if ! grep -B2 -F "$symbol" "$TUNNEL" | grep -qF "$GATE"; then
        bad "'$symbol' in $TUNNEL is not gated behind $GATE"
    fi
done
# Any other crate may name it only from a test-gated file (a lab rig or a test
# suite), never from code that a release build compiles.
for src in $(grep -rl "PassThrough" crates --include=*.rs | sort); do
    [ "$src" = "$TUNNEL" ] && continue
    case "$src" in
        */tests/*) continue ;; # cargo compiles tests/ only for test targets
    esac
    if ! grep -q "#\[cfg(test)\]" "$src"; then
        bad "$src uses PassThrough but has no #[cfg(test)] gate"
    fi
done
[ "$fail" -eq 0 ] && note "PassThrough is compiled only for tests / the lab-crypto feature"

echo "4/6  the lab relay cannot be started in the clear"
if ! grep -q 'not(feature = "lab-crypto")' crates/relay/src/main.rs; then
    bad "crates/relay/src/main.rs has no refusal path for builds without a cipher"
else
    note "a release build of balancify-relay refuses to start (exit 2)"
fi

echo "5/6  driver control access and injected-packet lifetime are guarded"
IOCTL=driver/src/ioctl.c
if grep -Eq 'FILE_ANY_ACCESS|SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R' "$IOCTL"; then
    bad "$IOCTL contains world-accessible device permissions or FILE_ANY_ACCESS"
fi
if ! grep -Fq 'RtlInitUnicodeString(&deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)")' "$IOCTL"; then
    bad "$IOCTL must grant control-device access only to SYSTEM and Administrators"
fi
for operation in SET_MTU INJECT_NBL SET_QUANTA; do
    if ! grep -q "#define IOCTL_BALANCIFY_${operation} .*FILE_WRITE_ACCESS" "$IOCTL"; then
        bad "$IOCTL must require FILE_WRITE_ACCESS for ${operation}"
    fi
done
if ! grep -q '#define IOCTL_BALANCIFY_GET_STATS .*FILE_READ_ACCESS' "$IOCTL"; then
    bad "$IOCTL must require FILE_READ_ACCESS for GET_STATS"
fi
if ! grep -Fq 'NdisMoveMemory(packetCopy, inputBuffer, inputBufferLength)' "$IOCTL"; then
    bad "$IOCTL must copy METHOD_BUFFERED input before indicating an NBL"
fi
if grep -Fq 'NdisAllocateMdl(adapter->miniportAdapterHandle, inputBuffer' "$IOCTL"; then
    bad "$IOCTL must not let an indicated NBL reference the short-lived request buffer"
fi
if ! grep -Fq 'NdisFreeMemory(context->packetBuffer, context->packetLength, 0)' driver/src/miniport.c; then
    bad "MiniportReturnNetBufferLists must release each owned injected packet copy"
fi
[ "$fail" -eq 0 ] && note "privileged ACL, operation access bits, and deferred packet-buffer ownership are enforced"

echo "6/6  Windows key storage defaults to DPAPI and uses private atomic files"
if ! grep -Fq 'default = ["dpapi"]' crates/crypto/Cargo.toml; then
    bad "crates/crypto/Cargo.toml must enable DPAPI by default for Windows consumers"
fi
if ! grep -Fq 'options.write(true).create_new(true)' crates/crypto/src/store.rs; then
    bad "key-store temporary files must use create_new to refuse pre-existing paths"
fi
if ! grep -Fq 'options.mode(0o600)' crates/crypto/src/store.rs; then
    bad "Unix key-store temporary files must be private at creation"
fi
if ! grep -Fq 'fn CryptProtectData' crates/crypto/src/store.rs || ! grep -Fq 'fn CryptUnprotectData' crates/crypto/src/store.rs; then
    bad "Windows DPAPI protect/unprotect entry points must remain implemented"
fi
if ! grep -Fq 'Zeroizing::new(keypair.secret_bytes())' crates/crypto/src/store.rs || ! grep -Fq 'data.zeroize();' crates/crypto/src/store.rs; then
    bad "temporary key copies must be zeroized after use"
fi
[ "$fail" -eq 0 ] && note "DPAPI is enabled by default; key files use create_new, Unix 0600, atomic rename, and zeroized plaintext copies"

if [ "$fail" -ne 0 ]; then
    echo
    echo "policy audit FAILED - see docs/decisions/ADR-0002-dependency-policy.md"
    exit 1
fi
echo
echo "policy audit passed"
