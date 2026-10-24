# Balancify NDIS virtual miniport -- Phase 2 S2b source scaffold

This directory contains first-party NDIS miniport and WDF control-device source for the planned packet path (Sec.4.8, Sec.5, Sec.7). No third-party kernel component is used in the intended data path (C2).

**Status:** source-level scaffold with an opt-in, one-way injection path and bounded reverse TX queue/polling source. `MiniportInitializeEx` submits NDIS registration attributes followed by revision-2 general attributes, reads the `Mtu` adapter parameter with a bounded 1440-byte fallback, configures raw-IP `NdisMediumIP`, publishes its supported OID list, and unwinds resources if initialization fails. Pause waits asynchronously for active receive-indication calls, returned receive NBLs, and active send callback chains before reporting completion. Pinned x64/ARM64 WDK CI confirms compile/link and static artifact checks; no runtime lifecycle, Driver Verifier, HVCI, install, or packet-path validation is claimed. The lab prototype still uses simulated uplinks and bound UDP sockets (S2a); G2 remains open pending test-signed installation and adapter/runtime acceptance.

**Structure:**
- `src/miniport.c` + `src/miniport.h` -- NDIS 6.8 callback source, registration/general attributes, supported OID queries and shared adapter/NBL ownership. `MiniportSendNetBufferLists` validates raw-IP boundaries plus TCP/UDP header lengths using the WDK-independent helper in `src/ip_packet_validation.h` (including exact UDP/IP length agreement for unfragmented packets), reserves space for the entire NBL batch in the fixed 64-packet queue, and publishes the batch only after all records copy and validate. Accepted sends complete successfully after queueing; a full queue returns `NDIS_STATUS_RESOURCES`, invalid batches fail, and paused sends return `NDIS_STATUS_PAUSED`. The pause state machine drains active send/receive callbacks before completion. Runtime behavior remains unvalidated.
- `src/ioctl.c` -- WDF IOCTLs for set MTU, inject NBL, query stats, set quanta, and dequeue TX. `INJECT_NBL` validates raw IPv4/IPv6 lengths and non-fragmented TCP/UDP header boundaries, then retains an owned copy until NDIS returns the NBL. The shared C validator bounds IPv6 extension traversal to 16 headers; checksum validation and reassembly are not implemented. `DEQUEUE_TX` emits a versioned 16-byte header plus one queued raw-IP packet; an empty poll succeeds with zero output bytes. CI compiles/links the source; Driver Verifier and runtime ownership/queue behavior remain unvalidated.
- `src/tx_packet_queue.h` -- WDK-independent bounded FIFO helpers: 64 records, up to 9000 bytes each, atomic batch publication, FIFO dequeue, sequence metadata, and wraparound. Portable C tests cover capacity, atomic visibility, ordering, and wraparound.
- `balancify.inf` -- INF for PnP install, `*IfType = IF_TYPE_PROP_VIRTUAL (53)`, `*MediaType = NdisMediumIP (19)`, and `LowerRange = nolower` for raw IP packets without Ethernet framing.
- `balancify.vcxproj` -- WDK 10.0.26100-compatible build; CI uses the pinned 10.0.26100.6584 NuGet kit for x64 and ARM64.

**Known runtime/product gaps (not closed by the CI build):**
- `IOCTL_BALANCIFY_SET_MTU` accepts a confirmation of the configured MTU, but rejects a different value with `STATUS_NOT_SUPPORTED`. NDIS handles OID_GEN_MAXIMUM_FRAME_SIZE for NDIS 6+ from initialization/restart attributes; this scaffold has no supported runtime reconfiguration path, so it must not mutate only the driver's local view ([Microsoft documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/oid-gen-maximum-frame-size)).
- `IOCTL_BALANCIFY_SET_QUANTA` validates basic request sizing and returns `STATUS_NOT_SUPPORTED`; no scheduler consumes the weights yet, so the driver does not report a false success.
- The TX queue and service-side `DEQUEUE_TX` polling path now exist in source, but the device handle, IOCTL operation, and service-to-relay packet path have not been tested against an installed driver. The service retains one dequeued packet when scheduling returns `Hold` or `Refused`, retries it before reading later packets, and leaves the rest in the kernel queue for backpressure. This pending slot and the kernel queue are bounded and volatile; neither survives a service or adapter restart. End-to-end behavior remains unverified.

**Signing & HVCI:**
- Partner Center enrolment + EV cert ordered in Phase 1 (G1).
- Attestation signing first, HLK only if Server support added (Sec.9.3).
- HVCI readiness trio: Driver Verifier with code-integrity checks, HLK HVCI readiness test, run on VBS/Memory-Integrity machine (Sec.9.5, S15).
- CI generates SPDX 2.3 and SPDX 3.0.1 inventories from `cargo metadata --locked` and validates both; reviewed VEX and clean-machine installer-sidecar verification remain pending (S13).

**Performance targets (G3):**
- Added median delay <= 3 ms wired lab (Sec.10.3)
- CPU per Gbit/s reported, limits set after Spike S2
- Working set bounded

**Security:**
- Minimal IOCTLs, validated lengths, portable C boundary tests for raw IPv4/IPv6 parsing, TCP/UDP headers, IPv6 extensions, queue state, and pause accounting run under strict warnings plus AddressSanitizer/UndefinedBehaviorSanitizer in Ubuntu CI; the parser also processes 12,000 deterministic malformed/near-valid length mutations per test run. This is bounded mutation testing, not kernel fuzzing; Driver Verifier and kernel fuzzing remain pending.
- Memory Integrity compatibility is intended but unverified until WDK/HVCI testing.

**Build (Windows only, WDK 10.0.26100):**
```powershell
# Prerequisites: Visual Studio 2022 with C++ desktop, WDK and SDK 10.0.26100.
# CI uses Microsoft's pinned WDK NuGet package 10.0.26100.6584 for x64 and ARM64.
# From repo root:
msbuild driver\balancify.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild driver\balancify.vcxproj /p:Configuration=Release /p:Platform=ARM64
# Output: x64\Release\balancify.sys, ARM64\Release\balancify.sys
# Sign test:
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f test.pfx /p password x64\Release\balancify.sys
# Verify HVCI flags:
dumpbin /headers x64\Release\balancify.sys | findstr /i "integrity DYNAMICBASE NXCOMPAT"
# Check PoolTag:
strings x64\Release\balancify.sys | findstr BlaB
```

**Test (real VM required):**
- After test-signing and installing the driver, run `powershell -NoProfile -ExecutionPolicy Bypass -File tools\ci\inspect-driver-device.ps1` from the repository root in an elevated PowerShell. This read-only preflight opens the privileged control device, calls `GET_STATS`, and writes OS/device counters to ignored `target/local-wdk/runtime-checks/`; stop the service first because its control-device handle is exclusive. It does not inject or dequeue packets and is not a packet-path acceptance test.
- Hyper-V VM Gen2 Secure Boot on vTPM VBS on, Memory Integrity on/off
- Enable test-signing: `bcdedit /set testsigning on`, reboot
- Install: `pnputil /add-driver driver\balancify.inf /install`
- Driver Verifier: `verifier /standard /driver balancify.sys` flags 0x209BB special pool, force IRQL, pool tracking, I/O verification, deadlock, DMA, security, DDI compliance, code integrity — reboot, `!verifier` in WinDbg, run traffic, no bugchecks
- HLK: Studio -> HVCIMemoryIntegrity test, checks no executable NonPagedPool, no executable MDL, no RWX, no self-modifying — pass criteria no failures
- VBS/MI: `msinfo32` VBS Running MI enabled, driver loaded, traffic via `throughput.rs` + `balancify-service` binary, ETW 200/201/300/400/401/402/500/600 visible via WPA
- S2b (pending): install and bidirectional socket/packet-path test through miniport. `INJECT_NBL` copies service-delivered bytes into an owned NBL; `MiniportSendNetBufferLists` queues OS-originated raw-IP NBs; `DEQUEUE_TX` returns those records for service tunnel ingress. The source is covered by WDK x64/ARM64 builds and portable contract tests only; test signing, Driver Verifier, HVCI, and runtime validation remain outstanding.
- G3 benchmark + HVCI trio documented in `docs/phase2/hvci-readiness.md` with date, Windows build, hardware, driver version

**INF:**
- `driver/balancify.inf` Universal, PnpLockdown=1, NDIS 6.8, MTU param 576..9000 default 1440, WDF verifier, PoolTag BlaB, METHOD_BUFFERED, length validation, attestation signing
- WDF control-device DACL grants access only to SYSTEM and Administrators; GET_STATS and DEQUEUE_TX require `FILE_READ_ACCESS`, while mutating IOCTLs require `FILE_WRITE_ACCESS`. The service opens the device for both read and write. It must run with the required privileged identity; the desktop shell must never open this device directly. WDK build and ACL behavior still require validation on a Windows driver lab machine.
- `driver/miniport.inf` legacy skeleton, use balancify.inf for new builds

**vcxproj:**
- `driver/balancify.vcxproj` HVCI flags /integritycheck /DYNAMICBASE /NXCOMPAT /Qspectre, PoolTag BlaB, Spectre mitigation, KMDF 1.33, Universal, 10.0.26100.0, NDIS680_MINIPORT, NDIS 6.8, WDF

**HVCI readiness trio (S15):**
- Verifier 0x209BB + code integrity, HLK HVCIMemoryIntegrity, VBS/MI VM Secure Boot/vTPM/test-signing remain pending. Push run 39799406998 passed pinned x64 and ARM64 WDK compile/link on `windows-2022` with VS 2022, verified each PE machine type, required DYNAMIC_BASE/FORCE_INTEGRITY/NX_COMPAT flags, and empty certificate table, and passed the INF architecture/version contract tests; it uploaded `balancify-driver-unsigned-x64` and `balancify-driver-unsigned-arm64` as seven-day artifacts. These are unsigned software build artifacts only; no signed install or hardware validation is claimed.

**Exception policy (Sec.11.2):**
If G3/G7 blocked >4 weeks by signing/HVCI, product owner may ship flow-level only with bundled Wintun signed DLL (single allowed third-party runtime artifact, disclosed), while bonding + driver continue; must be retired next minor release.
