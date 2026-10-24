# ADR-0040: Bounded miniport TX queue and service polling

- **Status:** Accepted
- **Date:** 2026-10-23
- **Scope:** source-level reverse direction from NDIS send callbacks to the service. This does not claim an installed-driver or end-to-end runtime path.

## Context

BalanciFy advertises a raw-IP NDIS miniport (`NdisMediumIP`). The service can inject received tunnel packets into NDIS through `IOCTL_BALANCIFY_INJECT_NBL`, but the opposite direction was missing: NDIS calls `MiniportSendNetBufferLists` with OS-originated packets, and the service had no bounded way to retrieve them. Completing send NBLs successfully without retaining their payload would silently drop traffic; retaining arbitrary caller-owned NBL memory beyond the callback would violate ownership and lifetime constraints.

## Decision

Implement a driver-owned bounded FIFO and a privileged pull IOCTL:

- Keep 64 packet slots in nonpaged adapter context; each slot holds at most the configured MTU (bounded to 9000 bytes). The storage is volatile and fixed-capacity.
- `MiniportSendNetBufferLists` counts and size-checks all NBs in each NBL, reserves enough capacity for the entire batch, copies each NB through `NdisGetDataBuffer` into driver-owned storage, and validates the resulting complete raw IPv4/IPv6 packet. The lock protects producer/consumer state. The queue count advances only after the full NBL batch is copied and validated, so the service never observes a partially published NBL.
- Successful NDIS completion means the packet batch was accepted into the queue. A full queue completes with `NDIS_STATUS_RESOURCES`; malformed packets fail; packets received while paused complete with `NDIS_STATUS_PAUSED`.
- `IOCTL_BALANCIFY_DEQUEUE_TX` (`FILE_READ_ACCESS`, `METHOD_BUFFERED`, function `0x804`) returns at most one record: a 16-byte little-endian header (`version: u32`, `packet_length: u32`, `sequence: u64`) followed by the raw IP packet. An empty poll returns `STATUS_SUCCESS` with zero output bytes. A short caller buffer does not dequeue anything.
- The Rust client opens the control device with read/write access, bounds-checks the output record, revalidates its IP payload, and the service polls at 10 ms intervals before passing packets through `Service::send_ip_packet`. The service retains one dequeued packet and retries it before reading later packets whenever scheduling returns `Hold` or `Refused`.
- The kernel queue and user-mode pending slot are volatile and do not survive adapter removal or service restart. There is no durable retry, explicit queue-ready notification, or reverse TX completion mechanism from relay delivery to NDIS.

## Consequences

- The service data-path source now has both directions: tunnel-delivered packets can be injected into NDIS, and NDIS send packets can be copied out to the service for tunnel ingress.
- The portable queue tests verify capacity, atomic batch visibility, FIFO ordering and wraparound. Windows CI compiles/links x64 and ARM64 driver artifacts; Rust CI tests IOCTL encoding and record parsing.
- No test-signed installation, Driver Verifier, HVCI, device IOCTL execution, NDIS steering test, or end-to-end packet-path acceptance has been performed. G2 remains open until these runtime gates have recorded results.
