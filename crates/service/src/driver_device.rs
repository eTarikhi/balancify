//! Optional user-mode control-device client for the first-party NDIS miniport.
//!
//! Provides the optional service-to-driver receive direction (`INJECT_NBL`)
//! and dequeues raw IP packets from the driver's bounded TX queue. The queue
//! path is source/CI validated only; an installed-driver runtime remains pending.

use std::io;

use crate::packet::{flow_key_from_packet, MAX_INNER_PACKET_LEN};

const FILE_DEVICE_NETWORK: u32 = 0x12;
const FILE_WRITE_ACCESS: u32 = 0x2;
const METHOD_BUFFERED: u32 = 0;
const IOCTL_FUNCTION_INJECT_NBL: u32 = 0x802;
const IOCTL_FUNCTION_DEQUEUE_TX: u32 = 0x804;
const FILE_READ_ACCESS: u32 = 0x1;
const TX_PACKET_HEADER_LEN: usize = 16;
const TX_PACKET_VERSION: u32 = 1;
#[cfg(windows)]
const TX_PACKET_OUTPUT_LEN: usize = TX_PACKET_HEADER_LEN + MAX_INNER_PACKET_LEN;

/// A dequeued miniport packet must remain in user mode while the service says
/// it is held or has no eligible route. In those cases the driver queue has
/// already popped it, so retrying is required to avoid silently dropping it.
pub fn should_retry_driver_tx(actions: &[super::Action]) -> bool {
    !actions.iter().any(|action| matches!(action, super::Action::Send { .. }))
}

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Control code mirrored from `driver/src/ioctl.c`.
pub const IOCTL_BALANCIFY_INJECT_NBL: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    IOCTL_FUNCTION_INJECT_NBL,
    METHOD_BUFFERED,
    FILE_WRITE_ACCESS,
);

/// Control code mirrored from `driver/src/ioctl.c`.
pub const IOCTL_BALANCIFY_DEQUEUE_TX: u32 = ctl_code(
    FILE_DEVICE_NETWORK,
    IOCTL_FUNCTION_DEQUEUE_TX,
    METHOD_BUFFERED,
    FILE_READ_ACCESS,
);

/// Decode one versioned packet record, validating the entire raw IP payload.
/// An empty buffer is the successful empty-queue response from the driver.
pub fn decode_dequeued_packet(output: &[u8]) -> io::Result<Option<Vec<u8>>> {
    if output.is_empty() {
        return Ok(None);
    }
    if output.len() < TX_PACKET_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DEQUEUE_TX returned a truncated header",
        ));
    }
    let version = u32::from_le_bytes(output[0..4].try_into().expect("fixed header slice"));
    let packet_len = u32::from_le_bytes(output[4..8].try_into().expect("fixed header slice")) as usize;
    if version != TX_PACKET_VERSION || packet_len == 0 || packet_len > MAX_INNER_PACKET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DEQUEUE_TX returned an unsupported version or packet length",
        ));
    }
    let expected_len = TX_PACKET_HEADER_LEN + packet_len;
    if output.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DEQUEUE_TX returned an inconsistent record length",
        ));
    }
    let packet = output[TX_PACKET_HEADER_LEN..].to_vec();
    validate_injection_packet(&packet).map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid queued IP packet: {error}"))
    })?;
    Ok(Some(packet))
}

/// Validate the full packet before making a user-to-kernel transition.
pub fn validate_injection_packet(packet: &[u8]) -> io::Result<()> {
    if packet.is_empty() || packet.len() > MAX_INNER_PACKET_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inner IP packet is empty or exceeds the 9000-byte limit",
        ));
    }
    flow_key_from_packet(packet)
        .map(|_| ())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn DeviceIoControl(
            device: Handle,
            control_code: u32,
            input_buffer: *mut c_void,
            input_buffer_size: u32,
            output_buffer: *mut c_void,
            output_buffer_size: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    pub struct DriverDevice {
        handle: Handle,
    }

    impl DriverDevice {
        pub fn open() -> io::Result<Self> {
            Self::open_path(Path::new(r"\\.\Balancify"))
        }

        fn open_path(path: &Path) -> io::Result<Self> {
            let path: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle })
        }

        pub fn inject_nbl(&self, packet: &[u8]) -> io::Result<()> {
            validate_injection_packet(packet)?;
            let input_len = u32::try_from(packet.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet length overflows Win32 size"))?;
            let mut bytes_returned = 0u32;
            let succeeded = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_BALANCIFY_INJECT_NBL,
                    packet.as_ptr() as *mut c_void,
                    input_len,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };
            if succeeded == 0 {
                return Err(io::Error::last_os_error());
            }
            if bytes_returned != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "INJECT_NBL unexpectedly returned output bytes",
                ));
            }
            Ok(())
        }

        /// Pop one packet from the bounded miniport TX queue; an empty queue
        /// returns `Ok(None)` without blocking the service loop.
        pub fn dequeue_tx(&self) -> io::Result<Option<Vec<u8>>> {
            let mut output = [0u8; TX_PACKET_OUTPUT_LEN];
            let output_len = u32::try_from(output.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TX buffer overflows Win32 size"))?;
            let mut bytes_returned = 0u32;
            let succeeded = unsafe {
                DeviceIoControl(
                    self.handle,
                    IOCTL_BALANCIFY_DEQUEUE_TX,
                    std::ptr::null_mut(),
                    0,
                    output.as_mut_ptr() as *mut c_void,
                    output_len,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };
            if succeeded == 0 {
                return Err(io::Error::last_os_error());
            }
            let bytes_returned = usize::try_from(bytes_returned).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "TX output length overflows usize")
            })?;
            if bytes_returned > output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DEQUEUE_TX returned more bytes than the output buffer",
                ));
            }
            decode_dequeued_packet(&output[..bytes_returned])
        }
    }

    impl Drop for DriverDevice {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub struct DriverDevice;

    impl DriverDevice {
        pub fn open() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the BalanciFy NDIS control device is available only on Windows",
            ))
        }

        pub fn inject_nbl(&self, packet: &[u8]) -> io::Result<()> {
            validate_injection_packet(packet)?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the BalanciFy NDIS control device is available only on Windows",
            ))
        }

        pub fn dequeue_tx(&self) -> io::Result<Option<Vec<u8>>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the BalanciFy NDIS control device is available only on Windows",
            ))
        }
    }
}

pub use platform::DriverDevice;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_tx_retries_when_the_service_did_not_schedule_a_send() {
        use balancify_core::{FlowClass, FlowKey, UplinkId};
        use std::net::SocketAddr;

        let flow = FlowKey::new(
            17,
            "192.0.2.1:1000".parse::<SocketAddr>().unwrap(),
            "192.0.2.2:2000".parse::<SocketAddr>().unwrap(),
        );
        assert!(should_retry_driver_tx(&[]));
        assert!(should_retry_driver_tx(&[super::super::Action::Hold {
            flow: flow.clone(),
            data: vec![1, 2, 3],
        }]));
        assert!(should_retry_driver_tx(&[super::super::Action::Refused {
            flow: flow.clone(),
            class: FlowClass::Bulk,
        }]));
        assert!(!should_retry_driver_tx(&[super::super::Action::Send {
            uplink: UplinkId(0),
            bytes: vec![1, 2, 3],
        }]));
    }

    #[test]
    fn inject_ioctl_matches_the_wdf_control_code_contract() {
        assert_eq!(IOCTL_BALANCIFY_INJECT_NBL, 0x0012_a008);
    }

    #[test]
    fn dequeue_ioctl_matches_the_wdf_control_code_contract() {
        assert_eq!(IOCTL_BALANCIFY_DEQUEUE_TX, 0x0012_6010);
    }

    fn valid_ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet
    }

    fn dequeue_record(packet: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(TX_PACKET_HEADER_LEN + packet.len());
        output.extend_from_slice(&TX_PACKET_VERSION.to_le_bytes());
        output.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        output.extend_from_slice(&1u64.to_le_bytes());
        output.extend_from_slice(packet);
        output
    }

    #[test]
    fn dequeue_decoder_accepts_empty_and_valid_records() {
        assert_eq!(decode_dequeued_packet(&[]).unwrap(), None);
        let packet = valid_ipv4_packet();
        assert_eq!(decode_dequeued_packet(&dequeue_record(&packet)).unwrap(), Some(packet));
    }

    #[test]
    fn dequeue_decoder_rejects_truncated_or_malformed_records() {
        assert_eq!(
            decode_dequeued_packet(&[1, 0, 0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let packet = valid_ipv4_packet();
        let mut record = dequeue_record(&packet);
        record[0] = 2;
        assert_eq!(decode_dequeued_packet(&record).unwrap_err().kind(), io::ErrorKind::InvalidData);
        record = dequeue_record(&packet);
        record[4..8].copy_from_slice(&19u32.to_le_bytes());
        assert_eq!(decode_dequeued_packet(&record).unwrap_err().kind(), io::ErrorKind::InvalidData);
        record = dequeue_record(&[0x45, 0, 0, 20]);
        assert_eq!(decode_dequeued_packet(&record).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn injection_validation_rejects_bad_or_oversized_packets() {
        assert_eq!(
            validate_injection_packet(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            validate_injection_packet(&[0x45, 0, 0, 20]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            validate_injection_packet(&vec![0; MAX_INNER_PACKET_LEN + 1])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
