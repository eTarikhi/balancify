//! ETW diagnostics for Windows, with stderr fallback on non-Windows platforms.
//! The provider uses a stable Balancify GUID and writes event IDs 100-600 with
//! the message as a UTF-16 payload. This keeps the service dependency-free while
//! allowing Windows ETW consumers to subscribe to the provider.

use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwLevel {
    Info,
    Warning,
    Error,
    Verbose,
}

#[derive(Debug, Clone)]
pub struct EtwEvent {
    pub level: EtwLevel,
    pub id: u16,
    pub message: String,
    pub at: Instant,
}

pub struct EtwProvider {
    provider_name: String,
    #[cfg(windows)]
    handle: Option<WindowsEtwHandle>,
}

#[cfg(windows)]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(windows)]
const BALANCIFY_PROVIDER_GUID: Guid = Guid {
    data1: 0x9b2d_7a31,
    data2: 0x6f84,
    data3: 0x4f52,
    data4: [0x91, 0x2e, 0x35, 0x6a, 0x71, 0xc4, 0x08, 0x23],
};

#[cfg(windows)]
#[repr(C)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

#[cfg(windows)]
#[repr(C)]
struct EventDataDescriptor {
    ptr: u64,
    size: u32,
    reserved: u32,
}

#[cfg(windows)]
#[repr(C)]
struct EventFilterDescriptor {
    ptr: u64,
    size: u32,
    filter_type: u32,
}

#[cfg(windows)]
type EnableCallback = unsafe extern "system" fn(
    source_id: *const Guid,
    is_enabled: u32,
    level: u8,
    match_any_keyword: u64,
    match_all_keyword: u64,
    filter_data: *const EventFilterDescriptor,
    callback_context: *mut std::ffi::c_void,
);

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn EventRegister(
        provider_id: *const Guid,
        enable_callback: Option<EnableCallback>,
        callback_context: *mut std::ffi::c_void,
        registration_handle: *mut u64,
    ) -> u32;
    fn EventEnabled(
        registration_handle: u64,
        event_descriptor: *const EventDescriptor,
    ) -> u8;
    fn EventWrite(
        registration_handle: u64,
        event_descriptor: *const EventDescriptor,
        user_data_count: u32,
        user_data: *const EventDataDescriptor,
    ) -> u32;
    fn EventUnregister(registration_handle: u64) -> u32;
}

#[cfg(windows)]
struct WindowsEtwHandle(u64);

#[cfg(windows)]
impl Drop for WindowsEtwHandle {
    fn drop(&mut self) {
        // EventUnregister is safe for a successfully registered handle and is
        // deliberately best-effort during service shutdown.
        unsafe {
            EventUnregister(self.0);
        }
    }
}

impl EtwProvider {
    pub fn new(name: &str) -> Self {
        #[cfg(windows)]
        {
            let mut registration_handle = 0;
            let status = unsafe {
                EventRegister(
                    &BALANCIFY_PROVIDER_GUID,
                    None,
                    std::ptr::null_mut(),
                    &mut registration_handle,
                )
            };
            Self {
                provider_name: name.to_string(),
                handle: (status == 0).then_some(WindowsEtwHandle(registration_handle)),
            }
        }
        #[cfg(not(windows))]
        {
            Self {
                provider_name: name.to_string(),
            }
        }
    }

    pub fn log(&self, level: EtwLevel, id: u16, msg: &str) {
        let event = EtwEvent {
            level,
            id,
            message: msg.to_string(),
            at: Instant::now(),
        };

        #[cfg(windows)]
        {
            if let Some(handle) = &self.handle {
                if write_windows_event(handle.0, &self.provider_name, &event) {
                    return;
                }
            }
            eprintln!(
                "[ETW {} {:?} {}] {}",
                self.provider_name, event.level, event.id, event.message
            );
        }

        #[cfg(not(windows))]
        eprintln!(
            "[ETW {} {:?} {}] {}",
            self.provider_name, event.level, event.id, event.message
        );
    }

    pub fn info(&self, id: u16, msg: &str) {
        self.log(EtwLevel::Info, id, msg);
    }

    pub fn warn(&self, id: u16, msg: &str) {
        self.log(EtwLevel::Warning, id, msg);
    }

    pub fn error(&self, id: u16, msg: &str) {
        self.log(EtwLevel::Error, id, msg);
    }

    pub fn verbose(&self, id: u16, msg: &str) {
        self.log(EtwLevel::Verbose, id, msg);
    }
}

#[cfg(any(windows, test))]
const MAX_MESSAGE_UTF16_UNITS: usize = 8 * 1024;

#[cfg(any(windows, test))]
fn etw_level_code(level: EtwLevel) -> u8 {
    match level {
        EtwLevel::Error => 2,
        EtwLevel::Warning => 3,
        EtwLevel::Info => 4,
        EtwLevel::Verbose => 5,
    }
}

#[cfg(any(windows, test))]
fn encode_etw_message(provider_name: &str, message: &str) -> Vec<u16> {
    let message = format!("{provider_name}: {message}");
    let mut payload: Vec<u16> = message
        .encode_utf16()
        .take(MAX_MESSAGE_UTF16_UNITS - 1)
        .collect();
    if matches!(payload.last(), Some(unit) if (0xD800..=0xDBFF).contains(unit)) {
        payload.pop();
    }
    payload.push(0);
    payload
}

#[cfg(windows)]
fn write_windows_event(handle: u64, provider_name: &str, event: &EtwEvent) -> bool {
    const BALANCIFY_KEYWORD: u64 = 1;
    let descriptor = EventDescriptor {
        id: event.id,
        version: 0,
        channel: 0,
        level: etw_level_code(event.level),
        opcode: 0,
        task: 0,
        keyword: BALANCIFY_KEYWORD,
    };
    if unsafe { EventEnabled(handle, &descriptor) } == 0 {
        return true;
    }

    let payload = encode_etw_message(provider_name, &event.message);
    let data = EventDataDescriptor {
        ptr: payload.as_ptr() as usize as u64,
        size: (payload.len() * std::mem::size_of::<u16>()) as u32,
        reserved: 0,
    };

    unsafe { EventWrite(handle, &descriptor, 1, &data) == 0 }
}

// Well-known event IDs (Sec.8.2)
pub const EVT_SERVICE_START: u16 = 100;
pub const EVT_SERVICE_STOP: u16 = 101;
pub const EVT_UPLINK_UP: u16 = 200;
pub const EVT_UPLINK_DOWN: u16 = 201;
pub const EVT_BOND_REVERTED: u16 = 300;
pub const EVT_REKEY: u16 = 400;
pub const EVT_ECN_CE: u16 = 401;
pub const EVT_DELAY_CONGESTION: u16 = 402;
pub const EVT_RELAY_FAILOVER: u16 = 500;
pub const EVT_AUTH_FAILED: u16 = 600;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etw_provider_logs_each_supported_level() {
        let provider = EtwProvider::new("BalancifyTest");
        provider.info(EVT_SERVICE_START, "service start");
        provider.warn(EVT_UPLINK_DOWN, "uplink down");
        provider.error(EVT_AUTH_FAILED, "auth failed");
        provider.verbose(EVT_SERVICE_STOP, "service stop");
    }

    #[test]
    fn event_levels_use_windows_etw_level_codes() {
        assert_eq!(etw_level_code(EtwLevel::Error), 2);
        assert_eq!(etw_level_code(EtwLevel::Warning), 3);
        assert_eq!(etw_level_code(EtwLevel::Info), 4);
        assert_eq!(etw_level_code(EtwLevel::Verbose), 5);
    }

    #[test]
    fn event_message_is_terminated_and_truncation_keeps_valid_utf16() {
        let prefix_units = "provider: ".encode_utf16().count();
        let filler = "a".repeat(MAX_MESSAGE_UTF16_UNITS - 1 - prefix_units - 1);
        let payload = encode_etw_message("provider", &format!("{filler}😀"));
        assert_eq!(payload.last(), Some(&0));
        assert!(payload.len() <= MAX_MESSAGE_UTF16_UNITS);
        assert!(!matches!(payload.get(payload.len() - 2), Some(unit) if (0xD800..=0xDBFF).contains(unit)));
    }

    #[test]
    fn event_ids_are_stable_and_unique() {
        let ids = [
            EVT_SERVICE_START,
            EVT_SERVICE_STOP,
            EVT_UPLINK_UP,
            EVT_UPLINK_DOWN,
            EVT_BOND_REVERTED,
            EVT_REKEY,
            EVT_ECN_CE,
            EVT_DELAY_CONGESTION,
            EVT_RELAY_FAILOVER,
            EVT_AUTH_FAILED,
        ];
        let mut unique = ids.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
        assert_eq!((EVT_SERVICE_START, EVT_SERVICE_STOP), (100, 101));
        assert_eq!((EVT_UPLINK_UP, EVT_UPLINK_DOWN), (200, 201));
        assert_eq!(EVT_BOND_REVERTED, 300);
        assert_eq!(EVT_REKEY, 400);
        assert_eq!((EVT_ECN_CE, EVT_DELAY_CONGESTION), (401, 402));
        assert_eq!(EVT_RELAY_FAILOVER, 500);
        assert_eq!(EVT_AUTH_FAILED, 600);
    }
}
