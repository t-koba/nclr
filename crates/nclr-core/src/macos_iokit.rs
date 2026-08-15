//! Shared macOS IOKit COM-style plug-in ABI used by device transports.

use crate::errors::{Error, Result};
use std::ffi::{c_char, c_void, CString};
use std::ptr;

pub(crate) type IoObject = u32;
pub(crate) type IoService = u32;
pub(crate) type IoReturn = i32;
pub(crate) type CfUuidRef = *const c_void;
pub(crate) type CfMutableDictionaryRef = *mut c_void;

pub(crate) const IO_SUCCESS: IoReturn = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CfUuidBytes {
    pub(crate) bytes: [u8; 16],
}

#[repr(C)]
pub(crate) struct IoCfPlugInInterface {
    pub(crate) reserved: *mut c_void,
    pub(crate) query_interface:
        Option<unsafe extern "C" fn(*mut c_void, CfUuidBytes, *mut *mut c_void) -> i32>,
    pub(crate) add_ref: *const c_void,
    pub(crate) release: *const c_void,
}

pub(crate) type PlugInRef = *mut *mut IoCfPlugInInterface;

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    pub(crate) fn IOBSDNameMatching(
        main_port: u32,
        options: u32,
        bsd_name: *const c_char,
    ) -> CfMutableDictionaryRef;
    pub(crate) fn IOServiceGetMatchingService(
        main_port: u32,
        matching: CfMutableDictionaryRef,
    ) -> IoService;
    pub(crate) fn IORegistryEntryGetParentEntry(
        entry: IoObject,
        plane: *const c_char,
        parent: *mut IoObject,
    ) -> IoReturn;
    pub(crate) fn IOObjectRelease(object: IoObject) -> IoReturn;
    pub(crate) fn IOCreatePlugInInterfaceForService(
        service: IoService,
        plugin_type: CfUuidRef,
        interface_type: CfUuidRef,
        interface: *mut PlugInRef,
        score: *mut i32,
    ) -> IoReturn;
    pub(crate) fn IODestroyPlugInInterface(interface: PlugInRef) -> IoReturn;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFUUIDGetConstantUUIDWithBytes(
        allocator: *const c_void,
        byte0: u8,
        byte1: u8,
        byte2: u8,
        byte3: u8,
        byte4: u8,
        byte5: u8,
        byte6: u8,
        byte7: u8,
        byte8: u8,
        byte9: u8,
        byte10: u8,
        byte11: u8,
        byte12: u8,
        byte13: u8,
        byte14: u8,
        byte15: u8,
    ) -> CfUuidRef;
}

pub(crate) fn constant_uuid(bytes: [u8; 16]) -> CfUuidRef {
    unsafe {
        CFUUIDGetConstantUUIDWithBytes(
            ptr::null(),
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15],
        )
    }
}

pub(crate) fn whole_disk_bsd_name(path: &str, transport: &str) -> Result<CString> {
    let name = path.strip_prefix("/dev/").unwrap_or(path);
    let name = name.strip_prefix('r').unwrap_or(name);
    if !name.starts_with("disk")
        || name.len() == 4
        || !name[4..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::Usage(format!(
            "macOS {transport} target must be a whole disk, got {path}"
        )));
    }
    CString::new(name).map_err(|_| Error::Usage("macOS disk name contains an embedded NUL".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_whole_disk_names() {
        assert_eq!(
            whole_disk_bsd_name("/dev/disk9", "test")
                .unwrap()
                .to_str()
                .unwrap(),
            "disk9"
        );
        assert_eq!(
            whole_disk_bsd_name("/dev/rdisk10", "test")
                .unwrap()
                .to_str()
                .unwrap(),
            "disk10"
        );
        assert!(whole_disk_bsd_name("/dev/disk9s1", "test").is_err());
        assert!(whole_disk_bsd_name("/dev/sda", "test").is_err());
    }
}
