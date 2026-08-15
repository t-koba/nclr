//! Bounded macOS SCSI task transport for controller research and execution.
//!
//! Apple requires exclusive access before a user process may submit a
//! `SCSITask`. Callers must therefore unmount the complete disk first. Every
//! transfer requires an exact byte count, TASK COMPLETE service response and
//! GOOD SCSI status. The higher-level profile and runtime gates decide which
//! commands are authorized; this module only implements the transport.

use crate::controller_recipe::TransferDirection;
use crate::errors::{Error, Result};
use crate::macos_iokit::{
    constant_uuid, whole_disk_bsd_name, CfUuidBytes, IOBSDNameMatching,
    IOCreatePlugInInterfaceForService, IODestroyPlugInInterface, IOObjectRelease,
    IORegistryEntryGetParentEntry, IOServiceGetMatchingService, IoReturn, IoService, PlugInRef,
    IO_SUCCESS,
};
use std::ffi::c_void;
use std::ptr;
const SCSI_SERVICE_TASK_COMPLETE: u32 = 2;
const SCSI_STATUS_GOOD: u32 = 0;
const SCSI_NO_DATA_TRANSFER: u8 = 0;
const SCSI_FROM_INITIATOR_TO_TARGET: u8 = 1;
const SCSI_FROM_TARGET_TO_INITIATOR: u8 = 2;
const MAX_TRANSFER_BYTES: usize = crate::controller_recipe::MAX_COMMAND_TRANSFER as usize;

const TASK_DEVICE_USER_CLIENT_UUID: [u8; 16] = [
    0x7d, 0x66, 0x67, 0x8e, 0x08, 0xa2, 0x11, 0xd5, 0xa1, 0xb8, 0x00, 0x30, 0x65, 0x7d, 0x05, 0x2a,
];
const PLUG_IN_INTERFACE_UUID: [u8; 16] = [
    0xc2, 0x44, 0xe8, 0x58, 0x10, 0x9c, 0x11, 0xd4, 0x91, 0xd4, 0x00, 0x50, 0xe4, 0xc6, 0x42, 0x6f,
];
const TASK_DEVICE_INTERFACE_UUID: [u8; 16] = [
    0x1b, 0xbc, 0x41, 0x32, 0x08, 0xa5, 0x11, 0xd5, 0x90, 0xed, 0x00, 0x30, 0x65, 0x7d, 0x05, 0x2a,
];

#[repr(C)]
struct ScsiTaskDeviceInterface {
    reserved: *mut c_void,
    query_interface: *const c_void,
    add_ref: *const c_void,
    release: Option<unsafe extern "C" fn(*mut c_void) -> u32>,
    version: u16,
    revision: u16,
    is_exclusive_access_available: *const c_void,
    add_callback_dispatcher_to_run_loop: *const c_void,
    remove_callback_dispatcher_from_run_loop: *const c_void,
    obtain_exclusive_access: Option<unsafe extern "C" fn(*mut c_void) -> IoReturn>,
    release_exclusive_access: Option<unsafe extern "C" fn(*mut c_void) -> IoReturn>,
    create_scsi_task: Option<unsafe extern "C" fn(*mut c_void) -> ScsiTaskRef>,
}

type ScsiTaskDeviceRef = *mut *mut ScsiTaskDeviceInterface;

#[repr(C)]
struct ScsiTaskInterface {
    reserved: *mut c_void,
    query_interface: *const c_void,
    add_ref: *const c_void,
    release: Option<unsafe extern "C" fn(*mut c_void) -> u32>,
    version: u16,
    revision: u16,
    is_task_active: *const c_void,
    set_task_attribute: *const c_void,
    get_task_attribute: *const c_void,
    set_command_descriptor_block:
        Option<unsafe extern "C" fn(*mut c_void, *mut u8, u8) -> IoReturn>,
    get_command_descriptor_block_size: *const c_void,
    get_command_descriptor_block: *const c_void,
    set_scatter_gather_entries:
        Option<unsafe extern "C" fn(*mut c_void, *mut ScsiTaskSgElement, u8, u64, u8) -> IoReturn>,
    set_timeout_duration: Option<unsafe extern "C" fn(*mut c_void, u32) -> IoReturn>,
    get_timeout_duration: *const c_void,
    set_task_completion_callback: *const c_void,
    execute_task_async: *const c_void,
    execute_task_sync:
        Option<unsafe extern "C" fn(*mut c_void, *mut u8, *mut u32, *mut u64) -> IoReturn>,
    abort_task: *const c_void,
    get_scsi_service_response: Option<unsafe extern "C" fn(*mut c_void, *mut u32) -> IoReturn>,
}

type ScsiTaskRef = *mut *mut ScsiTaskInterface;

#[repr(C)]
struct ScsiTaskSgElement {
    address: u64,
    length: u64,
}

fn io_error(action: &str, code: IoReturn) -> Error {
    Error::Backend(format!(
        "macOS SCSITask {action} failed with IOReturn 0x{:08x}",
        code as u32
    ))
}

fn query_task_device(plugin: PlugInRef) -> Result<Option<ScsiTaskDeviceRef>> {
    let Some(query) = (unsafe { (**plugin).query_interface }) else {
        return Err(Error::Backend(
            "macOS SCSITask plug-in has no QueryInterface entry".into(),
        ));
    };
    let mut raw = ptr::null_mut();
    let result = unsafe {
        query(
            plugin.cast(),
            CfUuidBytes {
                bytes: TASK_DEVICE_INTERFACE_UUID,
            },
            &mut raw,
        )
    };
    if result < 0 || raw.is_null() {
        return Ok(None);
    }
    Ok(Some(raw.cast::<*mut ScsiTaskDeviceInterface>()))
}

fn create_task_device(service: IoService) -> Result<Option<(PlugInRef, ScsiTaskDeviceRef)>> {
    let mut plugin: PlugInRef = ptr::null_mut();
    let mut score = 0i32;
    let result = unsafe {
        IOCreatePlugInInterfaceForService(
            service,
            constant_uuid(TASK_DEVICE_USER_CLIENT_UUID),
            constant_uuid(PLUG_IN_INTERFACE_UUID),
            &mut plugin,
            &mut score,
        )
    };
    if result != IO_SUCCESS || plugin.is_null() {
        return Ok(None);
    }
    match query_task_device(plugin) {
        Ok(Some(device)) => Ok(Some((plugin, device))),
        Ok(None) => {
            let _ = unsafe { IODestroyPlugInInterface(plugin) };
            Ok(None)
        }
        Err(error) => {
            let _ = unsafe { IODestroyPlugInInterface(plugin) };
            Err(error)
        }
    }
}

/// An exclusively opened macOS SCSI task device.
pub struct ScsiDevice {
    plugin: PlugInRef,
    device: ScsiTaskDeviceRef,
    exclusive: bool,
}

impl ScsiDevice {
    /// Resolve a BSD whole disk to its SCSI logical-unit provider and obtain
    /// exclusive access. Mounted media are rejected by macOS.
    pub fn open(path: &str) -> Result<Self> {
        let name = whole_disk_bsd_name(path, "SCSITask")?;
        let matching = unsafe { IOBSDNameMatching(0, 0, name.as_ptr()) };
        if matching.is_null() {
            return Err(Error::Backend(format!(
                "macOS could not create an IOKit match for {path}"
            )));
        }
        let mut current = unsafe { IOServiceGetMatchingService(0, matching) };
        if current == 0 {
            return Err(Error::Backend(format!(
                "macOS IOKit has no service for {path}"
            )));
        }

        let plane = b"IOService\0";
        loop {
            let candidate = match create_task_device(current) {
                Ok(candidate) => candidate,
                Err(error) => {
                    let _ = unsafe { IOObjectRelease(current) };
                    return Err(error);
                }
            };
            if let Some((plugin, device)) = candidate {
                let _ = unsafe { IOObjectRelease(current) };
                let mut opened = Self {
                    plugin,
                    device,
                    exclusive: false,
                };
                let obtain = unsafe { (**device).obtain_exclusive_access }.ok_or_else(|| {
                    Error::Backend(
                        "macOS SCSITask device has no ObtainExclusiveAccess entry".into(),
                    )
                })?;
                let result = unsafe { obtain(device.cast()) };
                if result != IO_SUCCESS {
                    return Err(io_error(
                        "exclusive access (unmount the complete disk first)",
                        result,
                    ));
                }
                opened.exclusive = true;
                return Ok(opened);
            }

            let mut parent = 0;
            let result = unsafe {
                IORegistryEntryGetParentEntry(current, plane.as_ptr().cast(), &mut parent)
            };
            let _ = unsafe { IOObjectRelease(current) };
            if result != IO_SUCCESS || parent == 0 {
                break;
            }
            current = parent;
        }
        Err(Error::Unsupported(format!(
            "macOS did not expose a SCSITask user client for {path}"
        )))
    }

    fn validate_transfer(
        cdb: &[u8],
        direction: TransferDirection,
        length: usize,
        timeout_ms: u64,
    ) -> Result<()> {
        if !matches!(cdb.len(), 6 | 10 | 12 | 16) {
            return Err(Error::Unsupported(format!(
                "macOS SCSITask cannot submit an exact {}-byte CDB",
                cdb.len()
            )));
        }
        if direction == TransferDirection::None && length != 0 {
            return Err(Error::Invalid(
                "macOS no-data SCSI command has a non-empty transfer buffer".into(),
            ));
        }
        if direction != TransferDirection::None && !(1..=MAX_TRANSFER_BYTES).contains(&length) {
            return Err(Error::Invalid(format!(
                "macOS SCSI transfer must be in 1..={MAX_TRANSFER_BYTES} bytes"
            )));
        }
        if !(100..=3_600_000).contains(&timeout_ms) {
            return Err(Error::Invalid(
                "macOS SCSI timeout must be in 100..=3600000 milliseconds".into(),
            ));
        }
        Ok(())
    }

    fn execute_exact(
        &mut self,
        cdb: &[u8],
        direction: TransferDirection,
        data: &mut [u8],
        timeout_ms: u64,
    ) -> Result<()> {
        Self::validate_transfer(cdb, direction, data.len(), timeout_ms)?;
        let timeout = timeout_ms as u32;
        let create = unsafe { (**self.device).create_scsi_task }.ok_or_else(|| {
            Error::Backend("macOS SCSITask device has no CreateSCSITask entry".into())
        })?;
        let task = unsafe { create(self.device.cast()) };
        if task.is_null() {
            return Err(Error::Backend(
                "macOS SCSITask could not allocate a task".into(),
            ));
        }
        let release_task = unsafe { (**task).release }
            .ok_or_else(|| Error::Backend("macOS SCSITask has no IUnknown Release entry".into()))?;

        let result = (|| {
            let interface = unsafe { &**task };
            let set_cdb = interface
                .set_command_descriptor_block
                .ok_or_else(|| Error::Backend("macOS SCSITask has no CDB setter".into()))?;
            let set_sg = interface.set_scatter_gather_entries.ok_or_else(|| {
                Error::Backend("macOS SCSITask has no scatter/gather setter".into())
            })?;
            let set_timeout = interface
                .set_timeout_duration
                .ok_or_else(|| Error::Backend("macOS SCSITask has no timeout setter".into()))?;
            let execute = interface
                .execute_task_sync
                .ok_or_else(|| Error::Backend("macOS SCSITask has no sync executor".into()))?;
            let get_service = interface.get_scsi_service_response.ok_or_else(|| {
                Error::Backend("macOS SCSITask has no service-response getter".into())
            })?;

            let mut exact_cdb = cdb.to_vec();
            let code =
                unsafe { set_cdb(task.cast(), exact_cdb.as_mut_ptr(), exact_cdb.len() as u8) };
            if code != IO_SUCCESS {
                return Err(io_error("SetCommandDescriptorBlock", code));
            }
            let mut element = ScsiTaskSgElement {
                address: data.as_mut_ptr() as usize as u64,
                length: data.len() as u64,
            };
            let (elements, count, transfer_direction) = match direction {
                // Apple's implementation requires a non-null list pointer
                // even when the entry count and transfer count are zero.
                TransferDirection::None => (
                    &mut element as *mut ScsiTaskSgElement,
                    0,
                    SCSI_NO_DATA_TRANSFER,
                ),
                TransferDirection::FromDevice => (
                    &mut element as *mut ScsiTaskSgElement,
                    1,
                    SCSI_FROM_TARGET_TO_INITIATOR,
                ),
                TransferDirection::ToDevice => (
                    &mut element as *mut ScsiTaskSgElement,
                    1,
                    SCSI_FROM_INITIATOR_TO_TARGET,
                ),
            };
            let code = unsafe {
                set_sg(
                    task.cast(),
                    elements,
                    count,
                    data.len() as u64,
                    transfer_direction,
                )
            };
            if code != IO_SUCCESS {
                return Err(io_error("SetScatterGatherEntries", code));
            }
            let code = unsafe { set_timeout(task.cast(), timeout) };
            if code != IO_SUCCESS {
                return Err(io_error("SetTimeoutDuration", code));
            }

            let mut sense = [0u8; 18];
            let mut status = u32::MAX;
            let mut realized = 0u64;
            let code =
                unsafe { execute(task.cast(), sense.as_mut_ptr(), &mut status, &mut realized) };
            if code != IO_SUCCESS {
                return Err(io_error("ExecuteTaskSync", code));
            }
            let mut service = u32::MAX;
            let code = unsafe { get_service(task.cast(), &mut service) };
            if code != IO_SUCCESS {
                return Err(io_error("GetSCSIServiceResponse", code));
            }
            if service != SCSI_SERVICE_TASK_COMPLETE
                || status != SCSI_STATUS_GOOD
                || realized != data.len() as u64
            {
                return Err(Error::Backend(format!(
                    "macOS SCSITask command failed: service={service}, status=0x{status:02x}, transferred={realized}/{}, sense={}",
                    data.len(),
                    hex::encode(sense)
                )));
            }
            Ok(())
        })();

        unsafe { release_task(task.cast()) };
        result
    }

    /// Submit one bounded exact device-to-host command. Apple accepts only
    /// standard CDB sizes 6, 10, 12 and 16; an 8-byte vendor CDB is rejected
    /// unchanged instead of being padded.
    pub fn read_exact(&mut self, cdb: &[u8], length: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        let mut data = vec![0u8; length];
        self.execute_exact(cdb, TransferDirection::FromDevice, &mut data, timeout_ms)?;
        Ok(data)
    }

    /// Submit one bounded exact host-to-device command.
    pub fn write_exact(&mut self, cdb: &[u8], data: &[u8], timeout_ms: u64) -> Result<()> {
        let mut owned = data.to_vec();
        self.execute_exact(cdb, TransferDirection::ToDevice, &mut owned, timeout_ms)
    }

    /// Submit one bounded exact no-data command.
    pub fn execute_no_data(&mut self, cdb: &[u8], timeout_ms: u64) -> Result<()> {
        self.execute_exact(cdb, TransferDirection::None, &mut [], timeout_ms)
    }

    /// Release exclusive access and both plug-in interfaces. Cleanup errors
    /// are returned instead of being silently ignored.
    pub fn close(&mut self) -> Result<()> {
        let mut failure = None;
        if self.exclusive && !self.device.is_null() {
            if let Some(release) = unsafe { (**self.device).release_exclusive_access } {
                let result = unsafe { release(self.device.cast()) };
                if result != IO_SUCCESS {
                    failure = Some(io_error("ReleaseExclusiveAccess", result));
                }
            } else {
                failure = Some(Error::Backend(
                    "macOS SCSITask device has no ReleaseExclusiveAccess entry".into(),
                ));
            }
            self.exclusive = false;
        }
        if !self.device.is_null() {
            if let Some(release) = unsafe { (**self.device).release } {
                unsafe { release(self.device.cast()) };
            } else if failure.is_none() {
                failure = Some(Error::Backend(
                    "macOS SCSITask device has no IUnknown Release entry".into(),
                ));
            }
            self.device = ptr::null_mut();
        }
        if !self.plugin.is_null() {
            let result = unsafe { IODestroyPlugInInterface(self.plugin) };
            if result != IO_SUCCESS && failure.is_none() {
                failure = Some(io_error("IODestroyPlugInInterface", result));
            }
            self.plugin = ptr::null_mut();
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for ScsiDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_prefix_layout_matches_the_64_bit_sdk_abi() {
        assert_eq!(std::mem::size_of::<CfUuidBytes>(), 16);
        assert_eq!(std::mem::size_of::<ScsiTaskSgElement>(), 16);
        assert_eq!(
            std::mem::offset_of!(ScsiTaskDeviceInterface, obtain_exclusive_access),
            64
        );
        assert_eq!(
            std::mem::offset_of!(ScsiTaskDeviceInterface, create_scsi_task),
            80
        );
        assert_eq!(
            std::mem::offset_of!(ScsiTaskInterface, set_command_descriptor_block),
            64
        );
        assert_eq!(
            std::mem::offset_of!(ScsiTaskInterface, execute_task_sync),
            128
        );
        assert_eq!(
            std::mem::offset_of!(ScsiTaskInterface, get_scsi_service_response),
            144
        );
    }

    #[test]
    fn validates_all_three_bounded_transfer_directions() {
        let cdb = [0u8; 16];
        ScsiDevice::validate_transfer(&cdb, TransferDirection::None, 0, 100).unwrap();
        ScsiDevice::validate_transfer(&cdb, TransferDirection::FromDevice, 1, 60_000).unwrap();
        ScsiDevice::validate_transfer(
            &cdb,
            TransferDirection::ToDevice,
            MAX_TRANSFER_BYTES,
            3_600_000,
        )
        .unwrap();
        assert!(ScsiDevice::validate_transfer(&cdb, TransferDirection::None, 1, 100).is_err());
        assert!(
            ScsiDevice::validate_transfer(&[0u8; 8], TransferDirection::FromDevice, 1, 100)
                .is_err()
        );
    }
}
