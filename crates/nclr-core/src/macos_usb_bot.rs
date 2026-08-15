//! Exact USB Mass Storage Bulk-Only Transport for macOS.
//!
//! `SCSITask` accepts only the standard 6, 10, 12 and 16 byte SCSI CDB
//! lengths. Controller factory protocols also use exact vendor lengths such
//! as Alcor's eight-byte service CDBs. This transport resolves the target BSD
//! whole disk through its own IOKit provider chain, verifies the physical USB
//! tuple and Mass Storage Bulk-Only interface, then uses the legacy
//! `IOUSBInterfaceInterface190` ABI documented by Apple's SDK.

use crate::controller_recipe::TransferDirection;
use crate::errors::{Error, Result};
use crate::macos_iokit::{
    constant_uuid, whole_disk_bsd_name, CfUuidBytes, IOBSDNameMatching,
    IOCreatePlugInInterfaceForService, IODestroyPlugInInterface, IOObjectRelease,
    IORegistryEntryGetParentEntry, IOServiceGetMatchingService, IoObject, IoReturn, IoService,
    PlugInRef, IO_SUCCESS,
};
use crate::usb_bot::{command_block_wrapper, command_status_wrapper, CSW_LEN};
use std::ffi::c_void;
use std::ptr;
const USB_CLASS_MASS_STORAGE: u8 = 0x08;
const USB_SUBCLASS_SCSI_TRANSPARENT: u8 = 0x06;
const USB_PROTOCOL_BULK_ONLY: u8 = 0x50;
const USB_ENDPOINT_OUT: u8 = 0;
const USB_ENDPOINT_IN: u8 = 1;
const USB_ENDPOINT_BULK: u8 = 2;
const IO_USB_PIPE_STALLED: u32 = 0xe000_404f;
const IO_USB_HOST_PIPE_STALLED: u32 = 0xe000_5000;
const MAX_TRANSFER_BYTES: usize = crate::controller_recipe::MAX_COMMAND_TRANSFER as usize;

const USB_INTERFACE_USER_CLIENT_UUID: [u8; 16] = [
    0x2d, 0x97, 0x86, 0xc6, 0x9e, 0xf3, 0x11, 0xd4, 0xad, 0x51, 0x00, 0x0a, 0x27, 0x05, 0x28, 0x61,
];
const PLUG_IN_INTERFACE_UUID: [u8; 16] = [
    0xc2, 0x44, 0xe8, 0x58, 0x10, 0x9c, 0x11, 0xd4, 0x91, 0xd4, 0x00, 0x50, 0xe4, 0xc6, 0x42, 0x6f,
];
const USB_INTERFACE_190_UUID: [u8; 16] = [
    0x8f, 0xdb, 0x84, 0x55, 0x74, 0xa6, 0x11, 0xd6, 0x97, 0xb1, 0x00, 0x30, 0x65, 0xd3, 0x60, 0x8e,
];

#[repr(C)]
struct UsbInterface190 {
    reserved: *mut c_void,
    query_interface: *const c_void,
    add_ref: *const c_void,
    release: Option<unsafe extern "C" fn(*mut c_void) -> u32>,
    create_async_event_source: *const c_void,
    get_async_event_source: *const c_void,
    create_async_port: *const c_void,
    get_async_port: *const c_void,
    open: *const c_void,
    close: Option<unsafe extern "C" fn(*mut c_void) -> IoReturn>,
    get_interface_class: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> IoReturn>,
    get_interface_subclass: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> IoReturn>,
    get_interface_protocol: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> IoReturn>,
    get_device_vendor: Option<unsafe extern "C" fn(*mut c_void, *mut u16) -> IoReturn>,
    get_device_product: Option<unsafe extern "C" fn(*mut c_void, *mut u16) -> IoReturn>,
    get_device_release: Option<unsafe extern "C" fn(*mut c_void, *mut u16) -> IoReturn>,
    get_configuration: *const c_void,
    get_interface_number: *const c_void,
    get_alternate_setting: *const c_void,
    get_num_endpoints: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> IoReturn>,
    get_location_id: Option<unsafe extern "C" fn(*mut c_void, *mut u32) -> IoReturn>,
    get_device: *const c_void,
    set_alternate_interface: *const c_void,
    get_bus_frame_number: *const c_void,
    control_request: *const c_void,
    control_request_async: *const c_void,
    get_pipe_properties: Option<
        unsafe extern "C" fn(
            *mut c_void,
            u8,
            *mut u8,
            *mut u8,
            *mut u8,
            *mut u16,
            *mut u8,
        ) -> IoReturn,
    >,
    get_pipe_status: *const c_void,
    abort_pipe: *const c_void,
    reset_pipe: *const c_void,
    clear_pipe_stall: *const c_void,
    read_pipe: *const c_void,
    write_pipe: *const c_void,
    read_pipe_async: *const c_void,
    write_pipe_async: *const c_void,
    read_isoch_pipe_async: *const c_void,
    write_isoch_pipe_async: *const c_void,
    control_request_timeout: *const c_void,
    control_request_async_timeout: *const c_void,
    read_pipe_timeout:
        Option<unsafe extern "C" fn(*mut c_void, u8, *mut c_void, *mut u32, u32, u32) -> IoReturn>,
    write_pipe_timeout:
        Option<unsafe extern "C" fn(*mut c_void, u8, *mut c_void, u32, u32, u32) -> IoReturn>,
    read_pipe_async_timeout: *const c_void,
    write_pipe_async_timeout: *const c_void,
    get_string_index: *const c_void,
    open_seize: Option<unsafe extern "C" fn(*mut c_void) -> IoReturn>,
    clear_pipe_stall_both_ends: Option<unsafe extern "C" fn(*mut c_void, u8) -> IoReturn>,
}

type UsbInterfaceRef = *mut *mut UsbInterface190;

fn io_error(action: &str, code: IoReturn) -> Error {
    Error::Backend(format!(
        "macOS USB BOT {action} failed with IOReturn 0x{:08x}",
        code as u32
    ))
}

fn is_pipe_stall(code: IoReturn) -> bool {
    matches!(code as u32, IO_USB_PIPE_STALLED | IO_USB_HOST_PIPE_STALLED)
}

#[derive(Debug)]
struct PipeTransferFailure {
    error: Error,
    io_code: Option<IoReturn>,
}

impl PipeTransferFailure {
    fn setup(error: Error) -> Self {
        Self {
            error,
            io_code: None,
        }
    }

    fn io(action: &str, code: IoReturn) -> Self {
        Self {
            error: io_error(action, code),
            io_code: Some(code),
        }
    }

    fn is_stall(&self) -> bool {
        self.io_code.is_some_and(is_pipe_stall)
    }

    fn into_error(self) -> Error {
        self.error
    }
}

fn combine_cleanup(operation: Error, cleanup: Error) -> Error {
    Error::Backend(format!(
        "macOS USB BOT operation failed: {operation}; cleanup also failed: {cleanup}"
    ))
}

fn release_io_object(object: IoObject) -> Result<()> {
    let code = unsafe { IOObjectRelease(object) };
    if code == IO_SUCCESS {
        Ok(())
    } else {
        Err(io_error("IOObjectRelease", code))
    }
}

fn destroy_plugin(plugin: PlugInRef) -> Result<()> {
    let code = unsafe { IODestroyPlugInInterface(plugin) };
    if code == IO_SUCCESS {
        Ok(())
    } else {
        Err(io_error("IODestroyPlugInInterface", code))
    }
}

fn query_usb_interface(plugin: PlugInRef) -> Result<Option<UsbInterfaceRef>> {
    let Some(query) = (unsafe { (**plugin).query_interface }) else {
        return Err(Error::Backend(
            "macOS USB plug-in has no QueryInterface entry".into(),
        ));
    };
    let mut raw = ptr::null_mut();
    let result = unsafe {
        query(
            plugin.cast(),
            CfUuidBytes {
                bytes: USB_INTERFACE_190_UUID,
            },
            &mut raw,
        )
    };
    if result != 0 || raw.is_null() {
        return Ok(None);
    }
    Ok(Some(raw.cast::<*mut UsbInterface190>()))
}

fn create_usb_interface(service: IoService) -> Result<Option<(PlugInRef, UsbInterfaceRef)>> {
    let mut plugin: PlugInRef = ptr::null_mut();
    let mut score = 0i32;
    let code = unsafe {
        IOCreatePlugInInterfaceForService(
            service,
            constant_uuid(USB_INTERFACE_USER_CLIENT_UUID),
            constant_uuid(PLUG_IN_INTERFACE_UUID),
            &mut plugin,
            &mut score,
        )
    };
    if code != IO_SUCCESS || plugin.is_null() {
        return Ok(None);
    }
    match query_usb_interface(plugin) {
        Ok(Some(interface)) => Ok(Some((plugin, interface))),
        Ok(None) => {
            destroy_plugin(plugin)?;
            Ok(None)
        }
        Err(operation) => match destroy_plugin(plugin) {
            Ok(()) => Err(operation),
            Err(cleanup) => Err(combine_cleanup(operation, cleanup)),
        },
    }
}

fn required_entry<T: Copy>(entry: Option<T>, name: &str) -> Result<T> {
    entry.ok_or_else(|| Error::Backend(format!("macOS USB interface has no {name} entry")))
}

fn get_u8(
    interface: UsbInterfaceRef,
    entry: Option<unsafe extern "C" fn(*mut c_void, *mut u8) -> IoReturn>,
    name: &str,
) -> Result<u8> {
    let call = required_entry(entry, name)?;
    let mut value = 0;
    let code = unsafe { call(interface.cast(), &mut value) };
    if code != IO_SUCCESS {
        return Err(io_error(name, code));
    }
    Ok(value)
}

fn get_u16(
    interface: UsbInterfaceRef,
    entry: Option<unsafe extern "C" fn(*mut c_void, *mut u16) -> IoReturn>,
    name: &str,
) -> Result<u16> {
    let call = required_entry(entry, name)?;
    let mut value = 0;
    let code = unsafe { call(interface.cast(), &mut value) };
    if code != IO_SUCCESS {
        return Err(io_error(name, code));
    }
    Ok(value)
}

fn get_u32(
    interface: UsbInterfaceRef,
    entry: Option<unsafe extern "C" fn(*mut c_void, *mut u32) -> IoReturn>,
    name: &str,
) -> Result<u32> {
    let call = required_entry(entry, name)?;
    let mut value = 0;
    let code = unsafe { call(interface.cast(), &mut value) };
    if code != IO_SUCCESS {
        return Err(io_error(name, code));
    }
    Ok(value)
}

/// Exact physical USB descriptor tuple expected for the selected BSD disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedUsbDevice {
    pub vendor_id: u16,
    pub product_id: u16,
    pub release_number: u16,
    pub location_id: Option<u32>,
}

/// Observed interface metadata retained for diagnostics and qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbBotInterfaceIdentity {
    pub vendor_id: u16,
    pub product_id: u16,
    pub release_number: u16,
    pub location_id: u32,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub bulk_in_endpoint: u8,
    pub bulk_out_endpoint: u8,
}

/// Exclusively opened macOS USB Mass Storage Bulk-Only interface.
pub struct UsbBotDevice {
    plugin: PlugInRef,
    interface: UsbInterfaceRef,
    opened: bool,
    bulk_in_pipe: u8,
    bulk_out_pipe: u8,
    next_tag: u32,
    identity: UsbBotInterfaceIdentity,
}

impl UsbBotDevice {
    /// Resolve a whole BSD disk to its own USB interface and seize that
    /// interface only after the physical and protocol tuple is authenticated.
    pub fn open(path: &str, expected: ExpectedUsbDevice) -> Result<Self> {
        let name = whole_disk_bsd_name(path, "USB BOT")?;
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
            let candidate = match create_usb_interface(current) {
                Ok(candidate) => candidate,
                Err(operation) => {
                    return match release_io_object(current) {
                        Ok(()) => Err(operation),
                        Err(cleanup) => Err(combine_cleanup(operation, cleanup)),
                    };
                }
            };
            if let Some((plugin, interface)) = candidate {
                if let Err(release) = release_io_object(current) {
                    let cleanup = destroy_plugin(plugin);
                    return match cleanup {
                        Ok(()) => Err(release),
                        Err(cleanup) => Err(combine_cleanup(release, cleanup)),
                    };
                }
                return Self::finish_open(path, expected, plugin, interface);
            }

            let mut parent = 0;
            let parent_code = unsafe {
                IORegistryEntryGetParentEntry(current, plane.as_ptr().cast(), &mut parent)
            };
            release_io_object(current)?;
            if parent_code != IO_SUCCESS || parent == 0 {
                break;
            }
            current = parent;
        }
        Err(Error::Unsupported(format!(
            "macOS did not expose an IOUSBInterfaceInterface190 Bulk-Only user client for {path}"
        )))
    }

    fn finish_open(
        path: &str,
        expected: ExpectedUsbDevice,
        plugin: PlugInRef,
        interface: UsbInterfaceRef,
    ) -> Result<Self> {
        let observed = (|| {
            let table = unsafe { &**interface };
            Ok::<_, Error>((
                get_u16(interface, table.get_device_vendor, "GetDeviceVendor")?,
                get_u16(interface, table.get_device_product, "GetDeviceProduct")?,
                get_u16(
                    interface,
                    table.get_device_release,
                    "GetDeviceReleaseNumber",
                )?,
                get_u32(interface, table.get_location_id, "GetLocationID")?,
                get_u8(interface, table.get_interface_class, "GetInterfaceClass")?,
                get_u8(
                    interface,
                    table.get_interface_subclass,
                    "GetInterfaceSubClass",
                )?,
                get_u8(
                    interface,
                    table.get_interface_protocol,
                    "GetInterfaceProtocol",
                )?,
            ))
        })();
        let (vendor, product, release, location, class, subclass, protocol) = match observed {
            Ok(value) => value,
            Err(operation) => {
                return match Self::release_unopened(plugin, interface) {
                    Ok(()) => Err(operation),
                    Err(cleanup) => Err(combine_cleanup(operation, cleanup)),
                };
            }
        };

        let expected_matches = vendor == expected.vendor_id
            && product == expected.product_id
            && release == expected.release_number
            && expected.location_id.is_none_or(|value| value == location);
        if !expected_matches {
            let operation = Error::Permission(format!(
                "macOS USB interface for {path} changed identity: expected {:04x}:{:04x}:{:04x} location {}, observed {vendor:04x}:{product:04x}:{release:04x} location {location:08x}",
                expected.vendor_id,
                expected.product_id,
                expected.release_number,
                expected
                    .location_id
                    .map_or_else(|| "provider-chain-only".into(), |value| format!("{value:08x}"))
            ));
            return match Self::release_unopened(plugin, interface) {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(combine_cleanup(operation, cleanup)),
            };
        }
        if class != USB_CLASS_MASS_STORAGE
            || subclass != USB_SUBCLASS_SCSI_TRANSPARENT
            || protocol != USB_PROTOCOL_BULK_ONLY
        {
            let operation = Error::Unsupported(format!(
                "macOS USB interface for {path} is not a supported Mass Storage Bulk-Only command set: class={class:#04x}, subclass={subclass:#04x}, protocol={protocol:#04x}"
            ));
            return match Self::release_unopened(plugin, interface) {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(combine_cleanup(operation, cleanup)),
            };
        }

        let mut device = Self {
            plugin,
            interface,
            opened: false,
            bulk_in_pipe: 0,
            bulk_out_pipe: 0,
            next_tag: 1,
            identity: UsbBotInterfaceIdentity {
                vendor_id: vendor,
                product_id: product,
                release_number: release,
                location_id: location,
                interface_class: class,
                interface_subclass: subclass,
                interface_protocol: protocol,
                bulk_in_endpoint: 0,
                bulk_out_endpoint: 0,
            },
        };
        let initialized = (|| {
            let open =
                required_entry(unsafe { (**interface).open_seize }, "USBInterfaceOpenSeize")?;
            let code = unsafe { open(interface.cast()) };
            if code != IO_SUCCESS {
                return Err(io_error(
                    "USBInterfaceOpenSeize (unmount the complete disk first)",
                    code,
                ));
            }
            device.opened = true;
            device.discover_bulk_pipes()?;
            Ok(())
        })();
        if let Err(operation) = initialized {
            return match device.close() {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(combine_cleanup(operation, cleanup)),
            };
        }
        Ok(device)
    }

    fn release_unopened(plugin: PlugInRef, interface: UsbInterfaceRef) -> Result<()> {
        let mut failure = None;
        if !interface.is_null() {
            if let Some(release) = unsafe { (**interface).release } {
                unsafe { release(interface.cast()) };
            } else {
                failure = Some(Error::Backend(
                    "macOS USB interface has no IUnknown Release entry".into(),
                ));
            }
        }
        if let Err(error) = destroy_plugin(plugin) {
            if let Some(operation) = failure {
                return Err(combine_cleanup(operation, error));
            }
            return Err(error);
        }
        failure.map_or(Ok(()), Err)
    }

    fn discover_bulk_pipes(&mut self) -> Result<()> {
        let table = unsafe { &**self.interface };
        let count = get_u8(self.interface, table.get_num_endpoints, "GetNumEndpoints")?;
        if count == 0 {
            return Err(Error::Invalid(
                "macOS USB Bulk-Only interface has no endpoints".into(),
            ));
        }
        let get_properties = required_entry(table.get_pipe_properties, "GetPipeProperties")?;
        let mut bulk_in = None;
        let mut bulk_out = None;
        let mut bulk_in_endpoint = 0;
        let mut bulk_out_endpoint = 0;
        for pipe in 1..=count {
            let mut direction = 0;
            let mut endpoint = 0;
            let mut transfer_type = 0;
            let mut max_packet = 0;
            let mut interval = 0;
            let code = unsafe {
                get_properties(
                    self.interface.cast(),
                    pipe,
                    &mut direction,
                    &mut endpoint,
                    &mut transfer_type,
                    &mut max_packet,
                    &mut interval,
                )
            };
            if code != IO_SUCCESS {
                return Err(io_error("GetPipeProperties", code));
            }
            if transfer_type != USB_ENDPOINT_BULK {
                continue;
            }
            if endpoint == 0 || max_packet == 0 {
                return Err(Error::Invalid(format!(
                    "macOS USB bulk pipe {pipe} has invalid endpoint {endpoint} or max packet {max_packet}"
                )));
            }
            match direction {
                USB_ENDPOINT_IN if bulk_in.replace(pipe).is_some() => {
                    return Err(Error::Invalid(
                        "macOS USB interface has multiple bulk IN pipes".into(),
                    ));
                }
                USB_ENDPOINT_IN => bulk_in_endpoint = endpoint,
                USB_ENDPOINT_OUT if bulk_out.replace(pipe).is_some() => {
                    return Err(Error::Invalid(
                        "macOS USB interface has multiple bulk OUT pipes".into(),
                    ));
                }
                USB_ENDPOINT_OUT => bulk_out_endpoint = endpoint,
                value => {
                    return Err(Error::Invalid(format!(
                        "macOS USB bulk pipe {pipe} has reserved direction {value}"
                    )));
                }
            }
        }
        self.bulk_in_pipe = bulk_in.ok_or_else(|| {
            Error::Invalid("macOS USB Bulk-Only interface has no bulk IN pipe".into())
        })?;
        self.bulk_out_pipe = bulk_out.ok_or_else(|| {
            Error::Invalid("macOS USB Bulk-Only interface has no bulk OUT pipe".into())
        })?;
        self.identity.bulk_in_endpoint = 0x80 | bulk_in_endpoint;
        self.identity.bulk_out_endpoint = bulk_out_endpoint;
        Ok(())
    }

    fn validate_transfer(
        cdb: &[u8],
        direction: TransferDirection,
        length: usize,
        timeout_ms: u64,
    ) -> Result<u32> {
        if !(1..=16).contains(&cdb.len()) {
            return Err(Error::Unsupported(format!(
                "USB BOT cannot submit a {}-byte CDB",
                cdb.len()
            )));
        }
        if (direction == TransferDirection::None) != (length == 0) {
            return Err(Error::Invalid(
                "USB BOT no-data direction and empty transfer buffer must agree".into(),
            ));
        }
        if direction != TransferDirection::None && !(1..=MAX_TRANSFER_BYTES).contains(&length) {
            return Err(Error::Invalid(format!(
                "USB BOT transfer must be in 1..={MAX_TRANSFER_BYTES} bytes"
            )));
        }
        if !(100..=3_600_000).contains(&timeout_ms) {
            return Err(Error::Invalid(
                "USB BOT timeout must be in 100..=3600000 milliseconds".into(),
            ));
        }
        u32::try_from(length)
            .map_err(|_| Error::Invalid("USB BOT transfer length does not fit u32".into()))
    }

    fn next_command_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        if self.next_tag == 0 {
            self.next_tag = 1;
        }
        tag
    }

    fn write_pipe_exact(
        &self,
        pipe: u8,
        data: &[u8],
        timeout: u32,
        action: &str,
    ) -> std::result::Result<(), PipeTransferFailure> {
        let write = required_entry(
            unsafe { (**self.interface).write_pipe_timeout },
            "WritePipeTO",
        )
        .map_err(PipeTransferFailure::setup)?;
        let length = u32::try_from(data.len()).map_err(|_| {
            PipeTransferFailure::setup(Error::Invalid(
                "USB BOT write length does not fit u32".into(),
            ))
        })?;
        let code = unsafe {
            write(
                self.interface.cast(),
                pipe,
                data.as_ptr().cast_mut().cast(),
                length,
                timeout,
                timeout,
            )
        };
        if code != IO_SUCCESS {
            return Err(PipeTransferFailure::io(action, code));
        }
        Ok(())
    }

    fn read_pipe(
        &self,
        pipe: u8,
        data: &mut [u8],
        timeout: u32,
        action: &str,
    ) -> std::result::Result<usize, PipeTransferFailure> {
        let read = required_entry(
            unsafe { (**self.interface).read_pipe_timeout },
            "ReadPipeTO",
        )
        .map_err(PipeTransferFailure::setup)?;
        let mut length = u32::try_from(data.len()).map_err(|_| {
            PipeTransferFailure::setup(Error::Invalid(
                "USB BOT read length does not fit u32".into(),
            ))
        })?;
        let code = unsafe {
            read(
                self.interface.cast(),
                pipe,
                data.as_mut_ptr().cast(),
                &mut length,
                timeout,
                timeout,
            )
        };
        if code != IO_SUCCESS {
            return Err(PipeTransferFailure::io(action, code));
        }
        usize::try_from(length).map_err(|_| {
            PipeTransferFailure::setup(Error::Invalid(
                "USB BOT realized length does not fit usize".into(),
            ))
        })
    }

    fn clear_stall(&self, pipe: u8) -> Result<()> {
        let clear = required_entry(
            unsafe { (**self.interface).clear_pipe_stall_both_ends },
            "ClearPipeStallBothEnds",
        )?;
        let code = unsafe { clear(self.interface.cast(), pipe) };
        if code != IO_SUCCESS {
            return Err(io_error("ClearPipeStallBothEnds", code));
        }
        Ok(())
    }

    fn read_csw(&self, tag: u32, transfer_length: u32, timeout: u32) -> Result<[u8; CSW_LEN]> {
        let mut csw = [0u8; CSW_LEN];
        match self.read_pipe(self.bulk_in_pipe, &mut csw, timeout, "CSW ReadPipeTO") {
            Ok(CSW_LEN) => Ok(csw),
            Ok(realized) => Err(Error::Backend(format!(
                "macOS USB BOT CSW read transferred {realized}/{CSW_LEN} bytes for tag {tag:#010x}"
            ))),
            Err(failure) => {
                if !failure.is_stall() {
                    return Err(failure.into_error());
                }
                self.clear_stall(self.bulk_in_pipe)?;
                let realized = self
                    .read_pipe(
                        self.bulk_in_pipe,
                        &mut csw,
                        timeout,
                        "CSW ReadPipeTO after ClearPipeStallBothEnds",
                    )
                    .map_err(PipeTransferFailure::into_error)?;
                if realized != CSW_LEN {
                    return Err(Error::Backend(format!(
                        "macOS USB BOT CSW retry transferred {realized}/{CSW_LEN} bytes for tag {tag:#010x}, transfer length {transfer_length}"
                    )));
                }
                Ok(csw)
            }
        }
    }

    /// Submit one exact 1..=16 byte command through a CBW, optional data
    /// stage and authenticated CSW. A phase error is never reset or retried
    /// automatically because a destructive command's state is then unknown.
    pub fn execute(
        &mut self,
        cdb: &[u8],
        direction: TransferDirection,
        data: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize> {
        if !self.opened {
            return Err(Error::Backend("macOS USB BOT interface is closed".into()));
        }
        let transfer_length = Self::validate_transfer(cdb, direction, data.len(), timeout_ms)?;
        let timeout = timeout_ms as u32;
        let tag = self.next_command_tag();
        let cbw = command_block_wrapper(tag, 0, cdb, direction, transfer_length)?;
        self.write_pipe_exact(self.bulk_out_pipe, &cbw, timeout, "CBW WritePipeTO")
            .map_err(PipeTransferFailure::into_error)?;

        let data_result = match direction {
            TransferDirection::None => Ok(0),
            TransferDirection::FromDevice => {
                self.read_pipe(self.bulk_in_pipe, data, timeout, "data-in ReadPipeTO")
            }
            TransferDirection::ToDevice => self
                .write_pipe_exact(self.bulk_out_pipe, data, timeout, "data-out WritePipeTO")
                .map(|()| data.len()),
        };
        let data_stall_pipe = match &data_result {
            Err(failure) if failure.is_stall() => Some(match direction {
                TransferDirection::FromDevice => self.bulk_in_pipe,
                TransferDirection::ToDevice => self.bulk_out_pipe,
                TransferDirection::None => unreachable!("no-data stage cannot stall"),
            }),
            _ => None,
        };
        if let Some(pipe) = data_stall_pipe {
            self.clear_stall(pipe)?;
        } else if let Err(failure) = data_result.as_ref() {
            return Err(Error::Backend(format!(
                "macOS USB BOT data stage failed for tag {tag:#010x}; command state is ambiguous: {}",
                failure.error
            )));
        }

        let csw_bytes = self.read_csw(tag, transfer_length, timeout)?;
        let csw = command_status_wrapper(&csw_bytes, tag, transfer_length)?;
        let expected_transferred = usize::try_from(transfer_length - csw.residue)
            .map_err(|_| Error::Invalid("USB BOT transferred length does not fit usize".into()))?;
        if let Some(pipe) = data_stall_pipe {
            return Err(Error::Backend(format!(
                "macOS USB BOT data stage stalled on pipe {pipe}; CSW status={}, residue={}, tag={tag:#010x}; command data is unusable",
                csw.status, csw.residue
            )));
        }
        let realized = data_result.expect("non-stall data result checked");
        match csw.status {
            1 => {
                return Err(Error::Backend(format!(
                    "macOS USB BOT command failed: tag={tag:#010x}, transferred={realized}, residue={}, cdb={}",
                    csw.residue,
                    hex::encode(cdb)
                )))
            }
            2 => {
                return Err(Error::Backend(format!(
                    "macOS USB BOT phase error: tag={tag:#010x}, transferred={realized}, residue={}, cdb={}; reset recovery is required and was not attempted",
                    csw.residue,
                    hex::encode(cdb)
                )))
            }
            0 => {}
            _ => unreachable!("CSW parser rejects reserved status"),
        }
        if realized != expected_transferred {
            return Err(Error::Backend(format!(
                "macOS USB BOT data length {realized} does not equal transfer length {transfer_length} minus CSW residue {} for tag {tag:#010x}",
                csw.residue
            )));
        }
        Ok(expected_transferred)
    }

    pub fn identity(&self) -> UsbBotInterfaceIdentity {
        self.identity
    }

    /// Close the seized interface and release both COM-style references.
    /// Cleanup errors are returned instead of being silently ignored.
    pub fn close(&mut self) -> Result<()> {
        let mut failure = None;
        if self.opened && !self.interface.is_null() {
            match unsafe { (**self.interface).close } {
                Some(close) => {
                    let code = unsafe { close(self.interface.cast()) };
                    if code != IO_SUCCESS {
                        failure = Some(io_error("USBInterfaceClose", code));
                    }
                }
                None => {
                    failure = Some(Error::Backend(
                        "macOS USB interface has no USBInterfaceClose entry".into(),
                    ));
                }
            }
            self.opened = false;
        }
        if !self.interface.is_null() {
            if let Some(release) = unsafe { (**self.interface).release } {
                unsafe { release(self.interface.cast()) };
            } else if failure.is_none() {
                failure = Some(Error::Backend(
                    "macOS USB interface has no IUnknown Release entry".into(),
                ));
            }
            self.interface = ptr::null_mut();
        }
        if !self.plugin.is_null() {
            let code = unsafe { IODestroyPlugInInterface(self.plugin) };
            if code != IO_SUCCESS && failure.is_none() {
                failure = Some(io_error("IODestroyPlugInInterface", code));
            }
            self.plugin = ptr::null_mut();
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for UsbBotDevice {
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
        assert_eq!(std::mem::offset_of!(UsbInterface190, close), 72);
        assert_eq!(
            std::mem::offset_of!(UsbInterface190, get_interface_class),
            80
        );
        assert_eq!(
            std::mem::offset_of!(UsbInterface190, get_pipe_properties),
            208
        );
        assert_eq!(
            std::mem::offset_of!(UsbInterface190, read_pipe_timeout),
            312
        );
        assert_eq!(
            std::mem::offset_of!(UsbInterface190, write_pipe_timeout),
            320
        );
        assert_eq!(std::mem::offset_of!(UsbInterface190, open_seize), 352);
        assert_eq!(
            std::mem::offset_of!(UsbInterface190, clear_pipe_stall_both_ends),
            360
        );
    }

    #[test]
    fn validates_exact_vendor_cdb_and_bounded_transfers() {
        let cdb = [0xfa; 8];
        assert_eq!(
            UsbBotDevice::validate_transfer(&cdb, TransferDirection::None, 0, 100).unwrap(),
            0
        );
        assert_eq!(
            UsbBotDevice::validate_transfer(
                &cdb,
                TransferDirection::FromDevice,
                MAX_TRANSFER_BYTES,
                3_600_000,
            )
            .unwrap(),
            MAX_TRANSFER_BYTES as u32
        );
        assert!(
            UsbBotDevice::validate_transfer(&[], TransferDirection::FromDevice, 1, 100).is_err()
        );
        assert!(UsbBotDevice::validate_transfer(&cdb, TransferDirection::None, 1, 100).is_err());
    }

    #[test]
    fn recognizes_legacy_and_host_family_stall_codes() {
        assert!(is_pipe_stall(IO_USB_PIPE_STALLED as i32));
        assert!(is_pipe_stall(IO_USB_HOST_PIPE_STALLED as i32));
        assert!(!is_pipe_stall(0));
    }
}
