//! Controller vendor backend.
//!
//! The backend implements bounded, response-signed identification for the
//! publicly researched Phison PS2251, Alcor AU698x and SMI SM32X command
//! families, plus exact USB/SCSI bootstrap selection followed by recipe-owned
//! identification for proprietary, later-generation and OEM VID controllers.
//!
//! A USB VID only selects which read-only probe may be attempted. It never
//! identifies a controller by itself. Destructive operations additionally
//! require an independently qualified production profile and a digest-pinned
//! declarative protocol recipe. The common engine implements the physical
//! block, BBT and FTL lifecycle without embedding guessed vendor opcodes.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use nclr::backend::{FD_DEVICE, PROTOCOL_API};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use nclr::VERSION;

fn main() {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (FD_DEVICE, PROTOCOL_API, VERSION);
        eprintln!("nclr-controller: the controller backend requires Linux SG_IO or macOS SCSITask");
        std::process::exit(69);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        platform::platform_main();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use nclr::backend::{BackendEvents, FD_DEVICE, PROTOCOL_API};
    use nclr::backend_common;
    use nclr::controller::{self, ServiceModeState};
    use nclr::controller_probe::{self, ObservedBootstrap};
    use nclr::controller_protocol::{self as vendor, ControllerIdentity, Family};
    use nclr::controller_recipe::{
        self as recipe, BlockDisposition, CommandContext, ControllerRecipe, ControllerRunState,
        TransferDirection,
    };
    use nclr::errors::{Error, Result};
    use nclr::lba::LbaDevice;
    use nclr::profile::{self, Profile};
    use nclr::scsi;
    use nclr::VERSION;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::FromRawFd;

    trait CommandTransport {
        fn select_recipe_transport(&self, transport: &str) -> Result<()> {
            if matches!(
                transport,
                recipe::TRANSPORT_SCSI_COMMAND | recipe::TRANSPORT_USB_BOT
            ) {
                Ok(())
            } else {
                Err(Error::Unsupported(format!(
                    "controller recipe transport {transport} is unsupported"
                )))
            }
        }

        fn execute(
            &self,
            cdb: &[u8],
            direction: TransferDirection,
            data: &mut [u8],
            timeout_ms: u64,
        ) -> Result<usize>;

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    impl CommandTransport for std::fs::File {
        fn execute(
            &self,
            cdb: &[u8],
            direction: TransferDirection,
            data: &mut [u8],
            timeout_ms: u64,
        ) -> Result<usize> {
            let direction = match direction {
                TransferDirection::None => scsi::SG_DXFER_NONE,
                TransferDirection::FromDevice => scsi::SG_DXFER_FROM_DEV,
                TransferDirection::ToDevice => scsi::SG_DXFER_TO_DEV,
            };
            let timeout_ms = u32::try_from(timeout_ms)
                .map_err(|_| Error::Invalid("SCSI timeout does not fit SG_IO".into()))?;
            scsi::sg::exec_len(self, cdb, direction, data, timeout_ms)
        }
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MacSelectedTransport {
        ScsiCommand,
        UsbBot,
    }

    #[cfg(target_os = "macos")]
    enum MacTransportState {
        Unopened,
        Scsi(nclr::macos_scsi::ScsiDevice),
        UsbBot(nclr::macos_usb_bot::UsbBotDevice),
        Closed,
    }

    #[cfg(target_os = "macos")]
    struct MacTransportInner {
        selected: MacSelectedTransport,
        state: MacTransportState,
    }

    #[cfg(target_os = "macos")]
    struct MacCommandTransport {
        disk_path: String,
        expected_usb: Option<nclr::macos_usb_bot::ExpectedUsbDevice>,
        inner: std::cell::RefCell<MacTransportInner>,
    }

    #[cfg(target_os = "macos")]
    impl MacCommandTransport {
        fn new(
            disk_path: String,
            expected_usb: Option<nclr::macos_usb_bot::ExpectedUsbDevice>,
        ) -> Self {
            Self {
                disk_path,
                expected_usb,
                inner: std::cell::RefCell::new(MacTransportInner {
                    selected: MacSelectedTransport::ScsiCommand,
                    state: MacTransportState::Unopened,
                }),
            }
        }

        fn open_selected(&self, inner: &mut MacTransportInner) -> Result<()> {
            if !matches!(inner.state, MacTransportState::Unopened) {
                return Ok(());
            }
            inner.state = match inner.selected {
                MacSelectedTransport::ScsiCommand => {
                    MacTransportState::Scsi(nclr::macos_scsi::ScsiDevice::open(&self.disk_path)?)
                }
                MacSelectedTransport::UsbBot => {
                    let expected = self.expected_usb.ok_or_else(|| {
                        Error::Unsupported(
                            "macOS USB BOT requires an exact USB descriptor and location tuple"
                                .into(),
                        )
                    })?;
                    MacTransportState::UsbBot(nclr::macos_usb_bot::UsbBotDevice::open(
                        &self.disk_path,
                        expected,
                    )?)
                }
            };
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    impl CommandTransport for MacCommandTransport {
        fn select_recipe_transport(&self, transport: &str) -> Result<()> {
            let selected = match transport {
                recipe::TRANSPORT_SCSI_COMMAND => MacSelectedTransport::ScsiCommand,
                recipe::TRANSPORT_USB_BOT => MacSelectedTransport::UsbBot,
                other => {
                    return Err(Error::Unsupported(format!(
                        "controller recipe transport {other} is unsupported on macOS"
                    )))
                }
            };
            let mut inner = self.inner.try_borrow_mut().map_err(|_| {
                Error::Backend("macOS command transport is already borrowed".into())
            })?;
            if matches!(inner.state, MacTransportState::Closed) {
                return Err(Error::Backend("macOS command transport is closed".into()));
            }
            if inner.selected == selected {
                return Ok(());
            }
            if matches!(inner.state, MacTransportState::UsbBot(_)) {
                return Err(Error::Permission(
                    "macOS cannot switch a seized USB BOT session back to SCSITask".into(),
                ));
            }
            if let MacTransportState::Scsi(mut device) =
                std::mem::replace(&mut inner.state, MacTransportState::Unopened)
            {
                device.close()?;
            }
            inner.selected = selected;
            Ok(())
        }

        fn execute(
            &self,
            cdb: &[u8],
            direction: TransferDirection,
            data: &mut [u8],
            timeout_ms: u64,
        ) -> Result<usize> {
            let mut inner = self.inner.try_borrow_mut().map_err(|_| {
                Error::Backend("macOS command transport is already borrowed".into())
            })?;
            self.open_selected(&mut inner)?;
            match &mut inner.state {
                MacTransportState::Scsi(device) => {
                    match direction {
                        TransferDirection::None => device.execute_no_data(cdb, timeout_ms)?,
                        TransferDirection::FromDevice => {
                            let received = device.read_exact(cdb, data.len(), timeout_ms)?;
                            data.copy_from_slice(&received);
                        }
                        TransferDirection::ToDevice => device.write_exact(cdb, data, timeout_ms)?,
                    }
                    Ok(data.len())
                }
                MacTransportState::UsbBot(device) => {
                    device.execute(cdb, direction, data, timeout_ms)
                }
                MacTransportState::Unopened => Err(Error::Backend(
                    "macOS command transport remained unopened".into(),
                )),
                MacTransportState::Closed => {
                    Err(Error::Backend("macOS command transport is closed".into()))
                }
            }
        }

        fn close(&self) -> Result<()> {
            let mut inner = self.inner.try_borrow_mut().map_err(|_| {
                Error::Backend("macOS command transport is already borrowed".into())
            })?;
            let state = std::mem::replace(&mut inner.state, MacTransportState::Closed);
            match state {
                MacTransportState::Scsi(mut device) => device.close(),
                MacTransportState::UsbBot(mut device) => device.close(),
                MacTransportState::Unopened | MacTransportState::Closed => Ok(()),
            }
        }
    }

    /// SCSI INQUIRY is reported for diagnostics only. It is not sufficiently
    /// controller-specific to authorize a vendor profile.
    fn scsi_identity(transport: &dyn CommandTransport) -> Result<(nclr::scsi::Inquiry, Vec<u8>)> {
        let inq_raw = scsi_command(
            transport,
            &scsi::cdb_inquiry(false, 0, 96),
            TransferDirection::FromDevice,
            96,
        )?;
        Ok((scsi::parse_inquiry(&inq_raw)?, inq_raw))
    }

    fn scsi_command(
        transport: &dyn CommandTransport,
        cdb: &[u8],
        direction: TransferDirection,
        len: usize,
    ) -> Result<Vec<u8>> {
        scsi_command_timeout(transport, cdb, direction, len, 60_000)
    }

    fn scsi_command_timeout(
        transport: &dyn CommandTransport,
        cdb: &[u8],
        direction: TransferDirection,
        len: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let transferred = transport.execute(cdb, direction, &mut buf, timeout_ms)?;
        if direction == TransferDirection::FromDevice {
            buf.truncate(transferred);
        } else if transferred != len {
            return Err(Error::Invalid(format!(
                "SCSI command transferred {transferred} of {len} bytes"
            )));
        }
        Ok(buf)
    }

    fn command<'a>(recipe: &'a ControllerRecipe, name: &str) -> Result<&'a recipe::CommandSpec> {
        recipe
            .commands
            .get(name)
            .ok_or_else(|| Error::Invalid(format!("controller recipe command {name} is absent")))
    }

    fn execute_recipe_command(
        transport: &dyn CommandTransport,
        recipe: &ControllerRecipe,
        name: &str,
        mut context: CommandContext,
        payload: Option<&[u8]>,
    ) -> Result<(Vec<u8>, BTreeMap<String, u64>)> {
        transport.select_recipe_transport(&recipe.transport)?;
        let spec = command(recipe, name)?;
        context.payload_bytes = payload.map_or(0, |data| data.len() as u64);
        let cdb = recipe::build_cdb(spec, context)?;
        let mut data = match spec.direction {
            TransferDirection::None => {
                if payload.is_some() {
                    return Err(Error::Invalid(format!(
                        "command {name} received payload for a no-data transfer"
                    )));
                }
                Vec::new()
            }
            TransferDirection::FromDevice => {
                if payload.is_some() {
                    return Err(Error::Invalid(format!(
                        "command {name} received payload for a device-to-host transfer"
                    )));
                }
                vec![0u8; spec.transfer_bytes as usize]
            }
            TransferDirection::ToDevice => {
                let payload = payload
                    .ok_or_else(|| Error::Invalid(format!("command {name} requires a payload")))?;
                if payload.len() != spec.transfer_bytes as usize {
                    return Err(Error::Invalid(format!(
                        "command {name} payload length {} != recipe transfer length {}",
                        payload.len(),
                        spec.transfer_bytes
                    )));
                }
                payload.to_vec()
            }
        };
        let transferred = transport.execute(&cdb, spec.direction, &mut data, spec.timeout_ms)?;
        if spec.direction == TransferDirection::ToDevice && transferred != data.len() {
            return Err(Error::Invalid(format!(
                "command {name} transferred {transferred} of {} payload bytes",
                data.len()
            )));
        }
        if spec.direction == TransferDirection::FromDevice {
            data.truncate(transferred);
        }
        let decoded = if spec.direction == TransferDirection::FromDevice {
            recipe::decode_response(spec, &data)?
        } else {
            recipe::decode_response(spec, &[])?
        };
        let payload = if spec.direction == TransferDirection::FromDevice {
            recipe::response_payload(spec, &data)?.to_vec()
        } else {
            data
        };
        Ok((payload, decoded))
    }

    fn artifact_payload(
        files: &mut [(String, std::fs::File)],
        id: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        let role = format!("artifact:{id}");
        let file = files
            .iter_mut()
            .find(|(candidate, _)| candidate == &role)
            .map(|(_, file)| file)
            .ok_or_else(|| Error::Permission(format!("artifact {id} was not inherited")))?;
        let size = file
            .metadata()
            .map_err(|e| Error::io(format!("stat artifact {id}"), Some(e)))?
            .len();
        let length = if length == 0 {
            size.checked_sub(offset)
                .ok_or_else(|| Error::Invalid(format!("artifact {id} offset is out of range")))?
        } else {
            length
        };
        let end = offset
            .checked_add(length)
            .ok_or_else(|| Error::Invalid(format!("artifact {id} slice overflow")))?;
        if end > size || length > u64::from(recipe::MAX_COMMAND_TRANSFER) {
            return Err(Error::Invalid(format!(
                "artifact {id} slice is out of range"
            )));
        }
        let mut payload = vec![0u8; length as usize];
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut payload))
            .map_err(|e| Error::io(format!("read artifact {id}"), Some(e)))?;
        Ok(payload)
    }

    fn command_payload(
        spec: &recipe::CommandSpec,
        files: &mut [(String, std::fs::File)],
        context: CommandContext,
        caller: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        match spec.payload.as_ref() {
            None => Ok(None),
            Some(recipe::PayloadSource::Caller) => Ok(Some(
                caller
                    .ok_or_else(|| Error::Invalid("caller payload is absent".into()))?
                    .to_vec(),
            )),
            Some(recipe::PayloadSource::Artifact {
                artifact_id,
                offset,
                length,
            }) => Ok(Some(artifact_payload(
                files,
                artifact_id,
                *offset,
                *length,
            )?)),
            Some(recipe::PayloadSource::Bbt)
            | Some(recipe::PayloadSource::Ftl)
            | Some(recipe::PayloadSource::Capacity) => Ok(Some(
                caller
                    .ok_or_else(|| Error::Invalid("generated command payload is absent".into()))?
                    .to_vec(),
            )),
            Some(recipe::PayloadSource::Context { .. }) => {
                if caller.is_some() {
                    return Err(Error::Invalid(
                        "context-generated command received a caller payload".into(),
                    ));
                }
                Ok(Some(recipe::build_context_payload(spec, context)?))
            }
        }
    }

    fn execute_named(
        transport: &dyn CommandTransport,
        recipe: &ControllerRecipe,
        files: &mut [(String, std::fs::File)],
        name: &str,
        context: CommandContext,
        caller: Option<&[u8]>,
    ) -> Result<(Vec<u8>, BTreeMap<String, u64>)> {
        let steps = recipe::resolve_operation_steps(recipe, name)?;
        let mut output = Vec::new();
        let mut fields = BTreeMap::new();
        for step in steps {
            let step_caller = if step.is_target { caller } else { None };
            let payload = command_payload(step.command, files, context, step_caller)?;
            let (step_output, step_fields) = execute_recipe_command(
                transport,
                recipe,
                step.command_name,
                context,
                payload.as_deref(),
            )?;
            if step.capture.captures_payload() {
                let aggregate = output
                    .len()
                    .checked_add(step_output.len())
                    .ok_or_else(|| Error::Invalid("operation output length overflow".into()))?;
                if aggregate > recipe::MAX_COMMAND_TRANSFER as usize {
                    return Err(Error::Invalid(format!(
                        "operation {name} output exceeds the aggregate transfer bound"
                    )));
                }
                output.extend_from_slice(&step_output);
            }
            if step.capture.captures_fields() {
                for (field, value) in step_fields {
                    if fields.insert(field.clone(), value).is_some() {
                        return Err(Error::Invalid(format!(
                            "operation {name} returned duplicate field {field}"
                        )));
                    }
                }
            }
        }
        Ok((output, fields))
    }

    fn state_digest(state: &ControllerRunState) -> Result<String> {
        let bytes = serde_json::to_vec(state)
            .map_err(|e| Error::Invalid(format!("serialize controller block map: {e}")))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn required_geometry(profile: &Profile) -> Result<&nclr::profile::NandGeometryPolicy> {
        profile
            .geometry
            .as_ref()
            .ok_or_else(|| Error::Invalid("production profile has no NAND geometry".into()))
    }

    fn required_metadata(profile: &Profile) -> Result<&nclr::profile::MetadataLayoutPolicy> {
        profile
            .metadata_layout
            .as_ref()
            .ok_or_else(|| Error::Invalid("production profile has no metadata layout".into()))
    }

    fn load_bound_state(
        state_file: &mut std::fs::File,
        plan_hash: &str,
        profile: &Profile,
        recipe_sha256: &str,
    ) -> Result<ControllerRunState> {
        match recipe::load_state(state_file)? {
            Some(state) => {
                state.verify_binding(plan_hash, profile, recipe_sha256)?;
                Ok(state)
            }
            None => ControllerRunState::new(plan_hash, profile, recipe_sha256),
        }
    }

    fn save_state(state_file: &mut std::fs::File, state: &mut ControllerRunState) -> Result<()> {
        recipe::store_state(state_file, state)
    }

    fn result(action: &str, mut fields: serde_json::Map<String, Value>) -> Value {
        fields.insert("action".to_string(), json!(action));
        fields
            .entry("status".to_string())
            .or_insert_with(|| json!("ok"));
        json!({
            "api": PROTOCOL_API,
            "ok": true,
            "backend": "controller",
            "version": VERSION,
            "action": action,
            "action_results": [Value::Object(fields)],
        })
    }

    fn block_counts(state: &ControllerRunState) -> serde_json::Map<String, Value> {
        let mut counts = BTreeMap::<&str, u64>::new();
        for block in &state.blocks {
            let key = match block.disposition {
                BlockDisposition::Unknown => "unknown",
                BlockDisposition::FactoryBad => "factory_bad",
                BlockDisposition::HistoricalRuntimeBad => "old_rbb",
                BlockDisposition::SystemPreserved => "system_preserved",
                BlockDisposition::SystemRebuild => "system_rebuild",
                BlockDisposition::Data => "data",
                BlockDisposition::Erased => "erased",
                BlockDisposition::Qualified => "qualified",
                BlockDisposition::Quarantined => "quarantined",
            };
            *counts.entry(key).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(key, value)| (key.into(), json!(value)))
            .collect()
    }

    fn disposition_code(disposition: BlockDisposition) -> u8 {
        match disposition {
            BlockDisposition::Unknown => 0,
            BlockDisposition::FactoryBad => 1,
            BlockDisposition::HistoricalRuntimeBad => 2,
            BlockDisposition::SystemPreserved => 3,
            BlockDisposition::SystemRebuild => 4,
            BlockDisposition::Data => 5,
            BlockDisposition::Erased => 6,
            BlockDisposition::Qualified => 7,
            BlockDisposition::Quarantined => 8,
        }
    }

    fn physical_disposition(disposition: BlockDisposition) -> nclr::physical::PhysicalDisposition {
        match disposition {
            BlockDisposition::Unknown => nclr::physical::PhysicalDisposition::Unknown,
            BlockDisposition::FactoryBad => nclr::physical::PhysicalDisposition::FactoryBad,
            BlockDisposition::HistoricalRuntimeBad => {
                nclr::physical::PhysicalDisposition::HistoricalRuntimeBad
            }
            BlockDisposition::SystemPreserved => {
                nclr::physical::PhysicalDisposition::SystemPreserved
            }
            BlockDisposition::SystemRebuild => nclr::physical::PhysicalDisposition::SystemRebuild,
            BlockDisposition::Data => nclr::physical::PhysicalDisposition::Data,
            BlockDisposition::Erased => nclr::physical::PhysicalDisposition::Erased,
            BlockDisposition::Qualified => nclr::physical::PhysicalDisposition::Qualified,
            BlockDisposition::Quarantined => nclr::physical::PhysicalDisposition::Quarantined,
        }
    }

    /// Shared immutable transport, recipe and geometry context for the
    /// controller run actions; groups the stable read-only execution
    /// inputs so the physical sweep and per-block erase entry points stay
    /// callable without a long argument list. The mutable per-call inputs
    /// (artifacts, events) stay explicit arguments.
    struct RecipeRunContext<'a> {
        file: &'a dyn CommandTransport,
        controller_recipe: &'a ControllerRecipe,
        geometry: &'a nclr::profile::NandGeometryPolicy,
    }

    fn sweep_physical(
        run: &RecipeRunContext<'_>,
        state: &ControllerRunState,
        image: Option<&mut std::fs::File>,
        map: Option<&mut std::fs::File>,
        action: &str,
        artifacts: &mut [(String, std::fs::File)],
        events: &mut BackendEvents,
    ) -> Result<nclr::physical::SweepSummary> {
        let dispositions = state
            .blocks
            .iter()
            .map(|block| physical_disposition(block.disposition))
            .collect::<Vec<_>>();
        let sweep_geometry = nclr::physical::SweepGeometry {
            blocks: recipe::total_blocks(run.geometry)?,
            channels: run.geometry.channels,
            chips_per_channel: run.geometry.chips_per_channel,
            luns_per_chip: run.geometry.luns_per_chip,
            planes_per_lun: run.geometry.planes_per_lun,
            blocks_per_lun: run.geometry.blocks_per_lun,
            pages_per_block: run.geometry.pages_per_block,
            page_bytes: run.geometry.page_bytes,
            oob_bytes: run.geometry.oob_bytes,
        };
        nclr::physical::sweep_physical_pages(
            sweep_geometry,
            &dispositions,
            run.controller_recipe.policy.erased_byte,
            image.map(|writer| writer as &mut dyn nclr::physical::WriteSeek),
            map.map(|writer| writer as &mut dyn std::io::Write),
            |flat, page| {
                let context = CommandContext {
                    page: u64::from(page),
                    ..recipe::coordinate(flat, run.geometry)?
                };
                let (raw, fields) = execute_named(
                    run.file,
                    run.controller_recipe,
                    artifacts,
                    "read-page",
                    context,
                    None,
                )?;
                let ecc_known = response_value(&fields, "ecc_known")? != 0;
                let uncorrectable = response_value(&fields, "uncorrectable")? != 0;
                Ok(nclr::physical::PageRead {
                    raw,
                    metrics: nclr::physical::PageMetrics {
                        corrected_bits: response_value(&fields, "corrected_bits")?,
                        read_retries: response_value(&fields, "read_retries")?,
                        read_latency_ms: response_value(&fields, "read_latency_ms")?,
                        ecc_status: if !ecc_known {
                            nclr::physical::PageEccStatus::Unknown
                        } else if uncorrectable {
                            nclr::physical::PageEccStatus::Uncorrectable
                        } else {
                            nclr::physical::PageEccStatus::Correctable
                        },
                    },
                })
            },
            |done, total| events.progress(action, done, total, "page"),
        )
    }

    fn set_in_flight(
        state_file: &mut std::fs::File,
        state: &mut ControllerRunState,
        operation: &str,
        flat: u64,
        phase: &str,
    ) -> Result<()> {
        state.in_flight = Some(recipe::InFlight {
            operation: operation.into(),
            flat_block: flat,
            phase: phase.into(),
        });
        save_state(state_file, state)
    }

    fn command_idle(fields: &BTreeMap<String, u64>) -> Result<()> {
        if response_value(fields, "busy")? != 0 {
            return Err(Error::Interrupted(
                "controller reports an operation still in progress; resume will query status again"
                    .into(),
            ));
        }
        if response_value(fields, "failed")? != 0 {
            return Err(Error::Backend(
                "controller reports failure for the previous physical operation".into(),
            ));
        }
        Ok(())
    }

    fn wait_controller_idle(
        file: &dyn CommandTransport,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        context: CommandContext,
        events: &mut BackendEvents,
        phase: &str,
    ) -> Result<BTreeMap<String, u64>> {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(controller_recipe.policy.operation_timeout_ms);
        let mut polls = 0u64;
        let mut last_heartbeat = std::time::Instant::now();
        loop {
            let (_, status) = execute_named(
                file,
                controller_recipe,
                artifacts,
                "read-status",
                context,
                None,
            )?;
            if response_value(&status, "failed")? != 0 {
                return Err(Error::Backend(
                    "controller reports failure for the previous physical operation".into(),
                ));
            }
            if response_value(&status, "busy")? == 0 {
                return Ok(status);
            }
            polls = polls.saturating_add(1);
            if last_heartbeat.elapsed() >= std::time::Duration::from_secs(5) {
                events.heartbeat(phase, polls, "status-poll")?;
                last_heartbeat = std::time::Instant::now();
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Interrupted(
                    "controller operation is still busy; durable state permits resume".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(
                controller_recipe.policy.status_poll_ms,
            ));
        }
    }

    fn response_value(fields: &BTreeMap<String, u64>, name: &str) -> Result<u64> {
        fields.get(name).copied().ok_or_else(|| {
            Error::Invalid(format!("controller response omitted required field {name}"))
        })
    }

    fn validate_inquiry_continuation(
        inquiry_available: bool,
        service_state_bound: bool,
        diagnostic: Option<&str>,
    ) -> Result<()> {
        if inquiry_available || service_state_bound {
            return Ok(());
        }
        Err(Error::Permission(format!(
            "standard SCSI INQUIRY failed and no recipe-bound non-normal controller state permits continuation: {}",
            diagnostic.unwrap_or("the transport returned no diagnostic")
        )))
    }

    fn bounded_failure(error: &Error) -> String {
        const MAX_CHARS: usize = 64;
        let message = error.to_string();
        if message.chars().count() <= MAX_CHARS {
            return message;
        }
        let prefix = message.chars().take(MAX_CHARS).collect::<String>();
        format!(
            "{prefix} [truncated sha256={}]",
            hex::encode(Sha256::digest(message.as_bytes()))
        )
    }

    fn ambiguous_transport<T>(result: Result<T>, operation: &str) -> Result<T> {
        match result {
            Err(ambiguous @ (Error::Io(_, _) | Error::Interrupted(_))) => {
                Err(Error::Interrupted(format!(
                    "{operation} outcome is ambiguous: {ambiguous}; resume will query signed controller status"
                )))
            }
            other => other,
        }
    }

    fn verify_erased_page(
        file: &dyn CommandTransport,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        mut context: CommandContext,
        geometry: &nclr::profile::NandGeometryPolicy,
    ) -> Result<bool> {
        context.page = 0;
        let (page, _) = execute_named(
            file,
            controller_recipe,
            artifacts,
            "read-page",
            context,
            None,
        )?;
        let expected = usize::try_from(geometry.page_bytes)
            .ok()
            .and_then(|page_bytes| page_bytes.checked_add(geometry.oob_bytes as usize))
            .ok_or_else(|| Error::Invalid("page plus OOB length overflow".into()))?;
        if page.len() != expected {
            return Err(Error::Invalid(format!(
                "read-page returned {} bytes, expected {expected}",
                page.len()
            )));
        }
        Ok(page
            .iter()
            .all(|byte| *byte == controller_recipe.policy.erased_byte))
    }

    fn verify_factory_markers(
        file: &dyn CommandTransport,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        state: &ControllerRunState,
        geometry: &nclr::profile::NandGeometryPolicy,
    ) -> Result<bool> {
        let page_bytes = geometry.page_bytes as usize;
        let expected = page_bytes
            .checked_add(geometry.oob_bytes as usize)
            .ok_or_else(|| Error::Invalid("page plus OOB length overflow".into()))?;
        for block in state
            .blocks
            .iter()
            .filter(|block| block.disposition == BlockDisposition::FactoryBad)
        {
            let mut marker_present = false;
            for page in &geometry.bad_block_marker_pages {
                let context = CommandContext {
                    page: u64::from(*page),
                    ..recipe::coordinate(block.flat, geometry)?
                };
                let (raw, _) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-page",
                    context,
                    None,
                )?;
                if raw.len() != expected {
                    return Err(Error::Invalid(format!(
                        "factory-marker page for block {} has {} bytes, expected {expected}",
                        block.flat,
                        raw.len()
                    )));
                }
                marker_present |= geometry.bad_block_marker_offsets.iter().any(|offset| {
                    raw[page_bytes + *offset as usize] != controller_recipe.policy.erased_byte
                });
            }
            if !marker_present {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn erase_one(
        run: &RecipeRunContext<'_>,
        state_file: &mut std::fs::File,
        state: &mut ControllerRunState,
        flat: u64,
        phase: &str,
        artifacts: &mut [(String, std::fs::File)],
        events: &mut BackendEvents,
    ) -> Result<bool> {
        let context = recipe::coordinate(flat, run.geometry)?;
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.flat_block == flat && flight.operation == "erase-block")
        {
            if let Err(error) = ambiguous_transport(
                wait_controller_idle(
                    run.file,
                    run.controller_recipe,
                    artifacts,
                    context,
                    events,
                    phase,
                ),
                &format!("erase-block status for block {flat}"),
            ) {
                if matches!(&error, Error::Backend(_)) {
                    state.in_flight = None;
                    save_state(state_file, state)?;
                }
                return Err(error);
            }
            if verify_erased_page(
                run.file,
                run.controller_recipe,
                artifacts,
                context,
                run.geometry,
            )? {
                state.in_flight = None;
                save_state(state_file, state)?;
                return Ok(true);
            }
        }
        for attempt in 0..=run.controller_recipe.policy.erase_retries {
            set_in_flight(state_file, state, "erase-block", flat, phase)?;
            ambiguous_transport(
                execute_named(
                    run.file,
                    run.controller_recipe,
                    artifacts,
                    "erase-block",
                    context,
                    None,
                ),
                &format!("erase-block command for block {flat}"),
            )?;
            if let Err(error) = ambiguous_transport(
                wait_controller_idle(
                    run.file,
                    run.controller_recipe,
                    artifacts,
                    context,
                    events,
                    phase,
                ),
                &format!("erase-block status for block {flat}"),
            ) {
                if matches!(&error, Error::Backend(_)) {
                    state.in_flight = None;
                    save_state(state_file, state)?;
                }
                return Err(error);
            }
            state.blocks[flat as usize].erase_attempts = attempt.saturating_add(1);
            if verify_erased_page(
                run.file,
                run.controller_recipe,
                artifacts,
                context,
                run.geometry,
            )? {
                state.in_flight = None;
                return Ok(true);
            }
        }
        state.in_flight = None;
        Ok(false)
    }

    fn pattern_bytes(
        name: &str,
        data_len: usize,
        total_len: usize,
        erased_byte: u8,
        plan_hash: &str,
        flat: u64,
        page: u64,
    ) -> Result<Vec<u8>> {
        if data_len > total_len {
            return Err(Error::Invalid(
                "qualification data length exceeds page plus OOB".into(),
            ));
        }
        let mut out = vec![erased_byte; total_len];
        let data = &mut out[..data_len];
        match name {
            "zero" => data.fill(0),
            "one" => data.fill(0xff),
            "checkerboard" => {
                for (index, byte) in data.iter_mut().enumerate() {
                    *byte = if index & 1 == 0 { 0x55 } else { 0xaa };
                }
            }
            "inverse-checkerboard" => {
                for (index, byte) in data.iter_mut().enumerate() {
                    *byte = if index & 1 == 0 { 0xaa } else { 0x55 };
                }
            }
            "prbs" => {
                let seed = Sha256::digest(format!("{plan_hash}:{flat}:{page}").as_bytes());
                let mut value = u64::from_le_bytes(seed[..8].try_into().unwrap());
                for byte in data {
                    value ^= value >> 12;
                    value ^= value << 25;
                    value ^= value >> 27;
                    *byte = value.wrapping_mul(0x2545_f491_4f6c_dd1d) as u8;
                }
            }
            other => {
                return Err(Error::Invalid(format!(
                    "unknown qualification pattern {other}"
                )))
            }
        }
        Ok(out)
    }

    /// Bound inputs of one controller action invocation.
    struct ActionInvocation<'a> {
        action: &'a str,
        plan_hash: &'a str,
        reenumeration_nonce: Option<&'a str>,
        file: &'a dyn CommandTransport,
        block_file: &'a std::fs::File,
        profile: &'a Profile,
        controller_recipe: &'a ControllerRecipe,
        recipe_sha256: &'a str,
        artifacts: &'a mut [(String, std::fs::File)],
        state_file: &'a mut std::fs::File,
        physical_image: Option<&'a mut std::fs::File>,
        physical_map: Option<&'a mut std::fs::File>,
        events: &'a mut BackendEvents,
    }

    fn execute_action(invocation: ActionInvocation) -> Result<Value> {
        let ActionInvocation {
            action,
            plan_hash,
            reenumeration_nonce,
            file,
            block_file,
            profile,
            controller_recipe,
            recipe_sha256,
            artifacts,
            state_file,
            mut physical_image,
            mut physical_map,
            events,
        } = invocation;
        let geometry = required_geometry(profile)?;
        let metadata = required_metadata(profile)?;
        let mut state = load_bound_state(state_file, plan_hash, profile, recipe_sha256)?;
        let total = recipe::total_blocks(geometry)?;
        let mut fields = serde_json::Map::new();

        match action {
            "inventory" => {
                recipe::classify_system_blocks(&mut state, geometry, metadata)?;
                let (_, commit) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-commit-state",
                    CommandContext::default(),
                    None,
                )?;
                command_idle(&commit)?;
                state.generation = response_value(&commit, "generation")?;
                state.phase = "inventory-complete".into();
                save_state(state_file, &mut state)?;
                fields.extend(block_counts(&state));
                fields.insert("total_blocks".into(), json!(total));
                fields.insert("controller_id".into(), json!(state.controller_id));
                fields.insert("firmware".into(), json!(state.firmware));
                fields.insert("nand_id".into(), json!(state.nand_id));
            }
            "capture-old-bbt" => {
                recipe::classify_system_blocks(&mut state, geometry, metadata)?;
                let (raw, _) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-bbt",
                    CommandContext::default(),
                    None,
                )?;
                let decoded = recipe::decode_old_bbt(&raw, &controller_recipe.bbt, geometry)?;
                for (flat, disposition) in decoded {
                    let block = &mut state.blocks[flat as usize];
                    let declared_system = matches!(
                        block.disposition,
                        BlockDisposition::SystemPreserved | BlockDisposition::SystemRebuild
                    );
                    if declared_system && disposition != BlockDisposition::SystemRebuild {
                        return Err(Error::Invalid(format!(
                            "old BBT classifies controller system block {flat} as non-system"
                        )));
                    }
                    if !declared_system && disposition == BlockDisposition::SystemRebuild {
                        return Err(Error::Invalid(format!(
                            "old BBT contains undeclared controller system block {flat}"
                        )));
                    }
                    if declared_system {
                        continue;
                    }
                    block.disposition = disposition;
                    block.historical_rbb = disposition == BlockDisposition::HistoricalRuntimeBad;
                }
                state.old_bbt_sha256 = hex::encode(Sha256::digest(&raw));
                state.phase = "old-bbt-captured".into();
                save_state(state_file, &mut state)?;
                fields.extend(block_counts(&state));
                fields.insert("old_bbt_digest".into(), json!(state.old_bbt_sha256));
                fields.insert("old_bbt_copies".into(), json!(controller_recipe.bbt.copies));
                let fbb_count = state
                    .blocks
                    .iter()
                    .filter(|block| block.disposition == BlockDisposition::FactoryBad)
                    .count();
                let old_rbb_count = state
                    .blocks
                    .iter()
                    .filter(|block| block.historical_rbb)
                    .count();
                fields.insert("generation".into(), json!(state.generation));
                fields.insert("fbb_count".into(), json!(fbb_count));
                fields.insert("old_rbb_count".into(), json!(old_rbb_count));
            }
            "enumerate-blocks" => {
                recipe::classify_system_blocks(&mut state, geometry, metadata)?;
                let page_bytes = geometry.page_bytes as usize;
                let expected = page_bytes
                    .checked_add(geometry.oob_bytes as usize)
                    .ok_or_else(|| Error::Invalid("page plus OOB length overflow".into()))?;
                for flat in 0..total {
                    if matches!(
                        state.blocks[flat as usize].disposition,
                        BlockDisposition::SystemPreserved | BlockDisposition::SystemRebuild
                    ) {
                        if (flat + 1) % u64::from(controller_recipe.policy.block_batch_size) == 0
                            || flat + 1 == total
                        {
                            events.progress(action, flat + 1, total, "block")?;
                        }
                        continue;
                    }
                    let old_bbt_factory_bad =
                        state.blocks[flat as usize].disposition == BlockDisposition::FactoryBad;
                    let mut factory_bad = false;
                    for marker_page in &geometry.bad_block_marker_pages {
                        let mut context = recipe::coordinate(flat, geometry)?;
                        context.page = u64::from(*marker_page);
                        let (raw, _) = execute_named(
                            file,
                            controller_recipe,
                            artifacts,
                            "read-page",
                            context,
                            None,
                        )?;
                        if raw.len() != expected {
                            return Err(Error::Invalid(format!(
                                "physical page response for block {flat} has {} bytes, expected {expected}",
                                raw.len()
                            )));
                        }
                        for offset in &geometry.bad_block_marker_offsets {
                            if raw[page_bytes + *offset as usize]
                                != controller_recipe.policy.erased_byte
                            {
                                factory_bad = true;
                            }
                        }
                    }
                    if old_bbt_factory_bad && !factory_bad {
                        return Err(Error::Invalid(format!(
                            "old BBT factory-bad block {flat} has no configured physical marker"
                        )));
                    }
                    if factory_bad {
                        let block = &mut state.blocks[flat as usize];
                        if block.historical_rbb {
                            return Err(Error::Invalid(format!(
                                "block {flat} is RBB in the old BBT but carries a factory marker"
                            )));
                        }
                        block.disposition = BlockDisposition::FactoryBad;
                    }
                    if (flat + 1) % u64::from(controller_recipe.policy.block_batch_size) == 0 {
                        state.phase = format!(
                            "enumeration-batch-{}-complete",
                            flat / u64::from(controller_recipe.policy.block_batch_size)
                        );
                        save_state(state_file, &mut state)?;
                    }
                    if (flat + 1) % u64::from(controller_recipe.policy.block_batch_size) == 0
                        || flat + 1 == total
                    {
                        events.progress(action, flat + 1, total, "block")?;
                    }
                }
                state.phase = "physical-enumeration-complete".into();
                save_state(state_file, &mut state)?;
                let categories = block_counts(&state);
                fields.extend(categories.clone());
                fields.insert("categories".into(), Value::Object(categories));
                fields.insert("total".into(), json!(total));
                let fbb_count = state
                    .blocks
                    .iter()
                    .filter(|block| block.disposition == BlockDisposition::FactoryBad)
                    .count();
                fields.insert(
                    "data_blocks".into(),
                    json!(state
                        .blocks
                        .iter()
                        .filter(|block| matches!(
                            block.disposition,
                            BlockDisposition::HistoricalRuntimeBad
                                | BlockDisposition::SystemRebuild
                                | BlockDisposition::Data
                                | BlockDisposition::Erased
                                | BlockDisposition::Qualified
                                | BlockDisposition::Quarantined
                        ))
                        .count()),
                );
                fields.insert("fbb_count".into(), json!(fbb_count));
                fields.insert(
                    "unknown".into(),
                    json!(state
                        .blocks
                        .iter()
                        .filter(|block| block.disposition == BlockDisposition::Unknown)
                        .count()),
                );
                fields.insert("block_map_sha256".into(), json!(state_digest(&state)?));
                fields.insert(
                    "per_block_format".into(),
                    json!([
                        "flat",
                        "channel",
                        "chip",
                        "lun",
                        "plane",
                        "block",
                        "disposition_code"
                    ]),
                );
                fields.insert(
                    "per_block".into(),
                    Value::Array(
                        state
                            .blocks
                            .iter()
                            .map(|block| {
                                let coordinate = recipe::coordinate(block.flat, geometry)?;
                                Ok(json!([
                                    block.flat,
                                    coordinate.channel,
                                    coordinate.chip,
                                    coordinate.lun,
                                    coordinate.plane,
                                    coordinate.block,
                                    disposition_code(block.disposition)
                                ]))
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ),
                );
            }
            "enter-service-mode" => {
                if state.service_mode == "normal" {
                    let (_, status) = execute_named(
                        file,
                        controller_recipe,
                        artifacts,
                        "read-status",
                        CommandContext::default(),
                        None,
                    )?;
                    command_idle(&status)?;
                    if response_value(&status, "service_mode")? == 1 {
                        state.service_mode = "in-service".into();
                    } else {
                        state.service_mode = "entry-command-pending".into();
                        state.phase = "service-entry-command-started".into();
                        save_state(state_file, &mut state)?;
                    }
                }
                if state.service_mode == "entry-command-pending" {
                    let already_entered = if controller_recipe.family == "phison-ufd"
                        && controller_recipe
                            .policy
                            .service_loader_artifact_id
                            .is_some()
                    {
                        let page = scsi_command(
                            file,
                            &vendor::phison_version_cdb(),
                            TransferDirection::FromDevice,
                            vendor::PHISON_VERSION_PAGE_LEN,
                        )?;
                        vendor::parse_phison_version_page(&page)?.mode == "bootrom"
                    } else {
                        let (_, status) = execute_named(
                            file,
                            controller_recipe,
                            artifacts,
                            "read-status",
                            CommandContext::default(),
                            None,
                        )?;
                        command_idle(&status)?;
                        response_value(&status, "service_mode")? == 1
                    };
                    if already_entered {
                        state.service_mode = "entry-reenumerating".into();
                        save_state(state_file, &mut state)?;
                    }
                }
                if state.service_mode == "normal" || state.service_mode == "entry-command-pending" {
                    let spec = command(controller_recipe, "enter-service-mode")?;
                    let payload =
                        command_payload(spec, artifacts, CommandContext::default(), None)?;
                    ambiguous_transport(
                        execute_recipe_command(
                            file,
                            controller_recipe,
                            "enter-service-mode",
                            CommandContext::default(),
                            payload.as_deref(),
                        ),
                        "service-entry command",
                    )?;
                    if controller_recipe.policy.enter_reenumerates {
                        state.service_mode = "entry-reenumerating".into();
                        state.phase = "service-entry-command-sent".into();
                        save_state(state_file, &mut state)?;
                        fields.insert("awaiting_device".into(), json!(true));
                        fields.insert("reenumeration_stage".into(), json!("service-entry"));
                        fields.insert("service_mode".into(), json!(true));
                        fields.insert("state_sequence".into(), json!(state.sequence));
                        fields.insert("state_phase".into(), json!(state.phase));
                        return Ok(result(action, fields));
                    }
                }
                if matches!(
                    state.service_mode.as_str(),
                    "entry-reenumerating" | "loader-command-pending"
                ) {
                    if let Some(loader_id) = &controller_recipe.policy.service_loader_artifact_id {
                        let version = scsi_command(
                            file,
                            &vendor::phison_version_cdb(),
                            TransferDirection::FromDevice,
                            vendor::PHISON_VERSION_PAGE_LEN,
                        )?;
                        let mode = vendor::parse_phison_version_page(&version)?.mode;
                        if mode == "bootrom" {
                            if controller_recipe.policy.loader_reenumerates {
                                state.service_mode = "loader-command-pending".into();
                                state.phase = "service-loader-command-started".into();
                                save_state(state_file, &mut state)?;
                            }
                            let image = artifact_payload(artifacts, loader_id, 0, 0)?;
                            let load = nclr::controller_protocol::phison_load_pram_with(
                                &image,
                                &profile.controller_id,
                                profile.firmware.min.as_deref().ok_or_else(|| {
                                    Error::Invalid("exact profile firmware is absent".into())
                                })?,
                                |cdb, len| {
                                    let mut data = vec![0u8; len];
                                    let actual = file.execute(
                                        cdb,
                                        TransferDirection::FromDevice,
                                        &mut data,
                                        60_000,
                                    )?;
                                    data.truncate(actual);
                                    Ok(data)
                                },
                                |cdb, payload| {
                                    let mut data = payload.to_vec();
                                    let actual = file.execute(
                                        cdb,
                                        TransferDirection::ToDevice,
                                        &mut data,
                                        60_000,
                                    )?;
                                    if actual != data.len() {
                                        return Err(Error::Invalid(
                                            "Phison PRAM transfer has a nonzero residual".into(),
                                        ));
                                    }
                                    Ok(())
                                },
                            );
                            if let Err(error) = load {
                                return match error {
                                    ambiguous @ (Error::Io(_, _) | Error::Interrupted(_)) => {
                                        Err(Error::Interrupted(format!(
                                            "Phison service-loader outcome is ambiguous: {ambiguous}; resume will inspect BootROM/service mode"
                                        )))
                                    }
                                    other => Err(other),
                                };
                            }
                        } else if state.service_mode != "loader-command-pending" {
                            return Err(Error::Permission(format!(
                                "Phison service loader requires bootrom mode, got {mode}"
                            )));
                        }
                        if controller_recipe.policy.loader_reenumerates && mode == "bootrom" {
                            state.service_mode = "loader-reenumerating".into();
                            state.phase = "service-loader-started".into();
                            save_state(state_file, &mut state)?;
                            fields.insert("awaiting_device".into(), json!(true));
                            fields.insert("reenumeration_stage".into(), json!("service-loader"));
                            fields.insert("service_mode".into(), json!(true));
                            fields.insert("state_sequence".into(), json!(state.sequence));
                            fields.insert("state_phase".into(), json!(state.phase));
                            return Ok(result(action, fields));
                        }
                    }
                }
                let status = wait_controller_idle(
                    file,
                    controller_recipe,
                    artifacts,
                    CommandContext::default(),
                    events,
                    action,
                )?;
                if response_value(&status, "service_mode")? != 1 {
                    return Err(Error::Invalid(
                        "controller did not confirm service mode after entry".into(),
                    ));
                }
                state.service_mode = "in-service".into();
                state.phase = "service-mode-entered".into();
                save_state(state_file, &mut state)?;
                fields.insert("service_mode".into(), json!(true));
            }
            "erase-old-rbb" | "erase-data-blocks" | "final-erase" => {
                if state.service_mode != "in-service" {
                    return Err(Error::Permission(format!(
                        "action {action} requires confirmed service mode"
                    )));
                }
                recipe::classify_system_blocks(&mut state, geometry, metadata)?;
                let targets = state
                    .blocks
                    .iter()
                    .filter(|block| match action {
                        "erase-old-rbb" => block.historical_rbb,
                        "erase-data-blocks" => matches!(
                            block.disposition,
                            BlockDisposition::Data | BlockDisposition::SystemRebuild
                        ),
                        "final-erase" => matches!(
                            block.disposition,
                            BlockDisposition::Qualified
                                | BlockDisposition::Quarantined
                                | BlockDisposition::HistoricalRuntimeBad
                        ),
                        _ => false,
                    })
                    .map(|block| block.flat)
                    .collect::<Vec<_>>();
                let mut succeeded = 0u64;
                let mut failed = 0u64;
                let mut system_failed = false;
                let mut system_erased = 0u64;
                let mut historical_erased = 0u64;
                let mut historical_failed = 0u64;
                let mut per_block = Vec::with_capacity(targets.len());
                let run = RecipeRunContext {
                    file,
                    controller_recipe,
                    geometry,
                };
                for (index, flat) in targets.iter().copied().enumerate() {
                    let was_historical = state.blocks[flat as usize].historical_rbb;
                    let previous_disposition = state.blocks[flat as usize].disposition;
                    let is_system = previous_disposition == BlockDisposition::SystemRebuild;
                    match erase_one(
                        &run, state_file, &mut state, flat, action, artifacts, events,
                    ) {
                        Ok(true) => {
                            succeeded += 1;
                            if is_system {
                                system_erased += 1;
                            }
                            if was_historical {
                                historical_erased += 1;
                            }
                            let block = &mut state.blocks[flat as usize];
                            block.disposition = if action == "final-erase" {
                                previous_disposition
                            } else if previous_disposition == BlockDisposition::SystemRebuild {
                                BlockDisposition::SystemRebuild
                            } else if was_historical {
                                BlockDisposition::HistoricalRuntimeBad
                            } else {
                                BlockDisposition::Erased
                            };
                            block.failure.clear();
                        }
                        Ok(false) => {
                            failed += 1;
                            if was_historical {
                                historical_failed += 1;
                            }
                            system_failed |= is_system;
                            let block = &mut state.blocks[flat as usize];
                            block.disposition = if is_system {
                                BlockDisposition::SystemRebuild
                            } else {
                                BlockDisposition::Quarantined
                            };
                            block.failure = "erase-verification-failed".into();
                        }
                        Err(Error::Interrupted(message)) => {
                            return Err(Error::Interrupted(message))
                        }
                        Err(Error::Backend(message)) => {
                            failed += 1;
                            if was_historical {
                                historical_failed += 1;
                            }
                            system_failed |= is_system;
                            let block = &mut state.blocks[flat as usize];
                            block.disposition = if is_system {
                                BlockDisposition::SystemRebuild
                            } else {
                                BlockDisposition::Quarantined
                            };
                            block.failure = bounded_failure(&Error::Backend(message));
                        }
                        Err(error) => return Err(error),
                    }
                    let block = &state.blocks[flat as usize];
                    let coordinate = recipe::coordinate(flat, run.geometry)?;
                    per_block.push(json!([
                        flat,
                        coordinate.channel,
                        coordinate.chip,
                        coordinate.lun,
                        coordinate.plane,
                        coordinate.block,
                        disposition_code(block.disposition),
                        block.erase_attempts,
                        block.failure.clone()
                    ]));
                    if (index + 1) % run.controller_recipe.policy.block_batch_size as usize == 0 {
                        state.phase = format!(
                            "{action}-batch-{}-complete",
                            index / run.controller_recipe.policy.block_batch_size as usize
                        );
                        save_state(state_file, &mut state)?;
                    }
                    if (index + 1) % run.controller_recipe.policy.block_batch_size as usize == 0
                        || index + 1 == targets.len()
                    {
                        events.progress(
                            action,
                            (index + 1) as u64,
                            targets.len() as u64,
                            "block",
                        )?;
                    }
                }
                state.phase = format!("{action}-complete");
                save_state(state_file, &mut state)?;
                if system_failed {
                    return Err(Error::Backend(
                        "a rebuild-required controller metadata block could not be erased".into(),
                    ));
                }
                fields.insert("attempted".into(), json!(targets.len()));
                fields.insert("succeeded".into(), json!(succeeded));
                fields.insert("erased".into(), json!(succeeded));
                fields.insert("system_erased".into(), json!(system_erased));
                fields.insert("old_rbb_erased".into(), json!(historical_erased));
                fields.insert("old_rbb_failed".into(), json!(historical_failed));
                fields.insert("failed".into(), json!(failed));
                fields.insert("errors".into(), json!(failed));
                fields.insert(
                    "status".into(),
                    json!(if failed == 0 { "ok" } else { "partial" }),
                );
                fields.insert("block_map_sha256".into(), json!(state_digest(&state)?));
                fields.insert(
                    "per_block_format".into(),
                    json!([
                        "flat",
                        "channel",
                        "chip",
                        "lun",
                        "plane",
                        "block",
                        "disposition_code",
                        "erase_attempts",
                        "failure"
                    ]),
                );
                fields.insert("per_block".into(), Value::Array(per_block));
                if action == "final-erase" {
                    let fbb_preserved = verify_factory_markers(
                        file,
                        controller_recipe,
                        artifacts,
                        &state,
                        geometry,
                    )?;
                    if !fbb_preserved {
                        return Err(Error::Backend(
                            "factory-bad marker changed during physical processing".into(),
                        ));
                    }
                    fields.insert("uniform".into(), json!(failed == 0));
                    fields.insert("fbb_preserved".into(), json!(true));
                }
            }
            "qualify-blocks" => {
                if state.service_mode != "in-service" {
                    return Err(Error::Permission(
                        "qualify-blocks requires confirmed service mode".into(),
                    ));
                }
                if let Some(flight) = state.in_flight.clone() {
                    if flight.operation != "program-page" {
                        return Err(Error::Invalid(format!(
                            "qualification found unrelated in-flight operation {}",
                            flight.operation
                        )));
                    }
                    let context = recipe::coordinate(flight.flat_block, geometry)?;
                    match ambiguous_transport(
                        wait_controller_idle(
                            file,
                            controller_recipe,
                            artifacts,
                            context,
                            events,
                            action,
                        ),
                        "in-flight program-page status",
                    ) {
                        Ok(_) => {}
                        Err(Error::Backend(message)) => {
                            let block = state
                                .blocks
                                .get_mut(flight.flat_block as usize)
                                .ok_or_else(|| {
                                    Error::Invalid("in-flight program block is out of range".into())
                                })?;
                            block.disposition = BlockDisposition::Quarantined;
                            block.failure = bounded_failure(&Error::Backend(message));
                        }
                        Err(error) => return Err(error),
                    }
                    state.in_flight = None;
                    save_state(state_file, &mut state)?;
                }
                let targets = state
                    .blocks
                    .iter()
                    .filter(|block| {
                        matches!(
                            block.disposition,
                            BlockDisposition::Data | BlockDisposition::Erased
                        )
                    })
                    .map(|block| block.flat)
                    .collect::<Vec<_>>();
                let program_len =
                    command(controller_recipe, "program-page")?.transfer_bytes as usize;
                let run = RecipeRunContext {
                    file,
                    controller_recipe,
                    geometry,
                };
                for (index, flat) in targets.iter().copied().enumerate() {
                    let mut block_ok = true;
                    let mut block_weak = false;
                    for pattern in &controller_recipe.policy.qualification_patterns {
                        match erase_one(
                            &run,
                            state_file,
                            &mut state,
                            flat,
                            "qualification-pattern-erase",
                            artifacts,
                            events,
                        ) {
                            Ok(true) => {}
                            Ok(false) => {
                                block_ok = false;
                                state.blocks[flat as usize].failure =
                                    "qualification-erase-failed".into();
                                break;
                            }
                            Err(error) => return Err(error),
                        }
                        for page in &controller_recipe.policy.qualification_pages {
                            let context = CommandContext {
                                page: u64::from(*page),
                                ..recipe::coordinate(flat, geometry)?
                            };
                            let payload = pattern_bytes(
                                pattern,
                                geometry.page_bytes as usize,
                                program_len,
                                controller_recipe.policy.erased_byte,
                                plan_hash,
                                flat,
                                u64::from(*page),
                            )?;
                            set_in_flight(
                                state_file,
                                &mut state,
                                "program-page",
                                flat,
                                "qualification",
                            )?;
                            let program = ambiguous_transport(
                                execute_named(
                                    file,
                                    controller_recipe,
                                    artifacts,
                                    "program-page",
                                    context,
                                    Some(&payload),
                                ),
                                "program-page command",
                            )
                            .and_then(|_| {
                                ambiguous_transport(
                                    wait_controller_idle(
                                        file,
                                        controller_recipe,
                                        artifacts,
                                        context,
                                        events,
                                        action,
                                    ),
                                    "program-page status",
                                )
                                .map(|_| ())
                            });
                            if let Err(error) = program {
                                match error {
                                    Error::Backend(message) => {
                                        state.in_flight = None;
                                        state.blocks[flat as usize].failure =
                                            bounded_failure(&Error::Backend(message));
                                        block_ok = false;
                                        break;
                                    }
                                    other => return Err(other),
                                }
                            }
                            let (read, metrics) = ambiguous_transport(
                                execute_named(
                                    file,
                                    controller_recipe,
                                    artifacts,
                                    "read-page",
                                    context,
                                    None,
                                ),
                                "qualification read-page",
                            )?;
                            let data_bytes = geometry.page_bytes as usize;
                            let marker_changed =
                                geometry.bad_block_marker_offsets.iter().any(|offset| {
                                    read[data_bytes + *offset as usize]
                                        != controller_recipe.policy.erased_byte
                                });
                            if read[..data_bytes] != payload[..data_bytes]
                                || marker_changed
                                || response_value(&metrics, "ecc_known")? == 0
                                || response_value(&metrics, "uncorrectable")? != 0
                            {
                                block_ok = false;
                                state.blocks[flat as usize].failure =
                                    "program-read-compare-failed".into();
                                break;
                            }
                            let corrected =
                                u32::try_from(response_value(&metrics, "corrected_bits")?)
                                    .map_err(|_| {
                                        Error::Invalid("corrected_bits exceeds u32".into())
                                    })?;
                            let retries = u32::try_from(response_value(&metrics, "read_retries")?)
                                .map_err(|_| Error::Invalid("read_retries exceeds u32".into()))?;
                            let latency =
                                u32::try_from(response_value(&metrics, "read_latency_ms")?)
                                    .map_err(|_| {
                                        Error::Invalid("read_latency_ms exceeds u32".into())
                                    })?;
                            let block = &mut state.blocks[flat as usize];
                            block.corrected_bits = block.corrected_bits.max(corrected);
                            block.read_retries = block.read_retries.max(retries);
                            block.read_latency_ms = block.read_latency_ms.max(latency);
                            block_weak |=
                                nclr::profile::is_weak(corrected, retries, latency, &profile.ecc);
                        }
                        if !block_ok {
                            break;
                        }
                    }
                    state.in_flight = None;
                    let block = &mut state.blocks[flat as usize];
                    block.disposition = if !block_ok {
                        BlockDisposition::Quarantined
                    } else if block_weak {
                        block.failure = "ecc-margin".into();
                        BlockDisposition::Quarantined
                    } else {
                        block.failure.clear();
                        BlockDisposition::Qualified
                    };
                    if (index + 1) % controller_recipe.policy.block_batch_size as usize == 0 {
                        state.phase = format!(
                            "qualification-batch-{}-complete",
                            index / controller_recipe.policy.block_batch_size as usize
                        );
                        save_state(state_file, &mut state)?;
                    }
                    if (index + 1) % controller_recipe.policy.block_batch_size as usize == 0
                        || index + 1 == targets.len()
                    {
                        events.progress(
                            action,
                            (index + 1) as u64,
                            targets.len() as u64,
                            "block",
                        )?;
                    }
                }
                state.phase = "qualification-complete".into();
                save_state(state_file, &mut state)?;
                let qualified = state
                    .blocks
                    .iter()
                    .filter(|block| block.disposition == BlockDisposition::Qualified)
                    .count() as u64;
                let weak = state
                    .blocks
                    .iter()
                    .filter(|block| {
                        block.disposition == BlockDisposition::Quarantined
                            && block.failure == "ecc-margin"
                    })
                    .count() as u64;
                let failed = state
                    .blocks
                    .iter()
                    .filter(|block| {
                        block.disposition == BlockDisposition::Quarantined
                            && block.failure != "ecc-margin"
                    })
                    .count() as u64;
                fields.insert("tested".into(), json!(qualified + weak + failed));
                fields.insert("qualified".into(), json!(qualified));
                fields.insert("weak".into(), json!(weak));
                fields.insert("failed".into(), json!(failed));
                fields.insert("errors".into(), json!(failed));
                fields.insert("block_map_sha256".into(), json!(state_digest(&state)?));
                fields.insert(
                    "per_block_format".into(),
                    json!([
                        "flat",
                        "channel",
                        "chip",
                        "lun",
                        "plane",
                        "block",
                        "disposition_code",
                        "erase_attempts",
                        "corrected_bits",
                        "read_retries",
                        "read_latency_ms",
                        "failure"
                    ]),
                );
                fields.insert(
                    "per_block".into(),
                    Value::Array(
                        state
                            .blocks
                            .iter()
                            .filter(|block| {
                                matches!(
                                    block.disposition,
                                    BlockDisposition::Qualified | BlockDisposition::Quarantined
                                )
                            })
                            .map(|block| {
                                let coordinate = recipe::coordinate(block.flat, geometry)?;
                                Ok(json!([
                                    block.flat,
                                    coordinate.channel,
                                    coordinate.chip,
                                    coordinate.lun,
                                    coordinate.plane,
                                    coordinate.block,
                                    disposition_code(block.disposition),
                                    block.erase_attempts,
                                    block.corrected_bits,
                                    block.read_retries,
                                    block.read_latency_ms,
                                    block.failure.clone()
                                ]))
                            })
                            .collect::<Result<Vec<_>>>()?,
                    ),
                );
            }
            "verify-physical-erasure" | "salvage-physical" => {
                if state.service_mode != "in-service" {
                    return Err(Error::Permission(format!(
                        "action {action} requires confirmed service mode"
                    )));
                }
                recipe::classify_system_blocks(&mut state, geometry, metadata)?;
                let salvage = action == "salvage-physical";
                if salvage && (physical_image.is_none() || physical_map.is_none()) {
                    return Err(Error::Permission(
                        "salvage-physical requires inherited physical-image and physical-map outputs"
                            .into(),
                    ));
                }
                if !salvage && (physical_image.is_some() || physical_map.is_some()) {
                    return Err(Error::Invalid(
                        "physical output fds are only valid for salvage-physical".into(),
                    ));
                }
                let run = RecipeRunContext {
                    file,
                    controller_recipe,
                    geometry,
                };
                let summary = sweep_physical(
                    &run,
                    &state,
                    physical_image.as_deref_mut(),
                    physical_map.as_deref_mut(),
                    action,
                    artifacts,
                    events,
                )?;
                if let Some(output) = physical_image.as_mut() {
                    output
                        .sync_all()
                        .map_err(|error| Error::io("sync physical image", Some(error)))?;
                }
                if let Some(output) = physical_map.as_mut() {
                    output
                        .sync_all()
                        .map_err(|error| Error::io("sync physical page map", Some(error)))?;
                }
                state.phase = if salvage {
                    "physical-salvage-complete"
                } else {
                    "physical-erasure-verified"
                }
                .into();
                save_state(state_file, &mut state)?;
                let block_summary = serde_json::to_vec(&summary.blocks).map_err(|error| {
                    Error::Invalid(format!("serialize physical sweep block summary: {error}"))
                })?;
                let exceptions = summary
                    .blocks
                    .iter()
                    .filter(|block| {
                        block.unreadable_pages > 0
                            || block.ecc_unknown_pages > 0
                            || block.uncorrectable_pages > 0
                            || (!salvage
                                && block.disposition.expected_erased()
                                && block.non_erased_pages > 0)
                    })
                    .take(256)
                    .collect::<Vec<_>>();
                let exception_count = summary
                    .blocks
                    .iter()
                    .filter(|block| {
                        block.unreadable_pages > 0
                            || block.ecc_unknown_pages > 0
                            || block.uncorrectable_pages > 0
                            || (!salvage
                                && block.disposition.expected_erased()
                                && block.non_erased_pages > 0)
                    })
                    .count();
                fields.insert("total_blocks".into(), json!(summary.total_blocks));
                fields.insert("total_pages".into(), json!(summary.total_pages));
                fields.insert("readable_pages".into(), json!(summary.readable_pages));
                fields.insert("unreadable_pages".into(), json!(summary.unreadable_pages));
                fields.insert("ecc_unknown_pages".into(), json!(summary.ecc_unknown_pages));
                fields.insert(
                    "uncorrectable_pages".into(),
                    json!(summary.uncorrectable_pages),
                );
                fields.insert("target_pages".into(), json!(summary.target_pages));
                fields.insert(
                    "target_readable_pages".into(),
                    json!(summary.target_readable_pages),
                );
                fields.insert(
                    "target_unreadable_pages".into(),
                    json!(summary.target_unreadable_pages),
                );
                fields.insert(
                    "target_ecc_unknown_pages".into(),
                    json!(summary.target_ecc_unknown_pages),
                );
                fields.insert(
                    "target_uncorrectable_pages".into(),
                    json!(summary.target_uncorrectable_pages),
                );
                fields.insert(
                    "excluded_unreadable_pages".into(),
                    json!(summary.excluded_unreadable_pages),
                );
                fields.insert(
                    "target_non_erased_pages".into(),
                    json!(summary.target_non_erased_pages),
                );
                fields.insert(
                    "target_non_erased_bytes".into(),
                    json!(summary.target_non_erased_bytes),
                );
                fields.insert(
                    "excluded_non_erased_pages".into(),
                    json!(summary.excluded_non_erased_pages),
                );
                fields.insert(
                    "all_addresses_readable".into(),
                    json!(summary.all_addresses_readable),
                );
                fields.insert(
                    "all_pages_ecc_known".into(),
                    json!(summary.all_pages_ecc_known),
                );
                fields.insert(
                    "all_pages_correctable".into(),
                    json!(summary.all_pages_correctable),
                );
                fields.insert(
                    "erased_scope_verified".into(),
                    json!(summary.erased_scope_verified),
                );
                fields.insert(
                    "ordered_sweep_sha256".into(),
                    json!(summary.ordered_sweep_sha256),
                );
                fields.insert(
                    "block_summary_sha256".into(),
                    json!(hex::encode(Sha256::digest(&block_summary))),
                );
                fields.insert("exception_blocks".into(), json!(exceptions));
                fields.insert("exception_block_count".into(), json!(exception_count));
                fields.insert(
                    "exception_blocks_truncated".into(),
                    json!(exception_count > 256),
                );
                if salvage {
                    fields.insert("image_sha256".into(), json!(summary.image_sha256));
                    fields.insert("image_bytes".into(), json!(summary.image_bytes));
                }
                let complete = if salvage {
                    summary.all_addresses_readable && summary.all_pages_correctable
                } else {
                    summary.erased_scope_verified
                };
                fields.insert(
                    "status".into(),
                    json!(if complete { "ok" } else { "partial" }),
                );
                fields.insert(
                    "errors".into(),
                    json!(if complete {
                        0
                    } else if salvage {
                        summary
                            .unreadable_pages
                            .saturating_add(summary.ecc_unknown_pages)
                            .saturating_add(summary.uncorrectable_pages)
                    } else {
                        summary
                            .target_unreadable_pages
                            .saturating_add(summary.target_ecc_unknown_pages)
                            .saturating_add(summary.target_uncorrectable_pages)
                            .saturating_add(summary.target_non_erased_pages)
                            .max(
                                summary
                                    .unreadable_pages
                                    .saturating_add(summary.ecc_unknown_pages)
                                    .saturating_add(summary.uncorrectable_pages),
                            )
                    }),
                );
            }
            "rebuild-bbt-ftl" => {
                if state.service_mode != "in-service" {
                    return Err(Error::Permission(
                        "rebuild-bbt-ftl requires confirmed service mode".into(),
                    ));
                }
                let qualified = state
                    .blocks
                    .iter()
                    .filter(|block| block.disposition == BlockDisposition::Qualified)
                    .count() as u64;
                let quarantined = state
                    .blocks
                    .iter()
                    .filter(|block| {
                        matches!(
                            block.disposition,
                            BlockDisposition::Quarantined | BlockDisposition::HistoricalRuntimeBad
                        )
                    })
                    .count() as u64;
                let ratio_spare = ((qualified as f64) * profile.capacity.spare_ratio).ceil() as u64;
                let spare = u64::from(profile.capacity.minimum_spare_blocks)
                    .max(ratio_spare)
                    .max(quarantined.saturating_add(1));
                let mut user_blocks = qualified.checked_sub(spare).ok_or_else(|| {
                    Error::Backend(
                        "insufficient qualified NAND blocks for system and spare pools".into(),
                    )
                })?;
                let block_bytes = u64::from(geometry.pages_per_block)
                    .checked_mul(u64::from(geometry.page_bytes))
                    .ok_or_else(|| Error::Invalid("physical block byte size overflow".into()))?;
                if profile.capacity.bin_bytes > 0 {
                    let capacity = user_blocks
                        .checked_mul(block_bytes)
                        .ok_or_else(|| Error::Invalid("logical capacity overflow".into()))?;
                    let rounded = capacity
                        .checked_div(profile.capacity.bin_bytes)
                        .and_then(|quotient| quotient.checked_mul(profile.capacity.bin_bytes))
                        .ok_or_else(|| {
                            Error::Invalid("logical capacity rounding overflow".into())
                        })?;
                    user_blocks = rounded / block_bytes;
                }
                if user_blocks == 0 {
                    return Err(Error::Backend(
                        "capacity policy produced zero user blocks".into(),
                    ));
                }
                let metadata_pipeline = matches!(
                    state.phase.as_str(),
                    "metadata-prepare-started"
                        | "bbt-prepared"
                        | "ftl-prepared"
                        | "capacity-set"
                        | "metadata-activated"
                        | "metadata-commit-verified"
                );
                if metadata_pipeline {
                    if state.generation == 0
                        || state.user_blocks != user_blocks
                        || state.spare_blocks != spare
                    {
                        return Err(Error::Permission(
                            "durable metadata transaction no longer matches the block map or capacity policy"
                                .into(),
                        ));
                    }
                } else {
                    let (_, commit) = execute_named(
                        file,
                        controller_recipe,
                        artifacts,
                        "read-commit-state",
                        CommandContext::default(),
                        None,
                    )?;
                    command_idle(&commit)?;
                    state.generation = response_value(&commit, "generation")?
                        .checked_add(1)
                        .ok_or_else(|| Error::Invalid("metadata generation overflow".into()))?;
                    state.user_blocks = user_blocks;
                    state.spare_blocks = spare;
                }
                let bbt = recipe::build_bbt(&state, &controller_recipe.bbt_output, geometry)?;
                let ftl = recipe::build_ftl(
                    &state,
                    &bbt,
                    &controller_recipe.bbt_output,
                    &controller_recipe.ftl_output,
                )?;
                let mut committed_bbt = bbt.clone();
                committed_bbt[controller_recipe.bbt_output.commit_offset as usize] =
                    controller_recipe.bbt_output.commit_value;
                state.new_bbt_sha256 = hex::encode(Sha256::digest(&committed_bbt));
                let context = CommandContext {
                    generation: state.generation,
                    user_blocks,
                    spare_blocks: spare,
                    ..CommandContext::default()
                };
                if !matches!(
                    state.phase.as_str(),
                    "bbt-prepared"
                        | "ftl-prepared"
                        | "capacity-set"
                        | "metadata-activated"
                        | "metadata-commit-verified"
                ) {
                    state.phase = "metadata-prepare-started".into();
                    save_state(state_file, &mut state)?;
                    ambiguous_transport(
                        execute_named(
                            file,
                            controller_recipe,
                            artifacts,
                            "prepare-bbt",
                            context,
                            Some(&bbt),
                        ),
                        "prepare-bbt command",
                    )?;
                    ambiguous_transport(
                        wait_controller_idle(
                            file,
                            controller_recipe,
                            artifacts,
                            context,
                            events,
                            action,
                        ),
                        "prepare-bbt status",
                    )?;
                    state.phase = "bbt-prepared".into();
                    save_state(state_file, &mut state)?;
                }
                if !matches!(
                    state.phase.as_str(),
                    "ftl-prepared"
                        | "capacity-set"
                        | "metadata-activated"
                        | "metadata-commit-verified"
                ) {
                    ambiguous_transport(
                        execute_named(
                            file,
                            controller_recipe,
                            artifacts,
                            "prepare-ftl",
                            context,
                            Some(&ftl),
                        ),
                        "prepare-ftl command",
                    )?;
                    ambiguous_transport(
                        wait_controller_idle(
                            file,
                            controller_recipe,
                            artifacts,
                            context,
                            events,
                            action,
                        ),
                        "prepare-ftl status",
                    )?;
                    state.phase = "ftl-prepared".into();
                    save_state(state_file, &mut state)?;
                }
                if !matches!(
                    state.phase.as_str(),
                    "capacity-set" | "metadata-activated" | "metadata-commit-verified"
                ) {
                    let capacity_payload = recipe::build_capacity(
                        user_blocks,
                        block_bytes,
                        &controller_recipe.capacity_output,
                    )?;
                    ambiguous_transport(
                        execute_named(
                            file,
                            controller_recipe,
                            artifacts,
                            "set-capacity",
                            context,
                            Some(&capacity_payload),
                        ),
                        "set-capacity command",
                    )?;
                    ambiguous_transport(
                        wait_controller_idle(
                            file,
                            controller_recipe,
                            artifacts,
                            context,
                            events,
                            action,
                        ),
                        "set-capacity status",
                    )?;
                    state.phase = "capacity-set".into();
                    save_state(state_file, &mut state)?;
                }
                if !matches!(
                    state.phase.as_str(),
                    "metadata-activated" | "metadata-commit-verified"
                ) {
                    // Activation may have reached the controller even when
                    // the host lost its response. Query the signed generation
                    // before retrying the commit marker command.
                    ambiguous_transport(
                        wait_controller_idle(
                            file,
                            controller_recipe,
                            artifacts,
                            context,
                            events,
                            action,
                        ),
                        "metadata pre-activation status",
                    )?;
                    let (_, current_commit) = execute_named(
                        file,
                        controller_recipe,
                        artifacts,
                        "read-commit-state",
                        context,
                        None,
                    )?;
                    command_idle(&current_commit)?;
                    let already_committed = response_value(&current_commit, "generation")?
                        == state.generation
                        && response_value(&current_commit, "committed")? == 1;
                    if !already_committed {
                        ambiguous_transport(
                            execute_named(
                                file,
                                controller_recipe,
                                artifacts,
                                "activate-metadata",
                                context,
                                None,
                            ),
                            "activate-metadata command",
                        )?;
                        ambiguous_transport(
                            wait_controller_idle(
                                file,
                                controller_recipe,
                                artifacts,
                                context,
                                events,
                                action,
                            ),
                            "activate-metadata status",
                        )?;
                    }
                    state.phase = "metadata-activated".into();
                    save_state(state_file, &mut state)?;
                }
                let (committed_bbt, _) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-bbt",
                    CommandContext::default(),
                    None,
                )?;
                let decoded =
                    recipe::decode_old_bbt(&committed_bbt, &controller_recipe.bbt, geometry)?;
                let actual = decoded.into_iter().collect::<BTreeMap<_, _>>();
                for block in &state.blocks {
                    let expected = match block.disposition {
                        BlockDisposition::FactoryBad => Some(BlockDisposition::FactoryBad),
                        BlockDisposition::HistoricalRuntimeBad | BlockDisposition::Quarantined => {
                            Some(BlockDisposition::HistoricalRuntimeBad)
                        }
                        BlockDisposition::SystemPreserved | BlockDisposition::SystemRebuild => {
                            Some(BlockDisposition::SystemRebuild)
                        }
                        _ => None,
                    };
                    if actual.get(&block.flat).copied() != expected {
                        return Err(Error::Invalid(format!(
                            "committed BBT verification failed at block {}",
                            block.flat
                        )));
                    }
                }
                let (_, committed) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-commit-state",
                    context,
                    None,
                )?;
                command_idle(&committed)?;
                if response_value(&committed, "generation")? != state.generation
                    || response_value(&committed, "committed")? != 1
                {
                    return Err(Error::Invalid(
                        "metadata generation was not atomically committed".into(),
                    ));
                }
                state.phase = "metadata-commit-verified".into();
                save_state(state_file, &mut state)?;
                let expected_capacity = user_blocks
                    .checked_mul(block_bytes)
                    .ok_or_else(|| Error::Invalid("logical capacity overflow".into()))?;
                fields.insert("bbt_rebuilt".into(), json!(true));
                fields.insert("ftl_rebuilt".into(), json!(true));
                fields.insert("spare_pool_rebuilt".into(), json!(true));
                fields.insert("spare_ok".into(), json!(true));
                fields.insert("old_mapping_invalidated".into(), json!(true));
                fields.insert("ftl_generation".into(), json!(state.generation));
                fields.insert("bbt_generation".into(), json!(state.generation));
                fields.insert("expected_capacity_bytes".into(), json!(expected_capacity));
                fields.insert("capacity_bytes".into(), json!(expected_capacity));
                fields.insert("user_blocks".into(), json!(user_blocks));
                fields.insert("spare_blocks".into(), json!(spare));
                fields.insert("new_bbt_digest".into(), json!(state.new_bbt_sha256));
            }
            "exit-service-mode" => {
                if state.service_mode == "in-service" {
                    state.service_mode = "exit-command-pending".into();
                    state.phase = "service-exit-command-started".into();
                    save_state(state_file, &mut state)?;
                }
                if state.service_mode == "exit-command-pending" {
                    let (_, status) = execute_named(
                        file,
                        controller_recipe,
                        artifacts,
                        "read-status",
                        CommandContext::default(),
                        None,
                    )?;
                    command_idle(&status)?;
                    if response_value(&status, "service_mode")? != 0 {
                        ambiguous_transport(
                            execute_named(
                                file,
                                controller_recipe,
                                artifacts,
                                "exit-service-mode",
                                CommandContext {
                                    generation: state.generation,
                                    ..CommandContext::default()
                                },
                                None,
                            ),
                            "service-exit command",
                        )?;
                        if controller_recipe.policy.exit_reenumerates {
                            state.service_mode = "exit-reenumerating".into();
                            state.phase = "service-exit-command-sent".into();
                            save_state(state_file, &mut state)?;
                            fields.insert("awaiting_device".into(), json!(true));
                            fields.insert("reenumeration_stage".into(), json!("service-exit"));
                            fields.insert("service_mode".into(), json!(false));
                            fields.insert("state_sequence".into(), json!(state.sequence));
                            fields.insert("state_phase".into(), json!(state.phase));
                            return Ok(result(action, fields));
                        }
                    }
                } else if !matches!(state.service_mode.as_str(), "exit-reenumerating" | "normal") {
                    return Err(Error::Invalid(format!(
                        "cannot exit service mode from state {}",
                        state.service_mode
                    )));
                }
                let status = wait_controller_idle(
                    file,
                    controller_recipe,
                    artifacts,
                    CommandContext::default(),
                    events,
                    action,
                )?;
                if response_value(&status, "service_mode")? != 0 {
                    return Err(Error::Invalid(
                        "controller remained in service mode after exit".into(),
                    ));
                }
                state.service_mode = "normal".into();
                state.phase = "service-mode-exited".into();
                save_state(state_file, &mut state)?;
                fields.insert("service_mode".into(), json!(false));
            }
            "re-enumeration" => {
                let nonce = reenumeration_nonce.ok_or_else(|| {
                    Error::Invalid("re-enumeration action requires a nonce".into())
                })?;
                if nonce.is_empty()
                    || nonce.len() > 128
                    || !nonce.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(Error::Invalid("re-enumeration nonce is invalid".into()));
                }
                fields.insert("nonce".into(), json!(nonce));
                fields.insert("service_mode".into(), json!(false));
            }
            "postcheck-c3" | "postcheck-c4" => {
                let (_, status) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-status",
                    CommandContext::default(),
                    None,
                )?;
                command_idle(&status)?;
                // macOS quiesces the in-kernel logical-unit driver while
                // SCSITask exclusivity is held. Release it before the LBA
                // postcheck; Linux transport close is a no-op.
                file.close()?;
                let block_clone = block_file
                    .try_clone()
                    .map_err(|error| Error::io("clone controller block fd", Some(error)))?;
                let mut logical = LbaDevice::from_fd(block_clone.into(), false)?;
                let expected_blank = profile.logical_blank_value.ok_or_else(|| {
                    Error::Invalid("controller profile has no logical blank value".into())
                })?;
                let logical_result = backend_common::postcheck_p2(
                    &mut logical,
                    events,
                    "nclr-controller",
                    Some(expected_blank),
                )?;
                let logical_fields = logical_result.as_object().ok_or_else(|| {
                    Error::Invalid("controller logical postcheck result must be an object".into())
                })?;
                fields.extend(logical_fields.clone());
                fields.insert(
                    "spare_ok".into(),
                    json!(state.spare_blocks >= u64::from(profile.capacity.minimum_spare_blocks)),
                );
                fields.insert("unknown_reservation".into(), json!(0));
                fields.insert(
                    "service_mode".into(),
                    json!(response_value(&status, "service_mode")? != 0),
                );
            }
            other => {
                return Err(Error::Unsupported(format!(
                    "controller recipe engine does not implement action {other}"
                )))
            }
        }
        fields.insert("state_sequence".into(), json!(state.sequence));
        fields.insert("state_phase".into(), json!(state.phase));
        Ok(result(action, fields))
    }

    fn controller_status(
        file: &dyn CommandTransport,
        profile: &Profile,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        state_file: &mut std::fs::File,
    ) -> Result<Value> {
        let state = recipe::load_state(state_file)?;
        let (_, status) = execute_named(
            file,
            controller_recipe,
            artifacts,
            "read-status",
            CommandContext::default(),
            None,
        )?;
        let busy = response_value(&status, "busy")? != 0;
        let failed = response_value(&status, "failed")? != 0;
        Ok(json!({
            "api": PROTOCOL_API,
            "ok": !failed,
            "backend": "controller",
            "version": VERSION,
            "state": if failed { "failed" } else if busy { "in-progress" } else { "ready" },
            "progress": status.get("progress").copied(),
            "service_mode": response_value(&status, "service_mode")? != 0,
            "controller_phase": state.as_ref().map(|value| value.phase.as_str()),
            "controller_state_sequence": state.as_ref().map(|value| value.sequence),
            "profile": profile.id,
        }))
    }

    fn recover_controller(
        file: &dyn CommandTransport,
        profile: &Profile,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        state_file: &mut std::fs::File,
    ) -> Result<Value> {
        let mut state = recipe::load_state(state_file)?
            .ok_or_else(|| Error::Invalid("controller recovery state is absent".into()))?;
        let (_, status) = execute_named(
            file,
            controller_recipe,
            artifacts,
            "read-status",
            CommandContext::default(),
            None,
        )?;
        if response_value(&status, "busy")? != 0 {
            return Err(Error::Interrupted(
                "controller operation is still running; recovery did not issue another command"
                    .into(),
            ));
        }
        let commit_started = matches!(
            state.phase.as_str(),
            "metadata-prepare-started"
                | "bbt-prepared"
                | "ftl-prepared"
                | "capacity-set"
                | "metadata-activated"
        );
        if commit_started {
            let (_, commit) = execute_named(
                file,
                controller_recipe,
                artifacts,
                "read-commit-state",
                CommandContext {
                    generation: state.generation,
                    ..CommandContext::default()
                },
                None,
            )?;
            if response_value(&commit, "committed")? == 1
                && response_value(&commit, "generation")? == state.generation
            {
                state.phase = "metadata-commit-verified".into();
            } else if state.phase == "metadata-activated" {
                return Err(Error::Backend("metadata activation is ambiguous; refusing reset until the certified recovery procedure resolves it".into()));
            }
        }
        let method = controller::select_recovery(&profile.recovery.method);
        match method {
            controller::RecoveryAction::ControllerReset
            | controller::RecoveryAction::FirmwareBootstrap => {
                execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "reset-controller",
                    CommandContext::default(),
                    None,
                )?;
                state.service_mode = "normal".into();
                state.phase = "recovered".into();
                state.in_flight = None;
                save_state(state_file, &mut state)?;
            }
            controller::RecoveryAction::UsbReset | controller::RecoveryAction::PowerCycle => {
                return Err(Error::Interrupted(format!(
                    "profile recovery requires external action {method:?}"
                )));
            }
            controller::RecoveryAction::Manual => {
                return Err(Error::Permission(
                    "profile has no automated recovery procedure".into(),
                ));
            }
        }
        Ok(json!({
            "api": PROTOCOL_API,
            "ok": true,
            "backend": "controller",
            "version": VERSION,
            "recovery": format!("{method:?}"),
            "automated": true,
            "state_phase": state.phase,
        }))
    }

    fn usb_family_hint(request: &Value) -> Option<Family> {
        let vid = request.get("device")?.get("usb")?.get("vid")?.as_str()?;
        let vid = u16::from_str_radix(vid.trim_start_matches("0x"), 16).ok()?;
        let profiles = profile::load_identify_profiles(&[]);
        profile::family_hint_from_vid(vid, &profiles)
    }

    /// Probe only the family selected by a vendor-owned USB VID. Every
    /// successful path validates a controller response signature before it
    /// returns an identity. The identification profile supplies the probe
    /// parameters (vendor id hints, INQUIRY marker).
    fn vendor_identity(
        file: &dyn CommandTransport,
        hint: Option<Family>,
        standard_inquiry: &[u8],
        attempted: &mut Vec<Value>,
    ) -> Result<Option<ControllerIdentity>> {
        let profiles = profile::load_identify_profiles(&[]);
        let mut marker = None;
        for candidate in profiles.iter().filter(|profile| {
            hint.is_none_or(|family| profile.family == family.as_str())
                && profile.inquiry_marker.is_some()
        }) {
            let candidate = candidate
                .inquiry_marker
                .as_ref()
                .expect("filtered marker exists");
            if marker
                .as_ref()
                .is_some_and(|existing| existing != candidate)
            {
                return Err(Error::Invalid(
                    "conflicting standard-INQUIRY marker profiles are installed".into(),
                ));
            }
            marker = Some(candidate.clone());
        }
        match hint {
            Some(Family::UsbestUfd) => {
                let marker = marker.ok_or_else(|| {
                    Error::Invalid("USBest UT163 identification requires an inquiry marker".into())
                })?;
                Ok(Some(vendor::parse_inquiry_marker(
                    standard_inquiry,
                    &marker,
                )?))
            }
            Some(family) => vendor::identify_with(family, marker.as_ref(), |cdb, len| {
                attempted.push(json!({
                    "transport": "scsi",
                    "cdb_hex": hex::encode(cdb),
                    "direction": "from-device",
                    "transfer_bytes": len,
                    "source": "compiled-read-only-probe",
                }));
                scsi_command(file, cdb, TransferDirection::FromDevice, len)
            }),
            // No vendor-owned VID hint: inspect the controller signature in
            // the standard INQUIRY response already obtained above. No
            // additional command is sent.
            None => {
                let inquiry_marker = marker.as_ref();
                if let Some(marker) = inquiry_marker {
                    if let Ok(identity) = vendor::parse_inquiry_marker(standard_inquiry, marker) {
                        return Ok(Some(identity));
                    }
                }
                // A VID-less device (OEM rebrand) can still answer the
                // public Alcor flash-ID read (FA 00). Only a valid 6-byte
                // NAND id identifies the family; anything else (including a
                // CHECK CONDITION) simply does not match and is harmless.
                vendor::identify_with(Family::AlcorUfd, None, |cdb, len| {
                    attempted.push(json!({
                        "transport": "scsi",
                        "cdb_hex": hex::encode(cdb),
                        "direction": "from-device",
                        "transfer_bytes": len,
                        "source": "compiled-read-only-probe",
                    }));
                    scsi_command(file, cdb, TransferDirection::FromDevice, len)
                })
            }
        }
    }

    fn same_loaded_profile(left: &Profile, right: &Profile) -> bool {
        left.id == right.id && left.sha256.is_some() && left.sha256 == right.sha256
    }

    /// Find the first production-trust profile that matches the device.
    fn matching_production_profile(
        dirs: &[std::path::PathBuf],
        controller_id: &str,
        firmware: &str,
        nand_id: Option<&str>,
    ) -> Result<Option<Profile>> {
        let mut found: Option<Profile> = None;
        for dir in dirs {
            let rd = match std::fs::read_dir(dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(Error::io(
                        format!("read trusted profile directory {}", dir.display()),
                        Some(e),
                    ));
                }
            };
            for entry in rd {
                let e = entry.map_err(|err| {
                    Error::io(
                        format!("read entry in trusted profile directory {}", dir.display()),
                        Some(err),
                    )
                })?;
                let path = e.path();
                if !profile::is_runtime_profile_path(&path) {
                    continue;
                }
                let p = profile::load(&path)?;
                let profile_nand = p.nand_id.min.as_deref().unwrap_or_default();
                let identity_matches = nand_id.map_or_else(
                    || p.matches(controller_id, firmware, profile_nand),
                    |nand_id| p.matches(controller_id, firmware, nand_id),
                );
                if p.destructive_allowed() && identity_matches {
                    if let Some(existing) = &found {
                        if same_loaded_profile(existing, &p) {
                            continue;
                        }
                        return Err(Error::Invalid(format!(
                            "multiple production profiles match controller {controller_id} fw {firmware} NAND {}: {} and {}",
                            nand_id.unwrap_or("(any)"),
                            existing.id,
                            p.id
                        )));
                    }
                    found = Some(p);
                }
            }
        }
        Ok(found)
    }

    fn usb_hex_value(request: &Value, field: &str, bcd: bool) -> Result<u16> {
        let value = request
            .get("device")
            .and_then(|device| device.get("usb"))
            .and_then(|usb| usb.get(field))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Invalid(format!("USB {field} is absent")))?;
        let value = value.trim_start_matches("0x");
        let normalized = if bcd {
            value
                .chars()
                .filter(|character| *character != '.')
                .collect()
        } else {
            value.to_string()
        };
        if normalized.is_empty() || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Invalid(format!("USB {field} is not hexadecimal")));
        }
        u16::from_str_radix(&normalized, 16)
            .map_err(|_| Error::Invalid(format!("USB {field} is out of range")))
    }

    fn usb_string_value<'a>(request: &'a Value, field: &str) -> Result<&'a str> {
        request
            .get("device")
            .and_then(|device| device.get("usb"))
            .and_then(|usb| usb.get(field))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Invalid(format!("USB {field} is absent")))
    }

    #[cfg(target_os = "macos")]
    fn macos_expected_usb(
        request: &Value,
    ) -> Result<Option<nclr::macos_usb_bot::ExpectedUsbDevice>> {
        if request
            .get("device")
            .and_then(|device| device.get("usb"))
            .is_none()
        {
            return Ok(None);
        }
        let physical_path = request
            .get("device")
            .and_then(|device| device.get("physical_path"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Invalid("macOS USB physical_path is absent".into()))?;
        let location = physical_path.strip_prefix("macos-usb:").ok_or_else(|| {
            Error::Permission(format!(
                "macOS USB physical path does not carry an IOKit location id: {physical_path}"
            ))
        })?;
        if location.len() != 8 || !location.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Invalid(format!(
                "macOS USB IOKit location id is invalid: {location}"
            )));
        }
        Ok(Some(nclr::macos_usb_bot::ExpectedUsbDevice {
            vendor_id: usb_hex_value(request, "vid", false)?,
            product_id: usb_hex_value(request, "pid", false)?,
            release_number: usb_hex_value(request, "bcd_device", true)?,
            location_id: Some(u32::from_str_radix(location, 16).map_err(|_| {
                Error::Invalid("macOS USB IOKit location id is out of range".into())
            })?),
        }))
    }

    /// Select only the artifact set needed for a recipe-owned identity
    /// command. USB and INQUIRY data are not authorization; destructive use
    /// remains disabled until the recipe response is verified.
    fn matching_bootstrap_profile(
        dirs: &[std::path::PathBuf],
        request: &Value,
        inquiry: &nclr::scsi::Inquiry,
    ) -> Result<Option<Profile>> {
        let usb_vid = usb_hex_value(request, "vid", false)?;
        let usb_pid = usb_hex_value(request, "pid", false)?;
        let usb_bcd_device = usb_hex_value(request, "bcd_device", true)?;
        let usb_manufacturer = usb_string_value(request, "manufacturer")?;
        let usb_product = usb_string_value(request, "product")?;
        let usb_serial = usb_string_value(request, "serial")?;
        let mut found: Option<Profile> = None;
        for dir in dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(Error::io(
                        format!("read trusted profile directory {}", dir.display()),
                        Some(error),
                    ))
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    Error::io(
                        format!("read entry in trusted profile directory {}", dir.display()),
                        Some(error),
                    )
                })?;
                if !profile::is_runtime_profile_path(&entry.path()) {
                    continue;
                }
                let candidate = profile::load(&entry.path())?;
                let matches = candidate
                    .controller_bootstrap
                    .as_ref()
                    .is_some_and(|bootstrap| {
                        bootstrap.usb_vid == usb_vid
                            && bootstrap.usb_pid == usb_pid
                            && bootstrap.usb_bcd_device == usb_bcd_device
                            && bootstrap.usb_manufacturer == usb_manufacturer
                            && bootstrap.usb_product == usb_product
                            && bootstrap.usb_serial == usb_serial
                            && bootstrap.scsi_vendor == inquiry.vendor_id
                            && bootstrap.scsi_product == inquiry.product_id
                            && bootstrap.scsi_revision == inquiry.product_rev
                    });
                if !candidate.destructive_allowed() || !matches {
                    continue;
                }
                if let Some(existing) = &found {
                    if same_loaded_profile(existing, &candidate) {
                        continue;
                    }
                    return Err(Error::Invalid(format!(
                        "multiple production profiles match the exact USB descriptor and SCSI bootstrap tuple {:04x}:{:04x}:{:04x} {}/{}/{}: {} and {}",
                        usb_vid,
                        usb_pid,
                        usb_bcd_device,
                        inquiry.vendor_id,
                        inquiry.product_id,
                        inquiry.product_rev,
                        existing.id,
                        candidate.id
                    )));
                }
                found = Some(candidate);
            }
        }
        Ok(found)
    }

    /// Resolve the profile pinned by inherited runtime artifact roles. This
    /// is the durable continuation path after service firmware changes the
    /// normal-mode identity response. Artifact bytes are verified against the
    /// selected profile before the profile can be used.
    fn matching_artifact_profile(
        dirs: &[std::path::PathBuf],
        artifact_ids: &[String],
        files: &mut [(String, std::fs::File)],
    ) -> Result<Option<Profile>> {
        if artifact_ids.is_empty() {
            return Ok(None);
        }
        let mut found: Option<Profile> = None;
        for dir in dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(Error::io(
                        format!("read trusted profile directory {}", dir.display()),
                        Some(error),
                    ))
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    Error::io(
                        format!("read entry in trusted profile directory {}", dir.display()),
                        Some(error),
                    )
                })?;
                if !profile::is_runtime_profile_path(&entry.path()) {
                    continue;
                }
                let candidate = profile::load(&entry.path())?;
                let candidate_ids = candidate
                    .implementation
                    .as_ref()
                    .map(|implementation| implementation.artifact_ids.as_slice())
                    .unwrap_or_default();
                if !candidate.destructive_allowed() || candidate_ids != artifact_ids {
                    continue;
                }
                let mut artifacts_match = true;
                for ((role, file), id) in files.iter_mut().zip(artifact_ids) {
                    let expected_role = format!("artifact:{id}");
                    let Some(spec) = candidate.artifacts.iter().find(|spec| spec.id == *id) else {
                        artifacts_match = false;
                        break;
                    };
                    if role != &expected_role {
                        artifacts_match = false;
                        break;
                    }
                    let display = std::path::PathBuf::from(format!(
                        "inherited-fd:{role}:candidate:{}",
                        candidate.id
                    ));
                    match nclr::artifact::verify_open_file(file, &display, spec) {
                        Ok(_) => {}
                        Err(Error::Invalid(_) | Error::Permission(_)) => {
                            artifacts_match = false;
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                }
                if !artifacts_match || files.len() != artifact_ids.len() {
                    continue;
                }
                if let Some(existing) = &found {
                    if same_loaded_profile(existing, &candidate) {
                        continue;
                    }
                    return Err(Error::Invalid(format!(
                        "runtime artifact roles match multiple production profiles: {} and {}",
                        existing.id, candidate.id
                    )));
                }
                found = Some(candidate);
            }
        }
        Ok(found)
    }

    fn verify_recipe_hardware_identity(
        file: &dyn CommandTransport,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        profile: &Profile,
        detected: &ControllerIdentity,
    ) -> Result<String> {
        if controller_recipe.family != detected.family.recipe_str()
            || detected.controller_id != profile.controller_id
            || profile.firmware.min.as_deref() != Some(detected.firmware.as_str())
        {
            return Err(Error::Permission(
                "runtime recipe family or controller identity does not match the signed normal-mode response"
                    .into(),
            ));
        }
        let expected = recipe::exact_nand_id_bytes(&controller_recipe.nand_id)?;
        let actual = match detected.nand_id.as_deref() {
            Some(value) => recipe::exact_nand_id_bytes(value)?,
            None => {
                let (payload, _) = execute_named(
                    file,
                    controller_recipe,
                    artifacts,
                    "read-nand-id",
                    CommandContext::default(),
                    None,
                )?;
                payload
            }
        };
        if actual != expected {
            return Err(Error::Permission(format!(
                "runtime NAND identity {} does not match recipe {}",
                hex::encode(actual),
                hex::encode(expected)
            )));
        }
        Ok(hex::encode(expected))
    }

    fn verify_recipe_bootstrap_identity(
        file: &dyn CommandTransport,
        controller_recipe: &ControllerRecipe,
        artifacts: &mut [(String, std::fs::File)],
        profile: &Profile,
    ) -> Result<ControllerIdentity> {
        let bootstrap = profile.controller_bootstrap.as_ref().ok_or_else(|| {
            Error::Permission("runtime recipe has no controller bootstrap profile".into())
        })?;
        if controller_recipe.family != bootstrap.family {
            return Err(Error::Permission(
                "runtime recipe family does not match the controller bootstrap profile".into(),
            ));
        }
        let family = vendor::family_from_recipe_str(&bootstrap.family).ok_or_else(|| {
            Error::Invalid("controller bootstrap family is not implemented".into())
        })?;
        let expected_controller = recipe::exact_controller_identity_bytes(controller_recipe)?;
        let (actual_controller, _) = execute_named(
            file,
            controller_recipe,
            artifacts,
            "read-controller-id",
            CommandContext::default(),
            None,
        )?;
        if actual_controller != expected_controller {
            return Err(Error::Permission(format!(
                "runtime controller identity {} does not match recipe {}",
                hex::encode(actual_controller),
                hex::encode(expected_controller)
            )));
        }
        let expected_nand = recipe::exact_nand_id_bytes(&controller_recipe.nand_id)?;
        let (actual_nand, _) = execute_named(
            file,
            controller_recipe,
            artifacts,
            "read-nand-id",
            CommandContext::default(),
            None,
        )?;
        if actual_nand != expected_nand {
            return Err(Error::Permission(format!(
                "runtime NAND identity {} does not match recipe {}",
                hex::encode(actual_nand),
                hex::encode(expected_nand)
            )));
        }
        Ok(ControllerIdentity {
            family,
            controller_id: controller_recipe.controller_id.clone(),
            firmware: controller_recipe.firmware.clone(),
            nand_id: Some(hex::encode(expected_nand)),
            mode: "firmware".into(),
        })
    }

    /// Validate an inherited sg fd against the SCSI device object reached by
    /// the block fd. Block and sg nodes have different inodes and device
    /// numbers, so their canonical sysfs `device` targets must match.
    #[cfg(target_os = "linux")]
    fn validate_sg_fd(block_fd: &std::fs::File, sg_fd: &std::fs::File) -> Result<()> {
        use std::os::fd::AsRawFd;
        let bdev = scsi_device_of_fd(block_fd.as_raw_fd(), libc::S_IFBLK)?;
        let sdev = scsi_device_of_fd(sg_fd.as_raw_fd(), libc::S_IFCHR)?;
        if bdev == sdev {
            Ok(())
        } else {
            Err(Error::Permission(format!(
                "sg fd SCSI device {} does not match block fd SCSI device {}",
                sdev.display(),
                bdev.display()
            )))
        }
    }

    #[cfg(target_os = "linux")]
    fn scsi_device_of_fd(fd: i32, expected_kind: libc::mode_t) -> Result<std::path::PathBuf> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(Error::io(
                "fstat on inherited fd",
                Some(std::io::Error::last_os_error()),
            ));
        }
        if st.st_mode & libc::S_IFMT != expected_kind {
            return Err(Error::Permission(format!(
                "inherited fd {fd} has unexpected device-node type"
            )));
        }
        let class = if expected_kind == libc::S_IFBLK {
            "block"
        } else {
            "char"
        };
        let node = std::path::PathBuf::from(format!(
            "/sys/dev/{class}/{}:{}/device",
            libc::major(st.st_rdev),
            libc::minor(st.st_rdev)
        ));
        std::fs::canonicalize(&node).map_err(|e| {
            Error::io(
                format!("resolve inherited fd {fd} through {}", node.display()),
                Some(e),
            )
        })
    }

    #[cfg(target_os = "macos")]
    fn macos_disk_path(file: &std::fs::File) -> Result<String> {
        use std::ffi::CStr;
        use std::os::fd::AsRawFd;
        let mut path = [0i8; libc::PATH_MAX as usize];
        let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) };
        if result != 0 {
            return Err(Error::io(
                "resolve inherited macOS disk descriptor",
                Some(std::io::Error::last_os_error()),
            ));
        }
        let path = unsafe { CStr::from_ptr(path.as_ptr()) }
            .to_str()
            .map_err(|_| Error::Invalid("inherited macOS disk path is not UTF-8".into()))?;
        let normalized = path
            .strip_prefix("/dev/rdisk")
            .or_else(|| path.strip_prefix("/dev/disk"))
            .ok_or_else(|| {
                Error::Permission(format!(
                    "inherited descriptor does not name a whole macOS disk: {path}"
                ))
            })?;
        if normalized.is_empty() || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Permission(format!(
                "inherited descriptor does not name a whole macOS disk: {path}"
            )));
        }
        Ok(format!("/dev/disk{normalized}"))
    }

    pub fn platform_main() {
        let invocation = match nclr::backend::parse_backend_args() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("nclr-controller: {e}");
                std::process::exit(64);
            }
        };
        let request = match nclr::backend::read_request(invocation.request_fd) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("nclr-controller: {e}");
                std::process::exit(78);
            }
        };
        let op = invocation.op.as_str();
        let mut events = BackendEvents::open(invocation.events_fd);

        let block_fd = unsafe { std::fs::File::from_raw_fd(FD_DEVICE) };
        // Linux receives an associated sg descriptor first. macOS resolves
        // the inherited whole-disk descriptor to its SCSITask service and
        // therefore starts auxiliary artifact descriptors directly at fd 6.
        let declarations: Vec<(i32, String)> = request
            .get("extra_fds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some((
                            i32::try_from(e.get("fd")?.as_i64()?).ok()?,
                            e.get("role")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let transport_prefix = usize::from(cfg!(target_os = "linux"));
        let transport_layout_valid = if cfg!(target_os = "linux") {
            declarations.first() == Some(&(nclr::backend::FD_EXTRA_BASE, "sg".to_string()))
        } else {
            declarations.iter().all(|(_, role)| role != "sg")
        };
        if !transport_layout_valid
            || declarations.iter().enumerate().any(|(index, (fd, role))| {
                *fd != nclr::backend::FD_EXTRA_BASE + index as i32
                    || (index >= transport_prefix
                        && !role.starts_with("artifact:")
                        && !matches!(
                            role.as_str(),
                            "controller-state" | "physical-image" | "physical-map"
                        ))
            })
            || declarations
                .iter()
                .filter(|(_, role)| role == "controller-state")
                .count()
                > 1
            || declarations
                .iter()
                .filter(|(_, role)| role == "physical-image")
                .count()
                > 1
            || declarations
                .iter()
                .filter(|(_, role)| role == "physical-map")
                .count()
                > 1
            || (declarations
                .iter()
                .any(|(_, role)| role == "physical-image")
                != declarations.iter().any(|(_, role)| role == "physical-map"))
        {
            backend_common::respond_err(
                "controller",
                &Error::Invalid(
                    "platform transport descriptors must be followed by contiguous artifact, controller-state or paired physical-output fds"
                        .into(),
                ),
            );
        }
        #[cfg(target_os = "linux")]
        let command_transport: Box<dyn CommandTransport> = {
            let sg_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(nclr::backend::FD_EXTRA_BASE) };
            let sg_file = std::fs::File::from(sg_fd);
            if let Err(error) = validate_sg_fd(&block_fd, &sg_file) {
                backend_common::respond_err("controller", &error);
            }
            Box::new(sg_file)
        };
        #[cfg(target_os = "macos")]
        let command_transport: Box<dyn CommandTransport> = {
            let disk_path = match macos_disk_path(&block_fd) {
                Ok(path) => path,
                Err(error) => backend_common::respond_err("controller", &error),
            };
            let expected_usb = match macos_expected_usb(&request) {
                Ok(expected) => expected,
                Err(error) => backend_common::respond_err("controller", &error),
            };
            Box::new(MacCommandTransport::new(disk_path, expected_usb))
        };
        let mut artifact_files = Vec::new();
        let mut state_file = None;
        let mut physical_image = None;
        let mut physical_map = None;
        for (fd, role) in declarations.iter().skip(transport_prefix) {
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(*fd) };
            let file = std::fs::File::from(owned);
            if role == "controller-state" {
                state_file = Some(file);
            } else if role == "physical-image" {
                physical_image = Some(file);
            } else if role == "physical-map" {
                physical_map = Some(file);
            } else {
                artifact_files.push((role.clone(), file));
            }
        }
        let command_file = command_transport.as_ref();

        // Normal mode requires standard INQUIRY. A controller can stop
        // answering it after an authenticated service-mode transition, so
        // preserve the failure until the durable recipe state is checked.
        let (scsi_inquiry, standard_inquiry, scsi_inquiry_error) = match scsi_identity(command_file)
        {
            Ok((inquiry, bytes)) => (Some(inquiry), bytes, None),
            Err(error) => (None, Vec::new(), Some(error.to_string())),
        };

        let family_hint = usb_family_hint(&request);
        // Both destructive profiles and read-only probe profiles are loaded
        // only from package-managed locations. User-controlled directories
        // cannot cause a vendor CDB to be sent.
        let dirs = profile::trusted_search_dirs();
        let mut media_commands_sent = vec![json!({
            "transport": "scsi",
            "cdb_hex": hex::encode(scsi::cdb_inquiry(false, 0, 96)),
            "direction": "from-device",
            "transfer_bytes": 96,
            "source": "standard-inquiry",
        })];
        let observed_probe = if request.get("device").is_some() {
            scsi_inquiry
                .as_ref()
                .map(|scsi_inquiry| {
                    (|| -> Result<ObservedBootstrap<'_>> {
                        Ok(ObservedBootstrap {
                            usb_vid: usb_hex_value(&request, "vid", false)?,
                            usb_pid: usb_hex_value(&request, "pid", false)?,
                            usb_bcd_device: usb_hex_value(&request, "bcd_device", true)?,
                            usb_manufacturer: usb_string_value(&request, "manufacturer")?,
                            usb_product: usb_string_value(&request, "product")?,
                            usb_serial: usb_string_value(&request, "serial")?,
                            scsi_vendor: &scsi_inquiry.vendor_id,
                            scsi_product: &scsi_inquiry.product_id,
                            scsi_revision: &scsi_inquiry.product_rev,
                        })
                    })()
                })
                .transpose()
                .unwrap_or_else(|error| backend_common::respond_err("controller", &error))
        } else {
            None
        };
        let read_only_probe = match observed_probe.as_ref() {
            Some(observed) => match controller_probe::matching(&dirs, observed, family_hint) {
                Ok(profile) => profile,
                Err(error) => backend_common::respond_err("controller", &error),
            },
            None => None,
        };
        let probe_profile_id = read_only_probe.as_ref().map(|profile| profile.id.clone());
        let probe_profile_sha256 = read_only_probe
            .as_ref()
            .map(|profile| profile.source_sha256.clone());
        let (detected, probe_error) = if let Some(probe) = read_only_probe.as_ref() {
            match controller_probe::execute_with(probe, |name, cdb, len, timeout_ms| {
                media_commands_sent.push(json!({
                    "transport": "scsi",
                    "cdb_hex": hex::encode(cdb),
                    "direction": "from-device",
                    "transfer_bytes": len,
                    "source": "package-read-only-probe-profile",
                    "probe_profile": probe.id,
                    "command": name,
                }));
                scsi_command_timeout(
                    command_file,
                    cdb,
                    TransferDirection::FromDevice,
                    len,
                    timeout_ms,
                )
            }) {
                Ok(identity) => (Some(identity), None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else if scsi_inquiry.is_some() {
            match vendor_identity(
                command_file,
                family_hint,
                &standard_inquiry,
                &mut media_commands_sent,
            ) {
                Ok(identity) => (identity, None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, scsi_inquiry_error.clone())
        };
        let mut controller_id = detected
            .as_ref()
            .map(|i| i.controller_id.clone())
            .unwrap_or_else(|| "unidentified".into());
        let mut firmware = detected
            .as_ref()
            .map(|i| i.firmware.clone())
            .unwrap_or_else(|| "unidentified".into());
        let mut nand_id = detected
            .as_ref()
            .and_then(|i| i.nand_id.clone())
            .unwrap_or_else(|| "unidentified".into());

        let matched_by_identity = match detected.as_ref() {
            Some(identity) => match matching_production_profile(
                &dirs,
                &identity.controller_id,
                &identity.firmware,
                identity.nand_id.as_deref(),
            ) {
                Ok(profile) => profile,
                Err(e) => backend_common::respond_err("controller", &e),
            },
            None => None,
        };
        let matched_by_bootstrap = if request.get("device").is_some() {
            if let Some(scsi_inquiry) = scsi_inquiry.as_ref() {
                match matching_bootstrap_profile(&dirs, &request, scsi_inquiry) {
                    Ok(profile) => profile,
                    Err(e) => backend_common::respond_err("controller", &e),
                }
            } else {
                None
            }
        } else {
            None
        };
        if matched_by_identity
            .as_ref()
            .zip(matched_by_bootstrap.as_ref())
            .is_some_and(|(identity, bootstrap)| {
                identity.id != bootstrap.id || identity.sha256 != bootstrap.sha256
            })
        {
            backend_common::respond_err(
                "controller",
                &Error::Permission(
                    "controller identity and USB/SCSI bootstrap select different production profiles"
                        .into(),
                ),
            );
        }
        let declared_artifact_ids = declarations
            .iter()
            .filter_map(|(_, role)| role.strip_prefix("artifact:").map(str::to_string))
            .collect::<Vec<_>>();
        let matched_by_artifacts =
            match matching_artifact_profile(&dirs, &declared_artifact_ids, &mut artifact_files) {
                Ok(profile) => profile,
                Err(e) => backend_common::respond_err("controller", &e),
            };
        for selected in [matched_by_identity.as_ref(), matched_by_bootstrap.as_ref()]
            .into_iter()
            .flatten()
        {
            if matched_by_artifacts.as_ref().is_some_and(|artifacts| {
                selected.id != artifacts.id || selected.sha256 != artifacts.sha256
            }) {
                backend_common::respond_err(
                    "controller",
                    &Error::Permission(
                        "normal-mode selection and inherited artifacts select different production profiles"
                            .into(),
                    ),
                );
            }
        }
        let bootstrap_family = matched_by_bootstrap
            .as_ref()
            .and_then(|profile| profile.controller_bootstrap.as_ref())
            .and_then(|bootstrap| vendor::family_from_recipe_str(&bootstrap.family));
        if detected
            .as_ref()
            .zip(bootstrap_family)
            .is_some_and(|(identity, family)| identity.family != family)
        {
            backend_common::respond_err(
                "controller",
                &Error::Permission(
                    "signed controller identity conflicts with the USB/SCSI bootstrap family"
                        .into(),
                ),
            );
        }
        let bootstrap_selected = matched_by_bootstrap.is_some();
        let matched = matched_by_artifacts
            .or(matched_by_identity)
            .or(matched_by_bootstrap);
        // A bootstrap match may describe the recipe engine so planning can
        // request its immutable artifacts. It cannot make the driver
        // executable; that requires a signed built-in or recipe response.
        let support = detected
            .as_ref()
            .map(|identity| vendor::support(identity.family))
            .or_else(|| bootstrap_family.map(vendor::support))
            .or_else(|| family_hint.map(vendor::support));
        let profile_id = matched.as_ref().map(|p| p.id.clone());
        let rebuilds = matched
            .as_ref()
            .map(|p| p.rebuilds.clone())
            .unwrap_or_default();
        let capacity_policy = match matched.as_ref() {
            Some(p) => match serde_json::to_value(&p.capacity) {
                Ok(v) => v,
                Err(e) => backend_common::respond_err(
                    "controller",
                    &Error::Invalid(format!("capacity policy serialization: {e}")),
                ),
            },
            None => Value::Null,
        };
        let runtime_artifacts = matched
            .as_ref()
            .and_then(|p| p.implementation.as_ref().map(|i| (p, i)))
            .map(|(profile, implementation)| {
                implementation
                    .artifact_ids
                    .iter()
                    .filter_map(|id| profile.artifacts.iter().find(|a| &a.id == id))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !artifact_files.is_empty() {
            if artifact_files.len() != runtime_artifacts.len() {
                backend_common::respond_err(
                    "controller",
                    &Error::Invalid(format!(
                        "received {} artifact fds but profile requires {}",
                        artifact_files.len(),
                        runtime_artifacts.len()
                    )),
                );
            }
            for ((role, file), spec) in artifact_files.iter_mut().zip(&runtime_artifacts) {
                let expected_role = format!("artifact:{}", spec.id);
                if role != &expected_role {
                    backend_common::respond_err(
                        "controller",
                        &Error::Invalid(format!(
                            "artifact fd role {role} does not match {expected_role}"
                        )),
                    );
                }
                let display = std::path::PathBuf::from(format!("inherited-fd:{role}"));
                if let Err(e) = nclr::artifact::verify_open_file(file, &display, spec) {
                    backend_common::respond_err("controller", &e);
                }
            }
        }

        let recipe_spec = matched.as_ref().zip(
            runtime_artifacts
                .iter()
                .find(|artifact| artifact.kind == nclr::artifact::ArtifactKind::ProtocolRecipe),
        );
        // Profile validation already requires exactly one runtime recipe for
        // every real production tuple. Keep the execution boundary explicit
        // here as well: a future profile-format regression must not turn a
        // tuple with no executable protocol description into a C3/C4 plan.
        let runtime_recipe_declared = recipe_spec.is_some();
        let recipe_sha256 = recipe_spec.as_ref().map(|(_, spec)| {
            spec.sha256
                .trim_start_matches("sha256:")
                .to_ascii_lowercase()
        });
        let mut loaded_recipe: Option<ControllerRecipe> = None;
        let mut recipe_artifact_error = None;
        if let Some((profile, spec)) = recipe_spec {
            let role = format!("artifact:{}", spec.id);
            let file = artifact_files
                .iter_mut()
                .find(|(candidate, _)| candidate == &role)
                .map(|(_, file)| file)
                .ok_or_else(|| {
                    Error::Permission(format!(
                        "protocol recipe artifact {} was not inherited",
                        spec.id
                    ))
                });
            match file {
                Ok(file) => match recipe::load_reader(file, spec.format.clone()).and_then(|value| {
                    recipe::validate(&value, profile)?;
                    Ok(value)
                }) {
                    Ok(value) => loaded_recipe = Some(value),
                    Err(e) => backend_common::respond_err("controller", &e),
                },
                // A recipe file is optional at probe/plan time. Its absence
                // is reported explicitly while the immutable requirement is
                // still advertised for a later run.
                Err(e) if matches!(op, "probe" | "plan") => {
                    recipe_artifact_error = Some(e.to_string());
                }
                Err(e) => backend_common::respond_err("controller", &e),
            }
        }
        let recipe_state = match (
            matched.as_ref(),
            loaded_recipe.as_ref(),
            recipe_sha256.as_deref(),
            state_file.as_mut(),
        ) {
            (Some(profile), Some(_), Some(recipe_sha256), Some(state_file)) => {
                match recipe::load_state(state_file) {
                    Ok(Some(state)) => {
                        let request_plan_hash = request
                            .get("params")
                            .and_then(|params| params.get("plan_hash"))
                            .and_then(|value| value.as_str())
                            .unwrap_or(state.plan_hash.as_str());
                        if let Err(error) =
                            state.verify_binding(request_plan_hash, profile, recipe_sha256)
                        {
                            backend_common::respond_err("controller", &error);
                        }
                        Some(state)
                    }
                    Ok(None) => None,
                    Err(error) => backend_common::respond_err("controller", &error),
                }
            }
            _ => None,
        };
        let service_state_bound = match recipe_state
            .as_ref()
            .map(ControllerRunState::service_mode_transition_active)
            .transpose()
        {
            Ok(value) => value.unwrap_or(false),
            Err(error) => backend_common::respond_err("controller", &error),
        };
        if let Err(error) = validate_inquiry_continuation(
            scsi_inquiry.is_some(),
            service_state_bound,
            scsi_inquiry_error.as_deref(),
        ) {
            backend_common::respond_err("controller", &error);
        }
        let mut runtime_identity_verified = service_state_bound;
        if let (Some(profile), Some(controller_recipe)) = (matched.as_ref(), loaded_recipe.as_ref())
        {
            if !service_state_bound {
                if profile.controller_bootstrap.is_some() {
                    if !bootstrap_selected {
                        backend_common::respond_err(
                            "controller",
                            &Error::Permission(
                                "runtime artifacts selected a profile whose exact USB/SCSI bootstrap tuple did not match"
                                    .into(),
                            ),
                        );
                    }
                    let identity = match verify_recipe_bootstrap_identity(
                        command_file,
                        controller_recipe,
                        &mut artifact_files,
                        profile,
                    ) {
                        Ok(identity) => identity,
                        Err(error) => backend_common::respond_err("controller", &error),
                    };
                    if let Some(built_in) = detected.as_ref() {
                        let built_in_nand = match built_in
                            .nand_id
                            .as_deref()
                            .map(recipe::exact_nand_id_bytes)
                            .transpose()
                        {
                            Ok(value) => value,
                            Err(error) => backend_common::respond_err("controller", &error),
                        };
                        let expected_nand = match identity
                            .nand_id
                            .as_deref()
                            .map(recipe::exact_nand_id_bytes)
                            .transpose()
                        {
                            Ok(value) => value,
                            Err(error) => backend_common::respond_err("controller", &error),
                        };
                        if built_in.family != identity.family
                            || built_in.controller_id != identity.controller_id
                            || built_in.firmware != identity.firmware
                            || built_in_nand
                                .as_ref()
                                .is_some_and(|actual| expected_nand.as_ref() != Some(actual))
                        {
                            backend_common::respond_err(
                                "controller",
                                &Error::Permission(
                                    "built-in and recipe-owned controller identities disagree"
                                        .into(),
                                ),
                            );
                        }
                    }
                    controller_id = identity.controller_id;
                    firmware = identity.firmware;
                    nand_id = identity.nand_id.unwrap_or_else(|| "unidentified".into());
                    runtime_identity_verified = true;
                } else if let Some(identity) = detected.as_ref() {
                    nand_id = match verify_recipe_hardware_identity(
                        command_file,
                        controller_recipe,
                        &mut artifact_files,
                        profile,
                        identity,
                    ) {
                        Ok(nand_id) => nand_id,
                        Err(error) => backend_common::respond_err("controller", &error),
                    };
                    runtime_identity_verified = true;
                } else {
                    backend_common::respond_err(
                        "controller",
                        &Error::Permission(
                            "normal-mode controller identity is unavailable and no service-mode state is committed"
                                .into(),
                        ),
                    );
                }
            } else {
                controller_id = controller_recipe.controller_id.clone();
                firmware = controller_recipe.firmware.clone();
                nand_id = controller_recipe.nand_id.clone();
            }
        }
        let reported_service_mode = recipe_state
            .as_ref()
            .map(|state| state.service_mode.as_str())
            .or_else(|| detected.as_ref().map(|identity| identity.mode.as_str()))
            .unwrap_or(ServiceModeState::Normal.as_str());
        // The engine is executable only when the profile, recipe, parsed
        // controller-owned identity and durable state descriptor all exist.
        let executable_profile = matched.is_some()
            && recipe_sha256.is_some()
            && runtime_identity_verified
            && (matches!(op, "probe" | "plan") || loaded_recipe.is_some());
        // Planning is read-only and may advertise the immutable artifact
        // requirements from a trusted exact profile before those artifacts
        // are present. The run-time probe repeats this response with every
        // required runtime artifact inherited and verified; destructive
        // operations still use `executable_profile` exclusively.
        let advertised_profile = executable_profile
            || (op == "probe"
                && runtime_recipe_declared
                && matched.is_some()
                && (detected.is_some() || bootstrap_selected));
        let recipe_family_candidates = family_hint.map_or_else(
            || {
                Family::ALL
                    .iter()
                    .copied()
                    .filter(|family| vendor::support(*family).recipe_engine)
                    .map(Family::recipe_str)
                    .collect::<Vec<_>>()
            },
            |family| vec![family.recipe_str()],
        );
        let missing_for_production = if executable_profile {
            Vec::<&str>::new()
        } else if matched.is_some() {
            vec![
                "authenticated runtime artifacts",
                "recipe-owned identity response",
            ]
        } else if detected.is_some() {
            vec![
                "exact NAND geometry and ECC/randomizer layout",
                "service transition and runtime loader artifacts",
                "physical erase/status and page/OOB command contracts",
                "BBT, FTL, spare and atomic commit metadata layouts",
                "complete pre-HIL runtime recipe and profile",
                "independent HIL qualification and power-cut evidence",
            ]
        } else {
            vec![
                "exact controller identity response",
                "exact NAND identity and geometry",
                "successful and failing factory-tool protocol traces",
                "service transition and runtime loader artifacts",
                "BBT, FTL, spare and commit metadata layouts",
                "independent HIL qualification and power-cut evidence",
            ]
        };

        if op != "probe" && artifact_files.len() != runtime_artifacts.len() {
            backend_common::respond_err(
                "controller",
                &Error::Permission("required controller artifacts were not inherited".into()),
            );
        }
        if matches!(op, "run" | "status" | "recover") && state_file.is_none() {
            backend_common::respond_err(
                "controller",
                &Error::Permission("controller state fd was not inherited".into()),
            );
        }
        let result: Result<Value> = (|| {
            match op {
                "probe" | "plan" => {
                    // This backend does not implement generic LBA actions;
                    // advertising them would create an executable plan that
                    // fails only after confirmation.
                    let mut caps: Vec<String> = Vec::new();
                    if detected.is_some() && support.as_ref().is_some_and(|s| s.identify) {
                        caps.push("CONTROLLER_IDENTIFY".into());
                    }
                    if detected.is_some() && support.as_ref().is_some_and(|s| s.nand_identify) {
                        caps.push("NAND_IDENTIFY".into());
                    }
                    if detected.is_some()
                        && support.as_ref().is_some_and(|s| s.service_entry_documented)
                    {
                        caps.push("DOCUMENTED_SERVICE_MODE_ENTRY".into());
                    }
                    if detected.is_some()
                        && support
                            .as_ref()
                            .is_some_and(|s| s.volatile_loader_documented)
                    {
                        caps.push("DOCUMENTED_VOLATILE_SERVICE_LOADER".into());
                    }
                    let mut v = json!({
                        "api": PROTOCOL_API,
                        "ok": true,
                        "backend": "controller",
                        "match": if executable_profile { "exact-executable" } else if advertised_profile { "exact-artifacts-required" } else if matched.is_some() { "exact-not-executable" } else { "none" },
                        "version": VERSION,
                        "capabilities": caps,
                        "grade_ceiling": if advertised_profile { matched.as_ref().and_then(|profile| profile.certification.as_deref()).unwrap_or("C3") } else { "C0" },
                        "erase_coverage": [],
                        "erase_method": Value::Null,
                        "rebuilds": [],
                        "controller_profile": Value::Null,
                        "profile_sha256": Value::Null,
                        "capacity_policy": Value::Null,
                        "protected_area_bytes": matched
                            .as_ref()
                            .and_then(|profile| profile.protected_area_bytes)
                            .unwrap_or(0),
                        "certification": Value::Null,
                        "artifacts": [],
                        "family_hint": family_hint.map(Family::as_str),
                        "family_support": support,
                        "probe_error": probe_error,
                        "read_only_probe_profile": probe_profile_id,
                        "read_only_probe_profile_sha256": probe_profile_sha256,
                        "recipe_artifact_error": recipe_artifact_error,
                        "scsi": {
                            "vendor": scsi_inquiry.as_ref().map(|inquiry| inquiry.vendor_id.as_str()),
                            "product": scsi_inquiry.as_ref().map(|inquiry| inquiry.product_id.as_str()),
                            "revision": scsi_inquiry.as_ref().map(|inquiry| inquiry.product_rev.as_str()),
                            "inquiry_error": scsi_inquiry_error,
                        },
                        "controller_research": {
                            "schema": 1,
                            "selection": if read_only_probe.is_some() && detected.is_some() { "package-read-only-probe" } else if bootstrap_selected { "exact-bootstrap" } else if detected.is_some() { "signed-built-in-identity" } else if family_hint.is_some() { "vendor-id-candidate-only" } else { "undetermined" },
                            "recipe_family_candidates": recipe_family_candidates,
                            "exact_bootstrap_observed": {
                                "family": family_hint.map(Family::recipe_str),
                                "usb_vid": request.get("device").and_then(|device| device.get("usb")).and_then(|usb| usb.get("vid")).cloned().unwrap_or(Value::Null),
                                "usb_pid": request.get("device").and_then(|device| device.get("usb")).and_then(|usb| usb.get("pid")).cloned().unwrap_or(Value::Null),
                                "usb_bcd_device": request.get("device").and_then(|device| device.get("usb")).and_then(|usb| usb.get("bcd_device")).cloned().unwrap_or(Value::Null),
                                "usb_manufacturer": request.get("device").and_then(|device| device.get("usb")).and_then(|usb| usb.get("manufacturer")).cloned().unwrap_or(Value::Null),
                                "usb_product": request.get("device").and_then(|device| device.get("usb")).and_then(|usb| usb.get("product")).cloned().unwrap_or(Value::Null),
                                "usb_serial": request.get("device").and_then(|device| device.get("usb")).and_then(|usb| usb.get("serial")).cloned().unwrap_or(Value::Null),
                                "scsi_vendor": scsi_inquiry.as_ref().map(|inquiry| inquiry.vendor_id.as_str()),
                                "scsi_product": scsi_inquiry.as_ref().map(|inquiry| inquiry.product_id.as_str()),
                                "scsi_revision": scsi_inquiry.as_ref().map(|inquiry| inquiry.product_rev.as_str()),
                            },
                            "identity_source": if read_only_probe.is_some() { "package-read-only-probe+scsi-sg-io" } else { "scsi-sg-io" },
                            "media_commands_sent": media_commands_sent,
                            "unknown_vendor_commands_sent": false,
                            "missing_for_production": missing_for_production,
                        },
                        "device": {
                            "controller_id": controller_id,
                            "firmware": firmware,
                            "nand_id": nand_id,
                            "service_mode": reported_service_mode,
                        }
                    });
                    if advertised_profile {
                        if support.as_ref().is_some_and(|value| value.recipe_identify)
                            && !caps
                                .iter()
                                .any(|capability| capability == "CONTROLLER_IDENTIFY")
                        {
                            caps.push("CONTROLLER_IDENTIFY".into());
                        }
                        if support
                            .as_ref()
                            .is_some_and(|value| value.recipe_nand_identify)
                            && !caps.iter().any(|capability| capability == "NAND_IDENTIFY")
                        {
                            caps.push("NAND_IDENTIFY".into());
                        }
                        caps.extend([
                            "CONTROLLER_REINITIALIZE".into(),
                            "PHYSICAL_SALVAGE".into(),
                            "READ_BBT".into(),
                            "ENUM_PHYSICAL_BLOCKS".into(),
                            "ERASE_PHYSICAL_BLOCK".into(),
                            "PROGRAM_PHYSICAL_PAGE".into(),
                            "READ_PHYSICAL_PAGE".into(),
                            "READ_ERASE_STATUS".into(),
                            "ENTER_SERVICE_MODE".into(),
                            "EXIT_SERVICE_MODE".into(),
                            "RESET_CONTROLLER".into(),
                            "REBUILD_BBT".into(),
                            "SET_LOGICAL_CAPACITY".into(),
                            "SET_SPARE_POLICY".into(),
                            "REBUILD_FTL".into(),
                            "ERASE_SYSTEM_METADATA".into(),
                            "RESUME_AFTER_POWER_LOSS".into(),
                        ]);
                        v["capabilities"] = json!(caps);
                        v["rebuilds"] = json!(rebuilds);
                        v["controller_profile"] = json!(profile_id);
                        v["profile_sha256"] =
                            json!(matched.as_ref().and_then(|p| p.sha256.clone()));
                        v["capacity_policy"] = capacity_policy;
                        v["artifacts"] = json!(runtime_artifacts);
                        let certification = matched
                            .as_ref()
                            .and_then(|profile| profile.certification.as_deref())
                            .unwrap_or("C3");
                        if certification == "C4" {
                            caps.push("PHYSICAL_SCOPE".into());
                            v["capabilities"] = json!(caps);
                        }
                        v["grade_ceiling"] = json!(certification);
                        v["certification"] = json!(certification);
                        v["physical_certified"] = json!(certification == "C4");
                        v["erase_method"] = json!("controller-physical-block-erase-and-rebuild");
                        v["erase_coverage"] =
                            json!(matched.as_ref().map(|profile| &profile.coverage));
                    }
                    Ok(v)
                }
                "run" => {
                    let action = request.get("action").and_then(|v| v.as_str()).unwrap_or("");
                    // Without a certified profile, destructive controller
                    // operations are refused outright.
                    if !executable_profile {
                        return Err(Error::Permission(format!(
                            "no executable production controller profile matches {controller_id} fw {firmware} NAND {nand_id}; refusing destructive operation {action}"
                        )));
                    }
                    let plan_hash = request
                        .get("params")
                        .and_then(|value| value.get("plan_hash"))
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            Error::Invalid("controller action requires plan_hash".into())
                        })?;
                    if plan_hash.len() != 64
                        || !plan_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                    {
                        return Err(Error::Invalid(
                            "controller action plan_hash is invalid".into(),
                        ));
                    }
                    let profile = matched.as_ref().ok_or_else(|| {
                        Error::Invalid("executable controller profile disappeared".into())
                    })?;
                    let controller_recipe = loaded_recipe.as_ref().ok_or_else(|| {
                        Error::Invalid("executable controller recipe disappeared".into())
                    })?;
                    let recipe_digest = recipe_sha256.as_deref().ok_or_else(|| {
                        Error::Invalid("executable controller recipe digest disappeared".into())
                    })?;
                    let controller_state = state_file.as_mut().ok_or_else(|| {
                        Error::Invalid("executable controller state fd disappeared".into())
                    })?;
                    execute_action(ActionInvocation {
                        action,
                        plan_hash,
                        reenumeration_nonce: request
                            .get("params")
                            .and_then(|value| value.get("nonce"))
                            .and_then(|value| value.as_str()),
                        file: command_file,
                        block_file: &block_fd,
                        profile,
                        controller_recipe,
                        recipe_sha256: recipe_digest,
                        artifacts: &mut artifact_files,
                        state_file: controller_state,
                        physical_image: physical_image.as_mut(),
                        physical_map: physical_map.as_mut(),
                        events: &mut events,
                    })
                }
                "status" if executable_profile => {
                    let profile = matched.as_ref().ok_or_else(|| {
                        Error::Invalid("executable controller profile disappeared".into())
                    })?;
                    let controller_recipe = loaded_recipe.as_ref().ok_or_else(|| {
                        Error::Invalid("executable controller recipe disappeared".into())
                    })?;
                    let controller_state = state_file.as_mut().ok_or_else(|| {
                        Error::Invalid("executable controller state fd disappeared".into())
                    })?;
                    controller_status(
                        command_file,
                        profile,
                        controller_recipe,
                        &mut artifact_files,
                        controller_state,
                    )
                }
                "status" => Ok(json!({
                    "api": PROTOCOL_API,
                    "ok": true,
                    "backend": "controller",
                    "version": VERSION,
                    "state": "ready",
                    "service_mode": reported_service_mode,
                })),
                "recover" => {
                    if !executable_profile {
                        return Err(Error::Permission(
                            "controller recovery requires an executable production profile".into(),
                        ));
                    }
                    let profile = matched.as_ref().ok_or_else(|| {
                        Error::Invalid("executable controller profile disappeared".into())
                    })?;
                    let controller_recipe = loaded_recipe.as_ref().ok_or_else(|| {
                        Error::Invalid("executable controller recipe disappeared".into())
                    })?;
                    let controller_state = state_file.as_mut().ok_or_else(|| {
                        Error::Invalid("executable controller state fd disappeared".into())
                    })?;
                    recover_controller(
                        command_file,
                        profile,
                        controller_recipe,
                        &mut artifact_files,
                        controller_state,
                    )
                }
                other => Err(Error::Usage(format!("unknown controller op: {other}"))),
            }
        })();

        let result = match (result, command_transport.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(operation), Err(cleanup)) => Err(Error::Backend(format!(
                "controller operation failed: {operation}; transport cleanup also failed: {cleanup}"
            ))),
        };

        match result {
            Ok(v) => {
                if let Err(e) = nclr::backend::write_response(&v) {
                    eprintln!("nclr-controller: {e}");
                    std::process::exit(74);
                }
            }
            Err(e) => {
                if op == "run" {
                    backend_common::respond_action_err("controller", &e);
                }
                backend_common::respond_err("controller", &e);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::validate_inquiry_continuation;

        #[test]
        fn inquiry_failure_requires_recipe_bound_service_state() {
            assert!(validate_inquiry_continuation(true, false, None).is_ok());
            assert!(validate_inquiry_continuation(false, true, Some("not ready")).is_ok());
            let error = validate_inquiry_continuation(false, false, Some("not ready"))
                .expect_err("normal mode must retain the standard INQUIRY requirement");
            assert!(error.to_string().contains("not ready"));
        }
    }
}
