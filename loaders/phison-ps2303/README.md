# PS2303 clean-room raw NAND loader

This directory builds a volatile `BtPramCd` loader for Phison PS2251-03
(PS2303). It does not flash controller firmware. The host authenticates the
loader artifact, enters the documented BootROM path, transfers the image to
PRAM and runs it.

The build downloads the public-domain `flowswitch/phison` source at exact
commit `d9415a8d5c62354d09cd6410754c9d8bb65e164f`, verifies the archive SHA-256,
replaces only its SCSI handler, and adds the nclr endpoint-DMA implementation.
SDCC 4.6.0 is required so the output is reproducible.

```sh
./loaders/phison-ps2303/build.sh
```

An already downloaded archive can be supplied without network access:

```sh
./loaders/phison-ps2303/build.sh \
  --source flowswitch-phison-d9415a8.tar.gz \
  --output build/phison-ps2303/nclr-ps2303.btpram
```

The output manifest records both the source binary and `BtPramCd` image
digests. It always declares `hil_qualified = false` and
`runtime_authorized = false`; profile artifact binding and independent HIL
qualification remain separate gates.

## Protocol scope

The loader exposes only canonical 16-byte `C7` commands with schema byte 2:

| Subcommand | Direction | Scope |
|---|---|---|
| `00` | device to host | signed loader identity |
| `01` | device to host | six-byte NAND ID |
| `02` | device to host | all three 256-byte ONFI parameter copies |
| `03` | host to device | exact-NAND-ID-bound non-ONFI geometry |
| `10` | device to host | raw page plus OOB |
| `11` | none | raw block erase |
| `12` | device to host | signed last-operation status |
| `13` | host to device | raw page plus OOB program |
| `7e` | none | return to BootROM |

Channel, chip, LUN, block and page have fixed CDB offsets shared with
`crates/nclr-core/src/phison_ps2303.rs`. Geometry is accepted only from an
independently CRC-valid ONFI parameter copy. Non-ONFI geometry can instead be
provided by a digest-pinned vendor table; its CRC-protected payload includes
the exact six-byte NAND ID and is rejected unless the live ID matches. The
loader rejects x16 NAND,
invalid address-cycle counts, out-of-range coordinates and raw pages larger
than its mapped 36 KiB buffer. It does not perform majority recovery of a
damaged ONFI parameter page.

This loader reaches raw NAND for salvage, erase, program and post-erase page
inspection. Raw reads deliberately report an unknown ECC verdict, so they do
not by themselves claim complete salvage or verified erasure. It does not know
a vendor firmware's BBT or FTL format and
therefore is not, by itself, a complete reusable C3/C4 recipe. Those metadata
contracts must be reconstructed separately rather than guessed.
