#include "string.h"
#include "PS2303.h"
#include "usb.h"
#include "nclr_usb_dma.h"

#define NCLR_SCHEMA 2
#define NCLR_HEADER_BYTES 32
#define NCLR_BUFFER_VA 0x6000U
#define NCLR_BUFFER_PA 0x00e000UL
#define NCLR_BUFFER_BYTES 0x9000U
#define NCLR_MAX_RAW_BYTES (NCLR_BUFFER_BYTES - NCLR_HEADER_BYTES)
#define NCLR_ONFI_PAGE_BYTES 256U
#define NCLR_ONFI_COPIES 3U
#define NCLR_GEOMETRY_OVERRIDE_BYTES 40U
#define NCLR_GEOMETRY_MAGIC 0xa5
#define NCLR_READY_TIMEOUT 0x00ffffffUL

#define NCLR_CMD_READ_CONTROLLER_ID 0x00
#define NCLR_CMD_READ_NAND_ID 0x01
#define NCLR_CMD_READ_ONFI 0x02
#define NCLR_CMD_CONFIGURE_GEOMETRY 0x03
#define NCLR_CMD_READ_PAGE 0x10
#define NCLR_CMD_ERASE_BLOCK 0x11
#define NCLR_CMD_READ_STATUS 0x12
#define NCLR_CMD_PROGRAM_PAGE 0x13
#define NCLR_CMD_EXIT_TO_BOOTROM 0x7e

#define NCLR_FLAG_BUSY 0x01
#define NCLR_FLAG_FAILED 0x02
#define NCLR_FLAG_SERVICE_MODE 0x04
#define NCLR_FLAG_ECC_KNOWN 0x08
#define NCLR_FLAG_UNCORRECTABLE 0x10

#define NCLR_NAND_STATUS_FAIL 0x01
#define NCLR_NAND_STATUS_READY 0x40

#define NCLR_BUFFER ((BYTE __xdata *)NCLR_BUFFER_VA)

typedef struct {
    BYTE magic;
    BYTE column_cycles;
    BYTE row_cycles;
    BYTE luns;
    DWORD page_bytes;
    WORD oob_bytes;
    DWORD pages_per_block;
    DWORD blocks_per_lun;
} NclrGeometry;

__xdata __at (0x4f00) DWORD nclr_operation_sequence;
__xdata __at (0x4f04) BYTE nclr_last_failed;
__xdata __at (0x4f05) BYTE nclr_last_nand_status;
__xdata __at (0x4f06) BYTE nclr_state_magic[8];
__xdata __at (0x4f10) NclrGeometry nclr_geometries[16];
__xdata __at (0x5200) BYTE nclr_row_address[5];
__xdata __at (0x5205) BYTE nclr_multiply_scratch[9];

BYTE scsi_status;
DWORD scsi_data_residue, scsi_transfer_size;
BYTE scsi_tag[4];
__bit scsi_dir_in;
BYTE scsi_lun;
BYTE scsi_cdb[16];
BYTE scsi_cdb_size;

static const BYTE __code nclr_signature[8] = {
    'N', 'C', 'L', 'R', '2', '3', '0', '3'
};
static const BYTE __code nclr_identity[8] = {
    'P', 'S', '2', '3', '0', '3', 'V', '2'
};
static const BYTE __code nclr_geometry_signature[8] = {
    'N', 'C', 'L', 'R', 'G', 'E', 'O', '2'
};

static WORD NclrReadLe16(const BYTE __xdata *data, WORD offset)
{
    return (WORD)data[offset] | ((WORD)data[offset + 1] << 8);
}

static DWORD NclrReadLe32(const BYTE __xdata *data, WORD offset)
{
    return (DWORD)data[offset]
        | ((DWORD)data[offset + 1] << 8)
        | ((DWORD)data[offset + 2] << 16)
        | ((DWORD)data[offset + 3] << 24);
}

static DWORD NclrReadBe32(const BYTE *data)
{
    return ((DWORD)data[0] << 24)
        | ((DWORD)data[1] << 16)
        | ((DWORD)data[2] << 8)
        | (DWORD)data[3];
}

static WORD NclrReadBe16(const BYTE *data)
{
    return ((WORD)data[0] << 8) | (WORD)data[1];
}

static void NclrWriteLe32(BYTE __xdata *data, WORD offset, DWORD value)
{
    data[offset] = (BYTE)value;
    data[offset + 1] = (BYTE)(value >> 8);
    data[offset + 2] = (BYTE)(value >> 16);
    data[offset + 3] = (BYTE)(value >> 24);
}

static void NclrClearPayload(WORD length)
{
    WORD i;
    for (i = 0; i < length; ++i)
        NCLR_BUFFER[NCLR_HEADER_BYTES + i] = 0;
}

static void NclrInitializeState(void)
{
    BYTE i;
    if (nclr_state_magic[0] == 'N'
        && nclr_state_magic[1] == 'C'
        && nclr_state_magic[2] == 'L'
        && nclr_state_magic[3] == 'R'
        && nclr_state_magic[4] == 'S'
        && nclr_state_magic[5] == 'T'
        && nclr_state_magic[6] == '0'
        && nclr_state_magic[7] == '1')
        return;
    for (i = 0; i < 16; ++i)
        nclr_geometries[i].magic = 0;
    nclr_operation_sequence = 0;
    nclr_last_failed = 0;
    nclr_last_nand_status = 0;
    nclr_state_magic[0] = 'N';
    nclr_state_magic[1] = 'C';
    nclr_state_magic[2] = 'L';
    nclr_state_magic[3] = 'R';
    nclr_state_magic[4] = 'S';
    nclr_state_magic[5] = 'T';
    nclr_state_magic[6] = '0';
    nclr_state_magic[7] = '1';
}

static NANDREGS __xdata *NclrNfc(BYTE channel)
{
    return channel == 0 ? &NFC0 : &NFC1;
}

static BOOL NclrAddressIsZero(void)
{
    BYTE i;
    for (i = 3; i < 16; ++i) {
        if (scsi_cdb[i] != 0)
            return FALSE;
    }
    return TRUE;
}

static BOOL NclrCdbIsCanonical(void)
{
    return scsi_cdb_size == 16
        && scsi_cdb[0] == 0xc7
        && scsi_cdb[2] == NCLR_SCHEMA
        && scsi_cdb[3] <= 1
        && scsi_cdb[4] <= 7
        && scsi_cdb[6] == 0
        && scsi_cdb[7] == 0
        && scsi_cdb[14] == 0
        && scsi_cdb[15] == 0;
}

static BOOL NclrExpectIn(WORD size)
{
    return scsi_dir_in && scsi_transfer_size == (DWORD)size;
}

static BOOL NclrExpectOut(WORD size)
{
    return !scsi_dir_in && scsi_transfer_size == (DWORD)size;
}

static BOOL NclrExpectNoData(void)
{
    return !scsi_dir_in && scsi_transfer_size == 0;
}

static void NclrFillHeader(BYTE command, DWORD payload_bytes)
{
    BYTE i;
    for (i = 0; i < NCLR_HEADER_BYTES; ++i)
        NCLR_BUFFER[i] = 0;
    for (i = 0; i < 8; ++i)
        NCLR_BUFFER[i] = nclr_signature[i];
    NCLR_BUFFER[8] = NCLR_SCHEMA;
    NCLR_BUFFER[9] = command;
    NCLR_BUFFER[10] = NCLR_FLAG_SERVICE_MODE
        | (nclr_last_failed ? NCLR_FLAG_FAILED : 0);
    NCLR_BUFFER[11] = nclr_last_nand_status;
    NclrWriteLe32(NCLR_BUFFER, 12, nclr_operation_sequence);
    NclrWriteLe32(NCLR_BUFFER, 16, payload_bytes);
    NCLR_BUFFER[20] = 0;
    NCLR_BUFFER[21] = nclr_last_failed ? 1 : 0;
    NCLR_BUFFER[22] = 1;
    /* Raw NFC reads have no controller-side ECC verdict. */
    NCLR_BUFFER[23] = 0;
    NCLR_BUFFER[24] = 0;
}

static BOOL NclrSendResponse(BYTE command, WORD payload_bytes)
{
    WORD total = NCLR_HEADER_BYTES + payload_bytes;
    NclrFillHeader(command, payload_bytes);
    if (!NclrExpectIn(total))
        return FALSE;
    return NclrUsbTxDma(NCLR_BUFFER_PA, total);
}

static void NclrSelect(BYTE channel, BYTE chip)
{
    NANDREGS __xdata *nfc = NclrNfc(channel);
    NANDCSDIR = 0xff;
    NANDCSOUT = (BYTE)(0xff ^ ((BYTE)1 << chip));
    nfc->r80 = 0;
    XREG(0xF61C) = 0;
    XREG(0xF61D) = 0;
    XREG(0xF638) = (XREG(0xF638) & 0x7f) | 0x18;
}

static void NclrDeselect(void)
{
    NANDCSOUT = 0xff;
    NANDCSDIR = 0;
}

static BOOL NclrWaitReady(NANDREGS __xdata *nfc)
{
    DWORD remaining = NCLR_READY_TIMEOUT;
    while ((nfc->status & bmNandReady) == 0) {
        if (--remaining == 0)
            return FALSE;
    }
    return TRUE;
}

static BOOL NclrResetNand(NANDREGS __xdata *nfc)
{
    nfc->raw_cmd = 0xff;
    return NclrWaitReady(nfc);
}

static WORD NclrOnfiCrc16(const BYTE __xdata *data, WORD length)
{
    WORD crc = 0x4f4e;
    BYTE bit;
    while (length-- != 0) {
        crc ^= (WORD)(*data++) << 8;
        for (bit = 0; bit < 8; ++bit)
            crc = (crc << 1) ^ ((crc & 0x8000) ? 0x8005 : 0);
    }
    return crc;
}

static BOOL NclrReadOnfiRaw(BYTE channel, BYTE chip)
{
    NANDREGS __xdata *nfc = NclrNfc(channel);
    WORD i;
    NclrSelect(channel, chip);
    if (!NclrResetNand(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    nfc->raw_cmd = 0x90;
    nfc->raw_addr = 0x20;
    if (nfc->raw_data != 'O'
        || nfc->raw_data != 'N'
        || nfc->raw_data != 'F'
        || nfc->raw_data != 'I') {
        NclrDeselect();
        return FALSE;
    }
    nfc->raw_cmd = 0xec;
    nfc->raw_addr = 0;
    if (!NclrWaitReady(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    for (i = 0; i < NCLR_ONFI_PAGE_BYTES * NCLR_ONFI_COPIES; ++i)
        NCLR_BUFFER[NCLR_HEADER_BYTES + i] = nfc->raw_data;
    NclrDeselect();
    return TRUE;
}

static BOOL NclrParseGeometry(BYTE channel, BYTE chip)
{
    BYTE copy;
    NclrGeometry __xdata *geometry = &nclr_geometries[channel * 8 + chip];
    for (copy = 0; copy < NCLR_ONFI_COPIES; ++copy) {
        BYTE __xdata *page = NCLR_BUFFER + NCLR_HEADER_BYTES
            + (WORD)copy * NCLR_ONFI_PAGE_BYTES;
        DWORD raw_bytes;
        if (page[0] != 'O' || page[1] != 'N' || page[2] != 'F' || page[3] != 'I')
            continue;
        if (NclrOnfiCrc16(page, 254) != NclrReadLe16(page, 254))
            continue;
        if ((NclrReadLe16(page, 6) & 1) != 0)
            continue;
        geometry->page_bytes = NclrReadLe32(page, 80);
        geometry->oob_bytes = NclrReadLe16(page, 84);
        geometry->pages_per_block = NclrReadLe32(page, 92);
        geometry->blocks_per_lun = NclrReadLe32(page, 96);
        geometry->luns = page[100];
        geometry->column_cycles = page[101] & 0x0f;
        geometry->row_cycles = page[101] >> 4;
        raw_bytes = geometry->page_bytes + geometry->oob_bytes;
        if (geometry->page_bytes < 2048
            || geometry->oob_bytes == 0
            || geometry->pages_per_block == 0
            || geometry->blocks_per_lun == 0
            || geometry->luns == 0
            || geometry->column_cycles == 0
            || geometry->column_cycles > 4
            || geometry->row_cycles == 0
            || geometry->row_cycles > 5
            || raw_bytes < geometry->page_bytes
            || raw_bytes > NCLR_MAX_RAW_BYTES)
            continue;
        geometry->magic = NCLR_GEOMETRY_MAGIC;
        return TRUE;
    }
    geometry->magic = 0;
    return FALSE;
}

static NclrGeometry __xdata *NclrGeometryFor(BYTE channel, BYTE chip)
{
    NclrGeometry __xdata *geometry = &nclr_geometries[channel * 8 + chip];
    if (geometry->magic == NCLR_GEOMETRY_MAGIC)
        return geometry;
    if (!NclrReadOnfiRaw(channel, chip) || !NclrParseGeometry(channel, chip))
        return 0;
    return geometry;
}

static void NclrWriteZeroAddress(NANDREGS __xdata *nfc, BYTE cycles)
{
    while (cycles-- != 0)
        nfc->raw_addr = 0;
}

static void NclrWriteRowAddress(NANDREGS __xdata *nfc, BYTE cycles)
{
    BYTE i;
    for (i = 0; i < cycles; ++i)
        nfc->raw_addr = nclr_row_address[i];
}

static BOOL NclrAdd32ToRow(DWORD value)
{
    BYTE i;
    WORD sum;
    WORD carry = 0;
    for (i = 0; i < 5; ++i) {
        sum = nclr_row_address[i] + (value & 0xff) + carry;
        nclr_row_address[i] = (BYTE)sum;
        carry = sum >> 8;
        value >>= 8;
    }
    return value == 0 && carry == 0;
}

static BOOL NclrMultiplyRowBy32(DWORD multiplier)
{
    BYTE i;
    BYTE j;
    BYTE multiplier_byte;
    WORD product;
    WORD carry;
    for (i = 0; i < 9; ++i)
        nclr_multiply_scratch[i] = 0;
    for (i = 0; i < 5; ++i) {
        carry = 0;
        for (j = 0; j < 4; ++j) {
            multiplier_byte = (BYTE)(multiplier >> (j * 8));
            product = nclr_multiply_scratch[i + j]
                + (WORD)nclr_row_address[i] * multiplier_byte
                + carry;
            nclr_multiply_scratch[i + j] = (BYTE)product;
            carry = product >> 8;
        }
        j = i + 4;
        while (carry != 0 && j < 9) {
            product = nclr_multiply_scratch[j] + carry;
            nclr_multiply_scratch[j] = (BYTE)product;
            carry = product >> 8;
            ++j;
        }
        if (carry != 0)
            return FALSE;
    }
    if (nclr_multiply_scratch[5] != 0
        || nclr_multiply_scratch[6] != 0
        || nclr_multiply_scratch[7] != 0
        || nclr_multiply_scratch[8] != 0)
        return FALSE;
    for (i = 0; i < 5; ++i)
        nclr_row_address[i] = nclr_multiply_scratch[i];
    return TRUE;
}

static BOOL NclrBuildRowAddress(NclrGeometry __xdata *geometry,
                                DWORD block,
                                WORD page,
                                BYTE lun)
{
    BYTE i;
    BOOL valid;
    if (block >= geometry->blocks_per_lun
        || page >= geometry->pages_per_block
        || lun >= geometry->luns)
        return FALSE;
    for (i = 0; i < 5; ++i)
        nclr_row_address[i] = 0;
    for (i = 0; i < lun; ++i) {
        if (!NclrAdd32ToRow(geometry->blocks_per_lun))
            return FALSE;
    }
    valid = NclrAdd32ToRow(block)
        && NclrMultiplyRowBy32(geometry->pages_per_block)
        && NclrAdd32ToRow(page);
    if (!valid)
        return FALSE;
    for (i = geometry->row_cycles; i < 5; ++i) {
        if (nclr_row_address[i] != 0)
            return FALSE;
    }
    return TRUE;
}

static BYTE NclrReadNandStatus(NANDREGS __xdata *nfc)
{
    nfc->raw_cmd = 0x70;
    return nfc->raw_data;
}

static BOOL NclrReadId(BYTE channel, BYTE chip)
{
    NANDREGS __xdata *nfc = NclrNfc(channel);
    BYTE i;
    NclrSelect(channel, chip);
    if (!NclrResetNand(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    nfc->raw_cmd = 0x90;
    nfc->raw_addr = 0;
    for (i = 0; i < 6; ++i)
        NCLR_BUFFER[NCLR_HEADER_BYTES + i] = nfc->raw_data;
    NclrDeselect();
    return TRUE;
}

static BOOL NclrNandIdMatches(BYTE channel,
                              BYTE chip,
                              const BYTE __xdata *expected)
{
    NANDREGS __xdata *nfc = NclrNfc(channel);
    BYTE i;
    BYTE matches = 1;
    NclrSelect(channel, chip);
    if (!NclrResetNand(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    nfc->raw_cmd = 0x90;
    nfc->raw_addr = 0;
    for (i = 0; i < 6; ++i) {
        if (nfc->raw_data != expected[i])
            matches = 0;
    }
    NclrDeselect();
    return matches != 0;
}

static BOOL NclrConfigureGeometry(BYTE channel, BYTE chip)
{
    BYTE __xdata *data = NCLR_BUFFER + NCLR_HEADER_BYTES;
    NclrGeometry __xdata *geometry = &nclr_geometries[channel * 8 + chip];
    DWORD raw_bytes;
    BYTE i;
    geometry->magic = 0;
    for (i = 0; i < 8; ++i) {
        if (data[i] != nclr_geometry_signature[i])
            return FALSE;
    }
    if (NclrOnfiCrc16(data, 38) != NclrReadLe16(data, 38)
        || data[32] != 0
        || data[33] != 0
        || data[34] != 0
        || data[35] != 0
        || data[36] != 0
        || data[37] != 0)
        return FALSE;
    geometry->page_bytes = NclrReadLe32(data, 8);
    geometry->oob_bytes = NclrReadLe16(data, 12);
    geometry->pages_per_block = NclrReadLe32(data, 14);
    geometry->blocks_per_lun = NclrReadLe32(data, 18);
    geometry->luns = data[22];
    geometry->column_cycles = data[23];
    geometry->row_cycles = data[24];
    raw_bytes = geometry->page_bytes + geometry->oob_bytes;
    if (geometry->page_bytes < 2048
        || geometry->oob_bytes == 0
        || geometry->pages_per_block == 0
        || geometry->blocks_per_lun == 0
        || geometry->luns == 0
        || geometry->column_cycles == 0
        || geometry->column_cycles > 4
        || geometry->row_cycles == 0
        || geometry->row_cycles > 5
        || data[25] == 0
        || data[25] > 4
        || raw_bytes < geometry->page_bytes
        || raw_bytes > NCLR_MAX_RAW_BYTES
        || !NclrNandIdMatches(channel, chip, data + 26))
        return FALSE;
    geometry->magic = NCLR_GEOMETRY_MAGIC;
    return TRUE;
}

static BOOL NclrReadPage(BYTE channel,
                         BYTE chip,
                         BYTE lun,
                         DWORD block,
                         WORD page)
{
    NclrGeometry __xdata *geometry = NclrGeometryFor(channel, chip);
    NANDREGS __xdata *nfc = NclrNfc(channel);
    DWORD i;
    DWORD raw_bytes;
    if (geometry == 0 || !NclrBuildRowAddress(geometry, block, page, lun))
        return FALSE;
    raw_bytes = geometry->page_bytes + geometry->oob_bytes;
    NclrSelect(channel, chip);
    nfc->raw_cmd = 0x00;
    NclrWriteZeroAddress(nfc, geometry->column_cycles);
    NclrWriteRowAddress(nfc, geometry->row_cycles);
    nfc->raw_cmd = 0x30;
    if (!NclrWaitReady(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    for (i = 0; i < raw_bytes; ++i)
        NCLR_BUFFER[NCLR_HEADER_BYTES + i] = nfc->raw_data;
    nclr_last_nand_status = NclrReadNandStatus(nfc);
    NclrDeselect();
    return TRUE;
}

static BOOL NclrEraseBlock(BYTE channel,
                           BYTE chip,
                           BYTE lun,
                           DWORD block)
{
    NclrGeometry __xdata *geometry = NclrGeometryFor(channel, chip);
    NANDREGS __xdata *nfc = NclrNfc(channel);
    if (geometry == 0 || !NclrBuildRowAddress(geometry, block, 0, lun))
        return FALSE;
    NclrSelect(channel, chip);
    nfc->raw_cmd = 0x60;
    NclrWriteRowAddress(nfc, geometry->row_cycles);
    nfc->raw_cmd = 0xd0;
    if (!NclrWaitReady(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    nclr_last_nand_status = NclrReadNandStatus(nfc);
    NclrDeselect();
    return (nclr_last_nand_status & NCLR_NAND_STATUS_FAIL) == 0;
}

static BOOL NclrProgramPage(BYTE channel,
                            BYTE chip,
                            BYTE lun,
                            DWORD block,
                            WORD page)
{
    NclrGeometry __xdata *geometry = NclrGeometryFor(channel, chip);
    NANDREGS __xdata *nfc = NclrNfc(channel);
    DWORD i;
    DWORD raw_bytes;
    WORD received_bytes;
    if (scsi_dir_in
        || scsi_transfer_size == 0
        || scsi_transfer_size > NCLR_MAX_RAW_BYTES)
        return FALSE;
    received_bytes = (WORD)scsi_transfer_size;
    if (!NclrUsbRxDma(NCLR_BUFFER_PA + NCLR_HEADER_BYTES, received_bytes))
        return FALSE;
    if (geometry == 0 || !NclrBuildRowAddress(geometry, block, page, lun))
        return FALSE;
    raw_bytes = geometry->page_bytes + geometry->oob_bytes;
    if (!NclrExpectOut((WORD)raw_bytes) || received_bytes != (WORD)raw_bytes)
        return FALSE;
    NclrSelect(channel, chip);
    nfc->raw_cmd = 0x80;
    NclrWriteZeroAddress(nfc, geometry->column_cycles);
    NclrWriteRowAddress(nfc, geometry->row_cycles);
    for (i = 0; i < raw_bytes; ++i)
        nfc->raw_data = NCLR_BUFFER[NCLR_HEADER_BYTES + i];
    nfc->raw_cmd = 0x10;
    if (!NclrWaitReady(nfc)) {
        NclrDeselect();
        return FALSE;
    }
    nclr_last_nand_status = NclrReadNandStatus(nfc);
    NclrDeselect();
    return (nclr_last_nand_status & NCLR_NAND_STATUS_FAIL) == 0;
}

static BOOL NclrHandleVendorCommand(void)
{
    BYTE command = scsi_cdb[1];
    BYTE channel = scsi_cdb[3];
    BYTE chip = scsi_cdb[4];
    BYTE lun = scsi_cdb[5];
    DWORD block = NclrReadBe32(&scsi_cdb[8]);
    WORD page = NclrReadBe16(&scsi_cdb[12]);
    NclrGeometry __xdata *geometry;
    WORD raw_bytes;
    BYTE i;

    if (!NclrCdbIsCanonical())
        return FALSE;
    NclrInitializeState();
    scsi_status = 1;
    switch (command) {
    case NCLR_CMD_READ_CONTROLLER_ID:
        if (!NclrAddressIsZero())
            return FALSE;
        for (i = 0; i < 8; ++i)
            NCLR_BUFFER[NCLR_HEADER_BYTES + i] = nclr_identity[i];
        if (!NclrSendResponse(command, 8))
            return FALSE;
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_READ_NAND_ID:
        if (lun != 0 || block != 0 || page != 0)
            return FALSE;
        ++nclr_operation_sequence;
        nclr_last_nand_status = 0;
        NclrClearPayload(6);
        nclr_last_failed = !NclrReadId(channel, chip);
        if (!NclrSendResponse(command, 6))
            return FALSE;
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_READ_ONFI:
        if (lun != 0 || block != 0 || page != 0)
            return FALSE;
        ++nclr_operation_sequence;
        nclr_last_nand_status = 0;
        NclrClearPayload(NCLR_ONFI_PAGE_BYTES * NCLR_ONFI_COPIES);
        nclr_last_failed = !NclrReadOnfiRaw(channel, chip)
            || !NclrParseGeometry(channel, chip);
        if (!NclrSendResponse(command, NCLR_ONFI_PAGE_BYTES * NCLR_ONFI_COPIES))
            return FALSE;
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_CONFIGURE_GEOMETRY:
        if (lun != 0
            || block != 0
            || page != 0
            || !NclrExpectOut(NCLR_GEOMETRY_OVERRIDE_BYTES))
            return FALSE;
        ++nclr_operation_sequence;
        nclr_last_nand_status = 0;
        if (!NclrUsbRxDma(NCLR_BUFFER_PA + NCLR_HEADER_BYTES,
                          NCLR_GEOMETRY_OVERRIDE_BYTES))
            return FALSE;
        nclr_last_failed = !NclrConfigureGeometry(channel, chip);
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_READ_PAGE:
        ++nclr_operation_sequence;
        nclr_last_nand_status = 0;
        if (!scsi_dir_in
            || scsi_transfer_size <= NCLR_HEADER_BYTES
            || scsi_transfer_size > NCLR_BUFFER_BYTES)
            return FALSE;
        raw_bytes = (WORD)scsi_transfer_size - NCLR_HEADER_BYTES;
        geometry = NclrGeometryFor(channel, chip);
        nclr_last_failed = geometry == 0
            || geometry->page_bytes + geometry->oob_bytes != raw_bytes
            || !NclrReadPage(channel, chip, lun, block, page);
        if (nclr_last_failed)
            NclrClearPayload(raw_bytes);
        if (!NclrSendResponse(command, raw_bytes))
            return FALSE;
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_ERASE_BLOCK:
        if (page != 0 || !NclrExpectNoData())
            return FALSE;
        ++nclr_operation_sequence;
        nclr_last_nand_status = 0;
        nclr_last_failed = !NclrEraseBlock(channel, chip, lun, block);
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_READ_STATUS:
        if (!NclrAddressIsZero() || !NclrSendResponse(command, 0))
            return FALSE;
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_PROGRAM_PAGE:
        ++nclr_operation_sequence;
        nclr_last_nand_status = 0;
        nclr_last_failed = !NclrProgramPage(channel, chip, lun, block, page);
        scsi_status = 0;
        return TRUE;
    case NCLR_CMD_EXIT_TO_BOOTROM:
        if (!NclrAddressIsZero() || !NclrExpectNoData())
            return FALSE;
        scsi_status = 0;
        PRAMCTL &= (BYTE)~bmPRAM;
        return TRUE;
    default:
        return FALSE;
    }
}

bit ScsiHandleCDB(void)
{
    scsi_status = 1;
    switch (scsi_cdb[0]) {
    case 0x00:
        if (scsi_transfer_size != 0)
            return 0;
        scsi_status = 0;
        return 1;
    case 0x03:
        if (!NclrExpectIn(18))
            return 0;
        memset(EPBUF, 0, 18);
        EPBUF[0] = 0x70;
        EPBUF[2] = 0x02;
        EPBUF[7] = 10;
        EPBUF[12] = 0x3a;
        UsbTxDma(18, 0);
        scsi_status = 0;
        return 1;
    case 0xc7:
        return NclrHandleVendorCommand();
    default:
        return 0;
    }
}

BOOL HandleClassRequest(void)
{
    return FALSE;
}

BOOL HandleVendorRequest(void)
{
    return FALSE;
}
