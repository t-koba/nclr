#include "PS2303.h"
#include "nclr_usb_dma.h"

#define NCLR_USB_DMA_TIMEOUT 0x00ffffffUL

static void NclrArmUsbDma(BYTE p7, BYTE p5, BYTE p3, BYTE selector)
{
    XREG(0xF80B) = p7;
    XREG(0xF80C) = p5 - 1;
    if (selector == 0) {
        XREG(0xF80D) = p3;
        XREG(0xF80E) = p3;
    } else if (selector == 1) {
        XREG(0xF80D) = p3;
    } else {
        XREG(0xF80E) = p3;
    }
}

static BOOL NclrWaitForEndpoint(volatile BYTE __xdata *control)
{
    DWORD remaining = NCLR_USB_DMA_TIMEOUT;
    while ((*control & 0x80) != 0) {
        if (--remaining == 0)
            return FALSE;
    }
    return TRUE;
}

static void NclrConfigureEndpoint(volatile EPREGS __xdata *endpoint,
                                  DWORD physical_address,
                                  WORD size)
{
    endpoint->ptr_l = (BYTE)(physical_address >> 8);
    endpoint->ptr_m = (BYTE)(physical_address >> 16);
    endpoint->ptr_h = (BYTE)(physical_address >> 24);
    endpoint->r8 = 0x10;
    endpoint->ofs = 0;
    endpoint->len_l = LSB(size);
    endpoint->len_m = MSB(size);
    endpoint->len_h = 0;
}

BOOL NclrUsbTxDma(DWORD physical_address, WORD size)
{
    if (size == 0)
        return FALSE;
    NclrArmUsbDma(0, 0x20, 0, 0);
    NclrArmUsbDma(0, 0x20, 0x80, 1);
    NclrConfigureEndpoint(&EP1, physical_address, size);
    EP1.cs = 0x88;
    return NclrWaitForEndpoint(&EP1.cs);
}

BOOL NclrUsbRxDma(DWORD physical_address, WORD size)
{
    if (size == 0)
        return FALSE;
    NclrArmUsbDma(0, 0x20, 0, 0);
    NclrArmUsbDma(0, 0x20, 0x80, 2);
    NclrConfigureEndpoint(&EP2, physical_address, size);
    EP2.cs = 0x88;
    return NclrWaitForEndpoint(&EP2.cs);
}
