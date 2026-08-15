#ifndef NCLR_USB_DMA_H_INCLUDED
#define NCLR_USB_DMA_H_INCLUDED

#include "PS2303.h"

BOOL NclrUsbTxDma(DWORD physical_address, WORD size);
BOOL NclrUsbRxDma(DWORD physical_address, WORD size);

#endif
