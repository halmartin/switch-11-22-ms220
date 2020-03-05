/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __PLAT_IPROC_MEMORY_H
#define __PLAT_IPROC_MEMORY_H

#include <asm/pgtable.h>

//#define PHYS_OFFSET   (CONFIG_BCM_RAM_BASE+CONFIG_BCM_RAM_START_RESERVED_SIZE)

/* BCM5301x Reference Guide (Section 3) defines three regions of IO  memory, 
 * CORE, IDM, and ARMCORE. The CORE and IDM regions are contiguous, so they 
 * are combined into a single region for mapping and translation purposes
 */

#define IO_CORE_IDM_PA          0x18000000
#define IO_CORE_IDM_SIZE          0x200000
#define IO_ARMCORE_PA           0x19000000
#define IO_ARMCORE_SIZE           0x100000
#define IO_SMAU_IDM_PA          0xf8100000
#define IO_SMAU_IDM_SIZE          0x100000

#define IO_TOTAL_SIZE           (IO_CORE_IDM_SIZE   + \
                                 IO_ARMCORE_SIZE    + \
                                 IO_SMAU_IDM_SIZE)
    
/* VA should be in the range of VMALLOC_START ~ VMALLOC_END-1 */
#define IO_CORE_IDM_VA          (VMALLOC_END - IO_TOTAL_SIZE)
#define IO_ARMCORE_VA           (IO_CORE_IDM_VA + IO_CORE_IDM_SIZE)
#define IO_SMAU_IDM_VA          (IO_ARMCORE_VA + IO_ARMCORE_SIZE)

#define IO_CORE_IDM_PV_DELTA    (IO_CORE_IDM_VA - IO_CORE_IDM_PA)
#define IO_ARMCORE_PV_DELTA     (IO_ARMCORE_VA  - IO_ARMCORE_PA)
#define IO_SMAU_IDM_PV_DELTA    (IO_SMAU_IDM_VA  - IO_SMAU_IDM_PA)

#define HW_IO_VIRT_TO_PHYS(virt)                        \
        (((virt) < IO_ARMCORE_VA) ?                     \
         ((virt) - IO_CORE_IDM_PV_DELTA) :              \
         (((virt) < IO_SMAU_IDM_VA) ?                   \
          ((virt) - IO_ARMCORE_PV_DELTA) :              \
          ((virt) - IO_SMAU_IDM_PV_DELTA)))

/* 
 * HW_IO_PHYS_TO_VIRT used in asm, so the macro that performs this conversion
 * is written using only simple math so that the assembler's constant folding
 * can produce the correct result.

        #define HW_IO_PHYS_TO_VIRT(phys)                \
            (((phys) < IO_ARMCORE_PA) ?                 \
             ((phys) + IO_CORE_IDM_PV_DELTA) :          \
             ((phys) + IO_ARMCORE_PV_DELTA))
 */

#define HW_IO_PHYS_TO_VIRT(phys)                        \
        (((phys) + IO_CORE_IDM_PV_DELTA) +              \
         (((phys) >= IO_ARMCORE_PA) * (IO_ARMCORE_PV_DELTA - IO_CORE_IDM_PV_DELTA)) + \
         (((phys) >= IO_SMAU_IDM_PA) * (IO_SMAU_IDM_PV_DELTA - IO_ARMCORE_PV_DELTA)))

#define CONSISTENT_DMA_SIZE SZ_128M

#ifndef PHYS_RAM_SIZE
#define PHYS_RAM_SIZE   0x08000000
#endif

#endif /* __PLAT_IPROC_MEMORY_H */ 
