/*
 *
 * Hardware access header file.
 *
 * Copyright (C) 2010 Vitesse Semiconductor Inc.
 * Author: Lars Povlsen (lpovlsen@vitesse.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * VITESSE SEMICONDUCTOR INC SHALL HAVE NO LIABILITY WHATSOEVER OF ANY
 * KIND ARISING OUT OF OR RELATED TO THE PROGRAM OR THE OPEN SOURCE
 * MATERIALS UNDER ANY THEORY OF LIABILITY.
 *
 */

#ifndef __VCOREIII_HARDWARE_H
#define __VCOREIII_HARDWARE_H

#include <linux/io.h>
#include <linux/mutex.h>

/* We use virtual memory to map the registers */
#ifdef VTSS_IO_OFFSET1
# define VTSS_CRAZY_IO_OFFSET_HACK
#else
# define VTSS_IO_OFFSET1(offset) (map_base_switch + offset)
# define VTSS_IO_OFFSET2(offset) (map_base_cpu + offset)

/* We just want the addresses from VTSS_IOREG() */
# define VTSS_IOREG(t,o)	((void __iomem *)VTSS_IOADDR(t,o))
#endif

#define VTSS_IO_PI_REGION(x) (0x50000000 + (0x4000000*x))

#define VTSS_IO_ORIGIN1_OFFSET 0x60000000
#define VTSS_IO_ORIGIN1_SIZE   0x01000000
#define VTSS_IO_ORIGIN2_OFFSET 0x70000000
#define VTSS_IO_ORIGIN2_SIZE   0x00200000

#if defined(SUPPORT_VTSS_VCOREIII_JAGUAR)
#ifdef SUPPORT_VTSS_VCOREIII_LUTON26
#error More than one architecture defined!
#else
#include <vtss_jaguar_core_regs.h>
#define VCOREIII_EXPECTED_CHIP_ID 0x7460
#define VTSS_DEVCPU_PI_PI_PI_MODE            VTSS_IOREG(VTSS_TO_DEVCPU_PI,0x3)
#endif /* SUPPORT_VTSS_CVOREIII_LUTON26 */
#elif defined(SUPPORT_VTSS_VCOREIII_LUTON26)
#include <vtss_luton26_core_regs.h>
#define VCOREIII_EXPECTED_CHIP_ID 0x7427
#endif

#define VCOREIII_CPU_CLOCK 416666666              /* 416MHz */
#define VCOREIII_AHB_CLOCK (VCOREIII_CPU_CLOCK/2) /* 208MHz - half of the CPU freq */

#ifndef __ASSEMBLER__

extern void __iomem *map_base_switch;
extern void __iomem *map_base_cpu;
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
extern void __iomem *map_base_slv_switch;
#endif  /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

extern struct mutex vcoreiii_api_reg_mutex;

static inline void vcoreiii_api_lock(const char *function)
{
#ifdef DEBUG_VCOREIII_LOCK
	printk("%s:%s getting lock\n", __func__, function);
#endif /* DEBUG_VCOREIII_LOCK */
	mutex_lock(&vcoreiii_api_reg_mutex);
#ifdef DEBUG_VCOREIII_LOCK
	printk("%s:%s got lock\n", __func__, function);
#endif /* DEBUG_VCOREIII_LOCK */
}

static inline void vcoreiii_api_unlock(const char *function)
{
#ifdef DEBUG_VCOREIII_LOCK
	printk("%s:%s freeing lock\n", __func__, function);
#endif
	mutex_unlock(&vcoreiii_api_reg_mutex);
#ifdef DEBUG_VCOREIII_LOCK
	printk("%s:%s freed lock\n", __func__, function);
#endif
}

void vcoreiii_api_lock_wrapper(const char *function);
void vcoreiii_api_unlock_wrapper(const char *function);

static inline void vcoreiii_io_clr(volatile void __iomem *addr, u32 mask)
{
	writel(readl(addr) & ~mask, addr);
}

static inline void vcoreiii_io_set(volatile void __iomem *addr, u32 mask)
{
	writel(readl(addr) | mask, addr);
}

static inline void vcoreiii_io_mask_set(volatile void __iomem *addr, u32 clr_mask, u32 set_mask)
{
    u32 val = readl(addr);
    val &= ~clr_mask;
    val |= set_mask;
    writel(val, addr);
}

#if defined(CONFIG_VTSS_VCOREIII_JAGUAR_DUAL)

extern u32 slv_indirect_readl(volatile u32 __iomem *addr);
extern void slv_indirect_writel(u32 val, volatile u32 __iomem *addr);

static inline volatile void __iomem
*master2slave_addr(volatile void __iomem *addr)
{
    volatile void __iomem *slvaddr = (volatile void __iomem *)
        (((u32)addr) - ((u32)map_base_switch) + ((u32)map_base_slv_switch));
    return slvaddr;
}

static inline void slv_direct_writel(u32 val, volatile void __iomem *addr)
{
    //printk("slv_write(%p) = 0x%0x\n", addr, val);
    writel(val, master2slave_addr(addr));
}

static inline u32 slv_direct_readl(volatile void __iomem *addr)
{
    u32 r = readl(master2slave_addr(addr));
    //printk("slv_read(%p) = 0x%0x\n", addr, r);
    return r;
}

static inline int slv_region1_accessible(u32 addr)
{
    return
        (addr > (u32) map_base_switch) &&
        (addr < (((u32)map_base_switch) + VTSS_IO_ORIGIN1_SIZE));
}

static inline u32 slv_region2_offset(volatile u32 __iomem *addr)
{
    return 0x70000000 + (((u32)addr) - ((u32)map_base_cpu));
}

static inline void slv_writel(u32 val, volatile u32 __iomem *addr) {
    if (slv_region1_accessible((u32)addr))
        slv_direct_writel(val, addr);
    else
        slv_indirect_writel(val, addr);
}

static inline u32 slv_readl(volatile u32 __iomem *addr) {
    if (slv_region1_accessible((u32)addr))
        return slv_direct_readl(addr);
    return slv_indirect_readl(addr);
}

static inline void vcoreiii_io_clr_slv(volatile void __iomem *addr, u32 mask)
{
    slv_writel(slv_readl(addr) & ~mask, addr);
}

static inline void vcoreiii_io_set_slv(volatile void __iomem *addr, u32 mask)
{
    slv_writel(slv_readl(addr) | mask, addr);
}

static inline void vcoreiii_io_mask_set_slv(volatile void __iomem *addr, u32 clr_mask, u32 set_mask)
{
    u32 val = slv_readl(addr);
    val &= ~clr_mask;
    val |= set_mask;
    slv_writel(val, addr);
}

#endif	/* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

u32 vcoreiii_reg_to_phys(void __iomem *addr);

/*
 * check_chip_id - Verify we are on the right hardware
 */

#if defined(VCOREIII_EXPECTED_CHIP_ID) && !defined(VTSS_CRAZY_IO_OFFSET_HACK)

static inline u16
vcoreiii_get_chip_id(void)
{
    return (u16)(VTSS_X_DEVCPU_GCB_CHIP_REGS_CHIP_ID_PART_ID
                 (readl(VTSS_DEVCPU_GCB_CHIP_REGS_CHIP_ID)));
}

static inline bool
vcoreiii_check_chip_id(void)
{
  return (vcoreiii_get_chip_id() & 0xfff0) ==
    (VCOREIII_EXPECTED_CHIP_ID & 0xfff0);
}

#endif /* VCOREIII_EXPECTED_CHIP_ID */

#endif // __ASSEMBLER__

#endif /* __VCOREIII_HARDWARE_H */
