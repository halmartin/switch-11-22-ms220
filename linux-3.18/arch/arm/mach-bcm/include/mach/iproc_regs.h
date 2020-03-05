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

#ifndef __IPROC_REGS_H
#define __IPROC_REGS_H __FILE__
#include <linux/types.h>
#include <mach/irqs.h>
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_HR2))
#include "socregs_ing_open.h"
#elif defined(CONFIG_MACH_IPROC_P7)
#ifdef CONFIG_MACH_HR3
#include "../../xldk/hr3/hr3_socregs.h"
#else
#include "socregs_p7_open.h"
#endif /* CONFIG_MACH_HR3 */
#else 
#error "No valid iProc Machine type selected"
#endif /* (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || defined(CONFIG_MACH_HR2)) */

#if defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_IPROC_P7)
#define IPROC_NUM_CPUS                      (1)
#else
#define IPROC_NUM_CPUS                      (2)
#endif

#define IPROC_NUM_IRQS                      (256)

#define IPROC_CPU0_MIN_INT_PRIORITY         (0)
#define IPROC_CPU1_MIN_INT_PRIORITY         (0)

#define IPROC_DDR_MEM_BASE1                 (0x0)

#if defined(CONFIG_MACH_HR2)
#define IPROC_DDR_MEM_BASE2                 (0x60000000)
#else
#define IPROC_DDR_MEM_BASE2                 (0x80000000)
#endif


/* remap to newer reg file defs */
#define CCA_CHIPID                          ChipcommonA_ChipID

#define NAND_NAND_FLASH_REV                 NAND_nand_flash_REVISION
#define NAND_DIRECT_READ_RD_MISS            NAND_direct_read_rd_miss
#define NAND_ECC_MIPS_CORR                  NAND_ecc_mips_corr
#define NAND_NAND_FLASH_FLASH_CACHE127      NAND_nand_flash_FLASH_CACHE127
#define QSPI_MSPI_SPCR0_LSB                 QSPI_mspi_SPCR0_LSB
#define QSPI_MSPI_DISABLE_FLUSH_GEN         QSPI_mspi_DISABLE_FLUSH_GEN
#define QSPI_BSPI_REGS_REV_ID               QSPI_bspi_registers_REVISION_ID
#define QSPI_BSPI_REGS_BSPI_PIO_DATA        QSPI_bspi_registers_BSPI_PIO_DATA
#define QSPI_RAF_START_ADDR                 QSPI_raf_START_ADDR
#define QSPI_RAF_CURR_ADDR                  QSPI_raf_CURR_ADDR
#define QSPI_RAF_INTERRUPT_LR_FULLNESS_REACHED              QSPI_raf_interrupt_LR_fullness_reached
#define QSPI_MSPI_INTERRUPT_MSPI_HALT_SET_TRANSACTION_DONE  QSPI_mspi_interrupt_MSPI_halt_set_transaction_done

#define CCB_TIM0_TIM_TMR1_LOAD              ChipcommonB_tim0_TIM_TIMER1Load
#define CCB_TIM1_TIM_TMR1_LOAD              ChipcommonB_tim1_TIM_TIMER1Load

#define GMAC0_DEVCT                         GMAC0_DEVCONTROL

#define CCA_GPIO_EVT_BASE                   ChipcommonA_GPIOEvent_BASE
#define CCA_GPIO_INPUT_BASE                 ChipcommonA_GPIOInput_BASE
#define CCB_GP_INT_CLR_BASE                 ChipcommonB_GP_INT_TYPE_BASE 

#define PAXB_0_PCIE_CTL                     (PAXB_0_CLK_CONTROL)

#if defined(CONFIG_MACH_IPROC_P7)
#define CCB_MII_MGMT_CTL                    ChipcommonG_MII_Management_Control
#else
#define CCB_MII_MGMT_CTL                    ChipcommonB_MII_Management_Control
#endif

#if defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2)
#define CCB_RNG_CTRL                        ChipcommonB_rng_CTRL
#endif


/* the below might be NS specific */
#define IPROC_CCA_REG_BASE                  (CCA_CHIPID)
#define IPROC_CCB_GPIO_REG_BASE             (IPROC_GPIO_CCB_BASE)
#define IPROC_CCB_PWM_REG_BASE              (CCB_PWMCTL)
#define IPROC_CCB_MDIO_REG_BASE             (CCB_MII_MGMT_CTL)
#define IPROC_CCB_RNG_REG_BASE              (CCB_RNG_CTRL)
#define IPROC_CCB_TIM0_REG_BASE             (CCB_TIM0_TIM_TMR1_LOAD)
#define IPROC_CCB_TIM1_REG_BASE             (CCB_TIM1_TIM_TMR1_LOAD)
#define IPROC_CCB_SRAU_REG_BASE             (CCB_SRAB_CMDSTAT)
#define IPROC_CCB_UART0_REG_BASE            (CCB_UART0_RBR_THR_DLL)

/* iProc Profile 7 specific remapping */
#if defined(CONFIG_MACH_IPROC_P7) 
#define ChipcommonA_ChipID                  (ICFG_CHIP_ID_REG)
#define IPROC_CCA_UART0_REG_BASE            (ChipcommonG_UART0_UART_RBR_THR_DLL)
#define IPROC_CCA_UART1_REG_BASE            (ChipcommonG_UART1_UART_RBR_THR_DLL)

#else /* !CONFIG_MACH_IPROC_P7 */

#define IPROC_CCA_BASE                      (IPROC_CCA_REG_BASE)
#define IPROC_CCA_CORE_CAP_REG_BASE         (IPROC_CCA_BASE + 0x04)
#define IPROC_CCA_CORE_CTL_REG_BASE         (IPROC_CCA_BASE + 0x08)

#define IPROC_CCA_UART0_REG_BASE            (IPROC_CCA_BASE + 0x300)
#define IPROC_CCA_UART1_REG_BASE            (IPROC_CCA_BASE + 0x400)
#define IPROC_CCA_INTMASK_REG_BASE          (IPROC_CCA_BASE + 0x24)
#define IPROC_CCA_UART_CLK_REG_BASE         (IPROC_CCA_BASE + 0xa4)

#endif /* CONFIG_MACH_IPROC_P7 */

#define IPROC_CLK_WR_ACC_REG_BASE           (0x19000000)
#define IPROC_CLK_WR_ACC_REG_OFFSET         (0x000)
#define IPROC_CLK_POLICY_FREQ_REG           (0x19000008)
#define IPROC_CLK_POLICY_FREQ_OFFSET        (0x008)
#define IPROC_CLK_POLICY_CTL_REG            (0x1900000C)
#define IPROC_CLK_POLICY_CTL_OFFSET         (0x00C)
#define IPROC_CLK_POLICY0_MSK_REG           (0x19000010)
#define IPROC_CLK_POLICY0_MSK_OFFSET        (0x010)
#define IPROC_CLK_POLICY1_MSK_REG           (0x19000014)
#define IPROC_CLK_POLICY1_MSK_OFFSET        (0x014)
#define IPROC_CLK_POLICY2_MSK_REG           (0x19000018)
#define IPROC_CLK_POLICY2_MSK_OFFSET        (0x018)
#define IPROC_CLK_POLICY3_MSK_REG           (0x1900001C)
#define IPROC_CLK_POLICY3_MSK_OFFSET        (0x01C)
#define IPROC_CLK_INT_EN_REG                (0x19000020)
#define IPROC_CLK_INT_EN_OFFSET             (0x020)
#define IPROC_CLK_INT_STAT_REG              (0x19000024)
#define IPROC_CLK_INT_STAT_OFFSET           (0x024)
#define IPROC_CLK_LVM_EN_REG                (0x19000034)
#define IPROC_CLK_LVM_EN_OFFSET             (0x034)
#define IPROC_CLK_LVM0_3_REG                (0x19000038)
#define IPROC_CLK_LVM0_3_OFFSET             (0x038)
#define IPROC_CLK_LVM4_7_REG                (0x1900003C)
#define IPROC_CLK_LVM4_7_OFFSET             (0x03C)
#define IPROC_CLK_VLT0_3_REG                (0x19000040)
#define IPROC_CLK_VLT0_3_OFFSET             (0x040)
#define IPROC_CLK_VLT4_7_REG                (0x19000044)
#define IPROC_CLK_VLT4_7_OFFSET             (0x044)
#define IPROC_CLK_BUS_QUIESC_REG            (0x19000100)
#define IPROC_CLK_BUS_QUIESC_OFFSET         (0x100)
#define IPROC_CLK_CORE0_GATE_REG            (0x19000200)
#define IPROC_CLK_CORE0_GATE_OFFSET         (0x200)
#define IPROC_CLK_CORE1_GATE_REG            (0x19000204)
#define IPROC_CLK_CORE1_GATE_OFFSET         (0x204)
#define IPROC_CLK_ARM_SW_GATE_REG           (0x19000210)
#define IPROC_CLK_ARM_SW_GATE_OFFSET        (0x210)
#define IPROC_CLK_ARM_PERIPH_GATE_REG       (0x19000300)
#define IPROC_CLK_ARM_PERIPH_GATE_OFFSET    (0x300)
#define IPROC_CLK_APB0_CLKGATE_REG          (0x19000400)
#define IPROC_CLK_APB0_CLKGATE_OFFSET       (0x400)
#define IPROC_CLK_PL310_DIV_REG             (0x19000A00)
#define IPROC_CLK_PL310_DIV_OFFSET          (0xA00)
#define IPROC_CLK_PL310_TRG_REG             (0x19000A04)
#define IPROC_CLK_PL310_TRG_OFFSET          (0xA04)
#define IPROC_CLK_ARM_SW_DIV_REG            (0x19000A08)
#define IPROC_CLK_ARM_SW_DIV_OFFSET         (0xA08)
#define IPROC_CLK_ARM_SW_TRG_REG            (0x19000A0C)
#define IPROC_CLK_ARM_SW_TRG_OFFSET         (0xA0C)
#define IPROC_CLK_APB_SW_DIV_REG            (0x19000A10)
#define IPROC_CLK_APB_SW_DIV_OFFSET         (0xA10)
#define IPROC_CLK_APB_SW_TRG_REG            (0x19000A14)
#define IPROC_CLK_APB_SW_TRG_OFFSET         (0xA14)
#define IPROC_CLK_PLL_ARMA_REG              (0x19000C00)
#define IPROC_CLK_PLL_ARMA_OFFSET           (0xC00)
#define IPROC_CLK_PLL_ARMB_REG              (0x19000C04)
#define IPROC_CLK_PLL_ARMB_OFFSET           (0xC04)
#define IPROC_CLK_PLL_ARMC_REG              (0x19000C08)
#define IPROC_CLK_PLL_ARMC_OFFSET           (0xC08)
#define IPROC_CLK_PLL_ARMCTL0_REG           (0x19000C0C)
#define IPROC_CLK_PLL_ARMCTL0_OFFSET        (0xC0C)
#define IPROC_CLK_PLL_ARMCTL1_REG           (0x19000C10)
#define IPROC_CLK_PLL_ARMCTL1_OFFSET        (0xC10)
#define IPROC_CLK_PLL_ARMCTL2_REG           (0x19000C14)
#define IPROC_CLK_PLL_ARMCTL2_OFFSET        (0xC14)
#define IPROC_CLK_PLL_ARMCTL3_REG           (0x19000C18)
#define IPROC_CLK_PLL_ARMCTL3_OFFSET        (0xC18)
#define IPROC_CLK_PLL_ARMCTL4_REG           (0x19000C1C)
#define IPROC_CLK_PLL_ARMCTL4_OFFSET        (0xC1C)
#define IPROC_CLK_PLL_ARMCTL5_REG           (0x19000C20)
#define IPROC_CLK_PLL_ARMCTL5_OFFSET        (0xC20)
#define IPROC_CLK_PLL_ARM_OFFSET_REG        (0x19000C24)
#define IPROC_CLK_PLL_ARM_OFFSET_OFFSET     (0xC24)
#define IPROC_CLK_ARM_DIV_REG               (0x19000E00)
#define IPROC_CLK_ARM_DIV_OFFSET            (0xE00)
#define IPROC_CLK_ARM_SEG_TRG_REG           (0x19000E04)
#define IPROC_CLK_ARM_SEG_TRG_OFFSET        (0xE04)
#define IPROC_CLK_ARM_SEG_TRG_OVRD_REG      (0x19000E08)
#define IPROC_CLK_ARM_SEG_TRG_OVRD_OFFSET   (0xE08)
#define IPROC_CLK_PLL_DEBUG_REG             (0x19000E10)
#define IPROC_CLK_PLL_DEBUG_OFFSET          (0xE10)
#define IPROC_CLK_ACTIVITY_MON1_REG         (0x19000E20)
#define IPROC_CLK_ACTIVITY_MON1_OFFSET      (0xE20)
#define IPROC_CLK_ACTIVITY_MON2_REG         (0x19000E24)
#define IPROC_CLK_ACTIVITY_MON2_OFFSET      (0xE24)
#define IPROC_CLK_GATE_DBG_REG              (0x19000E40)
#define IPROC_CLK_GATE_DBG_OFFSET           (0xE40)
#define IPROC_CLK_APB_CLKGATE_DBG1_REG      (0x19000E48)
#define IPROC_CLK_APB_CLKGATE_DBG1_OFFSET   (0xE48)
#define IPROC_CLK_CLKMON_REG                (0x19000E64)
#define IPROC_CLK_CLKMON_OFFSET             (0xE64)
#define IPROC_CLK_KPROC_CCU_PROF_CTL_REG    (0x19000E90)
#define IPROC_CLK_KPROC_CCU_PROF_CTL_OFFSET (0xE90)
#define IPROC_CLK_KPROC_CCU_PROF_SEL_REG    (0x19000E94)
#define IPROC_CLK_KPROC_CCU_PROF_SEL_OFFSET (0xE94)
#define IPROC_CLK_KPROC_CCU_PROF_CNT_REG    (0x19000E98)
#define IPROC_CLK_KPROC_CCU_PROF_CNT_OFFSET (0xE98)
#define IPROC_CLK_KPROC_CCU_PROF_DBG_REG    (0x19000E9C)
#define IPROC_CLK_KPROC_CCU_PROF_DBG_OFFSET (0xE9C)
#define IPROC_CLK_POLICY_DBG_REG            (0x19000EC0)
#define IPROC_CLK_POLICY_DBG_OFFSET         (0xEC0)
#define IPROC_CLK_TGTMASK_DBG1_REG          (0x19000EC4)
#define IPROC_CLK_TGTMASK_DBG1_OFFSET       (0xEC4)
#define IPROC_RST_WR_ACCESS_REG             (0x19000F00)
#define IPROC_RST_WR_ACCESS_OFFSET          (0xF00)
#define IPROC_RST_SOFT_RSTN_REG             (0x19000F04)
#define IPROC_RST_SOFT_RSTN_OFFSET          (0xF04)
#define IPROC_RST_A9C_SOFT_RSTN_REG         (0x19000F08)
#define IPROC_RST_A9C_SOFT_RSTN_OFFSET      (0xF08)
#define IPROC_RST_A9CORE_SOFT_RSTN_REG      (0x19000F08)
#define IPROC_RST_A9CORE_SOFT_RSTN_OFFSET   (0xF08)

#define PLLARMC_PLLARM_MDIV_SHIFT           0
#define PLLARMC_PLLARM_LOAD_EN_MASK         (0x00000800)
#define PLLARMA_PLLARM_NDIV_INT_MASK        (0x0003FF00)
#define PLLARMA_PLLARM_NDIV_INT_SHIFT       8
#define PLLARMB_PLLARM_NDIV_FRAC_MASK       (0x000FFFFF)
#define PLLARMB_PLLARM_NDIV_FRAC_SHIFT      0
#define ARMCTL5_PLLARM_H_MDIV_MASK          (0x000000FF)
#define ARMCTL5_PLLARM_H_MDIV_SHIFT         0

#define IPROC_CLK_CTL_REG                   (IPROC_CCA_CLK_CTL_REG_BASE + 0x000)
#define IPROC_CCA_CLK_HW_REQ_OFF            0x00000020

#define IPROC_DDRC_REG_BASE                 (DDR_DENALI_CTL_00) //(0x18010000)
#define IPROC_DMAC_REG_BASE                 (DMAC_P1330_NON_DS) //(0x1802C000)
#define IPROC_PCIE_AXIB0_REG_BASE           (PAXB_0_PCIE_CTL) //(0x18012000)
#define IPROC_PCIE_AXIB1_REG_BASE           (PAXB_1_PCIE_CTL) //(0x18013000)
#define IPROC_PCIE_AXIB2_REG_BASE           (PAXB_2_PCIE_CTL) //(0x18014000)

/* USB */
#if (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2))
#define IPROC_USB20_EHCI_REG_BASE           (0x1802A000)
#define IPROC_USB20_EHCI_REG_SIZE           (0x0FFF)
#define IPROC_USB20_OHCI_REG_BASE           (0x1802B000)
#define IPROC_USB20_OHCI_REG_SIZE           (0x0FFF)
#elif (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_HR3))
#define IPROC_USB20_EHCI_REG_BASE           (0x18048000)
#define IPROC_USB20_EHCI_REG_SIZE           (0x07FF)
#define IPROC_USB20_OHCI_REG_BASE           (0x18048800)
#define IPROC_USB20_OHCI_REG_SIZE           (0x07FF)
#endif

#define IPROC_USB2D_REG_BASE                USB2D_ENDPNT_IN_CTRL_0  /* Defined in mach/socregs_xx_open.h */
#define IPROC_USB2D_REG_SIZE                (0x2000) /* 8KB */
#define IPROC_USB2D_IRQ                     BCM_INT_ID_USB2D2CORE_USB2D_INT /* Defined in mach/irqs.h */

#define IPROC_USB30_REG_BASE                (0x18023000)
#define IPROC_USB20_PHY_REG_BASE            (0x18023000) /* ??*/


/* AMAC */
#define IPROC_MAX_GMAC_CORES                4
#if (defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_HR3))
#define IPROC_NUM_GMACS                     1
#define IPROC_GMAC0_REG_BASE                (GMAC0_DEVCONTROL) /* Defined in mach/socregs_xx_open.h */
#define IPROC_GMAC1_REG_BASE                0 /* Unused */
#define IPROC_GMAC2_REG_BASE                0 /* Unused */
#define IPROC_GMAC3_REG_BASE                0 /* Unused */
#define IPROC_GMAC0_INT                     BCM_INT_ID_GMAC_INT0 /* Defined in mach/irqs.h */
#define IPROC_GMAC1_INT                     0 /* Unused */
#define IPROC_GMAC2_INT                     0 /* Unused */
#define IPROC_GMAC3_INT                     0 /* Unused */
#elif (defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_KT2) || \
	defined(CONFIG_MACH_SB2))
#define IPROC_NUM_GMACS                     2
#define IPROC_GMAC0_REG_BASE                (GMAC0_DEVCONTROL) /* Defined in mach/socregs_xx_open.h */
#define IPROC_GMAC1_REG_BASE                (GMAC1_DEVCONTROL) /* Defined in mach/socregs_xx_open.h */
#define IPROC_GMAC2_REG_BASE                0 /* Unused */
#define IPROC_GMAC3_REG_BASE                0 /* Unused */
#define IPROC_GMAC0_INT                     BCM_INT_ID_GMAC_INT0 /* Defined in mach/irqs.h */
#define IPROC_GMAC1_INT                     BCM_INT_ID_GMAC_INT1 /* Defined in mach/irqs.h */
#define IPROC_GMAC2_INT                     0 /* Unused */
#define IPROC_GMAC3_INT                     0 /* Unused */
#endif

/* SDIO */
#if defined(CONFIG_MACH_HR3)
#define IPROC_SDIO0_REG_BASE                (0x18041000)
#else
#define IPROC_SDIO0_REG_BASE                0
#endif /* defined(CONFIG_MACH_HR3) */


#define IPROC_CTF_REG_BASE                  (0x18027C00)

#define IPROC_I2S_REG_BASE                  (0x1802A000)
#define IPROC_CCU_PROF_CTL_REG_BASE         (0x19000E90)

/* IDM / CRU / DMU */
#define IPROC_CRU_REG_BASE                  CRU_control
#define IPROC_DMU_REG_BASE                  DMU_PCU_IPROC_CONTROL
#define IPROC_IDM_REG_BASE                  (IHOST_M0_IO_CONTROL_DIRECT - 0x408)
#if (!defined(CONFIG_MACH_GH) && !defined(CONFIG_MACH_SB2) && \
	!defined(CONFIG_MACH_HR3))
#define DMU_PCU_IPROC_CONTROL               0x1803f000
#endif 

/* Straps */
#if defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_KT2) || \
	defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_HR3)
#define IPROC_DMU_STRAPS_OFFSET             DMU_PCU_IPROC_STRAPS_CAPTURED_BASE
#define IPROC_STRAP_BOOT_DEV_SHIFT          DMU_PCU_IPROC_STRAPS_CAPTURED__strap_boot_dev_R
#define IPROC_STRAP_NAND_TYPE_SHIFT         DMU_PCU_IPROC_STRAPS_CAPTURED__strap_nand_type_R
#define IPROC_STRAP_NAND_PAGE_SHIFT         DMU_PCU_IPROC_STRAPS_CAPTURED__strap_nand_page_R
#endif
#define IPROC_STRAP_BOOT_DEV_QSPI           (0)
#define IPROC_STRAP_BOOT_DEV_NAND           (1)
#define IPROC_STRAP_BOOT_DEV_PNOR           (4)

/* NAND and QSPI */
#if defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_KT2)
#define IPROC_IDM_NAND_REG_BASE             NAND_IDM_IDM_IO_CONTROL_DIRECT
#define IPROC_NAND_IRQ_START                (106)
#define IPROC_IDM_QSPI_REG_BASE             QSPI_IDM_IDM_IO_CONTROL_DIRECT
#define IPROC_QSPI_IRQ_START                (110)
#define IPROC_QSPI_IRQ_END                  (116)
#elif defined(CONFIG_MACH_IPROC_P7)
#define IPROC_IDM_NAND_REG_BASE             NAND_IDM_IDM_IO_CONTROL_DIRECT
#define IPROC_IDM_QSPI_REG_BASE             QSPI_IDM_IDM_IO_CONTROL_DIRECT

#if defined(CONFIG_MACH_HR3)
#define IPROC_NAND_IRQ_START                (89)
#define IPROC_QSPI_IRQ_START                (90)
#define IPROC_QSPI_IRQ_END                  (90)
#else
#define IPROC_NAND_IRQ_START                (101)
#define IPROC_QSPI_IRQ_START                (102)
#define IPROC_QSPI_IRQ_END                  (102)
#endif

#endif

/* PNOR */
#ifdef CONFIG_MACH_IPROC_P7
#define S29GL_FLASH_SIZE                    0x04000000
#define S29GL_FLASH_PHYS                    0xe8000000
#define PNOR_NAND_SEL_REG                   ICFG_IPROC_IOPAD_SW_OVERRIDE_CTRL
#define PNOR_NAND_SEL_REG_OVERRIDE          ICFG_IPROC_IOPAD_SW_OVERRIDE_CTRL__iproc_pnor_sel_sw_ovwr
#define PNOR_NAND_SEL_REG_PNOR_SEL          ICFG_IPROC_IOPAD_SW_OVERRIDE_CTRL__iproc_pnor_sel
#elif defined(CONFIG_MACH_HR2)
#define S29GL_FLASH_SIZE                    0x04000000
#define S29GL_FLASH_PHYS                    0x20000000
#define PNOR_NAND_SEL_REG                   0x1803fc3c
#define PNOR_NAND_SEL_REG_OVERRIDE          2
#define PNOR_NAND_SEL_REG_PNOR_SEL          3
#endif

/* ARM9 Private memory region */
#define IPROC_PERIPH_BASE                   (0x19020000) //(IHOST_A9MP_scu_CONTROL)
#define IPROC_PERIPH_SCU_REG_BASE           (IPROC_PERIPH_BASE)
#define IPROC_PERIPH_INT_CTRL_REG_BASE      (IPROC_PERIPH_BASE + 0x100)
#define IPROC_PERIPH_GLB_TIM_REG_BASE       (IPROC_PERIPH_BASE + 0x200)
#define IPROC_PERIPH_PVT_TIM_REG_BASE       (IPROC_PERIPH_BASE + 0x600)
#define IPROC_PERIPH_PVT_WDT_REG_BASE       (IPROC_PERIPH_BASE + 0x620)
#define IPROC_PERIPH_INT_DISTR_REG_BASE     (IPROC_PERIPH_BASE + 0x1000)
#define IPROC_L2CC_REG_BASE                 (IPROC_PERIPH_BASE + 0x2000)
#define IPROC_GTIM_GLB_LO                   (0x00000000)
#define IPROC_GTIM_GLB_HI                   (0x00000004)
#define IPROC_GTIM_GLB_CTL                  (0x00000008)
#define IPROC_GTIM_GLB_STS                  (0x0000000C)
#define IPROC_GTIM_GLB_CMP_LO               (0x00000010)
#define IPROC_GTIM_GLB_CMP_HI               (0x00000014)
#define IPROC_GTIM_GLB_INCR                 (0x00000018)

/* Structures and bit definitions */
/* SCU Control register */
#define IPROC_SCU_CTRL_SCU_EN               (0x00000001)
#define IPROC_SCU_CTRL_ADRFLT_EN            (0x00000002)
#define IPROC_SCU_CTRL_PARITY_EN            (0x00000004)
#define IPROC_SCU_CTRL_SPEC_LNFL_EN         (0x00000008)
#define IPROC_SCU_CTRL_FRC2P0_EN            (0x00000010)
#define IPROC_SCU_CTRL_SCU_STNDBY_EN        (0x00000020)
#define IPROC_SCU_CTRL_IC_STNDBY_EN         (0x00000040)

/* ARM A9 Private Timer */
#define IPROC_PVT_TIM_CTRL_TIM_EN           (0x00000001)
#define IPROC_PVT_TIM_CTRL_AUTO_RELD        (0x00000002)
#define IPROC_PVT_TIM_CTRL_INT_EN           (0x00000004)
#define IPROC_PVT_TIM_CTRL_PRESC_MASK       (0x0000FF00)
#define IPROC_PVT_TIM_INT_STATUS_SET        (0x00000001)

/* Global timer */
#define IPROC_GLB_TIM_CTRL_STCS_EN          (0x00000000)
#define IPROC_GLB_TIM_CTRL_TIM_EN           (0x00000001)
#define IPROC_GLB_TIM_CTRL_COMP_EN          (0x00000002)
#define IPROC_GLB_TIM_CTRL_INT_EN           (0x00000004)
#define IPROC_GLB_TIM_CTRL_AUTO_INC         (0x00000008)
#define IPROC_GLB_TIM_CTRL_STCM_SET         (0x0000000C)
#define IPROC_GLB_TIM_CTRL_PRESC_MASK       (0x0000FF00)
#define IPROC_GLB_TIM_INT_STATUS_SET        (0x00000001)

#define GLBTMR_GLOB_STATUS_EVENT_G_SHIFT    (0x00000000)
#define GLBTMR_GLOB_CTRL_TIMER_EN_G_SHIFT   (0x00000000)

/* GIC(Generic Interrupt controller) CPU interface registers */
#define IPROC_GICCPU_CTL_REG_BASE           (0x19020100)
#define IPROC_GICCPU_PRI_MASK_OFFSET        (0x04)
#define IPROC_GICCPU_BIN_PT_OFFSET          (0x08)
#define IPROC_GICCPU_INT_ACK_OFFSET         (0x0C)
#define IPROC_GICCPU_EOI_OFFSET             (0x10)
#define IPROC_GICCPU_RUN_PRI_OFFSET         (0x14)
#define IPROC_GICCPU_HI_PEND_OFFSET         (0x18)
#define IPROC_GICCPU_ALIAS_BIN_PT_NS_OFFSET (0x1C)
#define IPROC_GICCPU_INT_GFC_OFFSET         (0x40)
#define IPROC_GICCPU_INT_FIQ_SET_OFFSET     (0x44)
#define IPROC_GICCPU_INTEG_MATCH_OFFSET     (0x50)
#define IPROC_GICCPU_INTEG_ENABLE_OFFSET    (0x54)
#define IPROC_GICCPU_CPU_IDENT_OFFSET       (0xFC)

#define IPROC_GIC_CI_CTRL_EN                (0x00000001)
#define IPROC_GIC_CI_PMR_PRIO_MASK          (0x000000FF)
#define IPROC_GIC_CI_BPR_BP_MASK            (0x00000003)
#define IPROC_GIC_CI_IAR_INTID_MASK         (0x000003FF)
#define IPROC_GIC_CI_IAR_CPUID_MASK         (0x00001C00)
#define IPROC_GIC_CI_IAR_CPUID_OFFSET       (10)
#define IPROC_GIC_CI_EOIR_INTID_MASK        (0x000003FF)
#define IPROC_GIC_CI_EOIR_CPUID_MASK        (0x00001C00)
#define IPROC_GIC_CI_EOIR_CPUID_OFFSET      (10)
#define IPROC_GIC_CI_RPR_PRIO_MASK          (0x000000FF)
#define IPROC_GIC_CI_HPIR_PENDID_MASK       (0x000003FF)
#define IPROC_GIC_CI_HPIR_CPUID_MASK        (0x00001C00)
#define IPROC_GIC_CI_HPIR_CPUID_OFFSET      (10)
#define IPROC_GIC_CI_ABPR_BP_MASK           (0x00000003)

#define IPROC_GIC_DIST_CTRL_S_EN_S          (0x00000001)
#define IPROC_GIC_DIST_CTRL_S_EN_NS         (0x00000002)
#define IPROC_GIC_DIST_CTRL_NS_EN_NS        (0x00000001)

#define IPROC_GIC_DIST_ISR_BIT_SIZE         (1)
#define IPROC_GIC_DIST_ISER_BIT_SIZE        (1)
#define IPROC_GIC_DIST_ICER_BIT_SIZE        (1)
#define IPROC_GIC_DIST_ISPR_BIT_SIZE        (1)
#define IPROC_GIC_DIST_ISPR_SECURE          (1)
#define IPROC_GIC_DIST_ISPR_NON_SECURE      (0)
#define IPROC_GIC_DIST_ICPR_BIT_SIZE        (1)
#define IPROC_GIC_DIST_IPR_BIT_SIZE         (8)
#define IPROC_GIC_DIST_IPTR_BIT_SIZE        (8)
#define IPROC_GIC_DIST_IPTR_CPU0            (0x01)
#define IPROC_GIC_DIST_IPTR_CPU1            (0x02)
#define IPROC_GIC_DIST_SGIR_ID_MASK         (0xF)
#define IPROC_GIC_DIST_SGIR_TR_LIST_MASK    (0x00FF0000)
#define IPROC_GIC_DIST_SGIR_TR_LIST_BOFFSET (16)
#define IPROC_GIC_DIST_SGIR_TR_FILT_MASK    (0x03000000)
#define IPROC_GIC_DIST_SGIR_TR_FILT_BOFFSET (24)
#define IPROC_GIC_DIST_SGIR_TR_FILT_FW_LIST (0)
#define IPROC_GIC_DIST_SGIR_TR_FILT_FW_ALL_EX_ME    (0x01)
#define IPROC_GIC_DIST_SGIR_TR_FILT_FW_ME_ONLY      (0x02)

#define IPROC_INTR_LEVEL_SENSITIVE          (1)
#define IPROC_INTR_EDGE_TRIGGERED           (2)

/* GPIO Driver */
#if defined(CONFIG_IPROC_GPIO) || defined(CONFIG_IPROC_GPIO_MODULE) || \
	defined(CONFIG_IPROC_PWM) || defined(CONFIG_IPROC_PWM_MODULE)

/* Chipcommon A GPIO */
/* CONFIG_MACH_HX4, CONFIG_MACH_HR2, CONFIG_MACH_KT2 */
#define IPROC_CCA_INT_STS               (ChipcommonA_IntStatus_BASE)
#define IPROC_CCA_INT_MASK              (ChipcommonA_IntMask_BASE)
#define IPROC_GPIO_CCA_BASE             (ChipcommonA_GPIOInput)
#define IPROC_GPIO_CCA_DIN              (ChipcommonA_GPIOInput_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_DOUT             (ChipcommonA_GPIOOut_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_EN               (ChipcommonA_GPIOOutEn_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_INT_LEVEL        (ChipcommonA_GPIOIntPolarity_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_INT_LEVEL_MASK   (ChipcommonA_GPIOIntMask_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_INT_EVENT        (ChipcommonA_GPIOEvent_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_INT_EVENT_MASK   (ChipcommonA_GPIOEventIntMask_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_WATCHDOG_COUNTER (ChipcommonA_WatchdogCounter_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_INT_EDGE         (ChipcommonA_GPIOEventIntPolarity_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_TIMER_VAL        (ChipcommonA_GPIOTimerVal_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_TIMEOUT_MASK     (ChipcommonA_GPIOTimerOutMask_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_CLK_DIV          (ChipcommonA_ClkDiv_BASE - ChipcommonA_GPIOInput_BASE)
#define IPROC_GPIO_CCA_DEBUG            (ChipcommonA_GPIODebugSel_BASE - ChipcommonA_GPIOInput_BASE)

/* Chipcommon B GPIO */
#if defined(CONFIG_MACH_IPROC_P7)
#define IPROC_GPIO_CCG_BASE             (ChipcommonG_GP_DATA_IN)
#define IPROC_GPIO_CCB_BASE             (ChipcommonG_GP_DATA_IN)
#define IPROC_GPIO_CCB_DIN              (ChipcommonG_GP_DATA_IN_BASE)
#define IPROC_GPIO_CCB_DOUT             (ChipcommonG_GP_DATA_OUT_BASE)
#define IPROC_GPIO_CCB_EN               (ChipcommonG_GP_OUT_EN_BASE)
#define IPROC_GPIO_CCB_INT_TYPE         (ChipcommonG_GP_INT_TYPE_BASE)
#define IPROC_GPIO_CCB_INT_DE           (ChipcommonG_GP_INT_DE_BASE)
#define IPROC_GPIO_CCB_INT_EDGE         (ChipcommonG_GP_INT_EDGE_BASE)
#define IPROC_GPIO_CCB_INT_MASK         (ChipcommonG_GP_INT_MSK_BASE)
#define IPROC_GPIO_CCB_INT_STAT         (ChipcommonG_GP_INT_STAT_BASE)
#define IPROC_GPIO_CCB_INT_MSTAT        (ChipcommonG_GP_INT_MSTAT_BASE)
#define IPROC_GPIO_CCB_INT_CLR          (ChipcommonG_GP_INT_CLR_BASE)
#define IPROC_GPIO_CCB_AUX_SEL          (ChipcommonG_GP_AUX_SEL_BASE)
#define IPROC_GPIO_CCB_INIT_VAL         (ChipcommonG_GP_INIT_VAL_BASE)
#define IPROC_GPIO_CCB_PAD_RES          (ChipcommonG_GP_PAD_RES_BASE)
#define IPROC_GPIO_CCB_RES_EN           (ChipcommonG_GP_RES_EN_BASE)
#define IPROC_GPIO_CCB_TST_IN           (ChipcommonG_GP_TEST_INPUT_BASE)
#define IPROC_GPIO_CCB_TST_OUT          (ChipcommonG_GP_TEST_OUTPUT_BASE)
#define IPROC_GPIO_CCB_TST_EN           (ChipcommonG_GP_TEST_ENABLE_BASE)
#define IPROC_GPIO_CCB_PRB_EN           (ChipcommonG_GP_PRB_ENABLE_BASE)
#define IPROC_GPIO_CCB_PRB_OE           (ChipcommonG_GP_PRB_OE_BASE)
#else
/* CONFIG_MACH_HX4, CONFIG_MACH_HR2, CONFIG_MACH_KT2 */
#define IPROC_GPIO_CCB_BASE             (ChipcommonB_GP_DATA_IN)
#define IPROC_GPIO_CCB_DIN              (ChipcommonB_GP_DATA_IN_BASE)
#define IPROC_GPIO_CCB_DOUT             (ChipcommonB_GP_DATA_OUT_BASE)
#define IPROC_GPIO_CCB_EN               (ChipcommonB_GP_OUT_EN_BASE)
#define IPROC_GPIO_CCB_INT_TYPE         (ChipcommonB_GP_INT_TYPE_BASE)
#define IPROC_GPIO_CCB_INT_DE           (ChipcommonB_GP_INT_DE_BASE)
#define IPROC_GPIO_CCB_INT_EDGE         (ChipcommonB_GP_INT_EDGE_BASE)
#define IPROC_GPIO_CCB_INT_MASK         (ChipcommonB_GP_INT_MSK_BASE)
#define IPROC_GPIO_CCB_INT_STAT         (ChipcommonB_GP_INT_STAT_BASE)
#define IPROC_GPIO_CCB_INT_MSTAT        (ChipcommonB_GP_INT_MSTAT_BASE)
#define IPROC_GPIO_CCB_INT_CLR          (ChipcommonB_GP_INT_CLR_BASE)
#define IPROC_GPIO_CCB_AUX_SEL          (ChipcommonB_GP_AUX_SEL_BASE)
#define IPROC_GPIO_CCB_INIT_VAL         (ChipcommonB_GP_INIT_VAL_BASE)
#define IPROC_GPIO_CCB_PAD_RES          (ChipcommonB_GP_PAD_RES_BASE)
#define IPROC_GPIO_CCB_RES_EN           (ChipcommonB_GP_RES_EN_BASE)
#define IPROC_GPIO_CCB_TST_IN           (ChipcommonB_GP_TEST_INPUT_BASE)
#define IPROC_GPIO_CCB_TST_OUT          (ChipcommonB_GP_TEST_OUTPUT_BASE)
#define IPROC_GPIO_CCB_TST_EN           (ChipcommonB_GP_TEST_ENABLE_BASE)
#define IPROC_GPIO_CCB_PRB_EN           (ChipcommonB_GP_PRB_ENABLE_BASE)
#define IPROC_GPIO_CCB_PRB_OE           (ChipcommonB_GP_PRB_OE_BASE)
#endif
#if defined(CONFIG_MACH_IPROC_P7)
#if defined(CONFIG_MACH_HR3)
#define IPROC_GPIO_CCG_INT              (96)
#else  /* CONFIG_MACH_HR3 */
#define IPROC_GPIO_CCG_INT              (116)
#endif /* CONFIG_MACH_HR3 */
#else
/* CONFIG_MACH_HX4, CONFIG_MACH_HR2, CONFIG_MACH_KT2 */
#define IPROC_GPIO_CCA_INT              (123)
#define IPROC_GPIO_CCB_INT              (125)
#endif
#endif /* CONFIG_IPROC_GPIO || CONFIG_IPROC_GPIO_MODULE */

/* ChipCommonB Timer */
#if defined(CONFIG_MACH_IPROC_P7)
#define IPROC_CCB_TIMER0_REGS_VA        HW_IO_PHYS_TO_VIRT(ChipcommonG_tim0_TIM_TIMER1Load)
#define IPROC_CCB_TIMER1_REGS_VA        HW_IO_PHYS_TO_VIRT(ChipcommonG_tim1_TIM_TIMER1Load)
#define IPROC_CCB_TIMER2_REGS_VA        HW_IO_PHYS_TO_VIRT(ChipcommonG_tim2_TIM_TIMER1Load)
#define IPROC_CCB_TIMER3_REGS_VA        HW_IO_PHYS_TO_VIRT(ChipcommonG_tim3_TIM_TIMER1Load)

#if defined(CONFIG_MACH_HR3)
#define IPROC_CCB_TIMER_INT_START       (99)
#else
#define IPROC_CCB_TIMER_INT_START       (119)
#endif

#define IPROC_CCB_TIMER_INT_COUNT       (4)
#else /* CONFIG_MACH_HX4, CONFIG_MACH_HR2, CONFIG_MACH_KT2 */
#define IPROC_CCB_TIMER0_REGS_VA        (IPROC_CCB_TIM0_REG_VA + 0x00)
#define IPROC_CCB_TIMER1_REGS_VA        (IPROC_CCB_TIM0_REG_VA + 0x20)
#define IPROC_CCB_TIMER2_REGS_VA        (IPROC_CCB_TIM1_REG_VA + 0x00)
#define IPROC_CCB_TIMER3_REGS_VA        (IPROC_CCB_TIM1_REG_VA + 0x20)
#define IPROC_CCB_TIMER_INT_START       (129)
#define IPROC_CCB_TIMER_INT_COUNT       (4)
#endif

/* ChipCommonB Watchdog */
#if defined(CONFIG_IPROC_CCB_WDT) || defined(CONFIG_IPROC_CCB_WDT_MODULE)
/* CCB WDT could be set only when CONFIG_MACH_HR2 or CONFIG_MACH_HX4 is set */
#define IPROC_CCB_WDT_WDOGLOAD          ChipcommonB_WDT_WDOGLOAD
#define IPROC_CCB_WDT_REG_BASE          IPROC_CCB_WDT_WDOGLOAD
#if defined(CONFIG_MACH_HX4) || defined(CONFIG_MACH_HR2) || defined(CONFIG_MACH_KT2)
#define IPROC_CCB_WDT_BOOTSTATUS        DMU_PCU_CRU_RESET_REASON
#define IPROC_CCB_WDT_BOOTSTATUS_BIT    DMU_PCU_CRU_RESET_REASON__watchdog_reset
#endif
#endif /* CONFIG_IPROC_CCB_WDT || CONFIG_IPROC_CCB_WDT_MODULE */

/* ChipCommonG Watchdog */
#if defined(CONFIG_IPROC_CCG_WDT) || defined(CONFIG_IPROC_CCG_WDT_MODULE)
#define IPROC_CCG_WDT_REG_BASE          ChipcommonG_WDT_WDOGLOAD
#if defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_HR3)
#define IPROC_CCG_WDT_BOOTSTATUS        DMU_PCU_CRU_RESET_REASON
#define IPROC_CCG_WDT_BOOTSTATUS_BIT    DMU_PCU_CRU_RESET_REASON__watchdog_reset
#endif
#endif /* CONFIG_IPROC_CCG_WDT || CONFIG_IPROC_CCG_WDT_MODULE */

#if defined(CONFIG_IPROC_SP805_WDT) || defined(CONFIG_IPROC_SP805_WDT_MODULE)
#if defined(CONFIG_IPROC_CCB_WDT) || defined(CONFIG_IPROC_CCB_WDT_MODULE)
#define IPROC_SP805_WDT_REG_BASE        IPROC_CCB_WDT_REG_BASE
#define IPROC_SP805_WDT_BOOTSTATUS      IPROC_CCB_WDT_BOOTSTATUS
#define IPROC_SP805_WDT_BOOTSTATUS_BIT  IPROC_CCB_WDT_BOOTSTATUS_BIT
#elif defined(CONFIG_IPROC_CCG_WDT) || defined(CONFIG_IPROC_CCG_WDT_MODULE)
#define IPROC_SP805_WDT_REG_BASE        IPROC_CCG_WDT_REG_BASE
#define IPROC_SP805_WDT_BOOTSTATUS      IPROC_CCG_WDT_BOOTSTATUS
#define IPROC_SP805_WDT_BOOTSTATUS_BIT  IPROC_CCG_WDT_BOOTSTATUS_BIT
#else
#warning "Wrong SP805 WDT config"
#endif
#endif /* CONFIG_IPROC_SP805_WDT */

#endif /*__IPROC_REGS_H */
