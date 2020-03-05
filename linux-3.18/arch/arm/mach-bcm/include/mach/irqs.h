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
#ifndef __PLAT_IPROC_IRQS_H
#define __PLAT_IPROC_IRQS_H

#define BCM_INT_PRIORITY_MAX                32  /* there are only 32 priority are supported */
#define BCM_INT_SPI_MAX                     128 /* there are 128 shared peripheral interrupt*/
/*=====================================================================*/
/* Software Trigger Interrupt IDs                                      */
/*=====================================================================*/
#define BCM_INT_ID_STI0                     0
#define BCM_INT_ID_STI1                     1
#define BCM_INT_ID_STI2                     2
#define BCM_INT_ID_STI3                     3
#define BCM_INT_ID_STI4                     4
#define BCM_INT_ID_STI5                     5
#define BCM_INT_ID_STI6                     6
#define BCM_INT_ID_STI7                     7
#define BCM_INT_ID_STI8                     8
#define BCM_INT_ID_STI9                     9
#define BCM_INT_ID_STI10                    10
#define BCM_INT_ID_STI11                    11
#define BCM_INT_ID_STI12                    12
#define BCM_INT_ID_STI13                    13
#define BCM_INT_ID_STI14                    14
#define BCM_INT_ID_STI15                    15
#define BCM_INT_ID_STI_MAX                  16 /* terminating ID */

/*=====================================================================*/
/* Private Peripheral Interrupt IDs                                    */
/*=====================================================================*/
#define BCM_INT_ID_PPI0                     (0 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI1                     (1 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI2                     (2 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI3                     (3 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI4                     (4 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI5                     (5 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI6                     (6 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI7                     (7 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI8                     (8 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI9                     (9 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI10                    (10 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI11                    (11 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI12                    (12 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI13                    (13 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI14                    (14 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI15                    (15 + BCM_INT_ID_STI_MAX)
#define BCM_INT_ID_PPI_MAX                  (16 + BCM_INT_ID_STI_MAX) /* terminating ID */

/*=====================================================================*/
/* iHost Interrupt IDs                                                 */
/*=====================================================================*/
#define BCM_INT_ID_IHOST_L2CC               32
#define BCM_INT_ID_IHOST_PWRWDOG            33
#define BCM_INT_ID_IHOST_TRAP8              34
#define BCM_INT_ID_IHOST_TRAP1              35
#define BCM_INT_ID_IHOST_COMMTX             36
#define BCM_INT_ID_IHOST_COMMRX             38
#define BCM_INT_ID_IHOST_PMU                40
#define BCM_INT_ID_IHOST_CT                 42
#define BCM_INT_ID_IHOST_DEFFLG_CPU0        44
#define BCM_INT_ID_IHOST_DEFFLG_CPU1        45
#define BCM_INT_ID_IHOST_CPU0_PAR		    46
#define BCM_INT_ID_IHOST_CPU1_PAR	        47
#define BCM_INT_ID_IHOST_SCU0_PAR		    48
#define BCM_INT_ID_IHOST_SCU1_PAR	        49
#define BCM_INT_ID_IHOST_I2_SEC	    	    50
#define BCM_INT_ID_IHOST_MAX                51

/*=====================================================================*/
/* IDM Interrupt IDs                                                   */
/*=====================================================================*/
#if defined(CONFIG_MACH_HR3)
#define BCM_INT_ID_IHOST_ACP                (0 + BCM_INT_ID_IHOST_MAX) /* HR3: 51 */
#define BCM_INT_ID_IHOST_S0                 (1 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S1                   (2 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S2                   (3 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_PCIE0_S0                 (4 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_ROM_S0                   (5 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_NAND_S0                  (6 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_QPSI_S0                  (7 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_NOR_S0                   (8 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_SRAM_S0                  (9 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_A9JTAG_S0                (10 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBR                     (11 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBS                     (12 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBX	                    (13 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBY	                    (14 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBZ	                    (15 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_CMICD_S0	                (16 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_0                     (17 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_1                     (18 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_2                     (19 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_IDM_MAX                  (20 + BCM_INT_ID_IHOST_MAX)
#elif (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2))
#define BCM_INT_ID_IHOST_M1                 (0 + BCM_INT_ID_IHOST_MAX) /* SB2: 51 */
#define BCM_INT_ID_IHOST_S0                 (1 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S0                   (2 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S1                   (3 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S2                   (4 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_PCIE0_S0                 (5 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_PCIE1_S0                 (6 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_ROM_S0                   (7 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_NAND_S0                  (8 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_QPSI_S0                  (9 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_NOR_S0                   (10 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_SRAM_S0                  (11 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_SMAU_S0                  (12 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_A9JTAG_S0                (13 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_SMAU_CRYPTO_S0           (14 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBR                     (15 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBS                     (16 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBX	                    (17 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBY	                    (18 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBZ	                    (19 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_CMICD_S0	                (20 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_MHOST0_S0	            (21 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_MHOST1_S0	            (22 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_CRYPTO_S0                (23 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_EXT_S0                   (24 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_EXT_S1                   (25 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DMU_S0                   (26 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_0                     (27 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_1                     (28 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_2                     (29 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_3                     (30 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_SMAU_IC_0             (31 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_IDM_MAX                  (32 + BCM_INT_ID_IHOST_MAX)
#else
#define BCM_INT_ID_IHOST_ACP                (11 + BCM_INT_ID_IHOST_MAX) /* KT2: 62 */
#define BCM_INT_ID_IHOST_S0                 (12 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S1                   (13 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DDR_S2                   (14 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_PCIE0_S0                 (15 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_PCIE1_S0                 (16 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_PCIE2_S0                 (17 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_ROM_S0                   (18 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_NAND_S0                  (19 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_QPSI_S0                  (20 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_A9JTAG_S0                (21 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_SATA_S0	                (22 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_SRAM_S0                  (23 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBW	                    (24 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBX	                    (25 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBY	                    (26 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_APBZ	                    (27 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_0                     (28 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_1                     (29 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_2                     (30 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_3                     (31 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_DS_4                     (32 + BCM_INT_ID_IHOST_MAX)
#define BCM_INT_ID_IDM_MAX                  (33 + BCM_INT_ID_IHOST_MAX)
#endif

/*=====================================================================*/
/* DDR Interrupt IDs                                                   */
/*=====================================================================*/
#define BCM_INT_ID_DDR_CONT                 (0 + BCM_INT_ID_IDM_MAX) /* HR3: 71, GH: 83, SB2: 83, KT2: 84 */
#define BCM_INT_ID_DDR_MAX                  (1 + BCM_INT_ID_IDM_MAX)

/*=====================================================================*/
/* DMAC Interrupt IDs                                                  */
/*=====================================================================*/
#define BCM_INT_ID_DMAC                     (0 + BCM_INT_ID_DDR_MAX) /* HR3: 72, GH: 84, SB2: 84, KT2: 85 */
#define BCM_INT_ID_DMAC_ABORT               (16 + BCM_INT_ID_DDR_MAX)
#define BCM_INT_ID_DMAC_MAX                 (17 + BCM_INT_ID_DDR_MAX)

/*=====================================================================*/
/* NAND Interrupt IDs                                                  */
/*=====================================================================*/
#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2)  || defined(CONFIG_MACH_HR3))
#define BCM_INT_ID_NAND_INTR                (0 + BCM_INT_ID_DMAC_MAX) /* HR3: 89, GH: 101, SB2: 101 */
#define BCM_INT_ID_NAND2CORE_MAX            (1 + BCM_INT_ID_DMAC_MAX)
#else
#define BCM_INT_ID_NAND2CORE_RD_MISS        (0 + BCM_INT_ID_DMAC_MAX) /* KT2: 102 */
#define BCM_INT_ID_NAND2CORE_ER_COMP        (1 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_CB_COMP        (2 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_PP_COMP        (3 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_ROCTL_RDY      (4 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_NAND_RBB       (5 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_ECC_MIPS_UNCOR (6 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_ECC_MIPS_COR   (7 + BCM_INT_ID_DMAC_MAX)
#define BCM_INT_ID_NAND2CORE_MAX            (8 + BCM_INT_ID_DMAC_MAX)
#endif

/*=====================================================================*/
/* QPSI Interrupt IDs                                                  */
/*=====================================================================*/
#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2)  || defined(CONFIG_MACH_HR3))
#define BCM_INT_ID_QSPI_INTR                (0 + BCM_INT_ID_NAND2CORE_MAX) /* HR3: 90, GH: 102, SB2: 102 */
#else
#define BCM_INT_ID_QPSI2CORE_FULL_RCHD      (0 + BCM_INT_ID_NAND2CORE_MAX) /* KT2: 110 */
#define BCM_INT_ID_QPSI2CORE_TRUNCATED      (1 + BCM_INT_ID_NAND2CORE_MAX)
#define BCM_INT_ID_QPSI2CORE_IMAPTIENT      (2 + BCM_INT_ID_NAND2CORE_MAX)
#define BCM_INT_ID_QPSI2CORE_SES_DONE       (3 + BCM_INT_ID_NAND2CORE_MAX)
#define BCM_INT_ID_QPSI2CORE_OVERREAD       (4 + BCM_INT_ID_NAND2CORE_MAX)
#define BCM_INT_ID_QPSI2CORE_MPSI_DONE      (5 + BCM_INT_ID_NAND2CORE_MAX)
#define BCM_INT_ID_QPSI2CORE_MPSI_HLT_SET   (6 + BCM_INT_ID_NAND2CORE_MAX)
#define BCM_INT_ID_QPSI2CORE_MAX            (7 + BCM_INT_ID_NAND2CORE_MAX)
#endif

/*=====================================================================*/
/* PNOR Host Interrupt IDs                                             */
/*=====================================================================*/
#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_HR3))
#define BCM_INT_ID_PNOR                     (1 + BCM_INT_ID_NAND2CORE_MAX) /* HR3: 91, GH: 103, SB2: 103 */
#define BCM_INT_ID_QPSI2CORE_MAX            (2 + BCM_INT_ID_NAND2CORE_MAX)
#endif

/*=====================================================================*/
/* USB2 Host Interrupt IDs                                             */
/*=====================================================================*/
#define BCM_INT_ID_USB2H2CORE_USB2_INT      (0 + BCM_INT_ID_QPSI2CORE_MAX) /* HR3: 92, GH: 104, SB2: 104, KT2: 117 */
#define BCM_INT_ID_USB2H2CORE_MAX           (1 + BCM_INT_ID_QPSI2CORE_MAX)

/*=====================================================================*/
/* USB3 Host Interrupt IDs                                             */
/*=====================================================================*/
#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2)  || defined(CONFIG_MACH_HR3))
#define BCM_INT_ID_USB3H2CORE_MAX           (0 + BCM_INT_ID_USB2H2CORE_MAX)
#else
#define BCM_INT_ID_USB3H2CORE_USB2_INT0     (0 + BCM_INT_ID_USB2H2CORE_MAX) /* KT2: 118 */
#define BCM_INT_ID_USB3H2CORE_USB2_INT1     (1 + BCM_INT_ID_USB2H2CORE_MAX)
#define BCM_INT_ID_USB3H2CORE_USB2_INT2     (2 + BCM_INT_ID_USB2H2CORE_MAX)
#define BCM_INT_ID_USB3H2CORE_USB2_INT3     (3 + BCM_INT_ID_USB2H2CORE_MAX)
#define BCM_INT_ID_USB3H2CORE_USB2_HSE      (4 + BCM_INT_ID_USB2H2CORE_MAX)
#define BCM_INT_ID_USB3H2CORE_MAX           (5 + BCM_INT_ID_USB2H2CORE_MAX)
#endif

/*=====================================================================*/
/* CCA Interrupt IDs                                                   */
/*=====================================================================*/
#if (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_HR3))
#define BCM_INT_ID_CCA_MAX                  (0 + BCM_INT_ID_USB3H2CORE_MAX)
#else
#define BCM_INT_ID_CCA_INT                  (0 + BCM_INT_ID_USB3H2CORE_MAX) /* KT2: 123 */
#define BCM_INT_ID_CCA_MAX                  (1 + BCM_INT_ID_USB3H2CORE_MAX)
#endif

/*=====================================================================*/
/* CCB Interrupt IDs                                                   */
/*=====================================================================*/
#if defined(CONFIG_MACH_HR3)
#define BCM_INT_ID_CCG_UART0                (0 + BCM_INT_ID_CCA_MAX)  /* HR3: 93 */
#define BCM_INT_ID_CCG_UART1                (1 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI0                 (2 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_GPIO                 (3 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SMBUS0               (4 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SMBUS1               (5 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM0_INT             (6 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM1_INT             (7 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM2_INT             (8 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM3_INT             (9 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_WDOG_INT             (10 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCS_GPIO                 (11 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCS_WDOG_INT             (12 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCS_RNG                  (13 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_PCIE_INT0                (14 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT0                (20 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM                     (21 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_EXTERNAL                 (22 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_USB2D2CORE_USB2D_INT     (30 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CMICD                    (31 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_ACPAL                    (94 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SDIO2CORE                (95 + BCM_INT_ID_CCA_MAX)
#elif (defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2))
#define BCM_INT_ID_CCG_UART0                (0 + BCM_INT_ID_CCA_MAX) /* SB2: 105 */
#define BCM_INT_ID_CCG_UART1                (1 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_UART2                (2 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_UART3                (3 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_UART4                (4 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI0                 (5 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI1                 (6 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI2                 (7 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI3                 (8 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI4                 (9 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SPI5                 (10 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_GPIO                 (11 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SMBUS0               (12 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_SMBUS1               (13 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM0_INT             (14 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM1_INT             (15 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM2_INT             (16 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_TIM3_INT             (17 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCG_WDOG_INT             (18 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SW_SOC                   (19 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCS_GPIO                 (20 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCS_WDOG_INT             (21 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCS_RNG                  (22 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_PCIE_INT0                (23 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_PCIE_INT1                (29 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SDIO2CORE                (35 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SDIO12CORE               (36 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT0                (37 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT1                (38 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_RESERVED                 (39 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM_CORRECTB            (40 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM_UNCORRECTB          (41 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_EXTERNAL                 (42 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_USB2D2CORE_USB2D_INT     (50 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SMAU                     (51 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_IHOST                    (52 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_MHOST0                   (53 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_MHOST1                   (54 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_MHOST2                   (55 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CMICD                    (56 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_ACPAL                    (119 + BCM_INT_ID_CCA_MAX)
#else
#define BCM_INT_ID_CCB_UART0                (0 + BCM_INT_ID_CCA_MAX) /* KT2: 124 */
#define BCM_INT_ID_CCB_GPIO                 (1 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_I2S                  (2 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_SMBUS0               (3 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_SMBUS1               (4 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_TIM0_INT1            (5 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_TIM0_INT2            (6 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_TIM1_INT1            (7 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_TIM1_INT2            (8 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_RNG                  (9 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_EXTERNAL                 (10 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_PCIE_INT0                (90 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_PCIE_INT1                (96 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_PCIE_INT2                (102 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SDIO2CORE                (108 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CTF                      (109 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT0                (110 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT1                (111 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT2                (112 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_GMAC_INT3                (113 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_USB2D2CORE_USB2D_INT     (114 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_APBV_INT                 (115 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM_CORRECTB            (116 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM_UNCORRECTB          (117 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM_ACCESSVIO           (118 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_SRAM_SBMA_MISMATCH       (119 + BCM_INT_ID_CCA_MAX)
#define BCM_INT_ID_CCB_WDOG                 (120 + BCM_INT_ID_CCA_MAX)
#endif

#ifdef CONFIG_ARCH_REQUIRE_GPIOLIB
#define IPROC_NR_IRQS                       (256)
#define IPROC_IRQ_GPIO_0                    (IPROC_NR_IRQS)
#define IPROC_NR_GPIO_IRQS                  (32 + 4)
#define NR_IRQS                             (IPROC_NR_IRQS + IPROC_NR_GPIO_IRQS)
#else 
#define NR_IRQS                             256
#endif

#endif /* __PLAT_IPROC_IRQS_H */
