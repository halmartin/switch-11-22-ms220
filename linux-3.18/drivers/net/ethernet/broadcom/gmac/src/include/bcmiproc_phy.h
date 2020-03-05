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
 *
 * These routines provide access to the external phy
 *
 */

#ifndef _bcm_iproc_phy_h_
#define _bcm_iproc_phy_h_


/* ---- Include Files ---------------------------------------------------- */
/*
 * Defines:	SOC_E_XXX
 * Purpose:	SOC API error codes
 * Notes:
 *      An error code may be converted to a string by passing
 *      the code to soc_errmsg().
 */

typedef enum {
    SOC_E_NONE                 = 0,
    SOC_E_INTERNAL             = -1,
    SOC_E_MEMORY               = -2,
    SOC_E_UNIT                 = -3,
    SOC_E_PARAM                = -4,
    SOC_E_EMPTY                = -5,
    SOC_E_FULL                 = -6,
    SOC_E_NOT_FOUND            = -7,
    SOC_E_EXISTS               = -8,
    SOC_E_TIMEOUT              = -9,
    SOC_E_BUSY                 = -10,
    SOC_E_FAIL                 = -11,
    SOC_E_DISABLED             = -12,
    SOC_E_BADID                = -13,
    SOC_E_RESOURCE             = -14,
    SOC_E_CONFIG               = -15,
    SOC_E_UNAVAIL              = -16,
    SOC_E_INIT                 = -17,
    SOC_E_PORT                 = -18,

    SOC_E_LIMIT                = -19           /* Must come last */
} soc_error_t;

#define SOC_SUCCESS(rv)              ((rv) >= 0)
#define SOC_FAILURE(rv)              ((rv) < 0)

typedef enum _soc_port_if_e {
    SOC_PORT_IF_NOCXN, /* No physical connection */
    SOC_PORT_IF_NULL,  /* Pass-through connection without PHY */
    SOC_PORT_IF_MII,
    SOC_PORT_IF_GMII,
    SOC_PORT_IF_SGMII,
    SOC_PORT_IF_TBI,
    SOC_PORT_IF_XGMII,
    SOC_PORT_IF_RGMII,
    SOC_PORT_IF_RvMII,
    SOC_PORT_IF_SFI,
    SOC_PORT_IF_XFI,
    SOC_PORT_IF_KR,
    SOC_PORT_IF_KR4,
    SOC_PORT_IF_CR,
    SOC_PORT_IF_CR4,
    SOC_PORT_IF_XLAUI,
    SOC_PORT_IF_SR,
    SOC_PORT_IF_RXAUI,
    SOC_PORT_IF_XAUI,
    SOC_PORT_IF_SPAUI,
    SOC_PORT_IF_QSGMII,
    SOC_PORT_IF_ILKN,
    SOC_PORT_IF_RCY,
    SOC_PORT_IF_FAT_PIPE,
    SOC_PORT_IF_CGMII,
    SOC_PORT_IF_CAUI,
    SOC_PORT_IF_LR,
    SOC_PORT_IF_LR4,
    SOC_PORT_IF_SR4,
    SOC_PORT_IF_KX,
    SOC_PORT_IF_CPU,
    SOC_PORT_IF_OLP,
    SOC_PORT_IF_OAMP,
    SOC_PORT_IF_ERP,
    SOC_PORT_IF_COUNT /* last, please */
} _soc_port_if_t;
typedef _soc_port_if_t soc_port_if_t;


/* 1000BASE-T/100BASE-TX/10BASE-T MII Control Register (Addr 00h) */
#define PHY_MII_CTRLr_FLAGS		0x00
#define PHY_MII_CTRLr_BANK		0x0000
#define PHY_MII_CTRLr_ADDR		0x00
/* 1000BASE-T/100BASE-TX/10BASE-T MII Status Register (ADDR 01h) */
#define PHY_MII_STATr_FLAGS		0x00
#define PHY_MII_STATr_BANK		0x0000
#define PHY_MII_STATr_ADDR		0x01
/* 1000BASE-T/100BASE-TX/10BASE-T PHY Identifier Register (ADDR 02h) */
#define PHY_MII_PHY_ID0r_FLAGS	_SOC_PHY_REG_DIRECT
#define PHY_MII_PHY_ID0r_BANK	0x0000
#define PHY_MII_PHY_ID0r_ADDR	0x02
/* 1000BASE-T/100BASE-TX/10BASE-T PHY Identifier Register (ADDR 03h) */
#define PHY_MII_PHY_ID1r_FLAGS	_SOC_PHY_REG_DIRECT
#define PHY_MII_PHY_ID1r_BANK	0x0000
#define PHY_MII_PHY_ID1r_ADDR	0x03
/* 1000BASE-T/100BASE-TX/10BASE-T Auto-neg Advertisment Register (ADDR 04h) */
#define PHY_MII_ANAr_FLAGS		0x00
#define PHY_MII_ANAr_BANK		0x0000
#define PHY_MII_ANAr_ADDR		0x04
/* 1000BASE-T/100BASE-TX/10BASE-T Auto-neg Link Partner Ability (ADDR 05h) */
#define PHY_MII_ANPr_FLAGS		0x00
#define PHY_MII_ANPr_BANK		0x0000
#define PHY_MII_ANPr_ADDR		0x05
/* 1000BASE-T Control Register  (ADDR 09h) */
#define PHY_MII_GB_CTRLr_FLAGS	0x00
#define PHY_MII_GB_CTRLr_BANK	0x0000
#define PHY_MII_GB_CTRLr_ADDR	0x09
/* 1000BASE-T Status Register (ADDR 0ah) */
#define PHY_MII_GB_STATr_FLAGS	0x00
#define PHY_MII_GB_STATr_BANK	0x0000
#define PHY_MII_GB_STATr_ADDR	0x0a
/* 1000BASE-T/100BASE-TX/10BASE-T IEEE Extended Status Register (ADDR 0fh) */
#define PHY_MII_ESRr_FLAGS		0x00
#define PHY_MII_ESRr_BANK		0x0000
#define PHY_MII_ESRr_ADDR		0x0f
/* 1000BASE-T/100BASE-TX/10BASE-T PHY Extended Control Register (ADDR 10h) */
#define PHY_MII_ECRr_FLAGS		0x00
#define PHY_MII_ECRr_BANK		0x0000
#define PHY_MII_ECRr_ADDR		0x10
/* 1000BASE-T/100BASE-TX/10BASE-T Auxiliary Control Reg (ADDR 18h Shadow 000)*/
#define PHY_MII_AUX_CTRLr_FLAGS		0x00
#define PHY_MII_AUX_CTRLr_BANK		0x0000
#define PHY_MII_AUX_CTRLr_ADDR		0x18
/* 1000BASE-T/100BASE-TX/10BASE-T Power/MII Control Reg (ADDR 18h Shadow 010)*/
#define PHY_MII_POWER_CTRLr_FLAGS	0x00
#define PHY_MII_POWER_CTRLr_BANK	0x0002
#define PHY_MII_POWER_CTRLr_ADDR	0x18
/* 1000BASE-T/100BASE-TX/10BASE-T Misc Control Reg (ADDR 18h Shadow 111)*/
#define PHY_MII_MISC_CTRLr_FLAGS	0x00
#define PHY_MII_MISC_CTRLr_BANK	    0x0007
#define PHY_MII_MISC_CTRLr_ADDR	    0x18
/* Auxiliary 1000BASE-X Control Reg (ADDR 1ch shadow 11011) */
#define PHY_AUX_1000X_CTRLr_FLAGS	0x00
#define PHY_AUX_1000X_CTRLr_BANK	0x001B
#define PHY_AUX_1000X_CTRLr_ADDRS	0x1c
/* Mode Control Reg (ADDR 1ch shadow 11111) */
#define PHY_MODE_CTRLr_FLAGS		0x00
#define PHY_MODE_CTRLr_BANK			0x001F
#define PHY_MODE_CTRLr_ADDR			0x1c

/*
 *		Primary SerDes Registers
 */
/* 1000BASE-X MII Control Register (Addr 00h) */
#define PHY_1000X_MII_CTRLr_FLAGS		SOC_PHY_REG_1000X
#define PHY_1000X_MII_CTRLr_BANK		0x0000
#define PHY_1000X_MII_CTRLr_ADDR		0x00


/* MII Control Register: bit definitions */
#define MII_CTRL_FS_2500        (1 << 5) /* Force speed to 2500 Mbps */
#define MII_CTRL_SS_MSB         (1 << 6) /* Speed select, MSb */
#define MII_CTRL_CST            (1 << 7) /* Collision Signal test */
#define MII_CTRL_FD             (1 << 8) /* Full Duplex */
#define MII_CTRL_RAN            (1 << 9) /* Restart Autonegotiation */
#define MII_CTRL_IP             (1 << 10) /* Isolate Phy */
#define MII_CTRL_PD             (1 << 11) /* Power Down */
#define MII_CTRL_AE             (1 << 12) /* Autonegotiation enable */
#define MII_CTRL_SS_LSB         (1 << 13) /* Speed select, LSb */
#define MII_CTRL_LE             (1 << 14) /* Loopback enable */
#define MII_CTRL_RESET          (1 << 15) /* PHY reset */

#define MII_CTRL_SS(_x)         ((_x) & (MII_CTRL_SS_LSB|MII_CTRL_SS_MSB))
#define MII_CTRL_SS_10          0
#define MII_CTRL_SS_100         (MII_CTRL_SS_LSB)
#define MII_CTRL_SS_1000        (MII_CTRL_SS_MSB)
#define MII_CTRL_SS_INVALID     (MII_CTRL_SS_LSB | MII_CTRL_SS_MSB)
#define MII_CTRL_SS_MASK        (MII_CTRL_SS_LSB | MII_CTRL_SS_MSB)

/* 
 * MII Status Register: See 802.3, 1998 pg 544 
 */
#define MII_STAT_EXT            (1 << 0) /* Extended Registers */
#define MII_STAT_JBBR           (1 << 1) /* Jabber Detected */
#define MII_STAT_LA             (1 << 2) /* Link Active */
#define MII_STAT_AN_CAP         (1 << 3) /* Autoneg capable */
#define MII_STAT_RF             (1 << 4) /* Remote Fault */
#define MII_STAT_AN_DONE        (1 << 5) /* Autoneg complete */
#define MII_STAT_MF_PS          (1 << 6) /* Preamble suppression */
#define MII_STAT_ES             (1 << 8) /* Extended status (R15) */
#define MII_STAT_HD_100_T2      (1 << 9) /* Half duplex 100Mb/s supported */
#define MII_STAT_FD_100_T2      (1 << 10)/* Full duplex 100Mb/s supported */
#define MII_STAT_HD_10          (1 << 11)/* Half duplex 100Mb/s supported */
#define MII_STAT_FD_10          (1 << 12)/* Full duplex 100Mb/s supported */
#define MII_STAT_HD_100         (1 << 13)/* Half duplex 100Mb/s supported */
#define MII_STAT_FD_100         (1 << 14)/* Full duplex 100Mb/s supported */
#define MII_STAT_100_T4         (1 << 15)/* Full duplex 100Mb/s supported */

/*
 * MII Link Advertisment
 */
#define MII_ANA_ASF             (1 << 0)/* Advertise Selector Field */
#define MII_ANA_HD_10           (1 << 5)/* Half duplex 10Mb/s supported */
#define MII_ANA_FD_10           (1 << 6)/* Full duplex 10Mb/s supported */
#define MII_ANA_HD_100          (1 << 7)/* Half duplex 100Mb/s supported */
#define MII_ANA_FD_100          (1 << 8)/* Full duplex 100Mb/s supported */
#define MII_ANA_T4              (1 << 9)/* T4 */
#define MII_ANA_PAUSE           (1 << 10)/* Pause supported */
#define MII_ANA_ASYM_PAUSE      (1 << 11)/* Asymmetric pause supported */
#define MII_ANA_RF              (1 << 13)/* Remote fault */
#define MII_ANA_NP              (1 << 15)/* Next Page */

#define MII_ANA_ASF_802_3       (1)     /* 802.3 PHY */

/*
 * 1000Base-T Control Register
 */
#define MII_GB_CTRL_MS_MAN      (1 << 12) /* Manual Master/Slave mode */
#define MII_GB_CTRL_MS          (1 << 11) /* Master/Slave negotiation mode */
#define MII_GB_CTRL_PT          (1 << 10) /* Port type */
#define MII_GB_CTRL_ADV_1000FD  (1 << 9) /* Advertise 1000Base-T FD */
#define MII_GB_CTRL_ADV_1000HD  (1 << 8) /* Advertise 1000Base-T HD */

/*
 * 1000Base-T Status Register
 */
#define MII_GB_STAT_MS_FAULT    (1 << 15) /* Master/Slave Fault */
#define MII_GB_STAT_MS          (1 << 14) /* Master/Slave, 1 == Master */
#define MII_GB_STAT_LRS         (1 << 13) /* Local receiver status */
#define MII_GB_STAT_RRS         (1 << 12) /* Remote receiver status */
#define MII_GB_STAT_LP_1000FD   (1 << 11) /* Link partner 1000FD capable */
#define MII_GB_STAT_LP_1000HD   (1 << 10) /* Link partner 1000HD capable */
#define MII_GB_STAT_IDE         (0xff << 0) /* Idle error count */

/*
 * IEEE Extended Status Register
 */
#define MII_ESR_1000_X_FD       (1 << 15) /* 1000Base-T FD capable */
#define MII_ESR_1000_X_HD       (1 << 14) /* 1000Base-T HD capable */
#define MII_ESR_1000_T_FD       (1 << 13) /* 1000Base-T FD capable */
#define MII_ESR_1000_T_HD       (1 << 12) /* 1000Base-T FD capable */

/* MII Extended Control Register (BROADCOM) */
#define MII_ECR_FE              (1 << 0) /* FIFO Elasticity */
#define MII_ECR_TLLM            (1 << 1) /* Three link LED mode */
#define MII_ECR_ET_IPG          (1 << 2) /* Extended XMIT IPG mode */
#define MII_ECR_FLED_OFF        (1 << 3) /* Force LED off */
#define MII_ECR_FLED_ON         (1 << 4) /* Force LED on */
#define MII_ECR_ELT             (1 << 5) /* Enable LED traffic */
#define MII_ECR_RS              (1 << 6) /* Reset Scrambler */
#define MII_ECR_BRSA            (1 << 7) /* Bypass Receive Sym. align */
#define MII_ECR_BMLT3           (1 << 8) /* Bypass MLT3 Encoder/Decoder */
#define MII_ECR_BSD             (1 << 9) /* Bypass Scramble/Descramble */
#define MII_ECR_B4B5B           (1 << 10) /* Bypass 4B/5B Encode/Decode */
#define MII_ECR_FI              (1 << 11) /* Force Interrupt */
#define MII_ECR_ID              (1 << 12) /* Interrupt Disable */
#define MII_ECR_TD              (1 << 13) /* XMIT Disable */
#define MII_ECR_DAMC            (1 << 14) /* DIsable Auto-MDI Crossover */
#define MII_ECR_10B             (1 << 15) /* 1 == 10B, 0 == GMII */

/* MISC Control Register (Addr 18h, Shadow Value 111) */
#define MII_FORCED_AUTO_MDIX    (1 << 9) /* 1 == AUTO-MDIX enabled when AN disabled */
#endif	/* _bcm_iproc_phy_h_ */
