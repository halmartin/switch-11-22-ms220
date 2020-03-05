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
 * These are serdes defines
 *
 */

#ifndef   _PHY_XGXS16G_H_
#define   _PHY_XGXS16G_H_

/* macros */

/* Macros ONLY used after initialization */
#define XGXS16G_2p5G_ID(id2) ((id2 & 0xff) == 0xf)


/****************************************************************************/
/*****  Starting below is auto-generated register macros from RDB files *****/
/****************************************************************************/

/****************************************************************************
 * Core Enums.
 ***************************************************************************/

#define XGXS16G_IEEE0BLK_IEEECONTROL0r			0x00000000
#define XGXS16G_XGXSBLK0_XGXSCONTROLr			0x00008000
#define XGXS16G_XGXSBLK0_XGXSSTATUSr			0x00008001
#define XGXS16G_XGXSBLK0_MMDSELECTr				0x0000800d
#define XGXS16G_XGXSBLK0_MISCCONTROL1r			0x0000800e
#define XGXS16G_XGXSBLK1_LANECTRL0r				0x00008015
#define XGXS16G_XGXSBLK1_LANECTRL1r				0x00008016
#define XGXS16G_XGXSBLK1_LANECTRL3r				0x00008018
#define XGXS16G_TX0_TX_ACONTROL0r				0x00008061
#define XGXS16G_RX0_RX_CONTROLr					0x000080b1
#define XGXS16G_AN73_PDET_PARDET10GCONTROLr		0x00008131
#define XGXS16G_XGXSBLK7_EEECONTROLr			0x00008150
#define XGXS16G_TX_LN_SWAP1r					0x00008169
#define XGXS16G_SERDESDIGITAL_CONTROL1000X1r	0x00008300
#define XGXS16G_SERDESDIGITAL_CONTROL1000X2r	0x00008301
#define XGXS16G_SERDESDIGITAL_CONTROL1000X3r	0x00008302
#define XGXS16G_SERDESDIGITAL_STATUS1000X1r		0x00008304
#define XGXS16G_SERDESDIGITAL_MISC1r			0x00008308
#define XGXS16G_SERDESID_SERDESID0r				0x00008310
#define XGXS16G_SERDESID_SERDESID1r				0x00008311
#define XGXS16G_SERDESID_SERDESID2r				0x00008312
#define XGXS16G_SERDESID_SERDESID3r				0x00008313
#define XGXS16G_REMOTEPHY_MISC3r				0x0000833c
#define XGXS16G_REMOTEPHY_MISC5r				0x0000833e
#define XGXS16G_BAM_NEXTPAGE_MP5_NEXTPAGECTRLr	0x00008350
#define XGXS16G_BAM_NEXTPAGE_UD_FIELDr			0x00008357
#define XGXS16G_COMBO_IEEE0_MIICNTLr			0x0000ffe0
#define XGXS16G_COMBO_IEEE0_AUTONEGADVr			0x0000ffe4

#define WC40_DIGITAL4_MISC3r                    0x0000833c

/* Digital4 :: Misc3 :: laneDisable [06:06] */
#define DIGITAL4_MISC3_LANEDISABLE_MASK                            0x0040
#define DIGITAL4_MISC3_LANEDISABLE_ALIGN                           0
#define DIGITAL4_MISC3_LANEDISABLE_BITS                            1
#define DIGITAL4_MISC3_LANEDISABLE_SHIFT                           6


/****************************************************************************
 * XGXS16G_IEEE_ieee0Blk
 ***************************************************************************/
/****************************************************************************
 * ieee0Blk :: ieeeControl0
 ***************************************************************************/
/* ieee0Blk :: ieeeControl0 :: rst_hw [15:15] */
#define IEEE0BLK_IEEECONTROL0_RST_HW_MASK                          0x8000
#define IEEE0BLK_IEEECONTROL0_RST_HW_ALIGN                         0
#define IEEE0BLK_IEEECONTROL0_RST_HW_BITS                          1
#define IEEE0BLK_IEEECONTROL0_RST_HW_SHIFT                         15

/* ieee0Blk :: ieeeControl0 :: gloopback [14:14] */
#define IEEE0BLK_IEEECONTROL0_GLOOPBACK_MASK                       0x4000
#define IEEE0BLK_IEEECONTROL0_GLOOPBACK_ALIGN                      0
#define IEEE0BLK_IEEECONTROL0_GLOOPBACK_BITS                       1
#define IEEE0BLK_IEEECONTROL0_GLOOPBACK_SHIFT                      14


/****************************************************************************
 * XGXS16G_USER_XgxsBlk0
 ***************************************************************************/
/****************************************************************************
 * XgxsBlk0 :: xgxsControl
 ***************************************************************************/
/* XgxsBlk0 :: xgxsControl :: start_sequencer [13:13] */
#define XGXSBLK0_XGXSCONTROL_START_SEQUENCER_MASK                  0x2000
#define XGXSBLK0_XGXSCONTROL_START_SEQUENCER_ALIGN                 0
#define XGXSBLK0_XGXSCONTROL_START_SEQUENCER_BITS                  1
#define XGXSBLK0_XGXSCONTROL_START_SEQUENCER_SHIFT                 13

/* XgxsBlk0 :: xgxsControl :: mode_10g [11:08] */
#define XGXSBLK0_XGXSCONTROL_MODE_10G_MASK                         0x0f00
#define XGXSBLK0_XGXSCONTROL_MODE_10G_ALIGN                        0
#define XGXSBLK0_XGXSCONTROL_MODE_10G_BITS                         4
#define XGXSBLK0_XGXSCONTROL_MODE_10G_SHIFT                        8
#define XGXSBLK0_XGXSCONTROL_MODE_10G_XGXS                         0
#define XGXSBLK0_XGXSCONTROL_MODE_10G_XGXS_noCC                    1
#define XGXSBLK0_XGXSCONTROL_MODE_10G_IndLane                      6
#define XGXSBLK0_XGXSCONTROL_MODE_10G_XGXS_noLss                   8
#define XGXSBLK0_XGXSCONTROL_MODE_10G_XGXS_noLss_noCC              9
#define XGXSBLK0_XGXSCONTROL_MODE_10G_protBypass                   10
#define XGXSBLK0_XGXSCONTROL_MODE_10G_protBypass_noDsk             11
#define XGXSBLK0_XGXSCONTROL_MODE_10G_ComboCoreMode                12
#define XGXSBLK0_XGXSCONTROL_MODE_10G_ClocksOff                    15

/* XgxsBlk0 :: xgxsControl :: hstl [05:05] */
#define XGXSBLK0_XGXSCONTROL_HSTL_MASK                             0x0020
#define XGXSBLK0_XGXSCONTROL_HSTL_ALIGN                            0
#define XGXSBLK0_XGXSCONTROL_HSTL_BITS                             1
#define XGXSBLK0_XGXSCONTROL_HSTL_SHIFT                            5

/* XgxsBlk0 :: xgxsControl :: cdet_en [03:03] */
#define XGXSBLK0_XGXSCONTROL_CDET_EN_MASK                          0x0008
#define XGXSBLK0_XGXSCONTROL_CDET_EN_ALIGN                         0
#define XGXSBLK0_XGXSCONTROL_CDET_EN_BITS                          1
#define XGXSBLK0_XGXSCONTROL_CDET_EN_SHIFT                         3

/* XgxsBlk0 :: xgxsControl :: eden [02:02] */
#define XGXSBLK0_XGXSCONTROL_EDEN_MASK                             0x0004
#define XGXSBLK0_XGXSCONTROL_EDEN_ALIGN                            0
#define XGXSBLK0_XGXSCONTROL_EDEN_BITS                             1
#define XGXSBLK0_XGXSCONTROL_EDEN_SHIFT                            2

/* XgxsBlk0 :: xgxsControl :: afrst_en [01:01] */
#define XGXSBLK0_XGXSCONTROL_AFRST_EN_MASK                         0x0002
#define XGXSBLK0_XGXSCONTROL_AFRST_EN_ALIGN                        0
#define XGXSBLK0_XGXSCONTROL_AFRST_EN_BITS                         1
#define XGXSBLK0_XGXSCONTROL_AFRST_EN_SHIFT                        1

/* XgxsBlk0 :: xgxsControl :: txcko_div [00:00] */
#define XGXSBLK0_XGXSCONTROL_TXCKO_DIV_MASK                        0x0001
#define XGXSBLK0_XGXSCONTROL_TXCKO_DIV_ALIGN                       0
#define XGXSBLK0_XGXSCONTROL_TXCKO_DIV_BITS                        1
#define XGXSBLK0_XGXSCONTROL_TXCKO_DIV_SHIFT                       0


/****************************************************************************
 * XgxsBlk0 :: xgxsStatus
 ***************************************************************************/
/* XgxsBlk0 :: xgxsStatus :: txpll_lock [11:11] */
#define XGXSBLK0_XGXSSTATUS_TXPLL_LOCK_MASK                        0x0800
#define XGXSBLK0_XGXSSTATUS_TXPLL_LOCK_ALIGN                       0
#define XGXSBLK0_XGXSSTATUS_TXPLL_LOCK_BITS                        1
#define XGXSBLK0_XGXSSTATUS_TXPLL_LOCK_SHIFT                       11


/****************************************************************************
 * XgxsBlk0 :: miscControl1
 ***************************************************************************/
/* XgxsBlk0 :: miscControl1 :: PCS_dev_en_override [10:10] */
#define XGXSBLK0_MISCCONTROL1_PCS_DEV_EN_OVERRIDE_MASK             0x0400
#define XGXSBLK0_MISCCONTROL1_PCS_DEV_EN_OVERRIDE_ALIGN            0
#define XGXSBLK0_MISCCONTROL1_PCS_DEV_EN_OVERRIDE_BITS             1
#define XGXSBLK0_MISCCONTROL1_PCS_DEV_EN_OVERRIDE_SHIFT            10

/* XgxsBlk0 :: miscControl1 :: PMD_dev_en_override [09:09] */
#define XGXSBLK0_MISCCONTROL1_PMD_DEV_EN_OVERRIDE_MASK             0x0200
#define XGXSBLK0_MISCCONTROL1_PMD_DEV_EN_OVERRIDE_ALIGN            0
#define XGXSBLK0_MISCCONTROL1_PMD_DEV_EN_OVERRIDE_BITS             1
#define XGXSBLK0_MISCCONTROL1_PMD_DEV_EN_OVERRIDE_SHIFT            9

/* XgxsBlk0 :: miscControl1 :: ieee_blksel_autodet [01:01] */
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_AUTODET_MASK             0x0002
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_AUTODET_ALIGN            0
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_AUTODET_BITS             1
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_AUTODET_SHIFT            1

/* XgxsBlk0 :: miscControl1 :: ieee_blksel_val [00:00] */
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_VAL_MASK                 0x0001
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_VAL_ALIGN                0
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_VAL_BITS                 1
#define XGXSBLK0_MISCCONTROL1_IEEE_BLKSEL_VAL_SHIFT                0


/****************************************************************************
 * XGXS16G_USER_XgxsBlk1
 ***************************************************************************/
/****************************************************************************
 * XgxsBlk1 :: laneCtrl0
 ***************************************************************************/
/* XgxsBlk1 :: laneCtrl0 :: cl36_pcs_en_rx [07:04] */
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_RX_MASK                     0x00f0
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_RX_ALIGN                    0
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_RX_BITS                     4
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_RX_SHIFT                    4

/* XgxsBlk1 :: laneCtrl0 :: cl36_pcs_en_tx [03:00] */
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_TX_MASK                     0x000f
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_TX_ALIGN                    0
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_TX_BITS                     4
#define XGXSBLK1_LANECTRL0_CL36_PCS_EN_TX_SHIFT                    0


/****************************************************************************
 * XGXS16G_USER_TX0
 ***************************************************************************/
/****************************************************************************
 * TX0 :: Tx_AControl0
 ***************************************************************************/
/* TX0 :: Tx_AControl0 :: txpol_flip [05:05] */
#define TX0_TX_ACONTROL0_TXPOL_FLIP_MASK                           0x0020
#define TX0_TX_ACONTROL0_TXPOL_FLIP_ALIGN                          0
#define TX0_TX_ACONTROL0_TXPOL_FLIP_BITS                           1
#define TX0_TX_ACONTROL0_TXPOL_FLIP_SHIFT                          5


/****************************************************************************
 * XGXS16G_USER_dsc_2_0
 ***************************************************************************/
/****************************************************************************
 * dsc_2_0 :: dsc_ctrl0
 ***************************************************************************/
/* dsc_2_0 :: dsc_ctrl0 :: rxSeqStart [15:15] */
#define DSC_2_0_DSC_CTRL0_RXSEQSTART_MASK                          0x8000
#define DSC_2_0_DSC_CTRL0_RXSEQSTART_ALIGN                         0
#define DSC_2_0_DSC_CTRL0_RXSEQSTART_BITS                          1
#define DSC_2_0_DSC_CTRL0_RXSEQSTART_SHIFT                         15


/****************************************************************************
 * XGXS16G_USER_SerdesDigital
 ***************************************************************************/
/****************************************************************************
 * SerdesDigital :: Control1000X1
 ***************************************************************************/
/* SerdesDigital :: Control1000X1 :: crc_checker_disable [07:07] */
#define SERDESDIGITAL_CONTROL1000X1_CRC_CHECKER_DISABLE_MASK       0x0080
#define SERDESDIGITAL_CONTROL1000X1_CRC_CHECKER_DISABLE_ALIGN      0
#define SERDESDIGITAL_CONTROL1000X1_CRC_CHECKER_DISABLE_BITS       1
#define SERDESDIGITAL_CONTROL1000X1_CRC_CHECKER_DISABLE_SHIFT      7

/* SerdesDigital :: Control1000X1 :: disable_pll_pwrdwn [06:06] */
#define SERDESDIGITAL_CONTROL1000X1_DISABLE_PLL_PWRDWN_MASK        0x0040
#define SERDESDIGITAL_CONTROL1000X1_DISABLE_PLL_PWRDWN_ALIGN       0
#define SERDESDIGITAL_CONTROL1000X1_DISABLE_PLL_PWRDWN_BITS        1
#define SERDESDIGITAL_CONTROL1000X1_DISABLE_PLL_PWRDWN_SHIFT       6

/* SerdesDigital :: Control1000X1 :: fiber_mode_1000X [00:00] */
#define SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_MASK          0x0001
#define SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_ALIGN         0
#define SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_BITS          1
#define SERDESDIGITAL_CONTROL1000X1_FIBER_MODE_1000X_SHIFT         0

/****************************************************************************
 * SerdesDigital :: Control1000X3
 ***************************************************************************/
/* SerdesDigital :: Control1000X3 :: fifo_elasicity_tx_rx [02:01] */
#define SERDESDIGITAL_CONTROL1000X3_FIFO_ELASICITY_TX_RX_MASK      0x0006
#define SERDESDIGITAL_CONTROL1000X3_FIFO_ELASICITY_TX_RX_ALIGN     0
#define SERDESDIGITAL_CONTROL1000X3_FIFO_ELASICITY_TX_RX_BITS      2
#define SERDESDIGITAL_CONTROL1000X3_FIFO_ELASICITY_TX_RX_SHIFT     1

/* SerdesDigital :: Control1000X3 :: tx_fifo_rst [00:00] */
#define SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_MASK               0x0001
#define SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_ALIGN              0
#define SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_BITS               1
#define SERDESDIGITAL_CONTROL1000X3_TX_FIFO_RST_SHIFT              0

/****************************************************************************
 * SerdesDigital :: Status1000X1
 ***************************************************************************/
/* SerdesDigital :: Status1000X1 :: speed_status [04:03] */
#define SERDESDIGITAL_STATUS1000X1_SPEED_STATUS_MASK               0x0018
#define SERDESDIGITAL_STATUS1000X1_SPEED_STATUS_ALIGN              0
#define SERDESDIGITAL_STATUS1000X1_SPEED_STATUS_BITS               2
#define SERDESDIGITAL_STATUS1000X1_SPEED_STATUS_SHIFT              3

/****************************************************************************
 * SerdesDigital :: Misc1
 ***************************************************************************/
/* SerdesDigital :: Misc1 :: refclk_sel [15:13] */
#define SERDESDIGITAL_MISC1_REFCLK_SEL_MASK                        0xe000
#define SERDESDIGITAL_MISC1_REFCLK_SEL_ALIGN                       0
#define SERDESDIGITAL_MISC1_REFCLK_SEL_BITS                        3
#define SERDESDIGITAL_MISC1_REFCLK_SEL_SHIFT                       13
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_25MHz                   0
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_100MHz                  1
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_125MHz                  2
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_156p25MHz               3
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_187p5MHz                4
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_161p25Mhz               5
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_50Mhz                   6
#define SERDESDIGITAL_MISC1_REFCLK_SEL_clk_106p25Mhz               7

/* SerdesDigital :: Misc1 :: force_speed_sel [04:04] */
#define SERDESDIGITAL_MISC1_FORCE_SPEED_SEL_MASK                   0x0010
#define SERDESDIGITAL_MISC1_FORCE_SPEED_SEL_ALIGN                  0
#define SERDESDIGITAL_MISC1_FORCE_SPEED_SEL_BITS                   1
#define SERDESDIGITAL_MISC1_FORCE_SPEED_SEL_SHIFT                  4

/* SerdesDigital :: Misc1 :: force_speed [03:00] */
#define SERDESDIGITAL_MISC1_FORCE_SPEED_MASK                       0x000f
#define SERDESDIGITAL_MISC1_FORCE_SPEED_ALIGN                      0
#define SERDESDIGITAL_MISC1_FORCE_SPEED_BITS                       4
#define SERDESDIGITAL_MISC1_FORCE_SPEED_SHIFT                      0


/****************************************************************************
 * CL73_UserB0 :: CL73_BAMCtrl1
 ***************************************************************************/
/* CL73_UserB0 :: CL73_BAMCtrl1 :: CL73_bamEn [15:15] */
#define CL73_USERB0_CL73_BAMCTRL1_CL73_BAMEN_MASK                  0x8000
#define CL73_USERB0_CL73_BAMCTRL1_CL73_BAMEN_ALIGN                 0
#define CL73_USERB0_CL73_BAMCTRL1_CL73_BAMEN_BITS                  1
#define CL73_USERB0_CL73_BAMCTRL1_CL73_BAMEN_SHIFT                 15


/****************************************************************************
 * Datatype Definitions.
 ***************************************************************************/
#endif /*  _PHY_XGXS16G_H_ */

/* End of File */
