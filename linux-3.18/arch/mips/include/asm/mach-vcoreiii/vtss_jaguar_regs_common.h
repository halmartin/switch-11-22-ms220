#ifndef _VTSS_JAGUAR_REGS_COMMON_H_
#define _VTSS_JAGUAR_REGS_COMMON_H_

/*
 *
 * VCore-III Register Definitions
 *
 * Copyright (C) 2010 Vitesse Semiconductor Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
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

#ifndef VTSS_BITOPS_DEFINED
#ifdef __ASSEMBLER__
#define VTSS_BIT(x)                   (1 << (x))
#define VTSS_BITMASK(x)               ((1 << (x)) - 1)
#else
#define VTSS_BIT(x)                   (1U << (x))
#define VTSS_BITMASK(x)               ((1U << (x)) - 1)
#endif
#define VTSS_EXTRACT_BITFIELD(x,o,w)  (((x) >> (o)) & VTSS_BITMASK(w))
#define VTSS_ENCODE_BITFIELD(x,o,w)   (((x) & VTSS_BITMASK(w)) << (o))
#define VTSS_ENCODE_BITMASK(o,w)      (VTSS_BITMASK(w) << (o))
#define VTSS_BITOPS_DEFINED
#endif /* VTSS_BITOPS_DEFINED */


/*
 * Target offset base(s)
 */
#define VTSS_IO_ORIGIN1_OFFSET 0x60000000
#define VTSS_IO_ORIGIN1_SIZE   0x01000000
#define VTSS_IO_ORIGIN2_OFFSET 0x70000000
#define VTSS_IO_ORIGIN2_SIZE   0x00200000
#ifndef VTSS_IO_OFFSET1
#define VTSS_IO_OFFSET1(offset) (VTSS_IO_ORIGIN1_OFFSET + offset)
#endif
#ifndef VTSS_IO_OFFSET2
#define VTSS_IO_OFFSET2(offset) (VTSS_IO_ORIGIN2_OFFSET + offset)
#endif

/* Main target address offsets */
#define VTSS_TO_DEVCPU_ORG VTSS_IO_OFFSET1(0x00000000) /*!< Base offset for target DEVCPU_ORG */
#define VTSS_TO_DEVCPU_GCB VTSS_IO_OFFSET1(0x00010000) /*!< Base offset for target DEVCPU_GCB */
#define VTSS_TO_DEVCPU_QS  VTSS_IO_OFFSET1(0x00020000) /*!< Base offset for target DEVCPU_QS */
#define VTSS_TO_DEVCPU_PI  VTSS_IO_OFFSET1(0x00030000) /*!< Base offset for target DEVCPU_PI */
#define VTSS_TO_DEV1G_0    VTSS_IO_OFFSET1(0x00040000) /*!< Base offset for target DEV1G_0 */
#define VTSS_TO_DEV1G_1    VTSS_IO_OFFSET1(0x00050000) /*!< Base offset for target DEV1G_1 */
#define VTSS_TO_DEV1G_2    VTSS_IO_OFFSET1(0x00060000) /*!< Base offset for target DEV1G_2 */
#define VTSS_TO_DEV1G_3    VTSS_IO_OFFSET1(0x00070000) /*!< Base offset for target DEV1G_3 */
#define VTSS_TO_DEV1G_4    VTSS_IO_OFFSET1(0x00080000) /*!< Base offset for target DEV1G_4 */
#define VTSS_TO_DEV1G_5    VTSS_IO_OFFSET1(0x00090000) /*!< Base offset for target DEV1G_5 */
#define VTSS_TO_DEV1G_6    VTSS_IO_OFFSET1(0x000a0000) /*!< Base offset for target DEV1G_6 */
#define VTSS_TO_DEV1G_7    VTSS_IO_OFFSET1(0x000b0000) /*!< Base offset for target DEV1G_7 */
#define VTSS_TO_DEV1G_8    VTSS_IO_OFFSET1(0x000c0000) /*!< Base offset for target DEV1G_8 */
#define VTSS_TO_DEV1G_9    VTSS_IO_OFFSET1(0x000d0000) /*!< Base offset for target DEV1G_9 */
#define VTSS_TO_DEV1G_10   VTSS_IO_OFFSET1(0x000e0000) /*!< Base offset for target DEV1G_10 */
#define VTSS_TO_DEV1G_11   VTSS_IO_OFFSET1(0x000f0000) /*!< Base offset for target DEV1G_11 */
#define VTSS_TO_DEV1G_12   VTSS_IO_OFFSET1(0x00100000) /*!< Base offset for target DEV1G_12 */
#define VTSS_TO_DEV1G_13   VTSS_IO_OFFSET1(0x00110000) /*!< Base offset for target DEV1G_13 */
#define VTSS_TO_DEV1G_14   VTSS_IO_OFFSET1(0x00120000) /*!< Base offset for target DEV1G_14 */
#define VTSS_TO_DEV1G_15   VTSS_IO_OFFSET1(0x00130000) /*!< Base offset for target DEV1G_15 */
#define VTSS_TO_DEV1G_16   VTSS_IO_OFFSET1(0x00140000) /*!< Base offset for target DEV1G_16 */
#define VTSS_TO_DEV1G_17   VTSS_IO_OFFSET1(0x00150000) /*!< Base offset for target DEV1G_17 */
#define VTSS_TO_DEV2G5_0   VTSS_IO_OFFSET1(0x00160000) /*!< Base offset for target DEV2G5_0 */
#define VTSS_TO_DEV2G5_1   VTSS_IO_OFFSET1(0x00170000) /*!< Base offset for target DEV2G5_1 */
#define VTSS_TO_DEV2G5_2   VTSS_IO_OFFSET1(0x00180000) /*!< Base offset for target DEV2G5_2 */
#define VTSS_TO_DEV2G5_3   VTSS_IO_OFFSET1(0x00190000) /*!< Base offset for target DEV2G5_3 */
#define VTSS_TO_DEV2G5_4   VTSS_IO_OFFSET1(0x001a0000) /*!< Base offset for target DEV2G5_4 */
#define VTSS_TO_DEV2G5_5   VTSS_IO_OFFSET1(0x001b0000) /*!< Base offset for target DEV2G5_5 */
#define VTSS_TO_DEV2G5_6   VTSS_IO_OFFSET1(0x001c0000) /*!< Base offset for target DEV2G5_6 */
#define VTSS_TO_DEV2G5_7   VTSS_IO_OFFSET1(0x001d0000) /*!< Base offset for target DEV2G5_7 */
#define VTSS_TO_DEV2G5_8   VTSS_IO_OFFSET1(0x001e0000) /*!< Base offset for target DEV2G5_8 */
#define VTSS_TO_DEVRGMII_0 VTSS_IO_OFFSET1(0x001f0000) /*!< Base offset for target DEVRGMII_0 */
#define VTSS_TO_DEV10G_0   VTSS_IO_OFFSET1(0x00200000) /*!< Base offset for target DEV10G_0 */
#define VTSS_TO_DEV10G_1   VTSS_IO_OFFSET1(0x00210000) /*!< Base offset for target DEV10G_1 */
#define VTSS_TO_DEV10G_2   VTSS_IO_OFFSET1(0x00220000) /*!< Base offset for target DEV10G_2 */
#define VTSS_TO_DEV10G_3   VTSS_IO_OFFSET1(0x00230000) /*!< Base offset for target DEV10G_3 */
#define VTSS_TO_ASM        VTSS_IO_OFFSET1(0x00240000) /*!< Base offset for target ASM */
#define VTSS_TO_ANA_CL     VTSS_IO_OFFSET1(0x00250000) /*!< Base offset for target ANA_CL */
#define VTSS_TO_LRN        VTSS_IO_OFFSET1(0x00260000) /*!< Base offset for target LRN */
#define VTSS_TO_VCAP_IS0   VTSS_IO_OFFSET1(0x00270000) /*!< Base offset for target VCAP_IS0 */
#define VTSS_TO_VCAP_IS1   VTSS_IO_OFFSET1(0x00280000) /*!< Base offset for target VCAP_IS1 */
#define VTSS_TO_VCAP_IS2   VTSS_IO_OFFSET1(0x00290000) /*!< Base offset for target VCAP_IS2 */
#define VTSS_TO_ARB        VTSS_IO_OFFSET1(0x002a0000) /*!< Base offset for target ARB */
#define VTSS_TO_SCH        VTSS_IO_OFFSET1(0x002b0000) /*!< Base offset for target SCH */
#define VTSS_TO_DSM        VTSS_IO_OFFSET1(0x002c0000) /*!< Base offset for target DSM */
#define VTSS_TO_HSIO       VTSS_IO_OFFSET1(0x002d0000) /*!< Base offset for target HSIO */
#define VTSS_TO_VCAP_ES0   VTSS_IO_OFFSET1(0x002e0000) /*!< Base offset for target VCAP_ES0 */
#define VTSS_TO_ANA_L3     VTSS_IO_OFFSET1(0x00800000) /*!< Base offset for target ANA_L3 */
#define VTSS_TO_ANA_L2     VTSS_IO_OFFSET1(0x00900000) /*!< Base offset for target ANA_L2 */
#define VTSS_TO_ANA_AC     VTSS_IO_OFFSET1(0x00a00000) /*!< Base offset for target ANA_AC */
#define VTSS_TO_IQS        VTSS_IO_OFFSET1(0x00b00000) /*!< Base offset for target IQS */
#define VTSS_TO_OQS        VTSS_IO_OFFSET1(0x00c00000) /*!< Base offset for target OQS */
#define VTSS_TO_REW        VTSS_IO_OFFSET1(0x00d00000) /*!< Base offset for target REW */
#define VTSS_TO_CFG        VTSS_IO_OFFSET2(0x00000000) /*!< Base offset for target CFG */
#define VTSS_TO_UART       VTSS_IO_OFFSET2(0x00100000) /*!< Base offset for target UART */
#define VTSS_TO_TWI        VTSS_IO_OFFSET2(0x00100400) /*!< Base offset for target TWI */
#define VTSS_TO_SBA        VTSS_IO_OFFSET2(0x00110000) /*!< Base offset for target SBA */
#define VTSS_TO_DMAC       VTSS_IO_OFFSET2(0x00110800) /*!< Base offset for target DMAC */

/* IO address mapping macro - may be changed for platform */
#if !defined(VTSS_IOADDR)
#define VTSS_IOADDR(t,o)        ((t) + (4 * (o)))
#endif

/* IO register access macro - may be changed for platform */
#if !defined(VTSS_IOREG)
/** 
 * @param t - target base offset
 * @param o - subtarget offset
 */
#define VTSS_IOREG(t,o)      (*((volatile unsigned long*)(VTSS_IOADDR(t,o))))
#endif

/* IO indexed register access macro - may be changed for platform */
#if !defined(VTSS_IOREG_IX)
/** 
 * @param t  - target base offset
 * @param o  - subtarget offset
 * @param g  - group instance, 
 * @param gw - group width
 * @param ro - register offset, 
 * @param r  - register (instance) number
 */
#define VTSS_IOREG_IX(t,o,g,gw,r,ro)   VTSS_IOREG(t,(o) + ((g) * (gw)) + (ro) + (r))
#endif

#ifdef VTSS_JAGUAR_WANT_TARGET_ENUMS
/*
 * This section is primarily for documentation purposes.
 */

/**
  * \brief Target DEV10G target offset(s)
  */
enum vtss_target_DEV10G_e {
    VTSS_TOE_DEV10G_0        = VTSS_TO_DEV10G_0,
    VTSS_TOE_DEV10G_1        = VTSS_TO_DEV10G_1,
    VTSS_TOE_DEV10G_2        = VTSS_TO_DEV10G_2,
    VTSS_TOE_DEV10G_3        = VTSS_TO_DEV10G_3,
};

/**
  * \brief Target DEV2G5 target offset(s)
  */
enum vtss_target_DEV2G5_e {
    VTSS_TOE_DEV2G5_0        = VTSS_TO_DEV2G5_0,
    VTSS_TOE_DEV2G5_1        = VTSS_TO_DEV2G5_1,
    VTSS_TOE_DEV2G5_2        = VTSS_TO_DEV2G5_2,
    VTSS_TOE_DEV2G5_3        = VTSS_TO_DEV2G5_3,
    VTSS_TOE_DEV2G5_4        = VTSS_TO_DEV2G5_4,
    VTSS_TOE_DEV2G5_5        = VTSS_TO_DEV2G5_5,
    VTSS_TOE_DEV2G5_6        = VTSS_TO_DEV2G5_6,
    VTSS_TOE_DEV2G5_7        = VTSS_TO_DEV2G5_7,
    VTSS_TOE_DEV2G5_8        = VTSS_TO_DEV2G5_8,
};

/**
  * \brief Target DEV1G target offset(s)
  */
enum vtss_target_DEV1G_e {
    VTSS_TOE_DEV1G_0         = VTSS_TO_DEV1G_0,
    VTSS_TOE_DEV1G_1         = VTSS_TO_DEV1G_1,
    VTSS_TOE_DEV1G_2         = VTSS_TO_DEV1G_2,
    VTSS_TOE_DEV1G_3         = VTSS_TO_DEV1G_3,
    VTSS_TOE_DEV1G_4         = VTSS_TO_DEV1G_4,
    VTSS_TOE_DEV1G_5         = VTSS_TO_DEV1G_5,
    VTSS_TOE_DEV1G_6         = VTSS_TO_DEV1G_6,
    VTSS_TOE_DEV1G_7         = VTSS_TO_DEV1G_7,
    VTSS_TOE_DEV1G_8         = VTSS_TO_DEV1G_8,
    VTSS_TOE_DEV1G_9         = VTSS_TO_DEV1G_9,
    VTSS_TOE_DEV1G_10        = VTSS_TO_DEV1G_10,
    VTSS_TOE_DEV1G_11        = VTSS_TO_DEV1G_11,
    VTSS_TOE_DEV1G_12        = VTSS_TO_DEV1G_12,
    VTSS_TOE_DEV1G_13        = VTSS_TO_DEV1G_13,
    VTSS_TOE_DEV1G_14        = VTSS_TO_DEV1G_14,
    VTSS_TOE_DEV1G_15        = VTSS_TO_DEV1G_15,
    VTSS_TOE_DEV1G_16        = VTSS_TO_DEV1G_16,
    VTSS_TOE_DEV1G_17        = VTSS_TO_DEV1G_17,
};

#endif /* VTSS_JAGUAR_WANT_TARGET_ENUMS */


#endif /* _VTSS_JAGUAR_REGS_COMMON_H_ */
