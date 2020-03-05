#ifndef _VTSS_JAGUAR_REGS_UART_H_
#define _VTSS_JAGUAR_REGS_UART_H_

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

#include "vtss_jaguar_regs_common.h"

#define VTSS_UART_UART_RBR_THR               VTSS_IOREG(VTSS_TO_UART,0x0)
#define  VTSS_F_UART_UART_RBR_THR_RBR_THR(x)  VTSS_ENCODE_BITFIELD(x,0,8)
#define  VTSS_M_UART_UART_RBR_THR_RBR_THR     VTSS_ENCODE_BITMASK(0,8)
#define  VTSS_X_UART_UART_RBR_THR_RBR_THR(x)  VTSS_EXTRACT_BITFIELD(x,0,8)

#define VTSS_UART_UART_IER                   VTSS_IOREG(VTSS_TO_UART,0x1)
#define  VTSS_F_UART_UART_IER_PTIME           VTSS_BIT(7)
#define  VTSS_F_UART_UART_IER_EDSSI           VTSS_BIT(3)
#define  VTSS_F_UART_UART_IER_ELSI            VTSS_BIT(2)
#define  VTSS_F_UART_UART_IER_ETBEI           VTSS_BIT(1)
#define  VTSS_F_UART_UART_IER_ERBFI           VTSS_BIT(0)

#define VTSS_UART_UART_IIR_FCR               VTSS_IOREG(VTSS_TO_UART,0x2)
#define  VTSS_F_UART_UART_IIR_FCR_FIFOSE_RT(x)  VTSS_ENCODE_BITFIELD(x,6,2)
#define  VTSS_M_UART_UART_IIR_FCR_FIFOSE_RT     VTSS_ENCODE_BITMASK(6,2)
#define  VTSS_X_UART_UART_IIR_FCR_FIFOSE_RT(x)  VTSS_EXTRACT_BITFIELD(x,6,2)
#define  VTSS_F_UART_UART_IIR_FCR_TET(x)      VTSS_ENCODE_BITFIELD(x,4,2)
#define  VTSS_M_UART_UART_IIR_FCR_TET         VTSS_ENCODE_BITMASK(4,2)
#define  VTSS_X_UART_UART_IIR_FCR_TET(x)      VTSS_EXTRACT_BITFIELD(x,4,2)
#define  VTSS_F_UART_UART_IIR_FCR_XFIFOR      VTSS_BIT(2)
#define  VTSS_F_UART_UART_IIR_FCR_RFIFOR      VTSS_BIT(1)
#define  VTSS_F_UART_UART_IIR_FCR_FIFOE       VTSS_BIT(0)

#define VTSS_UART_UART_LCR                   VTSS_IOREG(VTSS_TO_UART,0x3)
#define  VTSS_F_UART_UART_LCR_DLAB            VTSS_BIT(7)
#define  VTSS_F_UART_UART_LCR_BC              VTSS_BIT(6)
#define  VTSS_F_UART_UART_LCR_EPS             VTSS_BIT(4)
#define  VTSS_F_UART_UART_LCR_PEN             VTSS_BIT(3)
#define  VTSS_F_UART_UART_LCR_STOP            VTSS_BIT(2)
#define  VTSS_F_UART_UART_LCR_DLS(x)          VTSS_ENCODE_BITFIELD(x,0,2)
#define  VTSS_M_UART_UART_LCR_DLS             VTSS_ENCODE_BITMASK(0,2)
#define  VTSS_X_UART_UART_LCR_DLS(x)          VTSS_EXTRACT_BITFIELD(x,0,2)

#define VTSS_UART_UART_MCR                   VTSS_IOREG(VTSS_TO_UART,0x4)
#define  VTSS_F_UART_UART_MCR_AFCE            VTSS_BIT(5)
#define  VTSS_F_UART_UART_MCR_LB              VTSS_BIT(4)
#define  VTSS_F_UART_UART_MCR_RTS             VTSS_BIT(1)

#define VTSS_UART_UART_LSR                   VTSS_IOREG(VTSS_TO_UART,0x5)
#define  VTSS_F_UART_UART_LSR_RFE             VTSS_BIT(7)
#define  VTSS_F_UART_UART_LSR_TEMT            VTSS_BIT(6)
#define  VTSS_F_UART_UART_LSR_THRE            VTSS_BIT(5)
#define  VTSS_F_UART_UART_LSR_BI              VTSS_BIT(4)
#define  VTSS_F_UART_UART_LSR_FE              VTSS_BIT(3)
#define  VTSS_F_UART_UART_LSR_PE              VTSS_BIT(2)
#define  VTSS_F_UART_UART_LSR_OE              VTSS_BIT(1)
#define  VTSS_F_UART_UART_LSR_DR              VTSS_BIT(0)

#define VTSS_UART_UART_MSR                   VTSS_IOREG(VTSS_TO_UART,0x6)
#define  VTSS_F_UART_UART_MSR_CTS             VTSS_BIT(4)
#define  VTSS_F_UART_UART_MSR_DCTS            VTSS_BIT(0)

#define VTSS_UART_UART_SCR                   VTSS_IOREG(VTSS_TO_UART,0x7)
#define  VTSS_F_UART_UART_SCR_SCR(x)          VTSS_ENCODE_BITFIELD(x,0,8)
#define  VTSS_M_UART_UART_SCR_SCR             VTSS_ENCODE_BITMASK(0,8)
#define  VTSS_X_UART_UART_SCR_SCR(x)          VTSS_EXTRACT_BITFIELD(x,0,8)

#define VTSS_UART_UART_USR                   VTSS_IOREG(VTSS_TO_UART,0x1f)
#define  VTSS_F_UART_UART_USR_BUSY            VTSS_BIT(0)


#endif /* _VTSS_JAGUAR_REGS_UART_H_ */
