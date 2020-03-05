/* cisco-mps-reg.h - register map for the Cisco FRU for the C2960-XR Series  */
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2013-2015 Cisco Systems, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.                */
/* ------------------------------------------------------------------------- */

#ifndef CISCO_MPS_REG_H
#define CISCO_MPS_REG_H

#include <linux/types.h>

/* The "Control" I2C slave expects SMBus commands: */
#define CISCO_MPS_COMMAND_W_CLEAR_FAULTS 0x03

#define CISCO_MPS_COMMAND_RW_FAN_SPEED_DUTY 0x3a
#define CISCO_MPS_COMMAND_RW_FAN_SPEED_CONTROL1 0x3b
#define CISCO_MPS_COMMAND_RW_FAN_SPEED_CONTROL2 0x3c

#define CISCO_MPS_COMMAND_R_FAULT_OC 0x46
#define CISCO_MPS_COMMAND_R_I_OUT_WARN 0x4a
#define CISCO_MPS_COMMAND_R_FAULT_TEMP 0x4f

#define CISCO_MPS_COMMAND_R_TEMP_WARN 0x51
#define CISCO_MPS_COMMAND_R_V_IN_UNDER 0x58
#define CISCO_MPS_COMMAND_R_FAULT_UNDERVOLT 0x59
#define CISCO_MPS_COMMAND_R_I_IN_WARN 0x5d
#define CISCO_MPS_COMMAND_R_POWER_GOOD_ON 0x5e
#define CISCO_MPS_COMMAND_R_POWER_GOOD_OFF 0x5f

#define CISCO_MPS_COMMAND_R_FAULT_OVERPOWER 0x68
#define CISCO_MPS_COMMAND_R_P_OUT_OVER 0x6a
#define CISCO_MPS_COMMAND_R_P_IN_OVER 0x6b

#define CISCO_MPS_COMMAND_R_STATUS_WORD 0x79
#define CISCO_MPS_COMMAND_R_STATUS_V_OUT 0x7a
#define CISCO_MPS_COMMAND_R_STATUS_I_OUT 0x7b
#define CISCO_MPS_COMMAND_R_STATUS_INPUT 0x7c
#define CISCO_MPS_COMMAND_R_STATUS_TEMP 0x7d
#define CISCO_MPS_COMMAND_R_STATUS_CML 0x7e

#define CISCO_MPS_COMMAND_R_STATUS_FAN 0x81
#define CISCO_MPS_COMMAND_R_V_IN 0x88
#define CISCO_MPS_COMMAND_R_I_IN 0x89
#define CISCO_MPS_COMMAND_R_V_OUT 0x8b
#define CISCO_MPS_COMMAND_R_I_OUT 0x8c
#define CISCO_MPS_COMMAND_R_INLET_TEMPERATURE 0x8d
#define CISCO_MPS_COMMAND_R_OUTLET_TEMPERATURE 0x8e
#define CISCO_MPS_COMMAND_R_HOTSPOT_TEMPERATURE 0x8f

#define CISCO_MPS_COMMAND_R_FAN_SPEED 0x90
#define CISCO_MPS_COMMAND_R_P_OUT 0x96
#define CISCO_MPS_COMMAND_R_P_IN 0x97

/* The "Data" I2C slave acts just as a 24c02. We use a custom layout
   for this: fru_ps_serial is 14 bytes intead of the standard 11. */

struct cisco_mps_data_eeprom_map {
    uint8_t fru_ps_id[18];
    uint8_t fru_ps_vid[3];
    uint8_t fru_ps_serial[14];
    uint8_t fru_ps_class;
    uint8_t fru_vendor[15];
    uint8_t fru_ps_tan[11];
    uint8_t fru_ps_clei[10];
    uint8_t fru_t_data[4];
    uint8_t fru_csum1;
    uint8_t fru_reserved[178];
    uint8_t fru_csum2;
};

#endif
