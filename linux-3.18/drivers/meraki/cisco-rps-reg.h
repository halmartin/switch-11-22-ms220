/* cisco-rps-reg.h - register maps for interfacing with the Cisco RPS 2300   */
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2013 Cisco Systems, Inc.

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

#ifndef CISCO_RPS_REG_H
#define CISCO_RPS_REG_H

#define CISCO_RPS_SID_LOWER_ADDR 0x54
#define CISCO_RPS_SID_UPPER_ADDR 0x55
#define CISCO_RPS_SCRATCH_ADDR 0x56
#define CISCO_RPS_FPGA_ADDR 0x57

#define CISCO_RPS_CMD_UPDATE_STANDBY 0x0e
#define CISCO_RPS_CMD_BACKOFF 0x10
#define CISCO_RPS_CMD_UPDATE_POWER_CLASS 0x12
#define CISCO_RPS_CMD_SET_FAN_SPEED 0x25
#define CISCO_RPS_CMD_SET_FRU_FAN_SPEED 0x26

/* Sid lower EEPROM addresses. Not all of these are readable or
   writable: some will enact commands upon being addressed -- of
   particular note, the *_control registers. */
struct cisco_rps_sid_lower_map {
    uint8_t sid_pid[18];
    uint8_t sid_vid[3];
    uint8_t sid_sn[11];

    uint8_t fru_a_pid[18];
    uint8_t fru_a_vid[3];
    uint8_t fru_a_sn[11];

    uint8_t fru_b_pid[18];
    uint8_t fru_b_vid[3];
    uint8_t fru_b_sn[11];

    uint8_t fru_a_power_class;
    uint8_t fru_a_status;

    uint8_t fru_b_power_class;
    uint8_t fru_b_status;

    uint8_t uart_status;
    uint8_t diagnostic[5];
    uint8_t ios_switch_num[6];

    uint8_t power_port_id;
    uint8_t power_port_priority[6];
    uint8_t reserved_ios_algo;
    uint8_t power_port_status[6];
    uint8_t power_port_control[6];

    uint8_t sid_fault;
    uint8_t sid_temp;
    uint8_t sid_status;
    uint8_t sid_control;
    uint8_t power_port_power_class[6];
    uint8_t fru_a_temp;
    uint8_t fru_b_temp;
    uint8_t sid_name[16];
    uint8_t power_port_name[6][16];
};

struct cisco_rps_sid_upper_map {
    uint8_t eeprom_que[16][4];

    uint8_t reserved0[64];

    uint8_t total_backups;
    uint8_t port_backups[6];
    uint8_t num_power_cycles[2];

    uint8_t sid_fault0;
    uint8_t sid_fault1;
    uint8_t scud_fault;
    uint8_t fru_fault;
    uint8_t fru_fault_serial[11];

    uint8_t reserved1[8];

    uint8_t port_command_buf[6][16];
};

/* Note: the FPGA memory map is arranged in 32-bit chunks, but can be
   addressed by byte. */
#define CISCO_RPS_RESET_MAGIC 0x5A
struct cisco_rps_fpga_map {
    uint8_t fpga_rev_minor;
    uint8_t fpga_rev_major;
    uint8_t unused0[2];

    uint32_t fsm_control;

    uint32_t fru_info;
    uint32_t priority_info;

    uint32_t fsm_status;
    uint32_t port_status;
    uint32_t port_present;
    uint32_t undervolt_status;
    uint32_t fru_status;
    uint32_t fru_control;
    uint32_t test_points;
    uint32_t atmel_io;
    uint32_t alternate_set_points;
    uint32_t int_sys_volt_mon;
    uint32_t hw_debug;
    uint32_t button_status;
    uint32_t drop_delay;
    uint32_t unused1[15];

    uint32_t port_update_flags[6];
    uint32_t eeprom_que_flag;
    uint32_t eeprom_que_base_addr;
    uint32_t eeprom_que_depth;
    uint32_t eeprom_que_status;
    uint32_t system_reset;
    uint32_t slave_reset;
    uint32_t smb_reset;
};

#endif
