/*
 *
 * pd690xx.h - Definitions for PD690xx Power over Ethernet controller
 *
 * Copyright (c) 2011, 2013 Meraki, Inc.
 * Author: Kevin Paul Herbert (kph@meraki.com)
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
 */

#ifndef _PD690XX_H_
#define _PD690XX_H_

struct pd690xx_platform_data {
	int		reset;			/* GPIO pin for reset */
	int		disable_ports;		/* GPIO pin for port disable */
	int		logic_low;		/* GPIO value for logic low */
	int		ports;			/* Number of managed ports */
	int		port_base;		/* Base # of managed ports */
	const u8	*slave_addr;		/* Slave address offsets */
	char		*therm_domain;		/* Thermal domain */
	int		temp_warm;		/* When we should start cooling */
	int		power_budget;		/* Total power budge available in mW*/
	int             controllers;		/* Number of controllers */
	int		poll_interval;		/* Polling interval */
	bool		fast_state_detect;	/* Expedite port on/off state detection */
};

#endif
