/*
 *
 * bcm59121.h - Definitions for Broadcom BCM59121 Power over Ethernet controller
 *
 * Copyright (c) 2015 Cisco Systems, Inc.
 * Author: Dean Thomas <dean@meraki.com>
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
 * This file based on pd690xx.h by Kevin Herbert
 */

#ifndef _BCM59121_H_
#define _BCM59121_H_

enum bcm59121_errcodes {
    OK = 0,
    EBADSTATE = 300,       /* We don't want to collide with standard errno's */
    EI2C,
    ERESPONSEBUFSIZE,
    ERESPONSECHECKSUM,
    ENOTREADY,
    EREQUESTCHECKSUM,
    EREQUESTINCOMPLETE,
    ERESPONSECMDBAD,
    ERESPONSESEQBAD,
    ERESPONSEALLFF,
    EREQENXIO,
    EBADSYSSTATUS,
    EZEROPORTS,
};

struct bcm59121_platform_data {
	int		gpio_disable;		/* GPIO pin for disable (H_POE_Disable) */
	int		gpio_reset;		/* GPIO pin for reset (H_POE_RST) */
	int		disable_ports;		/* GPIO pin for port disable */
	int		logic_low;		/* GPIO value for logic low */
	int		port_base;		/* Base # of managed ports */
	char		*therm_domain;		/* Thermal domain */
	int		temp_warm;		/* When we should start cooling */
	int		power_budget;		/* Total power budge available in mW*/
	int		poll_interval;		/* Polling interval */
	bool		fast_state_detect;	/* Expedite port on/off state detection */
};

#endif /* _BCM59121_H_ */
