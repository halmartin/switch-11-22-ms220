/*
 *
 * VCore-III SGPIO definitions
 *
 * Copyright (c) 2012 Meraki, Inc.
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
 *
 * Definitions for the VCoreIII SGPIO driver
 */

#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

struct sgpio_platform_data {
	char *label;			/* Name of device */
	int gpio_di;			/* Data in GPIO (-1 if none) */
	unsigned gpio_do;		/* Data out GPIO */
	unsigned gpio_clk;		/* Clock GPIO */
	struct vcoreiii_sgpio_ctrl *ctrl; /* Mapped controller address */
	unsigned base;			/* GPIO base */
	int num_ports;			/* Number of ports */
	int gpios_per_port;		/* GPIOs per port */
	int init_value;			/* Initial value */
};

struct sgpio_gpio_state {
	struct gpio_chip gpio_chip;
	int gpio_di;			/* Data in GPIO (-1 if none) */
	unsigned gpio_do;		/* Data out GPIO */
	unsigned gpio_clk;		/* Clock GPIO */
	struct vcoreiii_sgpio_ctrl *ctrl; /* Controller register */
	int gpios_per_port;		  /* Number of GPIOs per port */
};
