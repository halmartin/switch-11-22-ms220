#ifndef __THERMAL_GPIO_H__
#define __THERMAL_GPIO_H__

/*
 * Definitions for simple thermal GPIO driver
 *
 * Kevin Paul Herbert
 * Copyright (c) 2012, Meraki, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

struct thermal_gpio_platform_data {
	unsigned gpio;		/* GPIO number to use */
	int fan_active;		/* Value to write to enable fan */
	char *type;		/* Type of cooling device */
};

#endif /* __THERMAL_GPIO_H__ */
