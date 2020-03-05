/* cisco-act.h - definitions for cisco-act2 TAM support                     */ 
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2016 Cisco Systems, Inc.

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

#ifndef _CISCO_ACT_H_
#define _CISCO_ACT_H_

#include <linux/types.h>

/* Min/max number of bytes supported by tam library platform buffer */
#define WRITE_MIN 48
#define WRITE_MAX 259

struct act_data {
	/*
	* Lock protects against activities from other Linux tasks,
	* but not from changes by other I2C masters.
	*/
	struct mutex lock;

	struct bin_attribute bin;
	struct device *dev;
	void *bus_dev;

	const struct cisco_act_bus_ops* bus_ops;
	u8 *writebuf;
	uint16_t writebuf_size;
	u32 chip_family;

};

struct cisco_act_bus_ops {
	u16 bustype;
	int (*read)(struct act_data *act, char* buf, unsigned offset, size_t count);
	int (*write)(struct act_data *act, const char* buf, unsigned offset, size_t count);
};

extern struct act_data* cisco_act_common_probe(struct device* dev, const struct cisco_act_bus_ops* ops);

#endif
