/* cisco-act-i2c.c - a device driver for the Cisco ACT2 chip  */
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

/* Initial driver commit by William Hauser <whauser@meraki.com> */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/of_gpio.h>
#include <linux/input.h>
#include <linux/meraki/cisco-act.h>

static const struct i2c_device_id cisco_act_i2c_ids[] = {
	{ "act-i2c", 0 },
	{ /* END OF LIST */ }
};

MODULE_DEVICE_TABLE(i2c, cisco_act_i2c_ids);

static const struct of_device_id __maybe_unused cisco_act_dt_ids[] = {
	{ .compatible = "cisco,act-i2c", },
	{ /* END OF LIST */ }
};
MODULE_DEVICE_TABLE(of, cisco_act_dt_ids);

/*
 * Specs often allow 5 msec for a page write, sometimes 20 msec;
 * it's important to recover from write timeouts.
 */
static unsigned write_timeout = 5;
module_param(write_timeout, uint, 0);
MODULE_PARM_DESC(write_timeout, "Time (in ms) to try writes (default 5)");

static ssize_t act_data_read_i2c(struct act_data *act,
				 char *buf,
				 unsigned offset,
				 size_t count)
{
	struct i2c_client *client = act->bus_dev;
	struct i2c_msg msg;
	int status;

	memset(&msg, 0, sizeof(struct i2c_msg));

	if(client->adapter->quirks &&
	   count > client->adapter->quirks->max_read_len)
	count = client->adapter->quirks->max_read_len;

	msg.addr = client->addr;
	msg.flags = I2C_M_RD;
	msg.buf = buf;
	msg.len = count;

	/*
	 * Read data from chip, protecting against concurrent updates
	 * from this host, but not from other I2C masters.
	 */
	mutex_lock(&act->lock);
	status = i2c_transfer(client->adapter, &msg, 1);
	mutex_unlock(&act->lock);
	if (status == 1)
		status = count;
	dev_dbg(&client->dev, "read %zu@%d --> %d\n",
		count, offset, status);

	if (status == count)
		return count;

	return -ETIMEDOUT;

}

static ssize_t act_data_write_i2c(struct act_data *act,
				  const char *buf,
				  unsigned offset,
				  size_t count)
{
	struct i2c_client *client = act->bus_dev;
	struct i2c_msg msg;
	ssize_t status;

	msg.addr = client->addr;
	msg.flags = 0;

	/* msg.buf is u8 and casts will mask the values */
	msg.buf = act->writebuf;

	memcpy(msg.buf, buf, count);
	msg.len = count;

	/*
	 * Write data to chip, protecting against concurrent updates
	 * from this host, but not from other I2C masters.
	 */
	mutex_lock(&act->lock);
	status = i2c_transfer(client->adapter, &msg, 1);
	mutex_unlock(&act->lock);
	if (status == 1)
		status = count;
	dev_dbg(&client->dev, "write %zu@%d --> %zd\n",
		count, offset, status);

	if (status == count)
		return count;

	return -ETIMEDOUT;
}

static const struct cisco_act_bus_ops cisco_act_i2c_ops = {
	.bustype = BUS_I2C,
	.read = act_data_read_i2c,
	.write = act_data_write_i2c,
};

static int cisco_act_i2c_probe(struct i2c_client *client,
			       const struct i2c_device_id *id)
{
	struct act_data *act;
	int err = 0;

	act = cisco_act_common_probe(&client->dev, &cisco_act_i2c_ops);
	if (IS_ERR(act)) {
		err = PTR_ERR(act);
		goto fail_init_act_common;
	}

	act->bus_dev = client;

fail_init_act_common:
	return err;
}

static struct i2c_driver cisco_act_i2c_driver = {
	.driver = {
		.name		= "cisco-act-i2c",
		.owner		= THIS_MODULE,
	},
	.probe		= cisco_act_i2c_probe,
	.id_table	= cisco_act_i2c_ids,
};

module_i2c_driver(cisco_act_i2c_driver);

MODULE_AUTHOR("William H. Hauser <whauser@meraki.com>");
MODULE_DESCRIPTION("Device driver for ACT2");
MODULE_LICENSE("GPL");
