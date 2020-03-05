/* cisco-act.c - a device driver for the Cisco ACT2 chip  */
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
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of_gpio.h>
#include <linux/delay.h>
#include <linux/meraki/cisco-act.h>


static ssize_t cisco_act_show_buffer_size(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct act_data *act = dev_get_drvdata(dev);
	memcpy(buf, &act->writebuf_size, sizeof(uint16_t));
	return sizeof(uint16_t);
}
static DEVICE_ATTR(buffer_size, 0444, cisco_act_show_buffer_size, NULL);

static ssize_t cisco_act_show_chip_family(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct act_data *act = dev_get_drvdata(dev);
	memcpy(buf, &act->chip_family, sizeof(u32));
	return sizeof(u32);
}
static DEVICE_ATTR(chip_family, 0444, cisco_act_show_chip_family, NULL);

static ssize_t cisco_act_lock(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return 0;
}
static DEVICE_ATTR(lock, 0444, cisco_act_lock, NULL);

static struct device_attribute *cisco_act_attrs[] = {
	&dev_attr_buffer_size,
	&dev_attr_lock,
	&dev_attr_chip_family,
};

static ssize_t act_bin_read(struct file *filp, struct kobject *kobj,
			    struct bin_attribute *attr,
			    char *buf, loff_t off, size_t count)
{
	struct act_data *act;

	act = dev_get_drvdata(container_of(kobj, struct device, kobj));
	return act->bus_ops->read(act, buf, off, count);
}

static ssize_t act_bin_write(struct file *filp, struct kobject *kobj,
			     struct bin_attribute *attr,
			     char *buf, loff_t off, size_t count)
{
	struct act_data *act;

	act = dev_get_drvdata(container_of(kobj, struct device, kobj));
	return act->bus_ops->write(act, buf, off, count);
}

static struct class *act_class;
static struct device_type act_dev_type;

static void act_dev_release(struct device *dev)
{
	pr_debug("device: '%s': %s\n", dev_name(dev), __func__);
	kfree(dev);
}

static int cisco_act_init_device(struct act_data *act)
{
	struct device *dev;
	int rc;

	dev = (struct device *)kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	device_initialize(dev);

	dev->class = act_class;
	dev->type = &act_dev_type;
	dev->parent = NULL; // put device in /sys/devices/
	dev->release = act_dev_release;
	dev_set_drvdata(dev, act);
	act->dev = dev;

	rc = dev_set_name(dev, "act2");
	if (rc)
		goto dev_add_failed;

	rc = device_add(dev);
	if (rc)
		goto dev_set_name_failed;

	return 0;

dev_add_failed:
dev_set_name_failed:
	put_device(dev);
	return rc;
}

struct act_data* cisco_act_common_probe(struct device* dev,
					const struct cisco_act_bus_ops* bus_ops)
{
	struct act_data *act;
	int err;
	int i;
	unsigned reset_pin;
	enum of_gpio_flags reset_pin_flags;
	uint16_t writebuf_size;
	u8* writebuf;

	if (!bus_ops) {
		printk(KERN_ERR "Invalid arguments: bus_ops\n");
		err = -EINVAL;
		goto fail_init_device;
	}

	act = devm_kzalloc(dev, sizeof(struct act_data), GFP_KERNEL);
	if (!act) {
		printk(KERN_ERR "ACT2 alloc fail\n");
		err = -ENOMEM;
		goto fail_init_device;
	}

	mutex_init(&act->lock);

	err = of_property_read_u16(dev->of_node,
				   "write_buf_size",
				   &writebuf_size);

	if (err < 0)
		writebuf_size = WRITE_MIN;
	else if (writebuf_size < WRITE_MIN || WRITE_MAX < writebuf_size) {
		err = -EINVAL;
		printk(KERN_ERR "invalid write_buf_size must be between %u and %u\n",
			WRITE_MIN, WRITE_MAX);
		goto fail_init_device;
	}
	writebuf = devm_kzalloc(dev, writebuf_size, GFP_KERNEL);
	if (!writebuf) {
		err = -ENOMEM;
		goto fail_init_device;
	}
	act->writebuf_size = writebuf_size;
	act->writebuf = writebuf;

	err = of_property_read_u32(dev->of_node,
				   "chip_family",
				   &act->chip_family);
	if (err < 0) {
		dev_err(dev, "Couldn't read chip_family\n");
		goto fail_init_device;
	}

	err = cisco_act_init_device(act);
	if (err)
		goto fail_init_device;

	sysfs_bin_attr_init(&act->bin);
	act->bin.attr.name = "data";
	act->bin.attr.mode = 0644;
	act->bin.read = act_bin_read;
	act->bin.write = act_bin_write;
	act->bin.size = writebuf_size;

	err = sysfs_create_bin_file(&act->dev->kobj, &act->bin);
	if (err)
		goto fail_create_bin_file;

	for (i = 0; i < ARRAY_SIZE(cisco_act_attrs); ++i) {
		err = device_create_file(act->dev, cisco_act_attrs[i]);
		if (err < 0)
			goto fail_create_device_file;
	}

	act->bus_ops = bus_ops;

	reset_pin = of_get_named_gpio_flags(dev->of_node, "reset", 0,
		&reset_pin_flags);

	/* bring into reset then back out to get to known state after kernel init */
	if (gpio_is_valid(reset_pin))
	{
		gpio_set_value_cansleep(reset_pin, !(reset_pin_flags & OF_GPIO_ACTIVE_LOW));
		udelay(1000);
		gpio_set_value_cansleep(reset_pin, !!(reset_pin_flags & OF_GPIO_ACTIVE_LOW));
	}

	return act;

fail_create_device_file:
	while (i > 0)
		device_remove_file(dev, cisco_act_attrs[--i]);
fail_create_bin_file:
	put_device(act->dev);
fail_init_device:
	return ERR_PTR(err);

}

MODULE_AUTHOR("William H. Hauser <whauser@meraki.com>");
MODULE_DESCRIPTION("Device driver for ACT2");
MODULE_LICENSE("GPL");
