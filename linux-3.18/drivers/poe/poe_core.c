/*
 *
 * poe_core.c - PoE core support
 *
 * Copyright (c) 2011 Meraki, Inc.
 * Copyright (c) 2015 Cisco Systems, Inc.
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
 * This is the core of the PoE subsystem, representing the device
 * abstraction. A system may consist of multiple PoE devices, each
 * of which may have one or more controllers, managing one or more
 * ports. This driver manages the relationship between the high level
 * device model, the abstract controller and port objects, and the device
 * drivers which manange the controllers and ports.
 *
 * This is a generic subsystem device driver and should not contain any
 * hardware dependencies.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/poe.h>

static DEFINE_MUTEX(poe_mutex);

static LIST_HEAD(poe_dev_list);

#define POE_DEV_ATTR_SET(name)						\
static ssize_t poe_dev_show_##name(struct device *dev,			\
				    struct device_attribute *attr,	\
				    char *buf)				\
{									\
	struct poe_dev *poe_dev = device_to_poe_dev(dev)		\
									\
	return scnprintf(buf, PAGE_SIZE, "%u\n", poe_dev->name);	\
}									\
static DEVICE_ATTR(name, S_IRUGO | S_IWUSR, poe_dev_show_##name,	\
	poe_dev_set_##name)

#define POE_DEV_ATTR_SHOW(name)						\
static ssize_t poe_dev_show_##name(struct device *dev,			\
				     struct device_attribute *attr,	\
				     char *buf)				\
{									\
	struct poe_dev *poe_dev = device_to_poe_dev(dev);		\
									\
	return scnprintf(buf, PAGE_SIZE, "%u\n", poe_dev->name);	\
}									\
static DEVICE_ATTR(name, S_IRUGO, poe_dev_show_##name, NULL)

#ifdef CONFIG_THERMAL
static ssize_t
poe_dev_set_temp_warm(struct device *dev, struct device_attribute *attr,
		      const char *buf, size_t count)
{
	int temp;
	struct poe_dev *poe_dev = device_to_poe_dev(dev);

	temp = simple_strtoul(buf, NULL, 10);
	if (!temp)
		return -EINVAL;

	poe_dev->temp_warm = temp;

	return count;
}

POE_DEV_ATTR_SET(temp_warm);
#endif /* CONFIG_THERMAL */

static ssize_t
poe_dev_set_power_budget(struct device *dev, struct device_attribute *attr,
                         const char *buf, size_t count)
{
	uint32_t budget;
	int ret;
	struct poe_dev *poe_dev = device_to_poe_dev(dev);

	if (!poe_dev->set_power_budget)
		return -ENOSYS;

	budget = simple_strtoul(buf, NULL, 10);
	ret = poe_dev->set_power_budget(poe_dev, budget);
	if (ret < 0)
		return ret;
	return count;
}

POE_DEV_ATTR_SET(power_budget);

POE_DEV_ATTR_SHOW(total_power);
POE_DEV_ATTR_SHOW(status);

static struct attribute *poe_dev_attrs[] = {
	&dev_attr_total_power.attr,
	&dev_attr_power_budget.attr,
	&dev_attr_status.attr,
#ifdef CONFIG_THERMAL
	&dev_attr_temp_warm.attr,
#endif /* CONFIG_THERMAL */
	NULL
};

static const struct attribute_group poe_dev_attr_group = {
	.attrs = poe_dev_attrs,
};

static const struct attribute_group *poe_dev_attr_groups[] = {
	&poe_dev_attr_group,
	NULL
};

static void poe_dev_release(struct device *device)
{
	struct poe_dev *dev = device_to_poe_dev(device);

	kfree(dev);

	module_put(THIS_MODULE);
}

static struct class poe_class = {
	.name		= "poe",
	.owner		= THIS_MODULE,
};

struct device_type poe_dev_type = {
	.groups		= poe_dev_attr_groups,
	.release	= poe_dev_release,
};

/**
 * poe_allocate_device - Allocate memory for new PoE device
 *
 * Returns prepared struct poe_dev or NULL
 *
 * NOTE: Use poe_free_device() to free devices that have not been
 * registered; poe_unregister_device() should be used for already
 * registered devices.
 */

struct poe_dev *poe_allocate_device(void)
{
	struct poe_dev *dev;

	dev = kzalloc(sizeof(struct poe_dev), GFP_KERNEL);
	if (dev) {
		dev->dev.type = &poe_dev_type;
		dev->dev.class = &poe_class;
		dev->controllers = 1; /* Default one controller/device */
		device_initialize(&dev->dev);
		INIT_LIST_HEAD(&dev->node);

		__module_get(THIS_MODULE);
	}

	return dev;
}
EXPORT_SYMBOL(poe_allocate_device);

/**
 * poe_free_device - free memory occupied by poe_dev structure
 * @dev: poe device to free
 *
 * This function should only be used if poe_register_device()
 * was not called yet or if it failed. Once device was registered
 * use poe_unregister_device() and memory will be freed once last
 * reference to the device is dropped.
 *
 * Device should be allocated by poe_allocate_device().
 *
 * NOTE: If there are references to the poe device then memory
 * will not be freed until last reference is dropped.
 */
void poe_free_device(struct poe_dev *dev)
{
	if (dev)
		poe_put_device(dev);
}
EXPORT_SYMBOL(poe_free_device);

/**
 * poe_register_device - register device with poe core
 * @dev: device to be registered
 *
 * This function registers device with poe core. The device must be
 * allocated with poe_allocate_device() and all it's capabilities
 * set up before registering.
 * If function fails the device must be freed with poe_free_device().
 * Once device has been successfully registered it can be unregistered
 * with poe_unregister_device(); poe_free_device() should not be
 * called in this case.
 */
int poe_register_device(struct poe_dev *dev)
{
	static atomic_t poe_no = ATOMIC_INIT(0);
	const char *path;
	int error;

	dev_set_name(&dev->dev, "poe%ld",
		     (unsigned long) atomic_inc_return(&poe_no) - 1);

	error = device_add(&dev->dev);
	if (error)
		goto error_return;

	path = kobject_get_path(&dev->dev.kobj, GFP_KERNEL);
	printk(KERN_INFO "poe: %s as %s\n",
		dev->name ? dev->name : "Unspecified device", path ? path : "N/A");
	kfree(path);

	error = poe_register_controllers(dev);
	if (error)
		goto error_device_del;

	error = poe_register_ports(dev);
	if (error)
		goto error_free_controllers;

	error = mutex_lock_interruptible(&poe_mutex);
	if (error)
		goto error_free_ports;

	list_add_tail(&dev->node, &poe_dev_list);

	mutex_unlock(&poe_mutex);

	return 0;

error_free_ports:
	poe_free_ports(dev);
error_free_controllers:
	poe_free_controllers(dev);
error_device_del:
	device_del(&dev->dev);
error_return:
	return error;
}
EXPORT_SYMBOL(poe_register_device);

/**
 * poe_unregister_device - unregister previously registered device
 * @dev: device to be unregistered
 *
 * This function unregisters a PoE device. Once device is unregistered
 * the caller should not try to access it as it may get freed at any moment.
 */
void poe_unregister_device(struct poe_dev *dev)
{
	mutex_lock(&poe_mutex);

	list_del_init(&dev->node);

	mutex_unlock(&poe_mutex);

	poe_free_ports(dev);
	poe_free_controllers(dev);

	device_unregister(&dev->dev);
}
EXPORT_SYMBOL(poe_unregister_device);

static int __init init_poecore(void)
{
	int status;

	status = class_register(&poe_class);
	if (status < 0)
		return status;

	return 0;
}

static void __exit cleanup_poecore(void)
{
	class_unregister(&poe_class);
}

module_init(init_poecore);
module_exit(cleanup_poecore);

MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.net>");
MODULE_DESCRIPTION("PoE core");
MODULE_LICENSE("GPL");
