/*
 *
 * poe_controllers.c - PoE controller support
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
 * This driver abstracts the "controller" portion of the PoE subsystem.
 * A controller is responsible for managing one or more ports. A controller
 * is part of a device, and a device may have one or more controllers.
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

struct poe_controller_attr {
	struct attribute attr;
	ssize_t (*show)(struct poe_controller_kobj *, char *);
	ssize_t (*store)(struct poe_controller_kobj *, const char *, size_t);
};

#define attr_to_poe_controller_attr(a) \
container_of(a, struct poe_controller_attr, attr)

static ssize_t poe_controller_sysfs_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	int ret = -EIO;
	struct poe_controller_attr *pattr = attr_to_poe_controller_attr(attr);
	struct poe_controller_kobj *controller_kobj =
	  kobj_to_controller_obj(kobj);

	if (pattr->show)
		ret = pattr->show(controller_kobj, buf);

	return ret;
}

static ssize_t poe_controller_sysfs_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf,
				    size_t count)
{
	int ret = -EIO;
	struct poe_controller_attr *pattr = attr_to_poe_controller_attr(attr);
	struct poe_controller_kobj *controller_kobj =
	  kobj_to_controller_obj(kobj);

	if (pattr->store)
		ret = pattr->store(controller_kobj, buf, count);

	return ret;
}

static struct sysfs_ops poe_controller_sysfs_ops = {
	.show = poe_controller_sysfs_show,
	.store = poe_controller_sysfs_store,
};

#define POE_CONTROLLER_ATTR_SHOW_U(name)				\
static ssize_t poe_controller_show_##name(struct poe_controller_kobj *kobj, \
				    char *buf)				\
{									\
	return scnprintf(buf, PAGE_SIZE, "%u\n", kobj->name);		\
}									\
static struct poe_controller_attr poe_controller_attr_##name = __ATTR(name, S_IRUGO, poe_controller_show_##name, NULL);

#define POE_CONTROLLER_ATTR_SHOW_D(name)				\
static ssize_t poe_controller_show_##name(struct poe_controller_kobj *kobj, \
				    char *buf)				\
{									\
	return scnprintf(buf, PAGE_SIZE, "%d\n", kobj->name);		\
}									\
static struct poe_controller_attr poe_controller_attr_##name = __ATTR(name, S_IRUGO, poe_controller_show_##name, NULL);

POE_CONTROLLER_ATTR_SHOW_U(power_master);
POE_CONTROLLER_ATTR_SHOW_U(power_slave);
POE_CONTROLLER_ATTR_SHOW_U(power_limit);
POE_CONTROLLER_ATTR_SHOW_D(temp);
POE_CONTROLLER_ATTR_SHOW_U(vmain);

static ssize_t
poe_controller_show_raw_addr(struct poe_controller_kobj *kobj, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%X\n", kobj->raw_addr);
}

static ssize_t
poe_controller_set_raw_addr(struct poe_controller_kobj *kobj, const char *buf, size_t count)
{
	kobj->raw_addr = (0xffff & simple_strtoul(buf, NULL, 0));
	return count;
}

static struct poe_controller_attr poe_controller_attr_raw_addr = __ATTR(raw_addr, S_IRUGO | S_IWUSR, poe_controller_show_raw_addr, poe_controller_set_raw_addr);

static ssize_t
poe_controller_show_raw_value(struct poe_controller_kobj *kobj, char *buf)
{
	int ret;
	ret = kobj->poe_dev->read_raw_reg(kobj);
	if (ret < 0)
		return ret;

	return scnprintf(buf, PAGE_SIZE, "0x%X\n", ret);
}

static ssize_t
poe_controller_set_raw_value(struct poe_controller_kobj *kobj, const char *buf, size_t count)
{
	int ret;
	ret = kobj->poe_dev->write_raw_reg(kobj, (0xffff & simple_strtoul(buf, NULL, 0)));
	return ret < 0 ? ret : count;
}

static struct poe_controller_attr poe_controller_attr_raw_value = __ATTR(raw_value, S_IRUGO | S_IWUSR, poe_controller_show_raw_value, poe_controller_set_raw_value);

static ssize_t
poe_controller_show_stats(struct poe_controller_kobj *kobj, char *buf)
{
	struct poe_dev *poe;
        ssize_t status;

	poe = kobj->poe_dev;
        if (poe->controller_stats) {
                status = poe->controller_stats(kobj, PAGE_SIZE, buf);
        } else {
                status = -EINVAL;
        }
        return status;
}

static struct poe_controller_attr poe_controller_attr_stats =
                __ATTR(stats, S_IRUGO, poe_controller_show_stats, NULL);

static struct attribute *poe_controller_default_attrs[] = {
	&poe_controller_attr_power_master.attr,
	&poe_controller_attr_power_slave.attr,
	&poe_controller_attr_power_limit.attr,
	&poe_controller_attr_temp.attr,
	&poe_controller_attr_vmain.attr,
	&poe_controller_attr_raw_addr.attr,
	&poe_controller_attr_raw_value.attr,
	&poe_controller_attr_stats.attr,
	NULL
};

static void poe_free_controller_kobj(struct poe_dev *dev, int i)
{
	struct poe_controller_kobj *controller_kobj = dev->controller_kobjs[i];

	kobject_put(&controller_kobj->kobj);
	wait_for_completion(&controller_kobj->kobj_unregister);
#ifdef CONFIG_THERMAL
	thermal_zone_device_unregister(controller_kobj->tdev);
#endif
	kfree(controller_kobj);
	dev->controller_kobjs[i] = NULL;
}

void poe_free_controllers(struct poe_dev *dev)
{
	int i;

	for (i = 0; i < dev->controllers; i++)
		poe_free_controller_kobj(dev, i);
	kfree(dev->controller_kobjs);
	dev->controller_kobjs = NULL;
}

static void poe_controller_sysfs_release(struct kobject *kobj)
{
	struct poe_controller_kobj *controller_kobj = kobj_to_controller_obj(kobj);

	complete(&controller_kobj->kobj_unregister);
}

static struct kobj_type ktype_poe_controller = {
	.sysfs_ops = &poe_controller_sysfs_ops,
	.default_attrs = poe_controller_default_attrs,
	.release = poe_controller_sysfs_release,
};

#ifdef CONFIG_THERMAL
static int
poe_thermal_bind(struct thermal_zone_device *tdev,
		 struct thermal_cooling_device *cdev)
{
	return thermal_zone_bind_cooling_device(tdev, 0, cdev,
                THERMAL_NO_LIMIT, THERMAL_NO_LIMIT);
}

static int
poe_thermal_unbind(struct thermal_zone_device *tdev,
		   struct thermal_cooling_device *cdev)
{
	return thermal_zone_unbind_cooling_device(tdev, 0, cdev);
}

static int
poe_thermal_get_temp(struct thermal_zone_device *tdev, unsigned long *temp)
{
	struct poe_controller_kobj *controller_kobj = tdev->devdata;

	*temp = controller_kobj->temp * 1000;

	return 0;
}

static int
poe_thermal_get_trip_type(struct thermal_zone_device *tdev, int which,
			  enum thermal_trip_type *type)
{
	*type = THERMAL_TRIP_ACTIVE; /* All we do right now */
	return 0;
}

static int
poe_thermal_get_trip_temp(struct thermal_zone_device *tdev, int which,
			  unsigned long *temp)
{
	struct poe_controller_kobj *controller_kobj = tdev->devdata;
	struct poe_dev *poe = controller_kobj->poe_dev;

	*temp = poe->temp_warm * 1000;

	return 0;
}

static struct thermal_zone_device_ops poe_thermal_zone_ops = {
	.bind = poe_thermal_bind,
	.unbind = poe_thermal_unbind,
	.get_temp = poe_thermal_get_temp,
	.get_trip_type = poe_thermal_get_trip_type,
	.get_trip_temp = poe_thermal_get_trip_temp,
};
#endif /* CONFIG_THERMAL */

/**
 * poe_register_controllers - Register the controllers on a PoE device
 *
 * This routine creates sysfs entries for each of the controllers
 * on the PoE device.
 */

int poe_register_controllers(struct poe_dev *dev)
{
	int i;
	struct poe_controller_kobj *kobj;
	int ret;
#ifdef CONFIG_THERMAL
	struct thermal_zone_device *tdev;
#endif

	dev->controller_kobjs = kzalloc((sizeof kobj) * dev->controllers,
				  GFP_KERNEL);
	if (!dev->controller_kobjs)
		return -ENOMEM;

	for (i = 0; i < dev->controllers; i++) {
		kobj = kzalloc(sizeof(struct poe_controller_kobj), GFP_KERNEL);
		if (!kobj) {
			ret = -ENOMEM;
			goto error_state;
		}
		kobj->poe_dev = dev;
#ifdef CONFIG_THERMAL
		tdev = thermal_zone_device_register(dev->therm_domain, 1, 0x1, kobj,
						    &poe_thermal_zone_ops,
						    NULL, 0, 0);

		if (IS_ERR(tdev)) {
			ret = (tdev == NULL ? 0 : 1);
			goto free_kobj;
		}
		kobj->tdev = tdev;
#endif /* CONFIG_THERMAL */
		init_completion(&kobj->kobj_unregister);
		ret = kobject_init_and_add(&kobj->kobj, &ktype_poe_controller,
					   &dev->dev.kobj, "controller%d", i);
		if (ret) {
			goto free_therm;
		}
		kobject_uevent(&kobj->kobj, KOBJ_ADD);
		dev->controller_kobjs[i] = kobj;
	}

	return 0;

free_therm:
#ifdef CONFIG_THERMAL
	thermal_zone_device_unregister(tdev);
free_kobj:
#endif /* CONFIG_THERMAL */
	kfree(kobj);
error_state:
	for (i = i - 1; i >=0; i--)
		poe_free_controller_kobj(dev, i);
	kfree(dev->controller_kobjs);
	dev->controller_kobjs = NULL;
	return ret;
}
