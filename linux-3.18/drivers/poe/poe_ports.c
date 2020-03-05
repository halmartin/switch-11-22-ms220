/*
 *
 * poe_ports.c - PoE port support
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
 * This driver abstracts the "port" portion of the PoE subsystem. Each
 * powered port is represented in this driver by a port object. This
 * driver manages the relationship between ports and the rest of the system,
 * and interfaces with the physical device driver to manage these ports.
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

static int auto_power_enable = 0;

module_param(auto_power_enable, int, 0644);
MODULE_PARM_DESC(auto_power_enable, "Set to enable power by default.");

struct poe_port_attr {
	struct attribute attr;
	ssize_t (*show)(struct poe_port_kobj *, char *);
	ssize_t (*store)(struct poe_port_kobj *, const char *, size_t);
};

#define attr_to_poe_port_attr(a) container_of(a, struct poe_port_attr, attr)

static ssize_t poe_port_sysfs_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	int ret = -EIO;
	struct poe_port_attr *pattr = attr_to_poe_port_attr(attr);
	struct poe_port_kobj *port_kobj = kobj_to_port_obj(kobj);

	if (pattr->show)
		ret = pattr->show(port_kobj, buf);

	return ret;
}

static ssize_t poe_port_sysfs_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf,
				    size_t count)
{
	int ret = -EIO;
	struct poe_port_attr *pattr = attr_to_poe_port_attr(attr);
	struct poe_port_kobj *port_kobj = kobj_to_port_obj(kobj);

	if (pattr->store)
		ret = pattr->store(port_kobj, buf, count);

	return ret;
}

static struct sysfs_ops poe_port_sysfs_ops = {
	.show = poe_port_sysfs_show,
	.store = poe_port_sysfs_store,
};


#define POE_PORT_ATTR_SET(name)						\
static ssize_t poe_port_show_##name(struct poe_port_kobj *port_kobj,	\
				    char *buf)				\
{									\
	return scnprintf(buf, PAGE_SIZE, "%u\n", port_kobj->name);	\
}									\
static struct poe_port_attr poe_port_attr_##name = __ATTR(name, S_IRUGO | S_IWUSR, poe_port_show_##name, poe_port_set_##name);

#define POE_PORT_ATTR_SHOW(name)					\
static ssize_t poe_port_show_##name(struct poe_port_kobj *port_kobj,	\
				    char *buf)				\
{									\
	return scnprintf(buf, PAGE_SIZE, "%u\n", port_kobj->name);	\
}									\
static struct poe_port_attr poe_port_attr_##name = __ATTR(name, S_IRUGO, poe_port_show_##name, NULL);

static ssize_t
poe_port_set_enabled(struct poe_port_kobj *port_kobj, const char *buf,
		     size_t count)
{
	ssize_t		status = -EINVAL;
	struct poe_dev *poe;

	poe = kobj_to_poe_dev(port_kobj->kobj.parent);

	if (sysfs_streq(buf, "yes") || sysfs_streq(buf, "on") ||
	    sysfs_streq(buf, "1"))
		status = poe->port_enable(port_kobj, true);
	else if (sysfs_streq(buf, "no") || sysfs_streq(buf, "off") ||
		 sysfs_streq(buf, "0"))
		status = poe->port_enable(port_kobj, false);

	return status ? status : count;
}

POE_PORT_ATTR_SET(enabled);

static ssize_t
poe_port_set_priority(struct poe_port_kobj *port_kobj, const char *buf,
		     size_t count)
{
	ssize_t		status = -EINVAL;
	struct poe_dev *poe;
	int priority;

	poe = kobj_to_poe_dev(port_kobj->kobj.parent);
	if (!poe->set_priority)
		return status;

	if (sysfs_streq(buf, "critical"))
		priority = PORT_PRIORITY_CRITICAL;
	else if (sysfs_streq(buf, "high"))
		priority = PORT_PRIORITY_HIGH;
	else if (sysfs_streq(buf, "low"))
		priority = PORT_PRIORITY_LOW;
	else
		return status;

	status = poe->set_priority(port_kobj, priority);

	return status ? status : count;
}

static ssize_t
poe_port_show_priority(struct poe_port_kobj *port_kobj, char *buf)
{
	char *str;

	if (port_kobj->priority == PORT_PRIORITY_CRITICAL)
		str = "critical";
	else if (port_kobj->priority == PORT_PRIORITY_HIGH)
		str = "high";
	else if (port_kobj->priority == PORT_PRIORITY_LOW)
		str = "low";
	else
		return -EINVAL;

	return scnprintf(buf, PAGE_SIZE, "%s\n", str);
}
static struct poe_port_attr poe_port_attr_priority = __ATTR(priority, S_IRUGO | S_IWUSR, poe_port_show_priority, poe_port_set_priority);

static ssize_t
poe_port_show_stats(struct poe_port_kobj *port_kobj, char *buf)
{
	struct poe_dev *poe;
        ssize_t status;

	poe = kobj_to_poe_dev(port_kobj->kobj.parent);
        if (poe->port_stats) {
                status = poe->port_stats(port_kobj, PAGE_SIZE, buf);
        } else {
                status = -EINVAL;
        }
        return status;
}

static struct poe_port_attr poe_port_attr_stats = __ATTR(stats, S_IRUGO, poe_port_show_stats, NULL);

static ssize_t
poe_port_show_mode(struct poe_port_kobj *port_kobj, char *buf)
{
	char *str;

	if (port_kobj->mode == PORT_MODE_AF)
		str = "AF";
	else if (port_kobj->mode == PORT_MODE_AT)
		str = "AT";
	else
		return -EINVAL;

	return scnprintf(buf, PAGE_SIZE, "%s\n", str);
}
static struct poe_port_attr poe_port_attr_mode = __ATTR(mode, S_IRUGO, poe_port_show_mode, NULL);

static ssize_t
poe_port_show_millijoules(struct poe_port_kobj *port_kobj, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%llu\n", port_kobj->millijoules);
}
static struct poe_port_attr poe_port_attr_millijoules = __ATTR(millijoules, S_IRUGO, poe_port_show_millijoules, NULL);

POE_PORT_ATTR_SHOW(power);
POE_PORT_ATTR_SHOW(denied);
POE_PORT_ATTR_SHOW(overload);
POE_PORT_ATTR_SHOW(underload);
POE_PORT_ATTR_SHOW(class);
POE_PORT_ATTR_SHOW(status);
POE_PORT_ATTR_SHOW(substatus);

static struct attribute *poe_port_default_attrs[] = {
	&poe_port_attr_enabled.attr,
	&poe_port_attr_priority.attr,
	&poe_port_attr_mode.attr,
	&poe_port_attr_power.attr,
	&poe_port_attr_denied.attr,
	&poe_port_attr_overload.attr,
	&poe_port_attr_underload.attr,
	&poe_port_attr_millijoules.attr,
	&poe_port_attr_class.attr,
	&poe_port_attr_status.attr,
	&poe_port_attr_substatus.attr,
	&poe_port_attr_stats.attr,
	NULL
};

static void poe_free_port_kobj(struct poe_dev *poe, int i)
{
	struct poe_port_kobj *port_kobj = poe->port_kobjs[i];

	sysfs_remove_link(&port_kobj->kobj, "controller");
	sysfs_remove_link(&port_kobj->kobj, "device");
	sysfs_remove_link(&poe->controller_kobjs
			  [i / poe->ports_per_controller]->kobj,
			  port_kobj->port_name_controller);
	sysfs_remove_link(poe->dev.kobj.parent, port_kobj->port_name_system);
	led_trigger_unregister_simple(port_kobj->led_trig);
	kobject_put(&port_kobj->kobj);
	wait_for_completion(&port_kobj->kobj_unregister);
	kfree(port_kobj);
	poe->port_kobjs[i] = NULL;
}

void poe_free_ports(struct poe_dev *poe)
{
	int i;

	for (i = 0; i < poe->ports; i++)
		poe_free_port_kobj(poe, i);
        kobject_put(poe->sysports_kobj);
	kfree(poe->port_kobjs);
	poe->port_kobjs = NULL;
}

static void poe_port_sysfs_release(struct kobject *kobj)
{
	struct poe_port_kobj *port_kobj = kobj_to_port_obj(kobj);

	complete(&port_kobj->kobj_unregister);
}

static struct kobj_type ktype_poe_port = {
	.sysfs_ops = &poe_port_sysfs_ops,
	.default_attrs = poe_port_default_attrs,
	.release = poe_port_sysfs_release,
};

/**
 * poe_register_ports - Register the ports on a PoE device
 *
 * This routine creates sysfs entries for each of the ports
 * on the PoE device.
 */

int poe_register_ports(struct poe_dev *poe)
{
	int i;
	struct poe_port_kobj *port_kobj;
	struct poe_controller_kobj *controller_kobj;
	int ret;

	poe->port_kobjs = kzalloc((sizeof port_kobj) * poe->ports,
				  GFP_KERNEL);
	if (!poe->port_kobjs)
		return -ENOMEM;

	poe->sysports_kobj = kobject_create_and_add("sys_ports", &poe->dev.kobj);
        if (!poe->sysports_kobj) {
		ret = -ENOMEM;
		goto error_state2;
	}

	for (i = 0; i < poe->ports; i++) {
		port_kobj = kzalloc(sizeof(struct poe_port_kobj), GFP_KERNEL);
		if (!port_kobj) {
			ret = -ENOMEM;
			goto error_state;
		}
		port_kobj->port_num = i;
		port_kobj->enabled = auto_power_enable;
		init_completion(&port_kobj->kobj_unregister);
		sprintf(port_kobj->port_name_system, "port%d",
			i + poe->port_base);
		sprintf(port_kobj->port_name_controller, "port%d",
			i % poe->ports_per_controller);
		sprintf(port_kobj->led_trig_name, "port%d:poe",
			i + poe->port_base);
		ret = kobject_init_and_add(&port_kobj->kobj, &ktype_poe_port,
					   &poe->dev.kobj, "port%d", i);
		if (ret) {
			goto error_free;
		}
		ret = sysfs_create_link(poe->sysports_kobj, &port_kobj->kobj,
					port_kobj->port_name_system);
		if (ret)
			goto error_put;

		controller_kobj = poe->controller_kobjs
			[i / poe->ports_per_controller];
		ret = sysfs_create_link(&controller_kobj->kobj,
					&port_kobj->kobj,
					port_kobj->port_name_controller);
		if (ret)
			goto error_sysfs_toplevel_link;
		ret = sysfs_create_link(&port_kobj->kobj,
					&controller_kobj->kobj,
					"controller");
		if (ret)
			goto error_sysfs_controller_port_link;
		ret = sysfs_create_link(&port_kobj->kobj,
					&poe->dev.kobj,
					"device");
		if (ret)
			goto error_sysfs_controller_link;

                led_trigger_register_simple(port_kobj->led_trig_name,
					    &port_kobj->led_trig);
		kobject_uevent(&port_kobj->kobj, KOBJ_ADD);
		poe->port_kobjs[i] = port_kobj;
	}

	return 0;

error_sysfs_controller_link:
	sysfs_remove_link(&port_kobj->kobj, "controller");
error_sysfs_controller_port_link:
	sysfs_remove_link(&controller_kobj->kobj,
			  port_kobj->port_name_controller);
error_sysfs_toplevel_link:
	sysfs_remove_link(poe->dev.kobj.parent, port_kobj->port_name_system);
error_put:
	kobject_put(&port_kobj->kobj);
error_free:
	kfree(port_kobj);
error_state:
	for (i = i - 1; i >=0; i--)
		poe_free_port_kobj(poe, i);
        kobject_put(poe->sysports_kobj);
error_state2:
	kfree(poe->port_kobjs);
	poe->port_kobjs = NULL;
	return ret;
}


void poe_port_notify_state_change(struct kobject* port)
{
	struct poe_port_kobj *port_kobj = kobj_to_port_obj(port);

	if (port_kobj->status == PORT_POWER_ON)
		led_trigger_event(port_kobj->led_trig, LED_FULL);
	else
		led_trigger_event(port_kobj->led_trig, LED_OFF);
}
EXPORT_SYMBOL(poe_port_notify_state_change);
