/* cisco-rps.c - a device driver for interfacing with the Cisco RPS 2300     */
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2013 Cisco Systems, Inc.

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

/* Initial driver commit by James C. Parks <jamparks@cisco.com> */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/sysfs.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/meraki/cisco-rps.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/power_supply.h>
#include <linux/slab.h>

#include <asm/atomic.h>

#include "cisco-rps-reg.h"

struct cisco_rps_data {
    /* EEPROMs */
    struct i2c_client *sid_lower_client;
    struct i2c_client *sid_upper_client;
    struct i2c_client *scratch_client;
    struct i2c_client *fpga_client;
    struct power_supply psy;
    /* GPIOs */
    int status_0;
    int status_1;
    /* Debug */
    u8 slave_addr;
    u8 mem_addr;

    /* State for detection, configuration, and initialization */
    u8 current_port;
    atomic_t force_reconfig;
    u32 poll_interval;     /* In milliseconds */
    struct delayed_work work;
    struct mutex lock;
    /* Power in units of mW. These budgets refer to how much 'we' claim
       to need, not how much the RPS 2300 can provide */
    u32 power_budget_poe;    /* -54V */
    u32 power_budget_system; /* 12V */
};

/* Helper functions */

/* This function assumes the RPS 2300 is in a safe state for
   reading */
static int cisco_rps_read(struct i2c_client *client, u8 addr, u8 size, u8 *buf)
{
    int ret;
    struct i2c_msg msg[2];

    msg[0].addr = client->addr;
    msg[0].flags = 0;
    msg[0].buf = &addr;
    msg[0].len = 1;

    msg[1].addr = client->addr;
    msg[1].flags = I2C_M_RD;
    msg[1].buf = buf;
    msg[1].len = size;
    ret = i2c_transfer(client->adapter, msg, 2);
    if (ret < 2)
        return -EIO;

    return size;
}

/* This function assumes that the RPS 2300 is in a safe state for
   writing */
static int cisco_rps_write(struct i2c_client *client, u8 addr, u8 size, const u8 *buf)
{
    int ret;
    struct i2c_msg msg;
    u8 writebuf[17];

    if (size > 16)
        return -EINVAL;

    msg.addr = client->addr;
    msg.flags = 0;
    msg.buf = &writebuf[0];
    msg.len = size + 1;

    writebuf[0] = addr;
    memcpy(&writebuf[1], buf, size);

    ret = i2c_transfer(client->adapter, &msg, 1);
    if (ret < 1)
        return -EIO;

    return size;
}

static int cisco_rps_get_port(const struct cisco_rps_data *data)
{
    int ret;
    u8 port;

    ret = cisco_rps_read(data->sid_lower_client, offsetof(struct cisco_rps_sid_lower_map, power_port_id), 1, &port);
    if (ret < 0)
        return ret;

    /* Only lower 3 bits valid */
    port &= 0x7;

    if (port < 1 || port > 6)
        return -EINVAL;
    return port;
}

static int cisco_rps_connected(const struct cisco_rps_data *data)
{
    if (cisco_rps_get_port(data) < 0)
        return 0;
    return 1;
}

/* Return 1 if an RPS 2300 is connected to us and not off (it is not
   'undervolted'). This essentially translates to "it's safe to
   write" */
static int cisco_rps_active(const struct cisco_rps_data *data)
{
    int ret;
    u8 fault_status;

    if (!cisco_rps_connected(data))
        return 0;
    if (gpio_get_value_cansleep(data->status_0) == 0 &&
        gpio_get_value_cansleep(data->status_1) == 0) {
        ret = cisco_rps_read(data->sid_lower_client, offsetof(struct cisco_rps_sid_lower_map, sid_fault), 1, &fault_status);
        if (ret < 0)
            return 0;
        if (fault_status & 0x3)
            return 0;
    }
    return 1;
}

static int cisco_rps_command_write(struct cisco_rps_data *data, u8 command, u8 size, const u8 *buf)
{
    int port, ret, retries = 5;
    struct i2c_client *upper = data->sid_upper_client;
    struct i2c_client *lower = data->sid_lower_client;

    if (!cisco_rps_active(data))
        return -ENXIO;

    ret = cisco_rps_get_port(data);
    if (ret < 0)
        return ret;

    port = ret;
    mutex_lock(&data->lock);

    ret = cisco_rps_write(upper, offsetof(struct cisco_rps_sid_upper_map, port_command_buf[port - 1]), size, buf);
    if (ret < 0)
        goto out_unlock;

    command &= 0x3F;
    ret = cisco_rps_write(lower, offsetof(struct cisco_rps_sid_lower_map, power_port_control[port - 1]), 1, &command);
    if (ret < 0)
        goto out_unlock;

    do {
        ret = cisco_rps_read(lower, offsetof(struct cisco_rps_sid_lower_map, power_port_control[port - 1]), 1, &command);
        if (ret < 0)
            goto out_unlock;
        if (command & 0x80)     /* Bit automatically set to indicate completion */
            break;
    } while (--retries);

    if (!retries) {
        ret = -EIO;
        goto out_unlock;
    }
    ret = size;
out_unlock:
    mutex_unlock(&data->lock);
    return ret;
}

static int cisco_rps_update_power_class(struct cisco_rps_data *data)
{
    u8 power_class;
    int ret;

    power_class = (((data->power_budget_poe / 100000) + 1) & 0x0F) << 4;
    power_class |= (((data->power_budget_system / 50000) + 1)& 0x0F);
    ret = cisco_rps_command_write(data, CISCO_RPS_CMD_UPDATE_POWER_CLASS, 1, &power_class);

    if (ret < 0)
        return ret;
    return 0;
}

/* SYSFS Interface */

static ssize_t cisco_rps_show_port(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    int port = cisco_rps_get_port(data);
    if (port < 0)
        return port;

    return sprintf(buf, "%d\n", port);
}
static DEVICE_ATTR(port, 0400, cisco_rps_show_port, NULL);

static ssize_t cisco_rps_store_fan_speed(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    int ret;
    u8 speed, command;

    if (strcmp(attr->attr.name, "fan_speed") == 0)
        command = CISCO_RPS_CMD_SET_FAN_SPEED;
    else if (strcmp(attr->attr.name, "fru_fan_speed") == 0)
        command = CISCO_RPS_CMD_SET_FRU_FAN_SPEED;
    else
        return -ENODEV;

    ret = sscanf(buf, "%hhu\n", &speed);
    if (!ret)
        return -EINVAL;

    if (speed > 100)
        speed = 100;

    ret = cisco_rps_command_write(data, command, 1, &speed);
    if (ret < 0)
        return ret;

    return size;
}
static DEVICE_ATTR(fan_speed, 0200, NULL, cisco_rps_store_fan_speed);
static DEVICE_ATTR(fru_fan_speed, 0200, NULL, cisco_rps_store_fan_speed);

static ssize_t cisco_rps_store_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    int ret;
    u8 reset_magic = CISCO_RPS_RESET_MAGIC;

    if (!cisco_rps_active(data))
        return -ENXIO;

    ret = cisco_rps_write(data->fpga_client, offsetof(struct cisco_rps_fpga_map, system_reset), 1, &reset_magic);
    if (ret < 0)
        return ret;

    atomic_xchg(&data->force_reconfig, 1);

    return size;
}
static DEVICE_ATTR(reset, 0200, NULL, cisco_rps_store_reset);

static ssize_t cisco_rps_show_connected(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    return sprintf(buf, "%d\n", cisco_rps_connected(data));
}
static DEVICE_ATTR(connected, 0400, cisco_rps_show_connected, NULL);

static ssize_t cisco_rps_show_active(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    return sprintf(buf, "%d\n", cisco_rps_active(data));
}
static DEVICE_ATTR(active, 0400, cisco_rps_show_active, NULL);

static ssize_t cisco_rps_show_available(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    return sprintf(buf, "%u\n", (unsigned int)(cisco_rps_connected(data) && (gpio_get_value_cansleep(data->status_1) == 1)));
}
static DEVICE_ATTR(available, 0400, cisco_rps_show_available, NULL);

static ssize_t cisco_rps_show_backed_up(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    return sprintf(buf, "%u\n", (unsigned int)(cisco_rps_connected(data) &&
                                               (gpio_get_value_cansleep(data->status_1) == 1) &&
                                               (gpio_get_value_cansleep(data->status_0) == 0)));
}
static DEVICE_ATTR(backed_up, 0400, cisco_rps_show_backed_up, NULL);

static ssize_t cisco_rps_show_debug_address(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);

    return sprintf(buf, "%hhx %hhx\n", data->slave_addr, data->mem_addr);
}

static ssize_t cisco_rps_store_debug_address(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    int ret;
    u8 slave_addr, mem_addr;
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);

    ret = sscanf(buf, "%hhx %hhx\n", &slave_addr, &mem_addr);
    if (ret < 2)
        return -EINVAL;

    data->slave_addr = slave_addr;
    data->mem_addr = mem_addr;
    return size;
}
static DEVICE_ATTR(debug_address, 0600, cisco_rps_show_debug_address, cisco_rps_store_debug_address);

static ssize_t cisco_rps_show_debug_rw(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    struct i2c_client *client;
    u8 val;

    if (data->slave_addr == 0xA8)
        client = data->sid_lower_client;
    else if (data->slave_addr == 0xAA)
        client = data->sid_upper_client;
    else if(data->slave_addr == 0xAE)
        client = data->fpga_client;
    else
        return -ENODEV;

    ret = cisco_rps_read(client, data->mem_addr, 1, &val);
    if (ret < 0)
        return ret;

    return sprintf(buf, "%02hhx\n", val);
}

static ssize_t cisco_rps_store_debug_rw(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    int ret;
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    struct i2c_client *client;
    u8 val;

    if (data->slave_addr == 0xA8)
        client = data->sid_lower_client;
    else if (data->slave_addr == 0xAA)
        client = data->sid_upper_client;
    else if(data->slave_addr == 0xAE)
        client = data->fpga_client;
    else
        return -ENODEV;

    ret = sscanf(buf, "%hhx\n", &val);
    if (ret < 1)
        return -EINVAL;

    ret = cisco_rps_write(client, data->mem_addr, 1, &val);
    if (ret < 0)
        return ret;

    return size;
}
static DEVICE_ATTR(debug_rw, 0600, cisco_rps_show_debug_rw, cisco_rps_store_debug_rw);

static ssize_t cisco_rps_show_poll_interval(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    return sprintf(buf, "%u\n", data->poll_interval);
}

static ssize_t cisco_rps_store_poll_interval(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    int ret;
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    u32 interval;

    ret = sscanf(buf, "%u\n", &interval);
    if (ret < 1)
        return -EINVAL;

    data->poll_interval = interval;
    return size;
}
static DEVICE_ATTR(poll_interval, 0600, cisco_rps_show_poll_interval, cisco_rps_store_poll_interval);

static ssize_t cisco_rps_show_power_budget(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    u32 *power_budget_p;

    if (strcmp(attr->attr.name, "power_budget_poe") == 0)
        power_budget_p = &data->power_budget_poe;
    else if (strcmp(attr->attr.name, "power_budget_system") == 0)
        power_budget_p = &data->power_budget_system;
    else
        return -EINVAL;

    return sprintf(buf, "%u\n", *power_budget_p);
}

static ssize_t cisco_rps_store_power_budget(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    int ret;
    u32 *power_budget_p;

    if (strcmp(attr->attr.name, "power_budget_poe") == 0)
        power_budget_p = &data->power_budget_poe;
    else if (strcmp(attr->attr.name, "power_budget_system") == 0)
        power_budget_p = &data->power_budget_system;
    else
        return -EINVAL;

    ret = sscanf(buf, "%u\n", power_budget_p);
    if (ret < 1)
        return -EINVAL;

    cisco_rps_update_power_class(data);
    return size;
}
static DEVICE_ATTR(power_budget_poe, 0600, cisco_rps_show_power_budget, cisco_rps_store_power_budget);
static DEVICE_ATTR(power_budget_system, 0600, cisco_rps_show_power_budget, cisco_rps_store_power_budget);

/* This tells the RPS 2300 to back off. If our power supply is
   functional, we will become self powered, else the RPS 2300 will
   continue to back us up. The RPS 2300 can only back up devices up to
   its power budget, and it doesn't automatically detect that it is no
   longer needed when our power supply becomes functional again, so
   it's important to cooperatively manage it.
*/
static ssize_t cisco_rps_store_backoff(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    u8 port;
    int ret, status0, status1;

    if (!cisco_rps_active(data))
        return -ENXIO;

    status0 = gpio_get_value_cansleep(data->status_0);
    if (status0 < 0) {
        dev_err(dev, "Could not read status_0 pin\n");
        return status0;
    }

    status1 = gpio_get_value_cansleep(data->status_1);
    if (status1 < 0) {
        dev_err(dev, "Could not read status_1 pin\n");
        return status1;
    }

    if (!((status0 == 0) && (status1 == 1))) {
        dev_warn(dev, "Backoff command requested when not backed-up\n");
    }

    ret = cisco_rps_get_port(data);
    if (ret < 0) {
        dev_err(dev, "Could not get port for backoff\n");
        return ret;
    }

    port = (u8)ret;
    ret = cisco_rps_command_write(data, CISCO_RPS_CMD_BACKOFF, 1, &port);
    if (ret < 0) {
        dev_err(dev, "Backoff command failed\n");
        return ret;
    }

    return size;
}
static DEVICE_ATTR(backoff, 0200, NULL, cisco_rps_store_backoff);

static ssize_t cisco_rps_show_standby(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    int ret, status0, status1;
    u8 fault_status;

    status0 = gpio_get_value_cansleep(data->status_0);
    if (status0 < 0) {
        dev_err(dev, "Could not read status_0 pin\n");
        return status0;
    }

    status1 = gpio_get_value_cansleep(data->status_1);
    if (status1 < 0) {
        dev_err(dev, "Could not read status_1 pin\n");
        return status1;
    }

    /* If either of status0 or status1 is nonzero, then we are in a
       non-standby state */
    if ((status0 != 0) || (status1 != 0)) {
        return sprintf(buf, "0\n");
    }

    ret = cisco_rps_read(data->sid_lower_client, offsetof(struct cisco_rps_sid_lower_map, sid_fault), 1, &fault_status);
    if (ret < 0) {
        return ret;
    }
    if (fault_status) {
        return sprintf(buf, "0\n");
    }

    return sprintf(buf, "1\n");
}

static ssize_t cisco_rps_store_standby(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    u8 port, standby_mode;
    int ret;

    if (!cisco_rps_active(data))
        return -ENXIO;

    ret = cisco_rps_get_port(data);
    if (ret < 0) {
        dev_err(dev, "Could not get port for updating standby\n");
        return ret;
    }
    port = (u8)ret;

    ret = sscanf(buf, "%hhu\n", &standby_mode);
    if (ret < 1 || (standby_mode != 1 && standby_mode != 0))
        return -EINVAL;

    /* The argument we give to the RPS to set the standby state for a
       port is a bitfield F where F[4] is the standby state (1 for
       standby, 0 for not-standby) and F[2:0] (the 3 least-significant
       bits) is the port in question. All other bits are reserved.*/
    standby_mode = (standby_mode << 4) | port;

    ret = cisco_rps_command_write(data, CISCO_RPS_CMD_UPDATE_STANDBY, 1, &standby_mode);
    if (ret < 0) {
        dev_err(dev, "Update standby mode command failed\n");
        return ret;
    }

    return size;
}
static DEVICE_ATTR(standby, 0600, cisco_rps_show_standby, cisco_rps_store_standby);

static ssize_t cisco_rps_show_status_pin(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    int gpio_pin, gpio_val;

    if (strcmp(attr->attr.name, "status0") == 0) {
        gpio_pin = data->status_0;
    } else if (strcmp(attr->attr.name, "status1") == 0) {
        gpio_pin = data->status_1;
    } else {
        return -EINVAL;
    }

    gpio_val = gpio_get_value_cansleep(gpio_pin);
    if (gpio_val < 0) {
        dev_err(dev, "Could not read %s pin\n", attr->attr.name);
        return gpio_val;
    }

    return sprintf(buf, "%d\n", gpio_val);
}
static DEVICE_ATTR(status0, 0400, cisco_rps_show_status_pin, NULL);
static DEVICE_ATTR(status1, 0400, cisco_rps_show_status_pin, NULL);

static ssize_t cisco_rps_show_fault(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_rps_data *data = container_of(dev_get_drvdata(dev), struct cisco_rps_data, psy);
    u8 fault_status;
    int ret;

    ret = cisco_rps_read(data->sid_lower_client, offsetof(struct cisco_rps_sid_lower_map, sid_fault), 1, &fault_status);
    if (ret < 0)
        return ret;

    return sprintf(buf, "%hhu\n", fault_status);
}
static DEVICE_ATTR(fault, 0400, cisco_rps_show_fault, NULL);

static struct device_attribute *cisco_rps_attrs[] = {
    &dev_attr_active,
    &dev_attr_available,
    &dev_attr_backed_up,
    &dev_attr_backoff,
    &dev_attr_connected,
    &dev_attr_debug_address,
    &dev_attr_debug_rw,
    &dev_attr_fan_speed,
    &dev_attr_fault,
    &dev_attr_fru_fan_speed,
    &dev_attr_poll_interval,
    &dev_attr_port,
    &dev_attr_power_budget_poe,
    &dev_attr_power_budget_system,
    &dev_attr_reset,
    &dev_attr_standby,
    &dev_attr_status0,
    &dev_attr_status1,
};

static int cisco_rps_get_property(struct power_supply *psy,
                                  enum power_supply_property psp,
                                  union power_supply_propval *val)
{
    return -ENOSYS;
}

static void cisco_rps_external_power_changed(struct power_supply *psy)
{
    return;
}

static void cisco_rps_set_charged(struct power_supply *psy)
{
    return;
}

static int cisco_rps_init_power_supply(struct platform_device *pdev, struct power_supply *psy)
{
    int ret;

    psy->name = "cisco-rps";
    psy->type = POWER_SUPPLY_TYPE_UPS;
    /* We support very little that integrates with the Power Supply
       core at the moment */
    psy->properties = NULL;
    psy->num_properties = 0;

    psy->supplied_to = NULL;
    psy->supplied_from = NULL;
    psy->num_supplicants = 0;
    psy->num_supplies = 0;
    psy->of_node = NULL;

    psy->get_property = cisco_rps_get_property;
    psy->external_power_changed = cisco_rps_external_power_changed;
    psy->set_charged = cisco_rps_set_charged;

    psy->use_for_apm = 0;

    ret = power_supply_register(&pdev->dev, psy);
    if (ret < 0)
        goto fail_register;

    return 0;

fail_register:
    kfree(psy);
    return ret;
}

static void cisco_rps_do_work(struct work_struct *work)
{
    struct cisco_rps_data *data = container_of(to_delayed_work(work), struct cisco_rps_data, work);
    int ret;
    u8 port, force = 0;

    force = atomic_cmpxchg(&data->force_reconfig, 1, 0);

    ret = cisco_rps_get_port(data);
    if (ret < 0)
        port = 0;
    else
        port = ret;

    if (port != data->current_port || force) {
        /* Only update current_port if we're disconnecting, or
         * connecting *and* we successfully configure the RPS to our
         * power class. If we fail to configure the power class, we
         * leave data->current_port different so we try again later.
         */
        if (!port || !cisco_rps_update_power_class(data)) {
            data->current_port = port;
        }
    }

    schedule_delayed_work(&data->work, msecs_to_jiffies(data->poll_interval));
}

#if IS_ENABLED(CONFIG_OF)
static int cisco_rps_of_init(struct platform_device* pdev)
{
    struct cisco_rps_platform_data* pdata;
    struct device* dev = &pdev->dev;
    struct i2c_client* i2c_node;
    int ret, power;

    pdata = devm_kzalloc(dev, sizeof(struct cisco_rps_platform_data), GFP_KERNEL);
    if (!pdata)
        return -ENOMEM;

    ret = of_property_read_u32(dev->of_node, "max_system_power", &power);
    if (ret < 0)
        power = 0;
    pdata->max_system_power = power;

    ret = of_property_read_u32(dev->of_node, "max_poe_power", &power);
    if (ret < 0)
        power = 0;
    pdata->max_poe_power = power;

    ret = of_get_named_gpio(dev->of_node, "status_0", 0);
    if (ret < 0)
        return ret;
    pdata->status_0 = ret;

    ret = of_get_named_gpio(dev->of_node, "status_1", 0);
    if (ret < 0)
        return ret;
    pdata->status_1 = ret;

    i2c_node = of_parse_phandle(dev->of_node, "i2c", 0);
    if (i2c_node != NULL) {
        struct i2c_adapter* adap = of_find_i2c_adapter_by_node(i2c_node);
        if (adap == NULL) {
            dev_err(dev, "i2c node not an i2c adapter\n");
            return -EINVAL;
        }
        pdata->i2c_adapter = i2c_adapter_id(adap);
        i2c_put_adapter(adap);
    }

    dev->platform_data = pdata;

    return 0;
}
#else
static int cisco_rps_of_init(struct platform_device* pdev)
{
}
#endif

static int cisco_rps_probe(struct platform_device *pdev)
{
    struct cisco_rps_platform_data *pdata;
    struct cisco_rps_data *data;
    struct i2c_adapter *adap;
    int i, ret;

    if (!pdev->dev.platform_data) {
        if (pdev->dev.of_node) {
            ret = cisco_rps_of_init(pdev);
            if (ret < 0) {
                return ret;
            }
        } else {
            dev_err(&pdev->dev, "No config data specified\n");
            return -EINVAL;
        }
    }

    pdata = dev_get_platdata(&pdev->dev);

    if (!pdata)
        return -EINVAL;

    if (pdev->id != -1) {
        printk(KERN_ERR "Cannot have more than one cisco-rps system\n");
        return -EEXIST;
    }

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    adap = i2c_get_adapter(pdata->i2c_adapter);
    if (!adap) {
        ret = -ENODEV;
        goto fail_adap;
    }

    data->sid_lower_client = i2c_new_dummy(adap, CISCO_RPS_SID_LOWER_ADDR);
    data->sid_upper_client = i2c_new_dummy(adap, CISCO_RPS_SID_UPPER_ADDR);
    data->scratch_client   = i2c_new_dummy(adap, CISCO_RPS_SCRATCH_ADDR);
    data->fpga_client      = i2c_new_dummy(adap, CISCO_RPS_FPGA_ADDR);
    if (!data->sid_lower_client ||
        !data->sid_upper_client ||
        !data->scratch_client ||
        !data->fpga_client) {
        ret = -EEXIST;
        goto fail_client;
    }

    if ((ret = gpio_request(pdata->status_0, NULL)) < 0)
        goto fail_status0_pin;
    data->status_0 = pdata->status_0;

    if ((ret = gpio_request(pdata->status_1, NULL)) < 0)
        goto fail_status1_pin;
    data->status_1 = pdata->status_1;

    ret = cisco_rps_init_power_supply(pdev, &data->psy);
    if (ret < 0)
        goto fail_psy;

    for (i = 0; i < ARRAY_SIZE(cisco_rps_attrs); ++i) {
        ret = device_create_file(data->psy.dev, cisco_rps_attrs[i]);
        if (ret < 0)
            goto fail_sysfs;
    }

    INIT_DELAYED_WORK(&data->work, cisco_rps_do_work);
    data->power_budget_system = pdata->max_system_power;
    data->power_budget_poe = pdata->max_poe_power;
    data->poll_interval = 60 * 1000;
    mutex_init(&data->lock);
    platform_set_drvdata(pdev, data);
    i2c_put_adapter(adap);
    dev_info(&pdev->dev, "Cisco RPS 2300 interface established\n");
    cisco_rps_do_work(&data->work.work);
    return 0;

fail_sysfs:
    while (i > 0)
        device_remove_file(data->psy.dev, cisco_rps_attrs[--i]);
    power_supply_unregister(&data->psy);
fail_psy:
    gpio_free(pdata->status_1);
fail_status1_pin:
    gpio_free(pdata->status_0);
fail_status0_pin:
fail_client:
    if (data->sid_lower_client) i2c_unregister_device(data->sid_lower_client);
    if (data->sid_upper_client) i2c_unregister_device(data->sid_upper_client);
    if (data->scratch_client)   i2c_unregister_device(data->scratch_client);
    if (data->fpga_client)      i2c_unregister_device(data->fpga_client);
    i2c_put_adapter(adap);
fail_adap:
    kfree(data);
    return ret;
}

static int cisco_rps_remove(struct platform_device *pdev)
{
    struct cisco_rps_data *data;
    int i = ARRAY_SIZE(cisco_rps_attrs);

    data = platform_get_drvdata(pdev);
    cancel_delayed_work_sync(&data->work);

    while (i > 0)
        device_remove_file(data->psy.dev, cisco_rps_attrs[--i]);

    power_supply_unregister(&data->psy);

    gpio_free(data->status_1);
    gpio_free(data->status_0);

    i2c_unregister_device(data->fpga_client);
    i2c_unregister_device(data->scratch_client);
    i2c_unregister_device(data->sid_upper_client);
    i2c_unregister_device(data->sid_lower_client);

    kfree(data);
    return 0;
}

#if IS_ENABLED(CONFIG_OF)
static const struct of_device_id cisco_rps_dt_match[] = {
    { .compatible = "meraki,cisco-rps", },
    {}
};
MODULE_DEVICE_TABLE(of, cisco_rps_dt_match);
#endif

static struct platform_driver cisco_rps_driver = {
    .driver = {
        .name = "cisco-rps",
        .owner = THIS_MODULE,
#if IS_ENABLED(CONFIG_OF)
        .of_match_table = cisco_rps_dt_match,
#endif
    },
    .probe = cisco_rps_probe,
    .remove = cisco_rps_remove,
};

module_platform_driver(cisco_rps_driver);

MODULE_AUTHOR("J. Chris Parks <jamparks@cisco.com>");
MODULE_DESCRIPTION("Cisco RPS 2300 driver");
MODULE_LICENSE("GPL");
