/* cisco-mps.c - a device driver for the Cisco FRU for the C2960-XR Series   */
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2013-2015 Cisco Systems, Inc.

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

#include <linux/of_gpio.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/meraki/cisco-mps.h>
#include <linux/gpio.h>
#include <linux/power_supply.h>
#include <linux/slab.h>

#include <asm/page.h>

#include "cisco-mps-reg.h"

struct cisco_mps_data {
    uint16_t present_pin;
    uint16_t power_good_pin;
    struct i2c_client *control_client;
    struct i2c_client *data_client;
    struct power_supply psy;
};

struct cisco_mps_psu_info {
    const char *pid;
    /* In mW */
    const unsigned int poe_budget;
    const unsigned int sys_budget;
    const uint8_t power_class;
} psu_table[] = {
    { "-250WAC", 0, 250000, 0x05 },
    { "-640WAC", 370000, 250000, 0x45 },
    { "-1025WAC", 740000, 250000, 0x85 },
};

static struct cisco_mps_psu_info *cisco_mps_get_psu(const struct cisco_mps_data_eeprom_map *eeprom)
{
    int i;
    uint8_t pid[sizeof(eeprom->fru_ps_id) + 1] = { 0 };

    strncpy(pid, eeprom->fru_ps_id, sizeof(eeprom->fru_ps_id));
    for (i = 0; i < ARRAY_SIZE(psu_table); ++i) {
        if ((strstr(pid, psu_table[i].pid)) &&
            (eeprom->fru_ps_class == psu_table[i].power_class))
            return &psu_table[i];
    }

    return NULL;
}

static int cisco_mps_verify_eeprom(struct cisco_mps_data_eeprom_map *eeprom)
{
    int i;
    uint8_t sum = 0;
    uint8_t zero_check = 0;

    for (i = 0; i < offsetof(struct cisco_mps_data_eeprom_map, fru_csum1); ++i) {
        sum += ((uint8_t *)eeprom)[i];
        zero_check |= ((uint8_t *)eeprom)[i];
    }
    if (zero_check == 0) {
        printk(KERN_ERR "MPS EEPROM empty read");
        return -EINVAL;
    } else if (sum != eeprom->fru_csum1) {
        printk(KERN_ERR "MPS EEPROM bad checksum");
        return -EINVAL;
    }
    return 0;
}

static ssize_t cisco_mps_eeprom_read(struct cisco_mps_data *data, struct cisco_mps_data_eeprom_map *eeprom)
{
    struct i2c_client *client = data->data_client;
    const uint8_t base_addr = 0;
    const int num_retries = 6;
    int i = 0;
    int bytes_read = 0;
    int bytes_remaining = 0;
    int ret = -1;

    while ((bytes_remaining = (sizeof(struct cisco_mps_data_eeprom_map) - bytes_read))) {
        for (i = 0; i < num_retries; ++i) {
            ret = i2c_smbus_read_i2c_block_data(client, base_addr + bytes_read, bytes_remaining > 32 ?
                                                    32 : bytes_remaining, (uint8_t*)eeprom + bytes_read);
            if (ret > 0) {
                bytes_read += ret;
                break;
            }
        }
        if (ret < 0) {
            return ret;
        } else if (ret == 0) {
            break;
        }
    }

    ret = cisco_mps_verify_eeprom(eeprom);
    if (ret < 0) {
        printk(KERN_ERR "Bad EEPROM read on dev %d", client->addr);
        return -ENODEV;
    }

    return sizeof(struct cisco_mps_data_eeprom_map);
}

static ssize_t cisco_mps_show_power_good(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    int gpioval = gpio_get_value_cansleep(data->power_good_pin);
    if (gpioval < 0)
        return gpioval;

    return scnprintf(buf, PAGE_SIZE, "%u\n", (unsigned int)gpioval);
}
static DEVICE_ATTR(power_good, 0444, cisco_mps_show_power_good, NULL);

static ssize_t cisco_mps_show_present(struct device *dev, struct device_attribute *attr, char *buf)
{
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    int gpioval = gpio_get_value_cansleep(data->present_pin);
    if (gpioval < 0)
        return gpioval;

    /* The "present" pin is inverted. 0 means it's there. */
    return scnprintf(buf, PAGE_SIZE, "%u\n", (unsigned int) !gpioval);
}
static DEVICE_ATTR(present, 0444, cisco_mps_show_present, NULL);

static ssize_t cisco_mps_show_fan_duty(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    union i2c_smbus_data smbus;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct i2c_client *client = data->control_client;

    ret = i2c_smbus_xfer(client->adapter, client->addr, 0, I2C_SMBUS_READ, CISCO_MPS_COMMAND_RW_FAN_SPEED_DUTY, I2C_SMBUS_WORD_DATA, &smbus);
    if (ret < 0)
        goto out;

    ret = scnprintf(buf, PAGE_SIZE, "%u\n", smbus.word);
out:
    return ret;
}
static DEVICE_ATTR(fan_duty, S_IRUGO, cisco_mps_show_fan_duty, NULL);

static ssize_t cisco_mps_show_fan_speed_control1(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    union i2c_smbus_data smbus;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct i2c_client *client = data->control_client;

    ret = i2c_smbus_xfer(client->adapter, client->addr, 0, I2C_SMBUS_READ, CISCO_MPS_COMMAND_RW_FAN_SPEED_CONTROL1, I2C_SMBUS_WORD_DATA, &smbus);
    if (ret < 0)
        goto out;

    ret = scnprintf(buf, PAGE_SIZE, "%u\n", smbus.word);
out:
    return ret;
}

static ssize_t cisco_mps_set_fan_speed_control1(struct device *dev, struct device_attribute *attr,
                        const char *buf, size_t count) {
    int ret;
    union i2c_smbus_data smbus;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct i2c_client *client = data->control_client;
    if (kstrtou16(buf, 10, &smbus.word) || smbus.word > 100)
        return -EINVAL;

    ret = i2c_smbus_xfer(client->adapter, client->addr, 0, I2C_SMBUS_WRITE, CISCO_MPS_COMMAND_RW_FAN_SPEED_CONTROL1, I2C_SMBUS_WORD_DATA, &smbus);
    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(fan_speed_control1, S_IRUGO | S_IWUSR, cisco_mps_show_fan_speed_control1, cisco_mps_set_fan_speed_control1);

static ssize_t cisco_mps_show_fan_speed_control2(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    union i2c_smbus_data smbus;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct i2c_client *client = data->control_client;

    ret = i2c_smbus_xfer(client->adapter, client->addr, 0, I2C_SMBUS_READ, CISCO_MPS_COMMAND_RW_FAN_SPEED_CONTROL2, I2C_SMBUS_WORD_DATA, &smbus);
    if (ret < 0)
        goto out;

    ret = scnprintf(buf, PAGE_SIZE, "%u\n", smbus.word);
out:
    return ret;
}

static ssize_t cisco_mps_set_fan_speed_control2(struct device *dev, struct device_attribute *attr,
                        const char *buf, size_t count) {
    int ret;
    union i2c_smbus_data smbus;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct i2c_client *client = data->control_client;
    if (kstrtou16(buf, 10, &smbus.word) || smbus.word > 100)
        return -EINVAL;

    ret = i2c_smbus_xfer(client->adapter, client->addr, 0, I2C_SMBUS_WRITE, CISCO_MPS_COMMAND_RW_FAN_SPEED_CONTROL2, I2C_SMBUS_WORD_DATA, &smbus);
    if (ret < 0)
        return ret;

    return count;
}
static DEVICE_ATTR(fan_speed_control2, S_IRUGO | S_IWUSR, cisco_mps_show_fan_speed_control2, cisco_mps_set_fan_speed_control2);

static ssize_t cisco_mps_show_fan_speed(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    union i2c_smbus_data smbus;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct i2c_client *client = data->control_client;

    ret = i2c_smbus_xfer(client->adapter, client->addr, 0, I2C_SMBUS_READ, CISCO_MPS_COMMAND_R_FAN_SPEED, I2C_SMBUS_WORD_DATA, &smbus);
    if (ret < 0)
        goto out;

    ret = scnprintf(buf, PAGE_SIZE, "%u\n", smbus.word);
out:
    return ret;
}
static DEVICE_ATTR(fan_speed, 0444, cisco_mps_show_fan_speed, NULL);

static ssize_t cisco_mps_show_power_budget(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct cisco_mps_data_eeprom_map eeprom;
    uint32_t power_budget;
    struct cisco_mps_psu_info *info;

    ret = cisco_mps_eeprom_read(data, &eeprom);
    if (ret < 0)
        return ret;

    /* fru_ps_class[7:4] is for -54V, fru_ps_class[3:0] is for 12V  */
    info = cisco_mps_get_psu(&eeprom);
    if (!info)
        power_budget = 0;
    else if (strcmp(attr->attr.name, "power_budget_poe") == 0)
        power_budget = info->poe_budget;
    else if (strcmp(attr->attr.name, "power_budget_system") == 0)
        power_budget = info->sys_budget;
    else
        return -ENODEV;

    return scnprintf(buf, PAGE_SIZE, "%u\n", (uint32_t)power_budget);
}
static DEVICE_ATTR(power_budget_poe, 0444, cisco_mps_show_power_budget, NULL);
static DEVICE_ATTR(power_budget_system, 0444, cisco_mps_show_power_budget, NULL);

static ssize_t cisco_mps_show_serial(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct cisco_mps_data_eeprom_map eeprom;
    const uint8_t serial_len = ARRAY_SIZE(((struct cisco_mps_data_eeprom_map *)NULL)->fru_ps_serial);

    if (PAGE_SIZE < serial_len + 2)
        return -EINVAL;

    ret = cisco_mps_eeprom_read(data, &eeprom);
    if (ret < 0)
        return ret;

    memcpy(buf, &eeprom.fru_ps_serial, serial_len);
    buf[serial_len] = '\n';
    buf[serial_len + 1] = 0;
    return serial_len + 1;
}
static DEVICE_ATTR(serial, 0444, cisco_mps_show_serial, NULL);

static ssize_t cisco_mps_show_product_id(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct cisco_mps_data_eeprom_map eeprom;
    const uint8_t pid_len = ARRAY_SIZE(((struct cisco_mps_data_eeprom_map *)NULL)->fru_ps_id);

    if (PAGE_SIZE < pid_len + 2)
        return -EINVAL;

    ret = cisco_mps_eeprom_read(data, &eeprom);
    if (ret < 0)
        return ret;

    memcpy(buf, &eeprom.fru_ps_id, pid_len);
    buf[pid_len] = '\n';
    buf[pid_len + 1] = 0;
    return pid_len + 1;
}
static DEVICE_ATTR(product_id, 0444, cisco_mps_show_product_id, NULL);

static ssize_t cisco_mps_show_top_assembly_number(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    struct cisco_mps_data_eeprom_map eeprom;
    const uint8_t tan_len = ARRAY_SIZE(((struct cisco_mps_data_eeprom_map *)NULL)->fru_ps_tan);

    if (PAGE_SIZE < tan_len + 2) {
        return -EINVAL;
    }

    ret = cisco_mps_eeprom_read(data, &eeprom);
    if (ret < 0) {
        return ret;
    }

    memcpy(buf, &eeprom.fru_ps_tan, tan_len);
    buf[tan_len] = '\n';
    buf[tan_len + 1] = 0;
    return tan_len + 1;
}
static DEVICE_ATTR(top_assembly_number, 0444, cisco_mps_show_top_assembly_number, NULL);

static ssize_t cisco_mps_show_eeprom(struct device *dev, struct device_attribute *attr, char *buf)
{
    int ret;
    struct cisco_mps_data *data = container_of(dev_get_drvdata(dev), struct cisco_mps_data, psy);
    const uint16_t eeprom_len = sizeof(struct cisco_mps_data_eeprom_map);

    if (PAGE_SIZE < eeprom_len + 1)
        return -EINVAL;

    ret = cisco_mps_eeprom_read(data, (struct cisco_mps_data_eeprom_map *)buf);
    if (ret < 0)
        return ret;

    buf[eeprom_len] = 0;
    return eeprom_len;
}
static DEVICE_ATTR(eeprom, 0444, cisco_mps_show_eeprom, NULL);

static struct device_attribute *cisco_mps_attrs[] = {
    &dev_attr_present,
    &dev_attr_power_good,
    &dev_attr_fan_speed,
    &dev_attr_fan_duty,
    &dev_attr_fan_speed_control1,
    &dev_attr_fan_speed_control2,
    &dev_attr_power_budget_poe,
    &dev_attr_power_budget_system,
    &dev_attr_serial,
    &dev_attr_product_id,
    &dev_attr_top_assembly_number,
    &dev_attr_eeprom,
};

static int cisco_mps_get_property(struct power_supply *psy,
                                  enum power_supply_property psp,
                                  union power_supply_propval *val)
{
    return -ENOSYS;
}

static void cisco_mps_external_power_changed(struct power_supply *psy)
{
    return;
}

static void cisco_mps_set_charged(struct power_supply *psy)
{
    return;
}

static int cisco_mps_make_sysfs_nodes(struct device *dev)
{
    int ret, i;

    for (i = 0; i < ARRAY_SIZE(cisco_mps_attrs); ++i) {
        ret = device_create_file(dev, cisco_mps_attrs[i]);
        if (ret < 0)
            goto fail;
    }
    return 0;

fail:
    while (i > 0)
        device_remove_file(dev, cisco_mps_attrs[--i]);
    return ret;
}

static void cisco_mps_unmake_sysfs_nodes(struct device *dev)
{
    int i = ARRAY_SIZE(cisco_mps_attrs);
    while (i > 0)
        device_remove_file(dev, cisco_mps_attrs[--i]);
}

static int cisco_mps_init_power_supply(struct platform_device *pdev, struct power_supply *psy)
{
    int ret = -ENOMEM;

    psy->name = kzalloc(sizeof(char) * 20, GFP_KERNEL);
    if (!psy->name)
        goto fail_name;

    sprintf((char *)psy->name, "cisco-mps.%u", (unsigned int)pdev->id);
    psy->type = POWER_SUPPLY_TYPE_MAINS;
    /* We support very little that integrates with the Power Supply core at the moment */
    psy->properties = NULL;
    psy->num_properties = 0;

    psy->supplied_to = NULL;
    psy->num_supplicants = 0;

    psy->supplied_from = NULL;
    psy->num_supplies = 0;
    psy->of_node = NULL;

    psy->get_property = cisco_mps_get_property;
    psy->external_power_changed = cisco_mps_external_power_changed;
    psy->set_charged = cisco_mps_set_charged;

    psy->use_for_apm = 0;

    ret = power_supply_register(&pdev->dev, psy);
    if (ret < 0)
        goto fail_register;

    return 0;

fail_register:
    kfree(psy->name);
fail_name:
    return ret;
}

static void cisco_mps_destroy_power_supply(struct power_supply *psy)
{
    power_supply_unregister(psy);
    kfree(psy->name);
}

#if IS_ENABLED(CONFIG_OF)
static int cisco_mps_of_init(struct platform_device* pdev)
{
    struct cisco_mps_platform_data* pdata;
    struct device* dev = &pdev->dev;
    struct resource* res;
    struct i2c_client* i2c_node;
    int ret;

    pdata = devm_kzalloc(dev, sizeof(struct cisco_mps_platform_data), GFP_KERNEL);
    if (!pdata)
        return -ENOMEM;

    ret = of_property_read_u32(dev->of_node, "id", &pdev->id);
    if (ret < 0)
        return ret;

    ret = of_get_named_gpio(dev->of_node, "present", 0);
    if (ret < 0)
        return ret;
    pdata->present_pin = ret;

    ret = of_get_named_gpio(dev->of_node, "power_good", 0);
    if (ret < 0)
        return ret;
    pdata->power_good_pin = ret;

    res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "control-i2c");
    if (!res)
        return -EINVAL;
    pdata->control_i2c_address = res->start;

    res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "data-i2c");
    if (!res)
        return -EINVAL;
    pdata->data_i2c_address = res->start;

    pdata->i2c_adapter_id = -1;

    i2c_node = of_parse_phandle(dev->of_node, "i2c", 0);
    if (i2c_node != NULL) {
        struct i2c_adapter* adap = of_find_i2c_adapter_by_node(i2c_node);
        if (adap == NULL) {
            dev_err(dev, "i2c node not an i2c adapter\n");
            return -EINVAL;
        }
        pdata->i2c_adapter_id = i2c_adapter_id(adap);
        i2c_put_adapter(adap);
    }

    dev->platform_data = pdata;

    return 0;
}
#else
static inline int cisco_mps_of_init(struct platform_device* pdev)
{
    return -EINVAL;
}
#endif

static int cisco_mps_probe(struct platform_device *dev)
{
    struct cisco_mps_platform_data *pdata;
    struct cisco_mps_data *data;
    struct i2c_adapter *adap;
    struct i2c_client *client;
    int ret;

    if (!dev->dev.platform_data) {
        if (dev->dev.of_node) {
            ret = cisco_mps_of_init(dev);
            if (ret < 0) {
                return ret;
            }
        } else {
            dev_err(&dev->dev, "No config data specified!\n");
            return -EINVAL;
        }
    }

    pdata = dev_get_platdata(&dev->dev);

    if (!pdata)
        return -ENODEV;

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    ret = gpio_request(pdata->present_pin, "present");
    if (ret < 0)
        goto fail_present;
    data->present_pin = pdata->present_pin;
    gpio_direction_input(data->present_pin);

    ret = gpio_request(pdata->power_good_pin, "power_good");
    if (ret < 0)
        goto fail_power;
    data->power_good_pin = pdata->power_good_pin;
    gpio_direction_input(data->power_good_pin);

    adap = i2c_get_adapter(pdata->i2c_adapter_id);
    if (!adap) {
        ret = -ENOSYS;
        goto fail_adap;
    }

    client = i2c_new_dummy(adap, pdata->control_i2c_address);
    if (!client) {
        ret = -ENXIO;
        goto fail_control_client;
    }
    data->control_client = client;

    client = i2c_new_dummy(adap, pdata->data_i2c_address);
    if (!client) {
        ret = -ENXIO;
        goto fail_data_client;
    }
    data->data_client = client;

    ret = cisco_mps_init_power_supply(dev, &data->psy);
    if (ret < 0)
        goto fail_psy;

    ret = cisco_mps_make_sysfs_nodes(data->psy.dev);
    if (ret < 0)
        goto fail_sysfs;

    i2c_put_adapter(adap);
    dev_set_drvdata(&dev->dev, data);
    return 0;

fail_sysfs:
    cisco_mps_destroy_power_supply(&data->psy);
fail_psy:
    i2c_unregister_device(data->data_client);
fail_data_client:
    i2c_unregister_device(data->control_client);
fail_control_client:
    i2c_put_adapter(adap);
fail_adap:
    gpio_free(pdata->power_good_pin);
fail_power:
    gpio_free(pdata->present_pin);
fail_present:
    kfree(data);
    return ret;
}

static int cisco_mps_remove(struct platform_device *dev)
{
    struct cisco_mps_data *data = dev_get_drvdata(&dev->dev);

    dev_set_drvdata(&dev->dev, NULL);

    cisco_mps_unmake_sysfs_nodes(&dev->dev);
    cisco_mps_destroy_power_supply(&data->psy);

    i2c_unregister_device(data->data_client);
    i2c_unregister_device(data->control_client);

    gpio_free(data->present_pin);
    gpio_free(data->power_good_pin);

    kfree(data);

    return 0;
}

#if IS_ENABLED(CONFIG_OF)
static const struct of_device_id cisco_mps_dt_match[] = {
    { .compatible = "meraki,cisco-mps", },
    {}
};
MODULE_DEVICE_TABLE(of, cisco_mps_dt_match);
#endif

static struct platform_driver cisco_mps_driver = {
	.driver = {
		.name = "cisco-mps",
		.owner = THIS_MODULE,
#if IS_ENABLED(CONFIG_OF)
		.of_match_table = cisco_mps_dt_match,
#endif
	},
	.probe = cisco_mps_probe,
	.remove = cisco_mps_remove,
};

module_platform_driver(cisco_mps_driver);

MODULE_AUTHOR("James C. Parks <jamparks@cisco.com>");
MODULE_DESCRIPTION("Device driver for FRU for C2960-XR Series");
MODULE_LICENSE("GPL");
