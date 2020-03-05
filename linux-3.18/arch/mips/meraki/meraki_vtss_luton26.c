/*
 *
 * Meraki board definition proxy for Vitesse 742x-based products.
 *
 * Copyright (c) 2013 Meraki, Inc.
 * Author: Stephen Segal (ssegal@meraki.com)
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
 */

#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/i2c-gpio.h>
#include <linux/i2c.h>
#include <linux/platform_data/at24.h>

#define SUPPORT_VTSS_VCOREIII_LUTON26

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

#include "ms22_ms220-24.h"
#include "ms220-8.h"
#include <linux/meraki/meraki_config.h>

static struct at24_platform_data luton26_config_eeprom_plat_data = {
    .byte_len = 1024,
    .page_size = 8,
    .flags = AT24_FLAG_ADDR16,
    .setup = NULL,
    .context = NULL
};

static struct i2c_gpio_platform_data luton26_config_i2c_controller_data = {
    .sda_pin = VCOREIII_GPIO_BASE + 10,
    .scl_pin = VCOREIII_GPIO_BASE + 11,
    .udelay = 10,
};

static struct meraki_config_platform_data luton26_config_platform_data = {
    .eeprom_data = &luton26_config_eeprom_plat_data,
    .write_protect_gpio = -1,
};

static struct i2c_board_info luton26_config_eeprom_board_info = {
    I2C_BOARD_INFO("24c08", 0x51),
    .platform_data = &luton26_config_eeprom_plat_data,
};

enum {
    PRODUCT_UNDETERMINED = -1,
    PRODUCT_UNKNOWN = 0,
    PRODUCT_MS22_MS220_24,
    PRODUCT_MS220_8,
};

static int __init determine_product(void)
{
    static int product = PRODUCT_UNDETERMINED;

    if (product == PRODUCT_UNDETERMINED) {
        switch (vcoreiii_get_chip_id()) {
        case 0x7427:
            product = PRODUCT_MS22_MS220_24;
            printk(KERN_INFO "Meraki MS22 or MS220-24 board detected\n");
            break;
        case 0x7425:
            product = PRODUCT_MS220_8;
            printk(KERN_INFO "Meraki MS220-8 board detected\n");
            break;
        default:
            product = PRODUCT_UNKNOWN;
            break;
        }
    }

    return product;
}

static int is_i2c_adapter(struct device* dev, void* data)
{
    return (dev->type == &i2c_adapter_type);
}

static struct i2c_adapter* i2c_adapter_from_platform_device(struct platform_device* pdev)
{
    struct device* dev = device_find_child(&pdev->dev, NULL, is_i2c_adapter);

    return (dev ? i2c_verify_adapter(dev) : NULL);
}

static int __init meraki_vtss_luton26_late_init(void)
{
    int product, ret;
    struct platform_device *adapter_dev, *eeprom_dev;
    struct i2c_adapter* i2c_adapt;
    struct i2c_client* i2c_client;

    if (!vcoreiii_check_chip_id())
        return -ENODEV;

    product = determine_product();
    if (product == PRODUCT_MS220_8)
        return meraki_ms220_8_late_init();

    /* Set up our I2C adapter */
    adapter_dev = platform_device_alloc("i2c-gpio", 1);
    if (!adapter_dev)
        return -ENOMEM;

    ret = platform_device_add_data(adapter_dev, &luton26_config_i2c_controller_data, sizeof(luton26_config_i2c_controller_data));
    if (ret < 0)
        goto fail_adapter;

    ret = platform_device_add(adapter_dev);
    if (ret < 0)
        goto fail_adapter;

    /* Set up the eeprom device */
    i2c_adapt = i2c_get_adapter(1);
    if (i2c_adapt == NULL) {
        ret = -ENODEV;
        goto fail_i2c;
    }

    i2c_client = i2c_new_device(i2c_adapt, &luton26_config_eeprom_board_info);
    if (i2c_client == NULL) {
        ret = -ENODEV;
        goto fail_i2c;
    }

    eeprom_dev = platform_device_alloc("meraki-config", -1);
    if (!eeprom_dev) {
        ret = -ENOMEM;
        goto fail_eeprom;
    }

    ret = platform_device_add_data(eeprom_dev, &luton26_config_platform_data, sizeof(luton26_config_platform_data));
    if (ret < 0) {
        platform_device_put(eeprom_dev);
        goto fail_eeprom;
    }

    ret = platform_device_add(eeprom_dev);
    if (!ret) {
        /* Try to use the EEPROM if we have one */
        switch (meraki_config_get_product()) {
        case MERAKI_BOARD_MS220_24P:
        case MERAKI_BOARD_MS220_24:
            return meraki_ms220_24_late_init();
        default:
            platform_device_del(eeprom_dev);
            break;
        }
    }

    platform_device_put(eeprom_dev);

    if (product == PRODUCT_MS22_MS220_24) {
        return meraki_ms22_late_init();
    }

    ret = -ENODEV;

fail_eeprom:
    i2c_unregister_device(i2c_client);
fail_i2c:
    platform_device_del(adapter_dev);
fail_adapter:
    platform_device_put(adapter_dev);
    return ret;
}

late_initcall(meraki_vtss_luton26_late_init);
