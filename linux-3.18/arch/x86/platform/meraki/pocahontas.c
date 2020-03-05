/*
 * Cisco Meraki MX84 platform definition file
 *
 * Copyright (C) 2015 Cisco Systems, Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>
#include <linux/platform_data/at24.h>
#include <linux/meraki/meraki_config.h>
#include <linux/platform_data/leds-lp55xx.h>
#include <linux/leds.h>
#include <linux/gpio.h>
#include <linux/input.h>
#include <linux/gpio_keys.h>
#include <linux/dmi.h>
#include <asm/reboot.h>

static struct kobject* pocahontas_kobj;

#define POCAHONTAS_SOC_GPIO_BASE 452
#define POCAHONTAS_SOC_SUS_GPIO_BASE 484

#define POCAHONTAS_SOC_GPIO(x) (POCAHONTAS_SOC_GPIO_BASE+(x))
#define POCAHONTAS_SOC_SUS_GPIO(x) (POCAHONTAS_SOC_SUS_GPIO_BASE+(x))

static struct at24_platform_data pocahontas_config_eeprom_plat_data = {
    .byte_len = 1024,
    .page_size = 16,
    .flags = 0,
    .setup = NULL,
    .context = NULL
};

static struct meraki_config_platform_data pocahontas_meraki_config_plat_data = {
    .eeprom_data = &pocahontas_config_eeprom_plat_data,
    .write_protect_gpio = -1,
};

static struct platform_device pocahontas_meraki_config_device = {
    .name = "meraki-config",
    .id = -1,
    .dev = {
        .platform_data = &pocahontas_meraki_config_plat_data,
    }
};

static struct gpio_led pocahontas_gpio_leds[] = {
    {
        .name = "power:orange",
        .gpio = POCAHONTAS_SOC_GPIO(59),
        .default_state = LEDS_GPIO_DEFSTATE_ON,
        .active_low = 1,
    },
    {
        .name = "ha:green",
        .gpio = POCAHONTAS_SOC_SUS_GPIO(18),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "ha:orange",
        .gpio = POCAHONTAS_SOC_SUS_GPIO(26),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "usb:green",
        .gpio = POCAHONTAS_SOC_SUS_GPIO(7),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "usb:orange",
        .gpio = POCAHONTAS_SOC_SUS_GPIO(8),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
};

static struct gpio_led_platform_data pocahontas_gpio_led_plat_data = {
    .num_leds = ARRAY_SIZE(pocahontas_gpio_leds),
    .leds = pocahontas_gpio_leds,
};

static struct platform_device pocahontas_gpio_led_device = {
    .name = "leds-gpio",
    .id = -1,
    .dev = {
        .platform_data = &pocahontas_gpio_led_plat_data,
    },
};

/********* Restore button *********/
static struct gpio_keys_button pocahontas_gpio_buttons[] = {
    {
        .code = KEY_RESTART,
        .gpio = POCAHONTAS_SOC_GPIO(0),
        .active_low = 1,
        .desc = "restore",
        .type = EV_KEY
    },
};

static struct gpio_keys_platform_data pocahontas_gpio_keys_plat_data = {
    .buttons = pocahontas_gpio_buttons,
    .nbuttons = ARRAY_SIZE(pocahontas_gpio_buttons),
    .poll_interval = 60,
    .rep = 1
};

static struct platform_device pocahontas_gpio_keys_device = {
    .name = "gpio-keys-polled",
    .id = -1,
    .dev = {
        .platform_data = &pocahontas_gpio_keys_plat_data,
    },
};

/********* Platform device config ********/

static struct platform_device* pocahontas_devices[] __initdata = {
    &pocahontas_meraki_config_device,
    &pocahontas_gpio_led_device,
    &pocahontas_gpio_keys_device,
};


/********* I2C1 *********/ /* Board Data Config EEPROM */
static const struct i2c_board_info pocahontas_i2c1_board_info[] = {
    {
        I2C_BOARD_INFO("24c08", 0x54 ),
        .platform_data = &pocahontas_config_eeprom_plat_data,
    },
};

/********* Tri-color LED controller (LP5562) ********/

static struct lp55xx_led_config pocahontas_lp5562_channels[] = {
    {
        .name = "tricolor0:red",
        .chan_nr = 0,
        .led_current = 150,
        .max_current = 255,
    },
    {
        .name = "tricolor0:green",
        .chan_nr = 1,
        .led_current = 150,
        .max_current = 255,
    },
    {
        .name = "tricolor0:blue",
        .chan_nr = 2,
        .led_current = 150,
        .max_current = 255,
    },
    {
        .name = "power:white",
        .chan_nr = 3,
        .led_current = 150,
        .max_current = 225,
    },
};

static struct lp55xx_platform_data pocahontas_lp5562_plat_data = {
    .led_config = pocahontas_lp5562_channels,
    .num_channels = ARRAY_SIZE(pocahontas_lp5562_channels),
    .clock_mode = LP55XX_CLOCK_INT,
    .enable_gpio = -1,
};

static const struct i2c_board_info pocahontas_i2c0_board_info[] = {
    {
        I2C_BOARD_INFO("lp5562", 0x30),
        .platform_data = &pocahontas_lp5562_plat_data,
    },
};


static void pocahontas_restart(void)
{
    printk(KERN_NOTICE "pocahontas_restart\n");
    gpio_set_value(POCAHONTAS_SOC_SUS_GPIO(3), 0);
}

static void pocahontas_add_i2c_devices(int busnum, const struct i2c_board_info* info,
                                    unsigned count)
{
    int i;
    struct i2c_adapter* i2c;

    i2c = i2c_get_adapter(busnum);
    if (i2c) {
        for (i = 0; i < count; i++) {
            if (i2c_new_device(i2c, &info[i]) == NULL) {
                printk(KERN_ERR "i2c_new_device failed (i2c%d, %s, %02X)", busnum,
                       info[i].type, info[i].addr);
            }
        }
        i2c_put_adapter(i2c);
    } else {
        printk(KERN_CRIT "i2c%d not found", busnum);
    }
}

static int pocahontas_sysfs_init(void)
{
    if (!pocahontas_kobj)
        pocahontas_kobj = kobject_create_and_add("pocahontas", firmware_kobj);
    if (!pocahontas_kobj) {
        printk(KERN_WARNING "kobject_create_and_add pocahontas failed\n");
        return -EINVAL;
    }

    return 0;
}

static int __init pocahontas_lateinit(void)
{
    int ret;
    const char *vendor, *product;

    vendor = dmi_get_system_info(DMI_SYS_VENDOR);
    if (!vendor || strcmp(vendor, "Cisco Meraki"))
            goto getout;

    product = dmi_get_system_info(DMI_PRODUCT_NAME);
    if (!product || strcmp(product, "MX84-HW"))
            goto getout;

    if ((ret = gpio_request_one(POCAHONTAS_SOC_SUS_GPIO(3),
                                GPIOF_OPEN_DRAIN | GPIOF_OUT_INIT_HIGH,
                                "master reset signal")) < 0) {
        printk(KERN_WARNING "Unable to request master reset GPIO, error = %d\n", ret);
    } else {
        machine_ops.emergency_restart = pocahontas_restart;
    }

    //pocahontas_sysfs_init();

    pocahontas_add_i2c_devices(0, pocahontas_i2c0_board_info, ARRAY_SIZE(pocahontas_i2c0_board_info));
    pocahontas_add_i2c_devices(1, pocahontas_i2c1_board_info, ARRAY_SIZE(pocahontas_i2c1_board_info));
    platform_add_devices(pocahontas_devices, ARRAY_SIZE(pocahontas_devices));
    printk(KERN_INFO "Cisco Meraki Pocahontas Init\n");

getout:
    return 0;
}
late_initcall(pocahontas_lateinit);


MODULE_AUTHOR("Miles Meraki <miles@meraki.com>");
MODULE_DESCRIPTION("Cisco Meraki MX84 platform definition");
MODULE_LICENSE("GPL");
