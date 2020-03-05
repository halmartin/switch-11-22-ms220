/*
 * Cisco Meraki MS350 platform definition file
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
#include <linux/meraki/cisco-mps.h>
#include <linux/i2c/pca954x.h>
#include <linux/platform_data/pca953x.h>
#include <linux/platform_data/leds-lp55xx.h>
#include <linux/leds.h>
#include <linux/gpio.h>
#include <linux/input.h>
#include <linux/gpio_keys.h>
#include <asm/reboot.h>
#include <linux/bcm59121.h>
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <acpi/acpixf.h>
#include <linux/meraki/sfp_user.h>

/* Described on the MS350 schematic */
enum bigpony_board_id {
    BOARD_ID_MS350_48FP = 0,
    BOARD_ID_MS350_48LP = 1,
    BOARD_ID_MS350_48 = 2,
    BOARD_ID_MS350_24P = 3,
    BOARD_ID_MS350_24 = 4,
};

static struct kobject* bigpony_kobj;
static int bigpony_board_id = -1;

#define BIGPONY_SOC_GPIO_BASE 452
#define BIGPONY_SOC_SUS_GPIO_BASE 484
#define BIGPONY_EXT0_GPIO_BASE 100
#define BIGPONY_EXT1_GPIO_BASE 120
#define BIGPONY_EXT2_GPIO_BASE 140

#define BIGPONY_EXT_GPIO_BASE(ext_id) (100 + (20*(ext_id)))

#define BIGPONY_SOC_GPIO(x) (BIGPONY_SOC_GPIO_BASE+(x))
#define BIGPONY_SOC_SUS_GPIO(x) (BIGPONY_SOC_SUS_GPIO_BASE+(x))
#define BIGPONY_EXT_GPIO(ext_id, gpio) (BIGPONY_EXT_GPIO_BASE(ext_id)+(gpio))

/******** meraki_config *******/

#define POE_I2C_ADDRESS 0x20
#define POE_I2C_BUS_NUMBER 1

#define POE_GPIO_DISABLE BIGPONY_SOC_GPIO(25)      /* PoE Disable GPIO pin */
#define POE_GPIO_RESET   BIGPONY_SOC_SUS_GPIO(19)    /* PoE Reset GPIO pin */

static struct at24_platform_data bigpony_config_eeprom_plat_data = {
    .byte_len = 1024,
    .page_size = 8,
    .flags = 0,
    .setup = NULL,
    .context = NULL
};

static struct meraki_config_platform_data bigpony_meraki_config_plat_data = {
    .eeprom_data = &bigpony_config_eeprom_plat_data,
    .write_protect_gpio = BIGPONY_EXT_GPIO(0, 11),
    .write_protect_active_low = true,
};

static struct pca953x_platform_data bigpony_gpiox_plat_data[] = {
    {
        .gpio_base = BIGPONY_EXT_GPIO_BASE(0),
        .irq_base = 0,
    },
    {
        .gpio_base = BIGPONY_EXT_GPIO_BASE(1),
        .irq_base = 0,
    },
    {
        .gpio_base = BIGPONY_EXT_GPIO_BASE(2),
        .irq_base = 0,
    }
};

static struct platform_device bigpony_meraki_config_device = {
    .name = "meraki-config",
    .id = -1,
    .dev = {
        .platform_data = &bigpony_meraki_config_plat_data,
    }
};

/********* Cisco MPS config ********/
static struct cisco_mps_platform_data bigpony_cisco_mps_plat_data[] = {
    {
        .present_pin = BIGPONY_EXT_GPIO(1, 2),
        .power_good_pin = BIGPONY_EXT_GPIO(1, 12),
        .control_i2c_address = 0x5a,
        .data_i2c_address = 0x52,
        .i2c_adapter_id = 10,
    },
    {
        .present_pin = BIGPONY_EXT_GPIO(1, 3),
        .power_good_pin = BIGPONY_EXT_GPIO(1, 13),
        .control_i2c_address = 0x5b,
        .data_i2c_address = 0x53,
        .i2c_adapter_id = 11,
    },
};

static struct platform_device bigpony_cisco_mps_device[] = {
    {
        .name = "cisco-mps",
        .id = 1,
        .dev = {
            .platform_data = &bigpony_cisco_mps_plat_data[0],
        },
    },
    {
        .name = "cisco-mps",
        .id = 2,
        .dev = {
            .platform_data = &bigpony_cisco_mps_plat_data[1],
        },
    },
};
/********* Orange and white power LEDs *********/

static struct gpio_led bigpony_gpio_leds[] = {
    {
        .name = "power:white",
        .gpio = BIGPONY_SOC_SUS_GPIO(17),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "power:orange",
        .gpio = BIGPONY_SOC_GPIO(0),
        .default_state = LEDS_GPIO_DEFSTATE_ON,
    },
    {
        .name = "fan1:orange",
        .gpio = BIGPONY_EXT_GPIO(0, 12),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "fan1:green",
        .gpio = BIGPONY_EXT_GPIO(0, 13),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "fan2:orange",
        .gpio = BIGPONY_EXT_GPIO(0, 14),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
    {
        .name = "fan2:green",
        .gpio = BIGPONY_EXT_GPIO(0, 15),
        .default_state = LEDS_GPIO_DEFSTATE_OFF,
    },
};

static struct gpio_led_platform_data bigpony_gpio_led_plat_data = {
    .num_leds = ARRAY_SIZE(bigpony_gpio_leds),
    .leds = bigpony_gpio_leds,
};

static struct platform_device bigpony_gpio_led_device = {
    .name = "leds-gpio",
    .id = -1,
    .dev = {
        .platform_data = &bigpony_gpio_led_plat_data,
    },
};

/********* Restore button *********/


static struct gpio_keys_button bigpony_gpio_buttons[] = {
    {
        .code = KEY_RESTART,
        .gpio = BIGPONY_SOC_SUS_GPIO(4),
        .active_low = 1,
        .desc = "restore",
        .type = EV_KEY
    },
};

static struct gpio_keys_platform_data bigpony_gpio_keys_plat_data = {
    .buttons = bigpony_gpio_buttons,
    .nbuttons = ARRAY_SIZE(bigpony_gpio_buttons),
    .poll_interval = 60,
    .rep = 1
};

static struct platform_device bigpony_gpio_keys_device = {
    .name = "gpio-keys-polled",
    .id = -1,
    .dev = {
        .platform_data = &bigpony_gpio_keys_plat_data,
    },
};

/********* I2C0 **********/
static struct i2c_board_info bigpony_i2c0_board_info[] = {
    {
        I2C_BOARD_INFO("lm75", 0x48),
    },
    {
        I2C_BOARD_INFO("pca9555", 0x20),
        .platform_data = &bigpony_gpiox_plat_data[0]
    },
    {
        I2C_BOARD_INFO("pca9555", 0x21),
        .platform_data = &bigpony_gpiox_plat_data[1]
    },
    {
        I2C_BOARD_INFO("pca9555", 0x22),
        .platform_data = &bigpony_gpiox_plat_data[2]
    },
    {
        I2C_BOARD_INFO("adt7473", 0x2e),
    },
};

/********* I2C1 *********/
/********* I2C mux (PCA9547) *********/

static struct pca954x_platform_mode bigpony_i2cmux_plat_modes[] = {
        {
            .adap_id = 10,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 11,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 12,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 13,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 14,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 15,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 16,
            .deselect_on_exit = 0,
        },
        {
            .adap_id = 17,
            .deselect_on_exit = 0,
        },
};


static struct pca954x_platform_data bigpony_i2cmux_plat_data = {
    .modes = bigpony_i2cmux_plat_modes,
    .num_modes = ARRAY_SIZE(bigpony_i2cmux_plat_modes),
};

/********* Tri-color LED controller (LP5521) ********/

static struct lp55xx_led_config bigpony_lp5521_channels[] = {
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
};

static struct lp55xx_platform_data bigpony_lp5521_plat_data = {
    .led_config = bigpony_lp5521_channels,
    .num_channels = ARRAY_SIZE(bigpony_lp5521_channels),
    .clock_mode = LP55XX_CLOCK_INT,
    .enable_gpio = -1,
};

struct bigpony_gpe_mapping {
    void* platform_data;
    unsigned int gpio;
};

static struct bigpony_gpe_mapping bigpony_int_map[] = {
    { &bigpony_gpiox_plat_data[0], BIGPONY_SOC_GPIO(5) },
/*** Temporarily (hopefully) disable because of interrupt issues on Clydesdale
    { &bigpony_gpiox_plat_data[1], BIGPONY_SOC_SUS_GPIO(0) },
    { &bigpony_gpiox_plat_data[2], BIGPONY_SOC_SUS_GPIO(7) },
***/
};


static struct i2c_board_info bigpony_i2c1_board_info[] = {
    {
        I2C_BOARD_INFO("24c08", 0x54),
        .platform_data = &bigpony_config_eeprom_plat_data,
    },
    {
        I2C_BOARD_INFO("pca9547", 0x71),
        .platform_data = &bigpony_i2cmux_plat_data
    },
};

#ifndef CONFIG_MERAKI_BIGPONY_MINIMAL_KERNEL
static struct i2c_board_info bigpony_i2c15_board_info[] = {
    {
        I2C_BOARD_INFO("lm75", 0x49),
    },
};

static struct i2c_board_info bigpony_i2c16_board_info[] = {
    {
        I2C_BOARD_INFO("lm75", 0x4a),
    },
};
#endif

static struct i2c_board_info bigpony_i2c17_board_info[] = {
    {
        I2C_BOARD_INFO("lp5521", 0x32),
        .platform_data = &bigpony_lp5521_plat_data,
    }
};

static const struct gpio bigpony_reset_gpios[] = {
    {
        .gpio = BIGPONY_SOC_SUS_GPIO(3),
        .flags = GPIOF_OUT_INIT_HIGH,
        .label = "rst_mac",
    },
    {
        .gpio = BIGPONY_SOC_SUS_GPIO(20),
        .flags = GPIOF_OUT_INIT_HIGH,
        .label = "rst_phy1-3",
    },
    {
        .gpio = BIGPONY_SOC_SUS_GPIO(21),
        .flags = GPIOF_OUT_INIT_HIGH,
        .label = "rst_phy4-6",
    },
    {
        .gpio = BIGPONY_SOC_SUS_GPIO(22),
        .flags = GPIOF_OUT_INIT_HIGH,
        .label = "rst_bcm54616s",
    },
    {
        .gpio = BIGPONY_SOC_SUS_GPIO(27),
        .flags = GPIOF_OUT_INIT_HIGH,
        .label = "rst_phy7",
    },
};

static const struct gpio bigpony_board_id_gpios[] = {
    {
        .gpio = BIGPONY_SOC_GPIO(21),
        .flags = GPIOF_IN,
        .label = "bd_id0",
    },
    {
        .gpio = BIGPONY_SOC_GPIO(22),
        .flags = GPIOF_IN,
        .label = "bd_id1",
    },
    {
        .gpio = BIGPONY_SOC_GPIO(23),
        .flags = GPIOF_IN,
        .label = "bd_id2",
    },
};

static struct sfp_user_platform_data bigpony_sfp_user_plat_data[] = {
    {
        .id = 1,
        .gpios = {
            [SFP_USER_GPIO_MOD_ABS] = BIGPONY_EXT_GPIO(2, 0),
            [SFP_USER_GPIO_RX_LOS] = BIGPONY_EXT_GPIO(2, 1),
        },
        .i2c_adapter_id = -1,
    },
    {
        .id = 2,
        .gpios = {
            [SFP_USER_GPIO_MOD_ABS] = BIGPONY_EXT_GPIO(2, 2),
            [SFP_USER_GPIO_RX_LOS] = BIGPONY_EXT_GPIO(2, 3),
        },
        .i2c_adapter_id = -1,
    },
    {
        .id = 3,
        .gpios = {
            [SFP_USER_GPIO_MOD_ABS] = BIGPONY_EXT_GPIO(2, 4),
            [SFP_USER_GPIO_RX_LOS] = BIGPONY_EXT_GPIO(2, 5),
        },
        .i2c_adapter_id = -1,
    },
    {
        .id = 4,
        .gpios = {
            [SFP_USER_GPIO_MOD_ABS] = BIGPONY_EXT_GPIO(2, 6),
            [SFP_USER_GPIO_RX_LOS] = BIGPONY_EXT_GPIO(2, 7),
        },
        .i2c_adapter_id = -1,
    },
    {
        .id = 5,
        .gpios = {
            [SFP_USER_GPIO_MOD_PRES] = BIGPONY_EXT_GPIO(1, 8),
            [SFP_USER_GPIO_MOD_SEL] = BIGPONY_EXT_GPIO(0, 6),
            [SFP_USER_GPIO_LPMODE] = BIGPONY_EXT_GPIO(0, 7),
        },
        .i2c_adapter_id = 12,
    },
    {
        .id = 6,
        .gpios = {
            [SFP_USER_GPIO_MOD_PRES] = BIGPONY_EXT_GPIO(1, 9),
            [SFP_USER_GPIO_MOD_SEL] = BIGPONY_EXT_GPIO(0, 8),
            [SFP_USER_GPIO_LPMODE] = BIGPONY_EXT_GPIO(0, 9),
        },
        .i2c_adapter_id = 13,
    }
};

static struct platform_device bigpony_sfp_user_plat_devices[] = {
    {
        .name = "sfp-user",
        .id = 1,
        .dev = {
            .platform_data = &bigpony_sfp_user_plat_data[0],
        },
    },
    {
        .name = "sfp-user",
        .id = 2,
        .dev = {
            .platform_data = &bigpony_sfp_user_plat_data[1],
        },
    },
    {
        .name = "sfp-user",
        .id = 3,
        .dev = {
            .platform_data = &bigpony_sfp_user_plat_data[2],
        },
    },
    {
        .name = "sfp-user",
        .id = 4,
        .dev = {
            .platform_data = &bigpony_sfp_user_plat_data[3],
        },
    },
    {
        .name = "sfp-user",
        .id = 5,
        .dev = {
            .platform_data = &bigpony_sfp_user_plat_data[4],
        },
    },
    {
        .name = "sfp-user",
        .id = 6,
        .dev = {
            .platform_data = &bigpony_sfp_user_plat_data[5],
        },
    },
};

/********* Platform device config ********/

static struct platform_device* bigpony_devices[] __initdata = {
    &bigpony_meraki_config_device,
    &bigpony_gpio_led_device,
    &bigpony_gpio_keys_device,
    &bigpony_cisco_mps_device[0],
    &bigpony_cisco_mps_device[1],
    &bigpony_sfp_user_plat_devices[0],
    &bigpony_sfp_user_plat_devices[1],
    &bigpony_sfp_user_plat_devices[2],
    &bigpony_sfp_user_plat_devices[3],
    &bigpony_sfp_user_plat_devices[4],
    &bigpony_sfp_user_plat_devices[5],
};

static unsigned short bigpony_gpe0_sts;
static unsigned short bigpony_gpe0_en;
static struct irq_domain* bigpony_gpe_irq_domain;

/* This is a pretty nasty hack, but we need to use the same lock ACPI uses. */
extern acpi_spinlock acpi_gbl_gpe_lock;

static void bigpony_restart(void)
{
    printk(KERN_NOTICE "bigpony_restart\n");
    gpio_set_value(BIGPONY_SOC_SUS_GPIO(18), 0);
}

static int bigpony_gpio_to_hwirq(int gpio)
{
    if (gpio >= BIGPONY_SOC_SUS_GPIO(0) && gpio <= BIGPONY_SOC_SUS_GPIO(7) &&
        gpio != BIGPONY_SOC_SUS_GPIO(4) && gpio != BIGPONY_SOC_SUS_GPIO(5))
        return (gpio - BIGPONY_SOC_SUS_GPIO_BASE);
    else if (gpio >= BIGPONY_SOC_GPIO(0) && gpio <= BIGPONY_SOC_GPIO(7))
        return (gpio - BIGPONY_SOC_GPIO_BASE + 8);

    return -1;
}

static void bigpony_add_i2c_devices(int busnum, struct i2c_board_info* info,
                                    unsigned count)
{
    int i,j;
    int virq;
    int hwirq;
    struct i2c_adapter* i2c;

    i2c = i2c_get_adapter(busnum);
    if (i2c) {
        for (i = 0; i < count; i++) {
            for (j = 0; j < ARRAY_SIZE(bigpony_int_map); j++) {
                if (info[i].platform_data == bigpony_int_map[j].platform_data) {
                    hwirq = bigpony_gpio_to_hwirq(bigpony_int_map[j].gpio);
                    if (hwirq < 0) {
                        printk(KERN_CRIT "GPIO %d does not have an associated GPE\n", bigpony_int_map[j].gpio);
                        continue;
                    }
                    virq = irq_create_mapping(bigpony_gpe_irq_domain, hwirq);
                    if (virq == 0) {
                        printk(KERN_CRIT "Unable to get virq for hwirq %d, error = %d\n",
                               hwirq, virq);
                    }
                    info[i].irq = virq;
                }
            }
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

static ssize_t board_id_show(struct kobject* kobj,
                             struct kobj_attribute* attr,
                             char* buf)
{
    return snprintf(buf, PAGE_SIZE, "%d\n", bigpony_board_id);
}

static struct kobj_attribute board_id_attr =
    __ATTR(board_id, S_IRUGO, board_id_show, NULL);

static int bigpony_sysfs_init(void)
{
    int ret;

    if (!bigpony_kobj)
        bigpony_kobj = kobject_create_and_add("bigpony", firmware_kobj);
    if (!bigpony_kobj) {
        printk(KERN_WARNING "kobject_create_and_add bigpony failed\n");
        return -EINVAL;
    }

    ret = sysfs_create_file(bigpony_kobj, &board_id_attr.attr);
    if (ret) {
        printk(KERN_WARNING "sysfs_create_file board_id failed\n");
        return ret;
    }

    return 0;
}

static void bigpony_gpe_irq_mask(struct irq_data* data)
{
    acpi_cpu_flags cpuflags;

    cpuflags = acpi_os_acquire_lock(acpi_gbl_gpe_lock);
    outl(inl(bigpony_gpe0_en) & ~(1 << (16 + data->hwirq)), bigpony_gpe0_en);
    acpi_os_release_lock(acpi_gbl_gpe_lock, cpuflags);
}

static void bigpony_gpe_irq_unmask(struct irq_data* data)
{
    acpi_cpu_flags cpuflags;

    cpuflags = acpi_os_acquire_lock(acpi_gbl_gpe_lock);
    outl(inl(bigpony_gpe0_en) | (1 << (16 + data->hwirq)), bigpony_gpe0_en);
    acpi_os_release_lock(acpi_gbl_gpe_lock, cpuflags);
}

static struct irq_chip bigpony_gpe_irq_chip = {
    .name = "bigpony_gpe_irq",
    .irq_mask = bigpony_gpe_irq_mask,
    .irq_unmask = bigpony_gpe_irq_unmask,
};

static int bigpony_gpe_irq_map(struct irq_domain* d, unsigned int virq, irq_hw_number_t hwirq)
{
    if (hwirq > 15)
        return -EINVAL;

    irq_set_chip_and_handler(virq, &bigpony_gpe_irq_chip, handle_simple_irq);

    return 0;
}

static struct irq_domain_ops bigpony_gpe_irq_ops = {
    .map = bigpony_gpe_irq_map,
};

/* The global GPE lock is already being held when this function is called */
static uint32_t bigpony_priority_sci_handler(void* context)
{
    uint32_t gpe0_en;
    uint32_t gpe0_sts;
    int i;
    unsigned int virq;
    uint32_t ret = ACPI_INTERRUPT_NOT_HANDLED;

    gpe0_en = inl(bigpony_gpe0_en);
    gpe0_sts = inl(bigpony_gpe0_sts);

    for (i = 0; i < 16; i++) {
        /* GPEs are in the upper 16 bits */
        uint32_t mask = (1 << (i + 16));

        /* Ignore status if not enabled */
        if (!(gpe0_en & mask))
            continue;

        if (gpe0_sts & mask) {
            virq = irq_linear_revmap(bigpony_gpe_irq_domain, i);
            outl(mask, bigpony_gpe0_sts);
            if (virq > 0)
                generic_handle_irq(virq);
            ret = ACPI_INTERRUPT_HANDLED;
        }
    }

    return ret;
}

static int bigpony_gpe_irq_init(void)
{
    acpi_status status;

    /* GPE hwirqs:
     *
     * 0-7: GPIO_SUS0-7
     * 8-15: GPIOS_0-7
     */
    bigpony_gpe_irq_domain = irq_domain_add_linear(NULL,
                                                   16,
                                                   &bigpony_gpe_irq_ops,
                                                   NULL);

    if (!bigpony_gpe_irq_domain) {
        printk(KERN_CRIT "Unable to allocate bigpony_gpe_irq_domain!\n");
        return -ENOMEM;
    }

    bigpony_gpe0_sts = (unsigned short)acpi_gbl_FADT.xgpe0_block.address;
    bigpony_gpe0_en = (unsigned short)(acpi_gbl_FADT.xgpe0_block.address + 8);

    status = acpi_install_priority_sci_handler(bigpony_priority_sci_handler, NULL);
    if (ACPI_FAILURE(status)) {
        printk(KERN_ERR "bigpony sci handler install failed: %s\n", acpi_format_exception(status));
        return -ENODEV;
    }
    return 0;
};

static int __init bigpony_lateinit(void)
{
    int ret;

    bigpony_gpe_irq_init();
    if ((ret = gpio_request_one(BIGPONY_SOC_SUS_GPIO(18),
                                GPIOF_OPEN_DRAIN | GPIOF_OUT_INIT_HIGH,
                                "master reset signal")) < 0)
        printk(KERN_WARNING "Unable to request master reset GPIO, error = %d\n", ret);
    else
        machine_ops.emergency_restart = bigpony_restart;

    if ((ret = gpio_request_array(bigpony_reset_gpios, ARRAY_SIZE(bigpony_reset_gpios))) < 0)
        printk(KERN_WARNING "Unable to request peripheral reset GPIOs, error = %d\n", ret);

    if ((ret = gpio_request_array(bigpony_board_id_gpios, ARRAY_SIZE(bigpony_board_id_gpios))) < 0) {
        printk(KERN_WARNING "Unable to request board id GPIOs, error = %d\n", ret);
    } else {        int val;
        int i;

        bigpony_board_id = 0;
        for (i = 0; i < ARRAY_SIZE(bigpony_board_id_gpios); i++) {
            val = gpio_get_value(bigpony_board_id_gpios[i].gpio);
            if (val < 0) {
                bigpony_board_id = -1;
                break;
            }
            bigpony_board_id |= (val << i);
        }

        if (bigpony_board_id < 0)
            printk(KERN_WARNING "Unable to read board id gpios!");
    }

    bigpony_sysfs_init();

    bigpony_add_i2c_devices(0, bigpony_i2c0_board_info, ARRAY_SIZE(bigpony_i2c0_board_info));
    bigpony_add_i2c_devices(1, bigpony_i2c1_board_info, ARRAY_SIZE(bigpony_i2c1_board_info));
    platform_add_devices(bigpony_devices, ARRAY_SIZE(bigpony_devices));
#ifndef CONFIG_MERAKI_BIGPONY_MINIMAL_KERNEL
    bigpony_add_i2c_devices(15, bigpony_i2c15_board_info, ARRAY_SIZE(bigpony_i2c15_board_info));
    bigpony_add_i2c_devices(16, bigpony_i2c16_board_info, ARRAY_SIZE(bigpony_i2c16_board_info));
#endif
    bigpony_add_i2c_devices(17, bigpony_i2c17_board_info, ARRAY_SIZE(bigpony_i2c17_board_info));

    printk(KERN_INFO "Cisco Meraki MS350 late init\n");

    return 0;
}
late_initcall(bigpony_lateinit);


MODULE_AUTHOR("Stephen Segal <stsegal@cisco.com>");
MODULE_DESCRIPTION("Cisco Meraki MS350 platform definition");
MODULE_LICENSE("GPL");
