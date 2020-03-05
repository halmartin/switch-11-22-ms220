/*
 *
 * Meraki MS-320-48 board definitions
 *
 * Copyright (c) 2013 Meraki, Inc.
 * Author: James Chris Parks (james.parks@meraki.com)
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
 * This is the board-specific code for the Meraki MS320-48(LP|FP) switches.
 */

#include <linux/kernel.h>

#include <linux/i2c.h>
#include <linux/i2c-gpio.h>
#include <linux/platform_device.h>
#include <linux/platform_data/at24.h>
#include <linux/pd690xx.h>
#include <linux/thermal_gpio.h>
#include <linux/delay.h>
#include <asm/reboot.h>
#include <asm/idle.h>
#include <linux/platform_data/pca953x.h>
#include <linux/meraki/cisco-mps.h>

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/mach-vcoreiii/phy8512_gpio.h>
#include <asm/mach-vcoreiii/phy8488_gpio.h>

static struct i2c_gpio_platform_data ms320_48_i2c_sfp_gpio_pins[4] = {
	{
		.sda_pin	= VCOREIII_GPIO_PHY_8488_BASE(0) + 4,
		.scl_pin	= VCOREIII_GPIO_PHY_8488_BASE(0) + 5,
		.udelay		= 10,
	},
	{
		.sda_pin	= VCOREIII_GPIO_PHY_8488_BASE(0) + 10,
		.scl_pin	= VCOREIII_GPIO_PHY_8488_BASE(0) + 11,
		.udelay		= 10,
	},
	{
		.sda_pin	= VCOREIII_GPIO_PHY_8488_BASE(1) + 4,
		.scl_pin	= VCOREIII_GPIO_PHY_8488_BASE(1) + 5,
		.udelay		= 10,
	},
	{
		.sda_pin	= VCOREIII_GPIO_PHY_8488_BASE(1) + 10,
		.scl_pin	= VCOREIII_GPIO_PHY_8488_BASE(1) + 11,
		.udelay		= 10,
	},
};

static struct i2c_gpio_platform_data ms320_48_i2c_power_gpio_pins[] = {
    /* connected to external I2C-to-GPIO chip, plus temperature sensors */
    {
        .sda_pin = VCOREIII_GPIO_BASE_SLV + 15,
        .scl_pin = VCOREIII_GPIO_BASE_SLV + 14,
        .udelay = 10,
    },
    /* connected to modular power supply A */
    {
        .sda_pin = VCOREIII_GPIO_BASE_SLV + 19,
        .scl_pin = VCOREIII_GPIO_BASE_SLV + 18,
        .udelay = 10,
    },
    /* connected to modular power supply B */
    {
        .sda_pin = VCOREIII_GPIO_BASE_SLV + 21,
        .scl_pin = VCOREIII_GPIO_BASE_SLV + 20,
        .udelay = 10,
    },
};
static const char *expander_pin_names[] = {
    "power_good_a",
    "off_a",
    "ps_p_a",
    "smb_a",
    "soc_a",

    "tca5",
    "tca6",
    "tca7",

    "power_good_b",
    "off_b",
    "ps_p_b",
    "smb_b",
    "soc_b",

    "tca15",
    "tca16",
    "tca17",

    "tca20",
    "tca21",
    "tca22",
    "tca23",
    "tca24",
    "tca25",
    "tca26",
    "tca27",
    NULL,
};

static struct pca953x_platform_data ms320_48_gpio_expander_data = {
	.gpio_base = VCOREIII_GPIO_TCA6424A_GPIO_BASE,
	.invert = 0,
        .context = NULL,
	.setup = NULL,
	.teardown = NULL,
	.names = (const char **)expander_pin_names,
};

static struct i2c_board_info power_i2c_board_info[] = {
    {
        I2C_BOARD_INFO("tca6424", 0x22),
        .platform_data = &ms320_48_gpio_expander_data,
    },
};

struct memory_accessor *ms320_48_sfp_eeprom_mems[4];
EXPORT_SYMBOL(ms320_48_sfp_eeprom_mems);

static void ms320_48_sfp_eeprom_setup(struct memory_accessor *ma, void *context)
{
	*((struct memory_accessor **)context) = ma;
}

static struct at24_platform_data ms320_48_sfp_eeprom_plat_data[4] = {
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_48_sfp_eeprom_setup,
		.context = &ms320_48_sfp_eeprom_mems[0],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_48_sfp_eeprom_setup,
		.context = &ms320_48_sfp_eeprom_mems[1],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_48_sfp_eeprom_setup,
		.context = &ms320_48_sfp_eeprom_mems[2],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_48_sfp_eeprom_setup,
		.context = &ms320_48_sfp_eeprom_mems[3],
	},
};

static struct platform_device ms320_48_sfp_gpio_i2c_controller[4] = {
	{
		.name	= "i2c-gpio",
		.id	= 2,
		.dev = {
			.platform_data = &ms320_48_i2c_sfp_gpio_pins[0],
		},
		.num_resources = 0,
	},
	{
		.name	= "i2c-gpio",
		.id	= 3,
		.dev = {
			.platform_data = &ms320_48_i2c_sfp_gpio_pins[1],
		},
		.num_resources = 0,
	},
	{
		.name	= "i2c-gpio",
		.id	= 4,
		.dev = {
			.platform_data = &ms320_48_i2c_sfp_gpio_pins[2],
		},
		.num_resources = 0,
	},
	{
		.name	= "i2c-gpio",
		.id	= 5,
		.dev = {
			.platform_data = &ms320_48_i2c_sfp_gpio_pins[3],
		},
		.num_resources = 0,
	},
};

static struct platform_device ms320_48_power_gpio_i2c_controller[] = {
    {
        .name = "i2c-gpio",
        .id = 6,
        .dev = {
            .platform_data = &ms320_48_i2c_power_gpio_pins[0],
        },
        .num_resources = 0,
    },
    {
        .name = "i2c-gpio",
        .id = 7,
        .dev = {
            .platform_data = &ms320_48_i2c_power_gpio_pins[1],
        },
        .num_resources = 0,
    },
    {
        .name = "i2c-gpio",
        .id = 8,
        .dev = {
            .platform_data = &ms320_48_i2c_power_gpio_pins[2],
       },
        .num_resources = 0,
    },
};

static struct cisco_mps_platform_data ms320_48_mps_data[] = {
    {
        .present_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 10,
        .power_good_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 8,
        .control_i2c_address = 0x5b,
        .data_i2c_address = 0x53,
        .i2c_adapter_id = 8,
    },
    {
        .present_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 2,
        .power_good_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 0,
        .control_i2c_address = 0x5a,
        .data_i2c_address = 0x52,
        .i2c_adapter_id = 7,
    },
};

static struct platform_device ms320_48_mps_device[] = {
    {
        .name = "cisco-mps",
        .id = 1,
        .dev = {
            .platform_data = &ms320_48_mps_data[0],
        },
        .num_resources = 0,
    },
    {
        .name = "cisco-mps",
        .id = 2,
        .dev = {
            .platform_data = &ms320_48_mps_data[1],
        },
        .num_resources = 0,
    },
};

static const struct i2c_board_info sfp_i2c_board_info[4] = {
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_48_sfp_eeprom_plat_data[0],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_48_sfp_eeprom_plat_data[1],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_48_sfp_eeprom_plat_data[2],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_48_sfp_eeprom_plat_data[3],
	},
};

static struct phy8488_gpio_chip ms320_48_phy8488_gpio[] = {
	{
		.gpio_chip = {
			.label = "phy8488-gpio0",
			.get = jaguar_phy8488_gpio_get_value,
			.set = jaguar_phy8488_gpio_set_value,
			.direction_input = jaguar_phy8488_gpio_direction_input,
			.direction_output = jaguar_phy8488_gpio_direction_output,
			.to_irq = jaguar_phy8488_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_8488_BASE(0),
			.ngpio = 12,
			.can_sleep = 1,
		},
		.inst = 1,
		.port_base = 30,
	},
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	{
		.gpio_chip = {
			.label = "phy8488-gpio1",
			.get = jaguar_slv_phy8488_gpio_get_value,
			.set = jaguar_slv_phy8488_gpio_set_value,
			.direction_input = jaguar_slv_phy8488_gpio_direction_input,
			.direction_output = jaguar_slv_phy8488_gpio_direction_output,
			.to_irq = jaguar_slv_phy8488_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_8488_BASE(1),
			.ngpio = 12,
			.can_sleep = 1,
		},
		.inst = 1,
		.port_base = 30,
	},
};
#endif

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO

static struct phy8512_gpio_chip ms320_48_phy8512_gpio[] = {
	{
		.gpio_chip = {
			.label = "phy8512-gpio0",
			.get = jaguar_phy8512_gpio_get_value,
			.set = jaguar_phy8512_gpio_set_value,
			.direction_input = jaguar_phy8512_gpio_direction_input,
			.direction_output = jaguar_phy8512_gpio_direction_output,
			.to_irq = jaguar_phy8512_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_BASE(0),
			.ngpio = 32,
			.can_sleep = 1,
		},
		.inst = 0,
		.port_base = 0,
	},
	{
		.gpio_chip = {
			.label = "phy8512-gpio1",
			.get = jaguar_phy8512_gpio_get_value,
			.set = jaguar_phy8512_gpio_set_value,
			.direction_input = jaguar_phy8512_gpio_direction_input,
			.direction_output = jaguar_phy8512_gpio_direction_output,
			.to_irq = jaguar_phy8512_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_BASE(1),
			.ngpio = 32,
			.can_sleep = 1,
		},
		.inst = 0,
		.port_base = 12,
	},
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	{
		.gpio_chip = {
			.label = "phy8512-gpio2",
			.get = jaguar_slv_phy8512_gpio_get_value,
			.set = jaguar_slv_phy8512_gpio_set_value,
			.direction_input = jaguar_slv_phy8512_gpio_direction_input,
			.direction_output = jaguar_slv_phy8512_gpio_direction_output,
			.to_irq = jaguar_slv_phy8512_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_BASE(2),
			.ngpio = 32,
			.can_sleep = 1,
		},
		.inst = 0,
		.port_base = 0,
	},
	{
		.gpio_chip = {
			.label = "phy8512-gpio3",
			.get = jaguar_slv_phy8512_gpio_get_value,
			.set = jaguar_slv_phy8512_gpio_set_value,
			.direction_input = jaguar_slv_phy8512_gpio_direction_input,
			.direction_output = jaguar_slv_phy8512_gpio_direction_output,
			.to_irq = jaguar_slv_phy8512_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_BASE(3),
			.ngpio = 32,
			.can_sleep = 1,
		},
		.inst = 0,
		.port_base = 12,
	},
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */
};

#endif /* CONFIG_VTSS_VCOREIII_PHY8512_GPIO */

static struct thermal_gpio_platform_data ms320_48_fan_data = {
	.gpio = VCOREIII_GPIO_PHY_BASE(0) + 2,
	.fan_active = 1,
	.type = "system",
};

static struct platform_device ms320_48_fan = {
	.name = "thermal-gpio",
	.dev = {
		.platform_data = &ms320_48_fan_data,
	}
};

static struct platform_device *ms320_48_devices[] __initdata = {
	&ms320_48_sfp_gpio_i2c_controller[0],
	&ms320_48_sfp_gpio_i2c_controller[1],
	&ms320_48_sfp_gpio_i2c_controller[2],
	&ms320_48_sfp_gpio_i2c_controller[3],
	&ms320_48_power_gpio_i2c_controller[0],
	&ms320_48_power_gpio_i2c_controller[1],
	&ms320_48_power_gpio_i2c_controller[2],
	&ms320_48_fan,
};

static struct platform_device *ms320_48_late_devices[] __initdata = {
	&ms320_48_mps_device[0],
	&ms320_48_mps_device[1],
};

static void ms320_48_machine_restart(char *command)
{
	int i;

	for (i = 0; i < 100; i++) {
		gpio_direction_output(VCOREIII_GPIO_BASE + 0, 0);
		udelay(100);
	}
	writel(VTSS_F_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST_SOFT_CHIP_RST,
	       VTSS_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST);

	while (true)
		cpu_wait();
}

int __init ms320_48_late_init(void)
{
	int i;
	int ret;
	struct i2c_adapter *adap;

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
	gpiochip_add(&ms320_48_phy8512_gpio[0].gpio_chip);
	gpiochip_add(&ms320_48_phy8512_gpio[1].gpio_chip);
#endif

	gpiochip_add(&ms320_48_phy8488_gpio[0].gpio_chip);
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if (map_base_slv_switch) {
		gpiochip_add(&ms320_48_phy8488_gpio[1].gpio_chip);
#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
		gpiochip_add(&ms320_48_phy8512_gpio[2].gpio_chip);
		gpiochip_add(&ms320_48_phy8512_gpio[3].gpio_chip);
#endif /* CONFIG_VTSS_VCOREIII_PHY8512_GPIO */
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

	platform_add_devices(ms320_48_devices, ARRAY_SIZE(ms320_48_devices));

	for (i = 0; i < ARRAY_SIZE(sfp_i2c_board_info); ++i) {
		adap = i2c_get_adapter(2 + i);
		if (!adap)
			return -ENODEV;
		i2c_new_device(adap, &sfp_i2c_board_info[i]);
		i2c_put_adapter(adap);
	}

	adap = i2c_get_adapter(6);
	if (!adap)
		return -ENODEV;
	for (i = 0; i < ARRAY_SIZE(power_i2c_board_info); ++i)
		i2c_new_device(adap, &power_i2c_board_info[i]);
	i2c_put_adapter(adap);

	platform_add_devices(ms320_48_late_devices, ARRAY_SIZE(ms320_48_late_devices));

	ret = gpio_request(VCOREIII_GPIO_BASE + 0, "reset");
	if (ret < 0) {
		printk(KERN_ERR "Unable to request reset pin, err=%d\n",
		       ret);
		return ret;
	} else {
		gpio_direction_output(VCOREIII_GPIO_BASE + 0, 1);
		_machine_restart = ms320_48_machine_restart;
	}
	return 0;
}
