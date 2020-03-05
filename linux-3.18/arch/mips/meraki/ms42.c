/*
 *
 * Meraki MS-42 board definitions
 *
 * Copyright (c) 2011 Meraki, Inc.
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
 * This is the board-specific code for the Meraki MS42/MS42P switches.
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

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/mach-vcoreiii/phy8512_gpio.h>
#include <asm/mach-vcoreiii/phy8488_gpio.h>

static struct i2c_gpio_platform_data ms42_i2c_sfp_gpio_pins[4] = {
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

struct memory_accessor *ms42_sfp_eeprom_mems[4];
EXPORT_SYMBOL(ms42_sfp_eeprom_mems);

static void ms42_sfp_eeprom_setup(struct memory_accessor *ma, void *context)
{
	*((struct memory_accessor **)context) = ma;
}

static struct at24_platform_data ms42_sfp_eeprom_plat_data[4] = {
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms42_sfp_eeprom_setup,
		.context = &ms42_sfp_eeprom_mems[0],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms42_sfp_eeprom_setup,
		.context = &ms42_sfp_eeprom_mems[1],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms42_sfp_eeprom_setup,
		.context = &ms42_sfp_eeprom_mems[2],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms42_sfp_eeprom_setup,
		.context = &ms42_sfp_eeprom_mems[3],
	},
};

static struct platform_device ms42_sfp_gpio_i2c_controller[4] = {
	{
		.name	= "i2c-gpio",
		.id	= 2,
		.dev = {
			.platform_data = &ms42_i2c_sfp_gpio_pins[0],
		},
		.num_resources = 0,
	},
	{
		.name	= "i2c-gpio",
		.id	= 3,
		.dev = {
			.platform_data = &ms42_i2c_sfp_gpio_pins[1],
		},
		.num_resources = 0,
	},
	{
		.name	= "i2c-gpio",
		.id	= 4,
		.dev = {
			.platform_data = &ms42_i2c_sfp_gpio_pins[2],
		},
		.num_resources = 0,
	},
	{
		.name	= "i2c-gpio",
		.id	= 5,
		.dev = {
			.platform_data = &ms42_i2c_sfp_gpio_pins[3],
		},
		.num_resources = 0,
	},
};

static const struct i2c_board_info sfp_i2c_board_info[4] = {
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms42_sfp_eeprom_plat_data[0],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms42_sfp_eeprom_plat_data[1],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms42_sfp_eeprom_plat_data[2],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms42_sfp_eeprom_plat_data[3],
	},
};

static struct phy8488_gpio_chip ms42_phy8488_gpio[] = {
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

static struct phy8512_gpio_chip ms42_phy8512_gpio[] = {
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

static struct thermal_gpio_platform_data ms42_fan_data = {
	.gpio = VCOREIII_GPIO_PHY_BASE(0) + 2,
	.fan_active = 1,
	.type = "system",
};

static struct platform_device ms42_fan = {
	.name = "thermal-gpio",
	.dev = {
		.platform_data = &ms42_fan_data,
	}
};

static struct platform_device *ms42_devices[] __initdata = {
	&ms42_sfp_gpio_i2c_controller[0],
	&ms42_sfp_gpio_i2c_controller[1],
	&ms42_sfp_gpio_i2c_controller[2],
	&ms42_sfp_gpio_i2c_controller[3],
	&ms42_fan,
};

static void ms42_machine_restart(char *command)
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

int __init ms42_late_init(void)
{
	int i;
	int ret;
	struct i2c_adapter *adap;

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
	gpiochip_add(&ms42_phy8512_gpio[0].gpio_chip);
	gpiochip_add(&ms42_phy8512_gpio[1].gpio_chip);
#endif

	gpiochip_add(&ms42_phy8488_gpio[0].gpio_chip);
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if (map_base_slv_switch) {
		gpiochip_add(&ms42_phy8488_gpio[1].gpio_chip);
#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
		gpiochip_add(&ms42_phy8512_gpio[2].gpio_chip);
		gpiochip_add(&ms42_phy8512_gpio[3].gpio_chip);
#endif /* CONFIG_VTSS_VCOREIII_PHY8512_GPIO */
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

	platform_add_devices(ms42_devices, ARRAY_SIZE(ms42_devices));

	for (i = 0; i < 4; ++i) {
		adap = i2c_get_adapter(2 + i);
		if (!adap) {
			return -ENODEV;
		}
		i2c_new_device(adap, &sfp_i2c_board_info[i]);
		i2c_put_adapter(adap);
	}

	ret = gpio_request(VCOREIII_GPIO_BASE + 0, "reset");
	if (ret < 0) {
		printk(KERN_ERR "Unable to request reset pin, err=%d\n",
		       ret);
		return ret;
	} else {
		gpio_direction_output(VCOREIII_GPIO_BASE + 0, 1);
		_machine_restart = ms42_machine_restart;
	}
	return 0;
}
