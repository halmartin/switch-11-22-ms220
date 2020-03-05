/*
 *
 * Meraki MS320-24P board definitions
 *
 * Copyright (c) 2013 Meraki, Inc.
 * Author: James Parks (james.parks@meraki.net)
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
 * This is the board-specific code for the Meraki MS320-24/MS320-24P switches.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/i2c.h>
#include <linux/i2c-gpio.h>
#include <linux/i2c-mux-gpio.h>
#include <linux/pd690xx.h>
#include <linux/platform_data/at24.h>
#include <linux/platform_device.h>
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

static unsigned ms320_24_gpio_i2cmux_pins[] = {
	VCOREIII_GPIO_PHY_8488_BASE(0) + 4, /* SFP 1 */
	VCOREIII_GPIO_PHY_8488_BASE(0) + 5, /* SFP 2 */
	VCOREIII_GPIO_PHY_8488_BASE(0) + 10, /* SFP 3 */
	VCOREIII_GPIO_PHY_8488_BASE(0) + 11, /* SFP 4 */
};

/* Inverted bus selects */
static unsigned ms320_24_gpio_i2cmux_values[] = {
	0xe,
	0xd,
	0xb,
	0x7,
};

static struct i2c_mux_gpio_platform_data ms320_24_gpio_i2cmux[] = {
	{
		.parent = 6,
		.base_nr = 2,
		.values = &ms320_24_gpio_i2cmux_values[0],
		.n_values = ARRAY_SIZE(ms320_24_gpio_i2cmux_values),
		.gpios = &ms320_24_gpio_i2cmux_pins[0],
		.n_gpios = ARRAY_SIZE(ms320_24_gpio_i2cmux_pins),
		.idle = 0xf,
	}
};

struct platform_device ms320_24_gpio_i2c_mux_controller[] = {
	{
		.name = "i2c-mux-gpio",
		.id = 2,
		.dev = {
			.platform_data = &ms320_24_gpio_i2cmux[0],
		},
		.num_resources = 0,
	},
};

static struct i2c_gpio_platform_data ms320_24_i2c_power_gpio_pins[] = {
	/* connected to external I2C-to-GPIO chip, temperature sensors,
	   modular power supply A, and modular power supply B */
	{
		.sda_pin = VCOREIII_GPIO_BASE + 17,
		.scl_pin = VCOREIII_GPIO_BASE + 0,
		.udelay = 10,
	},
};

static struct platform_device ms320_24_power_gpio_i2c_controller[] = {
	{
		.name = "i2c-gpio",
		.id = 6,
		.dev = {
			.platform_data = &ms320_24_i2c_power_gpio_pins[0],
		},
		.num_resources = 0,
	},
};

struct memory_accessor *ms320_24_sfp_eeprom_mems[4];
EXPORT_SYMBOL(ms320_24_sfp_eeprom_mems);

static void ms320_24_sfp_eeprom_setup(struct memory_accessor *ma, void *context)
{
	*((struct memory_accessor **)context) = ma;
}

static struct at24_platform_data ms320_24_sfp_eeprom_plat_data[4] = {
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_24_sfp_eeprom_setup,
		.context = &ms320_24_sfp_eeprom_mems[0],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_24_sfp_eeprom_setup,
		.context = &ms320_24_sfp_eeprom_mems[1],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_24_sfp_eeprom_setup,
		.context = &ms320_24_sfp_eeprom_mems[2],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms320_24_sfp_eeprom_setup,
		.context = &ms320_24_sfp_eeprom_mems[3],
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

static struct pca953x_platform_data ms320_24_gpio_expander_data = {
	.gpio_base = VCOREIII_GPIO_TCA6424A_GPIO_BASE,
	.names = (const char **)expander_pin_names,
};

static struct i2c_board_info power_i2c_board_info[] = {
	{
		I2C_BOARD_INFO("tca6424", 0x22),
		.platform_data = &ms320_24_gpio_expander_data,
	},
};

static const struct i2c_board_info sfp_i2c_board_info[4] = {
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_24_sfp_eeprom_plat_data[0],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_24_sfp_eeprom_plat_data[1],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_24_sfp_eeprom_plat_data[2],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms320_24_sfp_eeprom_plat_data[3],
	},
};

static struct phy8488_gpio_chip ms320_24_phy8488_gpio[] = {
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
		.port_base = 26,
	},
	{
		.gpio_chip = {
			.label = "phy8488-gpio1",
			.get = jaguar_phy8488_gpio_get_value,
			.set = jaguar_phy8488_gpio_set_value,
			.direction_input = jaguar_phy8488_gpio_direction_input,
			.direction_output = jaguar_phy8488_gpio_direction_output,
			.to_irq = jaguar_phy8488_gpio_to_irq,
			.base = VCOREIII_GPIO_PHY_8488_BASE(1),
			.ngpio = 12,
			.can_sleep = 1,
		},
		.inst = 1,
		.port_base = 28,
	},
};

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO

static struct phy8512_gpio_chip ms320_24_phy8512_gpio[] = {
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
};

#endif

/* FAN Control */
static struct thermal_gpio_platform_data ms320_24_fan_data = {
	.gpio = VCOREIII_GPIO_BASE + 18,
	.fan_active = 1,
	.type = "system",
};

static struct platform_device ms320_24_fan = {
	.name = "thermal-gpio",
	.dev = {
		.platform_data = &ms320_24_fan_data,
	}
};

static struct cisco_mps_platform_data ms320_24_mps_data[] = {
	{
		.present_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 10,
		.power_good_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 8,
		.control_i2c_address = 0x5b,
		.data_i2c_address = 0x53,
		.i2c_adapter_id = 6,
	},
	{
		.present_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 2,
		.power_good_pin = VCOREIII_GPIO_TCA6424A_GPIO_BASE + 0,
		.control_i2c_address = 0x5a,
		.data_i2c_address = 0x52,
		.i2c_adapter_id = 6,
	},
};

static struct platform_device ms320_24_mps_device[] = {
	{
		.name = "cisco-mps",
		.id = 1,
		.dev = {
			.platform_data = &ms320_24_mps_data[0],
		},
	},
	{
		.name = "cisco-mps",
		.id = 2,
		.dev = {
			.platform_data = &ms320_24_mps_data[1],
		},
	},
};

static struct platform_device *ms320_24_devices[] __initdata = {
	&ms320_24_fan,
	&ms320_24_power_gpio_i2c_controller[0],
	&ms320_24_gpio_i2c_mux_controller[0],
};

static struct platform_device *ms320_24_late_devices[] __initdata = {
	&ms320_24_mps_device[0],
	&ms320_24_mps_device[1],
};

static void ms320_24_machine_restart(char *command)
{
	int i;

	for (i = 0; i < 100; i++) {
		gpio_direction_output(VCOREIII_GPIO_BASE + 22, 0);
		udelay(100);
	}
	writel(VTSS_F_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST_SOFT_CHIP_RST,
	       VTSS_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST);

	while (true)
		cpu_wait();
}

int __init ms320_24_late_init(void)
{
	int i;
	int ret;
	struct i2c_adapter *adap;

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
	gpiochip_add(&ms320_24_phy8512_gpio[0].gpio_chip);
	gpiochip_add(&ms320_24_phy8512_gpio[1].gpio_chip);
#endif
	gpiochip_add(&ms320_24_phy8488_gpio[0].gpio_chip);
	gpiochip_add(&ms320_24_phy8488_gpio[1].gpio_chip);
	platform_add_devices(ms320_24_devices, ARRAY_SIZE(ms320_24_devices));
	for (i = 0; i < 4; ++i) {
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

	platform_add_devices(ms320_24_late_devices, ARRAY_SIZE(ms320_24_late_devices));

	ret = gpio_request(VCOREIII_GPIO_BASE + 22, "reset");
	if (ret < 0) {
		printk(KERN_ERR "Unable to request reset pin, err=%d\n",
		       ret);
		return ret;
	} else {
		gpio_direction_output(VCOREIII_GPIO_BASE + 22, 1);
		vcoreiii_gpio_set_alternate(22, 0);
		_machine_restart = ms320_24_machine_restart;
	}
	return 0;
}
