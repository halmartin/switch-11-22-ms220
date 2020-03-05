/*
 *
 * Meraki MS220-48 board definitions
 *
 * Copyright (c) 2013 Meraki, Inc.
 * Author: James Chris Parks (james.parks@meraki.net)
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
 * This is the board-specific code for the Meraki MS220-48/MS220-48P
 * switches.
 */

#include <linux/kernel.h>

#include <linux/i2c.h>
#include <linux/i2c-gpio.h>
#include <linux/i2c-gpio-scl.h>
#include <linux/platform_device.h>
#include <linux/platform_data/at24.h>
#include <linux/pd690xx.h>
#include <linux/thermal_gpio.h>
#include <linux/delay.h>
#include <asm/reboot.h>
#include <asm/idle.h>
#include <linux/meraki/cisco-rps.h>
#include <linux/meraki/meraki_config.h>

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/mach-vcoreiii/phy8512_gpio.h>

static unsigned int ms220_48_i2c_sfp_scl_pins[] = {
        VCOREIII_GPIO_BASE_SLV + 20,
        VCOREIII_GPIO_BASE_SLV + 19,
        VCOREIII_GPIO_BASE_SLV + 18,
        VCOREIII_GPIO_BASE_SLV + 17,
};

static struct i2c_gpio_scl_platform_data ms220_48_i2c_sfp_gpio_pins[] = {
        {
                .sda_pin = VCOREIII_GPIO_BASE_SLV + 21,
                .scl_pins = ms220_48_i2c_sfp_scl_pins,
                .num_scl = 4,
                .parent_id = 2,
                .child_id_base = 3,
                .udelay = 10,
        },
};

struct platform_device ms220_48_sfp_gpio_i2c_controller[] = {
	{
		.name	= "i2c-gpio-scl",
		.id	= 2,
		.dev = {
			.platform_data = &ms220_48_i2c_sfp_gpio_pins[0],
		},
		.num_resources = 0,
	},
};

static struct i2c_gpio_platform_data ms220_48_i2c_power_gpio_pins = {
	.sda_pin = VCOREIII_GPIO_BASE_SLV + 15,
	.scl_pin = VCOREIII_GPIO_BASE_SLV + 14,
	.udelay = 10,
};

static struct platform_device ms220_48_power_i2c_controller = {
	.name = "i2c-gpio",
	.id = 8,
	.dev = {
		.platform_data = &ms220_48_i2c_power_gpio_pins,
	},
	.num_resources = 0,
};

struct memory_accessor *ms220_48_sfp_eeprom_mems[4];
EXPORT_SYMBOL(ms220_48_sfp_eeprom_mems);

static void ms220_48_sfp_eeprom_setup(struct memory_accessor *ma, void *context)
{
	*((struct memory_accessor **)context) = ma;
}

static struct at24_platform_data ms220_48_sfp_eeprom_plat_data[4] = {
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms220_48_sfp_eeprom_setup,
		.context = &ms220_48_sfp_eeprom_mems[0],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms220_48_sfp_eeprom_setup,
		.context = &ms220_48_sfp_eeprom_mems[1],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms220_48_sfp_eeprom_setup,
		.context = &ms220_48_sfp_eeprom_mems[2],
	},
	{
		.byte_len = 256,
		.page_size = 1,
		.flags = AT24_FLAG_READONLY,
		.setup = ms220_48_sfp_eeprom_setup,
		.context = &ms220_48_sfp_eeprom_mems[3],
	},
};

static const struct i2c_board_info sfp_i2c_board_info[4] = {
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms220_48_sfp_eeprom_plat_data[0],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms220_48_sfp_eeprom_plat_data[1],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms220_48_sfp_eeprom_plat_data[2],
	},
	{
		I2C_BOARD_INFO("24c02", 0x50),
		.platform_data = &ms220_48_sfp_eeprom_plat_data[3],
	},
};

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO

static struct phy8512_gpio_chip ms220_48_phy8512_gpio[] = {
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

static struct thermal_gpio_platform_data ms220_48_fan_data = {
	.gpio = VCOREIII_GPIO_BASE + 20,
	.fan_active = 1,
	.type = "system",
};

static struct platform_device ms220_48_fan = {
	.name = "thermal-gpio",
	.dev = {
		.platform_data = &ms220_48_fan_data,
	}
};

static struct cisco_rps_platform_data ms220_48_rps_data = {
	.i2c_adapter = 8,
	.status_0 = VCOREIII_GPIO_BASE + 9,
	.status_1 = VCOREIII_GPIO_BASE + 8,
	.max_system_power = 250 * 1000,
};

static struct platform_device ms220_48_rps = {
	.name = "cisco-rps",
	.id = -1,
	.dev = {
		.platform_data = &ms220_48_rps_data,
	},
	.num_resources = 0,
};

static struct platform_device *ms220_48_devices[] __initdata = {
	&ms220_48_sfp_gpio_i2c_controller[0],
	&ms220_48_fan,
	&ms220_48_power_i2c_controller,
	&ms220_48_rps,
};

static void ms220_48_machine_restart(char *command)
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

int __init ms220_48_late_init(uint8_t board_type)
{
        int i;
        int ret;
        struct i2c_adapter *adap;
        uint32_t poe_budget = 0;

        if (board_type == MERAKI_BOARD_MS220_48LP)
            poe_budget = 370 * 1000;
        else if (board_type == MERAKI_BOARD_MS220_48FP)
            poe_budget = 740 * 1000;

        ms220_48_rps_data.max_poe_power = poe_budget;

#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
        gpiochip_add(&ms220_48_phy8512_gpio[0].gpio_chip);
        gpiochip_add(&ms220_48_phy8512_gpio[1].gpio_chip);
#endif
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
        if (map_base_slv_switch) {
#ifdef CONFIG_VTSS_VCOREIII_PHY8512_GPIO
                gpiochip_add(&ms220_48_phy8512_gpio[2].gpio_chip);
                gpiochip_add(&ms220_48_phy8512_gpio[3].gpio_chip);
#endif /* CONFIG_VTSS_VCOREIII_PHY8512_GPIO */
        }
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

        platform_add_devices(ms220_48_devices, ARRAY_SIZE(ms220_48_devices));

        for (i = 0; i < 4; ++i) {
                adap = i2c_get_adapter(3 + i);
                if (!adap)
                        return -ENODEV;
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
                _machine_restart = ms220_48_machine_restart;
        }
        return 0;
}
