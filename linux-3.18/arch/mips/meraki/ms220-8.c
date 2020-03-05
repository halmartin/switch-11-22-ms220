/*
 *
 * Meraki MS220 board definitions
 *
 * Copyright (c) 2011-13 Meraki, Inc.
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
 * This is the board-specific code for the Meraki MS220/MS220FP switches.
 */

#include <linux/kernel.h>

#include <linux/i2c.h>
#include <linux/i2c-gpio.h>
#include <linux/platform_device.h>
#include <linux/pd690xx.h>
#include <linux/thermal_gpio.h>
#include <linux/delay.h>
#include <asm/reboot.h>
#include <asm/idle.h>

#define SUPPORT_VTSS_VCOREIII_LUTON26

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/mach-vcoreiii/phy8512_gpio.h>

static struct i2c_gpio_platform_data ms220_8_i2c_gpio_pins = {
    .sda_pin    = VCOREIII_GPIO_BASE + 6,
    .scl_pin    = VCOREIII_GPIO_BASE + 5,
    .udelay     = 10,
};

static struct platform_device ms220_8_gpio_i2c_controller = {
    .name       = "i2c-gpio",
    .id = 1,
    .dev = {
        .platform_data = &ms220_8_i2c_gpio_pins,
    },
    .num_resources = 0,
};

static struct platform_device *ms220_8_devices[] __initdata = {
    &ms220_8_gpio_i2c_controller
};

static void ms220_8_machine_restart(char *command)
{
    writel(VTSS_F_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST_SOFT_CHIP_RST,
           VTSS_DEVCPU_GCB_DEVCPU_RST_REGS_SOFT_CHIP_RST);

    while (true)
        cpu_wait();
}

int __init meraki_ms220_8_late_init(void)
{
    struct i2c_adapter *adap;

    platform_add_devices(ms220_8_devices, ARRAY_SIZE(ms220_8_devices));

    _machine_restart = ms220_8_machine_restart;

    return 0;
}
