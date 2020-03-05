/*
 *
 * VCore-III platform ressources
 *
 * Copyright (C) 2010 Vitesse Semiconductor Inc.
 * Author: Lars Povlsen (lpovlsen@vitesse.com)
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
 * VITESSE SEMICONDUCTOR INC SHALL HAVE NO LIABILITY WHATSOEVER OF ANY
 * KIND ARISING OUT OF OR RELATED TO THE PROGRAM OR THE OPEN SOURCE
 * MATERIALS UNDER ANY THEORY OF LIABILITY.
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/serial_8250.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/irq.h>
#include <asm/mach-vcoreiii/i2c.h>

#define CBUS_UART_FLAGS (UPF_BOOT_AUTOCONF | UPF_SKIP_TEST | UPF_IOREMAP)

static struct plat_serial8250_port uart8250_vcoreiii_data[] = {
	{
		.mapbase	= 0x70100000,
		.irq		= UART_IRQ,
		.uartclk	= VCOREIII_AHB_CLOCK,
		.iotype		= UPIO_MEM32,
		.flags		= CBUS_UART_FLAGS | UPF_FIXED_TYPE,
		.type		= PORT_16550A,
		.regshift	= 2,
	},
	{ },
};

static struct platform_device uart8250_device = {
	.name			= "serial8250",
	.id			= PLAT8250_DEV_PLATFORM,
	.dev = {
		.platform_data = uart8250_vcoreiii_data,
	},
};

static int __init uart8250_init(void)
{
	return platform_device_register(&uart8250_device);
}

module_init(uart8250_init);

static struct vcoreiii_i2c_platform_data i2c_data = {
    .fast_mode = 0,             /* 100 kbit/s */
};

static int __init vcoreiii_i2c_init(void)
{
    int ret;
    struct platform_device *dev = platform_device_register_simple("i2c_vcoreiii", -1, NULL, 0);
    if(IS_ERR(dev))
        return PTR_ERR(dev);
    if((ret = platform_device_add_data(dev, &i2c_data, sizeof(struct vcoreiii_i2c_platform_data))))
        platform_device_unregister(dev);
    return ret;
}
device_initcall(vcoreiii_i2c_init);

MODULE_AUTHOR("Lars Povlsen <lpovlsen@vitesse.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("8250 UART probe driver for the VCore-III UART");
