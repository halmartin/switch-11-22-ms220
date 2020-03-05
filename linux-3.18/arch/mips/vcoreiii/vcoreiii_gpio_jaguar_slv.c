/*
 *
 * VCore-III GPIO on the slave device
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
 * Dual Jaguar GPIO support
 */

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

#ifdef CONFIG_GPIOLIB

static int
vcoreiii_gpiolib_get_value_slv(struct gpio_chip *chip, unsigned gpio)
{
	return (slv_readl(VTSS_DEVCPU_GCB_GPIO_GPIO_IN) & VTSS_BIT(gpio)) != 0;
}

static inline void
vcoreiii_gpiolib_set_value_slv(struct gpio_chip *chip, unsigned gpio, int value)
{
	if (value)
		slv_writel(VTSS_BIT(gpio), VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_SET);
	else
		slv_writel(VTSS_BIT(gpio), VTSS_DEVCPU_GCB_GPIO_GPIO_OUT_CLR);
}


static int
vcoreiii_gpiolib_direction_input_slv(struct gpio_chip *chip, unsigned gpio)
{
	vcoreiii_io_clr_slv(VTSS_DEVCPU_GCB_GPIO_GPIO_OE, VTSS_BIT(gpio));
	return 0;
}

static int
vcoreiii_gpiolib_direction_output_slv(struct gpio_chip *chip, unsigned gpio,
				   int value)
{
	vcoreiii_gpiolib_set_value_slv(chip, gpio, value); /* Set value first */
	vcoreiii_io_set_slv(VTSS_DEVCPU_GCB_GPIO_GPIO_OE, VTSS_BIT(gpio));
	return 0;
}

static inline int
vcoreiii_gpiolib_to_irq_slv(struct gpio_chip *chip, unsigned gpio)
{
	return -EINVAL;		/* Not yet */
}

static struct gpio_chip vcoreiii_gpio_chip_slv = {
	.label				= "vcoreiii-gpio-slv",
	.get				= vcoreiii_gpiolib_get_value_slv,
	.set				= vcoreiii_gpiolib_set_value_slv,
	.direction_input		= vcoreiii_gpiolib_direction_input_slv,
	.direction_output		= vcoreiii_gpiolib_direction_output_slv,
	.to_irq				= vcoreiii_gpiolib_to_irq_slv,
	.base				= VCOREIII_GPIO_BASE_SLV,
	.ngpio				= VCOREIII_GPIO_NUM,
};

int __init vcoreiii_gpio_init_slv(void)
{
	if (map_base_slv_switch) {
		gpiochip_add(&vcoreiii_gpio_chip_slv);
		return 0;
	}
	return -ENODEV;
}

arch_initcall(vcoreiii_gpio_init_slv);

#endif /* CONFIG_GPIOLIB */
