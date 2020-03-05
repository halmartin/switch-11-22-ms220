/*
 *
 * VCore-III GPIO
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
 * This is a rewrite of the original GPIO module to use gpiolib
 * and export all GPIO functionality.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/platform_device.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>

#ifdef CONFIG_GPIOLIB

static int
vcoreiii_gpiolib_get_value(struct gpio_chip *chip, unsigned gpio)
{
	return (vcoreiii_gpio_main->in & (1 << gpio)) != 0;
}

static inline void
vcoreiii_gpiolib_set_value(struct gpio_chip *chip, unsigned gpio, int value)
{
	if (value)
		vcoreiii_gpio_main->out_set = (1 << gpio);
	else
		vcoreiii_gpio_main->out_clr = (1 << gpio);
}

static int vcoreiii_gpiolib_direction_input(struct gpio_chip *chip,
					    unsigned gpio)
{
	vcoreiii_gpio_main->oe &= ~(1 << gpio);
	return 0;
}

static int vcoreiii_gpiolib_direction_output(struct gpio_chip *chip,
					     unsigned gpio, int value)
{
	vcoreiii_gpiolib_set_value(chip, gpio, value);
	vcoreiii_gpio_main->oe |= (1 << gpio);

	return 0;
}

static int vcoreiii_gpiolib_to_irq(struct gpio_chip *chip, unsigned gpio)
{
	return -EINVAL;		/* Not yet */
}

static struct gpio_chip vcoreiii_gpio_chip = {
	.label				= "vcoreiii-gpio",
	.get				= vcoreiii_gpiolib_get_value,
	.set				= vcoreiii_gpiolib_set_value,
	.direction_input		= vcoreiii_gpiolib_direction_input,
	.direction_output		= vcoreiii_gpiolib_direction_output,
	.to_irq				= vcoreiii_gpiolib_to_irq,
	.base				= VCOREIII_GPIO_BASE,
	.ngpio				= VCOREIII_GPIO_NUM,
};

static int __init vcoreiii_gpio_init(void)
{
	gpiochip_add(&vcoreiii_gpio_chip);
	return 0;
}

arch_initcall(vcoreiii_gpio_init);

#else /* !CONFIG_GPIOLIB */

int gpio_to_irq(unsigned gpio)
{
	return __gpio_to_irq(gpio);
}


#endif /* CONFIG_GPIOLIB */
