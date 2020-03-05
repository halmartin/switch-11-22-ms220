/*
 * VCore-III Serial GPIO
 *
 * Kevin Paul Herbert
 * Copyright (c) 2012, Meraki, Inc.
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
 * This is a GPIOLIB-based GPIO driver for the Serial GPIOs on the
 * VCore-III.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/sgpio.h>

struct vcoreiii_sgpio_ctrl {
	volatile u32 input_data[4]; /* Input data registers */
	volatile u32 int_pol[4];    /* Interrupt polarity */
	volatile u32 port_int_ena;  /* Interrupt enable */
	volatile u32 port_config[32]; /* Configuration for each port */
	volatile u32 port_enable;     /* Port enable register */
	volatile u32 config;	      /* General configuration register */
	volatile u32 clock;	      /* Serial I/O clock frequency */
	volatile u32 int_reg[4];      /* Interrupt register */
};

static inline struct sgpio_gpio_state *
gpio_to_sgpio(struct gpio_chip *chip, unsigned gpio, int *port, int *which)
{
	struct sgpio_gpio_state *sgpio =
		container_of(chip, struct sgpio_gpio_state, gpio_chip);

	*port = gpio / sgpio->gpios_per_port; /* Get which port this is */
	*which = gpio % sgpio->gpios_per_port; /* And which GPIO on the port */

	return sgpio;		/* Return SGPIO pointer */
}

static int vcoreiii_sgpio_get_value(struct gpio_chip *chip, unsigned gpio)
{
	int port, which;
	struct sgpio_gpio_state *sgpio =
		gpio_to_sgpio(chip, gpio, &port, &which);

	return ((sgpio->ctrl->input_data[which] & (1 << port)) != 0);
}

static void vcoreiii_sgpio_set_value(struct gpio_chip *chip, unsigned gpio,
				     int value)
{
	int port, which;
	struct sgpio_gpio_state *sgpio =
		gpio_to_sgpio(chip, gpio, &port, &which);
	u32 mask, val;

	mask = ~(7 << (which * 3));
	val = ((value != 0) << (which * 3));

	/*
	 * We do this locked in case the switch API is managing some
	 * GPIOs and we are managing others, or if we are running on
	 * a SMP system or with preemption.
	 */

	vcoreiii_api_lock(__func__); /* Lock the API */

	sgpio->ctrl->port_config[port] =
		(sgpio->ctrl->port_config[port] & mask) | val;

	vcoreiii_api_unlock(__func__); /* Unlock API */
}

static int vcoreiii_sgpio_direction_input(struct gpio_chip *chip,
					  unsigned gpio)
{
	return 0;		/* TBD: Check if platform allows */
}

static int vcoreiii_sgpio_direction_output(struct gpio_chip *chip,
					   unsigned gpio, int value)
{
	vcoreiii_sgpio_set_value(chip, gpio, value);
	return 0;
}

static int vcoreiii_sgpio_to_irq(struct gpio_chip *chip, unsigned gpio)
{
	return -EINVAL;		/* Not yet */

}

static int vcoreiii_sgpio_probe(struct platform_device *pdev)
{
	struct sgpio_platform_data *pdata = pdev->dev.platform_data;
	struct sgpio_gpio_state *sgpio;
	int ret;
	int port;

	sgpio = kzalloc(sizeof(struct sgpio_gpio_state), GFP_KERNEL);
	if (!sgpio)
		return -ENOMEM;

	sgpio->gpio_di = pdata->gpio_di;
	sgpio->gpio_do = pdata->gpio_do;
	sgpio->gpio_clk = pdata->gpio_clk;
	sgpio->ctrl = pdata->ctrl;
	sgpio->gpios_per_port = pdata->gpios_per_port;

	if (sgpio->gpio_di >= 0) {
		ret = gpio_request(sgpio->gpio_di, "sgpio_di");
		if (ret < 0)
		goto err_ret;
	}

	ret = gpio_request(sgpio->gpio_do, "sgpio_do");
	if (ret < 0)
		goto err_free_gpio_di;

	ret = gpio_request(sgpio->gpio_clk, "sgpio_clk");
	if (ret < 0)
		goto err_free_gpio_do;

	if (sgpio->gpio_di >= 0) {
		ret = vcoreiii_gpio_set_alternate(sgpio->gpio_di, 1);
		if (ret < 0)
			goto err_free_gpio_clk;
	}

	ret = vcoreiii_gpio_set_alternate(sgpio->gpio_do, 1);
	if (ret < 0)
		goto err_reset_gpio_di;

	ret = vcoreiii_gpio_set_alternate(sgpio->gpio_clk, 1);
	if (ret < 0)
		goto err_reset_gpio_do;

	sgpio->ctrl->port_int_ena = 0; /* No interrupt support yet */

	sgpio->ctrl->clock = 0x14; /* 12.5 MHZ - fix me */

	sgpio->ctrl->config = (31 << 7) | (1 << 5) |
		((pdata->gpios_per_port - 1) << 2);

	/* NB: 1 << 32 - 1 = 0xffffffff, which is what you want */

	sgpio->ctrl->port_enable = (1 << pdata->num_ports) - 1;

	/* Set the initial value to on or off */

	for (port = 0; port < pdata->num_ports; port++)
		sgpio->ctrl->port_config[port] = pdata->init_value ? 0x249 : 0;

	/* Hardware is good, register chip */

	sgpio->gpio_chip.label = pdev->name;
	sgpio->gpio_chip.dev = &pdev->dev;
	sgpio->gpio_chip.get = vcoreiii_sgpio_get_value;
	sgpio->gpio_chip.set = vcoreiii_sgpio_set_value;
	sgpio->gpio_chip.direction_input = vcoreiii_sgpio_direction_input;
	sgpio->gpio_chip.direction_output = vcoreiii_sgpio_direction_output;
	sgpio->gpio_chip.to_irq = vcoreiii_sgpio_to_irq;
	sgpio->gpio_chip.base = pdata->base;
	sgpio->gpio_chip.ngpio = pdata->num_ports * pdata->gpios_per_port;
	sgpio->gpio_chip.can_sleep = 1;
	sgpio->gpio_chip.owner = THIS_MODULE;

	platform_set_drvdata(pdev, sgpio);

	ret = gpiochip_add(&sgpio->gpio_chip);
	if (ret)
		goto err_reset_gpio_clk;

	return 0;

err_reset_gpio_clk:
	vcoreiii_gpio_set_alternate(sgpio->gpio_clk, 0);

err_reset_gpio_do:
	vcoreiii_gpio_set_alternate(sgpio->gpio_do, 0);

err_reset_gpio_di:
	if (sgpio->gpio_di >= 0)
		vcoreiii_gpio_set_alternate(sgpio->gpio_di, 0);

err_free_gpio_clk:
	gpio_free(sgpio->gpio_clk);

err_free_gpio_do:
	gpio_free(sgpio->gpio_do);

err_free_gpio_di:
	if (sgpio->gpio_di >= 0)
		gpio_free(sgpio->gpio_di);

err_ret:
	kfree(sgpio);
	return ret;

}

static int vcoreiii_sgpio_remove(struct platform_device *pdev)
{
	struct sgpio_gpio_state *sgpio = platform_get_drvdata(pdev);

	gpiochip_remove(&sgpio->gpio_chip);

	vcoreiii_gpio_set_alternate(sgpio->gpio_clk, 0);
	vcoreiii_gpio_set_alternate(sgpio->gpio_do, 0);
	gpio_set_value(sgpio->gpio_clk, 0);
	gpio_set_value(sgpio->gpio_do, 0);

	if (sgpio->gpio_di >= 0) {
		vcoreiii_gpio_set_alternate(sgpio->gpio_di, 1);
		gpio_free(sgpio->gpio_di);
	}

	gpio_free(sgpio->gpio_clk);
	gpio_free(sgpio->gpio_do);

	kfree(sgpio);

	return 0;
}

static struct platform_driver vcoreiii_sgpio_driver = {
	.probe		= vcoreiii_sgpio_probe,
	.remove		= vcoreiii_sgpio_remove,
	.driver		= {
		.name	= "vcoreiii-sgpio",
		.owner	= THIS_MODULE,
	},
};

static int __init vcoreiii_sgpio_init(void)
{
	return platform_driver_register(&vcoreiii_sgpio_driver);
}

static void __exit vcoreiii_sgpio_exit(void)
{
	platform_driver_unregister(&vcoreiii_sgpio_driver);
}


module_init(vcoreiii_sgpio_init);
module_exit(vcoreiii_sgpio_exit);

MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.net>");
MODULE_DESCRIPTION("VCore-III SGPIO driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platforms:vcoreiii-sgpio");
