/*
 * Simple thermal GPIO driver
 *
 * Kevin Paul Herbert
 * Copyright (c) 2012, Meraki, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>
#include <linux/thermal_gpio.h>
#include <linux/err.h>
#include <linux/slab.h>

#include <asm/gpio.h>

struct thermal_gpio_state {
	int state;		/* Current cooling state */
	unsigned gpio;		/* GPIO we are using */
	int fan_active;		/* State to activate fan */
};

static int
thermal_gpio_get_max_state(struct thermal_cooling_device *cdev,
			   unsigned long *state)
{
	*state = 1;		/* Only on or off */
	return 0;
}

static int
thermal_gpio_get_cur_state(struct thermal_cooling_device *cdev,
			   unsigned long *state)
{
	struct thermal_gpio_state *tgpio = cdev->devdata;

	*state = tgpio->state;

	return 0;
}

static int
thermal_gpio_set_cur_state(struct thermal_cooling_device *cdev,
			   unsigned long state)
{
	struct thermal_gpio_state *tgpio = cdev->devdata;

	gpio_set_value_cansleep(tgpio->gpio,
				state ? tgpio->fan_active : !tgpio->fan_active);
	tgpio->state = state;

	return 0;
}

static struct thermal_cooling_device_ops thermal_gpio_device_ops = {
	.get_max_state = thermal_gpio_get_max_state,
	.get_cur_state = thermal_gpio_get_cur_state,
	.set_cur_state = thermal_gpio_set_cur_state,
};

static int thermal_gpio_probe(struct platform_device *pdev)
{
	struct thermal_gpio_platform_data *pdata = pdev->dev.platform_data;
	int ret;
	struct thermal_gpio_state *tgpio;
	struct thermal_cooling_device *cdev;

	tgpio = kzalloc(sizeof(struct thermal_gpio_state), GFP_KERNEL);
	if (!tgpio)
		return -ENOMEM;

	tgpio->gpio = pdata->gpio;
	tgpio->fan_active = pdata->fan_active;
	tgpio->state = 0;

	ret = gpio_request(tgpio->gpio, "thermal_gpio");
	if (ret < 0)
		goto err_ret;

	ret = gpio_direction_output(tgpio->gpio, !pdata->fan_active);
	if (ret < 0)
		goto err_free_gpio;

	cdev = thermal_cooling_device_register(pdata->type, tgpio,
					       &thermal_gpio_device_ops);
	if (IS_ERR(cdev)) {
		ret = (int)cdev;
		goto err_free_gpio;
	}

	platform_set_drvdata(pdev, tgpio);

	return 0;

err_free_gpio:
	gpio_free(tgpio->gpio);

err_ret:
	kfree(tgpio);
	return ret;

}

static int thermal_gpio_remove(struct platform_device *pdev)
{
	struct thermal_gpio_state *tgpio = platform_get_drvdata(pdev);

	gpio_set_value_cansleep(tgpio->gpio, tgpio->fan_active); /* Leave it running */
	gpio_free(tgpio->gpio);
	kfree(tgpio);

	return 0;
}

static struct platform_driver thermal_gpio_driver = {
	.probe		= thermal_gpio_probe,
	.remove		= thermal_gpio_remove,
	.driver		= {
		.name	= "thermal-gpio",
		.owner	= THIS_MODULE,
	},
};

static int __init thermal_gpio_init(void)
{
	return platform_driver_register(&thermal_gpio_driver);
}

static void __exit thermal_gpio_exit(void)
{
	platform_driver_unregister(&thermal_gpio_driver);
}


module_init(thermal_gpio_init);
module_exit(thermal_gpio_exit);

MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.net>");
MODULE_DESCRIPTION("Simple thermal GPIO driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platforms:thermal-gpio");
