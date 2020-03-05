/*
 * Bitbanging I2C bus driver with SCL multiplexing support
 *
 * Copyright (C) 2013 Meraki Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Design drawn heavily from the work by
 * Haavard Skinnemoen <hskinnemoen@atmel.com> and
 * Peter Korsgaard <peter.korsgaard@barco.com>
 */

#include <linux/i2c.h>
#include <linux/i2c-mux.h>
#include <linux/i2c-algo-bit.h>
#include <linux/i2c-gpio-scl.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <asm/gpio.h>

struct sclmux {
	struct i2c_adapter *parent;
	struct i2c_adapter **adap;
	struct i2c_gpio_scl_platform_data *data;
};

static int i2c_gpio_scl_select(struct i2c_adapter *adap, void *data, u32 chan)
{
	struct sclmux *mux = data;
	struct i2c_gpio_scl_platform_data *pdata = mux->data;
	pdata->channel = chan;
	return 0;
}

static void i2c_gpio_scl_setsda_dir(void *data, int state)
{
	struct i2c_gpio_scl_platform_data *pdata = data;

	if (state)
		gpio_direction_input(pdata->sda_pin);
	else
		gpio_direction_output(pdata->sda_pin, 0);
}

static void i2c_gpio_scl_setsda_val(void *data, int state)
{
	struct i2c_gpio_scl_platform_data *pdata = data;

	gpio_set_value(pdata->sda_pin, state);
}

static void i2c_gpio_scl_setscl_dir(void *data, int state)
{
	struct i2c_gpio_scl_platform_data *pdata = data;

	if (state)
		gpio_direction_input(pdata->scl_pins[pdata->channel]);
	else
		gpio_direction_output(pdata->scl_pins[pdata->channel], 0);
}

static int i2c_gpio_scl_getsda(void *data)
{
	struct i2c_gpio_scl_platform_data *pdata = data;

	return gpio_get_value(pdata->sda_pin);
}

static int i2c_gpio_scl_getscl(void *data)
{
	struct i2c_gpio_scl_platform_data *pdata = data;

	return gpio_get_value(pdata->scl_pins[pdata->channel]);
}

static int i2c_gpio_scl_probe(struct platform_device *pdev)
{
	struct i2c_gpio_scl_platform_data *pdata;
	struct i2c_algo_bit_data *bit_data;
	struct i2c_adapter *adap;
	struct sclmux *mux;
	int ret, i, j;

	pdata = pdev->dev.platform_data;
	if (!pdata)
		return -ENXIO;

	ret = -ENOMEM;
	adap = kzalloc(sizeof(struct i2c_adapter), GFP_KERNEL);
	if (!adap)
		goto err_alloc_adap;
	bit_data = kzalloc(sizeof(struct i2c_algo_bit_data), GFP_KERNEL);
	if (!bit_data)
		goto err_alloc_bit_data;
	mux = kzalloc(sizeof(*mux), GFP_KERNEL);
	if (!mux)
		goto err_alloc_mux;
	mux->adap = kzalloc(sizeof(struct i2c_adapter *) * pdata->num_scl,
			    GFP_KERNEL);
	if (!mux->adap) {
		goto err_alloc_mux_adap;
	}

	ret = gpio_request(pdata->sda_pin, "sda");
	if (ret)
		goto err_request_sda;
	for (i = 0; i < pdata->num_scl; ++i) {
		ret = gpio_request(pdata->scl_pins[i], "scl");
		if (ret)
			goto err_request_scls;
		gpio_direction_input(pdata->scl_pins[i]);
	}
	if (pdata->sda_is_open_drain) {
		gpio_direction_output(pdata->sda_pin, 1);
		bit_data->setsda = i2c_gpio_scl_setsda_val;
	} else {
		gpio_direction_input(pdata->sda_pin);
		bit_data->setsda = i2c_gpio_scl_setsda_dir;
	}

	bit_data->setscl = i2c_gpio_scl_setscl_dir;

	bit_data->getscl = i2c_gpio_scl_getscl;
	bit_data->getsda = i2c_gpio_scl_getsda;

	if (pdata->udelay)
		bit_data->udelay = pdata->udelay;
	else
		bit_data->udelay = 5;			/* 100 kHz */

	if (pdata->timeout)
		bit_data->timeout = pdata->timeout;
	else
		bit_data->timeout = HZ / 10;		/* 100 ms */

	bit_data->data = pdata;

	adap->owner = THIS_MODULE;
	snprintf(adap->name, sizeof(adap->name), "i2c-gpio-scl%d", pdev->id);
	adap->algo_data = bit_data;
	adap->class = I2C_CLASS_HWMON | I2C_CLASS_SPD;
	adap->dev.parent = &pdev->dev;

	adap->nr = pdata->parent_id;
	ret = i2c_bit_add_numbered_bus(adap);
	if (ret)
		goto err_add_adap;

	platform_set_drvdata(pdev, mux);

	dev_info(&pdev->dev, "using pins %u (SDA) and %u (SCL)\n",
		 pdata->sda_pin, pdata->scl_pins[0]);

	mux->parent = adap;
	mux->data = pdata;

	for (j = 0; j < pdata->num_scl; j++) {
		u32 nr = pdata->child_id_base ? (pdata->child_id_base + j) : 0;

		mux->adap[j] = i2c_add_mux_adapter(adap, &pdev->dev, mux, nr, j, 0,
						   i2c_gpio_scl_select, NULL);
		if (!mux->adap[j]) {
			ret = -ENODEV;
			dev_err(&pdev->dev, "Failed to add adapter %d\n", j);
			goto err_add_mux_adap;
		}
	}
	return 0;

err_add_mux_adap:
	while (j > 0)
		i2c_del_mux_adapter(mux->adap[--j]);
	i2c_del_adapter(adap);
err_add_adap:
err_request_scls:
	while (i > 0)
		gpio_free(pdata->scl_pins[--i]);
	gpio_free(pdata->sda_pin);
err_request_sda:
	kfree(mux->adap);
err_alloc_mux_adap:
	kfree(mux);
err_alloc_mux:
	kfree(bit_data);
err_alloc_bit_data:
	kfree(adap);
err_alloc_adap:
	return ret;
}

static int i2c_gpio_scl_remove(struct platform_device *pdev)
{
	struct i2c_gpio_scl_platform_data *pdata;
	struct i2c_adapter *adap;
	struct sclmux *mux;
	int i;

	mux = platform_get_drvdata(pdev);
	adap = mux->parent;
	pdata = pdev->dev.platform_data;

        for (i = 0; i < pdata->num_scl; ++i)
		i2c_del_adapter(mux->adap[i]);

	i2c_del_adapter(adap);

	for (i = 0; i < pdata->num_scl; ++i)
		gpio_free(pdata->scl_pins[i]);

	gpio_free(pdata->sda_pin);
	kfree(mux->adap);
	kfree(mux);
	kfree(adap->algo_data);
	kfree(adap);

	return 0;
}

static struct platform_driver i2c_gpio_scl_driver = {
	.driver = {
		.name	= "i2c-gpio-scl",
		.owner	= THIS_MODULE,
	},
	.probe	= i2c_gpio_scl_probe,
	.remove = i2c_gpio_scl_remove,
};

static int __init i2c_gpio_scl_init(void)
{
	int ret;

	ret = platform_driver_register(&i2c_gpio_scl_driver);
	if (ret)
		printk(KERN_ERR "i2c-gpio-scl: probe failed: %d\n", ret);

	return ret;
}
module_init(i2c_gpio_scl_init);

static void __exit i2c_gpio_scl_exit(void)
{
	platform_driver_unregister(&i2c_gpio_scl_driver);
}
module_exit(i2c_gpio_scl_exit);

MODULE_AUTHOR("James Parks <james.parks@meraki.net>");
MODULE_DESCRIPTION("Bitbanging SCL multiplexed I2C driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:i2c-gpio-scl");
