/*
 * Meraki GPIO configuration
 *
 * Copyright 2015 Cisco Systems
 * Willy Hauser <whauser@meraki.net>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */

#include <linux/of_platform.h>
#include <linux/of_gpio.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>

#include <mach/gpio_cfg.h>

void gpio_cfgpin(struct gpio_cfg *cfg, unsigned int pin, unsigned int config)
{
	unsigned val;
	switch (config) {
		case GPIO_GENERAL:
			val = __raw_readl(cfg->cru_gpio_addr + CRU_GPIO_GENERAL_OFFSET);
			if (pin <= 17 || (21 <= pin && pin <= 25) || (28 <= pin && pin < 32)) {
				val |= 1 << pin;
			} else {
				val &= ~(1 << pin);
			}
			__raw_writel(val, cfg->cru_gpio_addr + CRU_GPIO_GENERAL_OFFSET);
			break;
		case GPIO_PULL_UP:
			val = __raw_readl(cfg->cru_gpio_addr + CRU_GPIO_PULL_UP_OFFSET);
			val |= 1 << pin;
			__raw_writel(val, cfg->cru_gpio_addr + CRU_GPIO_PULL_UP_OFFSET);
			/* We must unset the corresponding pull down bit */
			val = __raw_readl(cfg->cru_gpio_addr + CRU_GPIO_PULL_DOWN_OFFSET);
			val &= ~(1 << pin);
			__raw_writel(val, cfg->cru_gpio_addr + CRU_GPIO_PULL_DOWN_OFFSET);
			break;
		case GPIO_AUX_FUN:
			val = __raw_readl(cfg->aux_sel_addr);
			val |= 1 << (pin - GPIO_AUX_OFFSET);
			__raw_writel(val, cfg->aux_sel_addr);
			break;
	}
}

void board_cfgpin(struct gpio_cfg *cfg, struct property *prop, int state)
{
	int sz;
	const __be32 *val;

	if (!prop)
		return;

	sz = prop->length / 4;
	val = prop->value;
	while (sz--) {
		pr_debug("%s: gpio %d is %s\n", __func__, be32_to_cpup(val),
			state==GPIO_GENERAL?"General":state==GPIO_AUX_FUN?"Aux":"Pullup");
		gpio_cfgpin(cfg, be32_to_cpup(val), state);
		val++;
	}
}

int board_set_gdata(struct gpio_data *gdata)
{
	int ret;
	int state;
	ret = gpio_request(gdata->gpio, "sysfs");
	if (ret < 0) {
		printk(KERN_ERR
			"%s: gpio_%d request failed, ret = %d\n",
			__func__, gdata->gpio, ret);
		return ret;
	}

	ret = gpio_sysfs_set_active_low(gdata->gpio, gdata->active_low);
	if (ret < 0) {
		printk(KERN_ERR
			"%s: gpio_%d set active_low failed, ret = %d\n",
			__func__, gdata->gpio, ret);
		return ret;
	}

	if (gdata->default_state == GPIO_DEFSTATE_KEEP)
		state = !!gpio_get_value_cansleep(gdata->gpio) ^ gdata->active_low;
	else
		state = (gdata->default_state == GPIO_DEFSTATE_ON);
	if (gdata->direction == GPIO_INPUT)
		ret = gpio_direction_input(gdata->gpio);
	else
		ret = gpio_direction_output(gdata->gpio, state ^ gdata->active_low);
	if (ret < 0) {
		printk(KERN_ERR
			"%s: gpio_%d set direction failed, ret = %d\n",
			__func__, gdata->gpio, ret);
		return ret;
	}

	ret = gpio_export(gdata->gpio, true);
	if (ret < 0) {
		printk(KERN_ERR
			"%s: gpio_%d export failed, ret = %d\n",
			__func__, gdata->gpio, ret);
		return ret;
	}
	return 0;
}

int board_exportgpio(struct device_node *np)
{
	struct gpio_data gdata = {};
	enum of_gpio_flags flags;
	const char *state;
	const char *direction;

	gdata.gpio = of_get_gpio_flags(np, 0, &flags);
	gdata.active_low = flags & OF_GPIO_ACTIVE_LOW;

	gdata.default_state = GPIO_DEFSTATE_KEEP;
	state = of_get_property(np, "default-state", NULL);
	if (state) {
		if (!strcmp(state, "off"))
			gdata.default_state = GPIO_DEFSTATE_OFF;
		else if (!strcmp(state, "on"))
			gdata.default_state = GPIO_DEFSTATE_ON;
		else
			gdata.default_state = GPIO_DEFSTATE_KEEP;
	}

	gdata.direction = GPIO_INPUT;
	direction = of_get_property(np, "direction", NULL);
	if (direction) {
		if (!strcmp(direction, "out"))
			gdata.direction = GPIO_OUTPUT;
		else
			gdata.direction = GPIO_INPUT;
	}

	return board_set_gdata(&gdata);
}

static int gpio_cfg_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct device *dev = &pdev->dev;
	struct property *prop;
	struct gpio_cfg *cfg;
	struct device_node *np = pdev->dev.of_node;
	struct device_node *child;
	int ret;

	// make sure all gpios are available
	for_each_available_child_of_node(np, child)
		if (of_get_gpio(child, 0) == -EPROBE_DEFER)
			return -EPROBE_DEFER;

	for_each_available_child_of_node(np, child) {
		ret = board_exportgpio(child);
		if (ret < 0) {
			of_node_put(child);
			return ret;
		}
	}

	cfg = devm_kzalloc(&pdev->dev, sizeof(*cfg), GFP_KERNEL);
	if (!cfg) {
		dev_err(&pdev->dev, "failed to allocate memory\n");
		return -ENOMEM;
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "cru-gpio-ctl");
	if (res == NULL) {
		cfg->cru_gpio_addr = NULL;
	} else {
		cfg->cru_gpio_addr = devm_ioremap_resource(dev, res);
		if (IS_ERR(cfg->cru_gpio_addr))
			return PTR_ERR(cfg->cru_gpio_addr);
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "aux-sel");
	if (res == NULL) {
		cfg->aux_sel_addr = NULL;
	} else {
		cfg->aux_sel_addr = devm_ioremap_resource(dev, res);
		if (IS_ERR(cfg->aux_sel_addr))
			return PTR_ERR(cfg->aux_sel_addr);
	}

	if (cfg->cru_gpio_addr != NULL) {
		prop = of_find_property(dev->of_node, "gpios-general", NULL);
		board_cfgpin(cfg, prop, GPIO_GENERAL);
		prop = of_find_property(dev->of_node, "gpios-pullup", NULL);
		board_cfgpin(cfg, prop, GPIO_PULL_UP);
	}
	if (cfg->aux_sel_addr != NULL) {
		prop = of_find_property(dev->of_node, "gpios-aux", NULL);
		board_cfgpin(cfg, prop, GPIO_AUX_FUN);
	}

	return 0;
}

static int gpio_cfg_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gpio_cfg *cfg = platform_get_drvdata(pdev);

	devm_iounmap(dev, cfg->cru_gpio_addr);
	devm_iounmap(dev, cfg->aux_sel_addr);

	return 0;
}

static const struct of_device_id gpio_cfg_dt_match[] = {
	{ .compatible = "iproc-gpio-cfg", },
	{}
};

static struct platform_driver gpio_cfg_driver = {
	.driver		= {
		.name = "gpio_cfg",
		.owner = THIS_MODULE,
		.of_match_table = gpio_cfg_dt_match,
	},
	.probe		= gpio_cfg_probe,
	.remove		= gpio_cfg_remove,
};

static int __init gpio_cfg_init(void)
{
	return platform_driver_register(&gpio_cfg_driver);
}

static void __exit gpio_cfg_exit(void)
{
	platform_driver_unregister(&gpio_cfg_driver);
}

module_init(gpio_cfg_init);
module_exit(gpio_cfg_exit);

MODULE_AUTHOR("Meraki, Inc.");
MODULE_DESCRIPTION("Driver for GPIO config");
MODULE_LICENSE("GPL");
