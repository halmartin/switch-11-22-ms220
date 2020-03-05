/*
 *  Meraki small form-factor pluggable (SFP/SFP+) transceiver
 *  user-space proxy driver
 *
 *  Copyright (C) 2013-2015 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/idr.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/meraki/sfp_user.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>

static struct class sfp_user_class = {
    .name = "sfpu"
};

static const char* sfp_user_gpio_names[] = {
    "mod_abs",
    "rx_los",
    "rs0",
    "rs1",
    "lpmode",
    "mod_sel",
    "tx_dis",
};


struct sfp_user_data {
    struct device* dev;

    struct device nested_dev;
};

static DEFINE_IDR(sfp_user_idr);
static DEFINE_MUTEX(sfp_user_idr_mutex);

#if defined(CONFIG_OF_GPIO) && defined(CONFIG_OF_I2C)

static int sfp_user_of_init(struct device* dev)
{
    struct sfp_user_platform_data* pdata;
    struct device_node* i2c_node;
    int res;

    pdata = devm_kzalloc(dev, sizeof(struct sfp_user_platform_data), GFP_KERNEL);
    if (!pdata)
        return -ENOMEM;

    res = of_property_read_u32(dev->of_node, "id", &pdata->id);
    if (res < 0)
        return res;

    pdata->gpios[SFP_USER_GPIO_MOD_ABS] = of_get_named_gpio(dev->of_node, "mod-abs", 0);
    if (pdata->gpios[SFP_USER_GPIO_MOD_ABS] < 0)
        pdata->gpios[SFP_USER_GPIO_MOD_ABS] = of_get_named_gpio(dev->of_node, "mod-pres", 0);

    pdata->gpios[SFP_USER_GPIO_RX_LOS] = of_get_named_gpio(dev->of_node, "rx-los", 0);
    pdata->gpios[SFP_USER_GPIO_RS0] = of_get_named_gpio(dev->of_node, "rs0", 0);
    pdata->gpios[SFP_USER_GPIO_RS1] = of_get_named_gpio(dev->of_node, "rs1", 0);
    pdata->gpios[SFP_USER_GPIO_LPMODE] = of_get_named_gpio(dev->of_node, "lpmode", 0);
    pdata->gpios[SFP_USER_GPIO_MOD_SEL] = of_get_named_gpio(dev->of_node, "mod-sel", 0);
    pdata->gpios[SFP_USER_GPIO_TX_DIS] = of_get_named_gpio(dev->of_node, "tx-dis", 0);

    pdata->i2c_adapter_id = -1;

    i2c_node = of_parse_phandle(dev->of_node, "i2c", 0);
    if (i2c_node != NULL) {
        struct i2c_adapter* adap = of_find_i2c_adapter_by_node(i2c_node);
        if (adap == NULL) {
            dev_err(dev, "i2c node not an i2c adapter\n");
            return -EINVAL;
        }
        pdata->i2c_adapter_id = i2c_adapter_id(adap);
        i2c_put_adapter(adap);
    }

    dev->platform_data = pdata;

    return 0;
}


#else

static inline int sfp_user_of_init(struct device* dev)
{
    return -EINVAL;
}

#endif

static ssize_t sfp_show_i2c_adapter_id(struct device* dev,
                                       struct device_attribute* attr,
                                       char* buf)
{
    struct sfp_user_data* data = dev_get_drvdata(dev);
    struct sfp_user_platform_data* pdata = data->dev->platform_data;

    return scnprintf(buf, PAGE_SIZE, "%d\n", pdata->i2c_adapter_id);
}

static DEVICE_ATTR(i2c_adapter_id, 0444, sfp_show_i2c_adapter_id, NULL);

static void sfp_device_release(struct device* dev)
{
    int i;

    for (i = 0; i < SFP_USER_GPIO_MAX; i++)
        sysfs_remove_link(&dev->kobj, sfp_user_gpio_names[i]);

    sysfs_remove_link(&dev->kobj, "i2c_adapter");
    device_remove_file(dev, &dev_attr_i2c_adapter_id);
}

static struct device_type sfp_device_type = {
    .release = sfp_device_release,
};

static int sfp_user_probe(struct platform_device *pdev)
{
    int res, i;
    struct sfp_user_platform_data* pdata;
    struct sfp_user_data* data;

    if (!pdev->dev.platform_data) {
        if (pdev->dev.of_node) {
            res = sfp_user_of_init(&pdev->dev);
            if (res < 0)
                return res;
        } else {
            dev_err(&pdev->dev, "No config data specified!\n");
            return -EINVAL;
        }
    }

    pdata = pdev->dev.platform_data;

    data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    data->dev = &pdev->dev;

    mutex_lock(&sfp_user_idr_mutex);
    res = idr_alloc(&sfp_user_idr, pdev, pdata->id, pdata->id+1, GFP_KERNEL);
    mutex_unlock(&sfp_user_idr_mutex);
    if (res < 0) {
        dev_err(&pdev->dev, "idr_alloc failed: %d\n", res);
        return res;
    }

    data->nested_dev.class = &sfp_user_class;
    data->nested_dev.parent = data->dev;
    data->nested_dev.type = &sfp_device_type;
    dev_set_name(&data->nested_dev, "sfp%d", pdata->id);

    res = device_register(&data->nested_dev);
    if (res < 0) {
        dev_err(data->dev, "Unable to create nested device: %d\n", res);
        return res;
    }

    for (i = 0; i < SFP_USER_GPIO_MAX; i++) {
        if (pdata->gpios[i] > 0) {
            res = gpio_request((unsigned)pdata->gpios[i], sfp_user_gpio_names[i]);
            if (res < 0) {
                dev_err(&pdev->dev, "gpio_request failed for gpio %d (%s): %d\n",
                        pdata->gpios[i], sfp_user_gpio_names[i], res);
                continue;
            }
            res = gpio_export((unsigned)pdata->gpios[i], true);
            if (res < 0) {
                dev_err(&pdev->dev, "gpio_export failed for gpio %d (%s): %d\n",
                        pdata->gpios[i], sfp_user_gpio_names[i], res);
                continue;
            }
            res = gpio_export_link(&data->nested_dev, sfp_user_gpio_names[i], (unsigned)pdata->gpios[i]);
            if (res < 0)
                dev_err(&pdev->dev, "gpio_export_link failed for gpio %d (%s): %d\n",
                        pdata->gpios[i], sfp_user_gpio_names[i], res);
        }
    }

    if (pdata->i2c_adapter_id >= 0) {
        struct i2c_adapter* adap = i2c_get_adapter(pdata->i2c_adapter_id);
        if (!adap) {
            dev_err(&pdev->dev, "Unable to verify i2c adapter\n");
            return -EINVAL;
        }
        res = device_create_file(&data->nested_dev, &dev_attr_i2c_adapter_id);
        if (res < 0) {
            dev_err(&pdev->dev, "Unable to create i2c_adapter_id file\n");
            i2c_put_adapter(adap);
            return res;
        }
        res = sysfs_create_link(&data->nested_dev.kobj, &adap->dev.kobj, "i2c_adapter");
        i2c_put_adapter(adap);
        if (res < 0) {
            dev_err(&pdev->dev, "Unable to create link for i2c: %d\n", res);
            return res;
        }
    }

    dev_set_drvdata(data->dev, data);
    dev_set_drvdata(&data->nested_dev, data);

    return 0;
}

static int sfp_user_remove(struct platform_device* pdev)
{
    struct sfp_user_data* data = platform_get_drvdata(pdev);

    device_unregister(&data->nested_dev);

    return 0;
}

static const struct of_device_id sfp_user_dt_ids[] = {
    { .compatible = "meraki,sfp-user" },
    {}
};

static struct platform_driver sfp_user_driver = {
    .driver = {
        .name = "sfp-user",
        .owner = THIS_MODULE,
        .of_match_table = sfp_user_dt_ids,
    },
    .probe = sfp_user_probe,
    .remove = sfp_user_remove,
};

static int __init sfp_user_init(void)
{
    int ret;

    ret = class_register(&sfp_user_class);
    if (ret < 0)
        return ret;

    ret = platform_driver_register(&sfp_user_driver);
    if (ret) {
        printk(KERN_ERR "sfp-user: driver init failed: %d\n", ret);
        return ret;
    }

    return 0;
}
late_initcall(sfp_user_init);

static void __exit sfp_user_exit(void)
{
    platform_driver_unregister(&sfp_user_driver);
    class_unregister(&sfp_user_class);
}
module_exit(sfp_user_exit);


MODULE_AUTHOR("Stephen Segal <ssegal@meraki.com>");
MODULE_DESCRIPTION("Meraki SFP user-mode proxy driver");
MODULE_LICENSE("GPL");
