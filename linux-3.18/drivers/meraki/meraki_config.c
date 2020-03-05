/*
 *  Meraki board data config driver
 *
 *  Copyright (C) 2013-2015 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/platform_data/at24.h>
#include <linux/meraki/board_data.h>

#include <linux/meraki/meraki_config.h>

static struct memory_accessor *eeprom_accessor = NULL;
static struct device *config_dev = NULL;
static int wp_gpio = -1;
static bool wp_low = false;
static uint32_t eeprom_size = 0;

struct board_table_element {
    const char *board_name;
    int board_type;
};

static const struct board_table_element board_table[] = {
    { "meraki_MS220-48 600-21030", MERAKI_BOARD_MS220_48 },
    { "meraki_MS220-48LP 600-21040", MERAKI_BOARD_MS220_48LP },
    { "meraki_MS220-48FP 600-21050", MERAKI_BOARD_MS220_48FP },

    { "meraki_MS220-24 600-20030", MERAKI_BOARD_MS220_24 },
    { "meraki_MS220-24P 600-20040", MERAKI_BOARD_MS220_24P },

    { "meraki_MS320-24 600-20050", MERAKI_BOARD_MS320_24 },
    { "meraki_MS320-24P 600-20060", MERAKI_BOARD_MS320_24P },

    { "meraki_MS320-48 600-21060", MERAKI_BOARD_MS320_48 },
    { "meraki_MS320-48LP 600-21070", MERAKI_BOARD_MS320_48LP },
    { "meraki_MS320-48FP 600-21080", MERAKI_BOARD_MS320_48FP },

    { "meraki_MS350-24 600-36010", MERAKI_BOARD_MS350_24 },
    { "meraki_MS350-24P 600-36020", MERAKI_BOARD_MS350_24P },
    { "meraki_MS350_48 600-36030", MERAKI_BOARD_MS350_48 },
    { "meraki_MS350_48LP 600-36040", MERAKI_BOARD_MS350_48LP },
    { "meraki_MS350_48FP 600-36050", MERAKI_BOARD_MS350_48FP },

    { "meraki_MS420-24 600-29020", MERAKI_BOARD_MS420_24 },
    { "meraki_MS420-48 600-29010", MERAKI_BOARD_MS420_48 },

};


#if defined(CONFIG_OF)

static const struct of_device_id meraki_config_dt_ids[] = {
    { .compatible = "meraki,meraki-config" },
};

#endif

static DEFINE_MUTEX(fops_lock);

#define MERAKI_CONFIG_EEPROM_MAX_SIZE  8192

// Too big for stack.  Since reads and writes are mutex-protected we
// can make this a static variable.
static uint8_t meraki_config_buf[MERAKI_CONFIG_EEPROM_MAX_SIZE];

static ssize_t meraki_config_board_data_read(struct file* f, char __user *buf, size_t count, loff_t* offset)
{
    ssize_t ret = 0;

    if (!eeprom_accessor)
        return -ENODEV;

    if (*offset >= eeprom_size)
        return 0;

    if (count > (eeprom_size - *offset))
        count = eeprom_size - *offset;

    mutex_lock(&fops_lock);
    ret = eeprom_accessor->read(eeprom_accessor, meraki_config_buf, *offset, count);
    mutex_unlock(&fops_lock);

    if (ret > 0 && copy_to_user(buf, meraki_config_buf, ret)) {
        ret = -EFAULT;
    }

    if (ret > 0)
        *offset += ret;

    return ret;
}

static ssize_t meraki_config_board_data_write(struct file* f, const char __user *buf, size_t count, loff_t* offset)
{
    ssize_t ret = 0;

    if (!eeprom_accessor)
        return -ENODEV;

    if (*offset >= eeprom_size)
        return 0;

    if (count > (eeprom_size - *offset))
        count = eeprom_size - *offset;

    if (copy_from_user(meraki_config_buf, buf, count))
        ret = -EFAULT;
    else {
        mutex_lock(&fops_lock);
        if (wp_gpio >= 0)
            gpio_set_value_cansleep(wp_gpio, !wp_low);
        ret = eeprom_accessor->write(eeprom_accessor, meraki_config_buf, *offset, count);
        if (wp_gpio >= 0)
            gpio_set_value_cansleep(wp_gpio, wp_low);
        mutex_unlock(&fops_lock);
    }

    if (ret > 0)
        *offset += ret;

    return ret;
}

static loff_t meraki_config_board_data_llseek(struct file* f, loff_t offset, int orig)
{
    loff_t new_offset;

    switch (orig) {
    case SEEK_SET:
        new_offset = offset;
        break;
    case SEEK_CUR:
        new_offset = f->f_pos + offset;
        break;
    case SEEK_END:
        new_offset = eeprom_size + offset;
        break;
    default:
        return -EINVAL;
    }

    if (new_offset >= eeprom_size || new_offset < 0)
        return -EINVAL;

    f->f_pos = new_offset;

    return new_offset;
}


int meraki_config_get_product()
{
    struct ar531x_boarddata board_data;
    int i, retries = 5, ret;
    ssize_t count = 0, board_name_len;
    unsigned short csum;

    if (!eeprom_accessor) {
        return MERAKI_BOARD_UNKNOWN;
    }

    do {
        ret = eeprom_accessor->read(eeprom_accessor, ((char *)&board_data) + count, count, sizeof(board_data) - count);
        if (ret < 0)
            continue;

        count += ret;
        if (count >= sizeof(board_data))
            break;
    } while (--retries);

    if (!retries) {
        dev_warn(config_dev, "Failure to read from eeprom\n");
        return MERAKI_BOARD_UNKNOWN;
    }

    if (ntohl(board_data.magic) != AR531X_BD_MAGIC) {
        dev_warn(config_dev, "Board data has bad magic field\n");
        return MERAKI_BOARD_UNKNOWN;
    }

    csum = calc_board_data_checksum(&board_data);
    if (csum != 0 && csum != ntohs(board_data.cksum)) {
        dev_warn(config_dev, "Board data has bad checksum\n");
        return MERAKI_BOARD_UNKNOWN;
    }

    for (i = 0; i < ARRAY_SIZE(board_table); ++i) {
        board_name_len = strlen(board_table[i].board_name);
        if (strncmp(&board_data.boardName[0], board_table[i].board_name, board_name_len) == 0 &&
            (board_data.boardName[board_name_len] == '\0' || board_data.boardName[board_name_len] == '-')) {
            return board_table[i].board_type;
        }
    }

    return MERAKI_BOARD_UNKNOWN;
}
EXPORT_SYMBOL(meraki_config_get_product);

#if defined(CONFIG_OF_I2C)
static struct i2c_client* find_of_i2c_client(struct device_node* node)
{
    const __be32* i2cp;
    struct device_node* client_node;

    i2cp = of_get_property(node, "i2c-eeprom", NULL);
    if (i2cp == NULL)
        return NULL;

    client_node = of_find_node_by_phandle(be32_to_cpup(i2cp));
    if (!client_node)
        return NULL;

    return of_find_i2c_device_by_node(client_node);
}

#else
inline struct i2c_client* find_of_i2c_client(struct device_node* node)
{
    return NULL;
}

#endif

static int i2c_find_match(struct device* dev, void* data)
{
    return (dev->platform_data == data);
}


static struct i2c_client* find_i2c_client(struct meraki_config_platform_data* data)
{
    struct device* dev;

    if (data->eeprom_data == NULL)
        return NULL;

    dev = bus_find_device(&i2c_bus_type, NULL, data->eeprom_data,
                          i2c_find_match);

    if (!dev)
        return NULL;

    return i2c_verify_client(dev);
}

static struct file_operations meraki_config_fileops = {
    .owner = THIS_MODULE,
    .read = meraki_config_board_data_read,
    .write = meraki_config_board_data_write,
    .llseek = meraki_config_board_data_llseek,
};

static struct miscdevice meraki_config_miscdevice = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "meraki-board-config",
    .fops = &meraki_config_fileops,
};

static int meraki_config_probe(struct platform_device *pdev)
{
    struct meraki_config_platform_data *pdata = pdev->dev.platform_data;
    int ret;
    struct i2c_client* client;
    struct i2c_driver* drv;

    if (eeprom_accessor) {
        dev_err(&pdev->dev, "Cannot have more than one meraki-config\n");
        return -ENODEV;
    }
    pdev->id = -1;

    config_dev = &pdev->dev;

    if (pdev->dev.of_node) {
        client = find_of_i2c_client(pdev->dev.of_node);
        if (of_gpio_count(pdev->dev.of_node) > 0) {
            enum of_gpio_flags flags;
            wp_gpio = of_get_gpio_flags(pdev->dev.of_node, 0, &flags);
            if (wp_gpio < 0) {
                dev_err(&pdev->dev, "GPIO configuration incorrect\n");
                return wp_gpio;
            }
            if (flags & OF_GPIO_ACTIVE_LOW)
                wp_low = true;
        }
    } else {
        client = find_i2c_client(pdata);
        wp_gpio = pdata->write_protect_gpio;
        wp_low = pdata->write_protect_active_low;
    }

    if (!client || !client->dev.driver)
        return -ENODEV;

    if (wp_gpio >= 0) {
        ret = gpio_request_one(wp_gpio,
                               (wp_low ? GPIOF_OUT_INIT_HIGH : GPIOF_OUT_INIT_LOW),
                               "meraki-config WP");
        if (ret) {
            dev_err(&pdev->dev, "Unable to request write protect GPIO, error %d\n", ret);
            return -ENODEV;
        }
    }

    ret = -ENODEV;
    drv = to_i2c_driver(client->dev.driver);
    if (!drv || !drv->command) {
        put_device(&client->dev);
        dev_err(&pdev->dev, "Failed to get AT24 command function\n");
        goto err;
    } else {
        ret = drv->command(client, AT24_CMD_GET_ACCESSOR, &eeprom_accessor);
        if (ret) {
            put_device(&client->dev);
            dev_err(&pdev->dev, "Failed to get eeprom_accessor\n");
            goto err;
        }

        ret = drv->command(client, AT24_CMD_GET_SIZE, &eeprom_size);
        put_device(&client->dev);
        if (ret || (eeprom_size == 0)) {
            dev_err(&pdev->dev, "Failed to get eeprom_size\n");
            goto err;
        }
    }

    if (eeprom_size > MERAKI_CONFIG_EEPROM_MAX_SIZE) {
        dev_err(&pdev->dev, "EEPROM too big; maximum of 8192 bytes supported\n");
        ret = -EINVAL;
        goto err;
    }

    ret = misc_register(&meraki_config_miscdevice);
    if (ret) {
        dev_err(&pdev->dev, "Failed to register misc device, error %d\n", ret);
        goto err;
    }

    dev_info(&pdev->dev, "Meraki config device loaded\n");
    return 0;

err:
    if (wp_gpio)
        gpio_free(wp_gpio);

    return -ENODEV;
}

static int meraki_config_remove(struct platform_device *pdev)
{
    if (wp_gpio >= 0)
        gpio_free(wp_gpio);
    misc_deregister(&meraki_config_miscdevice);
    eeprom_accessor = NULL;
    config_dev = NULL;
    wp_gpio = -1;
    wp_low = false;

    return 0;
}

static struct platform_driver meraki_config_driver = {
	.driver		= {
		.name	= "meraki-config",
		.owner	= THIS_MODULE,
#if defined(CONFIG_OF)
		.of_match_table = meraki_config_dt_ids,
#endif
	},
	.probe		= meraki_config_probe,
	.remove		= meraki_config_remove,
};

static int __init meraki_config_init(void)
{
    int ret;
    ret = platform_driver_register(&meraki_config_driver);
    if (ret)
        printk(KERN_ERR "meraki-config: driver init failed: %d\n", ret);

    return ret;
}
module_init(meraki_config_init);

static void __exit meraki_config_exit(void)
{
    platform_driver_unregister(&meraki_config_driver);
}
module_exit(meraki_config_exit);


MODULE_AUTHOR("J. Chris Parks <jamparks@cisco.com>");
MODULE_DESCRIPTION("Meraki board data config driver");
MODULE_LICENSE("GPL");
