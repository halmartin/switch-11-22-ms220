/* cisco-act-spi.c - a device driver for the Cisco ACT2 chip  */
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2016 Cisco Systems, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.                */
/* ------------------------------------------------------------------------- */

/* Initial driver commit by Hart Thomson <hthomson@meraki.com> */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/spi/spi.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of_gpio.h>
#include <linux/of_gpio.h>
#include <linux/input.h>
#include <linux/meraki/cisco-act.h>


/*
 * If you are using a SPI bus that only supports a single device, then it may
 * be necessary to use a GPIO as your chip select signal (for example,
 * qspi_iproc, the SPI driver for the boot bus on HHH). Uncomment this flag
 * and add a "gpio-cs" directive in your dtsi. Do not use in production,
 * testing only.
 *
 */
//#define CISCO_ACT_SPI_CS_DEBUG

/* Default SPI Frequency set to 10 MHz */
#define DEFAULT_MAX_SPEED_HZ 125000

static u8* spi_tx_buf;

static unsigned gpio_cs;

static const struct spi_device_id cisco_act_spi_ids[] = {
	{ "act-spi", 0 },
	{ /* END OF LIST */ }
};

MODULE_DEVICE_TABLE(spi, cisco_act_spi_ids);

static const struct of_device_id __maybe_unused cisco_act_dt_ids[] = {
	{ .compatible = "cisco,act-spi", },
	{ /* END OF LIST */ }
};
MODULE_DEVICE_TABLE(of, cisco_act_dt_ids);

static ssize_t act_data_read_spi(struct act_data *act,
				 char *buf,
				 unsigned offset,
				 size_t count )
{
	int status;
	struct spi_device *spi = act->bus_dev;
	struct spi_message msg;
	struct spi_transfer xfer;

	if (!spi) {
		printk(KERN_ERR "cisco-act-spi write failed to get device\n");
		return 0;
	}

	mutex_lock(&act->lock);

	status = count;

	xfer.len = count;
	xfer.rx_buf = spi_tx_buf;
	xfer.tx_buf = act->writebuf;
	xfer.bits_per_word = spi->bits_per_word;
	xfer.speed_hz = spi->max_speed_hz;

	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);

#ifdef CISCO_ACT_SPI_CS_DEBUG
	gpio_set_value(gpio_cs, 0);
#endif

	status = spi_sync(spi, &msg);

#ifdef CISCO_ACT_SPI_CS_DEBUG
	gpio_set_value(gpio_cs, 1);
#endif

	memcpy(buf, spi_tx_buf, count);

	mutex_unlock(&act->lock);

	if (status == 0)
		return count;

	return -EIO;
}

static ssize_t act_data_write_spi(struct act_data *act,
				  const char *buf,
				  unsigned offset,
				  size_t count )
{
	int status;
	struct spi_device *spi = act->bus_dev;
	struct spi_message msg;
	struct spi_transfer xfer;

	if (!spi) {
		printk(KERN_ERR "cisco-act-spi write failed to get device\n");
		return 0;
	}

	memset(&xfer, 0, sizeof(struct spi_transfer));
	memcpy(spi_tx_buf, buf, count);

	mutex_lock(&act->lock);

	xfer.len = count;
	xfer.rx_buf = act->writebuf;
	xfer.tx_buf = spi_tx_buf;
	xfer.bits_per_word = spi->bits_per_word;
	xfer.speed_hz = spi->max_speed_hz;

	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);

#ifdef CISCO_ACT_SPI_CS_DEBUG
	gpio_set_value(gpio_cs, 0);
#endif

	status = spi_sync(spi, &msg);

#ifdef CISCO_ACT_SPI_CS_DEBUG
	gpio_set_value(gpio_cs, 1);
#endif

	mutex_unlock(&act->lock);

	if (status == 0)
		return count;

	return -EIO;
}

static const struct cisco_act_bus_ops cisco_act_spi_ops = {
	.bustype = BUS_SPI,
	.read = act_data_read_spi,
	.write = act_data_write_spi,
};

static int cisco_act_spi_probe(struct spi_device *spi)
{
	struct act_data *act;
	int err;
	enum of_gpio_flags gpio_cs_flags;

	err = of_property_read_u32(spi->dev.of_node,
				   "spi-max-frequency",
				   &spi->max_speed_hz);
	if (err < 0)
	{
		spi->max_speed_hz = DEFAULT_MAX_SPEED_HZ;
	}


	/* Initialize spi_device before common_probe
	*/
	spi->mode = SPI_MODE_0;
	spi->bits_per_word = 8;
	err = spi_setup(spi);
	if (err) {
		goto fail_init_spi;
	}

#ifdef CISCO_ACT_SPI_CS_DEBUG
	/* Initialize a GPIO to be used as CS incase the default won't work */
	gpio_cs = of_get_named_gpio_flags(spi->dev.of_node, "gpio-cs", 0,
					  &gpio_cs_flags);
	gpio_set_value(gpio_cs, 1);
#endif

	/* Common probe functions */
	act = cisco_act_common_probe(&spi->dev, &cisco_act_spi_ops);
	if (IS_ERR(act)) {
		err = PTR_ERR(act);
		goto fail_init_spi;
	}

	/* This buffer must be DMA-friendly */
	spi_tx_buf = devm_kzalloc(&spi->dev, act->writebuf_size, GFP_KERNEL);
	if (!spi_tx_buf) {
		err = -ENOMEM;
		goto fail_init_spi;
	}

	act->bus_dev = spi;

	return 0;

fail_init_spi:
	return err;
}

static struct spi_driver cisco_act_spi_driver = {
	.driver = {
		.name       = "cisco-act-spi",
		.owner      = THIS_MODULE,
	},
	.probe      = cisco_act_spi_probe,
	.id_table   = cisco_act_spi_ids,
};

module_spi_driver(cisco_act_spi_driver);

MODULE_AUTHOR("Hart A. Thomson <hthomson@meraki.com>");
MODULE_DESCRIPTION("Device driver for ACT2");
MODULE_LICENSE("GPL");
