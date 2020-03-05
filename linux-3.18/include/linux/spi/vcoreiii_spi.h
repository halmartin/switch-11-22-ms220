/*
 *
 * VCore-III SPI
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
 * This is a bitbang driver for the SPI master hardware on the VCore-III.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include <linux/spi/spi.h>
#include <linux/spi/spi_bitbang.h>
#include <linux/spi/spi_gpio.h>

#include <asm/mach-vcoreiii/hardware.h>

#ifdef CONFIG_SPI_MASTER

#define VCOREIII_SPI_N_CHIPSEL 4

static inline void setsck(const struct spi_device *spi, int is_on)
{
	if (is_on)
		vcoreiii_io_set(VTSS_ICPU_CFG_SPI_MST_SW_MODE,
				VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SCK);
	else
		vcoreiii_io_clr(VTSS_ICPU_CFG_SPI_MST_SW_MODE,
				VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SCK);
}

static inline void setmosi(const struct spi_device *spi, int is_on)
{
	if (is_on)
		vcoreiii_io_set(VTSS_ICPU_CFG_SPI_MST_SW_MODE,
				VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SDO);
	else
		vcoreiii_io_clr(VTSS_ICPU_CFG_SPI_MST_SW_MODE,
				VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SDO);
}

static inline int getmiso(const struct spi_device *spi)
{
	return (readl(VTSS_ICPU_CFG_SPI_MST_SW_MODE) &
		VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SDI) != 0;
}

#define spidelay(nsecs)	ndelay(nsecs)

#define	EXPAND_BITBANG_TXRX
#include <linux/spi/spi_bitbang.h>

static u32 spi_vcoreiii_txrx_word_mode0(struct spi_device *spi,
		unsigned nsecs, u32 word, u8 bits)
{
	return bitbang_txrx_be_cpha0(spi, nsecs, 0, word, bits);
}

static u32 spi_vcoreiii_txrx_word_mode1(struct spi_device *spi,
		unsigned nsecs, u32 word, u8 bits)
{
	return bitbang_txrx_be_cpha1(spi, nsecs, 0, word, bits);
}

static u32 spi_vcoreiii_txrx_word_mode2(struct spi_device *spi,
		unsigned nsecs, u32 word, u8 bits)
{
	return bitbang_txrx_be_cpha0(spi, nsecs, 1, word, bits);
}

static u32 spi_vcoreiii_txrx_word_mode3(struct spi_device *spi,
		unsigned nsecs, u32 word, u8 bits)
{
	return bitbang_txrx_be_cpha1(spi, nsecs, 1, word, bits);
}

static void spi_vcoreiii_chipselect(struct spi_device *spi, int is_active)
{
	unsigned long cs;

	if (unlikely(spi->mode & SPI_CS_HIGH))
		cs = 1 << (unsigned long) spi->controller_data;
	else
		cs = ~(1 << (unsigned long) spi->controller_data);

	if (is_active) {
		writel(VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_PIN_CTRL_MODE |
		       (spi->mode & SPI_CPOL ?
			VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SCK : 0) |
		       VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SCK_OE |
		       /* idle value for SW_SPI_SD0? */
		       VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_SDO_OE |
		       VTSS_F_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_CS(cs) |
		       VTSS_X_ICPU_CFG_SPI_MST_SW_MODE_SW_SPI_CS_OE(-1),
		       VTSS_ICPU_CFG_SPI_MST_SW_MODE);
	} else {
		writel(0, VTSS_ICPU_CFG_SPI_MST_SW_MODE);
		ndelay(200);
	}
}

static int __init spi_vcoreiii_probe(struct platform_device *pdev)
{
	int				status;
	struct spi_master		*master;
	struct spi_bitbang		*spi_bitbang;

	master = spi_alloc_master(&pdev->dev, sizeof (struct spi_bitbang));
	if (!master) {
		return -ENOMEM;
	}

	spi_bitbang = spi_master_get_devdata(master);
	platform_set_drvdata(pdev, spi_bitbang);

	master->bus_num = pdev->id;
	master->num_chipselect = VCOREIII_SPI_N_CHIPSEL;

	spi_bitbang->master = spi_master_get(master);
	spi_bitbang->chipselect = spi_vcoreiii_chipselect;
	spi_bitbang->txrx_word[SPI_MODE_0] = spi_vcoreiii_txrx_word_mode0;
	spi_bitbang->txrx_word[SPI_MODE_1] = spi_vcoreiii_txrx_word_mode1;
	spi_bitbang->txrx_word[SPI_MODE_2] = spi_vcoreiii_txrx_word_mode2;
	spi_bitbang->txrx_word[SPI_MODE_3] = spi_vcoreiii_txrx_word_mode3;

	status = spi_bitbang_start(spi_bitbang);
	if (status < 0) {
		spi_master_put(spi_bitbang->master);
		return status;
	}
	return 0;
}

static int __exit spi_vcoreiii_remove(struct platform_device *pdev)
{
	struct spi_bitbang		*spi_bitbang;
	int				status;

	spi_bitbang = platform_get_drvdata(pdev);

	/* stop() unregisters child devices too */
	status = spi_bitbang_stop(spi_bitbang);
	spi_master_put(spi_bitbang->master);

	platform_set_drvdata(pdev, NULL);

	return status;
}

#define DRIVER_NAME "vcoreiii_spi"

MODULE_ALIAS("platform:" DRIVER_NAME);

static struct platform_driver spi_vcoreiii_driver = {
	.driver.name	= DRIVER_NAME,
	.driver.owner	= THIS_MODULE,
	.remove		= __exit_p(spi_vcoreiii_remove),
};

static int __init spi_vcoreiii_init(void)
{
	if (vcoreiii_check_chip_id()) {
		return platform_driver_probe(&spi_vcoreiii_driver,
					     spi_vcoreiii_probe);
	}
	return -ENODEV;
}
module_init(spi_vcoreiii_init);

static void __exit spi_vcoreiii_exit(void)
{
	platform_driver_unregister(&spi_vcoreiii_driver);
}
module_exit(spi_vcoreiii_exit);

#endif /* CONFIG_SPI_MASTER */

MODULE_DESCRIPTION("SPI master driver for VCORE-III");
MODULE_AUTHOR("Kevin Paul Herbert");
MODULE_LICENSE("GPL");

