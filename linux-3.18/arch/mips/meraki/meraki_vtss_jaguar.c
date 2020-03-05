/*
 *
 * Meraki Jaguar-based switches spring-board code
 *
 * Copyright (c) 2013 Meraki, Inc.
 * Author: James Parks (james.parks@meraki.net)
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
 * This is spring-board code for MS4x switches.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/i2c-gpio.h>
#include <linux/i2c.h>
#include <linux/platform_data/at24.h>

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/phy8488_miim.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <linux/meraki/meraki_config.h>

static struct at24_platform_data jaguar_config_eeprom_plat_data = {
    .byte_len = 1024,
    .page_size = 8,
    .flags = AT24_FLAG_ADDR16,
    .setup = NULL,
    .context = NULL
};

static struct i2c_gpio_platform_data jaguar_config_i2c_controller_data = {
	.sda_pin = VCOREIII_GPIO_BASE + 15,
	.scl_pin = VCOREIII_GPIO_BASE + 14,
	.udelay = 10,
};

static struct meraki_config_platform_data jaguar_config_platform_data = {
	.eeprom_data = &jaguar_config_eeprom_plat_data,
	.write_protect_gpio = -1,
};

static struct i2c_board_info jaguar_config_eeprom_board_info = {
	I2C_BOARD_INFO("24c08", 0x51),
	.platform_data = &jaguar_config_eeprom_plat_data,
};


extern int ms42_late_init(void);
extern int ms220_48_late_init(uint8_t board_type);
extern int ms320_24_late_init(void);
extern int ms320_48_late_init(void);

static int board_is_ms42(void)
{
	/* Set the MDIO controller to Clause 45 operation */
	writel(VTSS_F_DEVCPU_GCB_MIIM_MII_CFG_MIIM_ST_CFG_FIELD(0) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CFG_MIIM_CFG_PRESCALE(0x32),
	       VTSS_DEVCPU_GCB_MIIM_MII_CFG(1));

	/* Legacy Layer 3 48-port (MS42) has 8488 PHYs at MDIO
	 * addresses 30,31 on the master and slave chips
	 */
	if (jaguar_phy8488_read(1, 30, 30, 0) == 0x8488)
		return 1;
	else
		return 0;
}

static int is_i2c_adapter(struct device* dev, void* data)
{
    return (dev->type == &i2c_adapter_type);
}

static struct i2c_adapter* i2c_adapter_from_platform_device(struct platform_device* pdev)
{
    struct device* dev = device_find_child(&pdev->dev, NULL, is_i2c_adapter);

    return (dev ? i2c_verify_adapter(dev) : NULL);
}

static int __init meraki_jaguar_late_init(void)
{
	int ret;
	uint8_t board_type;
	struct platform_device *adapter_dev, *eeprom_dev;
	struct i2c_adapter* i2c_adapt;
	struct i2c_client* i2c_client;

	if (!vcoreiii_check_chip_id())
		return -ENODEV;

	/* Set up our I2C adapter */
	adapter_dev = platform_device_alloc("i2c-gpio", 1);
	if (!adapter_dev)
		return -ENOMEM;

	ret = platform_device_add_data(adapter_dev, &jaguar_config_i2c_controller_data, sizeof(jaguar_config_i2c_controller_data));
	if (ret < 0)
		goto fail_adapter;

	ret = platform_device_add(adapter_dev);
	if (ret < 0)
		goto fail_adapter;

	/* Set up the eeprom device */
	i2c_adapt = i2c_adapter_from_platform_device(adapter_dev);
	if (i2c_adapt == NULL) {
		ret = -ENODEV;
		goto fail_i2c;
	}

	i2c_client = i2c_new_device(i2c_adapt, &jaguar_config_eeprom_board_info);
	if (i2c_client == NULL) {
		ret = -ENODEV;
		goto fail_i2c;
	}

	eeprom_dev = platform_device_alloc("meraki-config", -1);
	if (!eeprom_dev) {
		ret = -ENOMEM;
		goto fail_eeprom;
	}

	ret = platform_device_add_data(eeprom_dev, &jaguar_config_platform_data, sizeof(jaguar_config_platform_data));
	if (ret < 0) {
		platform_device_put(eeprom_dev);
		goto fail_eeprom;
	}

	ret = platform_device_add(eeprom_dev);
	if (!ret) {
		board_type = meraki_config_get_product();
		switch (board_type) {

		case MERAKI_BOARD_MS220_48FP:
		case MERAKI_BOARD_MS220_48LP:
		case MERAKI_BOARD_MS220_48:
			return ms220_48_late_init(board_type);

		case MERAKI_BOARD_MS320_24P:
		case MERAKI_BOARD_MS320_24:
			return ms320_24_late_init();

		case MERAKI_BOARD_MS320_48FP:
		case MERAKI_BOARD_MS320_48LP:
		case MERAKI_BOARD_MS320_48:
			return ms320_48_late_init();

		default:
			platform_device_del(eeprom_dev);
			break;
		}
	}

	platform_device_put(eeprom_dev);

	if (board_is_ms42()) {
		return ms42_late_init();
	}

	ret = -ENODEV;

fail_eeprom:
	i2c_unregister_device(i2c_client);
fail_i2c:
	platform_device_del(adapter_dev);
fail_adapter:
	platform_device_put(adapter_dev);
	return ret;
}

late_initcall(meraki_jaguar_late_init);
