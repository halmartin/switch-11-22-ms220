/*
 * i2c-gpio interface to platform code
 *
 * Copyright (C) 2007 Atmel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _LINUX_I2C_GPIO_SCL_H
#define _LINUX_I2C_GPIO_SCL_H

/**
 * struct i2c_gpio_scl_platform_data - Platform-dependent data for i2c-gpio-scl
 * @sda_pin: GPIO pin ID to use for SDA
 * @scl_pins: GPIO pin IDs to use for SCL
 * @udelay: signal toggle delay. SCL frequency is (500 / udelay) kHz
 * @timeout: clock stretching timeout in jiffies. If the slave keeps
 *	SCL low for longer than this, the transfer will time out.
 * @sda_is_open_drain: SDA is configured as open drain, i.e. the pin
 *	isn't actively driven high when setting the output value high.
 *	gpio_get_value() must return the actual pin state even if the
 *	pin is configured as an output.
 */
struct i2c_gpio_scl_platform_data {
	unsigned int	sda_pin;
	unsigned int	channel;
	unsigned int	*scl_pins;
	unsigned int	num_scl;
        unsigned int    parent_id;
	unsigned int	child_id_base;
	int		udelay;
	int		timeout;
	unsigned int	sda_is_open_drain:1;
};

#endif /* _LINUX_I2C_GPIO_SCL_H */
