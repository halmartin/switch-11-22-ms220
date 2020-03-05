/*
 *
 * VCore-III GPIO on the 8512 PHY
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
 * This is a GPIO driver for the GPIO bits on the 8512 PHY.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/mach-vcoreiii/hardware.h>
#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/mach-vcoreiii/phy8512_gpio.h>

#include <linux/gpio.h>

static int32_t read_mii(uint16_t, uint16_t, uint16_t);
static void write_mii(uint16_t, uint16_t, uint16_t, uint16_t);

#define GPIO_VIA_GPR ((1 << 2) | (1 << 3) | (1 << 4) | (1 << 13) |\
		      (1 << 14) | (1 << 15) | (1 << 16) | (1 << 29))

static inline uint8_t gpio_to_mask(unsigned which)
{
	if (!((1 << which) & GPIO_VIA_GPR))
		return 0;

	if (which == 29)
		return 1 << 3;

	if (which > 4)
		return 1 << (which - 9);

	return 1 << (which - 2);
}

/*
 * read_phy - High level read routine
 *
 * This routine is used to read PHY registers. It handles locking
 * and paging.
 */

static int32_t
read_phy(uint16_t controller, uint16_t phy_addr, uint16_t page,
	 uint16_t reg_addr)
{
	int32_t val;

	vcoreiii_api_lock(__func__);	/* Lock the controller */

	if (page)
		write_mii(controller, phy_addr, 31, page); /* Select page */

	val = read_mii(controller, phy_addr, reg_addr); /* Read register */

	if (page)
		write_mii(controller, phy_addr, 31, 0); /* Select page 0 */

	vcoreiii_api_unlock(__func__);	/* Unlock controller */

	return val;
}

/*
 * write_phy_masked - High level write routine
 *
 * This routine is used to modify PHY registers. It handles locking
 * and paging.
 */

static void
write_phy_masked(uint16_t controller, uint16_t phy_addr, uint16_t page,
		 uint16_t reg_addr, uint16_t data, uint16_t mask)
{
	int32_t old_val = 0;

	vcoreiii_api_lock(__func__);	/* Lock the controller */

	if (page)
		write_mii(controller, phy_addr, 31, page); /* Select page */

	if (mask != 0xffff)
		old_val = read_mii(controller, phy_addr, reg_addr) &
			~mask;	/* Get the old value, masked */

	if (old_val >= 0)	/* Write the new value */
		write_mii(controller, phy_addr, reg_addr, data | old_val);

	if (page)
		write_mii(controller, phy_addr, 31, 0); /* Select page 0 */

	vcoreiii_api_unlock(__func__);	/* Unlock controller */
}

static inline int
phy8512_gpio_get_value(struct gpio_chip *chip, unsigned gpio)
{
	struct phy8512_gpio_chip *phychip = (struct phy8512_gpio_chip *)chip;
	int bit = gpio_to_mask(gpio);
	uint32_t value;

	if (!bit)
		return 0;	/* Everything else is output only */

	value = read_phy(phychip->inst, phychip->port_base, 16, 15);
	if (value < 0) {
		printk("%s:%d error reading phy\n", __func__, __LINE__);
		return 0;
	}

	return (bit & value) != 0;
}

static inline void
phy8512_gpio_set_value(struct gpio_chip *chip, unsigned gpio, int value)
{
	struct phy8512_gpio_chip *phychip = (struct phy8512_gpio_chip *)chip;
	int bit = gpio_to_mask(gpio);

	/*
	 * Handle the R/W bits, 29, 16-13, 4-2
	 */

	if (bit) {
		write_phy_masked(phychip->inst, phychip->port_base, 16,
				 16,  value ? bit : 0, bit);
		return;
	}

	/*
	 * Handle 17 - 28, control via LED0
	 */

	if ((gpio >= 17) && (gpio <= 28)) {
		write_phy_masked(phychip->inst,
				 phychip->port_base + (gpio - 17), 0,
				 29, value ? 0xe : 0xf, 0xf);
		return;
	}

	/*
	 * Handle 5 - 12, control via LED1
	 */

	if ((gpio >= 5) && (gpio <= 12)) {
		write_phy_masked(phychip->inst,
				 phychip->port_base + (gpio - 5), 0,
				 29, value ? 0xe0 : 0xf0, 0xf0);
		return;
	}
}

static inline int
phy8512_get_gpio_ctrl(struct phy8512_gpio_chip *chip, unsigned gpio)
{
	if (gpio >=2 && gpio <= 4)
		return (gpio - 2) << 1;

	if (gpio == 29)
		return 6;

	return ((gpio - 13) << 1) + 8;
}

static inline int
phy8512_gpio_direction_input(struct gpio_chip *chip, unsigned gpio)
{
	struct phy8512_gpio_chip *phychip = (struct phy8512_gpio_chip *)chip;
	int bit = gpio_to_mask(gpio);
	int enablebit;

	if (!bit)
		return -EINVAL;	/* Only some can be inputs */

	enablebit = phy8512_get_gpio_ctrl(phychip, gpio);

	/*
	 * Set the port to be a GPIO
	 */

	write_phy_masked(phychip->inst, phychip->port_base, 16, 13,
			 3 << enablebit, 3 << enablebit);

	/*
	 * Set the direction to input
	 */

	write_phy_masked(phychip->inst, phychip->port_base, 16, 17,
			 0x0, bit);

	return 0;
}

static inline int
phy8512_gpio_direction_output(struct gpio_chip *chip, unsigned gpio, int value)
{
	struct phy8512_gpio_chip *phychip = (struct phy8512_gpio_chip *)chip;
	int bit = gpio_to_mask(gpio);
	int enablebit;

	if (bit) {

		/*
		 * Set the value before we set it to be an output,
		 * to avoid glitches.
		 */

		write_phy_masked(phychip->inst, phychip->port_base,
				 16, 16, value ? bit : 0, bit);

		enablebit = phy8512_get_gpio_ctrl(phychip, gpio);

		/*
		 * Enable the port for GPIO
		 */

		write_phy_masked(phychip->inst, phychip->port_base,
				 16, 13, 3 << enablebit, 3 << enablebit);

		/*
		 * Set the direction to be output
		 */

		write_phy_masked(phychip->inst, phychip->port_base,
				 16, 17, bit, bit);

		return 0;
	}

	/* The others are easy, just set the value */

	phy8512_gpio_set_value(chip, gpio, value);

	return 0;
}

static inline int phy8512_gpio_to_irq(struct gpio_chip *chip, unsigned gpio)
{
	return -EINVAL;		/* Not yet, could be GPIO_30 */
}
