/*
 *
 * VCore-III PHY8512 GPIO definitions
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
 * Definitions for the VCoreIII PHY8512 GPIO driver
 */


struct phy8512_gpio_chip {
	struct gpio_chip gpio_chip;
	int inst;		/* MII controller number */
	int port_base;		/* PHY base */
};

#ifdef CONFIG_VTSS_VCOREIII_LUTON26

extern int luton26_phy8512_gpio_get_value(struct gpio_chip *, unsigned);
extern void luton26_phy8512_gpio_set_value(struct gpio_chip *, unsigned, int);
extern int luton26_phy8512_gpio_direction_input(struct gpio_chip *, unsigned);
extern int luton26_phy8512_gpio_direction_output(struct gpio_chip *, unsigned, int);
extern int luton26_phy8512_gpio_to_irq(struct gpio_chip *, unsigned);

#endif
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR

extern int jaguar_phy8512_gpio_get_value(struct gpio_chip *, unsigned);
extern void jaguar_phy8512_gpio_set_value(struct gpio_chip *, unsigned, int);
extern int jaguar_phy8512_gpio_direction_input(struct gpio_chip *, unsigned);
extern int jaguar_phy8512_gpio_direction_output(struct gpio_chip *, unsigned, int);
extern int jaguar_phy8512_gpio_to_irq(struct gpio_chip *, unsigned);

#endif
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL

extern int jaguar_slv_phy8512_gpio_get_value(struct gpio_chip *, unsigned);
extern void jaguar_slv_phy8512_gpio_set_value(struct gpio_chip *, unsigned, int);
extern int jaguar_slv_phy8512_gpio_direction_input(struct gpio_chip *, unsigned);
extern int jaguar_slv_phy8512_gpio_direction_output(struct gpio_chip *, unsigned, int);
extern int jaguar_slv_phy8512_gpio_to_irq(struct gpio_chip *, unsigned);

#endif
