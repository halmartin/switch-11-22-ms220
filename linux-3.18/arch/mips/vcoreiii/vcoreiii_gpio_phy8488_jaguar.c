#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include "vcoreiii_miim_phy8488.h"
#include "vcoreiii_gpio_phy8488.h"

int jaguar_phy8488_gpio_get_value(struct gpio_chip *chip, unsigned gpio)
{
	return phy8488_gpio_get_value(chip, gpio);
}

void jaguar_phy8488_gpio_set_value(struct gpio_chip *chip, unsigned gpio,
				    int value)
{
	phy8488_gpio_set_value(chip, gpio, value);
}

int jaguar_phy8488_gpio_direction_input(struct gpio_chip *chip, unsigned gpio)
{
	return phy8488_gpio_direction_input(chip, gpio);
}

int jaguar_phy8488_gpio_direction_output(struct gpio_chip *chip, unsigned gpio,
					  int value)
{
	return phy8488_gpio_direction_output(chip, gpio, value);
}

int jaguar_phy8488_gpio_to_irq(struct gpio_chip *chip, unsigned gpio)
{
	return phy8488_gpio_to_irq(chip, gpio);
}

int __init jaguar_phy8488_init(void)
{
	uint8_t controller = 1; /* All Jaguar-based Meraki platforms
				   with 8488 PHYs have them on MDIO
				   controller 1 */

	if (!vcoreiii_check_chip_id())
		return -ENODEV;

	/* Set the MDIO controller to Clause 45 operation */
	writel(VTSS_F_DEVCPU_GCB_MIIM_MII_CFG_MIIM_ST_CFG_FIELD(0) |
	       VTSS_F_DEVCPU_GCB_MIIM_MII_CFG_MIIM_CFG_PRESCALE(0x32),
	       VTSS_DEVCPU_GCB_MIIM_MII_CFG(controller));

	return 0;
}
module_init(jaguar_phy8488_init);

MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.com>");
MODULE_DESCRIPTION("GPIO driver for 8488 PHY on Jaguar");
MODULE_LICENSE("GPL");
