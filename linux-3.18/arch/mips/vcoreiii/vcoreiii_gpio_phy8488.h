#include <asm/mach-vcoreiii/hardware.h>
#include <asm-generic/gpio.h>
#include <asm/mach-vcoreiii/phy8488_gpio.h>

static const uint32_t gpio_addrs[] = { 0x100, 0x102, 0x104, 0x106, 0x108, 0x10a,
                                       0x124, 0x126, 0x128, 0x12a, 0x12c, 0x12e};

static int32_t
read_phy(uint16_t controller, uint16_t phy_addr, uint16_t page,
	 uint16_t reg_addr)
{
	int32_t val;

	vcoreiii_api_lock(__func__);	/* Lock the controller */

	address_mii(controller, phy_addr, page, reg_addr);

	val = read_mii(controller, phy_addr, page); /* Read register */

	vcoreiii_api_unlock(__func__);	/* Unlock controller */

	return val;
}

static void
write_phy_masked(uint16_t controller, uint16_t phy_addr, uint16_t page,
		 uint16_t reg_addr, uint16_t data, uint16_t mask)
{
	int32_t old_val = 0;

	vcoreiii_api_lock(__func__);	/* Lock the controller */

	address_mii(controller, phy_addr, page, reg_addr);

	if (mask != 0xffff)
		old_val = read_mii(controller, phy_addr, page) &
			~mask;	/* Get the old value, masked */

	if (old_val >= 0)
		write_mii(controller, phy_addr, page, (data & mask) | old_val);

	vcoreiii_api_unlock(__func__);	/* Unlock controller */
}

/* Definitions for the PHY8488 GPIO registers -- does not include
   values we do not use. */

/* Controls whether or not the pin is an input or output */
#define PHY8488_GPIO_TRISTATE_INPUT_MODE  0x8000
#define PHY8488_GPIO_TRISTATE_OUTPUT_MODE 0x0000
#define PHY8488_GPIO_TRISTATE_MASK        0x8000

/* If the pin is an input, this controls interrupt options. We do not
   use interrupts with these pins, so we configure "none." */
#define PHY8488_GPIO_INPUT_NO_INTERRUPT   0x0000
#define PHY8488_GPIO_INPUT_INTERRUPT_MASK 0x6000

/* If the pin is an output, this controls blinking (options are 1Hz,
   2Hz, and 5Hz). We don't blink with our GPIOs. */
#define PHY8488_GPIO_OUTPUT_NO_BLINK      0x0000
#define PHY8488_GPIO_OUTPUT_BLINK_MASK    0x6000

/* This controls the value that is driven when the pin is an
   output. */
#define PHY8488_GPIO_OUTPUT_VAL_HIGH      0x1000
#define PHY8488_GPIO_OUTPUT_VAL_MASK      0x1000

/* This read-only bit returns the current value of the pin. */
#define PHY8488_GPIO_INPUT_VAL_HIGH       0x0400
#define PHY8488_GPIO_INPUT_VAL_MASK       0x0400

/* There are ways to have the GPIO be a special-purpose pin
   (interrupt, activity indicator, etc). We only use GPIO. */
#define PHY8488_GPIO_FUNCTION_GPIO        0x0000
#define PHY8488_GPIO_FUNCTION_MASK        0x0007

static int inline
phy8488_gpio_get_value(struct gpio_chip *chip, unsigned gpio)
{
	struct phy8488_gpio_chip *phychip = (struct phy8488_gpio_chip *)chip;
	uint32_t value;

	value = read_phy(phychip->inst, phychip->port_base, 30,
			 gpio_addrs[gpio]);
	if (value < 0) {
		printk("%s:%d error reading phy\n", __func__, __LINE__);
		return 0;
	}

	return (value & (PHY8488_GPIO_INPUT_VAL_HIGH)) != 0;
}

static inline void
phy8488_gpio_set_value(struct gpio_chip *chip, unsigned gpio, int value)
{
	struct phy8488_gpio_chip *phychip = (struct phy8488_gpio_chip *)chip;
	write_phy_masked(phychip->inst, phychip->port_base, 30,
			 gpio_addrs[gpio], value ? PHY8488_GPIO_OUTPUT_VAL_HIGH : 0,
			 PHY8488_GPIO_OUTPUT_VAL_MASK);
}

static inline int
phy8488_gpio_direction_input(struct gpio_chip *chip, unsigned gpio)
{
	struct phy8488_gpio_chip *phychip = (struct phy8488_gpio_chip *)chip;

	write_phy_masked(phychip->inst, phychip->port_base, 30,
			 gpio_addrs[gpio],
			 (PHY8488_GPIO_TRISTATE_INPUT_MODE |
			  PHY8488_GPIO_INPUT_NO_INTERRUPT |
			  PHY8488_GPIO_FUNCTION_GPIO),
			 (PHY8488_GPIO_TRISTATE_MASK |
			  PHY8488_GPIO_INPUT_INTERRUPT_MASK |
			  PHY8488_GPIO_FUNCTION_MASK));

	return 0;
}

static inline int
phy8488_gpio_direction_output(struct gpio_chip *chip, unsigned gpio, int value)
{
	struct phy8488_gpio_chip *phychip = (struct phy8488_gpio_chip *)chip;

	write_phy_masked(phychip->inst, phychip->port_base, 30,
			 gpio_addrs[gpio],
			 (PHY8488_GPIO_TRISTATE_OUTPUT_MODE |
			  PHY8488_GPIO_OUTPUT_NO_BLINK |
			  PHY8488_GPIO_FUNCTION_GPIO |
			  (value ? PHY8488_GPIO_OUTPUT_VAL_HIGH : 0)),
			 (PHY8488_GPIO_TRISTATE_MASK |
			  PHY8488_GPIO_OUTPUT_BLINK_MASK |
			  PHY8488_GPIO_OUTPUT_VAL_MASK |
			  PHY8488_GPIO_FUNCTION_MASK));

	return 0;
}

static inline int phy8488_gpio_to_irq(struct gpio_chip *chip, unsigned gpio)
{
	return -EINVAL;
}
