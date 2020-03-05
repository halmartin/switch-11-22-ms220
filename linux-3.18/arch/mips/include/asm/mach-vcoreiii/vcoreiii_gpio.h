#ifndef _VCOREIII_GPIO_H__
#define _VCOREIII_GPIO_H__

#define VCOREIII_GPIO_BASE 0
#define VCOREIII_GPIO_NUM 32
#define VCOREIII_GPIO_BASE_SLV (VCOREIII_GPIO_BASE + VCOREIII_GPIO_NUM)

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
#define VCOREIII_GPIO_MAX_MAC 2 /* Maximum number of MACs with GPIO */
#define VCOREIII_GPIO_MAX_SGPIO_CTRL 4 /* Maximum SGPIO controllers */
#else
#define VCOREIII_GPIO_MAX_MAC 1 /* Maximum number of MACs with GPIO */
#endif

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR
#define VCOREIII_GPIO_MAX_PHY 4	/* Maximum number of PHYs with GPIO */
#define VCOREIII_GPIO_MAX_PHY_8488 (2)
#else
#define VCOREIII_GPIO_MAX_PHY 1 /* Maximum number of PHYs with GPIO */
#define VCOREIII_GPIO_MAX_PHY_8488 0 /* Extra GPIOs on 8488 PHY */
#ifndef VCOREIII_GPIO_MAX_SGPIO_CTRL
#define VCOREIII_GPIO_MAX_SGPIO_CTRL 2 /* Maximum SGPIO controlers */
#endif /* VCOREIII_GPIO_MAX_SGPIO_CTRL */
#endif

#ifndef VCOREIII_GPIO_MAX_SGPIO_CTRL
#define VCOREIII_GPIO_MAX_SGPIO_CTRL 1
#endif /* VCOREIII_GPIO_MAX_SGPIO_CTRL */

#define VCOREIII_GPIO_MAX_SGPIO (128 * VCOREIII_GPIO_MAX_SGPIO_CTRL)
#define VCOREIII_GPIO_MAX_PHY_8488_GPIO (12 * VCOREIII_GPIO_MAX_PHY_8488)

#define VCOREIII_GPIO_MAX_TCA6424A_GPIO 24

#define ARCH_NR_GPIOS ((32 * (VCOREIII_GPIO_MAX_MAC + VCOREIII_GPIO_MAX_PHY)) + VCOREIII_GPIO_MAX_SGPIO + VCOREIII_GPIO_MAX_PHY_8488_GPIO + VCOREIII_GPIO_MAX_TCA6424A_GPIO)

#define VCOREIII_GPIO_PHY_BASE(n) (32 * (VCOREIII_GPIO_MAX_MAC + n))
#define VCOREIII_GPIO_SGPIO_BASE(n) ((32 * (VCOREIII_GPIO_MAX_MAC + VCOREIII_GPIO_MAX_PHY)) + ((n) * 128))
#define VCOREIII_GPIO_PHY_8488_BASE(n) ((32 * (VCOREIII_GPIO_MAX_MAC + VCOREIII_GPIO_MAX_PHY)) + VCOREIII_GPIO_MAX_SGPIO + 12*(n))
#define VCOREIII_GPIO_TCA6424A_GPIO_BASE ((32 * (VCOREIII_GPIO_MAX_MAC + VCOREIII_GPIO_MAX_PHY)) + VCOREIII_GPIO_MAX_SGPIO + VCOREIII_GPIO_MAX_PHY_8488_GPIO)

struct vcoreiii_gpio_ctrl {
	volatile u32 out_set;	/* Output set */
	volatile u32 out_clr;	/* Output clear */
	volatile u32 out;	/* Output */
	volatile u32 in;	/* Input */
	volatile u32 oe;	/* Pin direction (output enable) */
	volatile u32 intr;	/* Interrupt */
	volatile u32 intr_ena;	/* Interrupt enable */
	volatile u32 intr_ident; /* Interrupt identity */
	volatile u32 alt[2];	 /* Alternate functions */
};

extern struct vcoreiii_gpio_ctrl *vcoreiii_gpio_main;
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
extern struct vcoreiii_gpio_ctrl *vcoreiii_gpio_slv;
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

#include <asm-generic/gpio.h>	/* Must be after setting ARCH_NR_GPIOS */

static inline int vcoreiii_gpio_set_alternate(unsigned gpio, int which)
{
	if ((gpio >= VCOREIII_GPIO_BASE) &&
	    (gpio < (VCOREIII_GPIO_BASE + VCOREIII_GPIO_NUM))) {
			switch (which) {
			case 0:
				vcoreiii_gpio_main->alt[0] &=
					~(1 << (gpio - VCOREIII_GPIO_BASE));
				vcoreiii_gpio_main->alt[1] &=
					~(1 << (which - VCOREIII_GPIO_BASE));
				break;

			case 1:
				vcoreiii_gpio_main->alt[1] &=
					~(1 << (gpio - VCOREIII_GPIO_BASE));
				vcoreiii_gpio_main->alt[0] |=
					(1 << (gpio - VCOREIII_GPIO_BASE));
				break;
			default:
				return -EINVAL;
			}
			return 0;
	}

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if ((gpio >= VCOREIII_GPIO_BASE_SLV) &&
	    (gpio < (VCOREIII_GPIO_BASE_SLV + VCOREIII_GPIO_NUM))) {
			switch (which) {
			case 0:
				vcoreiii_gpio_slv->alt[0] &=
					~(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
				vcoreiii_gpio_slv->alt[1] &=
					~(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
				break;

			case 1:
				vcoreiii_gpio_slv->alt[1] &=
					~(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
				vcoreiii_gpio_slv->alt[0] |=
					(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
				break;
			default:
				return -EINVAL;
			}
			return 0;
	}
#endif

	return -EINVAL;
}

static inline int gpio_get_value(unsigned gpio)
{
	if ((gpio >= VCOREIII_GPIO_BASE) &&
	    (gpio < (VCOREIII_GPIO_BASE + VCOREIII_GPIO_NUM))) {
		return (vcoreiii_gpio_main->in &
			(1 << (gpio - VCOREIII_GPIO_BASE))) != 0;
	}

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if ((gpio >= VCOREIII_GPIO_BASE_SLV) &&
	    (gpio < (VCOREIII_GPIO_BASE_SLV + VCOREIII_GPIO_NUM))) {
		return (vcoreiii_gpio_slv->in &
			(1 << (gpio - VCOREIII_GPIO_BASE_SLV))) != 0;
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

#ifdef CONFIG_GPIOLIB
	return __gpio_get_value(gpio);
#else
	return 0;
#endif /* CONFIG_GPIOLIB */
}

static inline void gpio_set_value(int gpio, int value)
{
	if ((gpio >= VCOREIII_GPIO_BASE) &&
	    (gpio < (VCOREIII_GPIO_BASE + VCOREIII_GPIO_NUM))) {
		if (value) {
			vcoreiii_gpio_main->out_set =
				(1 << (gpio - VCOREIII_GPIO_BASE));
		} else {
			vcoreiii_gpio_main->out_clr =
				(1 << (gpio - VCOREIII_GPIO_BASE));
		}
		return;
	}

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if ((gpio >= VCOREIII_GPIO_BASE_SLV) &&
	    (gpio < (VCOREIII_GPIO_BASE_SLV + VCOREIII_GPIO_NUM))) {
		if (value) {
			vcoreiii_gpio_slv->out_set =
				(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
		} else {
			vcoreiii_gpio_slv->out_clr =
				(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
		}
		return;
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

#ifdef CONFIG_GPIOLIB
	__gpio_set_value(gpio, value);
#endif /* CONFIG_GPIOLIB */
}

#ifdef CONFIG_GPIOLIB

#define gpio_cansleep		__gpio_cansleep
#define gpio_to_irq		__gpio_to_irq

#else /* CONFIG_GPIOLIB */

static inline int gpio_direction_input(unsigned gpio)
{
	if ((gpio >= VCOREIII_GPIO_BASE) &&
	    (gpio < (VCOREIII_GPIO_BASE + VCOREIII_GPIO_NUM))) {
		vcoreiii_gpio_main->oe &= ~(1 << (gpio - VCOREIII_GPIO_BASE));
		return 0;
	}

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if ((gpio >= VCOREIII_GPIO_BASE_SLV) &&
	    (gpio < (VCOREIII_GPIO_BASE_SLV + VCOREIII_GPIO_NUM))) {
		vcoreiii_gpio_slv->oe &= ~(1 << (gpio - VCOREIII_GPIO_BASE_SLV));
		return 0;
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

	return 0;
}

static inline int gpio_direction_output(unsigned gpio, int value)
{
	gpio_set_value(gpio, value);
	if ((gpio >= VCOREIII_GPIO_BASE) &&
	    (gpio < (VCOREIII_GPIO_BASE + VCOREIII_GPIO_NUM))) {
		vcoreiii_gpio_main->oe |= 1 << (gpio - VCOREIII_GPIO_BASE);
		return 0;
	}

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if ((gpio >= VCOREIII_GPIO_BASE_SLV) &&
	    (gpio < (VCOREIII_GPIO_BASE_SLV + VCOREIII_GPIO_NUM))) {
		vcoreiii_gpio_slv->oe |= 1 << (gpio - VCOREIII_GPIO_BASE_SLV);
		return 0;
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

	return 0;
}

static inline int gpio_cansleep(unsigned gpio)
{
	return 0;
}

static inline int gpio_to_irq(unsigned gpio)
{
	return -EINVAL;
}

#endif /* !CONFIG_GPIOLIB */

#endif /* _VCOREIII_GPIO_H__ */
