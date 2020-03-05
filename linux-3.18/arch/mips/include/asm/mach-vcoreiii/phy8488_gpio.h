struct phy8488_gpio_chip {
	struct gpio_chip gpio_chip;
	int inst;		/* MII controller number */
	int port_base;		/* PHY base */
};

extern int jaguar_phy8488_gpio_get_value(struct gpio_chip *, unsigned);
extern void jaguar_phy8488_gpio_set_value(struct gpio_chip *, unsigned, int);
extern int jaguar_phy8488_gpio_direction_input(struct gpio_chip *, unsigned);
extern int jaguar_phy8488_gpio_direction_output(struct gpio_chip *, unsigned, int);
extern int jaguar_phy8488_gpio_to_irq(struct gpio_chip *, unsigned);

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL

extern int jaguar_slv_phy8488_gpio_get_value(struct gpio_chip *, unsigned);
extern void jaguar_slv_phy8488_gpio_set_value(struct gpio_chip *, unsigned, int);
extern int jaguar_slv_phy8488_gpio_direction_input(struct gpio_chip *, unsigned);
extern int jaguar_slv_phy8488_gpio_direction_output(struct gpio_chip *, unsigned, int);
extern int jaguar_slv_phy8488_gpio_to_irq(struct gpio_chip *, unsigned);

#endif
