/*
 * Meraki GPIO configuration header file
 *
 * Copyright 2015 Cisco Systems
 * Willy Hauser <whauser@meraki.net>
 *
 * Licensed under the GNU/GPL. See COPYING for details.
 */

#ifndef __PLAT_GPIO_CFG_H
#define __PLAT_GPIO_CFG_H

struct gpio_cfg {
	void __iomem *cru_gpio_addr;
	void __iomem *aux_sel_addr;
};

struct gpio_data {
	unsigned	gpio;
	unsigned	default_state : 2;
	unsigned	active_low : 1;
	unsigned	direction : 1;
};

#define GPIO_GENERAL  0
#define GPIO_AUX_FUN  1
#define GPIO_PULL_UP  2
#define CRU_GPIO_GENERAL_OFFSET		0x00 /* CRU_GPIO_CONTROL0 determines whether pin is general */
#define CRU_GPIO_PULL_UP_OFFSET		0x1c /* CRU_GPIO_CONTROL7 determines GPIO pull up */
#define CRU_GPIO_PULL_DOWN_OFFSET	0x20 /* CRU_GPIO_CONTROL8 determines GPIO pull down */
#define GPIO_AUX_OFFSET 33 /* Offset for indices of aux gpio pins */
#define GPIO_OUTPUT		0 /* Set direction as out */
#define GPIO_INPUT		1 /* Set direction as in */
#define GPIO_DEFSTATE_OFF	0 /* Set value 0 */
#define GPIO_DEFSTATE_ON	1 /* Set value 1 */
#define GPIO_DEFSTATE_KEEP	2 /* Write back the current value */

#endif
