/*
 * $Copyright Open Broadcom Corporation$
 */
 
#ifndef __IPROC_PLAT_GPIO_H
#define __IPROC_PLAT_GPIO_H

#include "hr3_regs.h"
#include <asm-generic/gpio.h>

#define IPROC_GPIO_CCG

#define IPROC_GPIO_REG_SIZE     (0x50)





#define REGOFFSET_GPIO_DIN          0x000 /* GPIO Data in register */
#define REGOFFSET_GPIO_DOUT         0x004 /* GPIO Data out register */
#define REGOFFSET_GPIO_EN           0x008 /* GPIO driver enable register */


#define IPROC_GPIO_CCA_ID   (0)
#define IPROC_GPIO_CCB_ID   (1)
#define IPROC_GPIO_CCG_ID   (2)
#define ASIU_GPIO_ID        (3)
#define AON_GPIO_ID         (4)

#define IPROC_GPIO_CCA_IRQ_BASE     (IPROC_IRQ_GPIO_0)
#define IPROC_GPIO_CCB_IRQ_BASE     (IPROC_IRQ_GPIO_0 + 32)
#define IPROC_GPIO_CCG_IRQ_BASE     (IPROC_IRQ_GPIO_0)

#define ASIU_GPIO_REGIDX(asiu_pin) ((asiu_pin) / 32)
#define ASIU_GPIO_REGBIT(asiu_pin) ((asiu_pin) % 32)  
#define ASIU_GPIO_REGOFFSET        (0x200)


#define IPROC_CCA_INT_F_GPIOINT     (1)

struct iproc_gpio_irqcfg {
    unsigned long flags;
    irqreturn_t (*handler)(int irq, void *dev);
    void (*ack)(unsigned int irq);
    void (*unmask)(unsigned int irq);
    void (*mask)(unsigned int irq);
    int (*set_type)(unsigned int irq, unsigned int type);
};

struct iproc_gpio_chip {
    int id;
    struct gpio_chip	chip;
    struct iproc_gpio_cfg	*config;
    void __iomem		*ioaddr;
    void __iomem		*intr_ioaddr;
    void __iomem		*dmu_ioaddr;
    spinlock_t		 lock;
    int irq_base;
	struct resource	* resource;
	int irq;
    struct iproc_gpio_irqcfg	*irqcfg;
    int pin_offset;
};


static inline struct iproc_gpio_chip *to_iproc_gpio(struct gpio_chip *gpc)
{
	return container_of(gpc, struct iproc_gpio_chip, chip);
}

#define IPROC_GPIO_END  (32 + 4)
extern struct iproc_gpio_chip *iproc_gpios[IPROC_GPIO_END];

static inline struct iproc_gpio_chip *iproc_gpiolib_getchip(unsigned int chip)
{
	return (chip < IPROC_GPIO_END) ? iproc_gpios[chip] : NULL;
}

/* locking wrappers to deal with multiple access to the same gpio bank */
#define iproc_gpio_lock(_oc, _fl) spin_lock_irqsave(&(_oc)->lock, _fl)
#define iproc_gpio_unlock(_oc, _fl) spin_unlock_irqrestore(&(_oc)->lock, _fl)

extern void iproc_gpiolib_add(struct iproc_gpio_chip *chip);
extern int iproc_gpiolib_init(void);

#define MAX_NS_GPIO 2

#endif
