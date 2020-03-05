/*
 *
 * VCore-III System initialization
 *
 * Copyright (C) 2010 Vitesse Semiconductor Inc.
 * Author: Lars Povlsen (lpovlsen@vitesse.com)
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
 * VITESSE SEMICONDUCTOR INC SHALL HAVE NO LIABILITY WHATSOEVER OF ANY
 * KIND ARISING OUT OF OR RELATED TO THE PROGRAM OR THE OPEN SOURCE
 * MATERIALS UNDER ANY THEORY OF LIABILITY.
 *
 */

#include <linux/init.h>
#include <linux/irq.h>
#include <linux/mutex.h>

#include <asm/time.h>
#include <asm/reboot.h>

#include <asm/mach-vcoreiii/vcoreiii_gpio.h>
#include <asm/mach-vcoreiii/hardware.h>

/* No other usable initialization hook than this ...  */
extern void (*late_time_init)(void);

const char *_machine_name;

void __iomem *map_base_switch;
void __iomem *map_base_cpu;

EXPORT_SYMBOL(map_base_switch);
EXPORT_SYMBOL(map_base_cpu);

struct vcoreiii_gpio_ctrl *vcoreiii_gpio_main;

EXPORT_SYMBOL(vcoreiii_gpio_main);

DEFINE_MUTEX(vcoreiii_api_reg_mutex);
EXPORT_SYMBOL(vcoreiii_api_reg_mutex);

static struct resource vcoreiii_reserved_resources[] = {
	{
		.name	= "Serial interface",
		.start	= 0x40000000,
		.end	= 0x4fffffff,
		.flags	= IORESOURCE_MEM
	},
	{
		.name	= "Parallel interface",
		.start	= 0x50000000,
		.end	= 0x5fffffff,
		.flags	= IORESOURCE_MEM
	},
        {
		.name   = "Switch registers",
		.start  = VTSS_IO_ORIGIN1_OFFSET,
		.end    = VTSS_IO_ORIGIN1_OFFSET + VTSS_IO_ORIGIN1_SIZE - 1,
		.flags  = IORESOURCE_MEM
        },
        {
		.name   = "CPU Registers",
		.start  = VTSS_IO_ORIGIN2_OFFSET,
		.end    = VTSS_IO_ORIGIN2_OFFSET + VTSS_IO_ORIGIN2_SIZE - 1,
		.flags  = IORESOURCE_MEM
        },
};

unsigned int __cpuinit get_c0_compare_int(void)
{
	return TIMER_IRQ;
}

void __init plat_time_init(void)
{
	mips_hpt_frequency = VCOREIII_AHB_CLOCK;
}

const char *get_system_type(void)
{
	return _machine_name;
}

u32 vcoreiii_reg_to_phys(void __iomem *addr)
{
    u32 offset;
    if(addr > map_base_switch && (offset = (addr - map_base_switch)) < VTSS_IO_ORIGIN1_SIZE) {
        return VTSS_IO_ORIGIN1_OFFSET + offset;
    } else if (addr > map_base_cpu && (offset = (addr - map_base_cpu)) < VTSS_IO_ORIGIN2_SIZE) {
        return VTSS_IO_ORIGIN2_OFFSET + offset;
    } else {
        printk("Invalid register address, %p reg1 %p reg2 %p\n",
               addr, map_base_switch, map_base_cpu);
        BUG();
        return -1;
    }
}
EXPORT_SYMBOL(vcoreiii_reg_to_phys);

void vcoreiii_api_lock_wrapper(const char *function)
{
    vcoreiii_api_lock(function);
}
EXPORT_SYMBOL(vcoreiii_api_lock_wrapper);

void vcoreiii_api_unlock_wrapper(const char *function)
{
    vcoreiii_api_unlock(function);
}
EXPORT_SYMBOL(vcoreiii_api_unlock_wrapper);

/* Not only time init but that's what the hook it's called through is named */
static void __init vcoreiii_late_time_init(void)
{
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR
	extern void __init vcoreiii_jaguar_irq_init(void);
	extern void __init vcoreiii_jaguar_plat_setup(void);
#endif

#ifdef CONFIG_VTSS_VCOREIII_LUTON26
	extern void __init vcoreiii_luton26_irq_init(void);
	extern void __init vcoreiii_luton26_plat_setup(void);
#endif

	map_base_switch = ioremap(vcoreiii_reserved_resources[2].start,
				  vcoreiii_reserved_resources[2].end -
				  vcoreiii_reserved_resources[2].start + 1);
	if(!map_base_switch)
                printk(KERN_ERR "Unable to ioremap switch register space\n");

	map_base_cpu = ioremap(vcoreiii_reserved_resources[3].start,
			       vcoreiii_reserved_resources[3].end -
			       vcoreiii_reserved_resources[3].start + 1);
	if(!map_base_cpu)
                printk(KERN_ERR "Unable to ioremap cpu register space\n");

	/*
	 * Initialize the chip access semaphore
	 */

	mutex_init(&vcoreiii_api_reg_mutex);

	/* Do platform specific board and IRQ setup */
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR
	vcoreiii_jaguar_plat_setup();
	vcoreiii_jaguar_irq_init();
#endif

#ifdef CONFIG_VTSS_VCOREIII_LUTON26
	vcoreiii_luton26_plat_setup();
	vcoreiii_luton26_irq_init();
#endif
}

void __init plat_mem_setup(void)
{
	int i;

	/* Callbacks for halt, restart done later */
	_machine_halt    = NULL;
	panic_timeout = 5;

	/* Set up initialization hooks */
	late_time_init = vcoreiii_late_time_init;

        for (i = 0; i < ARRAY_SIZE(vcoreiii_reserved_resources); i++)
                request_resource(&iomem_resource,
				 vcoreiii_reserved_resources + i);

}
