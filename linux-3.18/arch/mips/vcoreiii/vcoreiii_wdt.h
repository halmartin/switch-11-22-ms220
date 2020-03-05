/*
 *  Watchdog driver for Vitesse VCORE-III
 *
 *  Copyright (C) 2011 Cliff Frey <cliff@meraki.com>
 *  Adapted from the bcm47xx_wdt.c driver by Aleksandar Radovanovic/Matthieu CASTET
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/reboot.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/watchdog.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <asm/mach-vcoreiii/hardware.h>

#define DRV_NAME		"vcoreiii_wdt"

#define WDT_DEFAULT_TIME	30	/* seconds */
#define WDT_MAX_TIME		255	/* seconds */

static int wdt_time = WDT_DEFAULT_TIME;
static int nowayout = WATCHDOG_NOWAYOUT;
static int boot_status = 0;

module_param(wdt_time, int, 0);
MODULE_PARM_DESC(wdt_time, "Watchdog time in seconds. (default="
				__MODULE_STRING(WDT_DEFAULT_TIME) ")");

#ifdef CONFIG_WATCHDOG_NOWAYOUT
module_param(nowayout, int, 0);
MODULE_PARM_DESC(nowayout,
		"Watchdog cannot be stopped once started (default="
				__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");
#endif

static unsigned long vcoreiii_wdt_busy;
static char expect_release;
static struct timer_list wdt_timer;
static DEFINE_SPINLOCK(wdt_lock);
static atomic_t ticks;

static inline void vcoreiii_wdt_hw_start(void)
{
	spin_lock_bh(&wdt_lock);
	writel(VTSS_F_ICPU_CFG_TIMERS_WDT_WDT_ENABLE | 0xBE, VTSS_ICPU_CFG_TIMERS_WDT);
	writel(VTSS_F_ICPU_CFG_TIMERS_WDT_WDT_ENABLE | 0xEF, VTSS_ICPU_CFG_TIMERS_WDT);
	spin_unlock_bh(&wdt_lock);
}

static inline void vcoreiii_wdt_hw_stop(void)
{
	spin_lock_bh(&wdt_lock);
	writel(0xBE, VTSS_ICPU_CFG_TIMERS_WDT);
	writel(0xEF, VTSS_ICPU_CFG_TIMERS_WDT);
	spin_unlock_bh(&wdt_lock);
}

static void vcoreiii_timer_tick(unsigned long unused)
{
	int x = atomic_sub_return(1, &ticks);
	if (x < WDT_MAX_TIME && x > 0) {
		vcoreiii_wdt_hw_start();
	} else {
		printk(KERN_CRIT DRV_NAME ": Software watchdog hasn't been pet for %d seconds, panicing!!!\n", wdt_time);
		// Null function call to force a panic.
		((void (*)(void))0)();
	}
	mod_timer(&wdt_timer, jiffies + HZ);
}

static inline void vcoreiii_wdt_pet(void)
{
	atomic_set(&ticks, wdt_time);
}

static void vcoreiii_wdt_start(void)
{
	vcoreiii_wdt_pet();
	vcoreiii_timer_tick(0);
}

static void vcoreiii_wdt_pause(void)
{
	del_timer_sync(&wdt_timer);
	vcoreiii_wdt_hw_stop();
}

static void vcoreiii_wdt_stop(void)
{
	vcoreiii_wdt_pause();
}

static int vcoreiii_wdt_settimeout(int new_time)
{
	if ((new_time <= 0) || (new_time > WDT_MAX_TIME))
		return -EINVAL;

	wdt_time = new_time;
	return 0;
}

static int vcoreiii_wdt_open(struct inode *inode, struct file *file)
{
	if (test_and_set_bit(0, &vcoreiii_wdt_busy))
		return -EBUSY;

	vcoreiii_wdt_start();
	return nonseekable_open(inode, file);
}

static int vcoreiii_wdt_release(struct inode *inode, struct file *file)
{
	if (expect_release == 42) {
		vcoreiii_wdt_stop();
	} else {
		printk(KERN_CRIT DRV_NAME
			": Unexpected close, not stopping watchdog!\n");
		vcoreiii_wdt_start();
	}

	clear_bit(0, &vcoreiii_wdt_busy);
	expect_release = 0;
	return 0;
}

static ssize_t vcoreiii_wdt_write(struct file *file, const char __user *data, size_t len, loff_t *ppos)
{
	if (len) {
		if (!nowayout) {
			size_t i;

			expect_release = 0;

			for (i = 0; i != len; i++) {
				char c;
				if (get_user(c, data + i))
					return -EFAULT;
				if (c == 'V')
					expect_release = 42;
			}
		}
		vcoreiii_wdt_pet();
	}
	return len;
}

static struct watchdog_info vcoreiii_wdt_info = {
	.identity = DRV_NAME,
	.options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
};

static long vcoreiii_wdt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	int new_value, retval = -EINVAL;

	switch (cmd) {
	case WDIOC_GETSUPPORT:
		return copy_to_user(argp, &vcoreiii_wdt_info,
				sizeof(vcoreiii_wdt_info)) ? -EFAULT : 0;

	case WDIOC_GETSTATUS:
	case WDIOC_GETBOOTSTATUS:
		return put_user(boot_status, p);

	case WDIOC_SETOPTIONS:
		if (get_user(new_value, p))
			return -EFAULT;

		if (new_value & WDIOS_DISABLECARD) {
			vcoreiii_wdt_stop();
			retval = 0;
		}

		if (new_value & WDIOS_ENABLECARD) {
			vcoreiii_wdt_start();
			retval = 0;
		}

		return retval;

	case WDIOC_KEEPALIVE:
		vcoreiii_wdt_pet();
		return 0;

	case WDIOC_SETTIMEOUT:
		if (get_user(new_value, p))
			return -EFAULT;

		if (vcoreiii_wdt_settimeout(new_value))
			return -EINVAL;

		vcoreiii_wdt_pet();

	case WDIOC_GETTIMEOUT:
		return put_user(wdt_time, p);

	default:
		return -ENOTTY;
	}
}

static int vcoreiii_wdt_notify_sys(struct notifier_block *this,
	unsigned long code, void *unused)
{
	if (code == SYS_DOWN || code == SYS_HALT)
		vcoreiii_wdt_stop();
	return NOTIFY_DONE;
}

static const struct file_operations vcoreiii_wdt_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.unlocked_ioctl	= vcoreiii_wdt_ioctl,
	.open		= vcoreiii_wdt_open,
	.release	= vcoreiii_wdt_release,
	.write		= vcoreiii_wdt_write,
};

static struct miscdevice vcoreiii_wdt_miscdev = {
	.minor		= WATCHDOG_MINOR,
	.name		= "watchdog",
	.fops		= &vcoreiii_wdt_fops,
};

static struct notifier_block vcoreiii_wdt_notifier = {
	.notifier_call = vcoreiii_wdt_notify_sys,
};

static int __init vcoreiii_wdt_init(void)
{
	int ret;

	if (!vcoreiii_check_chip_id()) {
		return -ENODEV;
	}

	setup_timer(&wdt_timer, vcoreiii_timer_tick, 0L);

	if (vcoreiii_wdt_settimeout(wdt_time)) {
		vcoreiii_wdt_settimeout(WDT_DEFAULT_TIME);
		printk(KERN_INFO DRV_NAME ": "
			"wdt_time value must be 0 < wdt_time < %d, using %d\n",
			(WDT_MAX_TIME + 1), wdt_time);
	}

	ret = register_reboot_notifier(&vcoreiii_wdt_notifier);
	if (ret)
		return ret;

	ret = misc_register(&vcoreiii_wdt_miscdev);
	if (ret) {
		unregister_reboot_notifier(&vcoreiii_wdt_notifier);
		return ret;
	}

	boot_status = (readl(VTSS_ICPU_CFG_TIMERS_WDT) & VTSS_F_ICPU_CFG_TIMERS_WDT_WDT_STATUS) ? WDIOF_CARDRESET : 0;

	printk(KERN_INFO "VCORE-III Watchdog Timer enabled (%d seconds%s).  Prev boot was%s caused by WDT reset.\n",
	       wdt_time, nowayout ? ", nowayout" : "", boot_status ? "" : " not");
	return 0;
}

static void __exit vcoreiii_wdt_exit(void)
{
	if (!nowayout)
		vcoreiii_wdt_stop();

	misc_deregister(&vcoreiii_wdt_miscdev);

	unregister_reboot_notifier(&vcoreiii_wdt_notifier);
}

module_init(vcoreiii_wdt_init);
module_exit(vcoreiii_wdt_exit);

MODULE_DESCRIPTION("Watchdog driver for VCORE-III");
MODULE_AUTHOR("Cliff Frey");
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(WATCHDOG_MINOR);
