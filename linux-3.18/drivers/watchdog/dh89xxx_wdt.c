#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/watchdog.h>
#include <linux/platform_device.h>

#include "watchdog_core.h"

static u8 siw_base = 0x4e;
#define siw_a (siw_base)
#define siw_v (siw_base + 1)

static u16 __init siw_read_wdt_io_base(void)
{
	u16 r;
	//unlock SIW
	outb(0x80, siw_a);
	outb(0x86, siw_a);

	//choose logical device 6
	outb(7, siw_a);
	outb(6, siw_v);

	//read MSB
	outb(0x60, siw_a);
	r = inb(siw_v) << 8;

	//read LSB
	outb(0x61, siw_a);
	r |= inb(siw_v);

	//lock SIW
	outb(0x68, siw_a);
	outb(0x08, siw_a);

	return r;
}

static u16 io_base = 0xffff;
static int WDT_REGION_SIZE = 0x20;

#define WDTCR (io_base + 0x10)
#define WDTCR_WDT_TOUT_EN (1 << 5) //setting to one disables triggering WDT_TOUT on expire

#define WDTLR (io_base + 0x18)
#define WDTLR_WDT_ENABLED (1 << 1)

#define PVR1R0 (io_base + 0)
#define PVR2R0 (io_base + 4)
#define WDRR0 (io_base + 0xc)
#define WDRR1 (io_base + 0xd)
#define WDRR1_TOUT (1 << 1)

static void magic_outb(u8 val, u16 addr)
{
	outb(0x80, WDRR0);
	outb(0x86, WDRR0);

	outb(val, addr);
}

static void set_pvr(u16 pvr_base, u32 val)
{
	magic_outb(val & 0xff, pvr_base);
	magic_outb((val >> 8) & 0xff, pvr_base+1);
	magic_outb((val >> 16) & 0xff, pvr_base+2);
}

static int read_and_clear_tout(struct watchdog_device *wd)
{
	int r = inb(WDRR1) & WDRR1_TOUT;

	magic_outb(WDRR1_TOUT, WDRR1);

	return r;
}

static int dh_wdt_start(struct watchdog_device *wd)
{
	u8 r = inb(WDTLR);
	outb(r | WDTLR_WDT_ENABLED, WDTLR);

	r = inb(WDTCR);
	outb(r & ~WDTCR_WDT_TOUT_EN, WDTCR);

	return 0;
}

static int dh_wdt_stop(struct watchdog_device *wd)
{
	u8 lr = inb(WDTLR);
	outb(lr & ~WDTLR_WDT_ENABLED, WDTLR);
	return 0;
}

static int dh_wdt_ping(struct watchdog_device *wd)
{
	magic_outb(1, WDRR1);
	return 0;
}

static int dh_wdt_set_timeout(struct watchdog_device *wd, unsigned int secs)
{
	u32 ms = secs * 1000;
	set_pvr(PVR1R0, ms);
	set_pvr(PVR2R0, 0);
	wd->timeout = secs;
	return secs;
}

static struct watchdog_info dh_wdt_info = {
	.options = WDIOF_MAGICCLOSE | WDIOF_KEEPALIVEPING | WDIOF_SETTIMEOUT,
	.identity = "DH89XXXCC Watchdog",
};

static struct watchdog_ops dh_wdt_ops = {
	.owner = THIS_MODULE,
	.start = dh_wdt_start,
	.stop = dh_wdt_stop,
	.ping = dh_wdt_ping,
	.set_timeout = dh_wdt_set_timeout,
};

static struct watchdog_device wdd = {
	.info = &dh_wdt_info,
	.ops = &dh_wdt_ops,
};

static int __init dh_wdt_probe(struct platform_device* dev)
{
	int r = 0;
	io_base = siw_read_wdt_io_base();

	if (!request_region(io_base, WDT_REGION_SIZE, KBUILD_MODNAME)) {
		dev_err(&dev->dev, "request_region FAILED for addr 0x%x\n", io_base);
		return -ENODEV;
	}

	wdd.bootstatus = read_and_clear_tout(&wdd) ? WDIOF_CARDRESET : 0;
	wdd.max_timeout = 0x418937; //MAX_INT / 1000 seconds

	if ((r = watchdog_register_device(&wdd))) {
		release_region(io_base, WDT_REGION_SIZE);
		return r;
	}

	dh_wdt_set_timeout(&wdd, 30);

	dev_info(&dev->dev, "DH89xxxCC watchdog");

	return 0;
}

static int __exit dh_wdt_remove(struct platform_device* dev)
{
	release_region(io_base, WDT_REGION_SIZE);
	watchdog_unregister_device(&wdd);

	return 0;
}

static struct platform_driver dh_wdt_driver = {
	.driver = {
		.name = "dh89xxx-wdt",
		.owner = THIS_MODULE,
	},
	.probe = dh_wdt_probe,
	.remove = __exit_p(dh_wdt_remove),
};

module_platform_driver(dh_wdt_driver);

MODULE_AUTHOR("Justin Delegard <justin.delegard@meraki.net>");
MODULE_LICENSE("GPL");
