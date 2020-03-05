

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dmi.h>

#include <linux/leds.h>
#include <linux/leds-nu801.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>

static struct gpio_led leds[] = {
        {
                .name = "inet1",
                .gpio = 436,
                .active_low = 1,
        },
        {
                .name = "inet2",
                .gpio = 443,
        },
        {
                .name = "inet3",
                .gpio = 445,
        },
        {
                .name = "inet4",
                .gpio = 447,
        },
        {
                .name = "inet5",
                .gpio = 448,
        },
        {
                .name = "inet6",
                .gpio = 457,
        },
        {
                .name = "inet7",
                .gpio = 459,
        },
        {
                .name = "inet8",
                .gpio = 460,
        },
        {
                .name = "inet9",
                .gpio = 461,
        },
        {
                .name = "inet10",
                .gpio = 462,
        },
        {
                .name = "inet11",
                .gpio = 473,
        },
        {
                .name = "ha:green",
                .gpio = 441,
                .active_low = 1,
        },
        {
                .name = "ha:orange",
                .gpio = 432,
                .active_low = 1,
        },
        {
                .name = "usb:green",
                .gpio = 446,
                .active_low = 1,
        },
        {
                .name = "usb:orange",
                .gpio = 444,
                .active_low = 1,
        },

};

static struct gpio_led_platform_data tink_leds_data = {
        .num_leds = ARRAY_SIZE(leds),
        .leds = leds,
};

static struct platform_device tink_leds_dev = {
        .name = "leds-gpio",
        .id = -1,
        .dev.platform_data = &tink_leds_data,
};

static struct led_nu801_template tricolor_led_template = {
    .name = "tricolor",
    .num_leds = 1,
    .cki = 425 + 41,
    .sdi = 425 + 6,
    .lei = 425 + 5,
    .ndelay = 150,
    .init_brightness = {
        LED_OFF,
        LED_OFF,
        LED_OFF,
    },
#ifdef CONFIG_LEDS_TRIGGERS
    .default_trigger = "fade",
#endif
};

static struct led_nu801_platform_data tricolor_led_data = {
    .num_controllers = 1,
    .template = &tricolor_led_template,
};

static struct platform_device tricolor_leds = {
    .name = "leds-nu801",
    .id = -1,
    .dev.platform_data = &tricolor_led_data,
};

static struct platform_device wdt = {
    .name = "dh89xxx-wdt",
};

static struct __initdata platform_device *tink_devs[] = {
        &tink_leds_dev,
        &tricolor_leds,
        &wdt,
};

static int __init tink_init(void)
{
        const char *vendor, *product;

        vendor = dmi_get_system_info(DMI_SYS_VENDOR);
        if (!vendor || strcmp(vendor, "Cisco"))
                goto getout;

        product = dmi_get_system_info(DMI_PRODUCT_NAME);
        if (!product || strcmp(product, "MX100-HW"))
                goto getout;

        platform_add_devices(tink_devs, ARRAY_SIZE(tink_devs));

        printk(KERN_INFO "Cisco Meraki Tinkerbell Init\n");


getout:
        return 0;
}

module_init(tink_init);

MODULE_AUTHOR("Justin Delegard <jdizzle@meraki.net>");
MODULE_DESCRIPTION("CCNG Tinkerbell Board Setup");
