/*
 * VCore-III PWM control for Luton26
 *
 * Copyright (C) 2016 Cisco Systems, Inc.
 * Author: Dineshbabu Selvaraju <dinesh.selvaraju@meraki.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 *
 * This is the driver for PWM control available in LUTON26.
 */

#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/vcoreiii-pwm.h>
#include <linux/sysfs.h>
#define SUPPORT_VTSS_VCOREIII_LUTON26

#include <asm/mach-vcoreiii/hardware.h>

const char *freq_print_string[] = {
            "25KHz",
            "120Hz",
            "100Hz",
            "80Hz",
            "60Hz",
            "40Hz",
            "20Hz",
            "10Hz",
};

static void luton26_reg_write(volatile void* reg_addr,
                              unsigned int value, int offset,
                              int width, struct mutex *reg_lock) {
    u32 curr_value, value_to_be_written;
    mutex_lock(reg_lock);
    curr_value = readl((const volatile void*) reg_addr) & ~(VTSS_ENCODE_BITMASK(offset, width));
    value_to_be_written = curr_value | VTSS_ENCODE_BITFIELD(value, offset, width);
    writel(value_to_be_written, reg_addr);
    mutex_unlock(reg_lock);
}

static u32 luton26_reg_read(const volatile void* reg_addr,
                            int offset, int width) {
    return VTSS_EXTRACT_BITFIELD(readl(reg_addr), offset, width);
}

static void luton26_set_freq(unsigned long int freq, struct mutex *reg_lock) {
    luton26_reg_write(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            freq, FAN_PWM_OFFSET, FAN_PWM_WIDTH, reg_lock);
}

static unsigned int luton26_get_freq(void) {
    return luton26_reg_read(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            FAN_PWM_OFFSET, FAN_PWM_WIDTH);
}

static void luton26_set_duty(unsigned long int duty, struct mutex *reg_lock) {
    luton26_reg_write(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            duty, FAN_DUTY_OFFSET, FAN_DUTY_WIDTH, reg_lock);
}

static unsigned int luton26_get_duty(void) {
    return luton26_reg_read(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            FAN_DUTY_OFFSET, FAN_DUTY_WIDTH);
}

static void luton26_set_polarity(unsigned long int polarity, struct mutex *reg_lock) {
    luton26_reg_write(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            polarity, FAN_POLARITY_OFFSET, FAN_POLARITY_WIDTH, reg_lock);
}

static unsigned int luton26_get_polarity(void) {
    return luton26_reg_read(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            FAN_POLARITY_OFFSET, FAN_POLARITY_WIDTH);
}

static unsigned int luton26_get_rpm(void) {
    return luton26_reg_read(VTSS_DEVCPU_GCB_FAN_STAT_FAN_CNT,
            FAN_TACHO_OFFSET, FAN_TACHO_WIDTH);
}

static void luton26_set_gating(unsigned long int gating, struct mutex *reg_lock) {
    luton26_reg_write(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            gating, FAN_GATING_OFFSET, FAN_GATING_WIDTH, reg_lock);
}

static unsigned int luton26_get_gating(void) {
    return luton26_reg_read(VTSS_DEVCPU_GCB_FAN_STAT_FAN_CNT,
            FAN_GATING_OFFSET, FAN_GATING_WIDTH);
}

static void luton26_set_open_collector(unsigned long int open_collector,
                                       struct mutex *reg_lock) {
    luton26_reg_write(VTSS_DEVCPU_GCB_FAN_CFG_FAN_CFG,
            open_collector, FAN_OPEN_COLLECTOR_OFFSET, FAN_OPEN_COLLECTOR_WIDTH, reg_lock);
}

static unsigned int luton26_get_open_collector(void) {
    return luton26_reg_read(VTSS_DEVCPU_GCB_FAN_STAT_FAN_CNT,
            FAN_OPEN_COLLECTOR_OFFSET, FAN_OPEN_COLLECTOR_WIDTH);
}

static ssize_t set_freq(struct device *dev, struct device_attribute *attr,
                        const char *buf, size_t count) {
    struct pwm_fan_ctx *ctx = dev_get_drvdata(dev);
    unsigned long int freq;
    if (kstrtoul(buf, 10, &freq) || freq > MAX_FREQ)
        return -EINVAL;
    luton26_set_freq(freq, &ctx->reg_lock);
    return count;
}

static ssize_t show_freq(struct device *dev,
                         struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%s\n", freq_print_string[luton26_get_freq()]);
}

static ssize_t set_duty(struct device *dev, struct device_attribute *attr,
                        const char *buf, size_t count) {
    struct pwm_fan_ctx *ctx = dev_get_drvdata(dev);
    unsigned long int duty;
    if (kstrtoul(buf, 10, &duty) || duty > MAX_DUTY)
        return -EINVAL;
    luton26_set_duty(duty, &ctx->reg_lock);
    return count;
}

static ssize_t show_duty(struct device *dev,
                         struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", luton26_get_duty());
}


static ssize_t show_rpm(struct device *dev,
                        struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%x\n", luton26_get_rpm());
}

static ssize_t set_polarity(struct device *dev, struct device_attribute *attr,
                            const char *buf, size_t count) {
    struct pwm_fan_ctx *ctx = dev_get_drvdata(dev);
    unsigned long int polarity;
    if (kstrtoul(buf, 2, &polarity))
        return -EINVAL;
    luton26_set_polarity(polarity, &ctx->reg_lock);
    return count;
}

static ssize_t show_polarity(struct device *dev,
                             struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", luton26_get_polarity());
}

static ssize_t set_gating(struct device *dev, struct device_attribute *attr,
                          const char *buf, size_t count) {
    struct pwm_fan_ctx *ctx = dev_get_drvdata(dev);
    unsigned long int gating;
    if (kstrtoul(buf, 2, &gating))
        return -EINVAL;
    luton26_set_gating(gating, &ctx->reg_lock);
    return count;
}

static ssize_t show_gating(struct device *dev,
                           struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", luton26_get_gating());
}

static ssize_t set_open_collector(struct device *dev, struct device_attribute *attr,
                                  const char *buf, size_t count) {
    struct pwm_fan_ctx *ctx = dev_get_drvdata(dev);
    unsigned long int open_collector;
    if (kstrtoul(buf, 2, &open_collector))
        return -EINVAL;
    luton26_set_open_collector(open_collector, &ctx->reg_lock);
    return count;
}

static ssize_t show_open_collector(struct device *dev,
                                   struct device_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", luton26_get_open_collector());
}

void overlay_set(int overlay, int mode, struct mutex *reg_lock) {
    int overlay_offset, overlay_width;
    switch (overlay) {
        case PWM_OVERLAY:
            overlay_offset = FAN_GPIO_OVERLAY_PWM_OFFSET;
            overlay_width = FAN_GPIO_OVERLAY_PWM_WIDTH;
            break;
        case TACHO_OVERLAY:
            overlay_offset = FAN_GPIO_OVERLAY_TACHO_OFFSET;
            overlay_width = FAN_GPIO_OVERLAY_TACHO_WIDTH;
            break;
    }
    luton26_reg_write(VTSS_DEVCPU_GCB_GPIO_GPIO_INTR_ENA,
            0, overlay_offset, overlay_width, reg_lock);
    luton26_reg_write(VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(0),
            mode%2, overlay_offset, overlay_width, reg_lock);
    luton26_reg_write(VTSS_DEVCPU_GCB_GPIO_GPIO_ALT(1),
            mode/2, overlay_offset, overlay_width, reg_lock);
}

void pwm_fan_init(struct pwm_fan_ctx *ctx) {
    struct pwm_device *pwm = ctx->pwm;

    //GPIO Overlaid function for pwm/duty control
    overlay_set(PWM_OVERLAY, OVERLAY_MODE_ONE, &ctx->reg_lock);

    //Initial PWM frequency set
    luton26_set_freq(pwm->freq, &ctx->reg_lock);

    //Initial duty cycle set
    luton26_set_duty(pwm->duty_cycle, &ctx->reg_lock);

    //Initial polarity set
    luton26_set_polarity(pwm->polarity, &ctx->reg_lock);

    //Initial Gating set
    luton26_set_gating(pwm->gating, &ctx->reg_lock);

    //Initial open-collector mode set
    luton26_set_open_collector(pwm->open_collector, &ctx->reg_lock);

    //GPIO Overlaid function for Tacho read
    overlay_set(TACHO_OVERLAY, OVERLAY_MODE_TWO, &ctx->reg_lock);

}


static SENSOR_DEVICE_ATTR(pwm, S_IRUGO | S_IWUSR, show_freq, set_freq, 0);
static SENSOR_DEVICE_ATTR(duty, S_IRUGO | S_IWUSR, show_duty, set_duty, 0);
static SENSOR_DEVICE_ATTR(rpm, S_IRUGO, show_rpm, NULL, 0);
static SENSOR_DEVICE_ATTR(polarity, S_IRUGO | S_IWUSR, show_polarity, set_polarity, 0);
static SENSOR_DEVICE_ATTR(gating, S_IRUGO | S_IWUSR, show_gating, set_gating, 0);
static SENSOR_DEVICE_ATTR(open_collector, S_IRUGO | S_IWUSR, show_open_collector, set_open_collector, 0);

static struct attribute *vcoreiii_pwm_fan_attrs[] = {
    &sensor_dev_attr_pwm.dev_attr.attr,
    &sensor_dev_attr_duty.dev_attr.attr,
    &sensor_dev_attr_rpm.dev_attr.attr,
    &sensor_dev_attr_polarity.dev_attr.attr,
    &sensor_dev_attr_gating.dev_attr.attr,
    &sensor_dev_attr_open_collector.dev_attr.attr,
    NULL,
};

ATTRIBUTE_GROUPS(vcoreiii_pwm_fan);

static int vcoreiii_pwm_fan_probe(struct platform_device *pdev)
{
    struct pwm_fan_ctx *pdata = pdev->dev.platform_data;
    struct pwm_fan_ctx *ctx = devm_kzalloc(&pdev->dev, sizeof(*ctx), GFP_KERNEL);
    struct device *hwmon;
    ctx->pwm = pdata->pwm;
    mutex_init(&ctx->reg_lock);
    hwmon = devm_hwmon_device_register_with_groups(&pdev->dev, "vcoreiiipwmfan",
                               ctx, vcoreiii_pwm_fan_groups);
    if (IS_ERR(hwmon)) {
        dev_err(&pdev->dev, "Failed to register hwmon device\n");
        return PTR_ERR(hwmon);
    }
    platform_set_drvdata(pdev, ctx);
    pwm_fan_init(ctx);
    return 0;
}

static struct platform_driver vcoreiii_pwm_fan_driver = {
    .probe        = vcoreiii_pwm_fan_probe,
    .driver       = {
        .name        = "vcoreiii-pwm-fan",
    },
};

module_platform_driver(vcoreiii_pwm_fan_driver);

MODULE_AUTHOR("Dineshbabu Selvaraju <dinesh.selvaraju@meraki.com>");
MODULE_ALIAS("platform:vcoreiii-pwm-fan");
MODULE_DESCRIPTION("PWM FAN driver for Vitesse742x");
MODULE_LICENSE("GPL");
