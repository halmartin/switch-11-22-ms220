/*
 *  DH89xxCC - LPC bridge GPIO driver
 *
 *  Copyright (C) 2013 Cisco Inc. <jdelegar@cisco.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/gpio.h>

struct dh_gpio {
	unsigned io_base;
	struct device *dev;
	struct gpio_chip gpio;
	struct mutex lock;
};

#define GPIO_BAR 0x48
#define GPIO_REGION_SIZE 128

//sets 2 and three follow this reg layout convention
#define GPIO_IO_SEL  0x04
#define GPIO_LVL  0x08
//set 1 does not quite
#define GPIO_LVL_SET1  0x0c

#define GPIO_SET1_BASE 0x00
#define GPIO_SET2_BASE 0x30
#define GPIO_SET3_BASE 0x40

struct dh_gpio_regs {
	u16 io_sel;
	u16 lvl;
};

struct dh_gpio_regs reg_offs[] = {
	{.io_sel = GPIO_IO_SEL,
		.lvl = GPIO_LVL_SET1,},
	{.io_sel = GPIO_IO_SEL + GPIO_SET2_BASE,
		.lvl = GPIO_LVL + GPIO_SET2_BASE,},
	{.io_sel = GPIO_IO_SEL + GPIO_SET3_BASE,
		.lvl = GPIO_LVL + GPIO_SET3_BASE,},
};

static struct dh_gpio_regs *reg_set(unsigned nr) {
	return &reg_offs[nr/32];
}

static void gpio_writel(struct dh_gpio *chip, int offs, u32 val)
{
	//printk("write 0x%x:0x%x\n", chip->io_base + offs, val);
	outl(val, chip->io_base + offs);
}

static u32 gpio_readl(struct dh_gpio *chip, int offs)
{
	u32 val = inl(chip->io_base + offs);
	//printk("read 0x%x:0x%x\n", chip->io_base + offs, val);
	return val;
}

static int dh89xxcc_gpio_get(struct gpio_chip *gpio, unsigned nr)
{
	struct dh_gpio *chip = container_of(gpio, struct dh_gpio, gpio);
	u32 reg_val = gpio_readl(chip, reg_set(nr)->lvl);
	return reg_val & (1 << (nr % 32));
}
static void dh89xxcc_gpio_set(struct gpio_chip *gpio, unsigned nr, int val)
{
	struct dh_gpio *chip = container_of(gpio, struct dh_gpio, gpio);
	u32 reg_val;
	mutex_lock(&chip->lock);
	reg_val = gpio_readl(chip, reg_set(nr)->lvl);
	if (val)
		reg_val |= (1 << (nr % 32));
	else
		reg_val &= ~(1 << (nr % 32));
	gpio_writel(chip, reg_set(nr)->lvl, reg_val);
	mutex_unlock(&chip->lock);
}

static int dh89xxcc_gpio_dir_out(struct gpio_chip *gpio, unsigned nr, int val)
{
	struct dh_gpio *chip = container_of(gpio, struct dh_gpio, gpio);
	u32 reg_val;
	dh89xxcc_gpio_set(gpio, nr, val);

	mutex_lock(&chip->lock);
	reg_val = gpio_readl(chip, reg_set(nr)->io_sel);
	reg_val &= ~(1 << (nr % 32));
	gpio_writel(chip, reg_set(nr)->io_sel, reg_val);
	mutex_unlock(&chip->lock);

	return 0;
}

static int dh89xxcc_gpio_dir_in(struct gpio_chip *gpio, unsigned nr)
{
	struct dh_gpio *chip = container_of(gpio, struct dh_gpio, gpio);
	u32 reg_val;
	mutex_lock(&chip->lock);
	reg_val = gpio_readl(chip, reg_set(nr)->io_sel);
	reg_val |= (1 << (nr % 32));
	gpio_writel(chip, reg_set(nr)->io_sel, reg_val);
	mutex_unlock(&chip->lock);

	return 0;
}

static void dh89xxcc_gpio_setup(struct dh_gpio *chip)
{
	struct gpio_chip *gpio = &chip->gpio;

	gpio->label = dev_name(chip->dev);
	gpio->owner = THIS_MODULE;
	gpio->direction_input = dh89xxcc_gpio_dir_in;
	gpio->get = dh89xxcc_gpio_get;
	gpio->direction_output = dh89xxcc_gpio_dir_out;
	gpio->set = dh89xxcc_gpio_set;
	gpio->base = -1;
	gpio->ngpio = 87;
	gpio->can_sleep = 0;
}

static DEFINE_PCI_DEVICE_TABLE(dh89xxcc_gpio_pcidev_id) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, 0x2310) },
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, 0x8c54) },
	{ 0, }
};

static int __init dh89xxcc_gpio_probe(struct pci_dev *pdev,
		const struct pci_device_id *id)
{
	int ret;
	struct dh_gpio *chip;
	u32 bar_reg;

	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	if (chip == NULL)
		return -ENOMEM;

	chip->dev = &pdev->dev;
	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "%s : pci_enable_device FAILED\n", __func__);
		goto err_pci_enable;
	}

	pci_read_config_dword(pdev, GPIO_BAR, &bar_reg);
	//address is 4 byte aligned
	chip->io_base = bar_reg & ~0x3;

	if (!request_region(chip->io_base, GPIO_REGION_SIZE, KBUILD_MODNAME)) {
		ret = -ENOMEM;
		dev_err(&pdev->dev, "request_region FAILED-%d\n", ret);
		goto err_request_regions;
	}

	pci_set_drvdata(pdev, chip);
	mutex_init(&chip->lock);
	dh89xxcc_gpio_setup(chip);
	ret = gpiochip_add(&chip->gpio);
	if (ret) {
		dev_err(&pdev->dev, "%s : failed te rogister GPIO\\n", __func__);
		goto err_gpiochip_add;
	}

	return 0;

err_gpiochip_add:
	release_region(chip->io_base, GPIO_REGION_SIZE);
err_request_regions:
	pci_disable_device(pdev);
err_pci_enable:
	kfree(chip);
	return -1;
}

static void __exit dh89xxcc_gpio_remove(struct pci_dev *pdev)
{
	int err;
	struct dh_gpio *chip = pci_get_drvdata(pdev);

	gpiochip_remove(&chip->gpio);
	release_region(chip->io_base, GPIO_REGION_SIZE);
	pci_disable_device(pdev);
	kfree(chip);
}


static struct pci_driver dh89xxcc_gpi_driver = {
	.name = "dh89xxcc_gpio",
	.id_table = dh89xxcc_gpio_pcidev_id,
	.probe = dh89xxcc_gpio_probe,
	.remove = dh89xxcc_gpio_remove,
};

module_pci_driver(dh89xxcc_gpi_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DH89xxCC GPIO PCI Driver");
MODULE_DEVICE_TABLE(pci, dh89xxcc_gpio_pcidev_id);
