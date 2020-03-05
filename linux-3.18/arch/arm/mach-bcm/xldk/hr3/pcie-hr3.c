/*
 * Copyright (C) 2014 Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright (C) 2015 Broadcom Corporatcommon ion
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/msi.h>
#include <linux/clk.h>
#include <linux/module.h>
#include <linux/mbus.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/phy/phy.h>

#define CLK_CONTROL_OFFSET           0x000

#define CFG_IND_ADDR_OFFSET          0x120
#define CFG_IND_ADDR_MASK            0x00001ffc
#define CFG_IND_DATA_OFFSET          0x124

#define CFG_ADDR_OFFSET              0x1f8
#define CFG_ADDR_BUS_NUM_SHIFT       20
#define CFG_ADDR_BUS_NUM_MASK        0x0ff00000
#define CFG_ADDR_DEV_NUM_SHIFT       15
#define CFG_ADDR_DEV_NUM_MASK        0x000f8000
#define CFG_ADDR_FUNC_NUM_SHIFT      12
#define CFG_ADDR_FUNC_NUM_MASK       0x00007000
#define CFG_ADDR_REG_NUM_SHIFT       2
#define CFG_ADDR_REG_NUM_MASK        0x00000ffc
#define CFG_ADDR_CFG_TYPE_SHIFT      0
#define CFG_ADDR_CFG_TYPE_MASK       0x00000003

#define CFG_DATA_OFFSET              0x1fc

#define SYS_RC_INTX_EN               0x330
#define SYS_RC_INTX_MASK             0xf

#define IPROC_PCIE_MAX_NUM_IRQS 6

/**
 * iProc PCIe device
 * @dev: pointer to device data structure
 * @base: PCIe host controller I/O register base
 * @resources: linked list of all PCI resources
 * @sysdata: Per PCI controller data (ARM-specific)
 * @root_bus: pointer to root bus
 * @phy: optional PHY device that controls the Serdes
 * @irqs: interrupt IDs
 */
struct iproc_pcie {
	struct device *dev;
	void __iomem *base;
#ifdef CONFIG_ARM
	struct pci_sys_data sysdata;
#endif
	struct pci_bus *root_bus;
	struct phy *phy;
	int irqs[IPROC_PCIE_MAX_NUM_IRQS];
	int (*map_irq)(const struct pci_dev *, u8, u8);
};

#define PCI_PERST_SWR (1)
#define PCI_CONFIG_SWR (1)

#if PCI_CONFIG_SWR
//extern char * nvram_get(const char *name);
#endif /* PCI_CONFIG_SWR */

#define MII_DEV_LOCAL	0
extern int iproc_mii_write(int dev_type, int phy_addr, u32 reg_off, u16 data);

static inline struct iproc_pcie *iproc_pcie_data(struct pci_bus *bus)
{
	struct iproc_pcie *pcie;
#ifdef CONFIG_ARM
	struct pci_sys_data *sys = bus->sysdata;

	pcie = sys->private_data;
#else
	pcie = bus->sysdata;
#endif
	return pcie;
}

/**
 * Note access to the configuration registers are protected at the higher layer
 * by 'pci_lock' in drivers/pci/access.c
 */
static void __iomem *iproc_pcie_map_cfg_bus(struct pci_bus *bus,
					    unsigned int devfn,
					    int where)
{
	struct iproc_pcie *pcie = iproc_pcie_data(bus);
	unsigned slot = PCI_SLOT(devfn);
	unsigned fn = PCI_FUNC(devfn);
	unsigned busno = bus->number;
	u32 val;

	/* root complex access */
	if (busno == 0) {
		if (slot >= 1)
			return NULL;
		writel(where & CFG_IND_ADDR_MASK,
		       pcie->base + CFG_IND_ADDR_OFFSET);
		return (pcie->base + CFG_IND_DATA_OFFSET);
	}

	if (fn > 1)
		return NULL;

	/* EP device access */
	val = (busno << CFG_ADDR_BUS_NUM_SHIFT) |
		(slot << CFG_ADDR_DEV_NUM_SHIFT) |
		(fn << CFG_ADDR_FUNC_NUM_SHIFT) |
		(where & CFG_ADDR_REG_NUM_MASK) |
		(1 & CFG_ADDR_CFG_TYPE_MASK);
	writel(val, pcie->base + CFG_ADDR_OFFSET);

	return (pcie->base + CFG_DATA_OFFSET);
}

int pci_iproc_config_read32(struct pci_bus *bus, unsigned int devfn,
			      int where, int size, u32 *val)
{
	void __iomem *addr;

	addr = iproc_pcie_map_cfg_bus(bus, devfn, where & ~0x3);
	if (!addr) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	*val = readl(addr);

	if (size <= 2)
		*val = (*val >> (8 * (where & 3))) & ((1 << (size * 8)) - 1);

	return PCIBIOS_SUCCESSFUL;
}
EXPORT_SYMBOL_GPL(pci_iproc_config_read32);

int pci_iproc_config_write32(struct pci_bus *bus, unsigned int devfn,
			       int where, int size, u32 val)
{
	void __iomem *addr;
	u32 mask, tmp;

	addr = iproc_pcie_map_cfg_bus(bus, devfn, where & ~0x3);
	if (!addr)
		return PCIBIOS_DEVICE_NOT_FOUND;

	if (size == 4) {
		writel(val, addr);
		return PCIBIOS_SUCCESSFUL;
	} else {
		mask = ~(((1 << (size * 8)) - 1) << ((where & 0x3) * 8));
	}

	tmp = readl(addr) & mask;
	tmp |= val << ((where & 0x3) * 8);
	writel(tmp, addr);

	return PCIBIOS_SUCCESSFUL;
}
EXPORT_SYMBOL_GPL(pci_iproc_config_write32);

static struct pci_ops iproc_pcie_ops = {
	.read = pci_iproc_config_read32,
	.write = pci_iproc_config_write32,
};

static void iproc_pcie_reset(struct iproc_pcie *pcie)
{
	/* Configure the PCIe controller as root complex and send a downstream reset */
	writel(0, pcie->base + CLK_CONTROL_OFFSET);
	mdelay(1);
	writel(1, pcie->base + CLK_CONTROL_OFFSET);
	mdelay(100);
}

static int pcie_serdes_reg_write(int phyaddr, int reg, u16 val)
{
	iproc_mii_write(MII_DEV_LOCAL, phyaddr, 0x1f, reg & 0xfff0);
	iproc_mii_write(MII_DEV_LOCAL, phyaddr, reg & 0xf, val);
	
	return PCIBIOS_SUCCESSFUL;
}

static int pcie_rc_war(struct iproc_pcie * pcie)
{
 	/* Setting for PCIe Serdes PLL output */
    pcie_serdes_reg_write(2, 0x2103, 0x2b1c);
    pcie_serdes_reg_write(2, 0x1300, 0x000b);
    mdelay(100);

#if PCI_PERST_SWR
	iproc_pcie_reset(pcie);
#endif /* PCI_PERST_SWR */

	return PCIBIOS_SUCCESSFUL;
}

static int iproc_pcie_check_link(struct iproc_pcie *pcie, struct pci_bus *bus)
{
	u8 hdr_type;
	u32 link_ctrl;
	u16 pos, link_status;
	int link_is_active = 0;
	u32 tmp32;
#if PCI_CONFIG_SWR
	u32 devfn = 0;
	char *pcie_configs = NULL;
#endif /* PCI_CONFIG_SWR */


	/* make sure we are not in EP mode */
	pci_bus_read_config_byte(bus, 0, PCI_HEADER_TYPE, &hdr_type);
	if ((hdr_type & 0x7f) != PCI_HEADER_TYPE_BRIDGE) {
		dev_err(pcie->dev, "in EP mode, hdr=%#02x\n", hdr_type);
		return -EFAULT;
	}

	pcie_rc_war(pcie);

#if PCI_CONFIG_SWR
    //pcie_configs = nvram_get("pcie_configs");
	if (pcie_configs == NULL) {
        printk("\nNULL pcie_configs\n");
	} else if (!strcmp(pcie_configs, "tx-de-emp")) {
        pci_bus_read_config_dword(bus, devfn, 0xdc, &tmp32);
        printk("\nLink status control 2 register 0xdc: %08x; enable bit6\n", tmp32);
        tmp32 |= (0x1 << 6);
        pci_bus_write_config_dword(bus, devfn, 0xdc, tmp32);
        pci_bus_read_config_dword(bus, devfn, 0xdc, &tmp32);
        printk("\nLink status control 2 register 0xdc: %08x\n", tmp32);
    }
#endif /* PCI_CONFIG_SWR */

	 /* 
	* Under RC mode, write to function specific register 0x43c, to change
	* the CLASS code in configuration space 
	*/
	pci_bus_read_config_dword(bus, 0, 0x43c, &tmp32);
	tmp32 = (tmp32 & 0xff0000ff) | (PCI_CLASS_BRIDGE_PCI << 8);
	pci_bus_write_config_dword(bus, 0, 0x43c, tmp32);
	/* 
	* After this modification, the CLASS code in configuration space would be
	* read as PCI_CLASS_BRIDGE_PCI(0x0604) instead of network interface(0x0200) 
	*/

#if 0
	/* force class to PCI_CLASS_BRIDGE_PCI (0x0604) */
	pci_bus_write_config_word(bus, 0, PCI_CLASS_DEVICE,
				  PCI_CLASS_BRIDGE_PCI);
#endif

	/* check link status to see if link is active */
	pos = pci_bus_find_capability(bus, 0, PCI_CAP_ID_EXP);
	pci_bus_read_config_word(bus, 0, pos + PCI_EXP_LNKSTA, &link_status);
	if (link_status & PCI_EXP_LNKSTA_NLW)
		link_is_active = 1;

	if (!link_is_active) {
		/* try GEN 1 link speed */
#define PCI_LINK_STATUS_CTRL_2_OFFSET 0x0dc
#define PCI_TARGET_LINK_SPEED_MASK    0xf
#define PCI_TARGET_LINK_SPEED_GEN2    0x2
#define PCI_TARGET_LINK_SPEED_GEN1    0x1
		pci_bus_read_config_dword(bus, 0,
					  PCI_LINK_STATUS_CTRL_2_OFFSET,
					  &link_ctrl);
		if ((link_ctrl & PCI_TARGET_LINK_SPEED_MASK) ==
		    PCI_TARGET_LINK_SPEED_GEN2) {
			link_ctrl &= ~PCI_TARGET_LINK_SPEED_MASK;
			link_ctrl |= PCI_TARGET_LINK_SPEED_GEN1;
			pci_bus_write_config_dword(bus, 0,
					   PCI_LINK_STATUS_CTRL_2_OFFSET,
					   link_ctrl);
			msleep(100);

			pos = pci_bus_find_capability(bus, 0, PCI_CAP_ID_EXP);
			pci_bus_read_config_word(bus, 0, pos + PCI_EXP_LNKSTA,
						 &link_status);
			if (link_status & PCI_EXP_LNKSTA_NLW)
				link_is_active = 1;
		}
	}

	dev_info(pcie->dev, "link: %s\n", link_is_active ? "UP" : "DOWN");

	return link_is_active ? 0 : -ENODEV;
}

static void iproc_pcie_enable(struct iproc_pcie *pcie)
{
	writel(SYS_RC_INTX_MASK, pcie->base + SYS_RC_INTX_EN);
}

int iproc_pcie_setup(struct iproc_pcie *pcie, struct list_head *res)
{
	int ret;
	void *sysdata;
	struct pci_bus *bus;

	if (!pcie || !pcie->dev || !pcie->base)
		return -EINVAL;

	ret = phy_init(pcie->phy);
	if (ret) {
		dev_err(pcie->dev, "unable to initialize PCIe PHY\n");
		return ret;
	}

	ret = phy_power_on(pcie->phy);
	if (ret) {
		dev_err(pcie->dev, "unable to power on PCIe PHY\n");
		goto err_exit_phy;
	}

	iproc_pcie_reset(pcie);

#ifdef CONFIG_ARM
	pcie->sysdata.private_data = pcie;
	sysdata = &pcie->sysdata;
#else
	sysdata = pcie;
#endif

	bus = pci_create_root_bus(pcie->dev, 0, &iproc_pcie_ops, sysdata, res);
//	bus = pci_scan_root_bus(pcie->dev, 0, &iproc_pcie_ops, sysdata, res);
	if (!bus) {
		dev_err(pcie->dev, "unable to create PCI root bus\n");
		ret = -ENOMEM;
		goto err_power_off_phy;
	}
	pcie->root_bus = bus;

	ret = iproc_pcie_check_link(pcie, bus);
	if (ret) {
		dev_err(pcie->dev, "no PCIe EP device detected\n");
		goto err_rm_root_bus;
	}

	iproc_pcie_enable(pcie);

	pci_scan_child_bus(bus);
	pci_assign_unassigned_bus_resources(bus);
#ifdef CONFIG_ARM
	pci_fixup_irqs(pci_common_swizzle, pcie->map_irq);
#endif
	pci_bus_add_devices(bus);

	return 0;

err_rm_root_bus:
	pci_stop_root_bus(bus);
	pci_remove_root_bus(bus);

err_power_off_phy:
	phy_power_off(pcie->phy);
err_exit_phy:
	phy_exit(pcie->phy);
	return ret;
}
EXPORT_SYMBOL(iproc_pcie_setup);


int iproc_pcie_map_irq(const struct pci_dev *pdev, u8 slot, u8 pin)
{
	struct iproc_pcie *pcie = iproc_pcie_data(pdev->bus);
	int irq = pcie->irqs[4];
   
    return irq;				
}

static int iproc_pcie_probe(struct platform_device *pdev)
{
	struct iproc_pcie *pcie;
	struct device_node *np = pdev->dev.of_node;
	struct resource reg;
	resource_size_t iobase = 0;
	LIST_HEAD(res);
	int ret;
	u32 irqs_total;
	int i;

	pcie = devm_kzalloc(&pdev->dev, sizeof(struct iproc_pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pcie->dev = &pdev->dev;
	platform_set_drvdata(pdev, pcie);

	ret = of_address_to_resource(np, 0, &reg);
	if (ret < 0) {
		dev_err(pcie->dev, "unable to obtain controller resources\n");
		return ret;
	}

	pcie->base = devm_ioremap(pcie->dev, reg.start, resource_size(&reg));
	if (!pcie->base) {
		dev_err(pcie->dev, "unable to map controller registers\n");
		return -ENOMEM;
	}

	/* PHY use is optional */
	pcie->phy = devm_phy_get(&pdev->dev, "pcie-phy");
	if (IS_ERR(pcie->phy)) {
		if (PTR_ERR(pcie->phy) == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		pcie->phy = NULL;
	}

	ret = of_pci_get_host_bridge_resources(np, 0, 0xff, &res, &iobase);
	if (ret) {
		dev_err(pcie->dev,
			"unable to get PCI host bridge resources\n");
		return ret;
	}

	/*Parse IRQ*/ 	
  	irqs_total = of_irq_count(np);
  	if ( !irqs_total || (irqs_total > IPROC_PCIE_MAX_NUM_IRQS) )
  		return -EINVAL;
  	
	for (i = 0; i < irqs_total; i++) {
		pcie->irqs[i] = irq_of_parse_and_map(np, i);
		if (!pcie->irqs[i]) {
			dev_err(&pdev->dev, "unable to parse or map irq index:%d\n", i);
			return -EINVAL;
		}
	}


	//pcie->map_irq = of_irq_parse_and_map_pci;
	pcie->map_irq = iproc_pcie_map_irq;

	ret = iproc_pcie_setup(pcie, &res);
	if (ret)
		dev_err(pcie->dev, "PCIe controller setup failed\n");

	pci_free_resource_list(&res);

	return ret;
}

static int iproc_pcie_remove(struct platform_device *pdev)
{
	struct iproc_pcie *pcie = platform_get_drvdata(pdev);

	pci_stop_root_bus(pcie->root_bus);
	pci_remove_root_bus(pcie->root_bus);

	phy_power_off(pcie->phy);
	phy_exit(pcie->phy);

	return 0;
}

static const struct of_device_id iproc_pcie_of_match_table[] = {
	{ .compatible = "broadcom,hr3-pcie", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, iproc_pcie_of_match_table);

static struct platform_driver iproc_pcie_pltfm_driver = {
	.driver = {
		.name = "hr3-pcie",
		.of_match_table = of_match_ptr(iproc_pcie_of_match_table),
	},
	.probe = iproc_pcie_probe,
	.remove = iproc_pcie_remove,
};
module_platform_driver(iproc_pcie_pltfm_driver);
