/*
 * Copyright (C) 2014 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Features to be supported in the future:
 * 1) Hotplug
 * 2) AER
 *
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
#define EP_PERST_SOURCE_SELECT_SHIFT 2
#define EP_PERST_SOURCE_SELECT       (1 << EP_PERST_SOURCE_SELECT_SHIFT)
#define EP_MODE_SURVIVE_PERST_SHIFT  1
#define EP_MODE_SURVIVE_PERST        (1 << EP_MODE_SURVIVE_PERST_SHIFT)
#define RC_PCIE_RST_OUTPUT_SHIFT     0
#define RC_PCIE_RST_OUTPUT           (1 << RC_PCIE_RST_OUTPUT_SHIFT)

#define CFG_ADDR_OFFSET              0x1F8
#define CFG_ADDR_BUS_NUM_SHIFT       20
#define CFG_ADDR_BUS_NUM_MASK        0x0FF00000
#define CFG_ADDR_DEV_NUM_SHIFT       15
#define CFG_ADDR_DEV_NUM_MASK        0x000F8000
#define CFG_ADDR_FUNC_NUM_SHIFT      12
#define CFG_ADDR_FUNC_NUM_MASK       0x00007000
#define CFG_ADDR_REG_NUM_SHIFT       2
#define CFG_ADDR_REG_NUM_MASK        0x00000FFC
#define CFG_ADDR_CFG_TYPE_SHIFT      0
#define CFG_ADDR_CFG_TYPE_MASK       0x00000003

#define CFG_DATA_OFFSET			0x1FC
#define CFG_IND_ADDR_MASK		0x00001FFC

enum iproc_pcie_device {
	IPROC_STD = 0,
	IPROC_NITRO = 1,
};

struct iproc_pcie_data {
	enum iproc_pcie_device type;

	unsigned int num_pf;

	unsigned int cfg_ind_add_offset;
	unsigned int cfg_ind_data_offset;
};


#define NITRO_NUM_PF			4
#define NITRO_CFG_IND_ADDR_OFFSET	0x1f0
#define NITRO_CFG_IND_DATA_OFFSET	0x1f4

#define NITRO_MSIX_GEN_CONFIG_OFFSET	0xe80
#define NITRO_EQ_PAGE_PF_OFFSET		0xc00
#define NITRO_EQ_PAGE_UPPER_PF_OFFSET	0xc04
#define NITRO_MSI_PAGE_PF_OFFSET	0xc08
#define NITRO_MSI_PAGE_UPPER_PF_OFFSET	0xc0c
#define NITRO_MSI_CTRL_0_PF_OFFSET	0xc40
#define NITRO_EQ_PAGE_VF_OFFSET		0xc80
#define NITRO_EQ_PAGE_UPPER_VF_OFFSET	0xc84
#define NITRO_MSI_PAGE_VF_OFFSET	0xc88
#define NITRO_MSI_PAGE_UPPER_VF_OFFSET	0xc8c
#define NITRO_MSI_CTRL_0_VF_OFFSET	0xd80

#define NITRO_EQ_HEAD_0_PF_OFFSET	0xc50
#define NITRO_EQ_TAIL_0_PF_OFFSET	0xc60
#define NITRO_EQ_HEAD_0_VF_OFFSET	0xdc0
#define NITRO_EQ_TAIL_0_VF_OFFSET	0xe00


#define GEN_NUM_PF			1
#define GEN_CFG_IND_ADDR_OFFSET		0x120
#define GEN_CFG_IND_DATA_OFFSET		0x124

#define SYS_EQ_PAGE_OFFSET		0x200
#define SYS_MSI_PAGE_OFFSET		0x204
#define SYS_EQ_PAGE_UPPER_OFFSET	0x2c0
#define SYS_MSI_PAGE_UPPER_OFFSET	0x2c4


#define SYS_MSI_INTS_EN_OFFSET       0x208

#define SYS_MSI_CTRL_0_OFFSET        0x210
#define SYS_MSI_INTR_EN_SHIFT        11
#define SYS_MSI_INTR_EN              (1 << SYS_MSI_INTR_EN_SHIFT)
#define SYS_MSI_INT_N_EVENT_SHIFT    1
#define SYS_MSI_INT_N_EVENT          (1 << SYS_MSI_INT_N_EVENT_SHIFT)
#define SYS_MSI_EQ_EN_SHIFT          0
#define SYS_MSI_EQ_EN                (1 << SYS_MSI_EQ_EN_SHIFT)

#define SYS_EQ_HEAD_0_OFFSET         0x250
#define SYS_EQ_TAIL_0_OFFSET         0x254
#define SYS_EQ_TAIL_0_MASK           0x3F
#define SYS_RC_INTX_EN               0x330
#define SYS_RC_INTX_MASK             0xF

#define SYS_RC_INTX_CSR              0x334
#define SYS_RC_INTX_MASK             0xF

#define PCIE_LINK_STATUS_OFFSET      0xF0C
#define PCIE_PHYLINKUP_SHITF         3
#define PCIE_PHYLINKUP               (1 << PCIE_PHYLINKUP_SHITF)
#define PCIE_DL_ACTIVE_SHIFT         2
#define PCIE_DL_ACTIVE               (1 << PCIE_DL_ACTIVE_SHIFT)

#define STRAP_STATUS_OFFSET          0xF10
#define STRAP_1LANE_SHIFT            2
#define STRAP_1LANE                  (1 << STRAP_1LANE_SHIFT)
#define STRAP_IF_ENABLE_SHIFT        1
#define STRAP_IF_ENABLE              (1 << STRAP_IF_ENABLE_SHIFT)
#define STRAP_RC_MODE_SHIFT          0
#define STRAP_RC_MODE                (1 << STRAP_RC_MODE_SHIFT)

#define PCI_BRIDGE_CTRL_REG_OFFSET    0x43c
#define PCI_CLASS_BRIDGE_PCI_MASK     0xff0000ff

struct iproc_pcie;

/**
 * iProc MSI
 * @pcie: pointer to the iProc PCIe data structure
 * @irq_in_use: bitmap of MSI IRQs that are in use
 * @domain: MSI IRQ domain
 * @chip: MSI chip
 * @eq_page: memory page to store the iProc MSI event queue
 * @msi_page: memory page for MSI posted writes
 */
struct iproc_msi {
	struct iproc_pcie *pcie;
	unsigned long irq_in_use;
	struct irq_domain *domain;
	struct msi_chip chip;
	unsigned long *eq_page;
	unsigned long *msi_page;
};

/**
 * iProc PCIe
 * @dev: pointer to the device
 * @reg: PCIe I/O register base
 * @phy: optional PHY device that controls the Serdes
 * @io: PCIe I/O resource
 * @mem: PCIe memory resource
 * @busn: PCIe bus resource
 * @irqs: Array that stores IRQs
 * @msi: MSI related info
 */
struct iproc_pcie {
	struct device *dev;

	void __iomem *reg;

	struct phy *phy;

	struct resource io;
	struct resource mem;
	struct resource busn;

	unsigned int max_irqs;
	int *irqs;

	struct iproc_msi msi;
	const struct iproc_pcie_data *soc_data;
};

static inline struct iproc_pcie *sys_to_pcie(struct pci_sys_data *sys)
{
	return sys->private_data;
}

static void iproc_pcie_reset(struct iproc_pcie *pcie)
{
	if (pcie->soc_data->type == IPROC_NITRO) {
		writel(0x0000007F, pcie->reg + CLK_CONTROL_OFFSET);
	} else {
		u32 val;

		/*
		 * Select perst_b signal as reset source, and put the device in
		 * reset
		 */
		val = readl(pcie->reg + CLK_CONTROL_OFFSET);
		val &= ~EP_PERST_SOURCE_SELECT & ~EP_MODE_SURVIVE_PERST &
			~RC_PCIE_RST_OUTPUT;
		writel(val, pcie->reg + CLK_CONTROL_OFFSET);
		udelay(250);

		/* now bring it out of reset*/
		val |= RC_PCIE_RST_OUTPUT;
		writel(val, pcie->reg + CLK_CONTROL_OFFSET);
		mdelay(250);
	}
}

#define INVALID_ACCESS_OFFSET 0xFFFFFFFF
static u32 iproc_pcie_conf_access(struct iproc_pcie *pcie, struct pci_bus *bus,
		unsigned int devfn, int where)
{
	/* root complex access */
	if (bus->number == 0) {
		if (PCI_SLOT(devfn))
			return INVALID_ACCESS_OFFSET;
		writel(where & CFG_IND_ADDR_MASK,
				pcie->reg + pcie->soc_data->cfg_ind_add_offset);
		return pcie->soc_data->cfg_ind_data_offset;
	} else {
		u32 val;

		/* access of EP deivce */
		val = (bus->number << CFG_ADDR_BUS_NUM_SHIFT) |
		      (PCI_SLOT(devfn) << CFG_ADDR_DEV_NUM_SHIFT) |
		      (PCI_FUNC(devfn) << CFG_ADDR_FUNC_NUM_SHIFT) |
		      (where & CFG_ADDR_REG_NUM_MASK) |
		      (1 & CFG_ADDR_CFG_TYPE_MASK);
		writel(val, pcie->reg + CFG_ADDR_OFFSET);
	}

	return CFG_DATA_OFFSET;
}

#define INVALID_CFG_RD 0xFFFFFFFF
static int iproc_pci_read_conf(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 *val)
{
	u32 offset;
	struct iproc_pcie *pcie;

	*val = INVALID_CFG_RD;
	if (!bus || !bus->sysdata) {
		/*
		 * Use pr_err since we cannot obtain a valid device pointer
		 * in this case
		 */
		pr_err("pci rd conf: invalid pci bus\n");
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	pcie = sys_to_pcie(bus->sysdata);
	if (!pcie) {
		pr_err("pci rd conf: invalid pci bus private data\n");
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	if (size != 1 && size != 2 && size != 4)
		return PCIBIOS_BAD_REGISTER_NUMBER;
	else if ((size == 2) && (where & 1))
		return PCIBIOS_BAD_REGISTER_NUMBER;
	else if ((size == 4) && (where & 3))
		return PCIBIOS_BAD_REGISTER_NUMBER;

	pcie = sys_to_pcie(bus->sysdata);

	if (PCI_FUNC(devfn) >= pcie->soc_data->num_pf || PCI_SLOT(devfn) > 0)
		return PCIBIOS_FUNC_NOT_SUPPORTED;

	offset = iproc_pcie_conf_access(pcie, bus, devfn, where);
	if (offset == INVALID_ACCESS_OFFSET)
		return PCIBIOS_BAD_REGISTER_NUMBER;

	*val = readl(pcie->reg + offset);

	switch (size) {
	case 4:
		/* return raw data */
		break;
	case 2:
		*val = (*val >> (8 * (where & 3))) & 0xFFFF;
		break;
	case 1:
		*val = (*val >> (8 * (where & 3))) & 0xFF;
		break;
	default:
		BUG_ON(1);
	}

	dev_dbg(pcie->dev, "conf rd: busn=%d devfn=%d where=%d size=%d val=0x%08x\n",
			bus->number, devfn, where, size, *val);

	return PCIBIOS_SUCCESSFUL;
}

static int iproc_pci_write_conf(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 val)
{
	int shift;
	u32 offset, data;
	struct iproc_pcie *pcie;

	if (!bus || !bus->sysdata) {
		/*
		 * Use pr_err since we cannot obtain a valid device pointer
		 * in this case
		 */
		pr_err("pci wr conf: invalid pci bus\n");
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	pcie = sys_to_pcie(bus->sysdata);
	if (!pcie) {
		pr_err("pci wr conf: invalid pci bus private data\n");
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	if (size != 1 && size != 2 && size != 4)
		return PCIBIOS_BAD_REGISTER_NUMBER;
	else if ((size == 2) && (where & 1))
		return PCIBIOS_BAD_REGISTER_NUMBER;
	else if ((size == 4) && (where & 3))
		return PCIBIOS_BAD_REGISTER_NUMBER;

	offset = iproc_pcie_conf_access(pcie, bus, devfn, where);
	if (offset == INVALID_ACCESS_OFFSET)
		return PCIBIOS_BAD_REGISTER_NUMBER;

	data = readl(pcie->reg + offset);

	switch (size) {
	case 4:
		data = val;
		break;
	case 2:
		shift = 8 * (where & 2);
		data &= ~(0xFFFF << shift);
		data |= ((val & 0xFFFF) << shift);
		break;
	case 1:
		shift = 8 * (where & 3);
		data &= ~(0xFF << shift);
		data |= ((val & 0xFF) << shift);
		break;
	default:
		BUG_ON(1);
	}

	writel(data, pcie->reg + offset);

	dev_dbg(pcie->dev,
		"config wr: busn=%d devfn=%d where=%d size=%d data=0x%08x\n",
		bus->number, devfn, where, size, data);

	return PCIBIOS_SUCCESSFUL;
}

static struct pci_ops iproc_pcie_ops = {
	.read = iproc_pci_read_conf,
	.write = iproc_pci_write_conf,
};

/*
 * Utility function that creates a dummy PCI bus that can be used to access the
 * root complex
 */
static void iproc_pcie_create_rc_dummy_bus(struct iproc_pcie *pcie,
					   struct pci_bus *bus,
					   struct pci_sys_data *sys)
{
	memset(sys, 0, sizeof(*sys));
	memset(bus, 0, sizeof(*bus));

	bus->ops = &iproc_pcie_ops;
	bus->sysdata = sys;
	sys->private_data = pcie;
}

static int iproc_pcie_check_link(struct iproc_pcie *pcie)
{
	u8 hdr_type;
	u32 link_ctrl;
	u16 pos, link_status;
	u32 val;
	bool link_is_active = false;
	struct pci_bus bus;
	struct pci_sys_data sys;

	if (pcie->soc_data->type == IPROC_NITRO)
		return 0;

	val = readl(pcie->reg + PCIE_LINK_STATUS_OFFSET);
	dev_info(pcie->dev, "link status: 0x%08x\n", val);
	if (!(val & PCIE_PHYLINKUP) || !(val & PCIE_DL_ACTIVE)) {
		dev_err(pcie->dev, "PHY or data link is INACTIVE!\n");
		return -ENODEV;
	}

	val = readl(pcie->reg + STRAP_STATUS_OFFSET);
	dev_dbg(pcie->dev, "strap status: 0x%08x\n", val);

	iproc_pcie_create_rc_dummy_bus(pcie, &bus, &sys);

	pci_bus_read_config_byte(&bus, 0, PCI_HEADER_TYPE, &hdr_type);
	if ((hdr_type & 0x7f) != PCI_HEADER_TYPE_BRIDGE) {
		dev_err(pcie->dev, "in EP mode, hdr=0x08%x\n", hdr_type);
		return -EFAULT;
	}

	/* force class to PCI_CLASS_BRIDGE_PCI (0x0604) */
	pci_bus_read_config_dword(&bus, 0, PCI_BRIDGE_CTRL_REG_OFFSET, &val);
	val = (val & PCI_CLASS_BRIDGE_PCI_MASK) | (PCI_CLASS_BRIDGE_PCI << 8);
	pci_bus_write_config_dword(&bus, 0, PCI_BRIDGE_CTRL_REG_OFFSET, val);

	/* check link status to see if link is active */
	pos = pci_bus_find_capability(&bus, 0, PCI_CAP_ID_EXP);
	pci_bus_read_config_word(&bus, 0, pos + PCI_EXP_LNKSTA, &link_status);
	if (link_status & PCI_EXP_LNKSTA_NLW)
		link_is_active = true;

	if (!link_is_active) {
		/* try GEN 1 link speed */
#define PCI_LINK_CTRL_2_OFFSET        0x0dc
#define PCI_TARGET_LINK_SPEED_MASK    0xf
#define PCI_TARGET_LINK_SPEED_GEN2    0x2
#define PCI_TARGET_LINK_SPEED_GEN1    0x1
		pci_bus_read_config_dword(&bus, 0, PCI_LINK_CTRL_2_OFFSET,
					  &link_ctrl);
		if ((link_ctrl & PCI_TARGET_LINK_SPEED_MASK) ==
		    PCI_TARGET_LINK_SPEED_GEN2) {
			link_ctrl &= ~PCI_TARGET_LINK_SPEED_MASK;
			link_ctrl |= PCI_TARGET_LINK_SPEED_GEN1;
			pci_bus_write_config_dword(&bus, 0,
						   PCI_LINK_CTRL_2_OFFSET,
						   link_ctrl);
			msleep(100);

			pos = pci_bus_find_capability(&bus, 0, PCI_CAP_ID_EXP);
			pci_bus_read_config_word(&bus, 0, pos + PCI_EXP_LNKSTA,
						 &link_status);
			if (link_status & PCI_EXP_LNKSTA_NLW)
				link_is_active = true;
		}
	}

	dev_info(pcie->dev, "link: %s\n", link_is_active ? "UP" : "DOWN");

	return 0;
}

/*
 * As a PCIE RC driver, the OMAP/OARR could be disabled since we set OMAP/OARR
 * the same value of PCIE window range. This takes the same effect as no
 * address translation
 *
 * As a PCIE RC drive, the IMAP/IARR could be disabled and let the device
 * decide which address to write to
 *
 * In the end, here we only need to reserve the outbound memory resource
 */
static int iproc_pcie_setup(int nr, struct pci_sys_data *sys)
{
	struct iproc_pcie *pcie = sys_to_pcie(sys);

	pci_add_resource(&sys->resources, &pcie->io);
	pci_add_resource(&sys->resources, &pcie->mem);
	pci_add_resource(&sys->resources, &pcie->busn);

	return 1;
}

static struct pci_bus *iproc_pcie_scan_bus(int nr, struct pci_sys_data *sys)
{
	struct iproc_pcie *pcie = sys->private_data;
	struct pci_bus *bus;

	bus = pci_create_root_bus(pcie->dev, sys->busnr, &iproc_pcie_ops, sys,
			&sys->resources);
	if (!bus)
		return NULL;

	if (IS_ENABLED(CONFIG_PCI_MSI))
		bus->msi = &pcie->msi.chip;

	pci_scan_child_bus(bus);

	/* After the PCI-E bus has been walked and all devices discovered,
	 * configure any settings of the fabric that might be necessary.
	 */
	if (bus) {
		struct pci_bus *child;
		list_for_each_entry(child, &bus->children, node)
			pcie_bus_configure_settings(child);
	}

	return bus;
}

static int iproc_pcie_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct iproc_pcie *pcie = sys_to_pcie(dev->sysdata);

	/* need to use the 5th IRQ for INTx */
	return pcie->irqs[4];
}

static struct hw_pci hw;

static void iproc_pcie_enable(struct iproc_pcie *pcie)
{
	hw.nr_controllers = 1;
	hw.private_data = (void **)&pcie;
	hw.setup = iproc_pcie_setup;
	hw.scan = iproc_pcie_scan_bus;
	hw.map_irq = iproc_pcie_map_irq;
	hw.ops = &iproc_pcie_ops;

	/* enable root complex INTX */
	if (pcie->soc_data->type != IPROC_NITRO)
		writel(SYS_RC_INTX_MASK, pcie->reg + SYS_RC_INTX_EN);

	pci_common_init_dev(pcie->dev, &hw);
#ifdef CONFIG_PCI_DOMAINS
	hw.domain++;
#endif
}

static inline struct iproc_msi *to_iproc_msi(struct msi_chip *chip)
{
	return container_of(chip, struct iproc_msi, chip);
}

static int iproc_msi_irq_assign(struct iproc_msi *chip)
{
	int msi;

	msi = find_first_zero_bit(&chip->irq_in_use, chip->pcie->max_irqs);
	if (msi < chip->pcie->max_irqs)
		set_bit(msi, &chip->irq_in_use);
	else
		msi = -ENOSPC;

	return msi;
}

static void iproc_msi_irq_free(struct iproc_msi *chip, unsigned long irq)
{
	clear_bit(irq, &chip->irq_in_use);
}

static int iproc_msi_setup_irq(struct msi_chip *chip,
		struct pci_dev *pdev, struct msi_desc *desc)
{
	struct iproc_msi *msi = to_iproc_msi(chip);
	struct iproc_pcie *pcie = msi->pcie;
	struct msi_msg msg;
	unsigned int irq;
	int hwirq;
	unsigned long addr;

	hwirq = iproc_msi_irq_assign(msi);
	if (hwirq < 0)
		return hwirq;

	irq = irq_create_mapping(msi->domain, hwirq);
	if (!irq) {
		iproc_msi_irq_free(msi, hwirq);
		return -EINVAL;
	}

	dev_dbg(pcie->dev, "mapped irq:%d\n", irq);

	irq_set_msi_desc(irq, desc);

	addr = virt_to_phys((void *)msi->msi_page[0]) | (hwirq * 4);
	msg.address_lo = addr & 0xffffffff;
	msg.address_hi = addr >> 32;
	msg.data = hwirq;

	write_msi_msg(irq, &msg);

	return 0;
}

static void iproc_msi_teardown_irq(struct msi_chip *chip, unsigned int irq)
{
	struct iproc_msi *msi = to_iproc_msi(chip);
	struct irq_data *data = irq_get_irq_data(irq);

	iproc_msi_irq_free(msi, data->hwirq);
}

static struct irq_chip iproc_msi_irq_chip = {
	.name = "iProc PCIe MSI",
	.irq_enable = unmask_msi_irq,
	.irq_disable = mask_msi_irq,
	.irq_mask = mask_msi_irq,
	.irq_unmask = unmask_msi_irq,
};

static int iproc_msi_map(struct irq_domain *domain, unsigned int irq,
			irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &iproc_msi_irq_chip, handle_simple_irq);
	irq_set_chip_data(irq, domain->host_data);
	set_irq_flags(irq, IRQF_VALID);

	return 0;
}

static const struct irq_domain_ops iproc_msi_domain_ops = {
	.map = iproc_msi_map,
};

static irqreturn_t iproc_msi_irq(int irq, void *data)
{
	struct iproc_pcie *pcie = data;
	unsigned int eq, head, tail, num_events;

	/* Do not handle INTx interrupt */
	if ((readl(pcie->reg + SYS_RC_INTX_CSR) & SYS_RC_INTX_MASK) != 0)
		return IRQ_NONE;

	eq = irq - pcie->irqs[0];
	BUG_ON(eq >= pcie->max_irqs);

	irq = irq_find_mapping(pcie->msi.domain, eq);
	head = readl(pcie->reg + SYS_EQ_HEAD_0_OFFSET + (eq * 8));
	do {
		tail = readl(pcie->reg + SYS_EQ_TAIL_0_OFFSET + (eq * 8));
		tail &= SYS_EQ_TAIL_0_MASK;

		num_events = (tail < head) ?
			(64 + (tail - head)) : (tail - head);
		if (!num_events)
			break;

		generic_handle_irq(irq);

		head++;
		head %= 64;
		writel(head, pcie->reg + SYS_EQ_HEAD_0_OFFSET + (eq * 8));
	} while (true);

	return IRQ_HANDLED;
}

static void iproc_pcie_msi_enable(struct iproc_pcie *pcie)
{
	struct iproc_msi *msi = &pcie->msi;
	int i;
	u32 val;

	writel(virt_to_phys((void *)msi->eq_page[0]),
			pcie->reg + SYS_EQ_PAGE_OFFSET);
	writel(virt_to_phys((void *)msi->msi_page[0]),
			pcie->reg + SYS_MSI_PAGE_OFFSET);
#ifdef CONFIG_ARCH_NORTHSTAR2
	writel(virt_to_phys((void *)msi->eq_page[0]) >> 32,
			pcie->reg + SYS_EQ_PAGE_UPPER_OFFSET);
	writel(virt_to_phys((void *)msi->msi_page[0]) >> 32,
			pcie->reg + SYS_MSI_PAGE_UPPER_OFFSET);
#endif
	for (i = 0; i < pcie->max_irqs; i++) {
		/* enable MSI event queue and interrupt */
		val = SYS_MSI_INTR_EN | SYS_MSI_INT_N_EVENT | SYS_MSI_EQ_EN;
		writel(val, pcie->reg + SYS_MSI_CTRL_0_OFFSET + (i * 4));
		/*
		 * To support legacy platforms that require the MSI interrupt
		 * enable register to be set explicitly
		 */
		if (of_find_property(pcie->dev->of_node,
				     "have-msi-inten-reg", NULL)) {
			val = readl(pcie->reg + SYS_MSI_INTS_EN_OFFSET);
			val |= (1 << i);
			writel(val, pcie->reg + SYS_MSI_INTS_EN_OFFSET);
		}
	}
}

static int iproc_pcie_msi_init(struct iproc_pcie *pcie)
{
	struct iproc_msi *msi = &pcie->msi;
	int i, ret;

	msi->pcie = pcie;
	msi->chip.dev = pcie->dev;
	msi->chip.setup_irq = iproc_msi_setup_irq;
	msi->chip.teardown_irq = iproc_msi_teardown_irq;
	msi->irq_in_use = 0;

	msi->domain = irq_domain_add_linear(pcie->dev->of_node, pcie->max_irqs,
			&iproc_msi_domain_ops, &msi->chip);
	if (!msi->domain) {
		dev_err(pcie->dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}

	for (i = 0; i < pcie->max_irqs; i++) {
		ret = devm_request_irq(pcie->dev, pcie->irqs[i],
			iproc_msi_irq, IRQF_SHARED, "iproc-pcie", pcie);
		if (ret < 0) {
			dev_err(pcie->dev, "failed to request IRQ: %d\n",
					pcie->irqs[i]);
			goto err_rm_irq_domain;
		}
	}

	msi->eq_page = devm_kmalloc(pcie->dev, sizeof(unsigned long), GFP_KERNEL);
	if (!msi->eq_page) {
		dev_err(pcie->dev, "Error allocating EQ Pages\n");
		ret = -ENOMEM;
		goto err_rm_irq_domain;
	}

	msi->msi_page = devm_kmalloc(pcie->dev, sizeof(unsigned long), GFP_KERNEL);
	if (!msi->msi_page) {
		dev_err(pcie->dev, "Error allocating MSI Pages\n");
		ret = -ENOMEM;
		goto err_rm_irq_domain;
	}

	msi->eq_page[0] = __get_free_page(GFP_KERNEL);
	if (!msi->eq_page[0]) {
		dev_err(pcie->dev,
			"failed to allocate memory for MSI event queue\n");
		ret = -ENOMEM;
		goto err_rm_irq_domain;
	}

	msi->msi_page[0] = __get_free_page(GFP_KERNEL);
	if (!msi->msi_page[0]) {
		dev_err(pcie->dev,
			"failed to allocate memory for MSI\n");
		ret = -ENOMEM;
		goto err_free_msi_eq_page;
	}

	iproc_pcie_msi_enable(pcie);

	dev_info(pcie->dev, "MSI enabled\n");
	return 0;

err_free_msi_eq_page:
	free_page(msi->eq_page[0]);

err_rm_irq_domain:
	irq_domain_remove(msi->domain);
	return ret;
}

static int iproc_msix_irq_assign(struct iproc_msi *chip)
{
	int irq;

	irq = find_first_zero_bit(&chip->irq_in_use, chip->pcie->max_irqs);
	if (irq < chip->pcie->max_irqs)
		set_bit(irq, &chip->irq_in_use);
	else
		irq = -ENOSPC;

	return irq;
}

static void iproc_msix_irq_free(struct iproc_msi *chip, unsigned long irq)
{
	clear_bit(irq, &chip->irq_in_use);
}

static int iproc_msix_setup_irq(struct msi_chip *chip,
		struct pci_dev *pdev, struct msi_desc *desc)
{
	struct iproc_msi *msi = to_iproc_msi(chip);
	struct iproc_pcie *pcie = msi->pcie;
	struct msi_msg msg;
	unsigned int irq;
	int hwirq;
	unsigned long addr;

	hwirq = iproc_msix_irq_assign(msi);
	if (hwirq < 0)
		return hwirq;

	irq = irq_create_mapping(msi->domain, hwirq);
	if (!irq) {
		iproc_msi_irq_free(msi, hwirq);
		return -EINVAL;
	}

	dev_dbg(pcie->dev, "mapped irq:%d\n", irq);

	irq_set_msi_desc(irq, desc);

	addr = virt_to_phys((void *)msi->msi_page[hwirq]);
	msg.address_lo = addr & 0xffffffff;
	msg.address_hi = addr >> 32;
	msg.data = hwirq;

	write_msi_msg(irq, &msg);

	return 0;
}

static void iproc_msix_teardown_irq(struct msi_chip *chip, unsigned int irq)
{
	struct iproc_msi *msi = to_iproc_msi(chip);
	struct irq_data *data = irq_get_irq_data(irq);

	iproc_msix_irq_free(msi, data->hwirq);
}

static int iproc_irq_set_affinity(struct irq_data *data,
				  const struct cpumask *dest,
				  bool force)
{
	struct irq_chip *chip;
	struct msi_desc *md = irq_data_get_msi(data);
	struct iproc_pcie *pcie = sys_to_pcie(md->dev->bus->self->sysdata);
	int irq = pcie->irqs[0];
	struct irq_data new_data;

	chip = irq_get_chip(data->hwirq + irq);
	new_data.chip_data = irq_get_chip_data(data->hwirq + irq);
	new_data.chip = chip;
	new_data.hwirq = data->hwirq + irq;
	new_data.irq = data->hwirq + irq;
	return chip->irq_set_affinity(&new_data, dest, force);
}

static struct irq_chip iproc_msix_irq_chip = {
	.name = "iProc PCIe MSI-X",
	.irq_enable = unmask_msi_irq,
	.irq_disable = mask_msi_irq,
	.irq_mask = mask_msi_irq,
	.irq_unmask = unmask_msi_irq,
	/* FIXME - this is a pretty ugly hack.  In newer kernels, call
	 * msi_domain_set_affinity instead.
	 */
	.irq_set_affinity = iproc_irq_set_affinity,
};

static int iproc_msix_map(struct irq_domain *domain, unsigned int irq,
			irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &iproc_msix_irq_chip, handle_simple_irq);
	irq_set_chip_data(irq, domain->host_data);
	set_irq_flags(irq, IRQF_VALID);

	return 0;
}

static const struct irq_domain_ops iproc_msix_domain_ops = {
	.map = iproc_msix_map,
};

static irqreturn_t iproc_msix_irq(int irq, void *data)
{
	struct iproc_pcie *pcie = data;
	unsigned int eq, head, head_off, tail, tail_off, num_events;

	eq = irq - pcie->irqs[0];
	BUG_ON(eq >= pcie->max_irqs);

	if (eq < pcie->soc_data->num_pf) {
		head_off = NITRO_EQ_HEAD_0_PF_OFFSET + (eq * 4);
		tail_off = NITRO_EQ_TAIL_0_PF_OFFSET + (eq * 4);
	} else {
		u32 vf = (eq - pcie->soc_data->num_pf) * 4;
		head_off = NITRO_EQ_HEAD_0_VF_OFFSET + vf;
		tail_off = NITRO_EQ_TAIL_0_VF_OFFSET + vf;
	}

	irq = irq_find_mapping(pcie->msi.domain, eq);
	head = readl(pcie->reg + head_off);
	head &= SYS_EQ_TAIL_0_MASK;
	do {
		tail = readl(pcie->reg + tail_off);
		tail &= SYS_EQ_TAIL_0_MASK;

		num_events = (tail < head) ? (64 + (tail - head)) :
					     (tail - head);
		if (!num_events)
			break;

		generic_handle_irq(irq);

		head++;
		head %= 64;
		writel(head, pcie->reg + head_off);
	} while (true);

	return IRQ_HANDLED;
}

static int iproc_pcie_msix_init(struct iproc_pcie *pcie)
{
	struct iproc_msi *msi = &pcie->msi;
	int i, ret;
	u32 val;

	msi->pcie = pcie;
	msi->chip.dev = pcie->dev;
	msi->chip.setup_irq = iproc_msix_setup_irq;
	msi->chip.teardown_irq = iproc_msix_teardown_irq;
	msi->irq_in_use = 0;

	msi->domain = irq_domain_add_linear(pcie->dev->of_node, pcie->max_irqs,
			&iproc_msix_domain_ops, &msi->chip);
	if (!msi->domain) {
		dev_err(pcie->dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}

	BUG_ON(pcie->max_irqs < pcie->soc_data->num_pf);

	for (i = 0; i < pcie->max_irqs; i++) {
		ret = devm_request_irq(pcie->dev, pcie->irqs[i],
			iproc_msix_irq, 0, "iproc-nitro-pcie", pcie);
		if (ret < 0) {
			dev_err(pcie->dev, "failed to request IRQ: %d\n",
					pcie->irqs[i]);
			goto err_rm_irq_domain;
		}
	}

	msi->eq_page = devm_kcalloc(pcie->dev, pcie->max_irqs,
				    sizeof(unsigned long), GFP_KERNEL);
	if (!msi->eq_page) {
		dev_err(pcie->dev, "Error allocating EQ Pages\n");
		ret = -ENOMEM;
		goto err_rm_irq_domain;
	}

	msi->msi_page = devm_kcalloc(pcie->dev, pcie->max_irqs,
				     sizeof(unsigned long), GFP_KERNEL);
	if (!msi->msi_page) {
		dev_err(pcie->dev, "Error allocating MSI Pages\n");
		ret = -ENOMEM;
		goto err_rm_irq_domain;
	}

	/* set window to 256 bytes */
	writel(1, pcie->reg + NITRO_MSIX_GEN_CONFIG_OFFSET);

	/* Setup MSIX for all the PFs */
	for (i = 0; i < pcie->soc_data->num_pf; i++) {
		msi->eq_page[i] = __get_free_page(GFP_KERNEL);
		if (!msi->eq_page[i]) {
			dev_err(pcie->dev, "failed to allocate memory for MSI event queue\n");
			ret = -ENOMEM;
			goto err_free_pfs;
		}

		writel(virt_to_phys((void *)msi->eq_page[i]) & 0xffffffff,
		       pcie->reg + NITRO_EQ_PAGE_PF_OFFSET + (0x10 * i));
		writel(virt_to_phys((void *)msi->eq_page[i]) >> 32,
		       pcie->reg + NITRO_EQ_PAGE_UPPER_PF_OFFSET + (0x10 * i));

		msi->msi_page[i] = __get_free_page(GFP_KERNEL);
		if (!msi->msi_page[i]) {
			dev_err(pcie->dev, "failed to allocate memory for MSI\n");
			ret = -ENOMEM;
			goto err_free_pfs;
		}

		writel(virt_to_phys((void *)msi->msi_page[i]) & 0xffffffff,
		       pcie->reg + NITRO_MSI_PAGE_PF_OFFSET + (0x10 * i));
		writel(virt_to_phys((void *)msi->msi_page[i]) >> 32,
		       pcie->reg + NITRO_MSI_PAGE_UPPER_PF_OFFSET + (0x10 * i));

		/* enable MSI event queue and interrupt */
		val = SYS_MSI_INTR_EN | SYS_MSI_INT_N_EVENT | SYS_MSI_EQ_EN;
		writel(val, pcie->reg + NITRO_MSI_CTRL_0_PF_OFFSET + (i * 4));
	}

	/* Setup MSIX for all the VFs */
	for (i = pcie->soc_data->num_pf; i < pcie->max_irqs; i++) {
		u32 vf = i - pcie->soc_data->num_pf;

		msi->eq_page[i] = __get_free_page(GFP_KERNEL);
		if (!msi->eq_page[i]) {
			dev_err(pcie->dev, "failed to allocate memory for MSI event queue\n");
			ret = -ENOMEM;
			goto err_free_vfs;
		}

		writel(virt_to_phys((void *)msi->eq_page[i]) & 0xffffffff,
		       pcie->reg + NITRO_EQ_PAGE_VF_OFFSET + (0x10 * vf));
		writel(virt_to_phys((void *)msi->eq_page[i]) >> 32,
		       pcie->reg + NITRO_EQ_PAGE_UPPER_VF_OFFSET + (0x10 * vf));

		msi->msi_page[i] = __get_free_page(GFP_KERNEL);
		if (!msi->msi_page[i]) {
			dev_err(pcie->dev, "failed to allocate memory for MSI\n");
			ret = -ENOMEM;
			goto err_free_vfs;
		}

		writel(virt_to_phys((void *)msi->msi_page[i]) & 0xffffffff,
		       pcie->reg + NITRO_MSI_PAGE_VF_OFFSET + (0x10 * vf));
		writel(virt_to_phys((void *)msi->msi_page[i]) >> 32,
		       pcie->reg + NITRO_MSI_PAGE_UPPER_VF_OFFSET + (0x10 * vf));

		/* enable MSI event queue and interrupt */
		val = SYS_MSI_INTR_EN | SYS_MSI_INT_N_EVENT | SYS_MSI_EQ_EN;
		writel(val, pcie->reg + NITRO_MSI_CTRL_0_VF_OFFSET + (vf * 4));
	}

	dev_info(pcie->dev, "MSI-X enabled\n");
	return 0;

err_free_vfs:
	for (i = pcie->soc_data->num_pf; i < pcie->max_irqs; i++) {
		u32 vf = i - pcie->soc_data->num_pf;

		writel(0, pcie->reg + NITRO_MSI_CTRL_0_VF_OFFSET + (vf * 4));

		if (msi->eq_page[i])
			free_page(msi->eq_page[i]);
		if (msi->msi_page[i])
			free_page(msi->msi_page[i]);
	}
err_free_pfs:
	for (i = 0; i < pcie->soc_data->num_pf; i++) {
		writel(0, pcie->reg + NITRO_MSI_CTRL_0_PF_OFFSET + (i * 4));
		if (msi->eq_page[i])
			free_page(msi->eq_page[i]);
		if (msi->msi_page[i])
			free_page(msi->msi_page[i]);
	}
err_rm_irq_domain:
	irq_domain_remove(msi->domain);
	return ret;
}

static const struct iproc_pcie_data iproc_pcie_nitro = {
	.type				= IPROC_NITRO,
	.num_pf				= NITRO_NUM_PF,
	.cfg_ind_add_offset		= NITRO_CFG_IND_ADDR_OFFSET,
	.cfg_ind_data_offset		= NITRO_CFG_IND_DATA_OFFSET,
};

static const struct iproc_pcie_data iproc_pcie_std = {
	.type				= IPROC_STD,
	.num_pf				= GEN_NUM_PF,
	.cfg_ind_add_offset		= GEN_CFG_IND_ADDR_OFFSET,
	.cfg_ind_data_offset		= GEN_CFG_IND_DATA_OFFSET,
};

#ifdef CONFIG_PM_SLEEP

static int bcm_iproc_pcie_suspend(struct device *dev)
{
	/*
	 * Nothing needs to be done in suspend. This will take care of all
	 * deep sleep use cases regardless of the power status of PCIe serdes
	 * or host controller during deep sleep
	 */
	return 0;
}

static int bcm_iproc_pcie_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct iproc_pcie *pcie = platform_get_drvdata(pdev);
	struct pci_bus bus;
	struct pci_sys_data sys;
	int ret;
	u32 val;

	/*
	 * Check whether or not the PCIe host controller has lost its state
	 * during system level deep sleep. If PCIe host controller state is
	 * maintained, simply return from this function and do nothing
	 */
	iproc_pcie_create_rc_dummy_bus(pcie, &bus, &sys);
	pci_bus_read_config_dword(&bus, 0, PCI_BRIDGE_CTRL_REG_OFFSET, &val);
	val = (val >> 8) & 0xffff;
	if (val == PCI_CLASS_BRIDGE_PCI) {
		dev_info(pcie->dev, "host resumes without losing its power\n");
		return 0;
	}

	/* bring up PCIe Serdes */
	if (pcie->phy) {
		/*
		 * Need to shut off the PHY first to get the use count synced
		 * up
		 */
		phy_power_off(pcie->phy);
		phy_exit(pcie->phy);

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
	}

	/* if MSI is enabled, reprogram the MSI related registers */
	if (IS_ENABLED(CONFIG_PCI_MSI))
		iproc_pcie_msi_enable(pcie);

	/* now reset the host controller */
	iproc_pcie_reset(pcie);

	/* check to make sure PCIe link is up and running */
	ret = iproc_pcie_check_link(pcie);
	if (ret) {
		dev_err(pcie->dev, "EP cannot be detected\n");
		goto err_power_off_phy;
	}

	/* enable root complex INTX */
	writel(SYS_RC_INTX_MASK, pcie->reg + SYS_RC_INTX_EN);

	return 0;

err_power_off_phy:
	if (pcie->phy)
		phy_power_off(pcie->phy);

err_exit_phy:
	if (pcie->phy)
		phy_exit(pcie->phy);

	return ret;
}

/*
 * Need to execute suspend/resume callback with PCIe interrupt disabled
 */
static const struct dev_pm_ops bcm_iproc_pcie_pm_ops = {
	.suspend_noirq = &bcm_iproc_pcie_suspend,
	.resume_noirq = &bcm_iproc_pcie_resume
};

#define BCM_IPROC_PCIE_PM_OPS (&bcm_iproc_pcie_pm_ops)
#else
#define BCM_IPROC_PCIE_PM_OPS NULL
#endif /* CONFIG_PM_SLEEP */

static const struct of_device_id iproc_pcie_of_match_table[] = {
	{ .compatible = "brcm,iproc-pcie", .data = &iproc_pcie_std},
	{ .compatible = "brcm,iproc-pcie-nitro", .data = &iproc_pcie_nitro},
	{},
};
MODULE_DEVICE_TABLE(of, iproc_pcie_of_match_table);

static int iproc_pcie_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct iproc_pcie *pcie;
	struct device_node *np = pdev->dev.of_node;
	struct of_pci_range range;
	struct of_pci_range_parser parser;
	struct resource res, regs;
	int i, ret;

	pcie = devm_kzalloc(&pdev->dev, sizeof(struct iproc_pcie),
			    GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	match = of_match_device(iproc_pcie_of_match_table, &pdev->dev);
	if (!match)
		return -ENODEV;

	pcie->soc_data = match->data;
	pcie->dev = &pdev->dev;
	platform_set_drvdata(pdev, pcie);

	if (of_pci_parse_bus_range(pdev->dev.of_node, &pcie->busn)) {
		dev_err(&pdev->dev, "failed to parse bus-range property\n");
		return -EINVAL;
	}

	/* PCIE controller registers */
	ret = of_address_to_resource(np, 0, &regs);
	if (ret) {
		dev_err(pcie->dev, "unable to obtain device resources\n");
		return -ENODEV;
	}

	pcie->reg = devm_ioremap(pcie->dev, regs.start, resource_size(&regs));
	if (!pcie->reg) {
		dev_err(pcie->dev, "unable to map device reg resources\n");
		return -ENOMEM;
	}

	pcie->phy = devm_phy_get(pcie->dev, "pcie-phy");
	if (IS_ERR(pcie->phy)) {
		if (PTR_ERR(pcie->phy) == -EPROBE_DEFER)
			return -EPROBE_DEFER;
		pcie->phy = NULL;
	}

	pcie->max_irqs = of_irq_count(np);
	if (!pcie->max_irqs || BITS_TO_LONGS(pcie->max_irqs) > 1)
		return -EINVAL;

	pcie->irqs = devm_kcalloc(pcie->dev, pcie->max_irqs,
				  sizeof(*pcie->irqs), GFP_KERNEL);
	if (!pcie->irqs)
		return -ENOMEM;

	for (i = 0; i < pcie->max_irqs; i++) {
		pcie->irqs[i] = irq_of_parse_and_map(np, i);
		if (!pcie->irqs[i]) {
			dev_err(pcie->dev, "unable to parse irq index:%d\n", i);
			return -ENODEV;
		}
	}

	if (of_pci_range_parser_init(&parser, np)) {
		dev_err(pcie->dev, "missing \"ranges\" property in DT\n");
		return -EINVAL;
	}

	/* Get the PCI memory ranges from DT */
	for_each_of_pci_range(&parser, &range) {
		of_pci_range_to_resource(&range, np, &res);

		switch (res.flags & IORESOURCE_TYPE_BITS) {
		case IORESOURCE_IO:
			memcpy(&pcie->io, &res, sizeof(res));
			pcie->io.name = "I/O";
			break;

		case IORESOURCE_MEM:
			memcpy(&pcie->mem, &res, sizeof(res));
			pcie->mem.name = "MEM";
			break;
		}
	}

	if (pcie->phy) {
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
	} else {
#ifdef CONFIG_ARCH_NORTHSTAR2
#include <linux/phy/cmic_mdio.h>

		/* FIXME - This is an ugly hack, and should go into the device
		 * tree!  Support for having this there is not currently in the
		 * Phy driver.  So, putting this here for now.
		 */
		cmic_mdio_write(INTERNAL, CLAUS22, 0, 0, 0x1F, 0x2100);
		cmic_mdio_write(INTERNAL, CLAUS22, 0, 0, 0x13, 0x2b18);
		cmic_mdio_write(INTERNAL, CLAUS22, 7, 0, 0x1F, 0x2100);
		cmic_mdio_write(INTERNAL, CLAUS22, 7, 0, 0x13, 0x2b18);
#endif
	}

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		if (pcie->soc_data->type == IPROC_NITRO)
			ret = iproc_pcie_msix_init(pcie);
		else
			ret = iproc_pcie_msi_init(pcie);
		if (ret < 0) {
			dev_err(pcie->dev, "failed to enable MSI support\n");
			goto err_power_off_phy;
		}
	}

	iproc_pcie_reset(pcie);

	ret = iproc_pcie_check_link(pcie);
	if (ret) {
		dev_err(pcie->dev, "no PCIe EP device detected\n");
		goto err_power_off_phy;
	}

	iproc_pcie_enable(pcie);

	return 0;

err_power_off_phy:
	if (pcie->phy)
		phy_power_off(pcie->phy);

err_exit_phy:
	if (pcie->phy)
		phy_exit(pcie->phy);

	return ret;
}

static void northstar_nitro_bridge_fix(struct pci_dev *pdev)
{
	int i;

	/* The Nitro Bridge device does not correctly set the PCI class type on
	 * A0 HW.
	 */
	if (pdev->hdr_type == PCI_HEADER_TYPE_BRIDGE) {
		struct iproc_pcie *pcie = sys_to_pcie(pdev->sysdata);

		pdev->class = PCI_CLASS_BRIDGE_PCI << 8;

		for (i = 0; i < DEVICE_COUNT_RESOURCE; i++)
			pdev->resource[i].flags |= IORESOURCE_PCI_FIXED;


#define PAXC_RX_DEBUG_CONTROL	0x28
#define PAXC_RX_WR_INRC_AWID	(1 << 13)
#define PAXC_RX_WR_BURST	(4 << 9)
#define PAXC_RX_RD_BURST	(4 << 6)
#define PAXC_RX_IGNORE_BRESP	(1 << 5)
#define PAXC_RX_FREE_CMPL_BUF	(7 << 2)
#define PAXC_RX_FREE_ARID_CNT	(3)

		/* Tune the PAXC RX for increased performance */
		writel(PAXC_RX_WR_INRC_AWID | PAXC_RX_WR_BURST |
		       PAXC_RX_RD_BURST | PAXC_RX_IGNORE_BRESP |
		       PAXC_RX_FREE_CMPL_BUF | PAXC_RX_FREE_ARID_CNT,
		       pcie->reg + PAXC_RX_DEBUG_CONTROL);
	} else {
		struct iproc_pcie *pcie = sys_to_pcie(pdev->sysdata);

		/* The MSI-X BIR is incorrectly set to BAR0.  Use the backdoor
		 * registers to get it to point to BAR4 for each PF.  Once done,
		 * reset the ECM to 0 to allow Nitro access.
		 */
		for (i = 0; i < pcie->soc_data->num_pf; i++) {
#define CONFIG_ECM_ADDR	0x1e0
#define CONFIG_ECM_DATA	0x1e4
			/* Change the PBA BIR */
			writel(0x800004c8 | i << 12,
			       pcie->reg + CONFIG_ECM_ADDR);
			writel(0x00001004, pcie->reg + CONFIG_ECM_DATA);

			/* Change the BIR */
			writel(0x800004c4 | i << 12,
			       pcie->reg + CONFIG_ECM_ADDR);
			writel(0x00000004, pcie->reg + CONFIG_ECM_DATA);

			/* Change the QSIZE */
			writel(0x800004c0 | i << 12,
			       pcie->reg + CONFIG_ECM_ADDR);
			writel(0x000ba80b, pcie->reg + CONFIG_ECM_DATA);
		}
		writel(0, pcie->reg + CONFIG_ECM_ADDR);
	}
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_BROADCOM, 0x168e, northstar_nitro_bridge_fix);

static void northstar_nitro_fix(struct pci_dev *pdev)
{
	int i;

	/* The PCIE bridge and device have the same device ID.  Don't enable
	 * this workaround on the bridge.
	 */
	if (pdev->hdr_type == PCI_HEADER_TYPE_BRIDGE)
		return;

	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
		if (!pdev->resource[i].start && !pdev->resource[i].end)
			continue;

		pdev->resource[i].start += 0x60000000;
		pdev->resource[i].end += 0x60000000;

		dev_dbg(&pdev->dev, "Res %d start %llx end %llx\n",
			i, pdev->resource[i].start, pdev->resource[i].end);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_BROADCOM, 0x168e, northstar_nitro_fix);


#define NS2_SYS_OARR_OFFSET	0x0d20
#define NS2_SYS_OMAP_OFFSET	0x0d40

static void northstar_ns2_omap_fix(struct pci_dev *pdev)
{
	struct iproc_pcie *pcie = sys_to_pcie(pdev->sysdata);
	u32 val;

	if (!pcie || !pcie->reg)
		return;

	/* Enable the OARR */
	val = readl(pcie->reg + NS2_SYS_OARR_OFFSET);
	val |= 1;
	writel(val, pcie->reg + NS2_SYS_OARR_OFFSET);

	/* Write the Mem address to the OMAP */
	val = readl(pcie->reg + NS2_SYS_OMAP_OFFSET);
	val |= (u32) pcie->mem.start;
	writel(val, pcie->reg + NS2_SYS_OMAP_OFFSET);
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_BROADCOM, 0xd300, northstar_ns2_omap_fix);

static void northstar_ns2_perftune(struct pci_dev *pdev)
{
#define NS2_CREDIT_REPORTING		0xa14
#define NS2_CREDIT_REPORTING_INTERVAL	0x03402020

	pci_bus_write_config_dword(pdev->bus, 0, NS2_CREDIT_REPORTING,
				   NS2_CREDIT_REPORTING_INTERVAL);
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_BROADCOM, 0xd300, northstar_ns2_perftune);

static void iproc_coherent_device_setup(struct pci_dev *dev)
{
	struct device_node *np;
	struct pci_bus *bus = dev->bus;

	while (!pci_is_root_bus(bus))
		bus = bus->parent;

	np = bus->dev.of_node;
	if (np) {
		if (of_property_read_bool(np, "dma-coherent")) {
#ifdef CONFIG_ARCH_NORTHSTAR2
			set_dma_ops(&(dev->dev), &coherent_swiotlb_dma_ops);
#else
			set_dma_ops(&(dev->dev), &arm_coherent_dma_ops);
#endif
			pr_info("PCIe %s %04X.%04X will run in coherent mode\n",
				dev_name(&(dev->dev)), dev->vendor,
				dev->device);
		}
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_ANY_ID, PCI_ANY_ID, iproc_coherent_device_setup);

static struct platform_driver iproc_pcie_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "iproc-pcie",
		.of_match_table =
		   of_match_ptr(iproc_pcie_of_match_table),
		.pm = BCM_IPROC_PCIE_PM_OPS,
	},
	.probe = iproc_pcie_probe,
};
module_platform_driver(iproc_pcie_driver);

MODULE_AUTHOR("Ray Jui <rjui@broadcom.com>");
MODULE_DESCRIPTION("Broadcom iPROC PCIe driver");
MODULE_LICENSE("GPL v2");
