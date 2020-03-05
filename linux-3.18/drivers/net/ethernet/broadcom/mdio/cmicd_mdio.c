/*
 * $Copyright Open Broadcom Corporation$
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/types.h>
#include <linux/io.h>
#include <asm/memory.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/platform_device.h>
#define CONFIG_MACH_HR3
#define CONFIG_MACH_IPROC_P7
#include <mach/iproc_regs.h>
#undef CONFIG_MACH_IPROC_P7
#undef CONFIG_MACH_HR3
#include "iproc_mdio.h"

#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
static struct iproc_mdiobus_data iproc_mdiobus_data;

/* Greyhound CMICD MDIO */
#define CMIC_CMC2_MIIM_PARAM 0x03233080
#define CMIC_CMC2_MIIM_PARAM_BASE 0x080
#define CMIC_CMC2_MIIM_PARAM__MIIM_CYCLE_L 31
#define CMIC_CMC2_MIIM_PARAM__MIIM_CYCLE_R 29
#define CMIC_CMC2_MIIM_PARAM__MIIM_CYCLE_WIDTH 3
#define CMIC_CMC2_MIIM_PARAM__MIIM_CYCLE_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_PARAM__INTERNAL_SEL 25
#define CMIC_CMC2_MIIM_PARAM__INTERNAL_SEL_WIDTH 1
#define CMIC_CMC2_MIIM_PARAM__INTERNAL_SEL_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_PARAM__BUS_ID_L 24
#define CMIC_CMC2_MIIM_PARAM__BUS_ID_R 22
#define CMIC_CMC2_MIIM_PARAM__BUS_ID_WIDTH 3
#define CMIC_CMC2_MIIM_PARAM__BUS_ID_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_PARAM__C45_SEL 21
#define CMIC_CMC2_MIIM_PARAM__C45_SEL_WIDTH 1
#define CMIC_CMC2_MIIM_PARAM__C45_SEL_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_PARAM__PHY_ID_L 20
#define CMIC_CMC2_MIIM_PARAM__PHY_ID_R 16
#define CMIC_CMC2_MIIM_PARAM__PHY_ID_WIDTH 5
#define CMIC_CMC2_MIIM_PARAM__PHY_ID_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_PARAM__PHY_DATA_L 15
#define CMIC_CMC2_MIIM_PARAM__PHY_DATA_R 0
#define CMIC_CMC2_MIIM_PARAM__PHY_DATA_WIDTH 16
#define CMIC_CMC2_MIIM_PARAM__PHY_DATA_RESETVALUE 0x0000
#define CMIC_CMC2_MIIM_PARAM__RESERVED_L 28
#define CMIC_CMC2_MIIM_PARAM__RESERVED_R 26
#define CMIC_CMC2_MIIM_PARAM_WIDTH 32
#define CMIC_CMC2_MIIM_PARAM__WIDTH 32
#define CMIC_CMC2_MIIM_PARAM_ALL_L 31
#define CMIC_CMC2_MIIM_PARAM_ALL_R 0
#define CMIC_CMC2_MIIM_PARAM__ALL_L 31
#define CMIC_CMC2_MIIM_PARAM__ALL_R 0
#define CMIC_CMC2_MIIM_PARAM_DATAMASK 0xe3ffffff
#define CMIC_CMC2_MIIM_PARAM_RDWRMASK 0x1c000000
#define CMIC_CMC2_MIIM_PARAM_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_READ_DATA 0x03233084
#define CMIC_CMC2_MIIM_READ_DATA_BASE 0x084
#define CMIC_CMC2_MIIM_READ_DATA__DATA_L 15
#define CMIC_CMC2_MIIM_READ_DATA__DATA_R 0
#define CMIC_CMC2_MIIM_READ_DATA__DATA_WIDTH 16
#define CMIC_CMC2_MIIM_READ_DATA__DATA_RESETVALUE 0x0000
#define CMIC_CMC2_MIIM_READ_DATA__RESERVED_L 31
#define CMIC_CMC2_MIIM_READ_DATA__RESERVED_R 16
#define CMIC_CMC2_MIIM_READ_DATA_WIDTH 16
#define CMIC_CMC2_MIIM_READ_DATA__WIDTH 16
#define CMIC_CMC2_MIIM_READ_DATA_ALL_L 15
#define CMIC_CMC2_MIIM_READ_DATA_ALL_R 0
#define CMIC_CMC2_MIIM_READ_DATA__ALL_L 15
#define CMIC_CMC2_MIIM_READ_DATA__ALL_R 0
#define CMIC_CMC2_MIIM_READ_DATA_DATAMASK 0x0000ffff
#define CMIC_CMC2_MIIM_READ_DATA_RDWRMASK 0xffff0000
#define CMIC_CMC2_MIIM_READ_DATA_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_ADDRESS 0x03233088
#define CMIC_CMC2_MIIM_ADDRESS_BASE 0x088
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_DTYPE_L 20
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_DTYPE_R 16
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_DTYPE_WIDTH 5
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_DTYPE_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_REGADR_L 15
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_REGADR_R 0
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_REGADR_WIDTH 16
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_REGADR_RESETVALUE 0x0000
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_22_REGADR_L 4
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_22_REGADR_R 0
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_22_REGADR_WIDTH 5
#define CMIC_CMC2_MIIM_ADDRESS__CLAUSE_22_REGADR_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_ADDRESS__RESERVED_L 31
#define CMIC_CMC2_MIIM_ADDRESS__RESERVED_R 21
#define CMIC_CMC2_MIIM_ADDRESS_WIDTH 21
#define CMIC_CMC2_MIIM_ADDRESS__WIDTH 21
#define CMIC_CMC2_MIIM_ADDRESS_ALL_L 20
#define CMIC_CMC2_MIIM_ADDRESS_ALL_R 0
#define CMIC_CMC2_MIIM_ADDRESS__ALL_L 20
#define CMIC_CMC2_MIIM_ADDRESS__ALL_R 0
#define CMIC_CMC2_MIIM_ADDRESS_DATAMASK 0x001fffff
#define CMIC_CMC2_MIIM_ADDRESS_RDWRMASK 0xffe00000
#define CMIC_CMC2_MIIM_ADDRESS_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_CTRL 0x0323308c
#define CMIC_CMC2_MIIM_CTRL_BASE 0x08c
#define CMIC_CMC2_MIIM_CTRL__MIIM_RD_START 1
#define CMIC_CMC2_MIIM_CTRL__MIIM_RD_START_WIDTH 1
#define CMIC_CMC2_MIIM_CTRL__MIIM_RD_START_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_CTRL__MIIM_WR_START 0
#define CMIC_CMC2_MIIM_CTRL__MIIM_WR_START_WIDTH 1
#define CMIC_CMC2_MIIM_CTRL__MIIM_WR_START_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_CTRL__RESERVED_L 31
#define CMIC_CMC2_MIIM_CTRL__RESERVED_R 2
#define CMIC_CMC2_MIIM_CTRL_WIDTH 2
#define CMIC_CMC2_MIIM_CTRL__WIDTH 2
#define CMIC_CMC2_MIIM_CTRL_ALL_L 1
#define CMIC_CMC2_MIIM_CTRL_ALL_R 0
#define CMIC_CMC2_MIIM_CTRL__ALL_L 1
#define CMIC_CMC2_MIIM_CTRL__ALL_R 0
#define CMIC_CMC2_MIIM_CTRL_DATAMASK 0x00000003
#define CMIC_CMC2_MIIM_CTRL_RDWRMASK 0xfffffffc
#define CMIC_CMC2_MIIM_CTRL_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_STAT 0x03233090
#define CMIC_CMC2_MIIM_STAT_BASE 0x090
#define CMIC_CMC2_MIIM_STAT__MIIM_OPN_DONE 0
#define CMIC_CMC2_MIIM_STAT__MIIM_OPN_DONE_WIDTH 1
#define CMIC_CMC2_MIIM_STAT__MIIM_OPN_DONE_RESETVALUE 0x0
#define CMIC_CMC2_MIIM_STAT__RESERVED_L 31
#define CMIC_CMC2_MIIM_STAT__RESERVED_R 1
#define CMIC_CMC2_MIIM_STAT_WIDTH 1
#define CMIC_CMC2_MIIM_STAT__WIDTH 1
#define CMIC_CMC2_MIIM_STAT_ALL_L 0
#define CMIC_CMC2_MIIM_STAT_ALL_R 0
#define CMIC_CMC2_MIIM_STAT__ALL_L 0
#define CMIC_CMC2_MIIM_STAT__ALL_R 0
#define CMIC_CMC2_MIIM_STAT_DATAMASK 0x00000001
#define CMIC_CMC2_MIIM_STAT_RDWRMASK 0xfffffffe
#define CMIC_CMC2_MIIM_STAT_RESETVALUE 0x0

#define CMIC_COMMON_UC0_PIO_ENDIANESS 	0x1F0

#define MIIM_PARAM_REG 			CMIC_CMC2_MIIM_PARAM_BASE
#define MIIM_PARAM__MIIM_CYCLE_SHIFT	CMIC_CMC2_MIIM_PARAM__MIIM_CYCLE_R
#define MIIM_PARAM__MIIM_CYCLE_MASK	((1 << CMIC_CMC2_MIIM_PARAM__MIIM_CYCLE_WIDTH) - 1)
#define MIIM_PARAM__INTERNAL_SEL_SHIFT	CMIC_CMC2_MIIM_PARAM__INTERNAL_SEL
#define MIIM_PARAM__INTERNAL_SEL_MASK	((1 << CMIC_CMC2_MIIM_PARAM__INTERNAL_SEL_WIDTH) - 1)
#define MIIM_PARAM__BUS_ID_SHIFT	CMIC_CMC2_MIIM_PARAM__BUS_ID_R
#define MIIM_PARAM__BUS_ID_MASK		((1 << CMIC_CMC2_MIIM_PARAM__BUS_ID_WIDTH) - 1)
#define MIIM_PARAM__C45_SEL_SHIFT	CMIC_CMC2_MIIM_PARAM__C45_SEL
#define MIIM_PARAM__C45_SEL_MASK	((1 << CMIC_CMC2_MIIM_PARAM__C45_SEL_WIDTH) - 1)
#define MIIM_PARAM__PHY_ID_SHIFT	CMIC_CMC2_MIIM_PARAM__PHY_ID_R
#define MIIM_PARAM__PHY_ID_MASK		((1 << CMIC_CMC2_MIIM_PARAM__PHY_ID_WIDTH) - 1)
#define MIIM_PARAM__PHY_DATA_SHIFT 	CMIC_CMC2_MIIM_PARAM__PHY_DATA_R
#define MIIM_PARAM__PHY_DATA_MASK	((1 << CMIC_CMC2_MIIM_PARAM__PHY_DATA_WIDTH) - 1)

#define MIIM_READ_DATA_REG 		CMIC_CMC2_MIIM_READ_DATA_BASE
#define MIIM_READ_DATA__DATA_SHIFT	CMIC_CMC2_MIIM_READ_DATA__DATA_R
#define MIIM_READ_DATA__DATA_MASK	((1 << CMIC_CMC2_MIIM_READ_DATA__DATA_WIDTH) - 1)

#define MIIM_ADDRESS_REG 			CMIC_CMC2_MIIM_ADDRESS_BASE
#define MIIM_ADDRESS__CLAUSE_45_DTYPE_SHIFT	CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_DTYPE_R
#define MIIM_ADDRESS__CLAUSE_45_DTYPE_MASK	((1 << CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_DTYPE_WIDTH) - 1)
#define MIIM_ADDRESS__CLAUSE_45_REGADR_SHIFT	CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_REGADR_R
#define MIIM_ADDRESS__CLAUSE_45_REGADR_MASK	((1 << CMIC_CMC2_MIIM_ADDRESS__CLAUSE_45_REGADR_WIDTH) - 1)
#define MIIM_ADDRESS__CLAUSE_22_REGADR_SHIFT	CMIC_CMC2_MIIM_ADDRESS__CLAUSE_22_REGADR_R
#define MIIM_ADDRESS__CLAUSE_22_REGADR_MASK	((1 << CMIC_CMC2_MIIM_ADDRESS__CLAUSE_22_REGADR_WIDTH) - 1)

#define MIIM_CTRL_REG 			CMIC_CMC2_MIIM_CTRL_BASE
#define MIIM_CTRL__MIIM_RD_START_SHIFT	CMIC_CMC2_MIIM_CTRL__MIIM_RD_START
#define MIIM_CTRL__MIIM_RD_START_MASK	((1 << CMIC_CMC2_MIIM_CTRL__MIIM_RD_START_WIDTH) - 1)
#define MIIM_CTRL__MIIM_WR_START_SHIFT	CMIC_CMC2_MIIM_CTRL__MIIM_WR_START
#define MIIM_CTRL__MIIM_WR_START_MASK	((1 << CMIC_CMC2_MIIM_CTRL__MIIM_WR_START_WIDTH) - 1)

#define MIIM_STAT_REG 			CMIC_CMC2_MIIM_STAT_BASE
#define MIIM_STAT__MIIM_OPN_DONE_SHIFT	CMIC_CMC2_MIIM_STAT__MIIM_OPN_DONE
#define MIIM_STAT__MIIM_OPN_DONE_MASK	((1 << CMIC_CMC2_MIIM_STAT__MIIM_OPN_DONE_WIDTH) - 1)

#define SET_REG_FIELD(reg_value, fshift, fmask, fvalue)	\
	(reg_value) = ((reg_value) & ~((fmask) << (fshift))) |  \
			(((fvalue) & (fmask)) << (fshift))
#define ISET_REG_FIELD(reg_value, fshift, fmask, fvalue) \
		(reg_value) = (reg_value) | (((fvalue) & (fmask)) << (fshift))			
#define GET_REG_FIELD(reg_value, fshift, fmask)	\
	(((reg_value) & ((fmask) << (fshift))) >> (fshift))

#define MIIM_OP_MAX_HALT_USEC	500	

enum {
	MIIM_OP_MODE_READ,
	MIIM_OP_MODE_WRITE,
	MIIM_OP_MODE_MAX	
};

/**
 * struct cmicd_mdio: cmicd mdio structure
 * @resource: resource of cmicd cmc2
 * @base: base address of cmicd cmc2
 * @lock: spin lock protecting io access
 */
struct cmicd_mdio_ctrl {
	void __iomem *base;
#ifdef __BIG_ENDIAN
	void __iomem *cmic_common;
#endif
	/* Use spinlock to co-operate that the caller might be in interrupt context */ 
	/* struct mutex lock; */
	spinlock_t lock;    
	int ref_cnt;
};

struct cmicd_mdiobus_private {
	/* iproc_mdiobus_data field have to  be placed at the beginning of 
	 *  mdiobus private data */
	struct iproc_mdiobus_data bus_data;
	struct cmicd_mdio_ctrl *hw_ctrl;
};

struct cmicd_miim_cmd {
	int bus_id;
	int int_sel;
	int phy_id;
	int regnum;
	int c45_sel;
	u16 op_mode;
	u16 val;
};

static struct cmicd_mdio_ctrl *cmicd_cmc2 = NULL;


static void __maybe_unused cmicd_mdiobus_test(struct mii_bus *mii_bus)
{
	int i;
	u16 data1 = 0, data2 = 0;
	struct phy_device *phy_dev;
	struct cmicd_mdiobus_private *bus_priv = mii_bus->priv;
	struct iproc_mdiobus_data *bus_data = &bus_priv->bus_data;

	dev_info(mii_bus->parent, "%s : %s phy bus num[%d], type[%d]\n", 
			__func__, mii_bus->id, bus_data->phybus_num, bus_data->phybus_type);

	/* Check if mdiobus_read works fine */
	for (i = 0; i < PHY_MAX_ADDR; i++) {
		phy_dev = mii_bus->phy_map[i];
		if (phy_dev)
			dev_info(mii_bus->parent, "phy[%d] id=0x%08x, addr = %d\n", 
					i, phy_dev->phy_id, phy_dev->addr);	
	}

	/* Check if general interface function for mdiobus read works fine */
	for (i = 0; i < PHY_MAX_ADDR; i++) {
	    data1 = mii_bus->read(mii_bus, i, 2);
	    data2 = mii_bus->read(mii_bus, i, 3);
		if ((data1 < 0) || (data2 < 0)) {
			dev_info(mii_bus->parent, 
				"iproc_mdiobus_read failed!, %s phy bus num[%d], type[%d], phyaddr = %d, nRet1 = %d, nRet2 = %d\n",
				mii_bus->id, bus_data->phybus_num, bus_data->phybus_type, i, data1, data2);
		} else {
			dev_info(mii_bus->parent, 
				"read %s phy bus num[%d] type[%d] phyaddr[%d], reg2 = 0x%x, reg3 = 0x%x\n",
				mii_bus->id, bus_data->phybus_num, bus_data->phybus_type, i, data1, data2);
	    }
	}
}

static inline u32 cmicd_miim_reg_read(struct cmicd_mdio_ctrl *cmc2, u32 reg)
{
 	u32 value = readl(cmc2->base + reg);
#ifdef __BIG_ENDIAN
       if (readl(cmc2->cmic_common + CMIC_COMMON_UC0_PIO_ENDIANESS) != 0)
       { 
       		/* CMICD is in big-endian mode */
       		value = swab32(value);
       }
#endif
	return value;
}

static inline void cmicd_miim_reg_write(struct cmicd_mdio_ctrl *cmc2, u32 reg, u32 data)
{
#ifdef __BIG_ENDIAN
	if (readl(cmc2->cmic_common + CMIC_COMMON_UC0_PIO_ENDIANESS) != 0)
	{
       		/* CMICD is in big-endian mode */
		writel(swab32(data), cmc2->base + reg);
		return;
	}
#endif
	writel(data, cmc2->base + reg);
}

static inline void cmicd_miim_set_op_read(u32 *data, u32 set)
{
	SET_REG_FIELD(*data, MIIM_CTRL__MIIM_RD_START_SHIFT, 
			MIIM_CTRL__MIIM_RD_START_MASK, set);
}

static inline void cmicd_miim_set_op_write(u32 *data, u32 set)
{
	SET_REG_FIELD(*data, MIIM_CTRL__MIIM_WR_START_SHIFT, 
			MIIM_CTRL__MIIM_WR_START_MASK, set);
}

static inline int do_cmicd_miim_op(struct cmicd_mdio_ctrl *cmc2, u32 op, u32 param, u32 addr)
{
	u32 val, op_done;
	unsigned long flags;
	int ret = 0;
	int usec = MIIM_OP_MAX_HALT_USEC;

	if (op >= MIIM_OP_MODE_MAX) {
		printk(KERN_ERR "%s : invalid op code %d\n", __func__, op);
		return -EINVAL;
	}

	/* mutex_lock(&cmc2->lock); */
	spin_lock_irqsave(&cmc2->lock, flags);

	cmicd_miim_reg_write(cmc2, MIIM_PARAM_REG, param);
	cmicd_miim_reg_write(cmc2, MIIM_ADDRESS_REG, addr);
	val = cmicd_miim_reg_read(cmc2, MIIM_CTRL_REG);
	if(op == MIIM_OP_MODE_READ)
		cmicd_miim_set_op_read(&val, 1);
	else
		cmicd_miim_set_op_write(&val, 1);
	cmicd_miim_reg_write(cmc2, MIIM_CTRL_REG, val);

	do {
		op_done = GET_REG_FIELD(cmicd_miim_reg_read(cmc2, MIIM_STAT_REG),
				MIIM_STAT__MIIM_OPN_DONE_SHIFT, MIIM_STAT__MIIM_OPN_DONE_MASK);
		if (op_done)
			break;
		
		udelay(1);
		usec--;
	} while (usec > 0);

	if (op_done) {
		if(op == MIIM_OP_MODE_READ)
			ret = cmicd_miim_reg_read(cmc2, MIIM_READ_DATA_REG);
	}
	else
		ret = -ETIME;

	val = cmicd_miim_reg_read(cmc2, MIIM_CTRL_REG);
	if(op == MIIM_OP_MODE_READ)
		cmicd_miim_set_op_read(&val, 0);
	else
		cmicd_miim_set_op_write(&val, 0);
	cmicd_miim_reg_write(cmc2, MIIM_CTRL_REG, val);

	/* mutex_unlock(&cmc2->lock); */
        spin_unlock_irqrestore(&cmc2->lock, flags);

	return ret;
}


static int cmicd_miim_op(struct cmicd_mdio_ctrl *cmc2, struct cmicd_miim_cmd *cmd)
{
	u32 miim_param =0, miim_addr = 0;
	
	ISET_REG_FIELD(miim_param, MIIM_PARAM__BUS_ID_SHIFT, 
			MIIM_PARAM__BUS_ID_MASK, cmd->bus_id);

	if (cmd->int_sel)
		ISET_REG_FIELD(miim_param, MIIM_PARAM__INTERNAL_SEL_SHIFT, 
				MIIM_PARAM__INTERNAL_SEL_MASK, 1);

	ISET_REG_FIELD(miim_param, MIIM_PARAM__PHY_ID_SHIFT, 
			MIIM_PARAM__PHY_ID_MASK, cmd->phy_id);

	if (cmd->op_mode == MIIM_OP_MODE_WRITE)
		ISET_REG_FIELD(miim_param, MIIM_PARAM__PHY_DATA_SHIFT, 
				MIIM_PARAM__PHY_DATA_MASK, cmd->val);

	if (cmd->c45_sel) {
		ISET_REG_FIELD(miim_param, MIIM_PARAM__C45_SEL_SHIFT, 
				MIIM_PARAM__C45_SEL_MASK, 1);

		ISET_REG_FIELD(miim_addr, MIIM_ADDRESS__CLAUSE_45_REGADR_SHIFT, 
				MIIM_ADDRESS__CLAUSE_45_REGADR_MASK, cmd->regnum);
		ISET_REG_FIELD(miim_addr, MIIM_ADDRESS__CLAUSE_45_DTYPE_SHIFT, 
				MIIM_ADDRESS__CLAUSE_45_REGADR_MASK, cmd->regnum >> 16);
	}
	else {
		ISET_REG_FIELD(miim_addr, MIIM_ADDRESS__CLAUSE_22_REGADR_SHIFT, 
				MIIM_ADDRESS__CLAUSE_22_REGADR_MASK, cmd->regnum);
	}

	return do_cmicd_miim_op(cmc2, cmd->op_mode, miim_param, miim_addr);
}


static int cmicd_mdiobus_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct cmicd_mdiobus_private *bus_priv = bus->priv;
	struct iproc_mdiobus_data *bus_data = &bus_priv->bus_data;
	struct cmicd_miim_cmd cmd = {0};

	cmd.bus_id = bus_data->phybus_num;
	if (IPROC_MDIOBUS_TYPE_INTERNAL == bus_data->phybus_type)
		cmd.int_sel = 1;
	cmd.phy_id = phy_id;
	cmd.regnum = regnum;

	if (regnum & MII_ADDR_C45)
		cmd.c45_sel = 1;

	cmd.op_mode = MIIM_OP_MODE_READ;

	return cmicd_miim_op(bus_priv->hw_ctrl, &cmd);
}

static int cmicd_mdiobus_write(struct mii_bus *bus, int phy_id,
				int regnum, u16 val)
{
	struct cmicd_mdiobus_private *bus_priv = bus->priv;
	struct iproc_mdiobus_data *bus_data = &bus_priv->bus_data;
	struct cmicd_miim_cmd cmd = {0};

	cmd.bus_id = bus_data->phybus_num;
	if (IPROC_MDIOBUS_TYPE_INTERNAL == bus_data->phybus_type)
		cmd.int_sel = 1;
	cmd.phy_id = phy_id;
	cmd.regnum = regnum;
	cmd.val = val;

	if (regnum & MII_ADDR_C45)
		cmd.c45_sel = 1;

	cmd.op_mode = MIIM_OP_MODE_WRITE;
	
	return cmicd_miim_op(bus_priv->hw_ctrl, &cmd);
}

static struct cmicd_mdio_ctrl * cmicd_mdio_res_alloc(void)
{
	if (!cmicd_cmc2) {
		cmicd_cmc2 = kzalloc(sizeof(*cmicd_cmc2), GFP_KERNEL);
		if (!cmicd_cmc2)
			return NULL;
		/* mutex_init(&cmicd_cmc2->lock); */
		spin_lock_init(&cmicd_cmc2->lock);
		cmicd_cmc2->ref_cnt = 1;
	}
	else
		cmicd_cmc2->ref_cnt ++;

	return cmicd_cmc2;
}

static void cmicd_mdio_res_free(struct cmicd_mdio_ctrl *ctrl)
{
	if (ctrl) {
		ctrl->ref_cnt --;
		if (ctrl->ref_cnt == 0) {			
			iounmap(ctrl->base);
#ifdef __BIG_ENDIAN
			iounmap(ctrl->cmic_common);
#endif
			kfree(ctrl);
			cmicd_cmc2 = NULL;
		}
	}
}

static int cmicd_mdiobus_probe(struct platform_device *pdev)
{
	struct mii_bus *mii_bus;
	struct device_node *dn = pdev->dev.of_node;
	struct cmicd_mdiobus_private *bus_priv;
	struct iproc_mdiobus_data *bus_data;
	struct cmicd_mdio_ctrl *cmicd_ctrl;
	u32 mdio_bus_id;
	u32 logical_mdio_bus_id;
	const char *mdio_bus_type;
	int ret;
	
	if (!of_device_is_available(dn))
		return -ENODEV;

	cmicd_ctrl = cmicd_mdio_res_alloc();
	if (!cmicd_ctrl) {
		dev_err(&pdev->dev, "cmicd mdio rese alloc failed\n");
		ret = -ENOMEM;
		goto err_exit;
	}
	
	/* Get register base address */
	cmicd_ctrl->base = (void *)of_iomap(dn, 0); /* GH:0x03233000(cmc2), 0x03232000(cmc1) */
#ifdef __BIG_ENDIAN	
	cmicd_ctrl->cmic_common = (void *)of_iomap(dn, 1); /* GH:0x03210000 */
#endif
	
	if (of_property_read_u32(dn, "#bus-id", &mdio_bus_id)) {
    	mdio_bus_id = 2; /* no property available, use default: 2 */
    }
    if (of_property_read_u32(dn, "#logical-bus-id", &logical_mdio_bus_id)) {
    	logical_mdio_bus_id = 0; /* no property available, use default: 0 */
    }
    if (of_property_read_string(dn, "bus-type", &mdio_bus_type)) {
    	mdio_bus_type = "external"; /* no property available, use default: "external" */
    }
    iproc_mdiobus_data.phybus_num = (u8) mdio_bus_id;
    iproc_mdiobus_data.logbus_num = (u8) logical_mdio_bus_id;
    if (!strcmp(mdio_bus_type, "internal"))
    	iproc_mdiobus_data.phybus_type = IPROC_MDIOBUS_TYPE_INTERNAL;
    else
    	iproc_mdiobus_data.phybus_type = IPROC_MDIOBUS_TYPE_EXTERNAL;
	
	iproc_mdiobus_data.logbus_type = iproc_mdiobus_data.phybus_type;
	
	bus_data = &iproc_mdiobus_data;	
	
	mii_bus = mdiobus_alloc_size(sizeof(*bus_priv));
	if (!mii_bus) {
		dev_err(&pdev->dev, "mdiobus_alloc failed\n");
		ret = -ENOMEM;
		goto err_ctrl_free;
	}
	
	mii_bus->name = "iproc_cmicd_mdiobus";	
	snprintf(mii_bus->id, MII_BUS_ID_SIZE, IPROC_MDIO_ID_FMT, 
		bus_data->logbus_num, bus_data->logbus_type);
	mii_bus->parent = &pdev->dev;
	mii_bus->read = cmicd_mdiobus_read;
	mii_bus->write = cmicd_mdiobus_write;

	bus_priv = mii_bus->priv;
	memcpy(&bus_priv->bus_data, bus_data, sizeof(struct iproc_mdiobus_data));
	bus_priv->hw_ctrl = cmicd_ctrl;

	ret = mdiobus_register(mii_bus);
	if (ret) {
		dev_err(&pdev->dev, "mdiobus_register failed\n");
		goto err_bus_free;
	}

	platform_set_drvdata(pdev, mii_bus);

#if 0
	cmicd_mdiobus_test(mii_bus);
#endif	

	return 0;

err_bus_free:
	kfree(mii_bus);
err_ctrl_free:
	cmicd_mdio_res_free(cmicd_ctrl);
err_exit:
	return ret;
}

static int cmicd_mdiobus_remove(struct platform_device *pdev)
{
	struct mii_bus *mii_bus = platform_get_drvdata(pdev);
	struct cmicd_mdiobus_private *bus_priv;

	if (mii_bus) {	
		bus_priv = mii_bus->priv;

		mdiobus_unregister(mii_bus);
		if (bus_priv)
			cmicd_mdio_res_free(bus_priv->hw_ctrl);
		mdiobus_free(mii_bus);
	}

	return 0;
}

static const struct of_device_id bcm_iproc_dt_ids[] = {
	{ .compatible = "brcm,iproc-cmicd-mdio"},
	{  }
};
MODULE_DEVICE_TABLE(of, bcm_iproc_dt_ids);

static struct platform_driver iproc_cmicd_mdiobus_driver = 
{
	.driver = {
		.name = "iproc_cmicd_mdio",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(bcm_iproc_dt_ids),
	},
	.probe   = cmicd_mdiobus_probe,
	.remove  = cmicd_mdiobus_remove,
};

static int __init cmicd_mdio_init(void)
{
	return platform_driver_register(&iproc_cmicd_mdiobus_driver);
}

static void __exit cmicd_mdio_exit(void)
{
	platform_driver_unregister(&iproc_cmicd_mdiobus_driver);
}

//module_init(cmicd_mdio_init);
subsys_initcall(cmicd_mdio_init);
module_exit(cmicd_mdio_exit);

MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("iProc CMICd mdio driver");
MODULE_LICENSE("GPL");

