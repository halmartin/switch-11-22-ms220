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

#include "iproc_mdio.h"

#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/clk.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/platform_device.h>

#include "iproc_mdio_dev.h"

#ifdef CONFIG_OF_MDIO
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
static struct iproc_mdiobus_data iproc_mdiobus_data;
#define __devinit /* */
#define __devexit /* */
#endif /* CONFIG_OF_MDIO */

#ifndef CONFIG_OF_MDIO
#define CCB_MDIO_BASE_ADDRESS		IPROC_MII_MGMT_CTL
#endif

#define R_REG(reg)                  ioread32(ccb_mdio->base + (reg&0x0fff))
#define W_REG(reg, val)             iowrite32(val, ccb_mdio->base + (reg&0x0fff))

#define MII_ERR_VAL	                0x0001
#define MII_MSG_VAL	                0x0002
#define MII_DBG_VAL	                0x0004
//static u32 mii_msg_level = MII_ERR_VAL;

#if defined(BCMDBG) || defined(BCMDBG_ERR)
#define MII_ERR(args)	do {if (mii_msg_level & MII_ERR_VAL) printk args;} while (0)
#else
#define MII_ERR(args)
#endif

#ifdef BCMDBG
#define MII_MSG(args)	do {if (mii_msg_level & MII_MSG_VAL) printk args;} while (0)
#define MII_DBG(args)	do {if (mii_msg_level & MII_DBG_VAL) printk args;} while (0)
#else
#define MII_MSG(args)
#define MII_DBG(args)
#endif

#define MII_EN_CHK  \
    {\
         if (!ccb_mdio->base) { \
             return MII_ERR_INIT; \
		 } \
         if (!(R_REG(MII_MGMT) & 0x7f)) { \
             return MII_ERR_INTERNAL; \
		 } \
    }

#define MII_TRIES 100000
#define MII_POLL_USEC                     20

struct mdio_device_data {
    mdio_info_t *mdio;
    int init;
};

static struct mdio_device_data mdio_devices={0};
static uint32_t ccb_mdio_clk_rate;

#define DRIVER_VERSION              "0.01"
#define DRIVER_NAME                 "iproc mdio"

static int mdio_major;
static struct cdev mdio_cdev;

#define MDIO_IOC_OP_EXTERNAL_READ     0
#define MDIO_IOC_OP_EXTERNAL_WRITE    1
#define MDIO_IOC_OP_LOCAL_READ        2
#define MDIO_IOC_OP_LOCAL_WRITE       3


struct ccb_mdio_ctrl {
	void __iomem *base;
	int ref_cnt;
};

struct ccb_mdiobus_private {
	/* iproc_mdiobus_data field have to  be placed at the beginning of
	 *  mdiobus private data */
	struct iproc_mdiobus_data bus_data;
	struct ccb_mdio_ctrl *hw_ctrl;
};

static struct ccb_mdio_ctrl *ccb_mdio = NULL;

#ifndef CONFIG_OF_MDIO
static struct resource ccb_mdio_mem = {
	.name	= "ccb_mdio",
	.start 	= CCB_MDIO_BASE_ADDRESS,
	.end 	= CCB_MDIO_BASE_ADDRESS + 0x1000 - 1,
	.flags	= IORESOURCE_MEM,
};
#endif

/* Function : ccb_mii_read
 *  - Read operation.
 * Return :
 * Note :
 */
int
ccb_mii_read(int dev_type, int phy_addr, int reg_off, uint16_t *data)
{
    int i;
	uint32_t ctrl = 0;
    unsigned long flags;
    mdio_info_t *mdio = NULL;

    MII_EN_CHK;

    mdio = mdio_devices.mdio;

    spin_lock_irqsave(&mdio->lock, flags);

    ctrl = R_REG(MII_MGMT);
    if (dev_type == MII_DEV_LOCAL) {
        ctrl &= ~MII_MGMT_EXP_MASK;
    } else {
        ctrl |= MII_MGMT_EXP_MASK;
    }
    W_REG(MII_MGMT, ctrl);
    MII_DBG(("MII READ: write(0x%x)=0x%x\n",MII_MGMT, ctrl));

	for (i = 0; i < MII_TRIES; i++) {
        ctrl = R_REG(MII_MGMT);
		if (!(ctrl & MII_MGMT_BSY_MASK)) {
		    break;
		}
		udelay(MII_POLL_USEC);
	}
	if (i >= MII_TRIES) {
		MII_ERR(("\n%s: BUSY stuck: ctrl=0x%x, count=%d\n", __FUNCTION__, ctrl, i));
        spin_unlock_irqrestore(&mdio->lock, flags);
		return -1;
	}

	ctrl = (((1 << MII_CMD_DATA_SB_SHIFT) & MII_CMD_DATA_SB_MASK) |
            ((2 << MII_CMD_DATA_OP_SHIFT) & MII_CMD_DATA_OP_MASK) |
            ((phy_addr << MII_CMD_DATA_PA_SHIFT) & MII_CMD_DATA_PA_MASK) |
            ((reg_off << MII_CMD_DATA_RA_SHIFT) & MII_CMD_DATA_RA_MASK) |
            ((2 << MII_CMD_DATA_TA_SHIFT) & MII_CMD_DATA_TA_MASK));
    W_REG(MII_CMD_DATA, ctrl);
    MII_DBG(("MII READ: write(0x%x)=0x%x\n",MII_CMD_DATA, ctrl));

	for (i = 0; i < MII_TRIES; i++) {
        ctrl = R_REG(MII_MGMT);
		if (!(ctrl & MII_MGMT_BSY_MASK)) {
		    break;
		}
		udelay(MII_POLL_USEC);
	}
	if (i >= MII_TRIES) {
		MII_ERR(("\n%s: BUSY stuck: ctrl=0x%x, count=%d\n", __FUNCTION__, ctrl, i));
        spin_unlock_irqrestore(&mdio->lock, flags);
		return -1;
	}

	ctrl = R_REG(MII_CMD_DATA);

    MII_DBG(("MDIO READ: addr=%x off=%x value=%x\n", phy_addr, reg_off, ctrl));

    spin_unlock_irqrestore(&mdio->lock, flags);

    *data = (ctrl & 0xffff);
	return 0;
}

/* Function : ccb_mii_write
 *  - Write operation.
 * Return :
 * Note :
 */
int
ccb_mii_write(int dev_type, int phy_addr, int reg_off, uint16_t data)
{
    int i;
	uint32_t ctrl = 0;
    unsigned long flags;
    mdio_info_t *mdio = NULL;

    MII_DBG(("MDIO WRITE: addr=%x off=%x\n", phy_addr, reg_off));

    MII_EN_CHK;

    mdio = mdio_devices.mdio;

    spin_lock_irqsave(&mdio->lock, flags);

    ctrl = R_REG(MII_MGMT);
    if (dev_type == MII_DEV_LOCAL) {
        ctrl &= ~MII_MGMT_EXP_MASK;
    } else {
        ctrl |= MII_MGMT_EXP_MASK;
    }
    W_REG(MII_MGMT, ctrl);
    MII_DBG(("MII WRITE: write(0x%x)=0x%x\n",MII_MGMT, ctrl));

	for (i = 0; i < MII_TRIES; i++) {
        ctrl = R_REG(MII_MGMT);
		if (!(ctrl & MII_MGMT_BSY_MASK)) {
		    break;
		}
		udelay(MII_POLL_USEC);
	}
	if (i >= MII_TRIES) {
		MII_ERR(("\n%s: BUSY stuck: ctrl=0x%x, count=%d\n", __FUNCTION__, ctrl, i));
		spin_unlock_irqrestore(&mdio->lock, flags);
		return -1;
	}

	ctrl = (((1 << MII_CMD_DATA_SB_SHIFT) & MII_CMD_DATA_SB_MASK) |
            ((1 << MII_CMD_DATA_OP_SHIFT) & MII_CMD_DATA_OP_MASK) |
            ((phy_addr << MII_CMD_DATA_PA_SHIFT) & MII_CMD_DATA_PA_MASK) |
            ((reg_off << MII_CMD_DATA_RA_SHIFT) & MII_CMD_DATA_RA_MASK) |
            ((2 << MII_CMD_DATA_TA_SHIFT) & MII_CMD_DATA_TA_MASK) |
            ((data << MII_CMD_DATA_DATA_SHIFT) & MII_CMD_DATA_DATA_MASK));
    W_REG(MII_CMD_DATA, ctrl);
    MII_DBG(("MII WRITE: write(0x%x)=0x%x\n",MII_CMD_DATA, ctrl));


	for (i = 0; i < MII_TRIES; i++) {
        ctrl = R_REG(MII_MGMT);
		if (!(ctrl & MII_MGMT_BSY_MASK)) {
		    break;
		}
		udelay(MII_POLL_USEC);
	}
	if (i >= MII_TRIES) {
		MII_ERR(("\n%s: BUSY stuck: ctrl=0x%x, count=%d\n", __FUNCTION__, ctrl, i));
		spin_unlock_irqrestore(&mdio->lock, flags);
		return -1;
	}

    spin_unlock_irqrestore(&mdio->lock, flags);

	return MII_ERR_NONE;
}

/* Function : ccb_mii_freq_set
 *  - Set MII management interface frequency.
 * Return :
 * Note :
 *
 */
int
ccb_mii_freq_set(int speed_khz)
{
    int rv = MII_ERR_NONE;
	uint32_t divider = 0;
	uint32_t mgmt = 0;

    MII_DBG(("MDIO FREQ SET: %d KHz\n", speed_khz));

	/* host clock 66MHz device value the MDCDIV field */
	/* resultant MDIO clock should not exceed 2.5MHz */

	if (speed_khz > 2500) {
    	MII_ERR(("\n%s: Maximum MDIO frequency is 2.5MHz\n", __FUNCTION__));
	    return MII_ERR_PARAM;
	}

	divider = ccb_mdio_clk_rate / (1000*speed_khz);
	divider = (divider & MII_MGMT_MDCDIV_MASK);
	if (divider > 0x7f) {
	    /* make sure the minimum configurable frequency */
	    divider = 0x7f;
	}
    mgmt = R_REG(MII_MGMT);
	mgmt &= ~MII_MGMT_MDCDIV_MASK;
	mgmt |= divider;

    W_REG(MII_MGMT, mgmt);
    MII_DBG(("MII FREQ(%d KHz): write(0x%x)=0x%x\n",speed_khz, MII_MGMT, mgmt));

    return rv;
}

static int
mdio_open(struct inode *inode, struct file *filp)
{
    filp->private_data = mdio_devices.mdio;
    return 0;
}

static int
mdio_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static int mdio_message(mdio_info_t *mdio,
		struct mdio_ioc_transfer *u_xfers, unsigned n_xfers, int op)
{

    uint8_t pa, ra;
    uint16_t regval;

    pa = u_xfers->pa;
    ra = u_xfers->ra;

    MII_DBG(("mdio_message: op = %d\n", op));

    if (op == MDIO_IOC_OP_LOCAL_READ) {
        iproc_mii_read(MII_DEV_LOCAL, pa, ra, &regval);
        u_xfers->rx_buf = regval;
    }

    if (op == MDIO_IOC_OP_LOCAL_WRITE) {
        iproc_mii_write(MII_DEV_LOCAL, pa, ra, u_xfers->tx_buf);
    }

    if (op == MDIO_IOC_OP_EXTERNAL_READ) {
        iproc_mii_read(MII_DEV_EXT, pa, ra, &regval);
        u_xfers->rx_buf = regval;
    }

    if (op == MDIO_IOC_OP_EXTERNAL_WRITE) {
        iproc_mii_write(MII_DEV_EXT, pa, ra, u_xfers->tx_buf);
    }
    return 0;
}

static long
mdio_ioctl(struct file *filp,
                  unsigned int cmd, unsigned long arg)
{
    int         err = 0;
    int         retval = 0;
    int         ioc_op = 0;
    uint32_t      tmp;
    unsigned    n_ioc;
    struct mdio_ioc_transfer	*ioc, *uf;
    mdio_info_t *mdio;

    MII_DBG(("mdio_ioctl: cmd = %d\n", cmd));

    /* Check type and command number */
    if (_IOC_TYPE(cmd) != MDIO_IOC_MAGIC){
        return -ENOTTY;
    }

    /* Check access direction once here; don't repeat below.
     * IOC_DIR is from the user perspective, while access_ok is
     * from the kernel perspective; so they look reversed.
     */
    if (_IOC_DIR(cmd) & _IOC_READ) {
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    }
    if (err == 0 && _IOC_DIR(cmd) & _IOC_WRITE) {
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    }
    if (err) {
        return -EFAULT;
    }

    mdio = (mdio_info_t *)filp->private_data;

	switch (cmd) {
        case MDIO_IOC_EXTERNAL_R_REG:
            ioc_op = MDIO_IOC_OP_EXTERNAL_READ;
            break;
        case MDIO_IOC_EXTERNAL_W_REG:
            ioc_op = MDIO_IOC_OP_EXTERNAL_WRITE;
            break;
        case MDIO_IOC_LOCAL_R_REG:
            ioc_op = MDIO_IOC_OP_LOCAL_READ;
            break;
        case MDIO_IOC_LOCAL_W_REG:
            ioc_op = MDIO_IOC_OP_LOCAL_WRITE;
            break;
    }

    tmp = _IOC_SIZE(cmd);
    if ((tmp % sizeof(struct mdio_ioc_transfer)) != 0) {
        retval = -EINVAL;
        return retval;
    }
    n_ioc = tmp / sizeof(struct mdio_ioc_transfer);
    if (n_ioc == 0) {
        return 0;
    }

    /* copy into scratch area */
    ioc = kmalloc(tmp, GFP_KERNEL);
    if (!ioc) {
        retval = -ENOMEM;
        return retval;
    }
    if (__copy_from_user(ioc, (void __user *)arg, tmp)) {
        kfree(ioc);
        retval = -EFAULT;
        return retval;
    }
    /* translate to mdio_message, execute */
    retval = mdio_message(mdio, ioc, n_ioc, ioc_op);

    if ((ioc_op == MDIO_IOC_OP_EXTERNAL_READ) || (ioc_op == MDIO_IOC_OP_LOCAL_READ)) {
        uf = (struct mdio_ioc_transfer *)arg;
        if (__copy_to_user((u8 __user *)&uf->rx_buf, (uint8_t  *)&ioc->rx_buf, 2)) {
            kfree(ioc);
            retval = -EFAULT;
            return retval;
        }
    }
    kfree(ioc);

    return 0;
}

static const struct file_operations mdio_fops = {
    .open       = mdio_open,
    .release    = mdio_release,
    .unlocked_ioctl = mdio_ioctl,
    .owner      = THIS_MODULE,
};

static int _mdio_handler_init(void)
{
    mdio_info_t *mdio = NULL;

    mdio = kmalloc(sizeof(mdio_info_t), GFP_KERNEL);
    if (mdio == NULL) {
        MII_ERR(("mdio_init: out of memory\n"));
        return -ENOMEM;
    }
    memset(mdio, 0, sizeof(mdio_info_t));

	/* Initialize lock */
	spin_lock_init(&mdio->lock);

    mdio_devices.mdio = mdio;
    mdio_devices.init = 1;

    return 0;
}


static int ccb_mdiobus_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct ccb_mdiobus_private *bus_priv = bus->priv;
	struct iproc_mdiobus_data *bus_data = &bus_priv->bus_data;
	uint16_t data;
	int dev_type = 0;
	int err;

	if (IPROC_MDIOBUS_TYPE_INTERNAL == bus_data->phybus_type) {
		dev_type = MII_DEV_LOCAL;
	} else if (IPROC_MDIOBUS_TYPE_EXTERNAL == bus_data->phybus_type) {
		dev_type = MII_DEV_EXT;
	} else {
		return -EINVAL;
    }
    err = ccb_mii_read(dev_type, phy_id, regnum, &data);
    if (err < 0) {
        return err;
    } else {
        return data;
    }
}

static int ccb_mdiobus_write(struct mii_bus *bus, int phy_id,
				int regnum, u16 val)
{
	struct ccb_mdiobus_private *bus_priv = bus->priv;
	struct iproc_mdiobus_data *bus_data = &bus_priv->bus_data;
	int dev_type = 0;

	if (IPROC_MDIOBUS_TYPE_INTERNAL == bus_data->phybus_type) {
		dev_type = MII_DEV_LOCAL;
	} else if (IPROC_MDIOBUS_TYPE_EXTERNAL == bus_data->phybus_type) {
		dev_type = MII_DEV_EXT;
	} else {
		return -EINVAL;
    }

    return ccb_mii_write(dev_type, phy_id, regnum, val);
}

static void __maybe_unused ccb_mdiobus_test(struct mii_bus *mii_bus)
{
	int i, nRet1, nRet2;
	u16 data1 = 0, data2 = 0;
	struct phy_device *phy_dev;
	struct ccb_mdiobus_private *bus_priv = mii_bus->priv;
	struct iproc_mdiobus_data *bus_data = &bus_priv->bus_data;

	dev_info(mii_bus->parent, "%s : %s phy bus num[%d], type[%d]\n",
		__func__, mii_bus->id, bus_data->phybus_num, bus_data->phybus_type);

	/* Check if mdiobus_read works fine */
	for (i = 0; i < PHY_MAX_ADDR; i++) {
		phy_dev = mii_bus->phy_map[i];
		if (phy_dev) {
			dev_info(mii_bus->parent, "phy[%d] id=0x%08x, addr = %d\n",
				i, phy_dev->phy_id, phy_dev->addr);
			nRet1 = phy_read(phy_dev, 2);
			nRet2 = phy_read(phy_dev, 3);
			if ((nRet1 < 0) || (nRet2 < 0)) {
				dev_info(mii_bus->parent,
					"phy_read failed!, %s, nRet1 = %d, nRet2 = %d\n",
					dev_name(&phy_dev->dev), nRet1, nRet2);
			} else {
				dev_info(mii_bus->parent,
					"%s: reg2 = 0x%x, reg3 = 0x%x\n",
					dev_name(&phy_dev->dev), nRet1, nRet2);
	        }
		}
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

static struct ccb_mdio_ctrl *ccb_mdio_res_alloc(void)
{
	if (!ccb_mdio) {
		ccb_mdio = kzalloc(sizeof(*ccb_mdio), GFP_KERNEL);
		if (!ccb_mdio) {
			return NULL;
		}
		ccb_mdio->ref_cnt = 1;
	} else {
		ccb_mdio->ref_cnt++;
    }

	return ccb_mdio;
}

static void ccb_mdio_res_free(struct ccb_mdio_ctrl *ctrl)
{
	if (ctrl) {
		ctrl->ref_cnt --;
		if (ctrl->ref_cnt == 0) {
			iounmap(ctrl->base);
			kfree(ctrl);
			ccb_mdio = NULL;
		}
	}
}

void
ccb_mii_init(struct ccb_mdio_ctrl *ccb_mii)
{
    if (ccb_mii->ref_cnt == 1) {
        /* Set preamble */
        W_REG(MII_MGMT, MII_MGMT_PRE_MASK);

        /* Set the MII default clock 1MHz */
        ccb_mii_freq_set(1000); /* KHZ */
    }
}

#ifdef CONFIG_OF_MDIO
static int __devinit ccb_mii_probe(struct platform_device *pdev)
{
 	int ret = -ENODEV;
    struct device_node *dn = pdev->dev.of_node;
    struct mii_bus *mii_bus;
	struct ccb_mdiobus_private *bus_priv;
	struct iproc_mdiobus_data *bus_data;
	u32 mdio_bus_id;
	const char *mdio_bus_type;
	struct ccb_mdio_ctrl *ccb_ctrl;
	struct clk *clk=NULL;
		
	if (!of_device_is_available(dn))
		return -ENODEV;

	ccb_ctrl = ccb_mdio_res_alloc();
	if (!ccb_ctrl) {
		printk(KERN_ERR "ccb mdio res alloc failed\n");
		return -ENOMEM;
		
	}
	
	/* Get register base address */
	ccb_ctrl->base = (void *)of_iomap(dn, 0);
    MII_DBG(("MDIO INIT: Base Addr %x\n", ccb_ctrl->base));
	
	clk = of_clk_get (dn, 0);
	if (clk)
		ccb_mdio_clk_rate = clk_get_rate(clk)/2; /* used by ccb_mii_freq_set() */
	else {
		printk("No CCB MDIO Clock available from DT, use default clock rate: 62.5MHz\n");
		ccb_mdio_clk_rate = 62500000;
	}	
	
	ccb_mii_init(ccb_ctrl);

    if (of_property_read_u32(dn, "#bus-id", &mdio_bus_id)) {
    	mdio_bus_id = 0; /* no property available, use default: 0 */
    }
    if (of_property_read_string(dn, "bus-type", &mdio_bus_type)) {
    	mdio_bus_type = "internal"; /* no property available, use default: "internal" */
    }
    iproc_mdiobus_data.phybus_num = (u8) mdio_bus_id;
    if (!strcmp(mdio_bus_type, "internal"))
    	iproc_mdiobus_data.phybus_type = IPROC_MDIOBUS_TYPE_INTERNAL;
    else
    	iproc_mdiobus_data.phybus_type = IPROC_MDIOBUS_TYPE_EXTERNAL;
    /* Note: this applies to CCB/CCG MDIO, but not for CMICD MDIO */
    iproc_mdiobus_data.logbus_num = iproc_mdiobus_data.phybus_num;	  	
    iproc_mdiobus_data.logbus_type = iproc_mdiobus_data.phybus_type;	            
		
	bus_data = &iproc_mdiobus_data;
    
    mii_bus = mdiobus_alloc_size(sizeof(*bus_priv));
	if (!mii_bus)
		return -ENOMEM;
  
	mii_bus->name = "iproc_ccb_mdiobus";
	snprintf(mii_bus->id, MII_BUS_ID_SIZE, IPROC_MDIO_ID_FMT, 
			bus_data->logbus_num, bus_data->logbus_type);
	mii_bus->parent = &pdev->dev;
	mii_bus->read = ccb_mdiobus_read;
	mii_bus->write = ccb_mdiobus_write;
  
	bus_priv = mii_bus->priv;
	memcpy(&bus_priv->bus_data, bus_data, sizeof(struct iproc_mdiobus_data));
  	bus_priv->hw_ctrl = ccb_ctrl;
  
	ret = mdiobus_register(mii_bus);
	if (ret) {
		dev_err(&pdev->dev, "mdiobus_register failed\n");
		goto err_exit;
	}
    
    platform_set_drvdata(pdev, mii_bus);

	/* ccb_mdiobus_test(mii_bus); */

	return 0;

err_exit:
	kfree(mii_bus);
	return ret;
}

int ccb_mii_remove(struct platform_device *pdev)
{
	struct mii_bus *mii_bus = platform_get_drvdata(pdev);
	struct ccb_mdiobus_private *bus_priv;

	if (mii_bus) {
		bus_priv = mii_bus->priv;

		mdiobus_unregister(mii_bus);
		if (bus_priv) {
			ccb_mdio_res_free(bus_priv->hw_ctrl);
		}
		mdiobus_free(mii_bus);
	}

	return 0;
}


static const struct of_device_id bcm_iproc_dt_ids[] = {
	{ .compatible = "brcm,iproc-ccb-mdio"},
	{  }
};
MODULE_DEVICE_TABLE(of, bcm_iproc_dt_ids);

static struct platform_driver iproc_ccb_mdiobus_driver = {
	.probe = ccb_mii_probe,
	.remove = ccb_mii_remove,
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(bcm_iproc_dt_ids),
	},
};
/*module_platform_driver(iproc_ccb_mdiobus_driver);*/

#else /* CONFIG_OF_MDIO */

static int __devinit ccb_mdiobus_probe(struct platform_device *pdev)
{
	struct mii_bus *mii_bus;
	struct ccb_mdiobus_private *bus_priv;
	struct iproc_mdiobus_data *bus_data = pdev->dev.platform_data;
	struct ccb_mdio_ctrl *ccb_ctrl;
	int ret;

    /* Get register base address */
	ccb_ctrl = ccb_mdio_res_alloc();
	if (!ccb_ctrl) {
		printk(KERN_ERR "ccb mdio res alloc failed\n");
		ret = -ENOMEM;
		goto error_exit;
	}

	ccb_mii_init(ccb_ctrl);

	mii_bus = mdiobus_alloc_size(sizeof(*bus_priv));
	if (!mii_bus) {
		dev_err(&pdev->dev, "mdiobus alloc filed\n");
		ret = -ENOMEM;
		goto error_free_ctrl;
	}

	mii_bus->name = "iproc_ccb_mdiobus";
	snprintf(mii_bus->id, MII_BUS_ID_SIZE, IPROC_MDIO_ID_FMT,
		bus_data->logbus_num, bus_data->logbus_type);
	mii_bus->parent = &pdev->dev;
	mii_bus->read = ccb_mdiobus_read;
	mii_bus->write = ccb_mdiobus_write;

	bus_priv = mii_bus->priv;
	memcpy(&bus_priv->bus_data, bus_data, sizeof(struct iproc_mdiobus_data));
	bus_priv->hw_ctrl = ccb_ctrl;

	ret = mdiobus_register(mii_bus);
	if (ret) {
		dev_err(&pdev->dev, "mdiobus_register failed\n");
		goto error_free_bus;
	}

	platform_set_drvdata(pdev, mii_bus);

	return 0;

error_free_bus:
	kfree(mii_bus);
error_free_ctrl:
	ccb_mdio_res_free(ccb_ctrl);
error_exit:
	return ret;
}

static int __devexit ccb_mdiobus_remove(struct platform_device *pdev)
{
	struct mii_bus *mii_bus = platform_get_drvdata(pdev);
	struct ccb_mdiobus_private *bus_priv;

	if (mii_bus) {
		bus_priv = mii_bus->priv;

		mdiobus_unregister(mii_bus);
		if (bus_priv) {
			ccb_mdio_res_free(bus_priv->hw_ctrl);
		}
		mdiobus_free(mii_bus);
	}

	return 0;
}

static struct platform_driver iproc_ccb_mdiobus_driver =
{
	.driver = {
		.name = "iproc_ccb_mdio",
		.owner = THIS_MODULE,
	},
	.probe   = ccb_mdiobus_probe,
	.remove  = ccb_mdiobus_remove,
};
#endif /* CONFIG_OF_MDIO */

int
ccb_mdio_init(void)
{
    int ret = -ENODEV;
    dev_t mdio_dev;
    mdio_info_t *mdio = NULL;

    ret = _mdio_handler_init();
    if(ret != 0) {
        ret = -ENOMEM;
        goto error_exit;
    }
    
    mdio = mdio_devices.mdio;
    
    if (mdio_major) {
        mdio_dev = MKDEV(mdio_major, 0);
        ret = register_chrdev_region(mdio_dev, 1, "mdio");
    } else {
        ret = alloc_chrdev_region(&mdio_dev, 0, 1, "mdio");
        mdio_major = MAJOR(mdio_dev);
    }
    if (ret) {
        goto error_exit;
    }

    cdev_init(&mdio_cdev, &mdio_fops);
    ret = cdev_add(&mdio_cdev, mdio_dev, 1);
    if (ret) {
        printk(KERN_ERR "Fail to add mdio char dev!\n");
        goto error_region;
    }

	platform_driver_register(&iproc_ccb_mdiobus_driver);

    return 0;

error_region:
    unregister_chrdev_region(mdio_dev, 1);
error_exit:
    kfree(mdio);
    return ret;
}

void
ccb_mdio_exit(void)
{
    mdio_info_t *mdio = NULL;

    mdio = mdio_devices.mdio;
   	kfree(mdio);

    mdio_devices.mdio = NULL;
    mdio_devices.init = 0;
    unregister_chrdev_region(MKDEV(mdio_major, 0), 1);

	platform_driver_unregister(&iproc_ccb_mdiobus_driver);
}


//module_init(ccb_mdio_init);
subsys_initcall(ccb_mdio_init);
module_exit(ccb_mdio_exit);


EXPORT_SYMBOL(ccb_mii_init);
EXPORT_SYMBOL(ccb_mii_freq_set);
EXPORT_SYMBOL(ccb_mii_read);
EXPORT_SYMBOL(ccb_mii_write);

MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("BCM5301X MDIO Device Driver");
MODULE_LICENSE("GPL");

