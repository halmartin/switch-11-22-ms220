/*
 * $Copyright Open Broadcom Corporation$
 */
 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
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
#include "iproc_mdio.h"

/* Only one MDIO bus has been supported for each type */
static struct mii_bus *iproc_mdiobus[IPROC_MDIOBUS_TYPE_MAX] = {0};

static struct mii_bus* 
get_iproc_mdiobus(int bustype, int phy_addr)
{
	struct device *d;
	char bus_id[MII_BUS_ID_SIZE];
	char phy_id[20];
	struct phy_device *phy_dev;
    int idx;
    
    if (bustype < 0 || bustype >= IPROC_MDIOBUS_TYPE_MAX) {
        return NULL;
    }
    
    if (NULL == iproc_mdiobus[bustype]) {
        for (idx = 0; idx < IPROC_MDIOBUS_NUM_MAX; idx++) {
            snprintf(bus_id, MII_BUS_ID_SIZE, IPROC_MDIO_ID_FMT, idx, bustype);
            snprintf(phy_id, 20, PHY_ID_FMT, bus_id, phy_addr);
    		d = bus_find_device_by_name(&mdio_bus_type, NULL, phy_id);
    		if (d) {
    		    phy_dev = to_phy_device(d);
    		    iproc_mdiobus[bustype] = phy_dev->bus;
    		    idx = IPROC_MDIOBUS_NUM_MAX;
    		}
        }
    }
    
    return iproc_mdiobus[bustype];
}


/**
 * iproc_mii_read - General iProc interface function for reading a given PHY register 
 			if not registered PHY interface by phy_driver_register
 * @busnum: currently we're using busnum value 0
 * @bustype: the mdio bus type, coud be IPROC_MDIOBUS_TYPE_INTERNAL or IPROC_MDIOBUS_TYPE_EXTERNAL
 * @phy_addr: the phy address
 * @regnum: register number to read, if MII_ADDR_C45 == (@regnum & MII_ADDR_C45), means a C45 request
 * @val: the address to store read value if the read operation is successful
 * 
 * Returns 0 on success, or a negative value on error.
 */
int iproc_mii_read(int dev_type, int phy_addr, u32 reg_off, u16 *data)
{
	struct mii_bus *mii_bus;
	int bustype;
	int err = -1;

	if (MII_DEV_LOCAL == dev_type) {
		bustype = IPROC_MDIOBUS_TYPE_INTERNAL;
	} else if (MII_DEV_EXT == dev_type) {
		bustype = IPROC_MDIOBUS_TYPE_EXTERNAL;
	} else {
		return -EINVAL;
	}
	
	mii_bus = get_iproc_mdiobus(bustype, phy_addr);
	if (mii_bus) {
		err = mii_bus->read(mii_bus, phy_addr, reg_off);
		if (err >= 0) {
			*data = err;
		}
	} else {
		pr_err("%s : mdioubs:%d:%d is invalid!\n", __func__, 0, bustype);
    }
    
	return err;
}
EXPORT_SYMBOL(iproc_mii_read);

/**
 * iproc_mii_write - General iProc interface function for writing a given PHY register
 			if not registered PHY interface by phy_driver_register
 * @busnum: currently we're using busnum value 0
 * @bustype: the mdio bus type, coud be IPROC_MDIOBUS_TYPE_INTERNAL or IPROC_MDIOBUS_TYPE_EXTERNAL
 * @phy_addr: the phy address
 * @regnum: register number to write, if MII_ADDR_C45 == (@regnum & MII_ADDR_C45), means a C45 request
 * @val: value to write to @regnum
 *
 * Returns 0 on success, or a negative value on error.
 */
int iproc_mii_write(int dev_type, int phy_addr, u32 reg_off, u16 data)
{
	struct mii_bus *mii_bus;
	int bustype;
	int err = -1;

	if (MII_DEV_LOCAL == dev_type) {
		bustype = IPROC_MDIOBUS_TYPE_INTERNAL;
	} else if (MII_DEV_EXT == dev_type) {
		bustype = IPROC_MDIOBUS_TYPE_EXTERNAL;
	} else {
		return -EINVAL;
	}
	
	mii_bus = get_iproc_mdiobus(bustype, phy_addr);
	if (mii_bus) {
		err = mii_bus->write(mii_bus, phy_addr, reg_off, data);
	} else {
		pr_err("%s : mdioubs:%d:%d is invalid!\n", __func__, 0, bustype);
    }
    
	return err;
}
EXPORT_SYMBOL(iproc_mii_write);

