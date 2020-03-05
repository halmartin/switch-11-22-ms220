/*
 *
 * pd690xx_poe.c - Driver for PD690xx Power over Ethernet controller
 *
 * Copyright (c) 2011, 2013 Meraki, Inc.
 * Author: Kevin Paul Herbert (kph@meraki.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * This is a driver for the MicroSemi PD690xx power controllers in auto mode.
 * This driver interfaces with the PoE subsystem and provides the methods
 * to control the underlying PoE controllers and ports.
 *
 * This driver can support multiple PoE subsystems, each with up to
 * 8 controllers supporting 12 ports per controller. The platform is
 * responsible for defining the use of I2C and GPIO addresses, and
 * this driver will create the appropriate device, controller, and port
 * instances using the generic PoE subsystem.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/i2c.h>
#include <linux/poe.h>
#include <linux/pd690xx.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#define PD690XX_GENERAL_USER			(0x0318)
#define PD690XX_TOVID_AF			(0x100e)
#define PD690XX_TOVID_AT			(0x1010)
#define PD690XX_VMAIN_HIGH_TH			(0x12fe)
#define PD690XX_VMAIN_AT_LOW_MIN_TH		(0x1300)
#define PD690XX_VMAIN_AT_LOW_MAX_TH		(0x1302)
#define PD690XX_MST_CFG_SYS_POWER_BUDGET(bank)	(0x138c+(bank<<1))
#define PD690XX_PM_MODE				(0x1160)
#define PD690XX_STARTUP_PRIORITY		(0x1190)
#define PD690XX_BOOT_STATE			(0x1168)
#define PD690XX_SW_CONFIG_REG			(0x139e)
#define PD690XX_GENERAL_SYSTEM_ERRORS		(0x1314)
#define PD690XX_I2C_EXT_SYNC_TYPE		(0x1318)
#define PD690XX_EXT_EV_IRQ			(0x1144)
#define PD690XX_PORT_POWER_DENIED_CNT		(0x120c)
#define PD690XX_PORT_POWER_OVERLOAD_CNT		(0x1224)
#define PD690XX_PORT_POWER_UNDERLOAD_CNT	(0x123c)
#define PD690XX_FORCE_RECALCULATION		(0x139c)
#define PD690XX_PORT_POWER_DOWN_CANDIDATE	(0x129c)
#define PD690XX_PORT_CONFIG(port)		(0x131a+(port<<1))

#define PD690XX_PORT_CONFIG_PORT_ENABLE_SHIFT	(0)
#define PD690XX_PORT_CONFIG_PORT_ENABLE_MASK	(0x3)
#define PD690XX_PORT_CONFIG_PORT_PAIR_SHIFT	(2)
#define PD690XX_PORT_CONFIG_PORT_PAIR_MASK	(0x3<<2)
#define PD690XX_PORT_CONFIG_PORT_TYPE_SHIFT	(4)
#define PD690XX_PORT_CONFIG_PORT_TYPE_MASK	(0x3<<4)
#define PD690XX_PORT_CONFIG_PORT_PRIORITY_SHIFT	(6)
#define PD690XX_PORT_CONFIG_PORT_PRIORITY_MASK  (0x3<<6)

#define PD690XX_DIS_PORTS_CMD			(0x1332)
#define PD690XX_PORT_POWER_ALLOTMENT		(0x1334)
#define PD690XX_VMAIN				(0x105c)
#define PD690XX_SYS_INIT			(0x1164)
#define PD690XX_AVG_JUNC_TEMP			(0x130a)
#define PD690XX_CFGC_ICVER			(0x031a)
#define PD690XX_SYS_TOTAL_CALC_POWER_CONS	(0x12e2)
#define PD690XX_SYS_TOTAL_REAL_POWER_CONS	(0x12e8)
#define PD690XX_TOTAL_POWER_CONS_SLAVE(slave)	(0x12ec+(slave<<1))
#define PD690XX_LOCAL_TOTAL_REAL_POWER_CONS	(0x12aa)
#define PD690XX_PORT_CLASS			(0x11c2)
#define PD690XX_PORT_POWER_CONS			(0x12b4)
#define PD690XX_PORT_STATUS			(0x11aa)
// This is an undocumented register that Microsemi told us
// about over email so that we can detect when the PoE chip
// is receiving power and running in negative current
// protection mode.  In this mode it will continue to send
// power to existing clients but will not send power to new
// clients.
#define PD690XX_NEGATIVE_CURRENT_INDICATOR	(0x13a2)

#define PD690XX_RESET_RETRIES	10	/* Maximum initialization retries */

#define PD690XX_RESET_DELAY	500	/* Time to wait after reset */
#define PD690XX_INIT_DELAY	100	/* Additional wait time */
#define PD690XX_REINIT_DELAY	(5*1000) /* Wait when reinitializing */
#define PD690XX_POLL_INTERVAL	(250)   /* Poll frequency for chip (polls one controller or port per run) */

#define PD690XX_MAX_PORTS_PER_CONTROLLER 12
#define PD690XX_MAX_CONTROLLERS 8
#define PD690XX_MAX_PORTS  (PD690XX_MAX_CONTROLLERS * PD690XX_MAX_PORTS_PER_CONTROLLER)

#define PD690XX_FAST_STATE_DETECT_BATCH_SIZE 6

enum pd690xx_state {
	PD690XX_STATE_PROBE,	    /* Device is being probed */
	PD690XX_STATE_RESET,	    /* Controller is in reset state */
	PD690XX_STATE_INITIALIZING, /* Controller is initializing */
	PD690XX_STATE_RUNNING,	    /* Controller is running */
	PD690XX_STATE_RESET_PENDING, /* Error occured, reset pending */
};

struct pd690xx {
	struct delayed_work	work;
	int                     work_state; // 0..(poe->controllers + poe->ports)
	int                     work_substate;
	struct i2c_client	*client;
	struct poe_dev		*poe;
	int			disable_ports;
	int			reset;
	int			logic_low;
	const u8		*slave_addr;
	enum pd690xx_state	state;
	int			init_retries;
	uint32_t 		last_joule_time[PD690XX_MAX_PORTS];
	int			joule_time_set[PD690XX_MAX_PORTS];
	int			fast_state_detect_port;
	struct mutex		lock;
};

/*
 * pd690xx_reset - Schedule a reset
 *
 * This routine is called after an I/O error. We put the device in
 * reset, and schedule reinitialization.
 */

void pd690xx_reset(struct pd690xx *pd)
{
	struct i2c_client *client = pd->client;

	if ((pd->state == PD690XX_STATE_RESET_PENDING) ||
	    (pd->state == PD690XX_STATE_PROBE))
	    return;		/* Already pending or probing */

	dev_warn(&client->dev, "Unexpected error, resetting");
	pd->state = PD690XX_STATE_RESET_PENDING;
	gpio_set_value_cansleep(pd->disable_ports, !pd->logic_low); /* Power down */
	gpio_set_value_cansleep(pd->reset, pd->logic_low); /* Reset */
	schedule_delayed_work(&pd->work,
			      msecs_to_jiffies(PD690XX_REINIT_DELAY));
}

/*
 * pd690xx_read_value - Read a register from any PD690xx
 *
 * This routine is used to read a register from the PD690xx.
 * The command format is to send the register address to the
 * device as a 16 bit I2C write, and then issue a 16 bit I2C read
 * with no intervening stop bit.
 */

static int pd690xx_read_value(struct pd690xx *pd, int chip, u16 reg)
{
	struct i2c_client *client = pd->client;
	int ret;
	struct i2c_msg messages[2];
	u8 txbuf[2];
	u8 rxbuf[2];
	u16 addr = client->addr + pd->slave_addr[chip];

	if (pd->state == PD690XX_STATE_RESET_PENDING)
		return -EIO;	/* I/O error */

	txbuf[0] = reg >> 8;
	txbuf[1] = reg & 0xff;

	messages[0].addr = addr;
	messages[0].flags = 0;
	messages[0].len = 2;
	messages[0].buf = txbuf;

	messages[1].addr = addr;
	messages[1].flags = I2C_M_RD;
	messages[1].len = 2;
	messages[1].buf = rxbuf;

	ret = i2c_transfer(client->adapter, messages, 2);
	if (ret < 0) {
		dev_err(&client->dev,
			"%s: i2c_transfer[%02x:%04x] returned %d\n",
			__func__, addr, reg, ret);
		pd690xx_reset(pd);
		return -EIO;
	}

	if (ret != 2) {
		dev_err(&client->dev, "%s: unexpected I/O count %d\n",
			__func__, ret);
		pd690xx_reset(pd);
		return -EIO;
	}

	return ((rxbuf[0] << 8 | rxbuf[1]));
}

/*
 * pd690xx_read_port_value - Read a value for a specific port
 *
 * This routine is used to read a value for a specific port. Based on
 * the port number, we pick the correct controller and register offset.
 * The port number and base register are passed to us. Note that this
 * only works for registers that are indexed by port number * 2.
 */

static int pd690xx_read_port_value(struct pd690xx *pd, int sys_port, u16 reg)
{
	int ret;
	int controller = sys_port / pd->poe->ports_per_controller;
	int port = sys_port % pd->poe->ports_per_controller;
	struct poe_port_kobj *port_kobj = pd->poe->port_kobjs[port];

	ret =  pd690xx_read_value(pd, controller, reg + (port * 2));
	if (ret < 0) {
		port_kobj->status = PORT_POWER_OFF;
		poe_port_notify_state_change(&port_kobj->kobj);
		port_kobj->substatus = PORT_OFF_SYSTEM_ERROR;
	}

	return ret;
}

static int pd690xx_write_value(struct pd690xx *pd, int chip, u16 reg, u16 val)
{
	struct i2c_client *client = pd->client;
	int ret;
	struct i2c_msg message;
	u8 txbuf[4];
	u16 addr = client->addr + pd->slave_addr[chip];

	if (pd->state == PD690XX_STATE_RESET_PENDING)
		return -EIO;

	txbuf[0] = reg >> 8;
	txbuf[1] = reg & 0xff;
	txbuf[2] = val >> 8;
	txbuf[3] = val & 0xff;

	message.addr = addr;
	message.flags = 0;
	message.len = 4;
	message.buf = txbuf;

	ret = i2c_transfer(client->adapter, &message, 1);
	if (ret < 0) {
		dev_err(&client->dev, "%s: i2c_transfer returned %d\n",
			__func__, ret);
		pd690xx_reset(pd);
	} else 	if (ret != 1) {
		dev_err(&client->dev, "%s: unexpected I/O count %d\n",
			__func__, ret);

		pd690xx_reset(pd);
	}

	return ret;
}

/*
 * pd690xx_config_mode - Enter configuration mode
 *
 * Enter configuration mode. See section 1.4 of datasheet for info.
 */

static void pd690xx_config_mode(struct pd690xx *pd)
{
	struct poe_dev *poe = pd->poe;
	struct i2c_client *client = pd->client;
	int ret;
	int controller;

	for (controller = 0;
	     controller < poe->controllers;
	     controller++) {
		pd690xx_write_value(pd, controller,
				    PD690XX_DIS_PORTS_CMD, 0xfff);
		pd690xx_write_value(pd, controller,
				    PD690XX_SW_CONFIG_REG, 0xdc03);
		pd690xx_write_value(pd, controller,
				    PD690XX_I2C_EXT_SYNC_TYPE, 0x0020);
		pd690xx_write_value(pd, controller,
				    PD690XX_EXT_EV_IRQ, 0x0020);

		if (pd->state == PD690XX_STATE_RESET_PENDING)
			return;		/* Something is broken */

		msleep(50);

		ret = pd690xx_read_value(pd, controller, PD690XX_SW_CONFIG_REG);
		if (ret < 0) {
			dev_err(&client->dev, "Controller %d I/O error, "
				"ret = %d\n", controller, ret);
			pd690xx_reset(pd);
			return;
		}

		if (ret != 0x0003) {
			dev_err(&client->dev,
				"Controller %d unable to set config mode, "
				"SW_ConfigReg = %x\n",
				controller, ret);
			pd690xx_reset(pd);
			return;
		}
	}
}

/*
 * pd690xx_auto_mode - Enter auto mode
 *
 * Enter auto mode. See section 1.4 of datasheet for info.
 */

static void pd690xx_auto_mode(struct pd690xx *pd)
{
	struct poe_dev *poe = pd->poe;
	struct i2c_client *client = pd->client;
	struct poe_port_kobj *port_kobj;
	int ret;
	int controller;
	int disable_mask;
	int port;

	for (controller = 0;
	     controller < poe->controllers;
	     controller++) {

		pd690xx_write_value(pd, controller,
				    PD690XX_SW_CONFIG_REG, 0xdc00);
		pd690xx_write_value(pd, controller,
				    PD690XX_I2C_EXT_SYNC_TYPE, 0x0020);
		pd690xx_write_value(pd, controller,
				    PD690XX_EXT_EV_IRQ, 0x0020);

		msleep(50);
		ret = pd690xx_read_value(pd, controller,
					 PD690XX_SW_CONFIG_REG);
		if (ret != 0x0000) {
			dev_err(&client->dev,"pd690xx: Controller %d "
				"unable to set auto mode, SW_ConfigReg = %x\n",
				controller, ret);
			pd690xx_reset(pd);
			return;
		}
		disable_mask = 0;
		for (port = 0; port < poe->ports_per_controller; port++) {
			port_kobj = poe->port_kobjs[
				(controller * poe->ports_per_controller) +
				port];
			if (!port_kobj->enabled)
				disable_mask |= 1 << port;
		}

		pd690xx_write_value(pd, controller,
				    PD690XX_DIS_PORTS_CMD, disable_mask);
	}
}

static const enum PORT_POWER_STATE poe_status_to_state[] = {
	PORT_POWER_ON,
	PORT_POWER_ON,
	PORT_POWER_STARTING,
	PORT_POWER_STARTING,
	PORT_POWER_STARTING,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
	PORT_POWER_TEST,
	PORT_POWER_STARTING,
	PORT_POWER_OFF,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
	PORT_POWER_TEST,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
	PORT_POWER_OFF,
	PORT_POWER_ERROR,
	PORT_POWER_ERROR,
};

static const int poe_status_to_substate[] = {
	PORT_ON_VALID_SIGNATURE,
	PORT_ON_FORCED,
	PORT_STARTING_INIT,
	PORT_STARTING_FORCED,
	PORT_STARTING_SEARCHING,
	PORT_ERROR_SIGNATURE,
	PORT_ERROR_CLASS,
	PORT_TEST_WAITING,
	PORT_STARTING_DETECTED,
	PORT_OFF_DISABLED,
	PORT_ERROR_STARTUP_OVERLOAD,
	PORT_ERROR_STARTUP_UNDERLOAD,
	PORT_ERROR_STARTUP_SHORT,
	PORT_ERROR_DV_DT,
	PORT_TEST_ERROR,
	PORT_ERROR_OVERLOAD,
	PORT_ERROR_UNDERLOAD,
	PORT_ERROR_SHORT,
	PORT_OFF_PM,
	PORT_ERROR_CHIP,
	PORT_ERROR_UNKNOWN,
};

enum {SYS_RECALC = 0, SYS_TOTAL_POWER, SYS_NEG_CURRENT, SYS_GEN_ERROR, SYS_REG_CNT};
static int pd690xx_do_periodic_system(struct pd690xx *pd, int reg)
{
	struct poe_dev *poe = pd->poe;
	struct i2c_client *client = pd->client;
	int ret;

	switch (reg) {
	case SYS_RECALC:
		ret = pd690xx_write_value(pd, 0, PD690XX_FORCE_RECALCULATION, 1);
		if (ret < 0)
			return ret;
	break;
	case SYS_TOTAL_POWER:
		ret = pd690xx_read_value(pd, 0, PD690XX_SYS_TOTAL_REAL_POWER_CONS);
		if (ret < 0)
			return ret;
		poe->total_power = (ret & 0xffff) * 100; /* Return power in mW */
	break;
	case SYS_NEG_CURRENT:
		ret = pd690xx_read_value(pd, 0, PD690XX_NEGATIVE_CURRENT_INDICATOR);
		if (ret < 0)
			return ret;
		poe->status = ret ? DEVICE_STATUS_NEGATIVE_CURRENT_ERROR : DEVICE_STATUS_NORMAL;
	break;
	case SYS_GEN_ERROR:
		ret = pd690xx_read_value(pd, 0, PD690XX_GENERAL_SYSTEM_ERRORS);
		if (ret < 0)
			return ret;
		if (ret & 0x4) {
			dev_err(&client->dev, "Disable_ports PIN is active, resetting!\n");
			pd690xx_reset(pd);
			return -1;
		}
	break;
	};

	return 0;
}

enum {CTRL_REG_BOOT = 0, CTRL_REG_VMAIN, CTRL_REG_TEMP, CTRL_REG_MASTER,
	CTRL_REG_SLAVE, CTRL_REG_LIMIT, CTRL_REG_CNT};
static int pd690xx_do_periodic_controller(struct pd690xx *pd, int controller, int reg)
{
	struct poe_dev *poe = pd->poe;
	struct i2c_client *client = pd->client;
	int ret;
	int temp;

	switch (reg) {
	case CTRL_REG_BOOT:
		ret = pd690xx_read_value(pd, controller, PD690XX_BOOT_STATE);
		if (ret < 0)
			return ret;

		if ((ret & 0xff) != 0x9) {
			dev_err(&client->dev, "Controller %d "
				"unexpected ret %04x\n",
				controller, ret);
			pd690xx_reset(pd);
			return -1;
		}
		if (ret & 0x3f00) {
			dev_err(&client->dev, "Controller %d "
				"CPU error %04x\n",
				controller, ret);
			pd690xx_reset(pd);
			return -1;
		}
	break;
	case CTRL_REG_VMAIN:
		/* Slave is still working, read the stats */

		ret = pd690xx_read_value(pd, controller, PD690XX_VMAIN);
		if (ret < 0)
			return ret;

		poe->controller_kobjs[controller]->vmain = (ret & 0x3ff) * 61;
	break;
	case CTRL_REG_TEMP:
		ret = pd690xx_read_value(pd, controller, PD690XX_AVG_JUNC_TEMP);
		if (ret < 0)
			return ret;
		/*
		 * Ugly formula transliterated from page 10 of Rev 1.2
		 * datasheet. Ugly formula uses fixed point arithmetic
		 * and confuses ":" operator for subtraction.
		 */

		temp = ((((ret & 0x3ff) - 684) * 1000) / (-1514)) - 40;
		if (temp != poe->controller_kobjs[controller]->temp) {
			poe->controller_kobjs[controller]->temp = temp;
#ifdef CONFIG_THERMAL
			thermal_zone_device_update(poe->controller_kobjs[controller]->
						   tdev);
#endif
		}
	break;
	case CTRL_REG_MASTER:
		ret = pd690xx_read_value
			(pd, 0, PD690XX_TOTAL_POWER_CONS_SLAVE(controller));
		if (ret < 0)
			return ret;
		poe->controller_kobjs[controller]->power_master =
			(ret & 0xffff) * 100;
	break;
	case CTRL_REG_SLAVE:
		ret = pd690xx_read_value(pd, controller,
					 PD690XX_LOCAL_TOTAL_REAL_POWER_CONS);
		if (ret < 0)
			return ret;
		poe->controller_kobjs[controller]->power_slave =
			(ret & 0xffff) * 100;
	break;
	case CTRL_REG_LIMIT:
		ret = pd690xx_read_value(pd, controller,
					 PD690XX_MST_CFG_SYS_POWER_BUDGET(0));
		if (ret < 0)
			return ret;
		poe->controller_kobjs[controller]->power_limit =
			(ret & 0xffff) * 100;
	break;
	};

	return 0;
}

static int pd690xx_update_port_status(struct pd690xx *pd, int port)
{
	struct poe_dev *poe = pd->poe;
	int ret;
	int mode;

	ret = pd690xx_read_port_value(pd, port, PD690XX_PORT_STATUS);
	if (ret < 0)
		return ret;
	if ((ret & 0xff) > 20) {
		dev_err(&pd->client->dev,
			"Port %d unexpected status %x\n", port, ret);
		pd690xx_reset(pd);
		return -EIO;
	}

	mode = !!(ret & (1<<11));
	if (mode == 0)
		poe->port_kobjs[port]->mode = PORT_MODE_AF;
	else if (mode == 1)
		poe->port_kobjs[port]->mode = PORT_MODE_AT;

	poe->port_kobjs[port]->status = poe_status_to_state[ret & 0xff];
	poe->port_kobjs[port]->substatus = poe_status_to_substate[ret & 0xff];
	poe_port_notify_state_change(&poe->port_kobjs[port]->kobj);

	return 0;
}

enum {PORT_REG_POWER = 0, PORT_REG_DENIED, PORT_REG_OVERLOAD,
	PORT_REG_UNDERLOAD, PORT_REG_CLASS, PORT_REG_CNT};
static int pd690xx_do_periodic_port(struct pd690xx *pd, int port, int reg)
{
	struct poe_dev *poe = pd->poe;
	int ret, power;

        switch (reg) {
        case PORT_REG_POWER:
		ret = pd690xx_read_port_value(pd, port,
					      PD690XX_PORT_POWER_CONS);
		if (ret < 0)
			return ret;
		poe->port_kobjs[port]->power = (ret & 0xffff) * 100;
		power = ret;

		ret = pd690xx_update_port_status(pd, port);
		if (ret < 0)
			return ret;

		if (poe->port_kobjs[port]->status == PORT_POWER_ON) {
			if (pd->joule_time_set[port]) {
				poe->port_kobjs[port]->millijoules += power * jiffies_to_msecs(
					jiffies - pd->last_joule_time[port]) / 10;
			} else
				pd->joule_time_set[port] = 1;
		}
		pd->last_joule_time[port] = jiffies;
	break;
	case PORT_REG_DENIED:
		ret = pd690xx_read_port_value(pd, port,
					      PD690XX_PORT_POWER_DENIED_CNT);
		if (ret < 0)
			return ret;
		poe->port_kobjs[port]->denied = ret;
	break;
	case PORT_REG_OVERLOAD:
		ret = pd690xx_read_port_value(pd, port,
					      PD690XX_PORT_POWER_OVERLOAD_CNT);
		if (ret < 0)
			return ret;
		poe->port_kobjs[port]->overload = ret;
	break;
	case PORT_REG_UNDERLOAD:
		ret = pd690xx_read_port_value(pd, port,
					      PD690XX_PORT_POWER_UNDERLOAD_CNT);
		if (ret < 0)
			return ret;
		poe->port_kobjs[port]->underload = ret;
	break;
	case PORT_REG_CLASS:
		if (poe->port_kobjs[port]->status != 1)
			break;
		ret = pd690xx_read_port_value(pd, port,
					      PD690XX_PORT_CLASS);
		if (ret < 0)
			return ret;
		poe->port_kobjs[port]->class = (ret & (0xf << 8)) >> 8;
	break;
	}

	return 0;
}

/*
 * pd690xx_do_periodic - Perform periodic functions
 *
 * This routine is called while we are in RUNNING state to perform
 * periodic polling of the device.
 */

static void pd690xx_do_periodic(struct pd690xx *pd)
{
	struct poe_dev *poe = pd->poe;
	int ret;
	int i;

	if (pd->fast_state_detect_port >= 0) {
		for (i = 0; i < PD690XX_FAST_STATE_DETECT_BATCH_SIZE; i++) {
			ret = pd690xx_update_port_status(pd, pd->fast_state_detect_port);
			if (ret < 0)
				return;
			if (++pd->fast_state_detect_port == poe->ports)
				pd->fast_state_detect_port = 0;
		}
	}

	if (pd->work_state == 0) {
		ret = pd690xx_do_periodic_system(pd, pd->work_substate);
		if (ret < 0)
			return;
		if (++pd->work_substate == SYS_REG_CNT)
			pd->work_substate = 0;
	} else if (pd->work_state <= poe->controllers) {
		ret = pd690xx_do_periodic_controller(pd, pd->work_state - 1, pd->work_substate);
		if (ret < 0)
			return;
		if (++pd->work_substate == CTRL_REG_CNT)
			pd->work_substate = 0;
	} else if (pd->work_state <= poe->controllers + poe->ports) {
		ret = pd690xx_do_periodic_port(pd, pd->work_state - poe->controllers - 1, pd->work_substate);
		if (ret < 0)
			return;
		if (++pd->work_substate == PORT_REG_CNT)
			pd->work_substate = 0;
	}

	if (!pd->work_substate)
		++(pd->work_state);
	if (pd->work_state > poe->controllers + poe->ports)
		pd->work_state = 0;

	schedule_delayed_work(&pd->work,
			      msecs_to_jiffies(PD690XX_POLL_INTERVAL));
}

static void pd690xx_parse_config_reg(struct poe_port_kobj *port_kobj, int port_config)
{
	int priority;

	priority = (port_config & PD690XX_PORT_CONFIG_PORT_PRIORITY_MASK)
			>> PD690XX_PORT_CONFIG_PORT_PRIORITY_SHIFT;

	if (priority == 0)
		port_kobj->priority = PORT_PRIORITY_CRITICAL;
	else if (priority == 1)
		port_kobj->priority = PORT_PRIORITY_HIGH;
	else if (priority == 2)
		port_kobj->priority = PORT_PRIORITY_LOW;
	else
		port_kobj->priority = PORT_PRIORITY_UNDEF;
}

static void pd690xx_read_init_config(struct pd690xx *pd)
{
	struct poe_dev *poe = pd->poe;
	struct poe_port_kobj *port_kobj;
	int port_config;
	int controller;
	int port;

	for (controller = 0;
	     controller < poe->controllers;
	     controller++) {
		for (port = 0; port < poe->ports_per_controller; port++) {
			port_config = pd690xx_read_value(pd, controller,
				PD690XX_PORT_CONFIG(port));

			port_kobj = poe->port_kobjs[
				(controller * poe->ports_per_controller) +
				port];
			pd690xx_parse_config_reg(port_kobj, port_config);
		}
	}
}

/*
 * pd690xx_setup_power - Set up initial power values
 */

static void pd690xx_setup_power(struct pd690xx *pd)
{
	struct poe_dev *poe = pd->poe;
	int controller;
	int ret;

	pd690xx_config_mode(pd); /* Enter config mode */

	/* Enable capacitor detect; class[0123]=af */

	for (controller = 0;
	     controller < poe->controllers;
	     controller++) {
		// enable dynamic mode and DC disconnect condition
		pd690xx_write_value(pd, controller, PD690XX_PM_MODE, 0x0c01 | (1<<6));
	}

	pd690xx_write_value(pd, 0, PD690XX_MST_CFG_SYS_POWER_BUDGET(0),
		poe->power_budget / 100);

	ret = pd690xx_read_value(pd, 0, PD690XX_MST_CFG_SYS_POWER_BUDGET(0));
	if (ret < 0)
		return;
	poe->power_budget = (ret & 0xffff) * 100;

	ret = pd690xx_read_value(pd, 0, PD690XX_STARTUP_PRIORITY);
	if (ret < 0)
		return;
	pd690xx_write_value(pd, 0, PD690XX_STARTUP_PRIORITY, ret | (1<<6));

	pd690xx_read_init_config(pd);
	pd690xx_auto_mode(pd);

	if (pd->state != PD690XX_STATE_RESET_PENDING) {
		pd->state = PD690XX_STATE_RUNNING;
		pd690xx_do_periodic(pd);
	}
}

/*
 * pd6900x_init_device - Handle initialization state
 */

static void pd690xx_init_device(struct pd690xx *pd)
{
	int ret;
	int controller;
	struct poe_dev *poe = pd->poe;
	struct i2c_client *client = pd->client;

	for (controller = 0;
	     controller < poe->controllers;
	     controller++) {
		ret = pd690xx_read_value(pd, controller, PD690XX_BOOT_STATE);
		if (ret < 0) {
			return;	/* Errors go into RESET_PENDING */
		}

		if ((ret & 0xff) == 0x9) {
			dev_info(&client->dev, "Controller %d boot finished\n",
				 controller);
			continue;
		} else {
			dev_info(&client->dev, "Controller %d "
				 "waiting for boot to finish, state %02x\n",
				 controller, ret & 0xff);
		}
	}

	if (controller < poe->controllers) {
		if (--pd->init_retries < 0) {
			dev_err(&client->dev, "Gave up waiting for init");
			pd690xx_reset(pd);
			return;
		}
		schedule_delayed_work(&pd->work,
				      msecs_to_jiffies(PD690XX_INIT_DELAY));
		return;
	}
	pd690xx_setup_power(pd);

	/* Put 0x1234 in the General User register so we can detect resets */
	ret = pd690xx_write_value(pd, 0, PD690XX_GENERAL_USER, 0x1234);
	if (ret < 0)
		return; /* Errors go into RESET_PENDING */
}


/*
 * pd690xx_do_work - Do the work of this driver
 *
 * This is the work queue handler for the driver. Most everything
 * that we do is done here.
 */

static void pd690xx_do_work(struct work_struct *work)
{
	struct pd690xx *pd =
		container_of(to_delayed_work(work), struct pd690xx, work);

	mutex_lock(&pd->lock);

	switch (pd->state) {

	case PD690XX_STATE_RESET_PENDING:
		pd->state = PD690XX_STATE_RESET;
		/* Fall through */
	case PD690XX_STATE_RESET:

		/* Enable ports, take out of reset */
		gpio_set_value_cansleep(pd->disable_ports, pd->logic_low);
		gpio_set_value_cansleep(pd->reset, !pd->logic_low);

		pd->init_retries = PD690XX_RESET_RETRIES;
		pd->state = PD690XX_STATE_INITIALIZING;
		schedule_delayed_work(&pd->work,
				      msecs_to_jiffies(PD690XX_RESET_DELAY));
		break;

	case PD690XX_STATE_INITIALIZING:

		pd690xx_init_device(pd);
		break;

	case PD690XX_STATE_RUNNING:

		pd690xx_do_periodic(pd);
		break;

	case PD690XX_STATE_PROBE:

		return;		/* Should not happen */
	}
	mutex_unlock(&pd->lock);
}

/*
 * pd690xx_set_enable - Set the enabled bit for a port
 *
 * This routine is used to set the enable for a port
 */

static int
pd690xx_set_enable(struct poe_port_kobj *port_kobj, bool enable)
{
	struct poe_dev *poe;
	int port_num = port_kobj->port_num;
	int controller;
	int enable_bit;
	int disable_map;
	int ret;
	struct pd690xx *pd;

	poe = kobj_to_poe_dev(port_kobj->kobj.parent);
	pd = dev_get_drvdata(&poe->dev);
	controller = port_num / poe->ports_per_controller;
	enable_bit = 1 << (port_num % poe->ports_per_controller);

        disable_map = pd690xx_read_value(pd, controller, PD690XX_DIS_PORTS_CMD);
	if (disable_map < 0)
		return -EIO;

	disable_map = (disable_map & ~enable_bit) | (enable ? 0 : enable_bit);

	ret = pd690xx_write_value(pd, controller, PD690XX_DIS_PORTS_CMD,
				  disable_map);
	if (ret < 0)
		return -EIO;

	port_kobj->enabled = enable; /* Remember setting */

	return 0;
}

/*
 * pd690xx_set_priority - Set the priority of a port
 *
 * This routine is used to set the priority of a port
 */

static int
pd690xx_set_priority(struct poe_port_kobj *port_kobj, int priority)
{
	struct poe_dev *poe;
	int port_num = port_kobj->port_num;
	int controller;
	unsigned port_config;
	int ret;
	int reg_prio;
	struct pd690xx *pd;
	int real_port_num;

	poe = kobj_to_poe_dev(port_kobj->kobj.parent);
	pd = dev_get_drvdata(&poe->dev);
	real_port_num = port_num % poe->ports_per_controller;
	controller = port_num / poe->ports_per_controller;

        port_config = pd690xx_read_value(pd, controller,
		PD690XX_PORT_CONFIG(real_port_num));
	if (port_config < 0)
		return -EIO;

	if (priority == PORT_PRIORITY_CRITICAL)
		reg_prio = 0;
	else if (priority == PORT_PRIORITY_HIGH)
		reg_prio = 1;
	else if (priority == PORT_PRIORITY_LOW)
		reg_prio = 2;
	else
		return -EINVAL;

	if ((port_config & PD690XX_PORT_CONFIG_PORT_PRIORITY_MASK) ==
		reg_prio << PD690XX_PORT_CONFIG_PORT_PRIORITY_SHIFT)
		return 0;

	port_config &= ~PD690XX_PORT_CONFIG_PORT_PRIORITY_MASK;
	port_config |= reg_prio << PD690XX_PORT_CONFIG_PORT_PRIORITY_SHIFT;

	ret = pd690xx_write_value(pd, controller, PD690XX_PORT_CONFIG(real_port_num),
				  port_config);
	if (ret < 0)
		return -EIO;

	port_kobj->priority = priority; /* Remember setting */

	return 0;
}

/*
 * pd690xx_read_raw_reg - Read a raw register
 */

static int
pd690xx_read_raw_reg(struct poe_controller_kobj *controller)
{
	struct poe_dev *poe = controller->poe_dev;
	int controller_idx = 0;
	while (controller_idx < poe->controllers) {
		if (controller == poe->controller_kobjs[controller_idx])
			break;
		++controller_idx;
	}
	if (controller_idx >= poe->controllers)
		return -1;
	return pd690xx_read_value(dev_get_drvdata(&poe->dev), controller_idx, controller->raw_addr);
}

/*
 * pd690xx_write_raw_reg - Write a raw register
 */

static int
pd690xx_write_raw_reg(struct poe_controller_kobj *controller, u16 val)
{
	struct poe_dev *poe = controller->poe_dev;
	int ret, controller_idx = 0;
	while (controller_idx < poe->controllers) {
		if (controller == poe->controller_kobjs[controller_idx])
			break;
		++controller_idx;
	}
	if (controller_idx >= poe->controllers)
		return -1;
	ret = pd690xx_write_value(dev_get_drvdata(&poe->dev), controller_idx, controller->raw_addr, val);
	return ret < 0 ? ret : 0;
}

/*
 * pd690xx_set_power_budget - Set the power budget for the entire system
 *
 * This routine is used to notify the driver that more or less power
 * is available.
 */

static int
pd690xx_set_power_budget(struct poe_dev *poe, unsigned int power_mw)
{
	int ret;
	struct pd690xx *pd = dev_get_drvdata(&poe->dev);

	mutex_lock(&pd->lock);
	pd690xx_config_mode(pd);

	ret = pd690xx_write_value(pd, 0, PD690XX_MST_CFG_SYS_POWER_BUDGET(0),
		power_mw / 100);
	if (ret < 0)
		goto fail;

	/* Because the PoE chip can do rounding of the written value,
	   read it back. */
	ret = pd690xx_read_value(pd, 0, PD690XX_MST_CFG_SYS_POWER_BUDGET(0));
	if (ret < 0)
		goto fail;

	poe->power_budget = (ret & 0xffff) * 100;
	if (poe->power_budget != power_mw)
		dev_err(&pd->poe->dev, "Power budget setting was unexpectedly rounded from %u to %u\n", power_mw, poe->power_budget);
fail:
	pd690xx_auto_mode(pd);
	mutex_unlock(&pd->lock);
	return ret;
}

/*
 * Called when a pd690xx device is matched with this driver
 */

static int pd690xx_probe(struct i2c_client *client,
                         const struct i2c_device_id *id)
{
	int ret;
	struct pd690xx *pd;
	struct pd690xx_platform_data *pdata = client->dev.platform_data;
	struct poe_dev *poe;
	int controller;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "i2c bus does not support the pd690xx\n");
		return -ENODEV;
	}

	if (pdata->controllers == 0 || (pdata->ports % pdata->controllers != 0))
		return -EINVAL;

	pd = kzalloc(sizeof(struct pd690xx), GFP_KERNEL);
	if (!pd)
		return -ENOMEM;
	poe = poe_allocate_device();
	if (!poe) {
		ret = -ENOMEM;
		goto error_free_pd;
	}


	ret = gpio_request(pdata->reset, "PD690xx reset");
	if (ret < 0) {
		dev_err(&client->dev,
			"unable to allocate GPIO%d for PD690xx reset\n",
			pdata->reset);
		goto error_free_poe;
	}

	ret = gpio_request(pdata->disable_ports, "PD690xx ports disable");
	if (ret < 0) {
		dev_err(&client->dev,
			"unable to allocate GPIO%d for PD690xx port disable\n",
			pdata->disable_ports);
		goto error_reset;
	}

	pd->client = client;
	pd->disable_ports = pdata->disable_ports;
	pd->reset = pdata->reset;
	pd->logic_low = pdata->logic_low;
	pd->slave_addr = pdata->slave_addr;
	pd->state = PD690XX_STATE_PROBE;
	pd->fast_state_detect_port = (pdata->fast_state_detect ? 0 : -1);
	mutex_init(&pd->lock);
	INIT_DELAYED_WORK(&pd->work, pd690xx_do_work);
	i2c_set_clientdata(client, pd);
	dev_set_drvdata(&poe->dev, pd);

	/* Assert reset and disable, wait 10ms, and deassert reset */
	gpio_direction_output(pd->reset, pd->logic_low);
	gpio_direction_output(pd->disable_ports, !pd->logic_low);
	mdelay(10);
	gpio_set_value_cansleep(pd->reset, !pd->logic_low);

	for (controller = 0;
	     controller < pdata->controllers;
	     controller++) {
		ret = pd690xx_read_value(pd, controller, PD690XX_CFGC_ICVER);
		/* If the read failed, try once more in case i2c still had junk on the line. */
		if (ret != 0x3b22)
			ret = pd690xx_read_value(pd, controller, PD690XX_CFGC_ICVER);
		if (ret != 0x3b22) {
			ret = -ENODEV;
			goto error_disable;
		}
		ret = pd690xx_write_value(pd, controller,
					  PD690XX_DIS_PORTS_CMD, 0x3ff);
		if (ret < 0)
			goto error_disable;
	}
	dev_info(&client->dev, "device found");

	poe->name = client->name;	/* Let driver know our name */
	poe->controllers = pdata->controllers; /* Save number of controllers */
	poe->power_budget = pdata->power_budget;
	poe->ports_per_controller = pdata->ports / pdata->controllers;
	poe->ports = pdata->ports;	/* Save number of ports */
	poe->port_base = pdata->port_base; /* And port base */
	poe->dev.parent = &client->dev; /* And our parent driver */
	poe->port_enable = pd690xx_set_enable; /* Enable/disable handler */
	poe->read_raw_reg = pd690xx_read_raw_reg;
	poe->write_raw_reg = pd690xx_write_raw_reg;
	poe->set_priority = pd690xx_set_priority; /* PoE priority handler */
	poe->set_power_budget = pd690xx_set_power_budget; /* PoE total budget handler */
#ifdef CONFIG_THERMAL
	poe->therm_domain = pdata->therm_domain; /* Set thermal domain */
	poe->temp_warm = pdata->temp_warm; /* Set cooling point */
#endif /* CONFIG_THERMAL */
	pd->poe = poe;			/* Save pointer to PoE device */
	ret = poe_register_device(poe);	/* Now register it */
	if (ret)
		goto error_disable;
	pd->state = PD690XX_STATE_RESET; /* We are in reset state */
	pd690xx_do_work(&pd->work.work); /* Start the state machine */

	return 0;

error_disable:
	gpio_free(pdata->disable_ports);

error_reset:
	gpio_free(pdata->reset);

error_free_poe:
	poe_free_device(poe);
error_free_pd:
	kfree(pd);
	return ret;
}

static int pd690xx_remove(struct i2c_client *client)
{
	struct pd690xx *pd = i2c_get_clientdata(client);

	cancel_delayed_work(&pd->work); /* Ensure no work is pending */
	gpio_set_value_cansleep(pd->reset, pd->logic_low);  /* Put the device in reset */
	gpio_free(pd->disable_ports);  /* Free the GPIO */
	gpio_free(pd->reset);	       /* ... */
	poe_unregister_device(pd->poe); /* Unregister the PoE device */
	kfree(pd);

	return 0;
}

static const struct i2c_device_id pd690xx_id[] = {
	{ "pd690xx", 0 },
	{ }
};

static struct i2c_driver pd690xx_driver = {
	.driver = {
		.name = "pd690xx",
	},
	.probe = pd690xx_probe,
	.remove = pd690xx_remove,
	.id_table = pd690xx_id,
};

static int __init pd690xx_init(void)
{
	return i2c_add_driver(&pd690xx_driver);
}

static void __exit pd690xx_exit(void)
{
	i2c_del_driver(&pd690xx_driver);
}


MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.net>");
MODULE_DESCRIPTION("PD680xx auto-mode PoE driver");
MODULE_LICENSE("GPL");

module_init(pd690xx_init);
module_exit(pd690xx_exit);
