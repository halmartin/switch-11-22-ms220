#ifndef _POE_H
#define _POE_H

/*
 *
 * poe.h - Definitions for the Power over Ethernet (802.3af/802.3at) subsystem
 *
 * Copyright (c) 2011 Meraki, Inc.
 * Copyright (c) 2015 Cisco Systems, Inc.
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
 */

#include <linux/time.h>
#include <linux/list.h>
#include <linux/leds.h>

#ifdef CONFIG_THERMAL
#include <linux/thermal.h>
#endif /* CONFIG_THERMAL */

/*
 * Note the constants below are exported via the sysfs interface
 * and are thus part of the user interface contract. Please do
 * not change them, but feel free to add new codes to the end.
 */

enum DEVICE_STATUS {
	DEVICE_STATUS_NORMAL,
	DEVICE_STATUS_NEGATIVE_CURRENT_ERROR,
};

struct poe_dev {
	const char *name;
	struct device dev;
	struct list_head node;
	int controllers;	/* Number of controllers in complex */
	int ports_per_controller; /* Ports per controller */
	struct poe_controller_kobj **controller_kobjs; /* Controller array */
	int ports;		/* Number of ports controlled */
	int port_base;		/* Base port number */
	struct poe_port_kobj **port_kobjs; /* Array of port kobjs */
	int total_power;	/* Total system power consumption */
	int power_budget;
	int (*port_enable)(struct poe_port_kobj *, bool); /* Port enable */
	int (*port_stats)(struct poe_port_kobj *, ssize_t, char *); /* Port statistics */
        /* Controller statistics */
	int (*controller_stats)(struct poe_controller_kobj *, ssize_t, char *);
	int (*set_priority)(struct poe_port_kobj *, int); /* Port priority */
	int (*set_power_budget)(struct poe_dev *, unsigned int); /* System power budget */
	int (*read_raw_reg)(struct poe_controller_kobj *);
	int (*write_raw_reg)(struct poe_controller_kobj *, u16);
#ifdef CONFIG_THERMAL
	char *therm_domain;	/* Name of thermal domain */
	int temp_warm;		/* When do we want cooling */
#endif /* CONFIG_THERMAL */
	enum DEVICE_STATUS status;
        struct kobject *sysports_kobj;
};

#define device_to_poe_dev(d) container_of(d, struct poe_dev, dev);
#define kobj_to_poe_dev(d) device_to_poe_dev(container_of(d, struct device, kobj))
struct poe_dev *poe_allocate_device(void);
void poe_free_device(struct poe_dev *dev);

static inline void poe_put_device(struct poe_dev *dev)
{
	if (dev)
		put_device(&dev->dev);
}

int __must_check poe_register_device(struct poe_dev *);
void poe_unregister_device(struct poe_dev *);

struct poe_controller_kobj {
	struct completion kobj_unregister;
	struct kobject kobj;
	struct poe_dev *poe_dev;
	int power_master;	/* Power, as read by master, in mW */
	int power_slave;	/* Power, as read by slave, in mW */
	int power_limit;	/* Power, as read by slave, in mW */
	int temp;		/* Temperature of device, in C */
	int vmain;		/* vMain of device, in mV */
	u16 raw_addr;		/* Address used for raw read and write */
#ifdef CONFIG_THERMAL
	struct thermal_zone_device *tdev; /* Pointer to thermal device */
#endif
};

#define kobj_to_controller_obj(d) container_of(d, struct poe_controller_kobj, kobj);

int poe_register_controllers(struct poe_dev *);
void poe_free_controllers(struct poe_dev *);

/*
 * Note the constants below are exported via the sysfs interface
 * and are thus part of the user interface contract. Please do
 * not change them, but feel free to add new codes to the end.
 */

enum PORT_POWER_STATE {
	PORT_POWER_OFF,			/* Port is off */
	PORT_POWER_ON,			/* Port is on */
	PORT_POWER_STARTING,		/* Port is starting up */
	PORT_POWER_ERROR,		/* Port has an error */
	PORT_POWER_TEST,		/* Port is in test mode */
};

enum PORT_POWER_OFF {
	PORT_OFF_STARTUP,		/* Port is off - system is starting */
	PORT_OFF_SYSTEM_ERROR,		/* Port is off - system error */
	PORT_OFF_DISABLED,		/* Port is off - disabled */
	PORT_OFF_PM,			/* Port is off - power management */
};

enum PORT_POWER_ON {
	PORT_ON_VALID_SIGNATURE,	/* Port is on due to signature */
	PORT_ON_FORCED,			/* Port is forced on */
};

enum PORT_POWER_STARTING {
	PORT_STARTING_INIT,		/* Initial startup phase */
	PORT_STARTING_FORCED,		/* Powered due to force power */
	PORT_STARTING_SEARCHING,	/* Waiting/in detection phase */
	PORT_STARTING_DETECTED,		/* Valid signature detected */
};

enum PORT_POWER_ERROR {
	PORT_ERROR_UNKNOWN,	        /* Unknown error reason */
	PORT_ERROR_CHIP,		/* Chip level error */
	PORT_ERROR_DRIVER,		/* Device driver detected error */
	PORT_ERROR_SIGNATURE,		/* Invalid signature */
	PORT_ERROR_CLASS,		/* Error determining class */
	PORT_ERROR_STARTUP_OVERLOAD,	/* Overload during startup */
	PORT_ERROR_STARTUP_UNDERLOAD,	/* Underload during startup */
	PORT_ERROR_STARTUP_SHORT,	/* Short during startup */
	PORT_ERROR_DV_DT,		/* Error in Dv/Dt algorithm */
	PORT_ERROR_OVERLOAD,		/* Overload during operation */
	PORT_ERROR_UNDERLOAD,		/* Underload during operation */
	PORT_ERROR_SHORT,		/* Short during operation */
};

enum PORT_PORT_TEST {
	PORT_TEST_WAITING,		/* Waiting to be turned on */
	PORT_TEST_ERROR,		/* Error in test mode */
};

enum PORT_PRIORITY {
	PORT_PRIORITY_CRITICAL,
	PORT_PRIORITY_HIGH,
	PORT_PRIORITY_LOW,
	PORT_PRIORITY_UNDEF,
};

enum PORT_MODE {
	PORT_MODE_AF,
	PORT_MODE_AT,
	PORT_MODE_UNDEF,
};

#define POE_PORT_NAME_LEN 10		/* Pathological: max 99999 ports */
#define POE_LED_TRIGGER_NAME_LEN 15

struct poe_port_kobj {
	struct completion kobj_unregister;
	struct kobject kobj;
	char port_name_system[POE_PORT_NAME_LEN]; /* System unique port name */
	char port_name_controller[POE_PORT_NAME_LEN]; /* Per controller name */
	int port_num;			/* Port number in complex */
	int power;			/* Power used by port, in mW */
	int limit;			/* Power limit for port, in mW */
	int priority;
	int mode;                       /* AT or AF mode */
	unsigned int denied;
	unsigned int overload;
	unsigned int underload;
	unsigned int mps_absent;
	unsigned int short_counter;
	unsigned int invalid_sig_counter;
	int class;
	unsigned long long millijoules;
	enum PORT_POWER_STATE status;	/* Current power state */
	int substatus;			/* Substatus */
	bool enabled;		       /* Is port enabled? */
	char led_trig_name[POE_LED_TRIGGER_NAME_LEN];
	struct led_trigger* led_trig;
};

#define kobj_to_port_obj(d) container_of(d, struct poe_port_kobj, kobj);

int poe_register_ports(struct poe_dev *);
void poe_free_ports(struct poe_dev *);
void poe_port_notify_state_change(struct kobject*);

#endif /* _POE_H */
