/*
 *  Thermal driver for Vitesse VCore-III Jaguar temperature sensor
 *
 *  Copyright (C) 2012 Kevin Paul Herbert <kph.meraki.net>
 *  Adapted from the bcm47xx_wdt.c driver by Aleksandar Radovanovic/Matthieu CASTET
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/thermal.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define SUPPORT_VTSS_VCOREIII_JAGUAR

#include <asm/mach-vcoreiii/hardware.h>

#define TEMP_TO_MILLICELSIUS(adc) \
	((13530 - (71 *(adc &						\
	 VTSS_M_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_DATA_TEMP_SENSOR_DATA))) * \
	 10)
#define TEMP_VALID(adc) \
	(adc & \
	 VTSS_F_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_DATA_TEMP_SENSOR_DATA_VALID)

#define VCOREIII_THERMAL_TEMP_WARM (80)

#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
#define TEMP_SENSORS 2
#else
#define TEMP_SENSORS 1
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

struct vcoreiii_tdev {
	volatile void __iomem *sensor_addr;
	struct thermal_zone_device *tdev;
	struct proc_dir_entry *procdir;
	int temp_warm;
};

static struct vcoreiii_tdev vcoreiii_tdevs[TEMP_SENSORS];

static struct proc_dir_entry *vcoreiii_thermal_dir;

static int
vcoreiii_thermal_bind(struct thermal_zone_device *tdev,
		    struct thermal_cooling_device *cdev)
{
	return thermal_zone_bind_cooling_device(tdev, 0, cdev,
						THERMAL_NO_LIMIT,
						THERMAL_NO_LIMIT);
}

static int
vcoreiii_thermal_unbind(struct thermal_zone_device *tdev,
		      struct thermal_cooling_device *cdev)
{
	return thermal_zone_unbind_cooling_device(tdev, 0, cdev);
}

static int
vcoreiii_thermal_get_temp(struct thermal_zone_device *tdev,
			unsigned long *temp)
{
	struct vcoreiii_tdev *vctdev = tdev->devdata;
	uint32_t reg;

	reg = readl(vctdev->sensor_addr);
	if (TEMP_VALID(reg)) {
		*temp = TEMP_TO_MILLICELSIUS(reg);
		return 0;
	}
	return -ENODATA;		/* Sensor not ready yet */
}

static int
vcoreiii_thermal_get_trip_type(struct thermal_zone_device *tdev, int which,
			     enum thermal_trip_type *type)
{
	*type = THERMAL_TRIP_ACTIVE; /* All we do right now */
	return 0;
}

static int
vcoreiii_thermal_get_trip_temp(struct thermal_zone_device *tdev, int which,
			     unsigned long *temp)
{
	struct vcoreiii_tdev *vctdev = tdev->devdata;

	*temp = vctdev->temp_warm * 1000;

	return 0;
}


static struct thermal_zone_device_ops vcoreiii_thermal_zone_ops = {
	.bind = vcoreiii_thermal_bind,
	.unbind = vcoreiii_thermal_unbind,
	.get_temp = vcoreiii_thermal_get_temp,
	.get_trip_type = vcoreiii_thermal_get_trip_type,
	.get_trip_temp = vcoreiii_thermal_get_trip_temp,
};

static int vcoreiii_thermal_temp_threshold_show(struct seq_file *m, void *v)
{
	struct vcoreiii_tdev *vctdev = m->private;

	seq_printf(m, "%d\n", vctdev->temp_warm);

	return 0;
}

static ssize_t
vcoreiii_thermal_temp_threshold_set(const char *buffer, size_t len,
				    struct vcoreiii_tdev *vctdev)
{
	size_t write_size = len;
	char temp_str[6];
	int temp;

	if (len >= sizeof(temp_str)) {
		write_size = sizeof(temp_str) - 1;
	}

	if (copy_from_user(temp_str, buffer, write_size)) {
		return -EFAULT;
	}

	temp_str[write_size] = 0;
	temp = simple_strtoul(temp_str, NULL, 10);

	if (!temp)
		return -EINVAL;

	vctdev->temp_warm = temp;

	return write_size;
}


static int
vcoreiii_thermal_proc_generic_open(struct inode *inode, struct file *file)
{
	struct vcoreiii_tdev *vctdev = (struct vcoreiii_tdev *)
		(PDE_DATA(inode));

	return single_open(file, vcoreiii_thermal_temp_threshold_show, vctdev);
}

static ssize_t
vcoreiii_thermal_proc_write(struct file *file, const char *buffer,
			    size_t len, loff_t *off)
{
	struct vcoreiii_tdev *vctdev = (struct vcoreiii_tdev *)
		(PDE_DATA(file->f_dentry->d_inode));


	return vcoreiii_thermal_temp_threshold_set(buffer, len, vctdev);
}

static const struct file_operations vcoreiii_thermal_proc_ops = {
	.owner = THIS_MODULE,
	.open = vcoreiii_thermal_proc_generic_open,
	.read = seq_read,
	.write = vcoreiii_thermal_proc_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init vcoreiii_thermal_register(int which, char *name,
					    volatile void __iomem *ctrl_reg,
					    volatile void __iomem *data_reg)
{
	struct thermal_zone_device *tdev;
	int timeout = 10;

	writel(VTSS_F_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_CTRL_TEMP_SENSOR_RESET_N, ctrl_reg);

	while (--timeout) {
		if (TEMP_VALID(readl(data_reg)))
			break;
		mdelay(10);
	}

	if (timeout == 0) {
		printk(KERN_ERR "VCore-III temp sensor %s timeout\n",
		       name);
		return -ENODEV;
	}

	vcoreiii_tdevs[which].sensor_addr = data_reg;
	vcoreiii_tdevs[which].temp_warm = VCOREIII_THERMAL_TEMP_WARM;

	tdev = thermal_zone_device_register(name, 1, 0, &vcoreiii_tdevs[which],
					    &vcoreiii_thermal_zone_ops, NULL,
					    0, 10000);
	if (IS_ERR(tdev)) {
		printk(KERN_ERR "Error %d registering VCore-III temp sensor "
		       "%s\n", (int)tdev, name);
		return (int)tdev;
	}
	vcoreiii_tdevs[which].tdev = tdev;

	if (vcoreiii_thermal_dir) {
		vcoreiii_tdevs[which].procdir =
			proc_mkdir(name, vcoreiii_thermal_dir);
		if (!vcoreiii_tdevs[which].procdir) {
			printk(KERN_WARNING
			       "Unable to create /proc/vcoreiii_thermal/%s\n",
			       name);
		} else {
			if (!proc_create_data("temp_warm",
					      S_IFREG | S_IRUGO | S_IWUSR,
					      vcoreiii_tdevs[which].procdir,
					      &vcoreiii_thermal_proc_ops,
					      &vcoreiii_tdevs[which])){
				printk(KERN_WARNING
				       "Unable to create "
				       "/proc/vcoreiii_thermal/%s/%s\n",
				       name, "temp_warm");
			}
		}
	}
	return 0;
}

static int __init vcoreiii_thermal_init(void)
{
	int ret1;
	int ret2 = -ENODEV;

	if (!vcoreiii_check_chip_id())
		return -ENODEV;

	vcoreiii_thermal_dir = proc_mkdir("vcoreiii_thermal", NULL);
	if (!vcoreiii_thermal_dir) {
		printk(KERN_WARNING
		       "Unable to create /proc/vcoreiii_thermal\n");
	}

	ret1 = vcoreiii_thermal_register
		(0, "switch-primary",
		 VTSS_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_CTRL,
		 VTSS_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_DATA);
#ifdef CONFIG_VTSS_VCOREIII_JAGUAR_DUAL
	if (map_base_slv_switch) {
		ret2 = vcoreiii_thermal_register
			(1, "switch-secondary",
			 master2slave_addr
			 (VTSS_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_CTRL),
			 master2slave_addr
			 (VTSS_DEVCPU_GCB_TEMP_SENSOR_TEMP_SENSOR_DATA));
	}
#endif /* CONFIG_VTSS_VCOREIII_JAGUAR_DUAL */

	if ((ret1 == 0) || (ret2 == 0))
		return 0;

	return ((ret1 != 0) ? ret1 : ret2);
}

static void __exit vcoreiii_thermal_exit(void)
{
	int i;

	if (vcoreiii_thermal_dir) {
		proc_remove(vcoreiii_thermal_dir);
		vcoreiii_thermal_dir = NULL;
	}
	for (i = 0; i < TEMP_SENSORS; i++) {
		if (vcoreiii_tdevs[i].tdev) {
			thermal_zone_device_unregister(vcoreiii_tdevs[i].tdev);
			vcoreiii_tdevs[i].tdev = NULL;
		}
	}
}

module_init(vcoreiii_thermal_init);
module_exit(vcoreiii_thermal_exit);

MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.net>");
MODULE_DESCRIPTION("VCore-III Jaguar thermal driver");
MODULE_LICENSE("GPL");
