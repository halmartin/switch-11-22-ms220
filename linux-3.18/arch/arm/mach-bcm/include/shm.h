/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Header for declaring shim layer exports.
 */

#ifndef __SHM_DOT_H_INCLUDED__
#define __SHM_DOT_H_INCLUDED__

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>


#define iproc_class_create(owner, name)		\
({						\
	static struct lock_class_key __key;	\
	iproc__class_create(owner, name, &__key);	\
})

extern int iproc_platform_get_irq(struct platform_device *dev, unsigned int num);
extern struct resource *
iproc_platform_get_resource_byname(struct platform_device *dev, unsigned int type, const char *name);
extern struct resource *
iproc_platform_get_resource(struct platform_device *dev, unsigned int type,
		      unsigned int num);
extern int iproc_platform_device_add_resources(struct platform_device *pdev, const struct resource *res, unsigned int num);

extern int iproc_platform_device_register(struct platform_device * pdev);
extern void iproc_platform_device_unregister(struct platform_device * pdev);
extern int iproc_platform_driver_register(struct platform_driver *drv);
extern void iproc_platform_driver_unregister(struct platform_driver *drv);

extern struct platform_device *iproc_platform_device_alloc(const char *name, int id);

extern int iproc_platform_device_add(struct platform_device *pdev);
extern void iproc_platform_device_put(struct platform_device *pdev);

extern void iproc_platform_device_put(struct platform_device *pdev);
extern int iproc_platform_device_add(struct platform_device *pdev);
extern void iproc_platform_device_del(struct platform_device *pdev);
extern int iproc_sysfs_create_group(struct kobject *kobj, const struct attribute_group *grp);
extern void iproc_sysfs_remove_group(struct kobject *kobj, const struct attribute_group *grp);


extern struct class *iproc__class_create(struct module *owner, const char *name,
	struct lock_class_key *key);
extern void iproc_class_destroy(struct class *cls);
extern int iproc_device_create_file(struct device *dev,
	const struct device_attribute *attr);
extern struct device *iproc_device_create(struct class *class, 
	struct device *parent, dev_t devt, void *drvdata, const char *fmt, ...);
extern void iproc_device_destroy(struct class *class, dev_t devt);
extern void iproc_device_remove_file(struct device *dev,
	const struct device_attribute *attr);
extern int iproc_platform_get_irq_byname(struct platform_device *, const char *);

extern int iproc_gpio_to_irq(unsigned gpio);
#endif /*#ifndef __SHM_DOT_H_INCLUDED__*/
