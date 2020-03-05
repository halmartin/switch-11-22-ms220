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

#include "shm.h"
/**
 * iproc_platform_get_irq - get an IRQ for a device
 *           wrapper function for platform_get_irq
 * @dev: platform device
 * @num: IRQ number index
 */
int iproc_platform_get_irq(struct platform_device *dev, unsigned int num)
{
	return platform_get_irq(dev, num);
}
EXPORT_SYMBOL(iproc_platform_get_irq);


/**
 *	iproc_platform_get_resource_byname -
 *           wrapper function for platform_get_resource_byname
 * @dev: platform device
 * @type: resource type
 * @name: resource name
 */
struct resource *
iproc_platform_get_resource_byname(struct platform_device *dev,
					      unsigned int type,
					      const char *name)
{
	return platform_get_resource_byname(dev, type, name);
}
EXPORT_SYMBOL(iproc_platform_get_resource_byname);


/**
 *	iproc_platform_get_resource -
 *           wrapper function for platform_get_resource
 *	@dev: platform device
 *	@type: resource type
 *	@num: resource index
 */
struct resource *
iproc_platform_get_resource(struct platform_device *dev, unsigned int type,
		      unsigned int num)
{
	return platform_get_resource(dev, type, num);
}
EXPORT_SYMBOL(iproc_platform_get_resource);


/**
 *	iproc_platform_driver_register -
 *           wrapper function for platform_driver_register
 *	@drv: platform driver structure
 */
int iproc_platform_driver_register(struct platform_driver *drv)
{
	return platform_driver_register(drv);
}
EXPORT_SYMBOL(iproc_platform_driver_register);


/**
 *	iproc_platform_driver_unregister
 *           wrapper function for platform_driver_unregister
 *	@drv: platform driver structure
 */
void iproc_platform_driver_unregister(struct platform_driver *drv)
{
	return platform_driver_unregister(drv);
}
EXPORT_SYMBOL(iproc_platform_driver_unregister);


/**
 *      iproc_platform_device_register - add a platform-level device
 *          wrapper function for platform_device_register
 *      @pdev:  platform device we're adding
 *
 */
int iproc_platform_device_register(struct platform_device * pdev)
{
        return platform_device_register(pdev);
}
EXPORT_SYMBOL(iproc_platform_device_register);


/**
 *	iproc_platform_device_unregister -
 *          wrapper function for platform_device_unregister
 *	@pdev:	platform device we're unregistering
 */
void iproc_platform_device_unregister(struct platform_device * pdev)
{
	return platform_device_unregister(pdev);
}
EXPORT_SYMBOL(iproc_platform_device_unregister);


/**
 *	iproc_platform_device_alloc -
 *          wrapper function for platform_device_alloc
 *    @name: base name of the device we're adding
 *    @id: instance id
 */
struct platform_device *iproc_platform_device_alloc(const char *name, int id)
{
	return platform_device_alloc(name, id);
}
EXPORT_SYMBOL(iproc_platform_device_alloc);

/**
 *	iproc_platform_device_add -
 *			wrapper function for platform_device_add
 *	@pdev:	platform device we're adding
 */
int iproc_platform_device_add(struct platform_device *pdev)
{
	return platform_device_add(pdev);
}
EXPORT_SYMBOL(iproc_platform_device_add);

/**
 *	iproc_platform_device_del -
 *			wrapper function for platform_device_del
 *     @pdev: platform device we're removing
 */
void iproc_platform_device_del(struct platform_device *pdev)
{
	platform_device_del(pdev);
}
EXPORT_SYMBOL(iproc_platform_device_del);


/**
 *	iproc_platform_device_put -
 *			wrapper function for platform_device_put
 *	@pdev:	platform device to free
 */
void iproc_platform_device_put(struct platform_device *pdev)
{
	platform_device_put(pdev);
}
EXPORT_SYMBOL(iproc_platform_device_put);


/**
 *	iproc_platform_device_add_resources -
 *			wrapper function for platform_device_add_resources
 *    @pdev: platform device allocated by platform_device_alloc to add resources to
 *    @res: set of resources that needs to be allocated for the device
 *    @num: number of resources
 */
int iproc_platform_device_add_resources(struct platform_device *pdev,
				  const struct resource *res, unsigned int num)
{
	return platform_device_add_resources(pdev, res, num);
}
EXPORT_SYMBOL(iproc_platform_device_add_resources);


/**
 *	iproc_platform_device_put -
 *			wrapper function for sysfs_create_group
 *    @kobj:	The kobject to create the group on
 *    @grp:	The attribute group to create
 */
int iproc_sysfs_create_group(struct kobject *kobj, const struct attribute_group *grp)
{
	return sysfs_create_group(kobj, grp);
}
EXPORT_SYMBOL(iproc_sysfs_create_group);


/**
 *	iproc_sysfs_remove_group -
 *			wrapper function for sysfs_remove_group
 *    @kobj:	The kobject which the group is on
 *    @grp:	The attribute group to remove
 */
void iproc_sysfs_remove_group(struct kobject * kobj, const struct attribute_group * grp)
{
	sysfs_remove_group(kobj, grp);
}
EXPORT_SYMBOL(iproc_sysfs_remove_group);

/**
 * iproc__class_create - 
 *          wrapper function for __class_create
 *    @ower: pointer to the module that is to "own" this struct class
 *    @name: pointer to a string for the name of this class.
 *    @key: the lock_class_key for this class; used by mutex lock debugging
 */
struct class *iproc__class_create(struct module *owner, const char *name,
	struct lock_class_key *key)
{
	return __class_create(owner, name, key); 
}
EXPORT_SYMBOL(iproc__class_create);

/**
 * iproc_class_destroy - 
 *          wrapper function for class_destroy 
 *    @cls: pointer to the struct class that is to be destroyed
 */
void iproc_class_destroy(struct class *cls)
{
	class_destroy(cls);
}
EXPORT_SYMBOL(iproc_class_destroy);

/**
 * iproc_device_create_file -
 *          wrapper function for device_create_file
 *    @dev: device.
 *    @attr: device attribute descriptor.  
 */
int iproc_device_create_file(struct device *dev,
	const struct device_attribute *attr)
{
	return device_create_file(dev, attr);
}
EXPORT_SYMBOL(iproc_device_create_file);

/**
 * iproc_device_create -
 *          wrapper function for device_create
 *
 *    @class: pointer to the struct class that this device should be 
 *            registered to
 *    @parent: pointer to the parent struct device of this new device, if any
 *    @devt: the dev_t for the char device to be added
 *    @drvdata: the data to be added to the device for callbacks
 *    @fmt: string for the device's name
 */
struct device *iproc_device_create(struct class *class, 
	struct device *parent, dev_t devt, void *drvdata, const char *fmt, ...)
{
	va_list args;
	struct device *r;

	va_start(args, fmt);
	r = device_create_vargs(class, parent, devt, drvdata, fmt, args);
	va_end(args);

	return r; 
}
EXPORT_SYMBOL(iproc_device_create);

/**
 * iproc_device_destroy -
 *          wrapper function for device_destroy
 *    @class: pointer to the struct class that this device was registered with
 *    @devt: the dev_t of the device that was previously registered
 */
void iproc_device_destroy(struct class *class, dev_t devt)
{
	return device_destroy(class, devt);
}
EXPORT_SYMBOL(iproc_device_destroy);

/**
 * proc_device_remove_file - 
 *          wrapper function for device_remove_file
 *    @dev: device.
 *    @attr: device attribute descriptor.
 */
void iproc_device_remove_file(struct device *dev,
	const struct device_attribute *attr)
{
	return device_remove_file(dev, attr);
}
EXPORT_SYMBOL(iproc_device_remove_file);

/**
 * iproc_platform_get_irq_byname -
 *          wrapper function for platform_get_irq_byname
 *    @dev: platform device
 *    @name: IRQ name
 */
int iproc_platform_get_irq_byname(struct platform_device *dev, const char *n)
{
	return platform_get_irq_byname(dev,n);
}
EXPORT_SYMBOL(iproc_platform_get_irq_byname);

/**
 * iproc_gpio_to_irq -
 *          wrapper function for gpio_to_irq
 *    @gpio: gpio whose IRQ will be returned (already requested)
 */
int iproc_gpio_to_irq(unsigned gpio)
{
	return gpio_to_irq(gpio); 
}
EXPORT_SYMBOL(iproc_gpio_to_irq);
