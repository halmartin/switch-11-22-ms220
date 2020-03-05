/* Standard in kernel modules */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/miscdevice.h>
#include <asm/io.h>
#include <linux/delay.h>
//#include <linux/spinlock.h>
#include <asm/uaccess.h>

#define MAGIC_CHAR 'B'

#include <linux/ioctl.h>
#define IOCTL_BTN_GET_STATUS    _IOW(MAGIC_CHAR, 0, int)

#define inportb(x) inb_p(x)
#define outportb(x, y) outb_p(y, x)
#define inportl(x) inl_p(x)
#define outportl(x, y) outl_p(y, x)

#define PLATFORM_NAME "MB-8865"
#define CODE_VERSION "V2.0 2011-04-21"

/*
 * Device Depend Definition : Intel ICH8-M chipset
*/
#define PCH_GPIO_BASE_ADDRESS	0x500
#define GPIO_USE_SEL  0x02
#define GP_IO_SEL 0x06
#define GP_LVL	0x0E
#define PCH_GPIO_16_BIT	0x01<<0

/*
 * Return value:
 * 	0: BUTTON Pressed
 * 	1: BUTTON Released
 */
unsigned char get_btn_status(void)
{
        return  (inportb(PCH_GPIO_BASE_ADDRESS+GP_LVL) & (PCH_GPIO_16_BIT)) ? 0 : 1;
}

void btn_gpio_init(void)
{
        /* platform initial code */

        /* Reset button initial function */

        /* select GPIO function */
	outportb(PCH_GPIO_BASE_ADDRESS+GPIO_USE_SEL,inportl(PCH_GPIO_BASE_ADDRESS+GPIO_USE_SEL) | (PCH_GPIO_16_BIT));

        /* set to input mode */
	outportb(PCH_GPIO_BASE_ADDRESS+GP_IO_SEL,inportl(PCH_GPIO_BASE_ADDRESS+GP_IO_SEL) | (PCH_GPIO_16_BIT));

	return;
}


/*
 * Is the device opened right now?
 * Prevent to access the device in the same time
 */
static int Device_Open = 0;


static long btn_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        int value;
        unsigned char tmp;

        switch(cmd)
        {
                case IOCTL_BTN_GET_STATUS:
                        tmp = get_btn_status();
			value = tmp;
                        if ( copy_to_user((int *)arg, &value, sizeof(value)))
                                return -EFAULT;

                        break;
                default:
                        return -EOPNOTSUPP;
        }
        return 0;

}

/*
 * This function is called whenever a process attempts to
 * open the device file
 */
static int btn_open(struct inode * inode, struct file * file)
{
	/* we don't want to talk to two processes at the same time */
	if(Device_Open) return -EBUSY;
	Device_Open++;
	/* Make sure that the module isn't removed while the file
	 * is open by incrementing the usage count (the number of
	 * opened references to the module,if it's zero emmod will
	 * fail)
	 */
	return 0;
}

/*
 * This function is called when a process closes the device file.
 */
static int btn_release(struct inode * inode, struct file * file)
{
	/* ready for next caller */
	Device_Open--;
	/* Decrement the usage count, otherwise once you opened the file
	 * you'll never get rid of the module.
	 */
	return 0;
}

/*
 * This structure will hold the functions to be called
 * when a process does something to the device we created.
 * Since a pointer to this structure is kept in the
 * devices table, it can't be local to init_module.
 * NULL is for unimplemented functions.
 */
#if defined(OLDKERNEL)
static struct file_operations btn_fops = {
	owner:		THIS_MODULE,
	read:		NULL,
	write:		NULL,
	ioctl:		btn_ioctl,
	open:		btn_open,
	release:	btn_release,
};
#else
static const struct file_operations btn_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= btn_ioctl,
	.compat_ioctl	= btn_ioctl,
	.open		= btn_open,
	.release	= btn_release,
};
#endif

static struct miscdevice btn_miscdev = {
	.fops		= &btn_fops,
	.nodename	= "btn_drv",
	.name		= "btn_drv",
	.minor		= MISC_DYNAMIC_MINOR,
};



static int btn_init(void)
{
	int result;

	/*
	 * Register the character device
	 */

	result = misc_register(&btn_miscdev);

	if(result < 0)
	{
		printk("btn_drv : unable to register, err %d\n", result);
		return -EIO;
	}
	btn_gpio_init();
	printk("Lanner Platform <<%s>> Software Button Version %s -- loaded\n", PLATFORM_NAME, CODE_VERSION);
	return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
static void btn_exit(void)
{
	/* Unregister the device */
	misc_deregister(&btn_miscdev);
	/* If there's an error, report it */
	printk("Lanner Platform Software Button Driver -- Unloaded\n");
}

module_init(btn_init);
module_exit(btn_exit);

MODULE_AUTHOR("Lanner SW");
MODULE_DESCRIPTION("Lanner Platform Software Button Driver");
MODULE_LICENSE("Dual BSD/GPL");


