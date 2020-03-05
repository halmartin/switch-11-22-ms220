/*
 * Lanner Reset Button Driver for Kernel 2.6.x
 */

/* Standard in kernel modules */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include "btn_ioctl.h"

/*
 * Is the device opened right now?
 * Prevent to access the device in the same time
 */
static int Device_Open = 0;

/*
 * Device Depend Function Prototypes
 */
void platform_information(void);

/* Platform specificed start*/
/* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */

static unsigned char Driver_Version[] = "0.0.1 2010-09-08";

/*
 * Platform Depend GPIOs for Reset Button
 */
/*
 *------------------------------------------------------------------------------
 * MB-7565 Version V01
 *
 * The IO interface for Reset Button is connected to to Intel ICH8.
 * Refer to Inter ICH8 datasheet for details.
 * The high/low definition is as below:
 *	GPIO_PORT+0x0E  Button Status
 *  --------------------------
 *  0x10	Button Released
 *  else	Button Pressed
 *------------------------------------------------------------------------------
 */

#define INDEX_PORT  0x2e
#define DATA_PORT   0x2f
#define GPIO_PORT   0x500

void platform_information(void)
{
	printk("Reset Button Driver code for MB-7565...\n");
}

void enter_w83627_config(void)
{
        outb_p(0x87, INDEX_PORT); // Must Do It Twice
        outb_p(0x87, INDEX_PORT);
        return;
}

void exit_w83627_config(void)
{
        outb_p(0xAA, INDEX_PORT);
        return;
}

unsigned char read_w83627_reg(int LDN, int reg)
{
        unsigned char tmp = 0;

        enter_w83627_config();
        outb_p(0x07, INDEX_PORT); // LDN Register
        outb_p(LDN,  DATA_PORT); // Select LDNx
        outb_p(reg,  INDEX_PORT); // Select Register
        tmp = inb_p( DATA_PORT); // Read Register
        exit_w83627_config();
        return tmp;
}

void write_w83627_reg(int LDN, int reg, int value)
{
        enter_w83627_config();
        outb_p(0x07,  INDEX_PORT); // LDN Register
        outb_p(LDN,   DATA_PORT); // Select LDNx
        outb_p(reg,   INDEX_PORT); // Select Register
        outb_p(value, DATA_PORT); // Write Register
        exit_w83627_config();
        return;
}

int read_sb_gpio(int reg)
{
    return inb_p(GPIO_PORT + reg);
}

int write_sb_gpio(unsigned int reg, unsigned int value)
{
    outb_p(value, GPIO_PORT+reg);

    return 0;
}

/* Platform specificed end */
/*********************************************/

static long btn_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int value;

    switch (cmd) {
        case IOCTL_BTN_GET_STATUS:
            value = read_sb_gpio(0x0e) & 0x10;
            if (value == 0x10)
                value = BTN_STATUS_RELEASED;
            else
                value = BTN_STATUS_PRESSED;
            if (copy_to_user((int *)arg, &value, sizeof(value)))
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
	/*
	 * Get the minor device number in case you have more than
	 * one physical device using the driver.
	 */
	//printk("Device: %d.%d\n", inode->i_rdev>>8, inode->i_rdev & 0xff);
	/* we don't want to talk to two processes at the same time */
	if(Device_Open) return -EBUSY;
	Device_Open++;
	/* Make sure that the module isn't removed while the file
	 * is open by incrementing the usage count (the number of
	 * opened references to the module,if it's zero emmod will
	 * fail)
	 */
	//printk("Lanner Reset Button Driver Opened\n");
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
	//printk("Lanner Reset Button Driver Closed\n");
	return 0;
}

/*
 * This structure will hold the functions to be called
 * when a process does something to the device we created.
 * Since a pointer to this structure is kept in the
 * devices table, it can't be local to init_module.
 * NULL is for unimplemented functions.
 */
static const struct file_operations btn_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= btn_ioctl,
	.compat_ioctl	= btn_ioctl,
	.open		= btn_open,
	.release	= btn_release,
};

static struct miscdevice btn_miscdev = {
	.fops		= &btn_fops,
	.nodename	= "btn_drv",
	.name		= "btn_drv",
	.minor		= MISC_DYNAMIC_MINOR,
};

int btn_init(void)
{
	int result;

	/*
	 * Register the character device
	 */
	result = misc_register(&btn_miscdev);
	if (result < 0)
	{
		printk("btn : unable to register, err %d\n", result);
		return -EIO;
	}
	platform_information();
	printk("Reset Button Driver Version %s is loaded\n", Driver_Version);
	return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
void btn_exit(void)
{
	/* Unregister the device */
	misc_deregister(&btn_miscdev);
	/* If there's an error, report it */
	printk("Reset Button Driver Version %s is unloaded\n", Driver_Version);
}

module_init(btn_init);
module_exit(btn_exit);

MODULE_AUTHOR("Lanner SW");
MODULE_DESCRIPTION("Lanner Reset Button Linux Driver");
MODULE_LICENSE("Dual BSD/GPL");
