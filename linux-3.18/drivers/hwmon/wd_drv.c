/*
 * Lanner Watchdog/Lan-bypass Driver for Kernel and 2.6.x
 */

/* Standard in kernel modules */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <asm/io.h>
#include "wd_ioctl.h"

/*
 * Is the device opened right now?
 * Prevent to access the device in the same time
 */
static int Device_Open = 0;

/*
 * Device Depend Function Prototypes
 */
static void platform_information(void);

/* Platform specificed start*/
/* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */

static unsigned char Driver_Version[] = "0.0.1 2010-09-08";

#define INDEX_PORT  0x2e
#define DATA_PORT   0x2f
#define GPIO_PORT   0x500

#define WATCHDOG_TIMEOUT_MODE_BYPASS     1
#define WATCHDOG_TIMEOUT_MODE_RESET     2

int watchdog_time = 0;
int timeout_mode = 0;
int lanbypass_flag = 0;

static
void platform_information(void)
{
    printk("Watchdog/Lan-bypass Driver code for MB-7565...\n");
}

static
void enter_w83627_config(void)
{
    outb_p(0x87, INDEX_PORT); // Must Do It Twice
    outb_p(0x87, INDEX_PORT);
    return;
}

static
void exit_w83627_config(void)
{
    outb_p(0xAA, INDEX_PORT);
    return;
}

static
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

static
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

void gpio_init(void)
{
    write_w83627_reg(0x8, 0x2b, (read_w83627_reg(0x8, 0x2b) & 0xF3)|0x04);	//RX2b[3,2]=01 enable WDT
    write_w83627_reg(0x8, 0x2A, (read_w83627_reg(0x8, 0x2A) & 0xC1));	//RX2A[5-1]=00000 enable GPIO 22-26
    write_w83627_reg(0x8, 0x30, read_w83627_reg(0x8, 0x30) | 0x01); //rx30[0]=1 active GP2
    write_w83627_reg(0x8, 0xF0, read_w83627_reg(0x8, 0xF0) & 0x83); //rxF0[6,5,4,3,2]=0 gp22/23/24/25/26=000000 GPO
    write_w83627_reg(0x8, 0xF2, read_w83627_reg(0x8, 0xF2) & 0x00); //rxF2=00 ;
    write_w83627_reg(0x9, 0x2c, read_w83627_reg(0x9, 0x2c) & 0xCF); //rx2c[5,4]=00 ;enable GPIO30
    write_w83627_reg(0x9, 0x30, read_w83627_reg(0x9, 0x30) | 0x01); //rx30[0]=1 active GP3
    write_w83627_reg(0x9, 0xf0, read_w83627_reg(0x9, 0xf0) & 0xFE); //rxf0[0]=0 GPO30
    write_w83627_reg(0x9, 0xf2, read_w83627_reg(0x9, 0xf2) & 0xFE); //rxf2[0]=0
}

void clr_wd_status(void)
{
    write_w83627_reg(0x8, 0xf7, read_w83627_reg(0x8, 0xf7) | 0xff);
    write_w83627_reg(0x8, 0xf7, read_w83627_reg(0x8, 0xf7) & 0x00);
    write_w83627_reg(0x8, 0xf6, read_w83627_reg(0x8, 0xf6) & 0x00);
}
void set_runtime_bypass_enable_all(void)
{
    clr_wd_status();

    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3) | 0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) & 0xEF); //rxF1[4]=0;  gp24=0	lan1/2 by pass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) & 0xDF); //rxF1[5]=0;  gp25=0	lan3/4 by pass

    lanbypass_flag = 1;
}
void set_runtime_bypass_enable_12(void)
{
    clr_wd_status();

    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3) | 0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) & 0xEF); //rxF1[4]=0;  gp24=0	lan1/2 by pass

    lanbypass_flag = 1;
}
void set_runtime_bypass_enable_34(void)
{
    clr_wd_status();

    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3) | 0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) & 0xDF); //rxF1[5]=0;  gp25=0	lan3/4 by pass

    lanbypass_flag = 1;
}
void set_runtime_bypass_disable_all(void)
{
    clr_wd_status();

    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3)|0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) | 0x10); //rxF1[4]=1;  gp24=1 disable	lan1/2 by pass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) | 0x20); //rxF1[5]=1;  gp25=1	disable lan3/4 by pass

    lanbypass_flag = 0;
}
void set_runtime_bypass_disable_12(void)
{
    clr_wd_status();

    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3)|0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) | 0x10); //rxF1[4]=1;  gp24=1 disable	lan1/2 by pass

    lanbypass_flag = 0;
}
void set_runtime_bypass_disable_34(void)
{
    clr_wd_status();

    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3)|0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
    write_w83627_reg(0x8, 0xF1, read_w83627_reg(0x8, 0xF1) | 0x20); //rxF1[5]=1;  gp25=1	disable lan3/4 by pass

    lanbypass_flag = 0;
}
void set_bypass_enable_when_system_off(void)
{
    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3)|0x04); //rxF1[3,2]=01;  gp23=0 gp22=1 enable power-off lan bypass
}

void set_bypass_disable_when_system_off(void)
{
    write_w83627_reg(0x8, 0xF1, (read_w83627_reg(0x8, 0xF1) & 0xF3)|0x08); //rxF1[3,2]=10;  gp23=1 gp22=0 enable power-off lan bypass
}
void set_wdto_state_system_reset(void)
{
    timeout_mode = WATCHDOG_TIMEOUT_MODE_RESET;

    clr_wd_status();

    write_w83627_reg(0x8, 0xF6, 0x00);
    write_w83627_reg(0x8, 0xf5, read_w83627_reg(0x8, 0xF5) & 0xf7);
    write_w83627_reg(0x8, 0x30, read_w83627_reg(0x8, 0x30) | 0x01);
}

void set_wdto_state_system_bypass(void)
{
    timeout_mode = WATCHDOG_TIMEOUT_MODE_BYPASS;

    clr_wd_status();

    write_w83627_reg(0x8, 0xF6, 0x00);
    write_w83627_reg(0x8, 0xf5, read_w83627_reg(0x8, 0xF5) & 0xf7);
    write_w83627_reg(0x8, 0x30, read_w83627_reg(0x8, 0x30) | 0x01);
}

void start_watchdog_timer(void)
{
    if (timeout_mode == WATCHDOG_TIMEOUT_MODE_RESET) {
        if (lanbypass_flag == 1)
            set_runtime_bypass_disable_all();
        write_w83627_reg(0x8, 0xF6, watchdog_time);
        write_w83627_reg(0x9, 0xF1, read_w83627_reg(0x9, 0xF1) | 0x01);
    }
    else if (timeout_mode == WATCHDOG_TIMEOUT_MODE_BYPASS) {
        if (lanbypass_flag == 1)
            set_runtime_bypass_disable_all();
        write_w83627_reg(0x8, 0xF6, watchdog_time);
        write_w83627_reg(0x9, 0xF1, read_w83627_reg(0x9, 0xF1) & 0xFE);
    }
    else
        printk("Choose the Watchdog State first...\n");
}

void stop_watchdog_timer(void)
{
    clr_wd_status();
}
static long wd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {

        case IOCTL_RUNTIME_BYPASS_STATE:
	    switch ((int)arg) {
                case RUNTIME_BYPASS_STATE_ENABLE_LAN_ALL:
                    set_runtime_bypass_enable_all();
                    break;
                case RUNTIME_BYPASS_STATE_ENABLE_LAN_12:
                    set_runtime_bypass_enable_12();
                    break;
                case RUNTIME_BYPASS_STATE_ENABLE_LAN_34:
                    set_runtime_bypass_enable_34();
                    break;
                case RUNTIME_BYPASS_STATE_DISABLE_LAN_ALL:
                    set_runtime_bypass_disable_all();
                    break;
                case RUNTIME_BYPASS_STATE_DISABLE_LAN_12:
                    set_runtime_bypass_disable_12();
                    break;
                case RUNTIME_BYPASS_STATE_DISABLE_LAN_34:
                    set_runtime_bypass_disable_34();
                    break;
                default:
                    return -EOPNOTSUPP;
            }
            break;

        case IOCTL_SYSTEM_OFF_BYPASS_STATE:
	    switch ((int)arg) {
                case SYSTEM_OFF_BYPASS_STATE_ENABLE:
                    set_bypass_enable_when_system_off();
                    break;
                case SYSTEM_OFF_BYPASS_STATE_DISABLE:
                    set_bypass_disable_when_system_off();
                    break;
                default:
                    return -EOPNOTSUPP;
            }
            break;

        case IOCTL_SET_WDTO_STATE:
	    switch ((int)arg) {
                case SET_WDTO_STATE_SYSTEM_RESET:
                    set_wdto_state_system_reset();
                    break;
                case SET_WDTO_STATE_LAN_BYPASS:
                    set_wdto_state_system_bypass();
                    break;
                default:
                    return -EOPNOTSUPP;
            }
            break;

        case IOCTL_SET_WDTO_TIMER:
            watchdog_time = (int)arg;
            if ((watchdog_time < 0) || (watchdog_time > 255)) {
                printk(KERN_ERR "wd_drv error: Invalid time value\n");
                watchdog_time = 0;
                return -EOPNOTSUPP;
            }
            break;

        case IOCTL_START_STOP_WDT:
	    switch ((int)arg) {
                case START_WDT:
                    if (!timeout_mode) {
                        printk(KERN_ERR "wd_drv error: Invalid manipulation, you should first choose Watchdog Timeout Mode\n");
                        return -EOPNOTSUPP;
                    }
                    start_watchdog_timer();
                    break;
                case STOP_WDT:
                    stop_watchdog_timer();
                    break;
                default:
                    return -EOPNOTSUPP;
            }
            break;

        default:
            return -EOPNOTSUPP;
    }

    return 0;
}


static int wd_open(struct inode * inode, struct file * file)
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
    //printk("Lanner Watchdog Driver Opened\n");
    return 0;
}

/*
 * This function is called when a process closes the device file.
 */
static int wd_release(struct inode * inode, struct file * file)
{
    /* ready for next caller */
    Device_Open--;
    /* Decrement the usage count, otherwise once you opened the file
     * you'll never get rid of the module.
     */
    //printk("Lanner Watchdog Driver Closed\n");
    return 0;
}

/*
 * This structure will hold the functions to be called
 * when a process does something to the device we created.
 * Since a pointer to this structure is kept in the
 * devices table, it can't be local to init_module.
 * NULL is for unimplemented functions.
 */
static const struct file_operations wd_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= wd_ioctl,
	.compat_ioctl	= wd_ioctl,
	.open		= wd_open,
	.release	= wd_release,
};

static struct miscdevice wd_miscdev = {
	.name = "wd_drv",
	.fops = &wd_fops,
	.nodename = "wd_drv",
	.minor = MISC_DYNAMIC_MINOR,
};

int wd_init(void)
{
    /*
     * Register the character device
     */

    if(misc_register(&wd_miscdev))
    {
        printk("wd_drv : unable to register\n");
        return -EIO;
    }
    platform_information();
    gpio_init();
    printk("Watchdog Driver Version %s is loaded\n", Driver_Version);
    return 0;
}

/*
 * Cleanup - unregister the appropriate file from /proc
 */
void wd_exit(void)
{
    /* Unregister the device */
    misc_deregister(&wd_miscdev);
    /* If there's an error, report it */
    printk("Watchdog Driver Version %s is unloaded\n", Driver_Version);
}

module_init(wd_init);
module_exit(wd_exit);

MODULE_AUTHOR("Lanner SW");
MODULE_DESCRIPTION("Lanner Watchdog/Lan-bypass Linux Driver");
MODULE_LICENSE("Dual BSD/GPL");
