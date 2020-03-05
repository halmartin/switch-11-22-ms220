/*
 * faulty.c -- a module which generates an oops when read
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 *
 * $Id: faulty.c,v 1.3 2004/09/26 07:02:43 gregkh Exp $
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/types.h>  /* size_t */
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

MODULE_LICENSE("Dual BSD/GPL");


static int minor = MISC_DYNAMIC_MINOR; /* default to dynamic */

static struct timer_list timer;
static spinlock_t lock;

void tasklet0_handler(unsigned long c);
void tasklet1_handler(unsigned long c);
DECLARE_TASKLET(faulty_tasklet0, tasklet0_handler, 0);
DECLARE_TASKLET(faulty_tasklet1, tasklet1_handler, 0);
module_param(minor, int, 0);
MODULE_PARM_DESC(minor, "Minor device number");


static ssize_t
faulty_read(struct file *filp, char __user *buf,
            size_t count, loff_t *pos)
{
    return -EINVAL;
}

static void
faulty_infinite_loop(unsigned long c)
{
    while (1) {}
}

static void
faulty_div_zero(unsigned long c)
{
    volatile int a = 1;
    volatile int b = 0;
    volatile int d = a / b;
    (void) d;
}

static void
faulty_null_deref(unsigned long c)
{
    *(int *)0 = 0;
}

static void
faulty_null_func(unsigned long c)
{
    ((void (*)(void))0)();
}

void
faulty_panic(unsigned long c)
{
    panic("%s panic\n", __func__);
}

static void
faulty_corrupt(unsigned long c)
{
    memset((uint8_t*)(0xc0000000), 0, 0x3fffffff);
}

static void
faulty_alloc_1m(unsigned long c)
{
    int i;
    for (i = 0; i < 1024 / 4; ++i)
        kmalloc(4096, c ? GFP_ATOMIC : GFP_KERNEL);
}
#ifdef MODULE
__attribute__ ((__section__ (".text.fastpath")))
#endif
void
tasklet0_handler(unsigned long c)
{
    spin_lock_bh(&lock);
}

#ifdef MODULE
__attribute__ ((__section__ (".text.fastpath")))
#endif
void
tasklet1_handler(unsigned long c)
{
    spin_lock_bh(&lock);
}

#ifdef MODULE
__attribute__ ((__section__ (".text.fastpath")))
#endif
void
faulty_deadlock(unsigned long c)
{
    printk("starting deadlock\n");
    spin_lock_init(&lock);
    tasklet_schedule(&faulty_tasklet0);
    tasklet_schedule(&faulty_tasklet1);
}

static ssize_t faulty_write (struct file *filp, const char __user *data, size_t len,
        loff_t *pos)
{
    int i;
    for (i = 0; i < len; ++i) {
        char c;
        if (get_user(c, data+i))
            return -EFAULT;
        printk("faulty read '%c'\n", (int) c);
        switch (c)
            {
            case 'D': faulty_div_zero(0); break;
            case 'd': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_div_zero;
                add_timer(&timer);
                break;
            }
            case 'F': faulty_null_func(0); break;
            case 'f': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_null_func;
                add_timer(&timer);
                break;
            }
            case 'L': faulty_deadlock(0); break;
            case 'l': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_deadlock;
                add_timer(&timer);
                break;
            }
            case 'Z': faulty_null_deref(0); break;
            case 'z': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_null_deref;
                add_timer(&timer);
                break;
            }
            case 'I': faulty_infinite_loop(0); break;
            case 'i': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_infinite_loop;
                add_timer(&timer);
                break;
            }
            case 'P': faulty_panic(0); break;
            case 'p': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_panic;
                add_timer(&timer);
                break;
            }
            case 'C': faulty_corrupt(0); break;
            case 'c': {
                timer.expires = jiffies + msecs_to_jiffies(50);
                timer.function = faulty_corrupt;
                add_timer(&timer);
                break;
            }
            case 'M': {
                faulty_alloc_1m(1);
                break;
            }
            case 'm': {
                faulty_alloc_1m(0);
                break;
            }
            default:
                break;
            }
    }

    return len;
}



static struct file_operations faulty_fops = {
    .read =  faulty_read,
    .write = faulty_write,
    .owner = THIS_MODULE
};

static struct miscdevice faulty_miscdev = {
	.name		= "faulty",
	.fops		= &faulty_fops,
	.nodename	= "faulty",
};

static int __init faulty_init(void)
{
    int result;
    /*
     * Register your minor
     */
    printk("Trying to register dev faulty etc\n");

    faulty_miscdev.minor = minor;

    result = misc_register(&faulty_miscdev);

    if (result < 0)
        return result;

    init_timer(&timer);
    timer.data = 0;
    timer.function = 0;

    return 0;
}

static void faulty_cleanup(void)
{
	misc_deregister(&faulty_miscdev);
}

module_init(faulty_init);
module_exit(faulty_cleanup);

