/*
 *
 * poe_bcm59121.c - Driver for Broadcom BCM59121 Power over Ethernet controller
 *
 * Copyright (c) 2011 Meraki, Inc.
 * Copyright (c) 2013-2015 Cisco Systems, Inc.
 * Author: Kevin Paul Herbert (kph@meraki.com)
 * Author: Dean Thomas (dean@meraki.com)
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
 * This is a driver for the Broadcom BCM59121 power controllers in auto mode.
 * This driver interfaces with the PoE subsystem and provides the methods
 * to control the underlying PoE controllers and ports.
 *
 * This driver can supports one PoE Controller, up to 48 ports.
 * The platform is responsible for defining the use of I2C and GPIO addresses,
 * and this driver will create the appropriate device, controller, and
 * port instances using the generic PoE subsystem.
 *
 * This is based on poe/pd690xx_poe.c by Kevin Herbert
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/i2c.h>
#include <linux/poe.h>
#include <linux/bcm59121.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#define BCM59121_RESET_RETRIES    10   /* Maximum initialization retries */

/* Time in MS to wait while the RESET is pulled active */
#define BCM59121_RESET_ACTIVE_DELAY 500  /* 0.5 second delay, 500 ms */

/*
 * Time in MS to wait after setting RESET inactive and before issuing a
 * bcm59121 command. After much gnashing of teeth and rending of garments,
 * Broadcom told us to wait at least 1.5 seconds.
 */
#define BCM59121_RESET_DELAY    1500  /* 1.5 second delay, 1500 ms */

#define BCM59121_POLL_INTERVAL  250 /* Poll frequency (ms) for driver */

#define BCM59121_RETRY_INIT_DELAY  20 /* Delay (ms) before retrying RESET and initialization */

#define BCM59121_MAX_PORTS  48

/* The bcm59121 commands are always "cmd" followed by 11 bytes */
#define CMDBUFSIZE 11
/* But, we always read 12 bytes */
#define RECVBUFSIZE 12

/* Maximum number of retries of a command */
#define COMMAND_RETRIES 4

/*
 * Maximum number of error messages printed
 * This is reset by enabling an already enabled port
 */
#define ERROR_LIMIT 20
static int error_limit = ERROR_LIMIT;

/* Forward references */
static int bcm59121_set_power_budget(struct poe_dev *, unsigned int);
static int bcm59121_set_enable(struct poe_port_kobj *, bool);
static int bcm59121_set_enable2(struct poe_port_kobj *, bool, bool);
static int bcm59121_set_priority(struct poe_port_kobj *, int);
static int bcm59121_set_priority2(struct poe_port_kobj *, int, bool);
static int bcm59121_get_port_stats(struct poe_port_kobj *, ssize_t, char *);
static int bcm59121_get_controller_stats(struct poe_controller_kobj *, ssize_t, char *);
static void bcm59121_do_work(struct work_struct *);

enum bcm59121_state {
    BCM59121_STATE_RESET,            /* Error occurred, reset the PoE */
    BCM59121_STATE_GPIO_DISABLE,    /* GPIO Disable is asserted */
    BCM59121_STATE_INITIALIZING,    /* Controller is initializing */
    BCM59121_STATE_RUNNING,            /* Controller is running */
};

struct bcm59121 {
    struct delayed_work work;
    int                 work_state; // 1 + poe->ports)
    int                 work_substate;
    struct i2c_client   *client;
    struct poe_dev      *poe;
    int                 gpio_disable;
    int                 gpio_reset;
    int                 logic_low;
    enum bcm59121_state state;
    int                 init_retries;
    uint32_t            last_joule_time[BCM59121_MAX_PORTS];
    int                 joule_time_set[BCM59121_MAX_PORTS];
    struct mutex        lock;
    int                 seq;
};

static struct workqueue_struct *b_wq;

struct bcm59121_stats {
    uint32_t writeEIOerrors;
    uint32_t writeENOENTerrors;
    uint32_t writeENXIOerrors;
    uint32_t writeCommands;
    uint32_t sysResets;
    uint32_t readAllFF;
    uint32_t cmd_retries[COMMAND_RETRIES];
    uint32_t cmd_fail;
} bcm59121_stats;

/*
 * bcm59121_read_command - Do a read command on the device
 *
 * This routine is used to read responses from the BCM59121 Controller
 * The command format is to send the register address to the
 * device as a 8 bit I2C write, and then issue a 12 byte I2C read
 * with no intervening stop bit.
 *
 * rxbuf must be at least 12 bytes long.
 * rxbuf will have cmd, bcm->seq, 9 bytes data, checksum
 */

#define READ_RETRIES 4

static int bcm59121_read_command(struct bcm59121 *bcm, u8 cmd, u8 seq, u8 *rxbuf)
{
    struct i2c_client *client = bcm->client;
    int ret, i, j;
    u8 sum;
    bool allf;

    if ((bcm->state == BCM59121_STATE_GPIO_DISABLE) || (bcm->state == BCM59121_STATE_RESET)) {
        dev_err(&client->dev, "%s: PoE state is resetting", __func__);
        return -EBADSTATE;	/* I/O error */
        }

        for (i = 1; i <= READ_RETRIES; i++) {
            ret = i2c_smbus_read_i2c_block_data(client, cmd, RECVBUFSIZE, rxbuf);
            if (ret < 0) {
                /* Retry */
                dev_err(&client->dev,
                        "%s: (%d) i2c_smbus_read_block_data [%02x:%04x] returned %d\n",
                        __func__, i, client->addr, cmd, ret);
                ret = -EI2C;
            } else if (ret != RECVBUFSIZE) {
                /* Retry */
                dev_err(&client->dev, "%s: (%d) unexpected I/O count %d\n",
                        __func__, i , ret);
                ret = -ERESPONSEBUFSIZE;
            } else {
                /* Check if the result is all 0xff */
                allf = true;
                for (j = 0; j < RECVBUFSIZE; j++) {
                    if (rxbuf[j] != 0xff) {
                        allf = false;
                        break;
                    }
                }
                if (allf) {
                    ret = -ERESPONSEALLFF;
                    break;
                }
                /* Check the checksum */
                sum = 0;
                for (j = 0; j < RECVBUFSIZE-1; j++)
                    sum += rxbuf[j];

                if (sum != rxbuf[RECVBUFSIZE-1]) {
                    /* Retry */
                    dev_err(&client->dev, "%s: (%d) checksum got %u expected %u\n",
                            __func__, i, sum, rxbuf[RECVBUFSIZE-1]);
                    ret = -ERESPONSECHECKSUM;
                } else if (rxbuf[0] == 0xFF) { /* "Not ready to respond" */
                    /* Retry */
                    dev_err(&client->dev, "%s: (%d) Not ready to respond\n",
                            __func__, i);
                    ret = -ENOTREADY;
                } else {
                    /* Do NOT retry: we are done with the read loop */
                    ret = 0;
                    break;
                }
            }
            msleep(1);
                /* OK, try again */
        }
        /*
         * Either we ran out of retries, -or- we know that:
         * The read succeeded, we got the right number of bytes
         * the checksum was correct, and we did not get "Not Ready to Respond"
         */
        if (ret == -ERESPONSEALLFF) {
            bcm59121_stats.readAllFF++;
        } else if (ret) {
            dev_err(&client->dev, "%s: %d retries exceeded - Failing %d\n",
                    __func__, READ_RETRIES, rxbuf[0]);
        } else if (rxbuf[0] == 0xFE) {
            dev_err(&client->dev, "%s: (%d) Checksum Error in Request\n",
                         __func__, i);
            ret = -EREQUESTCHECKSUM;
        } else if (rxbuf[0] == 0xFD) {
            dev_err(&client->dev, "%s: (%d) Incomplete frame in Request\n",
                        __func__, i);
            ret = -EREQUESTINCOMPLETE;
        } else if (rxbuf[0] != cmd) {
            dev_err(&client->dev, "%s: (%d) cmd got %u expected %u\n",
                        __func__, i, rxbuf[0], cmd);
            ret = -ERESPONSECMDBAD;
        } else if (rxbuf[1] != seq) {
            dev_err(&client->dev, "%s: seq got %u expected %u\n",
                    __func__, rxbuf[1], seq);
            ret = -ERESPONSESEQBAD;
        }

        if (ret && ret != -ERESPONSEALLFF) {
            dev_err(&client->dev, "%s: %x %x %x %x %x %x %x %x %x %x %x %x\n",
                __func__, rxbuf[0], rxbuf[1], rxbuf[2], rxbuf[3], rxbuf[4], rxbuf[5],
                rxbuf[6], rxbuf[7], rxbuf[8], rxbuf[9], rxbuf[10], rxbuf[11]);
        }
    return ret;
}

#define WRITE_RETRIES 3

static int bcm59121_write_command(struct bcm59121 *bcm, u8 command, u8 *txbuf)
{
    struct i2c_client *client = bcm->client;
    int i, ret;
        u8 sum = 0;

    if ((bcm->state == BCM59121_STATE_GPIO_DISABLE) || (bcm->state == BCM59121_STATE_RESET))
        return -EBADSTATE;

    bcm59121_stats.writeCommands++;
    /* Compute checksum */
    sum = command;
    for (i = 0; i < CMDBUFSIZE - 1; i++)
        sum += txbuf[i];
    txbuf[CMDBUFSIZE - 1] = sum;

    for (i = 1; i <= WRITE_RETRIES; i++) {
        ret = i2c_smbus_write_i2c_block_data(client, command, CMDBUFSIZE, txbuf);
        if (ret == 0) {
            break;
        }
        if (ret == -ENXIO) {
            bcm59121_stats.writeENXIOerrors++;
            ret = -EREQENXIO;
            msleep(50);
            continue;
        }
        if (ret == -EIO) {
            bcm59121_stats.writeEIOerrors++;
        } else if (ret == -ENOENT) {
            bcm59121_stats.writeENOENTerrors++;
        } else {
            dev_err(&client->dev, "%s: (%d) i2c_smbus_write_block_data returned %d\n",
            __func__, i, ret);
        }
        ret = -EI2C;
        msleep(1);
    }
    return ret;
}

/* bcm59121_command - Send command to device and recieve response
 *
 * Send the cmdbuf[] to the device and recieve the rsponse in recvbuf[]
 * The cmdbuf[] and recvbuf must be at LEAST 12 bytes large.
 * The cmdbuf will contain the command and 10 bytes of data. cmdbuf[11]
 * is reserved for the checksum, which will be computed.
 *
 * returns 0 on success
 * Failure is returned on I/O or response protocol errors:
 *    Transmit failure
 *    Recieve failure
 *    Bad recieve cmd or sequence number
 *    Bad receive checksum
 */

static int
bcm59121_command(struct bcm59121 *bcm, u8 command, int bufsize, u8 cmdbuf[],
        u8 *recvbuf)
{
    int ret, i;

    if (bufsize < RECVBUFSIZE) {
        return -EINVAL;
    }

    for (i = 1; i <= COMMAND_RETRIES; i++) {
        ret = bcm59121_write_command(bcm, command, cmdbuf);
        if (ret == -EREQENXIO)
            break;
        if (ret != 0) {
            dev_err(&bcm->client->dev, "%s write (%d) failed %d\n", __func__, i, ret);
            break;
        }
        msleep(20);

        ret = bcm59121_read_command(bcm, command, cmdbuf[0], recvbuf);
        if (ret == 0)
            break;
        if (ret != -EREQUESTCHECKSUM && ret != -EREQUESTINCOMPLETE && ret != -ERESPONSECHECKSUM
                && ret != -ERESPONSEALLFF) {
            dev_err(&bcm->client->dev, "%s read (%d) failed %d\n", __func__, i, ret);
            break;
        }
        msleep(20);
    }

    if (ret && i > COMMAND_RETRIES) {
        bcm59121_stats.cmd_fail++;
        if (error_limit > 0) {
            error_limit--;
            dev_err(&bcm->client->dev, "%s Too many retries %d\n", __func__, ret);
        }
    } else {
        bcm59121_stats.cmd_retries[i-1]++;
        if (ret == 0 && i > 1 && error_limit > 0) {
            error_limit--;
            dev_err(&bcm->client->dev, "%s Succeeded retry %d\n", __func__, i);
        }
    }
    return ret;
}

#define CMDLOAD(b, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9) \
        b[0] = v0; b[1] = v1; b[2] = v2; b[3] = v3; b[4] = v4; b[5] = v5; \
        b[6] = v6; b[7] = v7; b[8] = v8; b[9] = v9;

static int
bcm59121_sysstatus(struct bcm59121 *bcm, int bufsize, u8 recvbuf[])
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x20, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_portStatusQuery(struct bcm59121 *bcm, int bufsize, u8 *recvbuf, uint port_num)
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, port_num, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x21, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_portStatistics(struct bcm59121 *bcm, int bufsize, u8 *recvbuf, uint port_num)
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, port_num, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x22, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_portMeasurement(struct bcm59121 *bcm, int bufsize, u8 *recvbuf, uint port_num)
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, port_num, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x30, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_totalPower(struct bcm59121 *bcm, int bufsize, u8 *recvbuf)
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x23, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_portConfig(struct bcm59121 *bcm, int bufsize, u8 *recvbuf, uint port_num)
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, port_num, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x25, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_portExtConfig(struct bcm59121 *bcm, int bufsize, u8 *recvbuf, uint port_num)
{
    u8 cmdbuf[RECVBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, port_num, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x26, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_setPortPriority(struct bcm59121 *bcm, u8 pri, u8 port_num)
{
    u8 cmdbuf[CMDBUFSIZE], rbuf[RECVBUFSIZE];
    int ret;
    CMDLOAD(cmdbuf, bcm->seq++, port_num, pri, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    ret = bcm59121_command(bcm, 0x1A, RECVBUFSIZE, cmdbuf, rbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s Port Set Priority command failed %d port %d\n",
                __func__, ret, port_num);
        return -1;
    }
    if (rbuf[3] != 0) {
        dev_err(&bcm->client->dev, "%s Port Set Priority command NAK %u port %d\n",
                __func__, rbuf[3], port_num);
        return -1;
    }
    return 0;
}

static int
bcm59121_setPSE(struct bcm59121 *bcm, bool enable, u8 port_num)
{
    u8 cmdbuf[CMDBUFSIZE], rbuf[RECVBUFSIZE];
    int ret;
    u8 enab = (enable ? 1 : 0);
    CMDLOAD(cmdbuf, bcm->seq++, port_num, enab, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    ret = bcm59121_command(bcm, 0x00, RECVBUFSIZE, cmdbuf, rbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s Port Enable PSE command failed %d port %d\n",
                __func__, ret, port_num);
        return -1;
    }
    if (rbuf[3] != 0) {
        dev_err(&bcm->client->dev, "%s Port Enable PSE command NAK %u port %d\n",
                __func__, rbuf[3], port_num);
        return -1;
    }
    return 0;
}

static int
bcm59121_systemPowerManConfig(struct bcm59121 *bcm, u8 mpss, int bufsize, u8 *recvbuf)
{
    u8 cmdbuf[RECVBUFSIZE];
    /* Note: unlike other commands, this does not have a sequence number (seq++) */
    CMDLOAD(cmdbuf, mpss, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x27, RECVBUFSIZE, cmdbuf, recvbuf));
}

static int
bcm59121_powerManMode(struct bcm59121 *bcm)
{
    u8 cmdbuf[CMDBUFSIZE], rbuf[RECVBUFSIZE];
    int ret;
    /* Set Power Management Mode to Dynamic Power Management */
    CMDLOAD(cmdbuf, bcm->seq++, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    ret = bcm59121_command(bcm, 0x17, RECVBUFSIZE, cmdbuf, rbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s Power Management Mode command failed %d\n",
                __func__, ret);
        return -1;
    }
    if (rbuf[2] != 0) {
        dev_err(&bcm->client->dev, "%s Power Management Mode command NAK %u \n",
                __func__, rbuf[2]);
        return -1;
    }
    return 0;
}

/*
 * power_dw - Power in .1 watt
 */

static int
bcm59121_powerSourceConfig(struct bcm59121 *bcm, unsigned int power_dw)
{
    u8 cmdbuf[CMDBUFSIZE], rbuf[RECVBUFSIZE];
    int ret, i;
    unsigned guard_band = power_dw / 20;        /* 1/20 of power, for now */

    /* Zero power when there are no power supplies */
    CMDLOAD(cmdbuf, bcm->seq++, 0, 0x0, 0x0, 0x0, 0x0, 0xFF, 0xFF, 0xFF, 0xFF);
    ret = bcm59121_command(bcm, 0x18, RECVBUFSIZE, cmdbuf, rbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s Power Configuration command 0 failed %d\n",
                __func__, ret);
    } else if (rbuf[3] != 0) {
        dev_err(&bcm->client->dev, "%s Power Configuration command 0 NAK %u\n",
                __func__, rbuf[3]);
    }

    /* Zero power when there is only the 3rd power supplies, which is not supported */
    CMDLOAD(cmdbuf, bcm->seq++, 0x4, 0x0, 0x0, 0x0, 0x0, 0xFF, 0xFF, 0xFF, 0xFF);
    ret = bcm59121_command(bcm, 0x18, RECVBUFSIZE, cmdbuf, rbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s Power Configuration command 4 failed %d\n",
                __func__, ret);
    } else if (rbuf[3] != 0) {
        dev_err(&bcm->client->dev, "%s Power Configuration command 4 NAK %u\n",
                __func__, rbuf[3]);
    }

    /* Set the power budget the same for all combinations of 2 PSU: REDUNDANT power */
    for (i = 1; i < 4; i++) {
        CMDLOAD(cmdbuf, bcm->seq++, i, (power_dw >> 8) & 0xFF, (power_dw & 0xFF),
                    (guard_band >> 8) & 0xFF, (guard_band & 0xFF),
                    0xFF, 0xFF, 0xFF, 0xFF);
        ret = bcm59121_command(bcm, 0x18, RECVBUFSIZE, cmdbuf, rbuf);
        if (ret != 0) {
            dev_err(&bcm->client->dev, "%s Power Configuration command %d failed %d\n",
                    __func__, i, ret);
        } else if (rbuf[3] != 0) {
            dev_err(&bcm->client->dev, "%s Power Configuration command %d NAK %u\n",
                    __func__, i, rbuf[3]);
        }
        /* Set this power whether PSU 3 (bit 0x4) is there or not */
        CMDLOAD(cmdbuf, bcm->seq++, i + 0x4, (power_dw >> 8) & 0xFF, (power_dw & 0xFF),
                    (guard_band >> 8) & 0xFF, (guard_band & 0xFF),
                    0xFF, 0xFF, 0xFF, 0xFF);
        ret = bcm59121_command(bcm, 0x18, RECVBUFSIZE, cmdbuf, rbuf);
        if (ret != 0) {
            dev_err(&bcm->client->dev, "%s Power Configuration command %d failed %d\n",
                    __func__, i + 0x4, ret);
        } if (rbuf[3] != 0) {
            dev_err(&bcm->client->dev, "%s Power Configuration command %d NAK %u\n",
                    __func__, i + 0x4, rbuf[3]);
        }
    }
    return 0;
}

static int
bcm59121_detectionType(struct bcm59121 *bcm, u8 port_num)
{
    u8 cmdbuf[CMDBUFSIZE], rbuf[RECVBUFSIZE];
    int ret;
    CMDLOAD(cmdbuf, bcm->seq++, port_num, 0x3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    ret = bcm59121_command(bcm, 0x10, RECVBUFSIZE, cmdbuf, rbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s Port Detection Type command failed %d port %d\n",
                __func__, ret, port_num);
        return -1;
    }
    if (rbuf[3] != 0) {
        dev_err(&bcm->client->dev, "%s Port Detection Type command NAK %u port %d\n",
                __func__, rbuf[3], port_num);
        return -1;
    }
    return 0;
}

static const enum PORT_POWER_STATE bcm59121_status_to_state[] = {
    PORT_POWER_OFF,
    PORT_POWER_OFF,
    PORT_POWER_ON,
    PORT_POWER_TEST,
    PORT_POWER_ERROR,
    PORT_POWER_ERROR,
    PORT_POWER_STARTING,
    PORT_POWER_ERROR,
};

static int
bcm59121_enhMultiPortStatQuery(struct bcm59121 *bcm, u8 group, int bufsize, u8 *rbuf)
{
    u8 cmdbuf[CMDBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, group, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x2A, bufsize, cmdbuf, rbuf));
}

static int
bcm59121_systemExtendedConfig(struct bcm59121 *bcm, int bufsize, u8 recvbuf[])
{
    u8 cmdbuf[CMDBUFSIZE];
    CMDLOAD(cmdbuf, bcm->seq++, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    return (bcm59121_command(bcm, 0x2B, RECVBUFSIZE, cmdbuf, recvbuf));
}

#define PORTSPERQUERY 8 /* Each enhMultiPortStatQuery returns info on 8 ports */
static int
bcm59121_update_port_group_status(struct bcm59121 *bcm)
{
    static u8 group = 0;
    struct poe_dev *poe = bcm->poe;
    u8 rbuf[RECVBUFSIZE];
    int ret, p, r;
    u8 s, status, error;
    struct poe_port_kobj *kp;

    ret = bcm59121_enhMultiPortStatQuery(bcm, group, RECVBUFSIZE, rbuf);
    if (ret < 0) {
        if (error_limit > 0) {
            error_limit--;
            dev_err(&bcm->client->dev, "%s Cannot get status %d\n",
                __func__, ret);
        }
        return ret;
    }
    p = group * PORTSPERQUERY;      /* Port Number */
    if (++group >= (poe->ports/PORTSPERQUERY))
        group = 0;
    for (r = 0; r < PORTSPERQUERY && p < poe->ports; r++) { /* 8 ports per request */
        s = rbuf[r + 3];      /* ports status starts at rbuf[3] */
        kp = poe->port_kobjs[p++];
        status = s & 0xF;
        kp->mode = ((s >> 7) ? PORT_MODE_AT : PORT_MODE_AF);
        if (status > 0x7)
            kp->status = PORT_POWER_ERROR;
        else
            kp->status = bcm59121_status_to_state[status];

        /* Handle "Power Denied" type of "Other Fault" */
        if (status == 5) {
            error = (s >> 4) & 0x7;
            if (error == 4)
                kp->denied++;
        } else if (status == 2 || status == 6) {
            kp->class = (s >> 4) & 0x7;
        }

        poe_port_notify_state_change(&kp->kobj);
    }
    return 0;
}

#define STATISTICSGROUP 8

static int
bcm59121_update_port_group_statistics(struct bcm59121 *bcm)
{
    static u8 statport = 0;
    struct poe_dev *poe = bcm->poe;
    u8 rbuf[RECVBUFSIZE];
    int ret, i;
    struct poe_port_kobj *kp;
    unsigned power;

    for (i = 0; i < STATISTICSGROUP && statport < poe->ports; i++) {
        kp = poe->port_kobjs[statport];
        ret = bcm59121_portStatistics(bcm, RECVBUFSIZE, rbuf, statport);
        if (ret < 0) {
            if (error_limit > 0) {
                error_limit--;
                dev_err(&bcm->client->dev, "%s Cannot get port %d statistics %d\n",
                        __func__, statport, ret);
            }
        } else {
            kp->mps_absent += rbuf[3];
            kp->overload += rbuf[4];
            kp->short_counter += rbuf[5];
            kp->invalid_sig_counter += rbuf[7];
        }
        ret = bcm59121_portMeasurement(bcm, RECVBUFSIZE, rbuf, statport);
        if (ret < 0) {
            if (error_limit > 0) {
                error_limit--;
                dev_err(&bcm->client->dev, "%s Cannot get port %d power measurements %d\n",
                    __func__, statport, ret);
            }
        } else {
            power = (rbuf[9] << 8) + rbuf[10];        /* Power in (.1)W */
            kp->power = power * 100;        /* Power in mW */
            if (poe->port_kobjs[statport]->status == PORT_POWER_ON) {
                if (bcm->joule_time_set[statport]) {
                    poe->port_kobjs[statport]->millijoules +=
                        power * jiffies_to_msecs(jiffies - bcm->last_joule_time[statport]) / 10;
                } else
                    bcm->joule_time_set[statport] = 1;
            }
            bcm->last_joule_time[statport] = jiffies;
        }

        if (++statport >= poe->ports)
            statport = 0;
    }
    return 0;
}

static int
bcm59121_update_system_info(struct bcm59121 *bcm)
{
    struct poe_dev *poe = bcm->poe;
    u8 rbuf[RECVBUFSIZE];
    int ret;

    ret = bcm59121_totalPower(bcm, RECVBUFSIZE, rbuf);
    if (ret == 0) {
        poe->total_power = (rbuf[2] << 8) + rbuf[3] * 100;     /* Power in mW */
    }
    return ret;
}

/*
 * bcm59121_init_device - Handle initialization state
 */

static int bcm59121_init_device(struct bcm59121 *bcm)
{
    int ret, i;
    struct poe_dev *poe = bcm->poe;
    struct i2c_client *client = bcm->client;
    struct bcm59121_platform_data *pdata = client->dev.platform_data;
    u8 recvbuf[RECVBUFSIZE];
    struct poe_port_kobj *kp;

    ret = bcm59121_sysstatus(bcm, RECVBUFSIZE, recvbuf);
    if (ret != 0) {
        if (ret != -EREQENXIO) {
            dev_err(&client->dev, "PoE %s Cannot get BCM59121 status - failing %d\n",
                __func__, ret);
            ret = -EBADSYSSTATUS;
        }
        goto out; /* Stop the state machine */
    }

    printk(KERN_INFO "bcm59121 PoE controller %s mode, %s interface, %u ports, map %u,"
            " id 0x%02x%02x\n"
            "        SW ver 0x%x MCU type %u Sys Stat 0x%x Ext SW Version 0x%x\n",
            (recvbuf[2] & 0x2 ? "Auto" : "Semi-auto"), (recvbuf[2] & 0x01 ? "UART" : "I2C"),
            (uint) recvbuf[3], (uint) recvbuf[4], (uint) recvbuf[5],
            (uint) recvbuf[6], (uint) recvbuf[7], (uint) recvbuf[8], (uint) recvbuf[9],
            (uint) recvbuf[10]);

    if (poe) {
        if (bcm->poe->ports !=  recvbuf[3]) {
            dev_err(&client->dev,
                    "PoE %s number of ports changed on reset: was %d now %d - Continuing\n",
                    __func__, bcm->poe->ports, recvbuf[3]);
        }
        /* We will just go on as if nothing happened... */

    } else {
        /* First time through, allocate poe structure */

        poe = poe_allocate_device();
        if (!poe) {
            dev_err(&client->dev, "PoE - Cannot allocate PoE device - Failing\n");
            ret = -ENOMEM;
            goto out;
        }

        poe->ports = recvbuf[3];        /* Save number of ports */
        if (poe->ports == 0) {
            dev_err(&client->dev, "PoE - 0 PoE ports reported by controller - Failing\n");
            poe_free_device(poe);
            ret = -EZEROPORTS;
            goto out;
        }

        dev_set_drvdata(&poe->dev, bcm);
        poe->name = client->name;       /* Let driver know our name */
        poe->controllers = 1;           /* We support one controller */
        poe->power_budget = pdata->power_budget;
        poe->port_base = pdata->port_base; /* And port base */
        poe->dev.parent = &client->dev; /* And our parent driver */
        poe->port_enable = bcm59121_set_enable; /* Enable/disable handler */
        poe->port_stats = bcm59121_get_port_stats; /* Get statistics */
        poe->controller_stats = bcm59121_get_controller_stats; /* Get statistics */
        poe->set_priority = bcm59121_set_priority; /* PoE priority handler */
        poe->set_power_budget = bcm59121_set_power_budget; /* PoE total budget handler */
#ifdef CONFIG_THERMAL
        poe->therm_domain = pdata->therm_domain; /* Set thermal domain */
        poe->temp_warm = pdata->temp_warm; /* Set cooling point */
#endif /* CONFIG_THERMAL */
        poe->ports_per_controller = poe->ports; /* All ports on one controller */
        ret = poe_register_device(poe); /* Now register the poe device */
        if (ret) {
            dev_err(&client->dev, "PoE %s Cannot register PoE device - Failing\n", __func__);
            poe_free_device(poe);
            goto out;
        }
        bcm->poe = poe;                 /* Save pointer to PoE device */
    }

    /* Set to Dynamic Power Management */
    ret = bcm59121_powerManMode(bcm);
    if (ret != 0) {
        dev_err(&client->dev, "PoE %s Cannot set power management mode %d - Continuing\n",
                __func__, poe->power_budget);
    }

    ret = bcm59121_powerSourceConfig(bcm, poe->power_budget / 100);
    if (ret != 0) {
        dev_err(&client->dev, "PoE %s Cannot set power budget %d - Continuing\n",
                __func__, poe->power_budget);
    }

    for (i = 0; i < poe->ports; i++) {
        kp = poe->port_kobjs[i];
        ret = bcm59121_set_priority2(kp, kp->priority, false);
        if (ret != 0)
            dev_err(&client->dev, "PoE %s Cannot set priority %d on port %d - Continuing\n",
            __func__, kp->priority, i);
        ret = bcm59121_set_enable2(kp, kp->enabled, false);
        if (ret != 0)
            dev_err(&client->dev, "PoE %s Cannot %sable port %d - Continuing\n",
            __func__, (kp->enabled ? "En" : "Dis"), i);
    }
    ret = 0;

out:
    return ret;
}

/*
 * bcm59121_do_periodic - Perform periodic functions
 *
 * This routine is called while we are in RUNNING state to perform
 * periodic polling of the device.
 */

static void bcm59121_do_periodic(struct bcm59121 *bcm)
{
    int ret;

    ret = bcm59121_update_port_group_status(bcm);
    ret = bcm59121_update_port_group_statistics(bcm);
    ret = bcm59121_update_system_info(bcm);

    return;
}

/*
 * bcm59121_do_work - Do the work of this driver
 *
 * This is the work queue handler for the driver. Most everything
 * that we do is done here.
 */

static void bcm59121_do_work(struct work_struct *work)
{
    struct bcm59121 *bcm =
        container_of(to_delayed_work(work), struct bcm59121, work);
    struct i2c_client *client = bcm->client;
    int ret;

    mutex_lock(&bcm->lock);

    switch (bcm->state) {
        case BCM59121_STATE_RESET:
            if (bcm->init_retries < 1) {
                dev_err(&client->dev, "Too many reset failures, giving up\n");
                break;
            }
            bcm->init_retries--;
            /* Set Reset to low, asserted, in reset */
            gpio_set_value(bcm->gpio_reset, 0);

            bcm->state = BCM59121_STATE_GPIO_DISABLE;
            /* Wait for the reset to take effect */
            queue_delayed_work(b_wq, &bcm->work, msecs_to_jiffies(BCM59121_RESET_ACTIVE_DELAY));
            break;

        case BCM59121_STATE_GPIO_DISABLE:

            bcm->state = BCM59121_STATE_INITIALIZING;
            /* Set Reset to high, de-asserted, NOT in reset */
            gpio_set_value(bcm->gpio_reset, 1);
            /*
             * At boot-up we need to wait at least 1.5 seconds after either
             *     1. De-asserting the RESET signal (done in
             *          STATE_RESET, above)
             *     2. Issueing a System Reset Command (0x09), which we no
             *          longer do, but may in the future.
             */
            queue_delayed_work(b_wq, &bcm->work, msecs_to_jiffies(BCM59121_RESET_DELAY));
            break;

        case BCM59121_STATE_INITIALIZING:

            ret = bcm59121_init_device(bcm);
            if ((ret == -EBADSYSSTATUS) || (ret == -EZEROPORTS)) {
                bcm->state = BCM59121_STATE_RESET;
                queue_delayed_work(b_wq, &bcm->work, msecs_to_jiffies(BCM59121_RETRY_INIT_DELAY));
                break;
            } else if (ret != 0) {
                dev_err(&client->dev, "PoE - Initialization Error - Failing\n");
                break;
            }

            /* Since we've gotten this far, allow more reset retries */
            bcm->init_retries = BCM59121_RESET_RETRIES;
            bcm->state = BCM59121_STATE_RUNNING;
            printk(KERN_INFO "PoE - Controller Running\n");
            /* Fall Through */

        case BCM59121_STATE_RUNNING:
            bcm59121_do_periodic(bcm);
            queue_delayed_work(b_wq, &bcm->work, msecs_to_jiffies(BCM59121_POLL_INTERVAL));
            break;
    }
    mutex_unlock(&bcm->lock);
}

/*
 * bcm59121_set_enable - Set the enabled bit for a port
 *
 * This routine is used to set the enable for a port
 */

static int
bcm59121_set_enable(struct poe_port_kobj *port_kobj, bool enable)
{
    return (bcm59121_set_enable2(port_kobj, enable, true));

}

/*
 * Lock or do not lock?
 */

static int
bcm59121_set_enable2(struct poe_port_kobj *port_kobj, bool enable, bool lockit)
{
    struct poe_dev *poe;
    int port_num = port_kobj->port_num;
    int ret, ret2;
    struct bcm59121 *bcm;

    poe = kobj_to_poe_dev(port_kobj->kobj.parent);
    bcm = dev_get_drvdata(&poe->dev);

    if (enable && port_kobj->enabled) {
        /* if we enable an already enabled port, reset the error reporting limit */
        error_limit = ERROR_LIMIT;
    }

    if (lockit && mutex_lock_interruptible(&bcm->lock) != 0)
        return -1;

    ret = bcm59121_setPSE(bcm, enable, port_num);
    if (ret < 0) {
        dev_err(&bcm->client->dev, "%s setPSE failed: %d", __func__, ret);
    } else {
        if (enable) {
            ret2 = bcm59121_detectionType(bcm, port_num);
            if (ret2 < 0)
                dev_err(&bcm->client->dev, "%s detectionType failed: %d", __func__, ret2);
        }

        port_kobj->enabled = enable; /* Remember setting */
    }

    port_kobj->substatus = 0;   /* Always 0 */

    if (lockit)
        mutex_unlock(&bcm->lock);

    return ret;
}

/* Port Status "Status Byte 1" to string */

char *
st12str(u8 stat1)
{
    switch(stat1) {
    case 0: return "Disabled";
    case 1: return "Searching";
    case 2: return "Delivering";
    case 3: return "Test Mode";
    case 4: return "Fault";
    case 5: return "Other Fault";
    case 6: return "Requesting Power";
    default: return "Unknown";
    }
}

char *
st22str(u8 stat2)
{
    switch(stat2) {
    case 0: return "OVLO";
    case 1: return "MPS Absent";
    case 2: return "Short";
    case 3: return "Overload";
    case 4: return "Power Denied";
    case 5: return "Thermal Shutdown";
    case 6: return "Startup Failure";
    case 7: return "UVLO";
    default: return "Unknown";
    }
}

char *
stPSE2str(u8 statPSE)
{
    switch(statPSE) {
    case 0: return "Disabled";
    case 1: return "Enabled";
    case 2: return "Teset mode";
    case 3: return "Reserved";
    default: return "Unknown";
    }
}

static int
bcm59121_get_port_stats(struct poe_port_kobj *port_kobj, ssize_t size, char *buf)
{
    struct poe_dev *poe;
    int port_num = port_kobj->port_num;
    int ret, i = 0;
    struct bcm59121 *bcm;
    u8 rxbuf[RECVBUFSIZE];
    struct poe_port_kobj *kp;

    poe = kobj_to_poe_dev(port_kobj->kobj.parent);
    bcm = dev_get_drvdata(&poe->dev);

    if (mutex_lock_interruptible(&bcm->lock) != 0)
        return -1;

    ret = bcm59121_portStatusQuery(bcm, RECVBUFSIZE, rxbuf, port_num);
    if (ret == 0) {
        i += scnprintf(&buf[i], size - i,
            "Port status %d    : %s, Fault Type %s, PD Class %x PD Type %x Mask %x "
            "Power Mode %s;  (.. %x %x %x)\n",
            rxbuf[2], st12str(rxbuf[3]), st22str(rxbuf[4]), rxbuf[5],
            rxbuf[6], rxbuf[7], (rxbuf[8] ? "high" : "low"), rxbuf[9], rxbuf[10], rxbuf[11]);
    }
    kp = poe->port_kobjs[port_num];
    i += scnprintf(&buf[i], size - i,
        "Port Statistics %d: MPS Absent %d, Overload %d Short %d Power Denied %d "
        "Invalid Signature %d\n",
        port_num, kp->mps_absent, kp->overload, kp->short_counter,
        kp->denied, kp->invalid_sig_counter);
    ret = bcm59121_portConfig(bcm, RECVBUFSIZE, rxbuf, port_num);
    if (ret == 0) {
        i += scnprintf(&buf[i], size - i,
            "Port Config %d    : PSE %s, Auto %sabled, Detection %x Classif %x"
            " Disconnect %x Pair 0x%x ( ... %x %x %x)\n",
            rxbuf[2], stPSE2str(rxbuf[3]), (rxbuf[4] ? "En" : "Dis"), rxbuf[5],
            rxbuf[6], rxbuf[7], rxbuf[8], rxbuf[9], rxbuf[10], rxbuf[11]);
    }
    ret = bcm59121_portExtConfig(bcm, RECVBUFSIZE, rxbuf, port_num);
    if (ret == 0) {
        i += scnprintf(&buf[i], size - i,
            "Port ExtConfig %d : Power Mode %s, Violation Type %x Max Power %d"
            " Priority %x Physical Port %d (... %x %x %x %x)\n",
            rxbuf[2], (rxbuf[3] ? "Normal" : "High Power"), rxbuf[4], rxbuf[5],
            rxbuf[6], rxbuf[7], rxbuf[8], rxbuf[9], rxbuf[10], rxbuf[11]);
    }
    mutex_unlock(&bcm->lock);
    return i;
}

static int
bcm59121_get_controller_stats(struct poe_controller_kobj *kobj, ssize_t size, char *buf)
{
    struct poe_dev *poe;
    int ret, i = 0, r;
    struct bcm59121 *bcm;
    u8 rxbuf[RECVBUFSIZE], mpss;

    poe = kobj->poe_dev;
    bcm = dev_get_drvdata(&poe->dev);

    if (mutex_lock_interruptible(&bcm->lock) != 0)
        return -1;

    ret = bcm59121_sysstatus(bcm, RECVBUFSIZE, rxbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "PoE %s Cannot get BCM59121 status, error %d\n",
            __func__, ret);
        i += scnprintf(&buf[i], size - i, "Failed System Status Query command\n");
    } else {
        i += scnprintf(&buf[i], size - i,
            "bcm59121 PoE controller %s mode, %s interface, %u ports, map %u,"
            " id 0x%02x%02x\n"
            "        SW ver 0x%x MCU type %u Sys Stat 0x%x Ext SW Version 0x%x\n",
            (rxbuf[2] & 0x2 ? "Auto" : "Semi-auto"), (rxbuf[2] & 0x01 ? "UART" : "I2C"),
            (uint) rxbuf[3], (uint) rxbuf[4], (uint) rxbuf[5],
            (uint) rxbuf[6], (uint) rxbuf[7], (uint) rxbuf[8], (uint) rxbuf[9],
            (uint) rxbuf[10]);
    }

    ret = bcm59121_systemExtendedConfig(bcm, RECVBUFSIZE, rxbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "PoE %s Cannot get BCM59121 Extended config status, error %d\n",
                __func__, ret);
        i += scnprintf(&buf[i], size - i, "Failed Extended Configuration Query command\n");
    } else {
        i += scnprintf(&buf[i], size - i,
            "Sys Extended Config: UVLO %d PreAlloc %d Power-up %d Disconnect %d "
            "Double Detection %d OVLO %d\n",
            rxbuf[2], rxbuf[3], rxbuf[4], rxbuf[5], rxbuf[6], rxbuf[7]);
    }

    ret = bcm59121_totalPower(bcm, RECVBUFSIZE, rxbuf);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "PoE %s Cannot get BCM59121 Total Power status, error %d\n",
                __func__, ret);
        i += scnprintf(&buf[i], size - i, "Failed Total Power Query command\n");
    } else {
        i += scnprintf(&buf[i], size - i,
            "Total Power        : Allocated %d  Avail %d MPSM Status 0x%x ICUT/ILIM 0x%x "
            "(... %x %x %x %x)\n",
            (rxbuf[2] << 8) + rxbuf[3], (rxbuf[4] << 8 ) + rxbuf[5],
            rxbuf[6], rxbuf[7], rxbuf[8], rxbuf[9], rxbuf[10], rxbuf[11]);
    }
    for (mpss = 0; mpss < 8; mpss += 2) {
        ret = bcm59121_systemPowerManConfig(bcm, mpss, RECVBUFSIZE, rxbuf);
        if (ret != 0) {
            dev_err(&bcm->client->dev,
                    "PoE %s Cannot get BCM59121 Power Management status for MPSS %d, error %d\n",
                    __func__, mpss, ret);
            i += scnprintf(&buf[i], size - i, "Failed Power Management Query command\n");
        } else {
            i += scnprintf(&buf[i], size - i,
                "Sys Power Mgmt Conf: PM Mode 0x%x; MPSS %d Power %d Guard %d; "
                "MPSS %d Power %d Guard %d\n",
                rxbuf[2], rxbuf[1], (rxbuf[3] << 8) + rxbuf[4], (rxbuf[5] << 8) + rxbuf[6],
                rxbuf[1] + 1, (rxbuf[7] << 8) + rxbuf[8], (rxbuf[9] << 8) + rxbuf[10]);
        }
    }

    i += scnprintf(&buf[i], size - i,
            "I2C writes         : Total %d, EIO %d, ENOENT %d, ENXIO %d\n",
            bcm59121_stats.writeCommands, bcm59121_stats.writeEIOerrors,
            bcm59121_stats.writeENOENTerrors, bcm59121_stats.writeENXIOerrors);

    i += scnprintf(&buf[i], size - i, "I2C reads          : All 0xFF %d; System Resets: %d\n",
            bcm59121_stats.readAllFF, bcm59121_stats.sysResets);
    i += scnprintf(&buf[i], size - i, "Command Retries    :");
    for (r = 0; r < COMMAND_RETRIES; r++) {
        i += scnprintf(&buf[i], size - i, " %d-%d", r, bcm59121_stats.cmd_retries[r]);
    }
    i += scnprintf(&buf[i], size - i, " FAIL-%d\n", bcm59121_stats.cmd_fail);

    mutex_unlock(&bcm->lock);
    return i;
}

/*
 * bcm59121_set_priority - Set the priority of a port
 *
 * This routine is used to set the priority of a port
 */

static int
bcm59121_set_priority(struct poe_port_kobj *port_kobj, int priority)
{
    return(bcm59121_set_priority2(port_kobj, priority, true));
}

/*
 * Lock or do not lock?
 */

static int
bcm59121_set_priority2(struct poe_port_kobj *port_kobj, int priority, bool lockit)
{
    struct poe_dev *poe;
    struct bcm59121 *bcm;
    u8 port_num = port_kobj->port_num;
    u8 reg_prio;
    int ret;

    poe = kobj_to_poe_dev(port_kobj->kobj.parent);
    bcm = dev_get_drvdata(&poe->dev);

    if (priority == PORT_PRIORITY_CRITICAL)
        reg_prio = 3;
    else if (priority == PORT_PRIORITY_HIGH)
        reg_prio = 2;
    else if (priority == PORT_PRIORITY_LOW)
        reg_prio = 0;
    else
        return -EINVAL;

    if (lockit && mutex_lock_interruptible(&bcm->lock) != 0)
        return -1;

    port_kobj->priority = priority; /* Remember setting */
    ret = bcm59121_setPortPriority(bcm, reg_prio, port_num);

    if (lockit)
        mutex_unlock(&bcm->lock);
    return ret;
}

/*
 * bcm59121_set_power_budget - Set the power budget for the entire system
 *
 * This routine is used to notify the driver that more or less power
 * is available.
 */

static int
bcm59121_set_power_budget(struct poe_dev *poe, unsigned int power_mw)
{
    int ret;
    struct bcm59121 *bcm = dev_get_drvdata(&poe->dev);

    if (mutex_lock_interruptible(&bcm->lock) != 0)
        return -1;

    ret = bcm59121_powerSourceConfig(bcm, power_mw / 100);
    if (ret != 0) {
        dev_err(&bcm->client->dev, "%s failed: %d", __func__, ret);
    }

    poe->power_budget = power_mw;
    mutex_unlock(&bcm->lock);
    return ret;
}

/*
 * Called when a bcm59121 device is matched with this driver
 */

static int bcm59121_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
    struct bcm59121 *bcm;
    struct bcm59121_platform_data *pdata = client->dev.platform_data;
    int ret;

    bcm = kzalloc(sizeof(struct bcm59121), GFP_KERNEL);
    if (!bcm)
        return -ENOMEM;

    bcm->client = client;
    bcm->gpio_disable = pdata->gpio_disable;
    bcm->gpio_reset = pdata->gpio_reset;
    bcm->logic_low = pdata->logic_low;
    bcm->seq = 0;

    /* Claim PoE Disable GPIO */
    ret = gpio_request(bcm->gpio_disable, "BCM59121 disable");
    if (ret < 0) {
        dev_err(&client->dev,
                "PoE unable to allocate disable GPIO %d for BCM59121\n", pdata->gpio_disable);
        ret = -ENODEV;
        goto errout0;
    }
    ret = gpio_direction_output(bcm->gpio_disable, 1);
    if (ret < 0) {
        dev_err(&client->dev,
                "PoE unable to set direction disable GPIO %d for BCM59121\n", bcm->gpio_disable);
        ret = -ENODEV;
        goto errout1;
    }

    /* Claim PoE Reset GPIO */
    ret = gpio_request(bcm->gpio_reset, "BCM59121 reset");
    if (ret < 0) {
        dev_err(&client->dev,
                "PoE unable to allocate reset GPIO %d for BCM59121\n", pdata->gpio_reset);
        ret = -ENODEV;
        goto errout1;
    }
    /* Set direction of gpio_reset and initial value (low, asserted, in reset) */
    ret = gpio_direction_output(bcm->gpio_reset, 0);
    if (ret < 0) {
        dev_err(&client->dev,
                "PoE unable to set direction reset GPIO %d for BCM59121\n", bcm->gpio_reset);
        ret = -ENODEV;
        goto errout2;
    }

    mutex_init(&bcm->lock);
    INIT_DELAYED_WORK(&bcm->work, bcm59121_do_work);
    b_wq = create_singlethread_workqueue("bcm59121");
    if (b_wq == NULL) {
        ret = -ENOMEM;
        goto errout2;
    }
    i2c_set_clientdata(client, bcm);

    bcm->state = BCM59121_STATE_RESET; /* We are in reset pending state */
    bcm->init_retries = BCM59121_RESET_RETRIES;
    bcm59121_do_work(&bcm->work.work); /* Start the state machine */

    return 0;

errout2:
    gpio_free(bcm->gpio_reset);
errout1:
    gpio_free(bcm->gpio_disable);
errout0:
    kfree(bcm);
    return ret;
}

static int bcm59121_remove(struct i2c_client *client)
{
    struct bcm59121 *bcm = i2c_get_clientdata(client);

    cancel_delayed_work(&bcm->work); /* Ensure no work is pending */
    gpio_free(bcm->gpio_disable);  /* Free the GPIO */
    poe_unregister_device(bcm->poe); /* Unregister the PoE device */
    kfree(bcm);

    return 0;
}

static const struct i2c_device_id bcm59121_id[] = {
    { "bcm59121", 0 },
    { }
};

static struct i2c_driver bcm59121_driver = {
    .driver = {
        .name = "bcm59121",
    },
    .probe = bcm59121_probe,
    .remove = bcm59121_remove,
    .id_table = bcm59121_id,
};

module_i2c_driver(bcm59121_driver);

MODULE_AUTHOR("Kevin Paul Herbert <kph@meraki.com>");
MODULE_AUTHOR("Dean Thomas <dean@meraki.com>");
MODULE_DESCRIPTION("BCM59121 auto-mode PoE driver");
MODULE_LICENSE("GPL");
