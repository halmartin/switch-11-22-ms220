/*
 * $Copyright Open Broadcom Corporation$
 */


#ifndef _IPROC_MDIO_DEV_H
#define _IPROC_MDIO_DEV_H

/* IOCTL commands */

#define MDIO_IOC_MAGIC       'm'

struct mdio_ioc_transfer {
    uint8_t   pa; /* phy address */
    uint8_t   ra; /* register address */
    uint16_t  tx_buf;
    uint16_t  rx_buf;
};

#define MDIO_MSGSIZE(N) \
	((((N)*(sizeof (struct mdio_ioc_transfer))) < (1 << _IOC_SIZEBITS)) \
		? ((N)*(sizeof (struct mdio_ioc_transfer))) : 0)

#define MDIO_IOC_MESSAGE(N) _IOW(MDIO_IOC_MAGIC, 0, char[MDIO_MSGSIZE(N)])

#define MDIO_IOC_EXTERNAL_R_REG _IOWR(MDIO_IOC_MAGIC, 0, char[MDIO_MSGSIZE(1)])
#define MDIO_IOC_EXTERNAL_W_REG _IOW(MDIO_IOC_MAGIC, 1, char[MDIO_MSGSIZE(1)])
#define MDIO_IOC_LOCAL_R_REG _IOWR(MDIO_IOC_MAGIC, 2, char[MDIO_MSGSIZE(1)])
#define MDIO_IOC_LOCAL_W_REG _IOW(MDIO_IOC_MAGIC, 3, char[MDIO_MSGSIZE(1)])


#endif
