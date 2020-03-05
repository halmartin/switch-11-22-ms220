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
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/version.h>

#define DBG(...) /* */

/*
 * Interrupts
 */

#define QSPI_INTR_COUNT                              (7)

#define QSPI_INTR_MSPI_HALTED_MASK                  (0x00000040)
#define QSPI_INTR_MSPI_DONE_MASK                    (0x00000020)
#define QSPI_INTR_BSPI_LR_OVERREAD_MASK             (0x00000010)
#define QSPI_INTR_BSPI_LR_SESSION_DONE_MASK         (0x00000008)
#define QSPI_INTR_BSPI_LR_IMPATIENT_MASK            (0x00000004)
#define QSPI_INTR_BSPI_LR_SESSION_ABORTED_MASK      (0x00000002)
#define QSPI_INTR_BSPI_LR_FULLNESS_REACHED_MASK     (0x00000001)

#define BSPI_LR_INTERRUPTS_DATA               \
    (QSPI_INTR_BSPI_LR_SESSION_DONE_MASK    | \
     QSPI_INTR_BSPI_LR_FULLNESS_REACHED_MASK)

#define BSPI_LR_INTERRUPTS_ERROR              \
    (QSPI_INTR_BSPI_LR_OVERREAD_MASK        | \
     QSPI_INTR_BSPI_LR_IMPATIENT_MASK       | \
     QSPI_INTR_BSPI_LR_SESSION_ABORTED_MASK)

#define BSPI_LR_INTERRUPTS_ALL                \
    (BSPI_LR_INTERRUPTS_ERROR               | \
     BSPI_LR_INTERRUPTS_DATA)

#define SPBR_MIN                    8U
#define SPBR_MAX                    255U
#define DEFAULT_SPEED_HZ            25000000UL

/*
 * Flash opcode and parameters
 */
#define OPCODE_RDID                 0x9f
#define OPCODE_WREN                 0x06
#define OPCODE_WRDI                 0x04
#define OPCODE_WRR                  0x01
#define OPCODE_RCR                  0x35
#define OPCODE_READ                 0x03
#define OPCODE_RDSR                 0x05
#define OPCODE_WRSR                 0x01
#define OPCODE_RDFSR                0x70
#define OPCODE_FAST_READ            0x0B
#define OPCODE_FAST_READ_4B         0x0C
#define OPCODE_EN4B                 0xB7
#define OPCODE_EX4B                 0xE9
#define OPCODE_BRWR                 0x17

#define BSPI_WIDTH_1BIT             1
#define BSPI_WIDTH_2BIT             2
#define BSPI_WIDTH_4BIT             4

#define BSPI_ADDRLEN_3BYTES         3
#define BSPI_ADDRLEN_4BYTES         4

#define BSPI_FLASH_TYPE_SPANSION    0
#define BSPI_FLASH_TYPE_MACRONIX    1
#define BSPI_FLASH_TYPE_NUMONYX     2
#define BSPI_FLASH_TYPE_SST         3
#define BSPI_FLASH_TYPE_UNKNOWN     -1

/*
 * Register masks/fields/values
 */
#define QSPI_BSPI_RAF_STATUS_FIFO_EMPTY_MASK                (0x00000002)
#define QSPI_BSPI_RAF_CONTROL_START_MASK                    (0x00000001)
#define QSPI_BSPI_RAF_CONTROL_CLEAR_MASK                    (0x00000002)
#define QSPI_BSPI_BPP_ADDR_BPP_SELECT_MASK                  (0x00010000)
#define QSPI_BSPI_BPP_MODE_BPP_MASK                         (0x00000100)
#define QSPI_BSPI_FLEX_MODE_ENABLE_MASK                     (0x00000001)


/*
 * Module parameters
 */

/* Mulit I/O for read: 0 - single, 1 - dual, 2 - quad */
#ifdef CONFIG_IPROC_QSPI_SINGLE_MODE
static int io_mode = 0;
#else /* !CONFIG_IPROC_QSPI_SINGLE_MODE */
#ifdef CONFIG_IPROC_QSPI_DUAL_MODE
static int io_mode = 1;
#else /* !CONFIG_IPROC_QSPI_DUAL_MODE */
static int io_mode = 2;
#endif /* !CONFIG_IPROC_QSPI_DUAL_MODE */
#endif /* !CONFIG_IPROC_QSPI_SINGLE_MODE */
module_param(io_mode, int, 0444);

/* Multi I/O for address (only if not in single mode) */
#ifdef CONFIG_IPROC_QSPI_MULTI_LANE_ADDR
static int addr_multi = 1;
#else /* !CONFIG_IPROC_QSPI_MULTI_LANE_ADDR */
static int addr_multi = 0;
#endif /* !CONFIG_IPROC_QSPI_MULTI_LANE_ADDR */
module_param(addr_multi, int, 0444);

/* Read opcode (only if not in single mode) */
#ifdef CONFIG_IPROC_QSPI_SINGLE_MODE
static int read_opcode = OPCODE_FAST_READ;
#else /* !CONFIG_IPROC_QSPI_SINGLE_MODE */
static int read_opcode = CONFIG_IPROC_QSPI_READ_CMD;
#endif /* !CONFIG_IPROC_QSPI_SINGLE_MODE */
module_param(read_opcode, int, 0444);

/* Dummy cycles for read (only if not in single mode) */
#ifdef CONFIG_IPROC_QSPI_SINGLE_MODE
static int dummy_cycles = 8;
#else /* !CONFIG_IPROC_QSPI_SINGLE_MODE */
static int dummy_cycles = CONFIG_IPROC_QSPI_READ_DUMMY_CYCLES;
#endif /* !CONFIG_IPROC_QSPI_SINGLE_MODE */
module_param(dummy_cycles, int, 0444);

/* Max SPI clock HZ */
static int max_hz = 0;
module_param(max_hz, int, 0444);

/* Spansion high performance mode */
static int bspi_hp;
module_param(bspi_hp, int, 0444);

struct bcmspi_parms {
    u32           speed_hz;
    u8            chip_select;
    u8            mode;
    u8            bits_per_word;
};

struct position {
    struct spi_message      *msg;
    struct spi_transfer     *trans;
    int                     byte;
    int                     mspi_16bit;
};

#define NUM_TXRAM        32
#define NUM_RXRAM        32
#define NUM_CDRAM        16

struct bcm_mspi_hw {
    u32             spcr0_lsb;               /* 0x000 */
    u32             spcr0_msb;               /* 0x004 */
    u32             spcr1_lsb;               /* 0x008 */
    u32             spcr1_msb;               /* 0x00c */
    u32             newqp;                   /* 0x010 */
    u32             endqp;                   /* 0x014 */
    u32             spcr2;                   /* 0x018 */
    u32             reserved0;               /* 0x01c */
    u32             mspi_status;             /* 0x020 */
    u32             cptqp;                   /* 0x024 */
    u32             reserved1[6];            /* 0x028 */
    u32             txram[NUM_TXRAM];        /* 0x040 */
    u32             rxram[NUM_RXRAM];        /* 0x0c0 */
    u32             cdram[NUM_CDRAM];        /* 0x140 */
    u32             write_lock;              /* 0x180 */
    u32             disable_flush_gen;       /* 0x184 */
};

struct bcm_bspi_hw {
    u32             revision_id;             /* 0x000 */
    u32             scratch;                 /* 0x004 */
    u32             mast_n_boot_ctrl;        /* 0x008 */
    u32             busy_status;             /* 0x00c */
    u32             intr_status;             /* 0x010 */
    u32             b0_status;               /* 0x014 */
    u32             b0_ctrl;                 /* 0x018 */
    u32             b1_status;               /* 0x01c */
    u32             b1_ctrl;                 /* 0x020 */
    u32             strap_override_ctrl;     /* 0x024 */
    u32             flex_mode_enable;        /* 0x028 */
    u32             bits_per_cycle;          /* 0x02C */
    u32             bits_per_phase;          /* 0x030 */
    u32             cmd_and_mode_byte;       /* 0x034 */
    u32             flash_upper_addr_byte;   /* 0x038 */
    u32             xor_value;               /* 0x03C */
    u32             xor_enable;              /* 0x040 */
    u32             pio_mode_enable;         /* 0x044 */
    u32             pio_iodir;               /* 0x048 */
    u32             pio_data;                /* 0x04C */
};

struct bcm_bspi_raf {
    u32             start_address;           /* 0x00 */
    u32             num_words;               /* 0x04 */
    u32             ctrl;                    /* 0x08 */
    u32             fullness;                /* 0x0C */
    u32             watermark;               /* 0x10 */
    u32             status;                  /* 0x14 */
    u32             read_data;               /* 0x18 */
    u32             word_cnt;                /* 0x1C */
    u32             curr_addr;               /* 0x20 */
};

struct bcm_idm_qspi_ctrl {
    u32            io_ctrl_direct;
};

struct bcm_cru_control {
    u32            cru_control;
};

struct bcm_flex_mode {
    int            width;
    int            addrlen;
    int            hp;
};

#define STATE_IDLE          0
#define STATE_RUNNING       1
#define STATE_SHUTDOWN      2

struct bcmspi_priv {
    struct platform_device              *pdev;
    struct spi_master                   *master;
    spinlock_t                          lock;
    struct bcmspi_parms                 last_parms;
    struct position                     pos;
    struct list_head                    msg_queue;
    int                                 state;
    int                                 outstanding_bytes;
    int                                 next_udelay;
    int                                 cs_change;
    struct clk                          *clk;
    unsigned int                        mspi_refclk;
    unsigned int                        max_speed_hz;
    volatile struct bcm_mspi_hw         *mspi_hw;
    int                                 irq;
    struct tasklet_struct               tasklet;
    int                                 curr_cs;

    /* BSPI */
    volatile struct bcm_bspi_hw         *bspi_hw;
    volatile struct bcm_cru_control     *cru_hw;
    int                                 bspi_enabled;
    /* all chip selects controlled by BSPI */
    int                                 bspi_chip_select;

    /* LR */
    volatile struct bcm_bspi_raf        *bspi_hw_raf;
    struct spi_transfer                 *cur_xfer;
    u32                                 cur_xfer_idx;
    u32                                 cur_xfer_len;
    u32                                 xfer_status;
    struct spi_message                  *cur_msg;
    u32                                 actual_length;
    u32                                 raf_next_addr;
    u32                                 raf_next_len;

    /* Interrupts */
    volatile u32                        *qspi_intr;
    volatile struct bcm_idm_qspi_ctrl   *idm_qspi;

    /* current flex mode settings */
    struct bcm_flex_mode                flex_mode;
};

static void bcmspi_enable_interrupt(struct bcmspi_priv *priv, u32 mask)
{
    priv->idm_qspi->io_ctrl_direct |= cpu_to_le32(mask << 2);
}

static void bcmspi_disable_interrupt(struct bcmspi_priv *priv, u32 mask)
{
    priv->idm_qspi->io_ctrl_direct &= cpu_to_le32(~(mask << 2));
}

static void bcmspi_clear_interrupt(struct bcmspi_priv *priv, u32 mask)
{
    int i;

    for(i=0; i<QSPI_INTR_COUNT; i++) {
        if (mask & (1UL << i)) {
            priv->qspi_intr[i] = cpu_to_le32(1);
        }
    }
}

static u32 bcmspi_read_interrupt(struct bcmspi_priv *priv)
{
    int i;
    u32 status = 0;

    for(i=0; i<QSPI_INTR_COUNT; i++) {
        if (priv->qspi_intr[i] & cpu_to_le32(1)) {
            status |= 1UL << i;
        }
    }

    return status;
}

static void bcmspi_flush_prefetch_buffers(struct bcmspi_priv *priv)
{
    priv->bspi_hw->b0_ctrl = 0;
    priv->bspi_hw->b1_ctrl = 0;
    priv->bspi_hw->b0_ctrl = cpu_to_le32(1);
    priv->bspi_hw->b1_ctrl = cpu_to_le32(1);
}

static int bcmspi_lr_is_fifo_empty(struct bcmspi_priv *priv)
{
    return priv->bspi_hw_raf->status & cpu_to_le32(QSPI_BSPI_RAF_STATUS_FIFO_EMPTY_MASK);
}

static inline u32 bcmspi_lr_read_fifo(struct bcmspi_priv *priv)
{
    /* for performance reasons return the raw data, rather than
     * byte-swapped data.  This works because the caller writes
     * values 32-bits at a time to the destination buffer, giving
     * an automatic byte-swap on big-endian machines. */

    return priv->bspi_hw_raf->read_data;
}

static inline void bcmspi_lr_start(struct bcmspi_priv *priv)
{
    priv->bspi_hw_raf->ctrl = cpu_to_le32(QSPI_BSPI_RAF_CONTROL_START_MASK);
}

static inline void bcmspi_lr_clear(struct bcmspi_priv *priv)
{
    priv->bspi_hw_raf->ctrl = cpu_to_le32(QSPI_BSPI_RAF_CONTROL_CLEAR_MASK);
    bcmspi_flush_prefetch_buffers(priv);
}

static inline int bcmspi_is_4_byte_mode(struct bcmspi_priv *priv)
{
    return priv->flex_mode.addrlen == BSPI_ADDRLEN_4BYTES;
}

static int bcmbspi_flash_type(struct bcmspi_priv *priv);

static int bcmspi_set_flex_mode(struct bcmspi_priv *priv,
    int width, int addrlen, int hp)
{
    int bpc = 0, bpp = dummy_cycles, command = read_opcode;
    int flex_mode = 1, error = 0;

    switch (width) {
    case BSPI_WIDTH_1BIT:
        if (addrlen == BSPI_ADDRLEN_3BYTES) {
            /* default mode, does not need flex_cmd */
            flex_mode = 0;
        } else {
            bpp = 8; /* dummy cycles */
            if (bcmbspi_flash_type(priv) == BSPI_FLASH_TYPE_SPANSION)
                command = OPCODE_FAST_READ_4B;
            else
                command = OPCODE_FAST_READ;
        }
        break;
    case BSPI_WIDTH_2BIT:
        bpc = 0x00000001; /* only data is 2-bit */
        if (addr_multi) {
            bpc |= 0x00010000;
        }
        if (hp) {
            bpc |= 0x00010100; /* address and mode are 2-bit too */
            bpp |= QSPI_BSPI_BPP_MODE_BPP_MASK;
        }
        break;
    case BSPI_WIDTH_4BIT:
        bpc = 0x00000002; /* only data is 4-bit */
        if (addr_multi) {
            bpc |= 0x00020000;
        }
        if (hp) {
            bpc |= 0x00020200; /* address and mode are 4-bit too */
            bpp |= QSPI_BSPI_BPP_MODE_BPP_MASK;
        }
        break;
    default:
        error = 1;
        break;
    }

    if (addrlen == BSPI_ADDRLEN_4BYTES) {
        bpp |= QSPI_BSPI_BPP_ADDR_BPP_SELECT_MASK;
    }

    if (!error) {
        priv->bspi_hw->flex_mode_enable = 0;
        priv->bspi_hw->bits_per_cycle = cpu_to_le32(bpc);
        priv->bspi_hw->bits_per_phase = cpu_to_le32(bpp);
        priv->bspi_hw->cmd_and_mode_byte = cpu_to_le32(command);
        priv->bspi_hw->flex_mode_enable = flex_mode ?
            cpu_to_le32(QSPI_BSPI_FLEX_MODE_ENABLE_MASK)
            : 0;
        DBG("%s: width=%d addrlen=%d hp=%d\n",
            __func__, width, addrlen, hp);
        DBG("%s: fme=%08x bpc=%08x bpp=%08x cmd=%08x\n", __func__,
            le32_to_cpu(priv->bspi_hw->flex_mode_enable),
            le32_to_cpu(priv->bspi_hw->bits_per_cycle),
            le32_to_cpu(priv->bspi_hw->bits_per_phase),
            le32_to_cpu(priv->bspi_hw->cmd_and_mode_byte));
    }

    return error;
}

static void bcmspi_set_mode(struct bcmspi_priv *priv,
    int width, int addrlen, int hp)
{
    int error = 0;
    int show_info = 0;

    if ((width != -1 && width != priv->flex_mode.width) ||
        (hp != -1 && hp != priv->flex_mode.hp)) {
        /* Don't print things if only for address mode change because it
         * could be very frequent. */
        show_info = 1;
    }
    if (width == -1)
        width = priv->flex_mode.width;
    if (addrlen == -1)
        addrlen = priv->flex_mode.addrlen;
    if (hp == -1)
        hp = priv->flex_mode.hp;

    error = bcmspi_set_flex_mode(priv, width, addrlen, hp);

    if (!error) {
        priv->flex_mode.width = width;
        priv->flex_mode.addrlen = addrlen;
        priv->flex_mode.hp = hp;
        if (show_info) {
            dev_info(&priv->pdev->dev,
                "%d-lane output, %d-byte address%s\n",
                priv->flex_mode.width,
                priv->flex_mode.addrlen,
                priv->flex_mode.hp ? ", high-performance mode" : "");
        }
    } else
        dev_warn(&priv->pdev->dev,
            "INVALID COMBINATION: width=%d addrlen=%d hp=%d\n",
            width, addrlen, hp);
}

static void bcmspi_set_chip_select(struct bcmspi_priv *priv, int cs)
{
    if (priv->curr_cs != cs) {
        DBG("Switching CS%1d => CS%1d\n",
            priv->curr_cs, cs);

        /* We don't have multiple chip selects for now */
    }
    priv->curr_cs = cs;

}

static inline int is_bspi_chip_select(struct bcmspi_priv *priv, u8 cs)
{
    return priv->bspi_chip_select & (1 << cs);
}

static void bcmspi_disable_bspi(struct bcmspi_priv *priv)
{
    int i;

    if (!priv->bspi_hw || !priv->bspi_enabled)
        return;
    if ((priv->bspi_hw->mast_n_boot_ctrl & cpu_to_le32(1)) == 1) {
        priv->bspi_enabled = 0;
        return;
    }

    DBG("disabling bspi\n");
    for (i = 0; i < 1000; i++) {
        if ((priv->bspi_hw->busy_status & cpu_to_le32(1)) == 0) {
            priv->bspi_hw->mast_n_boot_ctrl = cpu_to_le32(1);
            priv->bspi_enabled = 0;
            udelay(1);
            return;
        }
        udelay(1);
    }
    dev_warn(&priv->pdev->dev, "timeout setting MSPI mode\n");
}

static void bcmspi_enable_bspi(struct bcmspi_priv *priv)
{
    if (!priv->bspi_hw || priv->bspi_enabled)
        return;
    if ((priv->bspi_hw->mast_n_boot_ctrl & cpu_to_le32(1)) == 0) {
        priv->bspi_enabled = 1;
        return;
    }

    DBG("enabling bspi\n");
    priv->bspi_hw->mast_n_boot_ctrl = 0;
    priv->bspi_enabled = 1;
}

static void bcmspi_hw_set_parms(struct bcmspi_priv *priv,
    const struct bcmspi_parms *xp)
{
    if (xp->speed_hz) {
        unsigned int spbr = priv->mspi_refclk / (2 * xp->speed_hz);

        priv->mspi_hw->spcr0_lsb = cpu_to_le32(max(min(spbr, SPBR_MAX), SPBR_MIN));
    } else {
        priv->mspi_hw->spcr0_lsb = cpu_to_le32(SPBR_MIN);
    }

    if (priv->pos.msg == NULL || xp->bits_per_word > 8) {
        /* Global hw init for 16bit spi_transfer */
        int bits = xp->bits_per_word;
        bits = bits? (bits == 16? 0 : bits) : 8;
        priv->mspi_hw->spcr0_msb = cpu_to_le32(0x80 |    /* Master */
            (bits << 2) |
            (xp->mode & 3));
    } else {
        /* Configure for a new 8-bit spi_transfer */
        if (priv->pos.byte == 0) {
            /* Use 16-bit MSPI transfer for performance if applicable */
            if (priv->pos.mspi_16bit ^ (!(priv->pos.trans->len & 1))) {
                /* Update it only if needed */
                priv->pos.mspi_16bit = !priv->pos.mspi_16bit;
                priv->mspi_hw->spcr0_msb = cpu_to_le32(0x80 |    /* Master */
                    ((priv->pos.mspi_16bit? 0 : 8) << 2) |
                    (xp->mode & 3));
            }
        }
    }
    priv->last_parms = *xp;
}

#define PARMS_NO_OVERRIDE       0
#define PARMS_OVERRIDE          1

static int bcmspi_update_parms(struct bcmspi_priv *priv,
    struct spi_device *spidev, struct spi_transfer *trans, int override)
{
    struct bcmspi_parms xp;

    xp.speed_hz = min(trans->speed_hz ? trans->speed_hz :
        (spidev->max_speed_hz ? spidev->max_speed_hz : DEFAULT_SPEED_HZ),
        DEFAULT_SPEED_HZ);
    xp.chip_select = spidev->chip_select;
    xp.mode = spidev->mode;
    xp.bits_per_word = trans->bits_per_word ? trans->bits_per_word :
        (spidev->bits_per_word ? spidev->bits_per_word : 8);

    if ((override == PARMS_OVERRIDE) ||
        ((xp.speed_hz == priv->last_parms.speed_hz) &&
         (xp.chip_select == priv->last_parms.chip_select) &&
         (xp.mode == priv->last_parms.mode) &&
         (xp.bits_per_word == priv->last_parms.bits_per_word))) {
        bcmspi_hw_set_parms(priv, &xp);
        return 0;
    }
    /* no override, and parms do not match */
    return 1;
}


static int bcmspi_setup(struct spi_device *spi)
{
    struct bcmspi_parms *xp;
    struct bcmspi_priv *priv = spi_master_get_devdata(spi->master);
    unsigned int speed_hz;

    DBG("%s\n", __func__);

    if (spi->bits_per_word > 16)
        return -EINVAL;

    /* Module parameter override */
    if (max_hz != 0) {
        speed_hz = max_hz;
    } else {
        speed_hz = spi->max_speed_hz;
    }

    xp = spi_get_ctldata(spi);
    if (!xp) {
        xp = kzalloc(sizeof(struct bcmspi_parms), GFP_KERNEL);
        if (!xp)
            return -ENOMEM;
        spi_set_ctldata(spi, xp);
    }
    if (speed_hz < priv->max_speed_hz)
        xp->speed_hz = speed_hz;
    else
        xp->speed_hz = 0;

    priv->cru_hw->cru_control &= cpu_to_le32(~0x00000006);
    (void)priv->cru_hw->cru_control; /* Need to read back */
    if (speed_hz >= 62500000) {
        priv->cru_hw->cru_control |= cpu_to_le32(0x00000006);
    } else if (speed_hz >= 50000000) {
        priv->cru_hw->cru_control |= cpu_to_le32(0x00000002);
    } else if (speed_hz >= 31250000) {
        priv->cru_hw->cru_control |= cpu_to_le32(0x00000004);
    }
    (void)priv->cru_hw->cru_control; /* Need to read back */

    xp->chip_select = spi->chip_select;
    xp->mode = spi->mode;
    xp->bits_per_word = spi->bits_per_word ? spi->bits_per_word : 8;

    return 0;
}

/* stop at end of transfer, no other reason */
#define FNB_BREAK_NONE              0
/* stop at end of spi_message */
#define FNB_BREAK_EOM               1
/* stop at end of spi_transfer if delay */
#define FNB_BREAK_DELAY             2
/* stop at end of spi_transfer if cs_change */
#define FNB_BREAK_CS_CHANGE         4
/* stop if we run out of bytes */
#define FNB_BREAK_NO_BYTES          8
/* stop at end of spi_transfer */
#define FNB_BREAK_EOT               16

/* events that make us stop filling TX slots */
#define FNB_BREAK_TX            (FNB_BREAK_EOM | FNB_BREAK_DELAY | \
                     FNB_BREAK_CS_CHANGE)

/* events that make us deassert CS */
#define FNB_BREAK_DESELECT        (FNB_BREAK_EOM | FNB_BREAK_CS_CHANGE)


static int find_next_byte(struct bcmspi_priv *priv, struct position *p,
    struct list_head *completed, int flags)
{
    int ret = FNB_BREAK_NONE;

    p->byte++;

    while (p->byte >= p->trans->len) {
        /* we're at the end of the spi_transfer */

        /* in TX mode, need to pause for a delay or CS change */
        if (p->trans->delay_usecs && (flags & FNB_BREAK_DELAY))
            ret |= FNB_BREAK_DELAY;
        if (p->trans->cs_change && (flags & FNB_BREAK_CS_CHANGE))
            ret |= FNB_BREAK_CS_CHANGE;
        if (ret)
            return ret;

        /* advance to next spi_message? */
        if (list_is_last(&p->trans->transfer_list,
                &p->msg->transfers)) {
            struct spi_message *next_msg = NULL;

            /* TX breaks at the end of each message as well */
            if (!completed || (flags & FNB_BREAK_EOM)) {
                DBG("find_next_byte: advance msg exit\n");
                return FNB_BREAK_EOM;
            }
            if (!list_is_last(&p->msg->queue, &priv->msg_queue)) {
                next_msg = list_entry(p->msg->queue.next,
                    struct spi_message, queue);
            }
            /* delete from run queue, add to completion queue */
            list_del(&p->msg->queue);
            list_add_tail(&p->msg->queue, completed);

            p->msg = next_msg;
            p->byte = 0;
            if (p->msg == NULL) {
                p->trans = NULL;
                ret = FNB_BREAK_NO_BYTES;
                break;
            }

            /*
             * move on to the first spi_transfer of the new
             * spi_message
             */
            p->trans = list_entry(p->msg->transfers.next,
                struct spi_transfer, transfer_list);
        } else {
            /* or just advance to the next spi_transfer */
            p->trans = list_entry(p->trans->transfer_list.next,
                struct spi_transfer, transfer_list);
            p->byte = 0;

            /* Separate spi_transfers into MSPI transfers */
            ret = FNB_BREAK_EOT;
        }
    }
    DBG("find_next_byte: msg %p trans %p len %d byte %d ret %x\n",
        p->msg, p->trans, p->trans ? p->trans->len : 0, p->byte, ret);
    return ret;
}

static void read_from_hw(struct bcmspi_priv *priv, struct list_head *completed)
{
    struct position p;
    int slot = 0, n = priv->outstanding_bytes;

    DBG("%s\n", __func__);

    p = priv->pos;

    while (n > 0) {
        BUG_ON(p.msg == NULL);

        if (p.trans->bits_per_word <= 8) {
            u8 *buf = p.trans->rx_buf;

            if (buf) {

                if (p.mspi_16bit) {
                    /* Using 16-bit SPI transfers for performance */
                    buf[p.byte] =
                        le32_to_cpu(priv->mspi_hw->rxram[(slot << 1) + 0]) & 0xff;
                    DBG("RD %02x\n", buf ? buf[p.byte] : 0xff);
                    buf[p.byte + 1] =
                        le32_to_cpu(priv->mspi_hw->rxram[(slot << 1) + 1]) & 0xff;
                    DBG("RD %02x\n", buf ? buf[p.byte + 1] : 0xff);
                } else {
                    buf[p.byte] =
                        le32_to_cpu(priv->mspi_hw->rxram[(slot << 1) + 1]) & 0xff;
                    DBG("RD %02x\n", buf ? buf[p.byte] : 0xff);
                }
            }
        } else {
            u16 *buf = p.trans->rx_buf;

            if (buf) {
                buf[p.byte] =
                    ((le32_to_cpu(priv->mspi_hw->rxram[(slot << 1) + 1]) & 0xff) << 0) |
                    ((le32_to_cpu(priv->mspi_hw->rxram[(slot << 1) + 0] & 0xff)) << 8);
                DBG("RD %04x\n", buf ? buf[p.byte] : 0xffff);
            }
        }
        slot++;
        n--;
        p.msg->actual_length++;
        if (p.mspi_16bit) {
            p.byte++;
            p.msg->actual_length++;
        }

        find_next_byte(priv, &p, completed, FNB_BREAK_NONE);
    }

    priv->pos = p;
    priv->outstanding_bytes = 0;
}

static void write_to_hw(struct bcmspi_priv *priv)
{
    struct position p;
    int slot = 0, fnb = 0;
    struct spi_message *msg = NULL;

    DBG("%s\n", __func__);

    bcmspi_disable_bspi(priv);

    p = priv->pos;

    while (1) {
        if (p.msg == NULL)
            break;
        if (!msg) {
            msg = p.msg;
            bcmspi_update_parms(priv, msg->spi, p.trans,
                PARMS_OVERRIDE);
        } else {
            /* break if the speed, bits, etc. changed */
            if (bcmspi_update_parms(priv, msg->spi, p.trans,
                PARMS_NO_OVERRIDE)) {
                DBG("parms don't match, breaking\n");
                break;
            }
        }
        if (p.trans->bits_per_word <= 8) {
            const u8 *buf = p.trans->tx_buf;

            priv->mspi_hw->txram[slot << 1] =
                    cpu_to_le32(buf ? (buf[p.byte] & 0xff) : 0xff);
            DBG("WR %02x\n", buf ? buf[p.byte] : 0xff);

            if (priv->pos.mspi_16bit) {
                /* Using 16-bit SPI transfers for performance */
                p.byte++;
                priv->mspi_hw->txram[(slot << 1) + 1] =
                        cpu_to_le32(buf ? (buf[p.byte] & 0xff) : 0xff);
                DBG("WR %02x\n", buf ? buf[p.byte] : 0xff);
                priv->mspi_hw->cdram[slot] = cpu_to_le32(0xce);
            } else {
                priv->mspi_hw->cdram[slot] = cpu_to_le32(0x8e);
            }

        } else {
            const u16 *buf = p.trans->tx_buf;

            priv->mspi_hw->txram[(slot << 1) + 0] =
                    cpu_to_le32(buf ? (buf[p.byte] >> 8) : 0xff);
            priv->mspi_hw->txram[(slot << 1) + 1] =
                    cpu_to_le32(buf ? (buf[p.byte] & 0xff) : 0xff);
            DBG("WR %04x\n", buf ? buf[p.byte] : 0xffff);
            priv->mspi_hw->cdram[slot] = cpu_to_le32(0xce);
        }
        slot++;

        fnb = find_next_byte(priv, &p, NULL, FNB_BREAK_TX);

        if (fnb & FNB_BREAK_CS_CHANGE)
            priv->cs_change = 1;
        if (fnb & FNB_BREAK_DELAY)
            priv->next_udelay = p.trans->delay_usecs;
        if (fnb || (slot == NUM_CDRAM))
            break;
    }

    if (slot) {
        DBG("submitting %d slots\n", slot);
        priv->mspi_hw->newqp = 0;
        priv->mspi_hw->endqp = cpu_to_le32(slot - 1);

        /* deassert CS on the final byte */
        if (fnb & FNB_BREAK_DESELECT)
            priv->mspi_hw->cdram[slot - 1] &= cpu_to_le32(~0x80);

        /* tell HIF_MSPI which CS to use */
        bcmspi_set_chip_select(priv, msg->spi->chip_select);

        priv->mspi_hw->write_lock = cpu_to_le32(1);
        priv->mspi_hw->spcr2 = cpu_to_le32(0xe0);    /* cont | spe | spifie */

        priv->state = STATE_RUNNING;
        priv->outstanding_bytes = slot;
    } else {
        priv->mspi_hw->write_lock = 0;
        priv->state = STATE_IDLE;
    }
}

#define DWORD_ALIGNED(a)    (!(((unsigned long)(a)) & 3))
#define ACROSS_16MB(a, l)   (((a) ^ ((a) + (l) - 1)) & 0xFF000000)

static int bcmspi_emulate_flash_read(struct bcmspi_priv *priv,
    struct spi_message *msg)
{
    u32 addr, len;
    int idx = 0;            /* Also used for checking continuation */
    unsigned long flags = 0;

    /* Check if it's a continuation */
    if (priv->raf_next_len != 0) {

        /* Continuation (read across 16MB boundary) */
        addr = priv->raf_next_addr;
        len = priv->raf_next_len;

        /* Update upper address byte */
        if (bcmspi_is_4_byte_mode(priv)) {
            priv->bspi_hw->flash_upper_addr_byte = cpu_to_le32(addr & 0xFF000000);
            /* Flush prefecth buffers since upper byte changed */
            bcmspi_flush_prefetch_buffers(priv);
        }

    } else {

        /* It's the first session of this transfer */
        struct spi_transfer *trans;
        u8 *buf;

        /* acquire lock when the MSPI is idle */
        while (1) {
            spin_lock_irqsave(&priv->lock, flags);
            if (priv->state == STATE_IDLE)
                break;
            spin_unlock_irqrestore(&priv->lock, flags);
            if (priv->state == STATE_SHUTDOWN)
                return -EIO;
            udelay(1);
        }
        bcmspi_set_chip_select(priv, msg->spi->chip_select);

        /* first transfer - OPCODE_READ + 3-byte address */
        trans = list_entry(msg->transfers.next, struct spi_transfer,
            transfer_list);
        buf = (void *)trans->tx_buf;

        idx = 1;

        /* Check upper address byte for 4-byte mode */
        if (bcmspi_is_4_byte_mode(priv)) {
            addr = buf[idx++] << 24;
        } else {
            addr = 0;
        }

        /*
         * addr coming into this function is a raw flash offset
         * we need to convert it to the BSPI address
         */
        addr |= (buf[idx] << 16) | (buf[idx+1] << 8) | buf[idx+2];

        /* second transfer - read result into buffer */
        trans = list_entry(msg->transfers.next->next, struct spi_transfer,
            transfer_list);

        buf = (void *)trans->rx_buf;

        len = trans->len;

        /* non-aligned and very short transfers are handled by MSPI */
        if (unlikely(!DWORD_ALIGNED(addr) ||
                 !DWORD_ALIGNED(buf) ||
                 len < sizeof(u32) ||
                 !priv->bspi_hw_raf)) {
            spin_unlock_irqrestore(&priv->lock, flags);
            return -1;
        }

        /* Flush prefetch buffers only if upper address byte changed */
        if ((addr & 0xFF000000) != le32_to_cpu(priv->bspi_hw->flash_upper_addr_byte)) {
            bcmspi_flush_prefetch_buffers(priv);
            /* Update upper address byte */
            priv->bspi_hw->flash_upper_addr_byte = cpu_to_le32(addr & 0xFF000000);
        }

        /* Switching to BSPI */
        bcmspi_enable_bspi(priv);

        DBG("%s: dst %p src %p len %x addr BSPI %06x\n",
            __func__, buf, addr, len, addr);

        /* initialize software parameters */
        priv->xfer_status = 0;
        priv->cur_xfer = trans;
        priv->cur_xfer_idx = 0;
        priv->cur_msg = msg;
        priv->actual_length = idx + 4 + trans->len;
    }

    if (bcmspi_is_4_byte_mode(priv) && ACROSS_16MB(addr, len)) {

        /* Size for the first session */
        u32 bytes = 0x1000000 - (addr & 0x00FFFFFF);

        /* Address and size for remaining sessions */
        priv->raf_next_addr = addr + bytes;
        priv->raf_next_len = len - bytes;

        len = bytes;

    } else {
        priv->raf_next_len = 0;
    }

    /* Length for this session */
    priv->cur_xfer_len = len;

    /* setup hardware */
    /* address must be 4-byte aligned */
    priv->bspi_hw_raf->start_address = cpu_to_le32(addr & 0x00FFFFFF);
    priv->bspi_hw_raf->num_words = cpu_to_le32((len + 3) >> 2);
    priv->bspi_hw_raf->watermark = 0;

    DBG("READ: %08x %08x (%08x)\n", addr, ((len + 3) >> 2), len);

    bcmspi_clear_interrupt(priv, 0xffffffff);
    bcmspi_enable_interrupt(priv, BSPI_LR_INTERRUPTS_ALL);
    bcmspi_lr_start(priv);

    if (idx) {
        spin_unlock_irqrestore(&priv->lock, flags);
    }

    return 0;
}

/*
 * m25p80_read() calls wait_till_ready() before each read to check
 * the flash status register for pending writes.
 *
 * This can be safely skipped if our last transaction was just an
 * emulated BSPI read.
 */
static int bcmspi_emulate_flash_rdsr(struct bcmspi_priv *priv,
    struct spi_message *msg)
{
    u8 *buf;
    struct spi_transfer *trans;

    if (priv->bspi_enabled == 0)
        return 1;

    trans = list_entry(msg->transfers.next->next, struct spi_transfer,
        transfer_list);

    buf = (void *)trans->rx_buf;
    *buf = 0x00;

    msg->actual_length = 2;
    msg->status = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
    spi_finalize_current_message(priv->master);
#else
    msg->complete(msg->context);
#endif

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
static int bcmspi_prepare_transfer(struct spi_master *master)
{
    return 0;
}

static int bcmspi_unprepare_transfer(struct spi_master *master)
{
    return 0;
}
#endif

static int bcmspi_transfer_one(struct spi_master *master, struct spi_message *msg)
{
    struct bcmspi_priv *priv = spi_master_get_devdata(master);
    unsigned long flags;

    DBG("%s\n", __func__);

    if (is_bspi_chip_select(priv, msg->spi->chip_select)) {
        struct spi_transfer *trans;

        trans = list_entry(msg->transfers.next,
            struct spi_transfer, transfer_list);
        if (trans && trans->len && trans->tx_buf) {
            u8 command = ((u8 *)trans->tx_buf)[0];
            switch (command) {
            case OPCODE_FAST_READ:
                if (bcmspi_emulate_flash_read(priv, msg) == 0)
                    return 0;
                break;
            case OPCODE_RDSR:
                if (bcmspi_emulate_flash_rdsr(priv, msg) == 0)
                    return 0;
                break;
            case OPCODE_EN4B:
                DBG("ENABLE 4-BYTE MODE\n");
                bcmspi_set_mode(priv, -1, BSPI_ADDRLEN_4BYTES, -1);
                break;
            case OPCODE_EX4B:
                DBG("DISABLE 4-BYTE MODE\n");
                bcmspi_set_mode(priv, -1, BSPI_ADDRLEN_3BYTES, -1);
                break;
            case OPCODE_BRWR:
                {
                    u8 enable = ((u8 *)trans->tx_buf)[1];
                    DBG("%s 4-BYTE MODE\n", enable ? "ENABLE" : "DISABLE");
                    bcmspi_set_mode(priv, -1,
                        enable ? BSPI_ADDRLEN_4BYTES :
                        BSPI_ADDRLEN_3BYTES, -1);
                }
                break;
            default:
                break;
            }

            /* Mark prefetch buffers dirty (by using upper byte) if needed */
            switch(command) {
            case OPCODE_RDID:
            case OPCODE_WREN:
            case OPCODE_WRDI:
            case OPCODE_RCR:
            case OPCODE_READ:
            case OPCODE_RDSR:
            case OPCODE_WRSR:
            case OPCODE_RDFSR:
            case OPCODE_FAST_READ:
            case OPCODE_FAST_READ_4B:
            case OPCODE_EN4B:
            case OPCODE_EX4B:
            case OPCODE_BRWR:
                /* These are known opcodes that are not writing/erasing */
                break;
            default:
                /* Could be writing/erasing; mark buffers dirty */
                priv->bspi_hw->flash_upper_addr_byte = cpu_to_le32(0xff000000);
                break;
            }
        }
    }

    spin_lock_irqsave(&priv->lock, flags);

    if (priv->state == STATE_SHUTDOWN) {
        spin_unlock_irqrestore(&priv->lock, flags);
        return -EIO;
    }

    msg->actual_length = 0;

    list_add_tail(&msg->queue, &priv->msg_queue);

    if (priv->state == STATE_IDLE) {
        BUG_ON(priv->pos.msg != NULL);
        priv->pos.msg = msg;
        priv->pos.trans = list_entry(msg->transfers.next,
            struct spi_transfer, transfer_list);
        priv->pos.byte = 0;

        write_to_hw(priv);
    }
    spin_unlock_irqrestore(&priv->lock, flags);

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
static int bcmspi_transfer(struct spi_device *spi, struct spi_message *msg)
{
    return bcmspi_transfer_one(spi->master, msg);
}
#endif

static void bcmspi_cleanup(struct spi_device *spi)
{
    struct bcmspi_parms *xp = spi_get_ctldata(spi);

    DBG("%s\n", __func__);

    kfree(xp);
}

static irqreturn_t bcmspi_interrupt(int irq, void *dev_id)
{
    struct bcmspi_priv *priv = dev_id;

    if (priv->bspi_enabled && priv->cur_xfer) {
        int done = 0;
        u32 status = bcmspi_read_interrupt(priv);
        u32 *buf = (u32 *)priv->cur_xfer->rx_buf;
        if (status & BSPI_LR_INTERRUPTS_DATA) {
            while (!bcmspi_lr_is_fifo_empty(priv)) {
                u32 data = bcmspi_lr_read_fifo(priv);
                if (likely(priv->cur_xfer_len >= 4)) {
                    buf[priv->cur_xfer_idx++] = data;
                    priv->cur_xfer_len -= 4;
                } else {
                    /*
                     * Read out remaining bytes, make sure
                     * we do not cross the buffer boundary
                     */
                    u8 *cbuf =
                        (u8 *)&buf[priv->cur_xfer_idx];
                    data = cpu_to_le32(data);
                    while (priv->cur_xfer_len) {
                        *cbuf++ = (u8)data;
                        data >>= 8;
                        priv->cur_xfer_len--;
                    }
                }
            }
        }
        if (status & BSPI_LR_INTERRUPTS_ERROR) {
            dev_err(&priv->pdev->dev, "ERROR %02x\n", status);
            priv->xfer_status = -EIO;
        } else if ((status & QSPI_INTR_BSPI_LR_SESSION_DONE_MASK) &&
                    priv->cur_xfer_len == 0) {

            if (priv->raf_next_len) {

                /* Continuation for reading across 16MB boundary */
                bcmspi_disable_interrupt(priv, BSPI_LR_INTERRUPTS_ALL);
                bcmspi_emulate_flash_read(priv, NULL);
                return IRQ_HANDLED;

            } else {
                done = 1;
            }
        }

        if (done) {
            priv->cur_xfer = NULL;
            bcmspi_disable_interrupt(priv, BSPI_LR_INTERRUPTS_ALL);

            if (priv->xfer_status) {
                bcmspi_lr_clear(priv);
            } else {
                if (priv->cur_msg) {
                    priv->cur_msg->actual_length = priv->actual_length;
                    priv->cur_msg->status = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
                    spi_finalize_current_message(priv->master);
#else
                    priv->cur_msg->complete(priv->cur_msg->context);
#endif
                }
            }
            priv->cur_msg = NULL;
        }
        bcmspi_clear_interrupt(priv, status);
        return IRQ_HANDLED;
    }

    if (priv->mspi_hw->mspi_status & cpu_to_le32(1)) {
        /* clear interrupt */
        priv->mspi_hw->mspi_status &= cpu_to_le32(~1);
        bcmspi_clear_interrupt(priv, QSPI_INTR_MSPI_DONE_MASK);

        tasklet_schedule(&priv->tasklet);
        return IRQ_HANDLED;
    } else
        return IRQ_NONE;
}

static void bcmspi_complete(void *arg)
{
    complete(arg);
}

static void bcmspi_tasklet(unsigned long param)
{
    struct bcmspi_priv *priv = (void *)param;
    struct list_head completed;
    struct spi_message *msg;
    unsigned long flags;

    INIT_LIST_HEAD(&completed);
    spin_lock_irqsave(&priv->lock, flags);

    if (priv->next_udelay) {
        udelay(priv->next_udelay);
        priv->next_udelay = 0;
    }

    msg = priv->pos.msg;

    read_from_hw(priv, &completed);
    if (priv->cs_change) {
        udelay(10);
        priv->cs_change = 0;
    }

    write_to_hw(priv);
    spin_unlock_irqrestore(&priv->lock, flags);

    while (!list_empty(&completed)) {
        msg = list_first_entry(&completed, struct spi_message, queue);
        list_del(&msg->queue);
        msg->status = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
        if (msg->complete == bcmspi_complete)
            msg->complete(msg->context);
        else
            spi_finalize_current_message(priv->master);
#else
        if (msg->complete)
            msg->complete(msg->context);
#endif

    }
}

static struct spi_master *default_master;

static int bcmspi_simple_transaction(struct bcmspi_parms *xp,
    const void *tx_buf, int tx_len, void *rx_buf, int rx_len)
{
    DECLARE_COMPLETION_ONSTACK(fini);
    struct spi_message m;
    struct spi_transfer t_tx, t_rx;
    struct spi_device spi;
    int ret;

    memset(&spi, 0, sizeof(spi));
    spi.max_speed_hz = xp->speed_hz;
    spi.chip_select = xp->chip_select;
    spi.mode = xp->mode;
    spi.bits_per_word = xp->bits_per_word;
    spi.master = default_master;

    spi_message_init(&m);
    m.complete = bcmspi_complete;
    m.context = &fini;
    m.spi = &spi;

    memset(&t_tx, 0, sizeof(t_tx));
    memset(&t_rx, 0, sizeof(t_rx));
    t_tx.tx_buf = tx_buf;
    t_tx.len = tx_len;
    t_rx.rx_buf = rx_buf;
    t_rx.len = rx_len;

    if (tx_len)
        spi_message_add_tail(&t_tx, &m);
    if (rx_len)
        spi_message_add_tail(&t_rx, &m);

    ret = bcmspi_transfer_one(default_master, &m);
    if (!ret)
        wait_for_completion(&fini);
    return ret;
}

static void bcmspi_hw_init(struct bcmspi_priv *priv)
{
    const struct bcmspi_parms bcmspi_default_parms_cs0 = {
        .speed_hz           = DEFAULT_SPEED_HZ,
        .chip_select        = 0,
        .mode               = SPI_MODE_3,
        .bits_per_word      = 8,
    };

    priv->mspi_hw->spcr1_lsb = 0;
    priv->mspi_hw->spcr1_msb = 0;
    priv->mspi_hw->newqp = 0;
    priv->mspi_hw->endqp = 0;
    priv->mspi_hw->spcr2 = cpu_to_le32(0x20);    /* spifie */

    bcmspi_hw_set_parms(priv, &bcmspi_default_parms_cs0);

    priv->bspi_enabled = 1;
    bcmspi_disable_bspi(priv);
}

static void bcmspi_hw_uninit(struct bcmspi_priv *priv)
{
    priv->mspi_hw->spcr2 = 0x0;    /* disable irq and enable bits */
    bcmspi_enable_bspi(priv);
}

static int bcmbspi_flash_type(struct bcmspi_priv *priv)
{
    char tx_buf[4];
    unsigned char jedec_id[5] = {0};
    int bspi_flash;

    /* Read ID */
    tx_buf[0] = OPCODE_RDID;
    bcmspi_simple_transaction(&priv->last_parms, tx_buf, 1, &jedec_id, 5);

    switch (jedec_id[0]) {
    case 0x01: /* Spansion */
    case 0xef:
        bspi_flash = BSPI_FLASH_TYPE_SPANSION;
        break;
    case 0xc2: /* Macronix */
        bspi_flash = BSPI_FLASH_TYPE_MACRONIX;
        break;
    case 0xbf: /* SST */
        bspi_flash = BSPI_FLASH_TYPE_SST;
        break;
    case 0x89: /* Numonyx */
        bspi_flash = BSPI_FLASH_TYPE_NUMONYX;
        break;
    default:
        bspi_flash = BSPI_FLASH_TYPE_UNKNOWN;
        break;
    }
    return bspi_flash;
}

static int bcmspi_set_quad_mode(struct bcmspi_priv *priv, int _enable)
{
    char tx_buf[4];
    unsigned char cfg_reg, sts_reg;

    switch (bcmbspi_flash_type(priv)) {
    case BSPI_FLASH_TYPE_SPANSION:
        /* RCR */
        tx_buf[0] = OPCODE_RCR;
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 1, &cfg_reg, 1);
        if (_enable)
            cfg_reg |= 0x2;
        else
            cfg_reg &= ~0x2;
        /* WREN */
        tx_buf[0] = OPCODE_WREN;
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 1, NULL, 0);
        /* WRR */
        tx_buf[0] = OPCODE_WRR;
        tx_buf[1] = 0; /* status register */
        tx_buf[2] = cfg_reg; /* configuration register */
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 3, NULL, 0);
        /* wait till ready */
        do {
            tx_buf[0] = OPCODE_RDSR;
            bcmspi_simple_transaction(&priv->last_parms,
                tx_buf, 1, &sts_reg, 1);
            udelay(1);
        } while (sts_reg & 1);
        break;
    case BSPI_FLASH_TYPE_MACRONIX:
        /* RDSR */
        tx_buf[0] = OPCODE_RDSR;
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 1, &cfg_reg, 1);
        if (_enable)
            cfg_reg |= 0x40;
        else
            cfg_reg &= ~0x40;
        /* WREN */
        tx_buf[0] = OPCODE_WREN;
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 1, NULL, 0);
        /* WRSR */
        tx_buf[0] = OPCODE_WRSR;
        tx_buf[1] = cfg_reg; /* status register */
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 2, NULL, 0);
        /* wait till ready */
        do {
            tx_buf[0] = OPCODE_RDSR;
            bcmspi_simple_transaction(&priv->last_parms,
                tx_buf, 1, &sts_reg, 1);
            udelay(1);
        } while (sts_reg & 1);
        /* RDSR */
        tx_buf[0] = OPCODE_RDSR;
        bcmspi_simple_transaction(&priv->last_parms,
            tx_buf, 1, &cfg_reg, 1);
        break;
    case BSPI_FLASH_TYPE_SST:
    case BSPI_FLASH_TYPE_NUMONYX:
        /* TODO - send Quad mode control command */
        break;
    default:
        return _enable ? -1 : 0;
    }

    return 0;
}

static void * map_io_memory(struct platform_device *pdev, int handle)
{
    struct resource *res;
    void *base;
    res = platform_get_resource(pdev, IORESOURCE_MEM, handle);
    if (!res) {
        dev_err(&pdev->dev, "can't get memory resource %d\n", handle);
        return NULL;
    }
    base = ioremap(res->start, res->end - res->start);
    if (!base) {
        dev_err(&pdev->dev, "can't ioremap %#08x-%#08x\n", res->start, res->end);
        return NULL;
    }
    return base;
}

static int bcmspi_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct bcmspi_priv *priv;
    struct spi_master *master;
    struct resource *res;
    int ret;
    u32 irq;

    DBG("bcmspi_probe\n");

    master = spi_alloc_master(dev, sizeof(struct bcmspi_priv));
    if (!master) {
        dev_err(&pdev->dev, "error allocating spi_master\n");
        return -ENOMEM;
    }

    priv = spi_master_get_devdata(master);
    priv->pdev = pdev;
    priv->state = STATE_IDLE;
    priv->pos.msg = NULL;
    priv->pos.mspi_16bit = 0;
    priv->master = master;
    priv->raf_next_len = 0;
    platform_set_drvdata(pdev, priv);

    master->bus_num = pdev->id;
    master->num_chipselect = 1;
    master->mode_bits = SPI_MODE_3;

    master->setup = bcmspi_setup;
    master->cleanup = bcmspi_cleanup;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
    master->prepare_transfer_hardware = bcmspi_prepare_transfer;
    master->unprepare_transfer_hardware = bcmspi_unprepare_transfer;
    master->transfer_one_message = bcmspi_transfer_one;
    master->transfer = NULL;
#else
    master->transfer = bcmspi_transfer;
#endif

    /* SPI master will always use the SPI device(s) from DT. */
    master->dev.of_node = pdev->dev.of_node;

    priv->mspi_hw           = NULL;
    priv->bspi_hw           = NULL;
    priv->bspi_hw_raf       = NULL;
    priv->qspi_intr         = NULL;
    priv->idm_qspi          = NULL;
    priv->cru_hw            = NULL;
    priv->irq               = -1;

    /* Get MSPI reference clock and max speed hz */
    priv->clk = devm_clk_get(dev, NULL);
    if (!IS_ERR(priv->clk)) {
        clk_prepare_enable(priv->clk);
        priv->mspi_refclk = (unsigned int)clk_get_rate(priv->clk) * 2;
        priv->max_speed_hz = priv->mspi_refclk / (2 * SPBR_MIN);
    }

    /* Map IO memory */
    if (!(priv->mspi_hw = map_io_memory(pdev, 0))) {
        ret = -EIO;
        goto err2;
    }
    if (!(priv->bspi_hw = map_io_memory(pdev, 1))) {
        ret = -EIO;
        goto err2;
    }
    if (!(priv->bspi_hw_raf = map_io_memory(pdev, 2))) {
        ret = -EIO;
        goto err2;
    }
    if (!(priv->qspi_intr = map_io_memory(pdev, 3))) {
        ret = -EIO;
        goto err2;
    }
    if (!(priv->idm_qspi = map_io_memory(pdev, 4))) {
        ret = -EIO;
        goto err2;
    }
    if (!(priv->cru_hw = map_io_memory(pdev, 5))) {
        ret = -EIO;
        goto err2;
    }

    /* IRQ */
    res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
    if (!res) {
        dev_err(&pdev->dev, "no IRQ defined\n");
        ret = -ENODEV;
        goto err2;
    }

    /* Basic initialization (before enabling interrupts) */
    priv->bspi_hw->mast_n_boot_ctrl = cpu_to_le32(1);
    bcmspi_disable_interrupt(priv, 0xffffffff);
    bcmspi_clear_interrupt(priv, 0xffffffff);
    bcmspi_enable_interrupt(priv, QSPI_INTR_MSPI_DONE_MASK);

    /* Request all IRQs */
    for(irq=(u32)res->start; irq<=(u32)res->end; irq++) {
        ret = devm_request_irq(&pdev->dev, irq, bcmspi_interrupt, 0, "qspi_iproc", priv);
        if (ret < 0) {
            dev_err(&pdev->dev, "unable to allocate IRQ\n");
            goto err1;
        }
    }

    bcmspi_hw_init(priv);
    priv->curr_cs = -1;
    priv->bspi_chip_select = 0;

    INIT_LIST_HEAD(&priv->msg_queue);
    spin_lock_init(&priv->lock);

    platform_set_drvdata(pdev, priv);

    tasklet_init(&priv->tasklet, bcmspi_tasklet, (unsigned long)priv);

    ret = devm_spi_register_master(&pdev->dev, master);
    if (ret < 0) {
        dev_err(&pdev->dev, "can't register master\n");
        goto err0;
    }
    if (!default_master)
        default_master = master;

    /* default values - undefined */
    priv->flex_mode.width =
    priv->flex_mode.addrlen =
    priv->flex_mode.hp = -1;

    if (priv->bspi_chip_select) {
        int bspi_width = BSPI_WIDTH_1BIT;

        /* Module parameter validation */
        if (io_mode != 0) {
            if (read_opcode < 0 || read_opcode > 255) {
                dev_err(&pdev->dev, "invalid read_opcode\n");
                io_mode = 0;
            } else if (dummy_cycles < 0 || dummy_cycles > 255) {
                dev_err(&pdev->dev, "invalid dummy_cycles\n");
                io_mode = 0;
            }
        }
        if (io_mode == 2) {
            bspi_width = BSPI_WIDTH_4BIT;
        } else if (io_mode == 1) {
            bspi_width = BSPI_WIDTH_2BIT;
        } else if (io_mode != 0) {
            dev_err(&pdev->dev, "invalid io_mode (0/1/2)\n");
        }

        if (io_mode == 2)
            bcmspi_set_quad_mode(priv, 1);

        bcmspi_set_mode(priv, bspi_width, BSPI_ADDRLEN_3BYTES, bspi_hp);
    }

    dev_info(&pdev->dev, "iProc QSPI driver initialized successfully\n");

    return 0;

err0:
    bcmspi_hw_uninit(priv);
err1:
    for(irq=(u32)res->start; irq<=(u32)res->end; irq++) {
        free_irq(irq, priv);
    }
err2:
    if (priv->cru_hw) {
        iounmap(priv->cru_hw);
    }
    if (priv->idm_qspi) {
        iounmap(priv->idm_qspi);
    }
    if (priv->qspi_intr) {
        iounmap(priv->qspi_intr);
    }
    if (priv->bspi_hw_raf) {
        iounmap(priv->bspi_hw_raf);
    }
    if (priv->bspi_hw) {
        iounmap(priv->bspi_hw);
    }
    if (priv->mspi_hw) {
        iounmap(priv->mspi_hw);
    }
    spi_master_put(master);
    return ret;
}

static int bcmspi_remove(struct platform_device *pdev)
{
    struct bcmspi_priv *priv = platform_get_drvdata(pdev);
    unsigned long flags;
    struct resource *res;
    u32 irq;

    /* acquire lock when the MSPI is idle */
    while (1) {
        spin_lock_irqsave(&priv->lock, flags);
        if (priv->state == STATE_IDLE)
            break;
        spin_unlock_irqrestore(&priv->lock, flags);
        udelay(100);
    }
    priv->state = STATE_SHUTDOWN;
    spin_unlock_irqrestore(&priv->lock, flags);

    tasklet_kill(&priv->tasklet);
    platform_set_drvdata(pdev, NULL);
    bcmspi_hw_uninit(priv);
    if (priv->bspi_hw_raf)
        iounmap(priv->bspi_hw_raf);
    if (priv->bspi_hw)
        iounmap((volatile void __iomem *)priv->bspi_hw);
    res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
    if (res) {
        for(irq=(u32)res->start; irq<=(u32)res->end; irq++) {
            free_irq(irq, priv);
        }
    }
    iounmap((volatile void __iomem *)priv->mspi_hw);
    clk_disable_unprepare(priv->clk);
    spi_unregister_master(priv->master);

    return 0;
}

#ifdef CONFIG_PM
static int bcmspi_suspend(struct device *dev)
{
    struct bcmspi_priv *priv = dev_get_drvdata(dev);
    int ret;

    if (priv == NULL || priv->master == NULL) {
        return -EINVAL;
    }

    /* Do nothing if it's not yet initialized */
    if (!priv->bspi_hw) {
        return 0;
    }

    /* Flush transactions and stop the queue */
    ret = spi_master_suspend(priv->master);
    if (ret) {
        dev_warn(dev, "cannot suspend master\n");
        return ret;
    }

    /* Disable flex mode */
    priv->bspi_hw->flex_mode_enable = 0;

    /* Clear upper byte */
    priv->bspi_hw->flash_upper_addr_byte = 0;

    /* Ensure BSPI read is clean */
    bcmspi_flush_prefetch_buffers(priv);

    /* Switch to BSPI for waking up from boot code */
    if (!priv->bspi_enabled) {
        priv->bspi_hw->mast_n_boot_ctrl = 0;
    }

    return 0;
};

static int bcmspi_resume(struct device *dev)
{
    struct bcmspi_priv *priv = dev_get_drvdata(dev);
    int ret;

    if (priv == NULL || priv->master == NULL) {
        return -EINVAL;
    }

    /* Do nothing if it's not yet initialized */
    if (!priv->bspi_hw) {
        return 0;
    }

    /* Restore MSPI/BSPI mode */
    priv->bspi_enabled = !priv->bspi_enabled;
    if (priv->bspi_enabled) {
        bcmspi_disable_bspi(priv);
    } else {
        bcmspi_enable_bspi(priv);
    }

    /* Restore controller configuration */
    bcmspi_hw_set_parms(priv, &priv->last_parms);

    /* Restore flex mode configuration */
    bcmspi_set_mode(priv,
        priv->flex_mode.width, priv->flex_mode.addrlen, priv->flex_mode.hp);


    /* Restore interrupts */
    bcmspi_disable_interrupt(priv, 0xffffffff);
    bcmspi_clear_interrupt(priv, 0xffffffff);
    bcmspi_enable_interrupt(priv, QSPI_INTR_MSPI_DONE_MASK);

    /* Ensure BSPI read is clean */
    bcmspi_flush_prefetch_buffers(priv);

    /* Start the queue running */
    ret = spi_master_resume(priv->master);
    if (ret) {
        dev_err(dev, "problem starting queue (%d)\n", ret);
    }

    return ret;
}

static const struct dev_pm_ops bcmspi_pm_ops = {
    .suspend    = bcmspi_suspend,
    .resume     = bcmspi_resume,
};
#endif /* CONFIG_PM */

#if defined(CONFIG_OF)
static const struct of_device_id bcmspi_dt[] = {
    { .compatible = "brcm,qspi" },
    { /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, bcmspi_dt);
#endif

static struct platform_driver bcmspi_driver = {
    .driver = {
        .name = "qspi_iproc",
        .of_match_table = of_match_ptr(bcmspi_dt),
        .owner = THIS_MODULE,
#ifdef CONFIG_PM
        .pm = &bcmspi_pm_ops,
#endif
    },
    .probe = bcmspi_probe,
    .remove = bcmspi_remove,
};

module_platform_driver(bcmspi_driver);

MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("iProc QSPI driver");
MODULE_LICENSE("GPL");
