/*
 *  Meraki board data declarations
 *
 *  Copyright (C) 2006-2012 Meraki, Inc.
 *  Copyright (C) 2013-2015 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 */

#ifndef BOARD_DATA_H
#define BOARD_DATA_H

/* WARNING: the definition of struct ar531x_boarddata (and related
 * functions and constants) must be kept in sync with the associated
 * constants, functions, and definitions in the meraki source
 * directory, located at
 * <router-checkout>/meraki/libmeraki/board_data.hh
 */
struct ar531x_boarddata {
    uint32_t magic;                       /* board data is valid */
#define AR531X_BD_MAGIC 0x35333131        /* "5311", for all 531x platforms */
    uint16_t cksum;                       /* checksum (starting with BD_REV 2) */
    uint16_t rev;                         /* revision of this struct */
#define BD_REV  13
    char     boardName[64];               /* Name of board */
    uint16_t major;                       /* Board major number */
    uint16_t minor;                       /* Board minor number */

    uint8_t deep_dark_secrets_of_the_universe[60];
    uint8_t unified_field_theory[48];

    /* version 11 */
    char     hwRev[64];

    /* version 13*/
    uint8_t mesh_prefix;                  /* Per-OUI mesh ID prefix */
    uint8_t _pad[3];
};

#define AR531X_BD_REV3_SIZE offsetof(struct ar531x_boarddata, unified_field_theory);
#define AR531X_BD_REV3_CKSUM_OFFSET (0xff+0xff)

#define AR531X_BD_REV10_SIZE offsetof(struct ar531x_boarddata, hwRev);
#define AR531X_BD_REV11_SIZE offsetof(struct ar531x_boarddata, mesh_prefix);
#define AR531X_BD_REV12_SIZE AR531X_BD_REV11_SIZE  /* Size of structure didn't change */
#define AR531X_BD_REV13_SIZE (sizeof(struct ar531x_boarddata))

static inline unsigned short calc_board_data_checksum(const struct ar531x_boarddata *bd)
{
    struct ar531x_boarddata bd_temp = *bd;
    unsigned char *p = (unsigned char *) &bd_temp;
    int size = 0, i;
    unsigned short cksum = 0;

    bd_temp.cksum = 0;

    if (bd->rev == htons(13)) {
        size = AR531X_BD_REV13_SIZE;
    } else if (bd->rev == htons(12)) {
        size = AR531X_BD_REV12_SIZE;
    } else if (bd->rev == htons(11)) {
        size = AR531X_BD_REV11_SIZE;
    } else if (bd->rev == htons(10)) {
        size = AR531X_BD_REV10_SIZE;
    } else if (bd->rev == htons(3) || bd->rev == htons(5)) {
        size = AR531X_BD_REV3_SIZE;
        cksum += AR531X_BD_REV3_CKSUM_OFFSET;
    } else {
        return 0;
    }

    for (i = 0; i < size; i++) {
        cksum += p[i];
    }
    return cksum;
}

#endif
