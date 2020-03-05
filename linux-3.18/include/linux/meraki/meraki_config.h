/*
 *  Meraki board data config driver
 *
 *  Copyright (C) 2013-2015 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 */

#ifndef MERAKI_CONFIG_H
#define MERAKI_CONFIG_H

struct meraki_config_platform_data {
    struct at24_platform_data* eeprom_data;
    int write_protect_gpio;     // If there is no GPIO for write protect, set this to -1.
    bool write_protect_active_low;
};

enum {
    MERAKI_BOARD_UNKNOWN,
    MERAKI_BOARD_MS220_24,
    MERAKI_BOARD_MS220_24P,
    MERAKI_BOARD_MS220_48,
    MERAKI_BOARD_MS220_48LP,
    MERAKI_BOARD_MS220_48FP,
    MERAKI_BOARD_MS320_24,
    MERAKI_BOARD_MS320_24P,
    MERAKI_BOARD_MS320_48,
    MERAKI_BOARD_MS320_48LP,
    MERAKI_BOARD_MS320_48FP,
    MERAKI_BOARD_MS350_24,
    MERAKI_BOARD_MS350_24P,
    MERAKI_BOARD_MS350_48,
    MERAKI_BOARD_MS350_48LP,
    MERAKI_BOARD_MS350_48FP,
    MERAKI_BOARD_MS420_24,
    MERAKI_BOARD_MS420_48,
};

extern int meraki_config_get_product(void);

#endif
