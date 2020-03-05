/*
 *  Meraki small form-factor pluggable (SFP/SFP+) transceiver
 *  user-space proxy driver
 *
 *  Copyright (C) 2013-2015 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 */

enum sfp_user_sfp_gpios
{
    SFP_USER_GPIO_MOD_ABS = 0,
    SFP_USER_GPIO_MOD_PRES = SFP_USER_GPIO_MOD_ABS,
    SFP_USER_GPIO_RX_LOS,
    SFP_USER_GPIO_RS0,
    SFP_USER_GPIO_RS1,
    SFP_USER_GPIO_LPMODE,
    SFP_USER_GPIO_MOD_SEL,
    SFP_USER_GPIO_TX_DIS,

    SFP_USER_GPIO_MAX,
};

#define SFP_USER_NAME_MAX 21

struct sfp_user_platform_data
{
    int id;
    int gpios[SFP_USER_GPIO_MAX];
    int i2c_adapter_id;
};

