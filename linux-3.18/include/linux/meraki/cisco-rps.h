#ifndef CISCO_RPS_H
#define CISCO_RPS_H

#include <linux/types.h>

struct cisco_rps_platform_data {
    int i2c_adapter;
    /* GPIOs */
    int status_0;
    int status_1;
    /* Maximum expected power usage of load device, in mW */
    u32 max_system_power;
    u32 max_poe_power;
};

#endif
