/* cisco-mps.h - driver header for the Cisco FRU for the C2960-XR Series     */
/* ------------------------------------------------------------------------- */
/* Copyright (C) 2013 Cisco Systems, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.                */
/* ------------------------------------------------------------------------- */

#ifndef CISCO_MPS_H
#define CISCO_MPS_H

struct cisco_mps_platform_data {
    uint16_t present_pin;
    uint16_t power_good_pin;
    uint16_t control_i2c_address;
    uint16_t data_i2c_address;
    uint16_t i2c_adapter_id;
};

#endif
