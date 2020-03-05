/*
 *  Copyright (C) 2017 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdbool.h>
#include <stdio.h>

extern bool debug_enabled;
extern bool quiet_enabled;

#define debug(...) \
    if (debug_enabled) \
        fprintf(stderr, __VA_ARGS__)

#define out(...) \
    if (!quiet_enabled) \
        printf(__VA_ARGS__)

#define outerr(...) \
    if (!quiet_enabled) \
        fprintf(stderr, __VA_ARGS__)

#endif
