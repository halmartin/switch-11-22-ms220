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

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

extern int hash_calculate(const char *name,
                          const struct image_region region[],
                          int region_count, uint8_t *checksum);
extern int ecdsa_verify(struct image_sign_info *info,
                        const struct image_region region[], int region_count,
                        uint8_t *sig, unsigned sig_len);

#endif
