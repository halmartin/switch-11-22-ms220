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

#include "image.h"
#include "debug.h"
#include <time.h>
#include <libfdt.h>
#include "fdt_region.h"
#include <stdint.h>
#include <errno.h>
#include <openssl/evp.h>
#include <string.h>
#include "ecdsa.h"

int hash_calculate(const char *name,
		   const struct image_region region[],
		   int region_count, uint8_t *checksum)
{
	EVP_MD_CTX* ctx;
	const EVP_MD* type = NULL;
	int res = 0;

	ctx = EVP_MD_CTX_create();
	if (!ctx) {
		debug("EVP_MD_CTX_create failed\n");
		return -1;
	}

	if (strcmp(name, "sha1") == 0) {
		type = EVP_sha1();
	} else if (strcmp(name, "sha256") == 0) {
		type = EVP_sha256();
	} else if (strcmp(name, "sha384") == 0) {
		type = EVP_sha384();
	} else if (strcmp(name, "sha512") == 0) {
		type = EVP_sha512();
	} else if (strcmp(name, "md5") == 0) {
		type = EVP_md5();
	} else {
		debug("Unsupported hash algorithm\n");
		res = -1;
		goto done;
	}

	if (!type) {
		debug("Type is bad!\n");
		res = -1;
		goto done;
	}

	if (!EVP_DigestInit_ex(ctx, type, NULL)) {
		debug("EVP_DigestInit failed\n");
		res = -1;
		goto done;
	}

	for (int i = 0; i < region_count; i++) {
		if (!EVP_DigestUpdate(ctx, region[i].data, region[i].size)) {
			debug("EVP_DigestUpdate failed\n");
			res = -1;
			goto done;
		}
	}

	if (!EVP_DigestFinal_ex(ctx, checksum, NULL)) {
		debug("EVP_DigestFinal_ex failed\n");
		res = -1;
		goto done;
	}

done:
	EVP_MD_CTX_destroy(ctx);
	return res;
}

/*
 * ecdsa_verify_key - mbedtls portion of verify code
 */
static int ecdsa_verify_key(struct image_sign_info *info,
			    const uint8_t *pubkey, const unsigned pubkey_len,
			    const uint8_t *sig, const unsigned sig_len,
			    const uint8_t *hash)
{
	const mbedtls_ecp_curve_info *curve;
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q;
	mbedtls_mpi r, s;
	int ret;

	/* Init everything */
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Q);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	/* Get the ECP curve from the name */
	curve = mbedtls_ecp_curve_info_from_name(info->crypto->name);
	if (!curve) {
		debug("%s: Error finding curve info for %s\n", __func__,
		      info->crypto->name);
		ret = -EINVAL;
		goto cleanup;
	}

	/* Load the ECP group from the curve */
	ret = mbedtls_ecp_group_load(&grp, curve->grp_id);
	if (ret < 0) {
		debug("%s: Invalid or unsupported curve %s\n", __func__,
		      info->crypto->name);
		ret = -EINVAL;
		goto cleanup;
	}


	/* Read point Q from the pubkey */
	ret = mbedtls_ecp_point_read_binary(&grp, &Q, pubkey, pubkey_len);
	if (ret < 0) {
		debug("%s: Error parsing pubkey\n", __func__);
		ret = -EINVAL;
		goto cleanup;
	}

	/* Read r and s from the signature */
	ret = mbedtls_ecdsa_read_signature(sig, sig_len, &r, &s);
	if (ret < 0) {
		debug("%s: Error reading signature\n", __func__);
		ret = -EINVAL;
		goto cleanup;
	}

	/* Verify the points are valid */
	ret = mbedtls_ecdsa_verify(&grp, hash, info->crypto->key_len,
				   &Q, &r, &s);
	if (ret < 0) {
		debug("%s: Validation failed\n", __func__);
		ret = -EINVAL;
		goto cleanup;
	}

cleanup:
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_point_free(&Q);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return ret;
}

/*
 * ecdsa_verify - generic entry point to verify
 */
int ecdsa_verify(struct image_sign_info *info,
	       const struct image_region region[], int region_count,
	       uint8_t *sig, unsigned sig_len)
{
	/* Reserve memory for maximum checksum-length */
	const void *blob = info->fdt_blob;
	uint8_t hash[info->crypto->key_len];
	char name[100];
	int sig_node;
	int node;
	const uint8_t *pubkey;
	int pubkey_len;
	int ret;

	/* Sanity check the key length */
	if (info->checksum->checksum_len > info->crypto->key_len) {
		debug("%s: Invalid checksum-algorithm %s for %s\n",
		      __func__, info->checksum->name, info->crypto->name);
		return -EINVAL;
	}

	sig_node = fdt_subnode_offset(blob, 0, FIT_SIG_NODENAME);
	if (sig_node < 0) {
		debug("%s: No signature node found\n", __func__);
		return -ENOENT;
	}

	/* Calculate checksum with checksum-algorithm */
	ret = info->checksum->calculate(info->checksum->name,
					region, region_count, hash);
	if (ret < 0) {
		debug("%s: Error in checksum calculation\n", __func__);
		return -EINVAL;
	}

	/* Look for a key that matches our hint */
	snprintf(name, sizeof(name), "key-%s", info->keyname);
	node = fdt_subnode_offset(blob, sig_node, name);
	if (node < 0) {
		debug("%s: Error finding public key with name %s\n", __func__,
		      info->keyname);
		return -ENOENT;
	}

	pubkey = fdt_getprop(blob, node, "pubkey", &pubkey_len);
	if (!pubkey || pubkey_len <= 0) {
		debug("%s: Failed to read pubkey\n", __func__);
		return -EFAULT;
	}

	/* And verify using it */
	return ecdsa_verify_key(info, pubkey, pubkey_len, sig, sig_len, hash);
}
