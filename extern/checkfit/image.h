/*
 * (C) Copyright 2008 Semihalf
 *
 * (C) Copyright 2000-2005
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef _IMAGE_H_
#define _IMAGE_H_

#include <libfdt.h>
#include "fdt_region.h"
#include <time.h>
#include <openssl/evp.h>

/*******************************************************************/
/* New uImage format specific code (prefixed with fit_) */
/*******************************************************************/

#define FIT_IMAGES_PATH		"/images"
#define FIT_CONFS_PATH		"/configurations"

/* hash/signature node */
#define FIT_HASH_NODENAME	"hash"
#define FIT_ALGO_PROP		"algo"
#define FIT_VALUE_PROP		"value"
#define FIT_IGNORE_PROP		"uboot-ignore"
#define FIT_SIG_NODENAME	"signature"

/* image node */
#define FIT_DATA_PROP		"data"
#define FIT_TIMESTAMP_PROP	"timestamp"
#define FIT_DESC_PROP		"description"
#define FIT_ARCH_PROP		"arch"
#define FIT_TYPE_PROP		"type"
#define FIT_OS_PROP		"os"
#define FIT_COMP_PROP		"compression"
#define FIT_ENTRY_PROP		"entry"
#define FIT_LOAD_PROP		"load"

/* configuration node */
#define FIT_KERNEL_PROP		"kernel"
#define FIT_RAMDISK_PROP	"ramdisk"
#define FIT_FDT_PROP		"fdt"
#define FIT_LOADABLE_PROP	"loadables"
#define FIT_DEFAULT_PROP	"default"
#define FIT_SETUP_PROP		"setup"
#define FIT_FPGA_PROP		"fpga"

#define FIT_MAX_HASH_LEN	64

extern void* signature_fdt;

static inline unsigned long fit_get_size(const void *fit)
{
	return fdt_totalsize(fit);
}

/**
 * fit_get_name - get FIT node name
 * @fit: pointer to the FIT format image header
 *
 * returns:
 *     NULL, on error
 *     pointer to node name, on success
 */
static inline const char *fit_get_name(const void *fit_hdr,
		int noffset, int *len)
{
	return fdt_get_name(fit_hdr, noffset, len);
}

int fit_get_subimage_count(const void *fit, int images_noffset);
int fit_get_desc(const void *fit, int noffset, char **desc);
int fit_get_timestamp(const void *fit, int noffset, time_t *timestamp);
int fit_image_get_node(const void *fit, const char *image_uname);
int fit_image_get_data(const void *fit, int noffset,
		       const void **data, size_t *size);
int fit_image_hash_get_algo(const void *fit, int noffset, char **algo);
int fit_image_hash_get_value(const void *fit, int noffset, uint8_t **value,
			     int *value_len);

unsigned long fit_get_end(const void *fit);
int calculate_hash(const void *data, int data_len, const char *algo,
		   uint8_t *value, int *value_len);
int fit_image_verify(const void *fit, int image_noffset);
int fit_all_image_verify(const void *fit);
int fit_check_format(const void *fit);
int fit_conf_get_node(const void *fit, const char *conf_uname);
int fit_conf_get_prop_node(const void *fit, int noffset,
			   const char *prop_name);


struct image_sign_info {
	const char *keyname;		/* Name of key to use */
	void *fit;			/* Pointer to FIT blob */
	int node_offset;		/* Offset of signature node */
	const char *name;		/* Algorithm name */
	struct checksum_algo *checksum;	/* Checksum algorithm information */
	struct crypto_algo *crypto;	/* Crypto algorithm information */
	const void *fdt_blob;		/* FDT containing public keys */
	int required_keynode;		/* Node offset of key to use: -1=any */
};


/* A part of an image, used for hashing */
struct image_region {
	const void *data;
	int size;
};

struct checksum_algo {
	const char *name;
	const int checksum_len;
	const EVP_MD *(*calculate_sign)(void);
	int (*calculate)(const char *name,
			 const struct image_region region[],
			 int region_count, uint8_t *checksum);
};

struct crypto_algo {
	const char *name;		/* Name of algorithm */
	const int nid;			/* OpenSSL name ID */
	const int key_len;

	/**
	 * verify() - Verify a signature against some data
	 *
	 * @info:	Specifies key and FIT information
	 * @data:	Pointer to the input data
	 * @data_len:	Data length
	 * @sig:	Signature
	 * @sig_len:	Number of bytes in signature
	 * @return 0 if verified, -ve on error
	 */
	int (*verify)(struct image_sign_info *info,
		      const struct image_region region[], int region_count,
		      uint8_t *sig, unsigned sig_len);
};

struct checksum_algo *image_get_checksum_algo(const char *full_name);
struct crypto_algo *image_get_crypto_algo(const char *full_name);
struct image_region *fit_region_make_list(const void *fit,
					  struct fdt_region *fdt_regions,
					  int count,
					  struct image_region *region);
int fit_image_check_sig(const void *fit, int noffset, const void *data,
			size_t size, int required_keynode, char **err_msgp);
int fit_image_verify_required_sigs(const void *fit, int image_noffset,
				   const char *data, size_t size,
				   const void *sig_blob, int *no_sigsp);
int fit_config_check_sig(const void *fit, int noffset, int required_keynode,
			 char **err_msgp);
int fit_config_verify_required_sigs(const void *fit, int conf_noffset,
				    const void *sig_blob);
int fit_config_verify(const void *fit, int conf_noffset);

#endif
