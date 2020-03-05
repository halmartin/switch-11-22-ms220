/*
 * Copyright (c) 2013, Google Inc.
 *
 * (C) Copyright 2008 Semihalf
 *
 * (C) Copyright 2000-2006
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include "image.h"
#include "debug.h"
#include <time.h>
#include <libfdt.h>
#include "fdt_region.h"
#include <zlib.h>
#include <endian.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

/*****************************************************************************/
/* New uImage format routines */
/*****************************************************************************/

static void fit_get_debug(const void *fit, int noffset,
		char *prop_name, int err)
{
	debug("Can't get '%s' property from FIT 0x%08lx, node: offset %d, name %s (%s)\n",
	      prop_name, (ulong)fit, noffset, fit_get_name(fit, noffset, NULL),
	      fdt_strerror(err));
}

/**
 * fit_get_subimage_count - get component (sub-image) count
 * @fit: pointer to the FIT format image header
 * @images_noffset: offset of images node
 *
 * returns:
 *     number of image components
 */
int fit_get_subimage_count(const void *fit, int images_noffset)
{
	int noffset;
	int ndepth;
	int count = 0;

	/* Process its subnodes, print out component images details */
	for (ndepth = 0, count = 0,
		noffset = fdt_next_node(fit, images_noffset, &ndepth);
	     (noffset >= 0) && (ndepth > 0);
	     noffset = fdt_next_node(fit, noffset, &ndepth)) {
		if (ndepth == 1) {
			count++;
		}
	}

	return count;
}


/**
 * fit_get_desc - get node description property
 * @fit: pointer to the FIT format image header
 * @noffset: node offset
 * @desc: double pointer to the char, will hold pointer to the description
 *
 * fit_get_desc() reads description property from a given node, if
 * description is found pointer to it is returned in third call argument.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_get_desc(const void *fit, int noffset, char **desc)
{
	int len;

	*desc = (char *)fdt_getprop(fit, noffset, FIT_DESC_PROP, &len);
	if (*desc == NULL) {
		fit_get_debug(fit, noffset, FIT_DESC_PROP, len);
		return -1;
	}

	return 0;
}

/**
 * fit_get_timestamp - get node timestamp property
 * @fit: pointer to the FIT format image header
 * @noffset: node offset
 * @timestamp: pointer to the time_t, will hold read timestamp
 *
 * fit_get_timestamp() reads timestamp property from given node, if timestamp
 * is found and has a correct size its value is returned in third call
 * argument.
 *
 * returns:
 *     0, on success
 *     -1, on property read failure
 *     -2, on wrong timestamp size
 */
int fit_get_timestamp(const void *fit, int noffset, time_t *timestamp)
{
	int len;
	const void *data;

	data = fdt_getprop(fit, noffset, FIT_TIMESTAMP_PROP, &len);
	if (data == NULL) {
		fit_get_debug(fit, noffset, FIT_TIMESTAMP_PROP, len);
		return -1;
	}
	if (len != sizeof(uint32_t)) {
		debug("FIT timestamp with incorrect size of (%u)\n", len);
		return -2;
	}

	*timestamp = be32toh(*((uint32_t *)data));
	return 0;
}

/**
 * fit_image_get_node - get node offset for component image of a given unit name
 * @fit: pointer to the FIT format image header
 * @image_uname: component image node unit name
 *
 * fit_image_get_node() finds a component image (within the '/images'
 * node) of a provided unit name. If image is found its node offset is
 * returned to the caller.
 *
 * returns:
 *     image node offset when found (>=0)
 *     negative number on failure (FDT_ERR_* code)
 */
int fit_image_get_node(const void *fit, const char *image_uname)
{
	int noffset, images_noffset;

	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		debug("Can't find images parent node '%s' (%s)\n",
		      FIT_IMAGES_PATH, fdt_strerror(images_noffset));
		return images_noffset;
	}

	noffset = fdt_subnode_offset(fit, images_noffset, image_uname);
	if (noffset < 0) {
		debug("Can't get node offset for image unit name: '%s' (%s)\n",
		      image_uname, fdt_strerror(noffset));
	}

	return noffset;
}

/**
 * fit_image_get_data - get data property and its size for a given component image node
 * @fit: pointer to the FIT format image header
 * @noffset: component image node offset
 * @data: double pointer to void, will hold data property's data address
 * @size: pointer to size_t, will hold data property's data size
 *
 * fit_image_get_data() finds data property in a given component image node.
 * If the property is found its data start address and size are returned to
 * the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_get_data(const void *fit, int noffset,
		const void **data, size_t *size)
{
	int len;

	*data = fdt_getprop(fit, noffset, FIT_DATA_PROP, &len);
	if (*data == NULL) {
		fit_get_debug(fit, noffset, FIT_DATA_PROP, len);
		*size = 0;
		return -1;
	}

	*size = len;
	return 0;
}

/**
 * fit_image_hash_get_algo - get hash algorithm name
 * @fit: pointer to the FIT format image header
 * @noffset: hash node offset
 * @algo: double pointer to char, will hold pointer to the algorithm name
 *
 * fit_image_hash_get_algo() finds hash algorithm property in a given hash node.
 * If the property is found its data start address is returned to the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_hash_get_algo(const void *fit, int noffset, char **algo)
{
	int len;

	*algo = (char *)fdt_getprop(fit, noffset, FIT_ALGO_PROP, &len);
	if (*algo == NULL) {
		fit_get_debug(fit, noffset, FIT_ALGO_PROP, len);
		return -1;
	}

	return 0;
}

/**
 * fit_image_hash_get_value - get hash value and length
 * @fit: pointer to the FIT format image header
 * @noffset: hash node offset
 * @value: double pointer to uint8_t, will hold address of a hash value data
 * @value_len: pointer to an int, will hold hash data length
 *
 * fit_image_hash_get_value() finds hash value property in a given hash node.
 * If the property is found its data start address and size are returned to
 * the caller.
 *
 * returns:
 *     0, on success
 *     -1, on failure
 */
int fit_image_hash_get_value(const void *fit, int noffset, uint8_t **value,
				int *value_len)
{
	int len;

	*value = (uint8_t *)fdt_getprop(fit, noffset, FIT_VALUE_PROP, &len);
	if (*value == NULL) {
		fit_get_debug(fit, noffset, FIT_VALUE_PROP, len);
		*value_len = 0;
		return -1;
	}

	*value_len = len;
	return 0;
}

/**
 * fit_image_hash_get_ignore - get hash ignore flag
 * @fit: pointer to the FIT format image header
 * @noffset: hash node offset
 * @ignore: pointer to an int, will hold hash ignore flag
 *
 * fit_image_hash_get_ignore() finds hash ignore property in a given hash node.
 * If the property is found and non-zero, the hash algorithm is not verified by
 * u-boot automatically.
 *
 * returns:
 *     0, on ignore not found
 *     value, on ignore found
 */
static int fit_image_hash_get_ignore(const void *fit, int noffset, int *ignore)
{
	int len;
	int *value;

	value = (int *)fdt_getprop(fit, noffset, FIT_IGNORE_PROP, &len);
	if (value == NULL || len != sizeof(int))
		*ignore = 0;
	else
		*ignore = *value;

	return 0;
}

unsigned long fit_get_end(const void *fit)
{
	return ((uintptr_t)fit) + fdt_totalsize(fit);
}

/**
 * calculate_hash - calculate and return hash for provided input data
 * @data: pointer to the input data
 * @data_len: data length
 * @algo: requested hash algorithm
 * @value: pointer to the char, will hold hash value data (caller must
 * allocate enough free space)
 * value_len: length of the calculated hash
 *
 * calculate_hash() computes input data hash according to the requested
 * algorithm.
 * Resulting hash value is placed in caller provided 'value' buffer, length
 * of the calculated hash is returned via value_len pointer argument.
 *
 * returns:
 *     0, on success
 *    -1, when algo is unsupported
 */
int calculate_hash(const void *data, int data_len, const char *algo,
			uint8_t *value, int *value_len)
{
	if (strcmp(algo, "crc32") == 0) {
		*((uint32_t *)value) = crc32(0, data, data_len);
		*((uint32_t *)value) = htobe32(*((uint32_t *)value));
		*value_len = 4;
	} else if (strcmp(algo, "sha1") == 0) {
		SHA1((unsigned char *)data, data_len, (unsigned char *)value);
		*value_len = 20;
	} else if (strcmp(algo, "sha256") == 0) {
		SHA256((unsigned char *)data, data_len, (unsigned char *)value);
		*value_len = 32;
	} else if (strcmp(algo, "sha384") == 0) {
		SHA384((unsigned char *)data, data_len, (unsigned char *)value);
		*value_len = 48;
	} else if (strcmp(algo, "sha512") == 0) {
		SHA512((unsigned char *)data, data_len, (unsigned char *)value);
		*value_len = 64;
	} else if (strcmp(algo, "md5") == 0) {
		MD5((unsigned char *)data, data_len, value);
		*value_len = 16;
	} else {
		debug("Unsupported hash alogrithm\n");
		return -1;
	}
	return 0;
}

static int fit_image_check_hash(const void *fit, int noffset, const void *data,
				size_t size, char **err_msgp)
{
	uint8_t value[FIT_MAX_HASH_LEN];
	int value_len;
	char *algo;
	uint8_t *fit_value;
	int fit_value_len;
	int ignore;

	*err_msgp = NULL;

	if (fit_image_hash_get_algo(fit, noffset, &algo)) {
		*err_msgp = "Can't get hash algo property";
		return -1;
	}
	debug("%s", algo);

	fit_image_hash_get_ignore(fit, noffset, &ignore);
	if (ignore) {
		debug("-skipped ");
		return 0;
	}

	if (fit_image_hash_get_value(fit, noffset, &fit_value,
				     &fit_value_len)) {
		*err_msgp = "Can't get hash value property";
		return -1;
	}

	if (calculate_hash(data, size, algo, value, &value_len)) {
		*err_msgp = "Unsupported hash algorithm";
		return -1;
	}

	if (value_len != fit_value_len) {
		*err_msgp = "Bad hash value len";
		return -1;
	} else if (memcmp(value, fit_value, value_len) != 0) {
		*err_msgp = "Bad hash value";
		return -1;
	}

	return 0;
}

/**
 * fit_image_verify - verify data integrity
 * @fit: pointer to the FIT format image header
 * @image_noffset: component image node offset
 *
 * fit_image_verify() goes over component image hash nodes,
 * re-calculates each data hash and compares with the value stored in hash
 * node.
 *
 * returns:
 *     1, if all hashes are valid
 *     0, otherwise (or on error)
 */
int fit_image_verify(const void *fit, int image_noffset)
{
	const void	*data;
	size_t		size;
	int		noffset = 0;
	char		*err_msg = "";
	int verify_all = 1;
	int ret;

	/* Get image data and data length */
	if (fit_image_get_data(fit, image_noffset, &data, &size)) {
		err_msg = "Can't get image data/size";
		goto error;
	}

	/* Verify all required signatures */
	if (fit_image_verify_required_sigs(fit, image_noffset, data, size,
					   signature_fdt, &verify_all)) {
		err_msg = "Unable to verify required signature";
		goto error;
	}

	/* Process all hash subnodes of the component image node */
	fdt_for_each_subnode(noffset, fit, image_noffset) {
		const char *name = fit_get_name(fit, noffset, NULL);

		/*
		 * Check subnode name, must be equal to "hash".
		 * Multiple hash nodes require unique unit node
		 * names, e.g. hash@1, hash@2, etc.
		 */
		if (!strncmp(name, FIT_HASH_NODENAME,
			     strlen(FIT_HASH_NODENAME))) {
			if (fit_image_check_hash(fit, noffset, data, size,
						 &err_msg))
				goto error;
			puts("+ ");
		} else if (verify_all &&
				!strncmp(name, FIT_SIG_NODENAME,
					strlen(FIT_SIG_NODENAME))) {
			ret = fit_image_check_sig(fit, noffset, data,
							size, -1, &err_msg);

			/*
			 * Show an indication on failure, but do not return
			 * an error. Only keys marked 'required' can cause
			 * an image validation failure. See the call to
			 * fit_image_verify_required_sigs() above.
			 */
			if (ret)
				puts("- ");
			else
				puts("+ ");
		}
	}

	if (noffset == -FDT_ERR_TRUNCATED || noffset == -FDT_ERR_BADSTRUCTURE) {
		err_msg = "Corrupted or truncated tree";
		goto error;
	}

	return 1;

error:
	debug(" error!\n%s for '%s' hash node in '%s' image node\n",
	       err_msg, fit_get_name(fit, noffset, NULL),
	       fit_get_name(fit, image_noffset, NULL));
	return 0;
}

/**
 * fit_all_image_verify - verify data integrity for all images
 * @fit: pointer to the FIT format image header
 *
 * fit_all_image_verify() goes over all images in the FIT and
 * for every images checks if all it's hashes are valid.
 *
 * returns:
 *     1, if all hashes of all images are valid
 *     0, otherwise (or on error)
 */
int fit_all_image_verify(const void *fit)
{
	int images_noffset;
	int noffset;
	int ndepth;
	int count;

	/* Find images parent node offset */
	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		out("Can't find images parent node '%s' (%s)\n",
		       FIT_IMAGES_PATH, fdt_strerror(images_noffset));
		return 0;
	}

	/* Process all image subnodes, check hashes for each */
	out("## Checking hash(es) for FIT Image at %08lx ...\n",
	       (ulong)fit);
	for (ndepth = 0, count = 0,
	     noffset = fdt_next_node(fit, images_noffset, &ndepth);
			(noffset >= 0) && (ndepth > 0);
			noffset = fdt_next_node(fit, noffset, &ndepth)) {
		if (ndepth == 1) {
			/*
			 * Direct child node of the images parent node,
			 * i.e. component image node.
			 */
			out("   Hash(es) for Image %u (%s): ", count,
			       fit_get_name(fit, noffset, NULL));
			count++;

			if (!fit_image_verify(fit, noffset))
				return 0;
			out("\n");
		}
	}
	return 1;
}

/**
 * fit_check_format - sanity check FIT image format
 * @fit: pointer to the FIT format image header
 *
 * fit_check_format() runs a basic sanity FIT image verification.
 * Routine checks for mandatory properties, nodes, etc.
 *
 * returns:
 *     1, on success
 *     0, on failure
 */
int fit_check_format(const void *fit)
{
	/* mandatory / node 'description' property */
	if (fdt_getprop(fit, 0, FIT_DESC_PROP, NULL) == NULL) {
		debug("Wrong FIT format: no description\n");
		return 0;
	}

	/* mandatory subimages parent '/images' node */
	if (fdt_path_offset(fit, FIT_IMAGES_PATH) < 0) {
		debug("Wrong FIT format: no images parent node\n");
		return 0;
	}

	return 1;
}

/**
 * fit_conf_get_node - get node offset for configuration of a given unit name
 * @fit: pointer to the FIT format image header
 * @conf_uname: configuration node unit name
 *
 * fit_conf_get_node() finds a configuration (within the '/configurations'
 * parent node) of a provided unit name. If configuration is found its node
 * offset is returned to the caller.
 *
 * When NULL is provided in second argument fit_conf_get_node() will search
 * for a default configuration node instead. Default configuration node unit
 * name is retrieved from FIT_DEFAULT_PROP property of the '/configurations'
 * node.
 *
 * returns:
 *     configuration node offset when found (>=0)
 *     negative number on failure (FDT_ERR_* code)
 */
int fit_conf_get_node(const void *fit, const char *conf_uname)
{
	int noffset, confs_noffset;
	int len;

	confs_noffset = fdt_path_offset(fit, FIT_CONFS_PATH);
	if (confs_noffset < 0) {
		debug("Can't find configurations parent node '%s' (%s)\n",
		      FIT_CONFS_PATH, fdt_strerror(confs_noffset));
		return confs_noffset;
	}

	if (conf_uname == NULL) {
		/* get configuration unit name from the default property */
		debug("No configuration specified, trying default...\n");
		conf_uname = (char *)fdt_getprop(fit, confs_noffset,
						 FIT_DEFAULT_PROP, &len);
		if (conf_uname == NULL) {
			fit_get_debug(fit, confs_noffset, FIT_DEFAULT_PROP,
				      len);
			return len;
		}
		debug("Found default configuration: '%s'\n", conf_uname);
	}

	noffset = fdt_subnode_offset(fit, confs_noffset, conf_uname);
	if (noffset < 0) {
		debug("Can't get node offset for configuration unit name: '%s' (%s)\n",
		      conf_uname, fdt_strerror(noffset));
	}

	return noffset;
}

int fit_conf_get_prop_node(const void *fit, int noffset,
		const char *prop_name)
{
	char *uname;
	int len;

	/* get kernel image unit name from configuration kernel property */
	uname = (char *)fdt_getprop(fit, noffset, prop_name, &len);
	if (uname == NULL)
		return len;

	return fit_image_get_node(fit, uname);
}

