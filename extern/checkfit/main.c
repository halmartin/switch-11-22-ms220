/** Validate a FIT image (including signatures)
 *
 *  @copyright
 *  Copyright (C) 2017 Cisco Systems, Inc.
 *  Copyright (C) 2013 Google, Inc.
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


#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include "image.h"
#include <stdbool.h>
#include "debug.h"
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

static const struct option longopts[] = {
	{ "keys", required_argument, NULL, 'k' },
	{ "config", optional_argument, NULL, 'c' },
	{ "debug", no_argument, NULL, 'd' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "help", no_argument, NULL, '?' },
};

bool debug_enabled = false;
bool quiet_enabled = false;

void show_help()
{
	outerr("Syntax: %s [options] files...\n", program_invocation_short_name);
	outerr("\n");
	outerr("Options:\n");
	outerr("\t-k FILE, --keys=FILE\t\tFDT file containing public keys\n");
	outerr("\t-c STRING, --config=STRING\tConfig to use.  If omitted, use default config.\n");
	outerr("\t-d, --debug\t\t\tShow debug output.\n");
	outerr("\t-q, --quiet\t\t\tSuppress all output.\n");
	outerr("\t-?, --help\t\t\tShow this help.\n");
}

int main(int argc, char** argv)
{
	const char* keyfile = NULL;
	const char* config = NULL;

	while (true) {
		int c;
		int idx;

		c = getopt_long(argc, argv, "k:c::dq?",
				longopts, &idx);
		if (c < 0)
			break;

		switch (c) {
		case 'k':
			keyfile = optarg;
			break;
		case 'c':
			config = optarg;
			break;
		case 'd':
			debug_enabled = true;
			break;
		case 'q':
			quiet_enabled = true;
			break;
		case '?':
			show_help();
			return 0;
		default:
			outerr("%s: unknown option '%s'\n", argv[0], argv[idx]);
			show_help();
			return 1;
		}
	}

	if (!keyfile) {
		outerr("%s: no key file specified\n", argv[0]);
		return 1;
	}

	int keyfd = open(keyfile, O_RDONLY);
	if (keyfd < 0) {
		debug("%s: error opening \"%s\": %m\n", __func__, keyfile);
		out("%s: error opening keyfile", argv[0]);
		return 1;
	}

	struct stat keystat;

	if (fstat(keyfd, &keystat) < 0) {
		debug("%s: error stat \"%s\": %m", __func__, keyfile);
		out("%s: error opening keyfile", argv[0]);
		close(keyfd);
		return 1;
	}

	signature_fdt = mmap(NULL, keystat.st_size, PROT_READ, MAP_PRIVATE, keyfd, 0);
	if (signature_fdt == MAP_FAILED) {
		debug("%s: error mapping \"%s\": %m\n", __func__, keyfile);
		out("%s: error opening keyfile", argv[0]);
		close(keyfd);
		return 1;
	}

	int rc = 0;
	for (int i = optind; i < argc; i++) {
		int fit_fd = open(argv[i], O_RDONLY);
		if (fit_fd < 0) {
			debug("%s: error opening \"%s\": %m\n", __func__,
				argv[i]);
			rc = 1;
			out("%s: %s failed\n", argv[0], argv[i]);
			break;
		}
		off_t fit_size = 0;
		unsigned long numblocks = 0;
		int status = ioctl(fit_fd, BLKGETSIZE, &numblocks);
		if (status == 0) {
			fit_size = (numblocks * 512) & ~(sysconf(_SC_PAGESIZE) - 1);
		} else if (errno == ENOTTY) {
			struct stat fit_stat;
			status = fstat(fit_fd, &fit_stat);
			if (status == 0)
				fit_size = fit_stat.st_size;
		}

		if (status < 0) {
			debug("%s: error getting size of \"%s\": %m\n", __func__,
			      argv[i]);
			rc = 1;
			out("%s: %s failed\n", argv[0], argv[i]);
			close(fit_fd);
			break;
		}
		if (fit_size == 0) {
			debug("%s: size of \"%s\" is 0?\n", __func__, argv[i]);
			rc = 1;
			out("%s: %s failed\n", argv[0], argv[i]);
			close(fit_fd);
			break;
		}
		void* fit = mmap(NULL, fit_size, PROT_READ, MAP_PRIVATE, fit_fd, 0);
		if (fit == MAP_FAILED) {
			debug("%s: error on mmap with \"%s\": %m\n",
			      __func__, argv[i]);
			rc = 1;
			out("%s: %s failed\n", argv[0], argv[i]);
			close(fit_fd);
			break;
		}
		int conf = fit_conf_get_node(fit, config);
		if (conf < 0) {
			debug("%s: unable to find config \"%s\" in \"%s\"\n",
			      __func__, config, argv[i]);
			rc = 1;
			out("%s: %s failed\n", argv[0], argv[i]);
			munmap(fit, fit_size);
			close(fit_fd);
			break;
		}
		if (fit_config_verify(fit, conf) < 0) {
			rc = 1;
			("%s: %s failed\n", argv[0], argv[i]);
			munmap(fit, fit_size);
			close(fit_fd);
			break;
		}
		munmap(fit, fit_size);
		close(fit_fd);
		out("%s: %s success\n", argv[0], argv[i]);
	}

	munmap(signature_fdt, keystat.st_size);
	close(keyfd);

	if (rc == 0)
		out("%s: success!\n", argv[0]);
	else
		out("%s: failure!\n", argv[0]);

	return rc;
}

