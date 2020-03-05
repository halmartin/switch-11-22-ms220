/*
 * mtd - simple memory technology device manipulation tool
 *
 * Copyright (C) 2005 Waldemar Brodkorb <wbx@dass-it.de>,
 *	                  Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: mtd.c 3200 2006-02-09 08:47:48Z nbd $
 *
 * The code is based on the linux-mtd examples.
 */

#include <limits.h>
#define __USE_XOPEN_EXTENDED
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <string.h>
#include <signal.h>

#include <mtd/mtd-user.h>

#define TRX_MAGIC       0x30524448      /* "HDR0" */
#define BUFSIZE (16 * 1024)
#define MAX_ARGS 8

#define SLEEP_USECS 500000

#define DEBUG

#define SYSTYPE_UNKNOWN     0
#define SYSTYPE_BROADCOM    1
/* to be continued */

struct trx_header {
	uint32_t magic;		/* "HDR0" */
	uint32_t len;		/* Length of file including header */
	uint32_t crc32;		/* 32-bit CRC from flag_version to end of file */
	uint32_t flag_version;	/* 0:15 flags, 16:31 version */
	uint32_t offsets[3];    /* Offsets of partitions from start of header */
};

char buf[BUFSIZE];
int buflen;
int should_sleep = 0;

int mtd_open(const char *mtd, int flags);

static void
do_sleep(void)
{
	if (should_sleep)
		usleep(SLEEP_USECS);
}

int
image_check_bcom(int imagefd, const char *mtd)
{
	struct trx_header *trx = (struct trx_header *) buf;
	struct mtd_info_user mtdInfo;
	int fd;

	buflen = read(imagefd, buf, 32);
	if (buflen < 32) {
		fprintf(stdout, "Could not get image header, file too small (%ld bytes)\n", buflen);
		return 0;
	}

	switch(trx->magic) {
		case 0x47343557: /* W54G */
		case 0x53343557: /* W54S */
		case 0x73343557: /* W54s */
		case 0x46343557: /* W54F */
		case 0x55343557: /* W54U */
			/* ignore the first 32 bytes */
			buflen = read(imagefd, buf, sizeof(struct trx_header));
			break;
	}
	
	if (trx->magic != TRX_MAGIC || trx->len < sizeof(struct trx_header)) {
		fprintf(stderr, "Bad trx header\n");
		fprintf(stderr, "If this is a firmware in bin format, like some of the\n"
				"original firmware files are, use following command to convert to trx:\n"
				"dd if=firmware.bin of=firmware.trx bs=32 skip=1\n");
		return 0;
	}

	/* check if image fits to mtd device */
	fd = mtd_open(mtd, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Could not open mtd device: %s\n", mtd);
		exit(1);
	}

	if(ioctl(fd, MEMGETINFO, &mtdInfo)) {
		fprintf(stderr, "Could not get MTD device info from %s\n", mtd);
		exit(1);
	}
		
	if(mtdInfo.size < trx->len) {
		fprintf(stderr, "Image too big for partition: %s\n", mtd);
		close(fd);
		return 0;
	}	
	
	return 1;
}

int
image_check(int imagefd, const char *mtd)
{
	int fd, systype;
	size_t count;
	char *c;
	FILE *f;

	systype = SYSTYPE_UNKNOWN;
	f = fopen("/proc/cpuinfo", "r");
	while (!feof(f) && (fgets(buf, BUFSIZE - 1, f) != NULL)) {
		if ((strncmp(buf, "system type", 11) == 0) && (c = strchr(buf, ':'))) {
			c += 2;
			if (strncmp(c, "Broadcom BCM947XX", 17) == 0)
				systype = SYSTYPE_BROADCOM;
		}
	}
	fclose(f);
	
	switch(systype) {
		case SYSTYPE_BROADCOM:
			return image_check_bcom(imagefd, mtd);
		default:
			return 1;
	}
}

int mtd_check(char *mtd)
{
	struct mtd_info_user mtdInfo;
	int fd;

	fd = mtd_open(mtd, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Could not open mtd device: %s\n", mtd);
		return 0;
	}

	if(ioctl(fd, MEMGETINFO, &mtdInfo)) {
		fprintf(stderr, "Could not get MTD device info from %s\n", mtd);
		close(fd);
		return 0;
	}

	close(fd);
	return 1;
}

int
mtd_unlock(const char *mtd)
{
	int fd;
	struct mtd_info_user mtdInfo;
	struct erase_info_user mtdLockInfo;

	fd = mtd_open(mtd, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Could not open mtd device: %s\n", mtd);
		exit(1);
	}

	if(ioctl(fd, MEMGETINFO, &mtdInfo)) {
		fprintf(stderr, "Could not get MTD device info from %s\n", mtd);
		close(fd);
		exit(1);
	}

	mtdLockInfo.start = 0;
	mtdLockInfo.length = mtdInfo.size;
	if(ioctl(fd, MEMUNLOCK, &mtdLockInfo)) {
		close(fd);
		return 0;
	}
		
	close(fd);
	return 0;
}

int
mtd_open(const char *mtd, int flags)
{
	FILE *fp;
	char dev[PATH_MAX];
	int i;

	if ((fp = fopen("/proc/mtd", "r"))) {
		while (fgets(dev, sizeof(dev), fp)) {
			if (sscanf(dev, "mtd%d:", &i) && strstr(dev, mtd)) {
				snprintf(dev, sizeof(dev), "/dev/mtd/%d", i);
				fclose(fp);
				return open(dev, flags);
			}
		}
		fclose(fp);
	}

	return open(mtd, flags);
}

int
mtd_erase(const char *mtd, int sector, int skipbad)
{
	int fd;
	struct mtd_info_user mtdInfo;
	struct erase_info_user mtdEraseInfo;
	int eraseTop;

	fd = mtd_open(mtd, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Could not open mtd device: %s\n", mtd);
		exit(1);
	}

	if(ioctl(fd, MEMGETINFO, &mtdInfo)) {
		fprintf(stderr, "Could not get MTD device info from %s\n", mtd);
		close(fd);
		exit(1);
	}

	mtdEraseInfo.length = mtdInfo.erasesize;

	if (sector >= 0) {
		mtdEraseInfo.start = sector * mtdInfo.erasesize;
		if (mtdEraseInfo.start < 0 || mtdEraseInfo.start >= mtdInfo.size) {
			fprintf(stderr, "Bad sector specified for device: %s\n", mtd);
			close(fd);
			exit(1);
		}
		eraseTop = mtdEraseInfo.start + mtdInfo.erasesize;
	} else {
		mtdEraseInfo.start = 0;
		eraseTop = mtdInfo.size;
	}
	
	for (;
		 mtdEraseInfo.start < eraseTop;
		 mtdEraseInfo.start += mtdInfo.erasesize) {
		
		ioctl(fd, MEMUNLOCK, &mtdEraseInfo);
		if(ioctl(fd, MEMERASE, &mtdEraseInfo)) {
			fprintf(stderr, "Could not erase MTD device: %s\n", mtd);
			if (!skipbad) {
				close(fd);
				exit(1);
			}
		}
		do_sleep();

	}		

	close(fd);
	return 0;

}

int
mtd_write(int imagefd, const char *mtd, int quiet)
{
	int fd, i, result;
	size_t r, w, e;
	struct mtd_info_user mtdInfo;
	struct erase_info_user mtdEraseInfo;

	fd = mtd_open(mtd, O_RDWR);
	if(fd < 0) {
		fprintf(stderr, "Could not open mtd device: %s\n", mtd);
		exit(1);
	}

	if(ioctl(fd, MEMGETINFO, &mtdInfo)) {
		fprintf(stderr, "Could not get MTD device info from %s\n", mtd);
		close(fd);
		exit(1);
	}
		
	r = w = e = 0;
	if (!quiet)
		fprintf(stderr, " [ ]");

	for (;;) {
		/* buffer may contain data already (from trx check) */
		r = buflen;
		r += read(imagefd, buf + buflen, BUFSIZE - buflen);
		w += r;

		/* EOF */
		if (r <= 0) break;

		/* need to erase the next block before writing data to it */
		while (w > e) {
			mtdEraseInfo.start = e;
			mtdEraseInfo.length = mtdInfo.erasesize;

			if (!quiet)
				fprintf(stderr, "\b\b\b[e]");
			/* erase the chunk */
			if (ioctl (fd,MEMERASE,&mtdEraseInfo) < 0) {
				fprintf(stderr, "Erasing mtd failed: %s\n", mtd);
				exit(1);
			}
			e += mtdInfo.erasesize;

			do_sleep();
		}
		
		if (!quiet)
			fprintf(stderr, "\b\b\b[w]");

		{
			int to_write = r;
			char *buf_ptr = buf;
			while (to_write > 0) {
				result = write(fd, buf_ptr, to_write);
				if (result < 0) {
					fprintf(stderr, "Error writing image.\n");
					exit(1);
				} else {
					to_write -= result;
					buf_ptr += result;
				}
			}
		}
		
		buflen = 0;
		do_sleep();
	}
	if (!quiet)
		fprintf(stderr, "\b\b\b\b");
	
	return 0;
}

void usage(void)
{
	fprintf(stderr, "Usage: mtd [<options> ...] <command> [<arguments> ...] <device>\n\n"
	"The device is in the format of mtdX (eg: mtd4) or its label.\n"
	"mtd recognizes these commands:\n"
	"        unlock                  unlock the device\n"
	"        erase                   erase all data on device\n"
	"        write <imagefile>|-     write <imagefile> (use - for stdin) to device\n"
	"Following options are available:\n"
	"        -q                      quiet mode (once: no [w] on writing,\n"
	"                                           twice: no status messages)\n"
	"        -r                      reboot after successful command\n"
	"        -s                      regularly sleep while doing the command\n"
	"        -f                      force write without trx checks\n"
	"        -x                      skip bad blocks on erase\n"
	"        -e <device>             erase <device> before executing the command\n\n"
	"Example: To write linux.trx to mtd4 labeled as linux and reboot afterwards\n"
	"         mtd -r write linux.trx linux\n\n");
	exit(1);
}

int main (int argc, char **argv)
{
	int ch, i, boot, unlock, imagefd, force, quiet, unlocked, sector, skipbad;
	char *erase[MAX_ARGS], *device, *imagefile;
	enum {
		CMD_ERASE,
		CMD_WRITE,
		CMD_UNLOCK
	} cmd;
	
	erase[0] = NULL;
	boot = 0;
	force = 0;
	buflen = 0;
	quiet = 0;
	sector = -1;
	skipbad = 0;

	while ((ch = getopt(argc, argv, "frxqse:")) != -1)
		switch (ch) {
			case 'f':
				force = 1;
				break;
			case 'r':
				boot = 1;
				break;
			case 'x':
				skipbad = 1;
				break;
			case 'q':
				quiet++;
				break;
			case 's':
				should_sleep++;
				break;
			case 'e':
				i = 0;
				while ((erase[i] != NULL) && ((i + 1) < MAX_ARGS))
					i++;
					
				erase[i++] = optarg;
				erase[i] = NULL;
				break;
			
			case '?':
			default:
				usage();
		}
	argc -= optind;
	argv += optind;
	
	if (argc < 2)
		usage();

	if ((strcmp(argv[0], "unlock") == 0) && (argc == 2)) {
		cmd = CMD_UNLOCK;
		device = argv[1];
	} else if ((strcmp(argv[0], "erase") == 0) && (argc == 2)) {
		cmd = CMD_ERASE;
		device = argv[1];
	} else if ((strcmp(argv[0], "erase") == 0) && (argc == 3)) {
		cmd = CMD_ERASE;
		device = argv[1];
		sector = atoi(argv[2]);
	} else if ((strcmp(argv[0], "write") == 0)) {
                // MERAKI Special handling for out-of-order "-e"
                // option to allow backwards compatibility with old
                // upgrade scripts.
		optind = 0;
		if (erase[0] == NULL) {
			while ((ch = getopt(argc, argv, "e:")) != -1) {
				switch (ch) {
				case 'e':
					i = 0;
					while ((erase[i] != NULL) && ((i + 1) < MAX_ARGS))
						i++;

					erase[i++] = optarg;
					erase[i] = NULL;
					break;
				default:
					usage();
				}
			}
			argc -= optind;
			argv += optind;
		} else {
			argc--;
			argv++;
		}

		if (argc != 2)
			usage();

		cmd = CMD_WRITE;
		device = argv[1];

		if (strcmp(argv[0], "-") == 0) {
			imagefile = "<stdin>";
			imagefd = 0;
		} else {
			imagefile = argv[0];
			if ((imagefd = open(argv[0], O_RDONLY)) < 0) {
				fprintf(stderr, "Couldn't open image file: %s!\n", imagefile);
				exit(1);
			}
		}
	
		/* check trx file before erasing or writing anything */
		if (!image_check(imagefd, device)) {
			if ((quiet < 2) || !force)
				fprintf(stderr, "TRX check failed!\n");
			if (!force)
				exit(1);
		} else {
			if (!mtd_check(device)) {
				fprintf(stderr, "Can't open device for writing!\n");
				exit(1);
			}
		}
	} else {
		usage();
	}

	sync();
	
	i = 0;
	unlocked = 0;
	while (erase[i] != NULL) {
		if (quiet < 2)
			fprintf(stderr, "Unlocking %s ...\n", erase[i]);
		mtd_unlock(erase[i]);
		if (quiet < 2)
			fprintf(stderr, "Erasing %s ...\n", erase[i]);
		mtd_erase(erase[i], -1, skipbad);
		if (strcmp(erase[i], device) == 0)
			unlocked = 1;
		i++;
	}
	
	if (!unlocked) {
		if (quiet < 2) 
			fprintf(stderr, "Unlocking %s ...\n", device);
		mtd_unlock(device);
	}
		
	switch (cmd) {
		case CMD_UNLOCK:
			break;
		case CMD_ERASE:
			if (quiet < 2)
				fprintf(stderr, "Erasing %s ...\n", device);
			mtd_erase(device, sector, skipbad);
			break;
		case CMD_WRITE:
			if (quiet < 2)
				fprintf(stderr, "Writing from %s to %s ... ", imagefile, device);
			mtd_write(imagefd, device, quiet);
			if (quiet < 2)
				fprintf(stderr, "\n");
			break;
	}

	if (boot)
		kill(1, 15); // send SIGTERM to init for reboot

	return 0;
}
