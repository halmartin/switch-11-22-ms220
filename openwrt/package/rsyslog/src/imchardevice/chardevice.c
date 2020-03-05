/* imchardevice driver for Linux char device logging
 *
 * This contains Linux-specific functionality to read char devices
 * For a general overview, see head comment in imchardevice.c.
 * This is heavily based on imklog bsd.c file.
 *
 * Copyright 2008-2014 Adiscon GmbH, 2016 Meraki Inc
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <json.h>

#include "rsyslog.h"
#include "srUtils.h"
#include "debug.h"
#include "imchardevice.h"

#define DEV_PATH "/dev/click_to_rsyslog"

/* globals */
static int	fchardevice = -1;	/* kernel log fd */


/* open the kernel log - will be called inside the willRun() imchardevice entry point
 */
rsRetVal
charDeviceWillRunPrePrivDrop(modConfData_t *pModConf)
{
	char errmsg[2048];
	DEFiRet;

	fchardevice = open(DEV_PATH, O_RDONLY, 0);
	if (fchardevice < 0) {
		charDeviceLogIntMsg(LOG_ERR, "imchardevice: cannot open char device (%s): %s.",
			DEV_PATH, rs_strerror_r(errno, errmsg, sizeof(errmsg)));
		ABORT_FINALIZE(RS_RET_ERR_OPEN_KLOG);
	}

finalize_it:
	RETiRet;
}

/* make sure the kernel log is readable after dropping privileges
 */
rsRetVal
charDeviceWillRunPostPrivDrop(modConfData_t *pModConf)
{
	char errmsg[2048];
	int r;
	DEFiRet;

	/* this normally returns EINVAL */
	/* on an OpenVZ VM, we get EPERM */
	struct timeval tv = {0};
	fd_set fds;
	FD_SET(fchardevice, &fds);
	r = select(fchardevice + 1, &fds, NULL, NULL, &tv);

	if (r < 0) {
		charDeviceLogIntMsg(LOG_ERR, "imchardevice: cannot open char device (%s): %s.",
			DEV_PATH, rs_strerror_r(errno, errmsg, sizeof(errmsg)));
		fchardevice = -1;
		ABORT_FINALIZE(RS_RET_ERR_OPEN_KLOG);
	}

finalize_it:
	RETiRet;
}

/* Read char device log while data are available, each read() reads one
 * record from buffer.
 */
static void
readmsg(void)
{
	int i;
	uchar pRcv[8192+1];
	char errmsg[2048];

	for (;;) {
		dbgprintf("imchardevice waiting for log line\n");

		/* every read() from the opened device node receives one record of the buffer */
		i = read(fchardevice, pRcv, 8192);

		if (i > 0) {
			/* successful read of message of nonzero length */
			pRcv[i] = '\0';
		} else if (i == -EPIPE) {
			charDeviceLogIntMsg(LOG_WARNING,
					"imchardevice: some messages in circular buffer got overwritten");
			continue;
		} else {
			/* something went wrong - error or zero length message */
			if (i < 0 && errno != EINTR && errno != EAGAIN) {
				/* error occured */
				charDeviceLogIntMsg(LOG_ERR,
				       "imchardevice: error reading log - shutting down: %s",
					rs_strerror_r(errno, errmsg, sizeof(errmsg)));
				fchardevice = -1;
			}
			break;
		}

		Syslog(pRcv);
	}
}


/* to be called in the module's AfterRun entry point
 * rgerhards, 2008-04-09
 */
rsRetVal charDeviceAfterRun(modConfData_t *pModConf)
{
	DEFiRet;
	if(fchardevice != -1)
		close(fchardevice);
	RETiRet;
}


/* to be called in the module's WillRun entry point, this is the main
 * "message pull" mechanism.
 * rgerhards, 2008-04-09
 */
rsRetVal charDeviceLogMsg(modConfData_t __attribute__((unused)) *pModConf)
{
	DEFiRet;
	readmsg();
	RETiRet;
}


/* provide the (system-specific) default facility for internal messages
 * rgerhards, 2008-04-14
 */
int
charDeviceFacilIntMsg(void)
{
	return LOG_SYSLOG;
}

