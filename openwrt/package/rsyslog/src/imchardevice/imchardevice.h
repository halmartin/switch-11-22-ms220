/* imchardevice.h
 * These are the definitions for the chardevice message generation module.
 *
 * Copyright 2007-2012 Rainer Gerhards and Adiscon GmbH.
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
#ifndef	IMKLOG_H_INCLUDED
#define	IMKLOG_H_INCLUDED 1

#include "rsyslog.h"
#include "dirty.h"

/* we need to have the modConf type present in all submodules */
struct modConfData_s {
	rsconf_t *pConf;
	int iFacilIntMsg;
	uchar *pszPath;
	int console_log_level;
	sbool bPermitNonKernel;
	sbool configSetViaV2Method;
};

/* interface to "drivers"
 * the platform specific drivers must implement these entry points. Only one
 * driver may be active at any given time, thus we simply rely on the linker
 * to resolve the addresses.
 * rgerhards, 2008-04-09
 */
rsRetVal charDeviceLogMsg(modConfData_t *pModConf);
rsRetVal charDeviceWillRunPrePrivDrop(modConfData_t *pModConf);
rsRetVal charDeviceWillRunPostPrivDrop(modConfData_t *pModConf);
rsRetVal charDeviceAfterRun(modConfData_t *pModConf);
int charDeviceFacilIntMsg();

/* the functions below may be called by the drivers */
rsRetVal charDeviceLogIntMsg(syslog_pri_t priority, char *fmt, ...) __attribute__((format(printf,2, 3)));
rsRetVal Syslog(uchar *msg);

/* prototypes */
extern int InitKsyms(modConfData_t*);
extern void DeinitKsyms(void);
extern int InitMsyms(void);
extern void DeinitMsyms(void);
extern char * ExpandKadds(char *, char *);
extern void SetParanoiaLevel(int);

#endif /* #ifndef IMKLOG_H_INCLUDED */
/* vi:set ai:
 */
