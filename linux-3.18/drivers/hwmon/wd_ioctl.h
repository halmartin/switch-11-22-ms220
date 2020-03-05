#include <linux/ioctl.h>

#define MAGIC_CHAR 'W'

/* Set bypass enable/disable in runtime */
#define IOCTL_RUNTIME_BYPASS_STATE	_IOW(MAGIC_CHAR, 0, int)
#define RUNTIME_BYPASS_STATE_ENABLE_LAN_ALL	0
#define RUNTIME_BYPASS_STATE_ENABLE_LAN_12	1
#define RUNTIME_BYPASS_STATE_ENABLE_LAN_34	2
#define RUNTIME_BYPASS_STATE_DISABLE_LAN_ALL	3
#define RUNTIME_BYPASS_STATE_DISABLE_LAN_12		4
#define RUNTIME_BYPASS_STATE_DISABLE_LAN_34		5

/* Set bypass enable/disable when system off*/
#define IOCTL_SYSTEM_OFF_BYPASS_STATE	_IOW(MAGIC_CHAR, 1, int)
#define SYSTEM_OFF_BYPASS_STATE_ENABLE	0
#define SYSTEM_OFF_BYPASS_STATE_DISABLE	1

/* Start/Stop Watchdog timer */
#define IOCTL_START_STOP_WDT		_IOW(MAGIC_CHAR, 2, int)
#define START_WDT			0
#define STOP_WDT			1

/* Set the status while watchdog timeout */
#define IOCTL_SET_WDTO_STATE		_IOW(MAGIC_CHAR, 3, int)
#define SET_WDTO_STATE_LAN_BYPASS	0
#define SET_WDTO_STATE_SYSTEM_RESET	1

/* Set the watchdog timer */
#define IOCTL_SET_WDTO_TIMER		_IOW(MAGIC_CHAR, 4, int)