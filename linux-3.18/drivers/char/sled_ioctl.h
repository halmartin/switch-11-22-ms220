#include <linux/ioctl.h>

#define MAGIC_CHAR		'S'
#define IOCTL_LED_SET_STATUS	_IOW(MAGIC_CHAR, 0, int)

#define LED_SET_STATUS_OFF	    0x00
#define LED_SET_STATUS_ORANGE	0x01
#define LED_SET_STATUS_YELLOW	0x02