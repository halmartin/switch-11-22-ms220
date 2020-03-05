#include <linux/ioctl.h>

#define MAGIC_CHAR 'B'
#define IOCTL_BTN_GET_STATUS    _IOW(MAGIC_CHAR, 0, int)

#define BTN_STATUS_RELEASED 0x00
#define BTN_STATUS_PRESSED  0x01
