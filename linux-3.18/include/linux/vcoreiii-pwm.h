#ifndef __LINUX_VCOREIII_PWM_H
#define __LINUX_VCOREIII_PWM_H

#include <linux/err.h>
#include <linux/of.h>

#define MAX_DUTY 255
#define MAX_FREQ 7 // 0 - 7 : Frequency range

//FAN CFG Register offsets and widths
#define FAN_DUTY_OFFSET                 16
#define FAN_DUTY_WIDTH                  8
#define FAN_PWM_OFFSET                  3
#define FAN_PWM_WIDTH                   3
#define FAN_POLARITY_OFFSET             2
#define FAN_POLARITY_WIDTH              1
#define FAN_GATING_OFFSET               1
#define FAN_GATING_WIDTH                1
#define FAN_OPEN_COLLECTOR_OFFSET       0
#define FAN_OPEN_COLLECTOR_WIDTH        1
#define FAN_TACHO_OFFSET                0
#define FAN_TACHO_WIDTH                 16
#define FAN_GPIO_OVERLAY_PWM_OFFSET     29
#define FAN_GPIO_OVERLAY_PWM_WIDTH      1
#define FAN_GPIO_OVERLAY_TACHO_OFFSET   4
#define FAN_GPIO_OVERLAY_TACHO_WIDTH    1

//OVERLAY PROPERTY
#define PWM_OVERLAY                     0
#define TACHO_OVERLAY                   1

//OVERLAY MODE
#define OVERLAY_NORMAL_MODE             0
#define OVERLAY_MODE_ONE                1
#define OVERLAY_MODE_TWO                2

struct pwm_device;
struct pwm_fan_ctx {
    struct mutex reg_lock;
    struct pwm_device *pwm;
    };

enum pwm_polarity {
    PWM_POLARITY_NORMAL,
    PWM_POLARITY_INVERSED,
};

enum pwm_freq {
    PWM_FREQUENCY_25KHz,
    PWM_FREQUENCY_120Hz,
    PWM_FREQUENCY_100Hz,
    PWM_FREQUENCY_80Hz,
    PWM_FREQUENCY_60KHz,
    PWM_FREQUENCY_40Hz,
    PWM_FREQUENCY_20Hz,
    PWM_FREQUENCY_10Hz,
};

enum pwm_collector {
    PWM_COLLECTOR_NORMAL,
    PWM_COLLECTOR_OPEN,
};

enum pwm_gating {
    PWM_GATING_DISABLE,
    PWM_GATING_ENABLE,
};

// The member variables are meant only
// For initialization. Values thereafter
// are read directly from the registers.
struct pwm_device {
    const char          *label;
    enum pwm_freq       freq;           // in Hz
    unsigned int        duty_cycle;     // in nanoseconds
    enum pwm_polarity   polarity;
    enum pwm_collector  open_collector;
    enum pwm_gating     gating;
};

#endif /* __LINUX_VCOREIII_PWM_H */
