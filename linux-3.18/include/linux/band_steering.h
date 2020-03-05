#ifndef _LINUX_BANDSTEERING_H
#define _LINUX_BANDSTEERING_H

#include <linux/slab.h>
#include <linux/click_offload.h>

typedef int(*band_steering_cb)(uint8_t *mac);
int band_steering_check_client(uint8_t *mac);
int register_band_steering_check_cb(band_steering_cb);
int unregister_band_steering_check_cb(band_steering_cb);

typedef int(*click_dfs_mute_cb)(uint8_t radio);
int get_dfs_mute_channel(uint8_t radio);
int register_dfs_mute_channel_cb(click_dfs_mute_cb);
int unregister_dfs_mute_channel_cb(click_dfs_mute_cb);

/* callbacks for ap steering */
typedef int(*ap_steering_cb)(uint8_t *mac, int vapnum, bool reassoc);
int ap_steering_check_client(uint8_t *mac, int vapnum, bool reassoc);
int register_ap_steering_check_cb(ap_steering_cb);
int unregister_ap_steering_check_cb(ap_steering_cb);

/* for TCP Fast ACK */
#define MERAKI_MAX_FAST_FLOWS 60
#define MERAKI_MAX_STATUS_BLOCKS 32
#define TCP_FAST_ACK 0
#define MAX_TCP_FAST_FLOWS_PER_CLIENT 10        /* Meraki - max. TCP fast_acked flows/client */

/* struct for TCP fast-ACK,
 * included in the <MerakiFlowStatus> for each flow passed in
 * click callbacks
*/
typedef struct AckedBlock_t {
   uint32_t _start_seq_no;      // start TCP seq_num for block
   uint32_t _end_seq_no;        // end TCP seq_num
} __attribute__((__packed__)) AckedBlock;

/* For each fast-acked flow, this struct is filled in the
 * TX completion events, and relays the information about the layer-2
 * acks for each flow
 *
*/
struct MerakiFlowStatus {
   AckedBlock _acked_blocks[MERAKI_MAX_STATUS_BLOCKS];
   uint8_t _num_blocks;         // num of <AckedBlock>
   uint16_t _fid;               // flowId
   uint16_t _uniqueId;          // used in case flow stales out before l2 ack
   uint8_t _padding[3];         // to align it
} __attribute__((__packed__));

extern char *_global_hw_problem;

static inline char *
global_hw_problem_get(void) {
    return _global_hw_problem;
}
static inline void
global_hw_problem_set(char *reason)
{
    if (!_global_hw_problem && reason) {
        _global_hw_problem = kmalloc(strlen(reason) + 1, GFP_ATOMIC);
        memcpy(_global_hw_problem, reason, strlen(reason));
        _global_hw_problem[strlen(reason)] = '\0';
        printk("HW problem detected; reason %s\n", _global_hw_problem);
    }
}

extern int _global_wireless_log;

static inline int
global_wireless_log_get(void) {
    return _global_wireless_log;
}
static inline void
global_wireless_log_set(int ok)
{
    _global_wireless_log = ok;
}

typedef int(*mn_cb)(void *context, uint8_t *dev_mac, uint8_t *mac, int channel, int ext, int ht);
int register_meraki_neighbor(uint8_t *dev_mac, uint8_t *mac, int channel, int ht40, int ht);
int register_meraki_neighbor_cb(mn_cb, void *context);
int unregister_meraki_neighbor_cb(mn_cb, void *context);

typedef int(*meraki_wifi_event_cb)(int event, uint8_t *if_wifiname, int channel, int ht40, void *context);

enum {
  MERAKI_WIFI_DFS_EVENT = 1,
  MERAKI_WIFI_BEACON_STUCK = 2,
  MERAKI_WIFI_BEACON_RELOAD = 3,
};
int meraki_wifi_event(int event, uint8_t *if_wifiname, int channel, int ht40);

int register_meraki_wifi_event_cb(meraki_wifi_event_cb, void *context);
int unregister_meraki_wifi_event_cb(meraki_wifi_event_cb, void *context);

typedef void(*driver_packet_counter_cb)(void *context, uint8_t *mac, uint32_t seq, uint32_t type, uint8_t bitrate);
extern driver_packet_counter_cb __packet_event_cb;
extern void *__packet_event_cb_context;
static inline void packet_event(uint8_t *mac, uint32_t seq, uint32_t type, uint8_t bitrate) {
  if (__packet_event_cb)
    __packet_event_cb(__packet_event_cb_context, mac, seq, type, bitrate);
}
int register_driver_packet_counter_cb(driver_packet_counter_cb, void *context);
int unregister_driver_packet_counter_cb(driver_packet_counter_cb, void *context);

#define CLICK_PACKET_EVENT_TX     0x1
#define CLICK_PACKET_EVENT_RETRY  0x2
#define CLICK_PACKET_EVENT_TXFAIL 0x4
#define CLICK_PACKET_EVENT_ISAGGR 0x8
#define CLICK_PACKET_EVENT_MOREAGGR 0x10
typedef void(*click_packet_event_cb)(void *context, const char *dev, uint8_t *mac, uint32_t flags, uint8_t bitrate);
extern click_packet_event_cb __click_packet_event_cb;
extern void *__click_packet_event_cb_context;
typedef void(*click_packet_type_event_cb)(void *context, const char *dev, uint8_t *mac, uint32_t type, uint32_t extra);
extern click_packet_type_event_cb __click_packet_type_event_cb;
extern void *__click_packet_type_event_cb_context;
static inline void click_packet_event(const char *dev, uint8_t *mac, uint32_t flags, uint8_t bitrate) {
  if (__click_packet_event_cb)
    __click_packet_event_cb(__click_packet_event_cb_context, dev, mac, flags, bitrate);
}
static inline void click_packet_type_event(const char *dev, uint8_t *mac, uint32_t type, uint32_t extra) {
  if (__click_packet_type_event_cb)
    __click_packet_type_event_cb(__click_packet_type_event_cb_context, dev, mac, type, extra);
}

/* for flow events */
typedef void(*click_flow_event_cb)(void *context, const char *dev, uint8_t *mac, struct MerakiFlowStatus *flowStatus);
extern click_flow_event_cb __click_flow_event_cb;
extern void *__click_flow_event_cb_context;
static inline void click_flow_event(const char *dev, uint8_t *mac, struct MerakiFlowStatus *flowStatus) {
  if (__click_flow_event_cb)
    __click_flow_event_cb(__click_flow_event_cb_context, dev, mac, flowStatus);
}

#define CLICK_PACKET_TYPE_EVENT_TX        0x80000000
#define CLICK_PACKET_TYPE_EVENT_RAW_LEAVE 0x400000ff
int register_click_packet_event_cb(click_packet_event_cb, void *context, click_packet_type_event_cb, void *, click_flow_event_cb, void *);
int unregister_click_packet_event_cb(void *context);

typedef int(*click_queue_signal_cb)(void *context, uint8_t radio, uint8_t *mac, uint8_t qos, int signal);
extern int click_queue_signal(uint8_t radio, uint8_t *mac, uint8_t qos, int signal);
int register_click_queue_signal_cb(click_queue_signal_cb, void *context, unsigned int qos, unsigned int radio_num);
int unregister_click_queue_signal_cb(click_queue_signal_cb, void *context);

enum {
  MERAKI_APPLY_BACKPRESSURE = 0,
  MERAKI_RELEASE_BACKPRESSURE = 1,
};

static inline int click_start_queue(uint8_t radio, uint8_t *mac, uint8_t qos) {
    return click_queue_signal(radio, mac, qos, MERAKI_RELEASE_BACKPRESSURE);
}

static inline int click_stop_queue(uint8_t radio, uint8_t *mac, uint8_t qos) {
    return click_queue_signal(radio, mac, qos, MERAKI_APPLY_BACKPRESSURE);
}

extern uint8_t _global_ascout_mcast_mac[];

#endif /* _LINUX_BANDSTEERING_H */
