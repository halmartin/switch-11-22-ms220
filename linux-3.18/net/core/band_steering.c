#include <linux/module.h>
#include <linux/types.h>
#include <linux/band_steering.h>
#include <linux/init.h>
#include "click_offload.c"

static band_steering_cb band_steering_check_cb = 0;

int
band_steering_check_client(uint8_t *mac)
{
    if (band_steering_check_cb) {
        return band_steering_check_cb(mac);
    }
    return 0;
}

int
register_band_steering_check_cb(band_steering_cb cb)
{
    if (band_steering_check_cb) {
        printk("%s: overwriting current cb\n", __func__);
    }
    band_steering_check_cb = cb;
    return 0;
}

int
unregister_band_steering_check_cb(band_steering_cb cb)
{
    if (band_steering_check_cb == cb) {
        band_steering_check_cb = 0;
    } else {
        printk("%s: unregister cb mismatch\n", __func__);
    }
    return 0;
}

EXPORT_SYMBOL(band_steering_check_client);
EXPORT_SYMBOL(register_band_steering_check_cb);
EXPORT_SYMBOL(unregister_band_steering_check_cb);

static click_dfs_mute_cb dfs_mute_channel_cb = 0;

int
get_dfs_mute_channel(uint8_t radio)
{
    if (dfs_mute_channel_cb) {
        return dfs_mute_channel_cb(radio);
    }
    return 0;
}

int
register_dfs_mute_channel_cb(click_dfs_mute_cb cb)
{
    if (dfs_mute_channel_cb) {
        printk("%s: overwriting current cb\n", __func__);
    }
    dfs_mute_channel_cb = cb;
    return 0;
}

int
unregister_dfs_mute_channel_cb(click_dfs_mute_cb cb)
{
    if (dfs_mute_channel_cb == cb) {
        dfs_mute_channel_cb = 0;
    } else {
        printk("%s: unregister cb mismatch\n", __func__);
    }
    return 0;
}

EXPORT_SYMBOL(get_dfs_mute_channel);
EXPORT_SYMBOL(register_dfs_mute_channel_cb);
EXPORT_SYMBOL(unregister_dfs_mute_channel_cb);

/* callbacks for ap steering */
static ap_steering_cb ap_steering_check_cb = 0;

int
ap_steering_check_client(uint8_t *mac, int vapnum, bool reassoc)
{
    int i;
    if (ap_steering_check_cb) {
        return ap_steering_check_cb(mac, vapnum, reassoc);
    }
    return 0;
}

int
register_ap_steering_check_cb(ap_steering_cb cb)
{
    if (ap_steering_check_cb) {
        printk("%s: overwriting current ap steering cb\n", __func__);
    }
    ap_steering_check_cb = cb;
    return 0;
}

int
unregister_ap_steering_check_cb(ap_steering_cb cb)
{
    if (ap_steering_check_cb == cb) {
        ap_steering_check_cb = 0;
    } else {
        printk("%s: no ap steering cb\n", __func__);
    }
    return 0;
}

EXPORT_SYMBOL(ap_steering_check_client);
EXPORT_SYMBOL(register_ap_steering_check_cb);
EXPORT_SYMBOL(unregister_ap_steering_check_cb);
/* end of ap steering callbacks */

char *_global_hw_problem = 0;
EXPORT_SYMBOL(_global_hw_problem);

int _global_wireless_log = 0;
EXPORT_SYMBOL(_global_wireless_log);

#define MAX_CALLBACKS 10
static mn_cb mn_callbacks[MAX_CALLBACKS];
static void *mn_context[MAX_CALLBACKS];

int
register_meraki_neighbor(uint8_t *dev_mac, uint8_t *mac, int channel, int ht40, int ht)
{
    int x = 0;
    for (x = 0; x < MAX_CALLBACKS; x++) {
        if (mn_callbacks[x]) {
            mn_callbacks[x](mn_context[x], dev_mac, mac, channel, ht40, ht);
        }
    }
    return 0;
}

int
register_meraki_neighbor_cb(mn_cb c, void *context)
{
    int x = 0;
    for (x = 0; x < MAX_CALLBACKS; x++) {
        if (mn_callbacks[x] == 0 && mn_context[x] == 0) {
            mn_callbacks[x] = c;
            mn_context[x] = context;
            return 0;
        }
    }
    return -1;
}

int
unregister_meraki_neighbor_cb(mn_cb c, void *context)
{
    int x = 0;
    for (x = 0; x < MAX_CALLBACKS; x++) {
        if (mn_callbacks[x] == c && mn_context[x] == context) {
            mn_callbacks[x] = 0;
            mn_context[x] = 0;
            return 0;
        }
    }
    return -1;
}

EXPORT_SYMBOL(register_meraki_neighbor);
EXPORT_SYMBOL(register_meraki_neighbor_cb);
EXPORT_SYMBOL(unregister_meraki_neighbor_cb);

static meraki_wifi_event_cb meraki_wifi_event_callbacks[MAX_CALLBACKS];
static void *meraki_wifi_event_context[MAX_CALLBACKS];

int
meraki_wifi_event(int event, uint8_t *if_wifiname, int channel, int ht40)
{
    int x = 0;
    for (x = 0; x < MAX_CALLBACKS; x++) {
        if (meraki_wifi_event_callbacks[x]) {
            meraki_wifi_event_callbacks[x](event, if_wifiname, channel, ht40, meraki_wifi_event_context[x]);
        }
    }
    return 0;
}

int
register_meraki_wifi_event_cb(meraki_wifi_event_cb c, void *context)
{
    int x = 0;
    for (x = 0; x < MAX_CALLBACKS; x++) {
        if (meraki_wifi_event_callbacks[x] == 0 && meraki_wifi_event_context[x] == 0) {
            meraki_wifi_event_callbacks[x] = c;
            meraki_wifi_event_context[x] = context;
            return 0;
        }
    }
    printk("MERAKI_WIFI_EVENT cb registration failed!\n");
    return -1;
}

int
unregister_meraki_wifi_event_cb(meraki_wifi_event_cb c, void *context)
{
    int x = 0;
    for (x = 0; x < MAX_CALLBACKS; x++) {
        if (meraki_wifi_event_callbacks[x] == c && meraki_wifi_event_context[x] == context) {
            meraki_wifi_event_callbacks[x] = 0;
            meraki_wifi_event_context[x] = 0;
            return 0;
        }
    }
    printk("MERAKI_WIFI_EVENT cb unregistration failed!\n");
    return -1;
}

EXPORT_SYMBOL(meraki_wifi_event);
EXPORT_SYMBOL(register_meraki_wifi_event_cb);
EXPORT_SYMBOL(unregister_meraki_wifi_event_cb);

driver_packet_counter_cb __packet_event_cb;
void *__packet_event_cb_context;

int
register_driver_packet_counter_cb(driver_packet_counter_cb cb, void *context)
{
    if (__packet_event_cb == 0) {
        __packet_event_cb = cb;
        __packet_event_cb_context = context;
        return 0;
    }
    printk("packet tracker cb registration failed!\n");
    return -1;
}

int
unregister_driver_packet_counter_cb(driver_packet_counter_cb cb, void *context)
{
    if (__packet_event_cb == cb && __packet_event_cb_context == context) {
        __packet_event_cb = 0;
        __packet_event_cb_context = 0;
        return 0;
    }
    printk("packet tracker cb unregistration failed!\n");
    return -1;
}

EXPORT_SYMBOL(__packet_event_cb);
EXPORT_SYMBOL(__packet_event_cb_context);
EXPORT_SYMBOL(register_driver_packet_counter_cb);
EXPORT_SYMBOL(unregister_driver_packet_counter_cb);

click_packet_event_cb __click_packet_event_cb;
void *__click_packet_event_cb_context;

click_packet_type_event_cb __click_packet_type_event_cb;
void *__click_packet_type_event_cb_context;

click_flow_event_cb __click_flow_event_cb;
void *__click_flow_event_cb_context;

int
register_click_packet_event_cb(click_packet_event_cb cb, void *context, click_packet_type_event_cb cb2, void *context2, click_flow_event_cb cb3, void *context3)
{
    if (__click_packet_event_cb_context == 0) {
        __click_packet_event_cb = cb;
        __click_packet_event_cb_context = context;
        __click_packet_type_event_cb = cb2;
        __click_packet_type_event_cb_context = context2;
        __click_flow_event_cb = cb3;
        __click_flow_event_cb_context = context3;
        return 0;
    }
    printk("click packet tracker cb registration failed!\n");
    return -1;
}

// 3 radios * 16 vaps * 4 qos levels
#define MAX_Q 192
typedef struct click_msg_entry {
    uint8_t qos_priority;
    uint8_t radio_num;
    void * context;
    click_queue_signal_cb cb;
} click_msg_entry;

static click_msg_entry qosq_msg_reg[MAX_Q];

int
click_queue_signal(uint8_t radio, uint8_t *mac, uint8_t qos, int signal)
{
    int x = 0;
    for (x = 0; x < MAX_Q; x++) {
        if (qosq_msg_reg[x].context
            && qosq_msg_reg[x].qos_priority == qos
            && qosq_msg_reg[x].radio_num == radio) {
            qosq_msg_reg[x].cb(qosq_msg_reg[x].context, 0, mac, 0, signal);
        }
    }
    return 0;
}

int
register_click_queue_signal_cb(click_queue_signal_cb cb, void *context, unsigned int qos, unsigned int radio_num)
{
    int x = 0;
    for (x = 0; x < MAX_Q; x++) {
        if (qosq_msg_reg[x].cb == 0
            && qosq_msg_reg[x].context == 0) {
            qosq_msg_reg[x].cb = cb;
            qosq_msg_reg[x].context = context;
            qosq_msg_reg[x].radio_num = radio_num;
            qosq_msg_reg[x].qos_priority = qos;
            return 0;
        }
    }
    printk("Click Queue signal cb registration failed!\n");
    return -1;
}

int
unregister_click_packet_event_cb(void *context)
{
    if (__click_packet_event_cb_context == context) {
        __click_packet_event_cb = 0;
        __click_packet_type_event_cb = 0;
        __click_packet_event_cb_context = 0;
        __click_flow_event_cb = 0;
        __click_flow_event_cb_context = 0;
        return 0;
    }
    printk("click packet tracker cb unregistration failed!\n");
    return -1;
}

int
unregister_click_queue_signal_cb(click_queue_signal_cb cb, void *context)
{
    int x = 0;
    for (x = 0; x < MAX_Q; x++) {
        if (qosq_msg_reg[x].cb == cb && qosq_msg_reg[x].context == context) {
            qosq_msg_reg[x].cb = 0;
            qosq_msg_reg[x].context = 0;
            return 0;
        }
    }
    printk("Click Queue unregistration failed!\n");
    return -1;
}

EXPORT_SYMBOL(__click_flow_event_cb);
EXPORT_SYMBOL(__click_flow_event_cb_context);
EXPORT_SYMBOL(__click_packet_event_cb);
EXPORT_SYMBOL(__click_packet_event_cb_context);
EXPORT_SYMBOL(__click_packet_type_event_cb);
EXPORT_SYMBOL(__click_packet_type_event_cb_context);
EXPORT_SYMBOL(register_click_packet_event_cb);
EXPORT_SYMBOL(unregister_click_packet_event_cb);
EXPORT_SYMBOL(click_queue_signal);
EXPORT_SYMBOL(register_click_queue_signal_cb);
EXPORT_SYMBOL(unregister_click_queue_signal_cb);

// The mac address used by AeroScout tags to indicate tag blinks.
// Not related to band steering at all. Just defined here as it needs to be defined in the
// kernel so the wireless driver and click can access it.
uint8_t _global_ascout_mcast_mac[6] = { 0x01, 0x0C, 0xCC, 0x00, 0x00, 0x00 };
EXPORT_SYMBOL(_global_ascout_mcast_mac);
