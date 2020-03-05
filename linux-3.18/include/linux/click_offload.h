#ifndef _CLICK_OFFLOAD_H
#define _CLICK_OFFLOAD_H

#include <linux/skbuff.h>

/*
 * click flow offload interfaces
 */
struct click_ipv4_tuple {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
    uint8_t  reserved[3];
};

struct click_ipv4_rule_msg {
    struct click_ipv4_tuple flow;
    struct click_ipv4_tuple rev_flow;
    struct click_ipv4_tuple xlate_flow;
    char *sdevname;
    char *ddevname;
    uint8_t smac[6];
    uint8_t dmac[6];
    int16_t vlan;
    uint8_t qos;
    uint8_t dscp;
    bool isroute;
};

struct click_offloader_operations {
    int (*create_ipv4_rule)(struct click_ipv4_rule_msg *msg);
    int (*destroy_ipv4_rule)(struct click_ipv4_rule_msg *msg);
};

int register_click_offloader_ops(const struct click_offloader_operations *ops);
void unregister_click_offloader_ops(void);
bool click_offloader_enabled(void);

int click_offloader_create_ipv4_rule(struct click_ipv4_rule_msg *msg);
int click_offloader_destroy_ipv4_rule(struct click_ipv4_rule_msg *msg);

/*
 * click offloader event notification
 */
enum click_offload_event_type {
    CLICK_OFFLOAD_IPV4_CREATE_RULE_ACK,   /**< IPv4 create rule message */
    CLICK_OFFLOAD_IPV4_DESTROY_RULE_ACK,  /**< IPv4 destroy rule message */
    CLICK_OFFLOAD_IPV4_PER_FLOW_STATS,    /**< IPv4 connection stats sync message */
    CLICK_OFFLOAD_IPV4_MAX_EVENTS,        /**< IPv4 message max type number */
};

enum click_offload_status {
    CLICK_OFFLOAD_STATUS_OK,
    CLICK_PFFLOAD_STATUS_FAILURE,
    CLICK_OFFLOAD_STATUS_FLOW_FLUSHED,
};

struct click_offload_flow_stats {
    uint32_t rx_packets;  /**< Flow interface's RX packet count */
    uint32_t rx_bytes;    /**< Flow interface's RX byte count */
    uint32_t tx_packets;  /**< Flow interface's TX packet count */
    uint32_t tx_bytes;    /**< Flow interface's TX byte count */
};

struct click_offload_event {
    struct click_ipv4_tuple flow;
    enum click_offload_event_type type;
    enum click_offload_status status;
    struct click_offload_flow_stats stats;
};

typedef void(*click_offload_event_cb_t)(struct click_offload_event *event, void *data);

int register_click_offload_event_cb(click_offload_event_cb_t cb, void *data);
void unregister_click_offload_event_cb(void);

void click_offloader_event_notify(struct click_offload_event *event);

bool click_offload_bond_realdev_name(struct sk_buff *skb, const char *bond_dev, char *real_dev);

#endif /* _CLICK_OFFLOAD_H */
