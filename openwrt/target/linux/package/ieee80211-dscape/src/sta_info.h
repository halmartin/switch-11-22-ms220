/*
 * Copyright 2002-2005, Devicescape Software, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef STA_INFO_H
#define STA_INFO_H

/* Stations flags (struct sta_info::flags) */
#define WLAN_STA_AUTH BIT(0)
#define WLAN_STA_ASSOC BIT(1)
#define WLAN_STA_PS BIT(2)
#define WLAN_STA_TIM BIT(3) /* TIM bit is on for PS stations */
#define WLAN_STA_PERM BIT(4) /* permanent; do not remove entry on expiration */
#define WLAN_STA_AUTHORIZED BIT(5) /* If 802.1X is used, this flag is
				    * controlling whether STA is authorized to
				    * send and receive non-IEEE 802.1X frames
				    */
#define WLAN_STA_SHORT_PREAMBLE BIT(7)
#define WLAN_STA_WME BIT(9)
#define WLAN_STA_XR BIT(26)
#define WLAN_STA_WDS BIT(27)


struct sta_info {
	struct list_head list;
	struct sta_info *hnext; /* next entry in hash table list */
	atomic_t users; /* number of users (do not remove if > 0) */

	u8 addr[ETH_ALEN];
	u16 aid; /* STA's unique AID (1..2007), 0 = not yet assigned */
	u32 flags; /* WLAN_STA_ */

	struct sk_buff_head ps_tx_buf; /* buffer of TX frames for station in
					* power saving state */
	int pspoll; /* whether STA has send a PS Poll frame */
	struct sk_buff_head tx_filtered; /* buffer of TX frames that were
					  * already given to low-level driver,
					  * but were filtered */
	int clear_dst_mask;

	unsigned long rx_packets, tx_packets; /* number of RX/TX MSDUs */
	unsigned long rx_bytes, tx_bytes;
	unsigned long tx_retry_failed, tx_retry_count;
	unsigned long tx_filtered_count;

	unsigned int wep_weak_iv_count; /* number of RX frames with weak IV */

	unsigned long last_rx;
	u32 supp_rates; /* bitmap of supported rates in local->curr_rates */
        int txrate; /* index in local->curr_rates */
	int last_txrate; /* last rate used to send a frame to this STA */
	int last_nonerp_idx;

        struct net_device *dev; /* which net device is this station associated
				 * to */

	struct ieee80211_key *key;

	u32 tx_num_consecutive_failures;
	u32 tx_num_mpdu_ok;
	u32 tx_num_mpdu_fail;

	void *rate_ctrl_priv;

	/* last received seq/frag number from this STA (per RX queue) */
	u16 last_seq_ctrl[NUM_RX_DATA_QUEUES];
	unsigned long num_duplicates; /* number of duplicate frames received
				       * from this STA */
	unsigned long tx_fragments; /* number of transmitted MPDUs */
	unsigned long rx_fragments; /* number of received MPDUs */
	unsigned long rx_dropped; /* number of dropped MPDUs from this STA */

	int last_rssi; /* RSSI of last received frame from this STA */
	int last_ack_rssi[3]; /* RSSI of last received ACKs from this STA */
	unsigned long last_ack;
        int channel_use;
        int channel_use_raw;

	int antenna_sel;


	int key_idx_compression; /* key table index for compression and TX
				  * filtering; used only if sta->key is not
				  * set */

	int proc_entry_added:1;
	int assoc_ap:1; /* whether this is an AP that we are associated with
			 * as a client */

#ifdef CONFIG_HOSTAPD_WPA_TESTING
	u32 wpa_trigger;
#endif /* CONFIG_HOSTAPD_WPA_TESTING */

#ifdef CONFIG_IEEE80211_DEBUG_COUNTERS
	unsigned int wme_rx_queue[NUM_RX_DATA_QUEUES];
	unsigned int wme_tx_queue[NUM_RX_DATA_QUEUES];
#endif /* CONFIG_IEEE80211_DEBUG_COUNTERS */

	int vlan_id;
};


/* Maximum number of concurrently registered stations */
#define MAX_STA_COUNT 2007

/* Maximum number of AIDs to use for STAs; must be 2007 or lower
 * (IEEE 802.11 beacon format limitation) */
#define MAX_AID_TABLE_SIZE 2007

#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])


/* Maximum number of frames to buffer per power saving station */
#define STA_MAX_TX_BUFFER 128

/* Buffered frame expiry time */
#define STA_TX_BUFFER_EXPIRE (10 * HZ)

/* How often station data is cleaned up (e.g., expiration of buffered frames)
 */
#define STA_INFO_CLEANUP_INTERVAL (10 * HZ)


struct sta_info * sta_info_get(struct ieee80211_local *local, u8 *addr);
int sta_info_min_txrate_get(struct ieee80211_local *local);
void sta_info_release(struct ieee80211_local *local, struct sta_info *sta);
struct sta_info * sta_info_add(struct ieee80211_local *local,
			       struct net_device *dev, u8 *addr);
void sta_info_free(struct ieee80211_local *local, struct sta_info *sta,
		   int locked);
void sta_info_init(struct ieee80211_local *local);
void sta_info_start(struct ieee80211_local *local);
void sta_info_stop(struct ieee80211_local *local);
void sta_info_remove_aid_ptr(struct sta_info *sta);
void sta_info_flush(struct ieee80211_local *local, struct net_device *dev);

#endif /* STA_INFO_H */
