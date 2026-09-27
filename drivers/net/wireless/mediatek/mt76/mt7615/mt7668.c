// SPDX-License-Identifier: BSD-3-Clause-Clear
/* MT7668 support
 *
 * The MT7668 runs a "gen3" station firmware that predates the connac
 * unified commands: the host describes interfaces, BSSes and stations with
 * the legacy command set while scan, remain-on-channel and power save are
 * offloaded to the firmware.
 */

#include "mt7615.h"
#include "eeprom.h"
#include "mcu.h"
#include "mac.h"

#define MT7668_SCAN_CHANNEL_TIME	60

/* MT7668 (gen3 firmware) legacy commands */
enum {
	MT7668_CMD_BASIC_CONFIG = 0x02,
	MT7668_CMD_NIC_POWER_CTRL = 0x04,
	MT7668_CMD_POWER_SAVE_MODE = 0x05,
	MT7668_CMD_ADD_REMOVE_KEY = 0x07,
	MT7668_CMD_SET_RX_FILTER = 0x0a,
	MT7668_CMD_SET_DOMAIN_INFO = 0x0f,
	MT7668_CMD_BSS_ACTIVATE_CTRL = 0x11,
	MT7668_CMD_SET_BSS_INFO = 0x12,
	MT7668_CMD_UPDATE_STA_RECORD = 0x13,
	MT7668_CMD_REMOVE_STA_RECORD = 0x14,
	MT7668_CMD_INDICATE_PM_BSS_CONNECTED = 0x16,
	MT7668_CMD_INDICATE_PM_BSS_ABORT = 0x17,
	MT7668_CMD_CH_PRIVILEGE = 0x1c,
	MT7668_CMD_UPDATE_WMM_PARMS = 0x1d,
	MT7668_CMD_SET_BSS_RLM_PARAM = 0x19,
	MT7668_CMD_SET_DBDC_PARMS = 0x28,
	MT7668_CMD_SET_COUNTRY_POWER_LIMIT = 0x49,
};

#define MT7668_CMD(_t)		(__MCU_CMD_FIELD_CE | MT7668_CMD_##_t)

/* MT7668 (gen3 firmware) unsolicited events */
enum {
	MT7668_EVENT_RX_ADDBA = 0x0a,
	MT7668_EVENT_RX_DELBA = 0x0b,
};

enum {
	MT7668_NETWORK_TYPE_AIS,
	MT7668_NETWORK_TYPE_P2P,
};

static int
mt7668_mcu_add_dev(struct mt7615_phy *phy, struct ieee80211_vif *vif,
		   bool enable)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct {
		u8 bss_idx;
		u8 active;
		u8 network_type;
		u8 omac_idx;
		u8 addr[ETH_ALEN];
		u8 bmc_wlan_idx;
		u8 rsv;
	} __packed req = {
		.bss_idx = mvif->mt76.idx,
		.active = enable,
		.network_type = vif->p2p ? MT7668_NETWORK_TYPE_P2P :
					   MT7668_NETWORK_TYPE_AIS,
		.omac_idx = mvif->mt76.omac_idx,
		.bmc_wlan_idx = mvif->sta.wcid.idx,
	};

	struct {
		u8 bss_idx;
		u8 ps_profile;
		u8 rsv[2];
	} __packed ps = {
		.bss_idx = mvif->mt76.idx,
		.ps_profile = 0,	/* CAM */
	};
	int ret;

	memcpy(req.addr, vif->addr, ETH_ALEN);

	ret = mt76_mcu_send_msg(&phy->dev->mt76,
				MT7668_CMD(BSS_ACTIVATE_CTRL), &req,
				sizeof(req), false);
	if (ret || !enable)
		return ret;

	return mt76_mcu_send_msg(&phy->dev->mt76, MT7668_CMD(POWER_SAVE_MODE),
				 &ps, sizeof(ps), false);
}

enum {
	MT7668_PHY_HR_DSSS = BIT(0),
	MT7668_PHY_ERP = BIT(1),
	MT7668_PHY_OFDM = BIT(3),
	MT7668_PHY_HT = BIT(4),
	MT7668_PHY_VHT = BIT(5),
};

#define MT7668_PHY_IDX_ERP		1
#define MT7668_PHY_IDX_OFDM		3

#define MT7668_STA_TYPE_LEGACY		BIT(0)
#define MT7668_STA_TYPE_CLIENT		BIT(5)
#define MT7668_STA_TYPE_AP		BIT(6)

#define MT7668_STA_STATE_1		0
#define MT7668_STA_STATE_3		2

#define MT7668_STA_REC_IDX_NONE		0xfe

#define MT7668_RTS_POLICY_LEGACY	3

#define MT7668_MAX_AMSDU_LEN		4095

enum {
	MT7668_MEDIA_CONNECTED,
	MT7668_MEDIA_DISCONNECTED,
};

enum {
	MT7668_OP_MODE_INFRA,
	MT7668_OP_MODE_IBSS,
	MT7668_OP_MODE_AP,
};

enum {
	MT7668_AUTH_MODE_OPEN = 0,
	MT7668_AUTH_MODE_WPA_PSK = 4,
	MT7668_AUTH_MODE_WPA2_PSK = 7,
};

enum {
	MT7668_ENC_DISABLED = 1,
	MT7668_ENC2_ENABLED = 4,	/* TKIP */
	MT7668_ENC3_ENABLED = 6,	/* CCMP */
};

enum {
	MT7668_CIPHER_NONE,
	MT7668_CIPHER_WEP40,
	MT7668_CIPHER_TKIP,
	MT7668_CIPHER_TKIP_WO_MIC,
	MT7668_CIPHER_CCMP,
	MT7668_CIPHER_WEP104,
	MT7668_CIPHER_BIP,
	MT7668_CIPHER_WEP128,
};

/* The MT7658 shares the SDIO id and the firmware with the MT7668, but
 * transmits on a single stream: its firmware asserts in the tx path as
 * soon as a BSS is configured with two. It still receives on both chains.
 */
static u8 mt7668_fw_nss(struct mt7615_phy *phy)
{
	u8 *eeprom = phy->dev->mt76.eeprom.data;

	if (get_unaligned_le16(eeprom + MT_EE_CHIP_ID) == 0x7658)
		return 1;

	return hweight8(phy->mt76->antenna_mask);
}

static u8 mt7668_band(enum nl80211_band band)
{
	return band == NL80211_BAND_2GHZ ? 1 : 2;
}

/* legacy rates are passed as a bitmap indexed 1, 2, 5.5, 11, 22, 33,
 * 6, 9, 12, 18, 24, 36, 48, 54 Mbps
 */
static u16 mt7668_rate_bitmap(struct ieee80211_supported_band *sband,
			      u32 mask)
{
	static const u16 rates[] = {
		10, 20, 55, 110, 220, 330, 60, 90, 120, 180, 240, 360, 480, 540
	};
	u16 bitmap = 0;
	int i, j;

	for (i = 0; i < sband->n_bitrates; i++) {
		if (!(mask & BIT(i)))
			continue;

		for (j = 0; j < ARRAY_SIZE(rates); j++)
			if (sband->bitrates[i].bitrate == rates[j])
				bitmap |= BIT(j);
	}

	return bitmap;
}

static void
mt7668_mcu_fill_rlm(struct mt7615_phy *phy, struct mt7615_vif *mvif,
		    struct cfg80211_chan_def *chandef,
		    struct ieee80211_bss_conf *conf, u8 *rlm)
{
	struct {
		u8 bss_idx;
		u8 band;
		u8 primary_chan;
		u8 sco;
		u8 erp_protect;
		u8 ht_protect;
		u8 gf_operation;
		u8 rifs_mode;
		__le16 ht_op_info3;
		__le16 ht_op_info2;
		u8 ht_op_info1;
		u8 short_preamble;
		u8 short_slot;
		u8 vht_width;
		u8 vht_seg1;
		u8 vht_seg2;
		__le16 vht_basic_mcs;
		u8 nss;
	} __packed *req = (void *)rlm;
	struct ieee80211_channel *chan = chandef->chan;

	req->bss_idx = mvif->mt76.idx;
	req->band = mt7668_band(chan->band);
	req->primary_chan = chan->hw_value;
	req->short_preamble = conf->use_short_preamble;
	req->short_slot = conf->use_short_slot;
	req->erp_protect = conf->use_cts_prot;
	req->ht_protect = conf->ht_operation_mode &
			  IEEE80211_HT_OP_MODE_PROTECTION;
	req->nss = mt7668_fw_nss(phy);

	switch (chandef->width) {
	case NL80211_CHAN_WIDTH_40:
		req->sco = chandef->center_freq1 > chan->center_freq ? 1 : 3;
		req->ht_op_info1 = IEEE80211_HT_PARAM_CHAN_WIDTH_ANY;
		break;
	case NL80211_CHAN_WIDTH_80:
		req->sco = chandef->center_freq1 > chan->center_freq ? 1 : 3;
		req->ht_op_info1 = IEEE80211_HT_PARAM_CHAN_WIDTH_ANY;
		req->vht_width = 1;
		req->vht_seg1 = ieee80211_frequency_to_channel(chandef->center_freq1);
		break;
	default:
		break;
	}
}

static int
mt7668_mcu_set_rlm(struct mt7615_phy *phy, struct ieee80211_vif *vif)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct cfg80211_chan_def *chandef = &vif->bss_conf.chanreq.oper;
	u8 rlm[22] = {};

	if (!chandef->chan)
		return 0;

	mt7668_mcu_fill_rlm(phy, mvif, chandef, &vif->bss_conf, rlm);

	return mt76_mcu_send_msg(&phy->dev->mt76, MT7668_CMD(SET_BSS_RLM_PARAM),
				 rlm, sizeof(rlm), false);
}

static int
mt7668_mcu_add_bss(struct mt7615_phy *phy, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta, bool enable)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct cfg80211_chan_def *chandef = &vif->bss_conf.chanreq.oper;
	struct ieee80211_bss_conf *conf = &vif->bss_conf;
	struct ieee80211_supported_band *sband;
	struct {
		u8 bss_idx;
		u8 conn_state;
		u8 op_mode;
		u8 ssid_len;
		u8 ssid[IEEE80211_MAX_SSID_LEN];
		u8 bssid[ETH_ALEN];
		u8 qos;
		u8 rsv0;
		__le16 oper_rates;
		__le16 basic_rates;
		u8 ap_sta_idx;
		u8 rsv1;
		__le16 fixed_rate;
		u8 non_ht_basic_phy;
		u8 auth_mode;
		u8 enc_status;
		u8 phy_type;
		u8 wapi;
		u8 ap_mode;
		u8 bmc_wlan_idx;
		u8 hidden_ssid;
		u8 disconnect_th;
		u8 rsv2[3];
		__le32 private_data;
		u8 rlm[22];
		u8 dbdc_band;
		u8 wmm_set;
		u8 dbdc_action;
		u8 nss;
		u8 rsv3[22];
	} __packed req = {
		.bss_idx = mvif->mt76.idx,
		.conn_state = enable && vif->cfg.assoc ? MT7668_MEDIA_CONNECTED :
							 MT7668_MEDIA_DISCONNECTED,
		.ap_sta_idx = sta ? ((struct mt7615_sta *)sta->drv_priv)->wcid.idx :
				    MT7668_STA_REC_IDX_NONE,
		.qos = conf->qos,
		.bmc_wlan_idx = mvif->sta.wcid.idx,
		.wmm_set = mvif->mt76.wmm_idx,
		.nss = mt7668_fw_nss(phy),
	};

	switch (vif->type) {
	case NL80211_IFTYPE_STATION:
		req.op_mode = MT7668_OP_MODE_INFRA;
		break;
	case NL80211_IFTYPE_ADHOC:
		req.op_mode = MT7668_OP_MODE_IBSS;
		break;
	default:
		req.op_mode = MT7668_OP_MODE_AP;
		req.ap_mode = 1;
		break;
	}

	req.auth_mode = MT7668_AUTH_MODE_OPEN;
	req.enc_status = MT7668_ENC_DISABLED;
	switch (mvif->mt76.cipher) {
	case MCU_CIPHER_AES_CCMP:
		req.auth_mode = MT7668_AUTH_MODE_WPA2_PSK;
		req.enc_status = MT7668_ENC3_ENABLED;
		break;
	case MCU_CIPHER_TKIP:
		req.auth_mode = MT7668_AUTH_MODE_WPA_PSK;
		req.enc_status = MT7668_ENC2_ENABLED;
		break;
	default:
		break;
	}

	if (vif->cfg.ssid_len) {
		req.ssid_len = vif->cfg.ssid_len;
		memcpy(req.ssid, vif->cfg.ssid, vif->cfg.ssid_len);
	}
	if (conf->bssid)
		memcpy(req.bssid, conf->bssid, ETH_ALEN);

	if (chandef->chan) {
		u16 rates;

		sband = phy->mt76->hw->wiphy->bands[chandef->chan->band];

		rates = mt7668_rate_bitmap(sband, conf->basic_rates);
		req.basic_rates = cpu_to_le16(rates);
		if (sta) {
			rates = mt7668_rate_bitmap(sband,
				sta->deflink.supp_rates[chandef->chan->band]);
			req.oper_rates = cpu_to_le16(rates);
		}

		if (chandef->chan->band == NL80211_BAND_2GHZ) {
			req.non_ht_basic_phy = MT7668_PHY_IDX_ERP;
			req.phy_type = MT7668_PHY_HR_DSSS | MT7668_PHY_ERP |
				       MT7668_PHY_HT;
		} else {
			req.non_ht_basic_phy = MT7668_PHY_IDX_OFDM;
			req.phy_type = MT7668_PHY_OFDM | MT7668_PHY_HT |
				       MT7668_PHY_VHT;
		}

		mt7668_mcu_fill_rlm(phy, mvif, chandef, conf, req.rlm);
	}

	BUILD_BUG_ON(sizeof(req) != 116);

	return mt76_mcu_send_msg(&phy->dev->mt76, MT7668_CMD(SET_BSS_INFO),
				 &req, sizeof(req), false);
}

static int
mt7668_mcu_add_sta(struct mt7615_phy *phy, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta, bool enable)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct cfg80211_chan_def *chandef = &vif->bss_conf.chanreq.oper;
	struct mt7615_dev *dev = phy->dev;
	struct ieee80211_supported_band *sband;
	struct mt7615_sta *msta;
	struct {
		u8 sta_idx;
		u8 sta_type;
		u8 addr[ETH_ALEN];
		__le16 aid;
		__le16 listen_interval;
		u8 bss_idx;
		u8 phy_type;
		__le16 rates;
		__le16 basic_rates;
		u8 qos;
		u8 uapsd;
		u8 state;
		u8 mcs_set;
		u8 mcs32;
		u8 rsv0;
		u8 rx_mcs_mask[10];
		__le16 rx_highest;
		__le32 tx_rate_info;
		__le16 ht_cap;
		__le16 ht_ext_cap;
		__le32 txbf_cap;
		u8 ampdu_param;
		u8 asel_cap;
		u8 rcpi;
		u8 need_resp;
		u8 uapsd_ac;
		u8 uapsd_sp;
		u8 wlan_idx;
		u8 bmc_wlan_idx;
		__le32 vht_cap;
		__le16 vht_rx_mcs;
		__le16 vht_rx_highest;
		__le16 vht_tx_mcs;
		__le16 vht_tx_highest;
		u8 rts_policy;
		u8 vht_op_mode;
		u8 traffic_type;
		u8 tx_gf;
		u8 tx_sgi;
		u8 tx_stbc;
		__le16 fixed_rate;
		u8 tx_ampdu;
		u8 rx_ampdu;
		u8 rsv1[2];
		__le32 fixed_phy_rate;
		__le16 max_link_speed;
		__le16 min_link_speed;
		__le32 flags;
		u8 tx_ba_size;
		u8 rx_ba_size;
		u8 rsv2[2];
		u8 txbf_info[32];
		u8 tx_amsdu_in_ampdu;
		u8 rx_amsdu_in_ampdu;
		u8 rsv3[2];
		__le32 tx_max_amsdu_len;
	} __packed req = {};

	if (!sta)
		return 0;

	msta = (struct mt7615_sta *)sta->drv_priv;

	if (!enable) {
		struct {
			u8 action;
			u8 sta_idx;
			u8 bss_idx;
			u8 rsv;
		} __packed rm = {
			.sta_idx = msta->wcid.idx,
			.bss_idx = mvif->mt76.idx,
		};

		return mt76_mcu_send_msg(&dev->mt76,
					 MT7668_CMD(REMOVE_STA_RECORD),
					 &rm, sizeof(rm), false);
	}

	req.sta_idx = msta->wcid.idx;
	req.wlan_idx = msta->wcid.idx;
	req.bmc_wlan_idx = 0xff;
	req.bss_idx = mvif->mt76.idx;
	memcpy(req.addr, sta->addr, ETH_ALEN);
	req.sta_type = MT7668_STA_TYPE_LEGACY |
		       (vif->type == NL80211_IFTYPE_STATION ?
			MT7668_STA_TYPE_AP : MT7668_STA_TYPE_CLIENT);
	req.aid = cpu_to_le16(vif->type == NL80211_IFTYPE_STATION ?
			      vif->cfg.aid : sta->aid);
	req.listen_interval = cpu_to_le16(phy->mt76->hw->conf.listen_interval);
	req.state = vif->cfg.assoc ? MT7668_STA_STATE_3 : MT7668_STA_STATE_1;
	req.qos = sta->wme;

	if (chandef->chan) {
		enum nl80211_band band = chandef->chan->band;
		u16 rates;

		sband = phy->mt76->hw->wiphy->bands[band];

		rates = mt7668_rate_bitmap(sband, sta->deflink.supp_rates[band]);
		req.rates = cpu_to_le16(rates);
		rates = mt7668_rate_bitmap(sband, vif->bss_conf.basic_rates);
		req.basic_rates = cpu_to_le16(rates);
		req.phy_type = band == NL80211_BAND_2GHZ ?
			       MT7668_PHY_HR_DSSS | MT7668_PHY_ERP :
			       MT7668_PHY_OFDM;
	}

	if (sta->deflink.ht_cap.ht_supported) {
		struct ieee80211_sta_ht_cap *ht = &sta->deflink.ht_cap;

		req.phy_type |= MT7668_PHY_HT;
		/* the firmware sets up tx aggregation on its own */
		req.tx_ampdu = 1;
		req.rx_ampdu = 1;
		req.ht_cap = cpu_to_le16(ht->cap);
		req.ampdu_param = ht->ampdu_factor | (ht->ampdu_density << 2);
		memcpy(req.rx_mcs_mask, ht->mcs.rx_mask, sizeof(req.rx_mcs_mask));
		req.mcs_set = ht->mcs.rx_mask[0];
		req.rx_highest = ht->mcs.rx_highest;
	}

	if (sta->deflink.vht_cap.vht_supported) {
		struct ieee80211_sta_vht_cap *vht = &sta->deflink.vht_cap;

		req.phy_type |= MT7668_PHY_VHT;
		req.vht_cap = cpu_to_le32(vht->cap);
		req.vht_rx_mcs = vht->vht_mcs.rx_mcs_map;
		req.vht_rx_highest = vht->vht_mcs.rx_highest;
		req.vht_tx_mcs = vht->vht_mcs.tx_mcs_map;
		req.vht_tx_highest = vht->vht_mcs.tx_highest;
		/* the tx bandwidth and streams are taken from the operating
		 * mode, not from the capabilities
		 */
		req.vht_op_mode = min_t(u8, sta->deflink.bandwidth,
					IEEE80211_OPMODE_NOTIF_CHANWIDTH_160MHZ);
		req.vht_op_mode |= (max_t(u8, sta->deflink.rx_nss, 1) - 1) <<
				   IEEE80211_OPMODE_NOTIF_RX_NSS_SHIFT;
	}

	req.rts_policy = MT7668_RTS_POLICY_LEGACY;
	req.tx_ba_size = IEEE80211_MAX_AMPDU_BUF_HT;
	req.rx_ba_size = IEEE80211_MAX_AMPDU_BUF_HT;
	req.tx_max_amsdu_len = cpu_to_le32(MT7668_MAX_AMSDU_LEN);

	BUILD_BUG_ON(sizeof(req) != 136);

	return mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(UPDATE_STA_RECORD),
				 &req, sizeof(req), false);
}

static int
mt7668_mcu_ba(struct mt7615_dev *dev, struct ieee80211_ampdu_params *params,
	      bool enable)
{
	/* block ack agreements are tracked by the firmware per station
	 * record, rx reordering is done on the host
	 */
	return 0;
}

static int
mt7668_mcu_add_beacon(struct mt7615_dev *dev, struct ieee80211_hw *hw,
		      struct ieee80211_vif *vif, bool enable)
{
	return -EOPNOTSUPP;
}

static int
mt7668_mcu_set_pm_state(struct mt7615_dev *dev, int band, int state)
{
	return 0;
}

static int
mt7668_mcu_set_decap_offload(struct mt7615_dev *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_sta *sta)
{
	return 0;
}

const struct mt7615_mcu_ops mt7668_mcu_ops = {
	.add_beacon_offload = mt7668_mcu_add_beacon,
	.set_pm_state = mt7668_mcu_set_pm_state,
	.add_dev_info = mt7668_mcu_add_dev,
	.add_bss_info = mt7668_mcu_add_bss,
	.add_tx_ba = mt7668_mcu_ba,
	.add_rx_ba = mt7668_mcu_ba,
	.sta_add = mt7668_mcu_add_sta,
	.set_sta_decap_offload = mt7668_mcu_set_decap_offload,
};

static int mt7668_mcu_set_wmm(struct mt7615_dev *dev, struct ieee80211_vif *vif)
{
	/* firmware AC order is BE, BK, VI, VO */
	static const u8 fw_ac[] = {
		[IEEE80211_AC_BE] = 0,
		[IEEE80211_AC_BK] = 1,
		[IEEE80211_AC_VI] = 2,
		[IEEE80211_AC_VO] = 3,
	};
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct {
		struct {
			__le16 cw_min;
			__le16 cw_max;
			__le16 txop;
			__le16 aifs;
			u8 guard_time;
			u8 acm;
		} __packed ac[IEEE80211_NUM_ACS];
		u8 bss_idx;
		u8 qos;
		u8 wmm_set;
		u8 rsv;
	} __packed req = {
		.bss_idx = mvif->mt76.idx,
		.qos = vif->bss_conf.qos,
		.wmm_set = mvif->mt76.wmm_idx,
	};
	int i;

	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		struct ieee80211_tx_queue_params *q = &mvif->wmm[i];
		int ac = fw_ac[i];

		req.ac[ac].cw_min = cpu_to_le16(q->cw_min);
		req.ac[ac].cw_max = cpu_to_le16(q->cw_max);
		req.ac[ac].txop = cpu_to_le16(q->txop);
		req.ac[ac].aifs = cpu_to_le16(q->aifs);
		req.ac[ac].acm = q->acm;
	}

	BUILD_BUG_ON(sizeof(req) != 44);

	return mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(UPDATE_WMM_PARMS),
				 &req, sizeof(req), false);
}

static int
mt7668_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
	       unsigned int link_id, u16 queue,
	       const struct ieee80211_tx_queue_params *params)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	int err;

	mvif->wmm[queue] = *params;

	mt7615_mutex_acquire(dev);
	err = mt7668_mcu_set_wmm(dev, vif);
	mt7615_mutex_release(dev);

	return err;
}

static int mt7668_mcu_set_power_limit(struct mt76_phy *phy);

static int mt7668_config(struct ieee80211_hw *hw, int radio_idx, u32 changed)
{
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	int ret = 0;

	/* the firmware tunes the channel for scan, roc and the bss itself */
	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		mt7615_mutex_acquire(phy->dev);
		ret = mt7668_mcu_set_power_limit(phy->mt76);
		mt7615_mutex_release(phy->dev);
	}

	return ret;
}

static int mt7668_set_rts_threshold(struct ieee80211_hw *hw, int radio_idx,
				    u32 val)
{
	return 0;
}

static void mt7668_set_coverage_class(struct ieee80211_hw *hw, int radio_idx,
				      s16 coverage_class)
{
}

static void mt7668_sta_rate_tbl_update(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       struct ieee80211_sta *sta)
{
	/* rate control runs in firmware */
}

#define MT7668_SCAN_MAX_CHANNELS	32

static int mt7668_mcu_hw_scan(struct mt7615_phy *phy)
{
	struct cfg80211_scan_request *sreq = &phy->scan_req->req;
	struct mt7615_vif *mvif = (struct mt7615_vif *)phy->scan_vif->drv_priv;
	struct mt7615_dev *dev = phy->dev;
	struct mt76_connac_mcu_scan_channel *chan;
	struct {
		u8 seq_num;
		u8 bss_idx;
		u8 scan_type;
		u8 ssid_type;
		u8 ssids_num;
		u8 probe_req_num;
		u8 rsv[2];
		struct mt76_connac_mcu_scan_ssid ssids[4];
		__le16 probe_delay_time;
		__le16 channel_dwell_time;
		__le16 timeout_value;
		u8 channel_type;
		u8 channels_num;
		struct mt76_connac_mcu_scan_channel channels[MT7668_SCAN_MAX_CHANNELS];
		__le16 ies_len;
		u8 ies[MT76_CONNAC_SCAN_IE_LEN];
	} __packed *req;
	int i, n_ssids = 0, n_channels, duration;
	struct sk_buff *skb;

	skb = mt76_mcu_msg_alloc(&dev->mt76, NULL, sizeof(*req));
	if (!skb)
		return -ENOMEM;

	mvif->mt76.scan_seq_num = (mvif->mt76.scan_seq_num + 1) & 0x7f;

	req = skb_put_zero(skb, sizeof(*req));
	req->seq_num = mvif->mt76.scan_seq_num;
	req->bss_idx = mvif->mt76.idx;
	req->scan_type = sreq->n_ssids ? 1 : 0;
	req->probe_req_num = sreq->n_ssids ? 2 : 0;

	for (i = 0; i < sreq->n_ssids; i++) {
		if (!sreq->ssids[i].ssid_len)
			continue;

		req->ssids[n_ssids].ssid_len =
			cpu_to_le32(sreq->ssids[i].ssid_len);
		memcpy(req->ssids[n_ssids].ssid, sreq->ssids[i].ssid,
		       sreq->ssids[i].ssid_len);
		n_ssids++;
	}
	req->ssid_type = n_ssids ? BIT(2) : BIT(0);
	req->ssids_num = n_ssids;

	n_channels = min_t(int, sreq->n_channels - phy->scan_chan_idx,
			   MT7668_SCAN_MAX_CHANNELS);

	duration = MT7668_SCAN_CHANNEL_TIME;
	/* increase channel time for passive scan */
	if (!sreq->n_ssids)
		duration *= 2;
	req->timeout_value = cpu_to_le16(n_channels * duration);
	req->channel_dwell_time = cpu_to_le16(duration);

	/* the firmware only scans the channels it is given */
	req->channel_type = 4;
	req->channels_num = n_channels;
	for (i = 0; i < n_channels; i++) {
		struct ieee80211_channel *c;

		c = sreq->channels[phy->scan_chan_idx + i];
		chan = &req->channels[i];
		chan->band = mt7668_band(c->band);
		chan->channel_num = c->hw_value;
	}
	phy->scan_chan_idx += n_channels;

	if (sreq->ie_len) {
		memcpy(req->ies, sreq->ie, sreq->ie_len);
		req->ies_len = cpu_to_le16(sreq->ie_len);
	}

	/* the firmware only reads the ies it has been told about */
	skb_trim(skb, skb->len - MT76_CONNAC_SCAN_IE_LEN + sreq->ie_len);

	return mt76_mcu_skb_send_msg(&dev->mt76, skb,
				     MCU_CE_CMD(START_HW_SCAN), false);
}

bool mt7668_scan_next(struct mt7615_phy *phy)
{
	struct mt7615_dev *dev = phy->dev;
	bool ret = false;

	mt7615_mutex_acquire(dev);
	if (phy->scan_req &&
	    phy->scan_chan_idx < phy->scan_req->req.n_channels &&
	    test_bit(MT76_HW_SCANNING, &phy->mt76->state))
		ret = !mt7668_mcu_hw_scan(phy);
	if (!ret)
		phy->scan_req = NULL;
	mt7615_mutex_release(dev);

	return ret;
}

static int
mt7668_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
	       struct ieee80211_scan_request *scan_req)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	int err;

	if (scan_req->req.ie_len > MT76_CONNAC_SCAN_IE_LEN ||
	    !scan_req->req.n_channels)
		return -EINVAL;

	mt7615_mutex_acquire(dev);

	if (test_and_set_bit(MT76_HW_SCANNING, &phy->mt76->state)) {
		err = -EBUSY;
		goto out;
	}

	phy->scan_req = scan_req;
	phy->scan_vif = vif;
	phy->scan_chan_idx = 0;

	err = mt7668_mcu_hw_scan(phy);
	if (err) {
		phy->scan_req = NULL;
		clear_bit(MT76_HW_SCANNING, &phy->mt76->state);
	}
out:
	mt7615_mutex_release(dev);

	return err;
}

static void
mt7668_cancel_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);

	mt7615_mutex_acquire(dev);
	phy->scan_req = NULL;
	mt76_connac_mcu_cancel_hw_scan(phy->mt76, vif);
	mt7615_mutex_release(dev);
}

static int
mt7668_mcu_ch_privilege(struct mt7615_phy *phy, struct ieee80211_vif *vif,
			struct cfg80211_chan_def *chandef, int duration)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_roc_tlv req = {
		.bss_idx = mvif->mt76.idx,
		.active = !chandef,	/* 0: request, 1: abort */
		.max_interval = cpu_to_le32(duration),
		.req_type = 0,		/* join */
	};

	if (chandef) {
		u8 rlm[22] = {};

		mt7668_mcu_fill_rlm(phy, mvif, chandef, &vif->bss_conf, rlm);
		req.primary_chan = chandef->chan->hw_value;
		req.band = mt7668_band(chandef->chan->band);
		req.sco = rlm[3];
	}

	phy->roc_grant = false;

	return mt76_mcu_send_msg(&phy->dev->mt76, MT7668_CMD(CH_PRIVILEGE),
				 &req, sizeof(req), false);
}

static void
mt7668_mgd_prepare_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_prep_tx_info *info)
{
	struct cfg80211_chan_def *chandef = &vif->bss_conf.chanreq.oper;
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	struct mt7615_dev *dev = phy->dev;
	int duration = info->duration ? info->duration : 1000;

	if (!chandef->chan)
		return;

	mt7615_mutex_acquire(dev);
	/* drop a grant left over from a previous attempt */
	if (phy->join_chan)
		mt7668_mcu_ch_privilege(phy, vif, NULL, 0);
	phy->join_chan = true;
	if (!mt7668_mcu_ch_privilege(phy, vif, chandef, duration) &&
	    !wait_event_timeout(phy->roc_wait, phy->roc_grant, HZ))
		dev_warn(dev->mt76.dev, "channel grant timed out\n");
	mt7615_mutex_release(dev);
}

static void
mt7668_mgd_complete_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		       struct ieee80211_prep_tx_info *info)
{
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	struct mt7615_dev *dev = phy->dev;

	if (!phy->join_chan)
		return;

	mt7615_mutex_acquire(dev);
	mt7668_mcu_ch_privilege(phy, vif, NULL, 0);
	phy->join_chan = false;
	mt7615_mutex_release(dev);
}

static int
mt7668_mcu_set_bss_connected(struct mt7615_dev *dev, struct ieee80211_vif *vif,
			     bool connected)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;

	if (connected) {
		struct {
			u8 bss_idx;
			u8 dtim_period;
			__le16 aid;
			__le16 beacon_int;
			__le16 atim_window;
			u8 uapsd;
			u8 delivery_ac;
			u8 trigger_ac;
			u8 rsv;
		} __packed req = {
			.bss_idx = mvif->mt76.idx,
			.dtim_period = max_t(u8, vif->bss_conf.dtim_period, 1),
			.aid = cpu_to_le16(vif->cfg.aid),
			.beacon_int = cpu_to_le16(vif->bss_conf.beacon_int),
		};

		return mt76_mcu_send_msg(&dev->mt76,
					 MT7668_CMD(INDICATE_PM_BSS_CONNECTED),
					 &req, sizeof(req), false);
	} else {
		struct {
			u8 bss_idx;
			u8 rsv[3];
		} __packed req = {
			.bss_idx = mvif->mt76.idx,
		};

		return mt76_mcu_send_msg(&dev->mt76,
					 MT7668_CMD(INDICATE_PM_BSS_ABORT),
					 &req, sizeof(req), false);
	}
}

static void
mt7668_bss_info_changed(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			struct ieee80211_bss_conf *info, u64 changed)
{
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	struct mt7615_dev *dev = phy->dev;
	struct ieee80211_sta *sta = NULL;

	mt7615_mutex_acquire(dev);

	if (vif->type == NL80211_IFTYPE_STATION && info->bssid) {
		rcu_read_lock();
		sta = ieee80211_find_sta(vif, info->bssid);
		rcu_read_unlock();
	}

	if (changed & BSS_CHANGED_ASSOC) {
		if (vif->cfg.assoc && sta)
			mt7668_mcu_add_sta(phy, vif, sta, true);
		mt7668_mcu_add_bss(phy, vif, sta, true);
		mt7668_mcu_set_bss_connected(dev, vif, vif->cfg.assoc);
		if (vif->cfg.assoc)
			mt7668_mcu_set_rlm(phy, vif);

		/* the firmware tracks the beacons of the connected bss and
		 * reports beacon loss, it does not pass them up
		 */
		if (vif->type == NL80211_IFTYPE_STATION) {
			if (vif->cfg.assoc)
				vif->driver_flags |= IEEE80211_VIF_BEACON_FILTER;
			else
				vif->driver_flags &= ~IEEE80211_VIF_BEACON_FILTER;
		}
	} else if (changed & (BSS_CHANGED_ERP_CTS_PROT |
			      BSS_CHANGED_ERP_PREAMBLE |
			      BSS_CHANGED_ERP_SLOT | BSS_CHANGED_HT |
			      BSS_CHANGED_BASIC_RATES)) {
		mt7668_mcu_add_bss(phy, vif, sta, true);
		mt7668_mcu_set_rlm(phy, vif);
	}

	mt7615_mutex_release(dev);
}

static struct ieee80211_sta *
mt7668_find_ap_sta(struct ieee80211_vif *vif)
{
	struct ieee80211_sta *sta;

	if (vif->type != NL80211_IFTYPE_STATION || !vif->bss_conf.bssid)
		return NULL;

	rcu_read_lock();
	sta = ieee80211_find_sta(vif, vif->bss_conf.bssid);
	rcu_read_unlock();

	return sta;
}

static int
mt7668_mcu_add_key(struct mt7615_dev *dev, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta, struct mt76_wcid *wcid,
		   struct ieee80211_key_conf *key, enum set_key_cmd cmd)
{
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	bool pairwise = key->flags & IEEE80211_KEY_FLAG_PAIRWISE;
	struct {
		u8 add;
		u8 tx_key;
		u8 key_type;
		u8 is_authenticator;
		u8 peer_addr[ETH_ALEN];
		u8 bss_idx;
		u8 algo;
		u8 key_id;
		u8 key_len;
		u8 wlan_idx;
		u8 mgmt_protection;
		u8 key[32];
		u8 rsc[16];
	} __packed req = {
		.add = cmd == SET_KEY,
		.tx_key = pairwise || vif->type != NL80211_IFTYPE_STATION,
		.key_type = pairwise,
		.is_authenticator = vif->type == NL80211_IFTYPE_AP,
		.bss_idx = mvif->mt76.idx,
		.key_id = key->keyidx,
		.key_len = key->keylen,
		.wlan_idx = wcid->idx,
	};

	switch (key->cipher) {
	case WLAN_CIPHER_SUITE_TKIP:
		req.algo = MT7668_CIPHER_TKIP;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		req.algo = MT7668_CIPHER_CCMP;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (sta)
		memcpy(req.peer_addr, sta->addr, ETH_ALEN);
	else if (vif->type == NL80211_IFTYPE_STATION && vif->bss_conf.bssid)
		memcpy(req.peer_addr, vif->bss_conf.bssid, ETH_ALEN);
	else
		memcpy(req.peer_addr, vif->addr, ETH_ALEN);

	if (cmd == SET_KEY)
		memcpy(req.key, key->key, min_t(u8, key->keylen, sizeof(req.key)));

	return mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(ADD_REMOVE_KEY),
				 &req, sizeof(req), false);
}

static int
mt7668_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
	       struct ieee80211_vif *vif, struct ieee80211_sta *sta,
	       struct ieee80211_key_conf *key)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	struct mt7615_phy *phy = mt7615_hw_phy(hw);
	struct mt7615_vif *mvif = (struct mt7615_vif *)vif->drv_priv;
	struct mt7615_sta *msta = sta ? (struct mt7615_sta *)sta->drv_priv :
				  &mvif->sta;
	struct mt76_wcid *wcid = &msta->wcid;
	int err;

	switch (key->cipher) {
	case WLAN_CIPHER_SUITE_TKIP:
	case WLAN_CIPHER_SUITE_CCMP:
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* management frames are sent through the firmware command path,
	 * protect them in software
	 */
	key->flags |= IEEE80211_KEY_FLAG_SW_MGMT_TX;

	mt7615_mutex_acquire(dev);

	if (cmd == SET_KEY && !mvif->mt76.cipher) {
		mvif->mt76.cipher = mt76_connac_mcu_get_cipher(key->cipher);
		mt7668_mcu_add_bss(phy, vif, sta ? sta : mt7668_find_ap_sta(vif),
				   true);
	}

	if (cmd == SET_KEY) {
		wcid->hw_key_idx = key->keyidx;
		mt76_wcid_key_setup(&dev->mt76, wcid, key);
	} else {
		if (key->keyidx == wcid->hw_key_idx)
			wcid->hw_key_idx = -1;
		mt76_wcid_key_setup(&dev->mt76, wcid, NULL);
	}

	err = mt7668_mcu_add_key(dev, vif, sta, wcid, key, cmd);

	mt7615_mutex_release(dev);

	return err;
}

static __le32 mt7668_country_code(struct mt76_dev *dev)
{
	if (!dev->alpha2[0] || !dev->alpha2[1])
		return cpu_to_le32('0' | ('0' << 8));

	return cpu_to_le32(dev->alpha2[0] | (dev->alpha2[1] << 8));
}

#define MT7668_CHAN_FLAGS	(IEEE80211_CHAN_DISABLED |		\
				 IEEE80211_CHAN_NO_IR |			\
				 IEEE80211_CHAN_RADAR |			\
				 IEEE80211_CHAN_NO_HT40PLUS |		\
				 IEEE80211_CHAN_NO_HT40MINUS |		\
				 IEEE80211_CHAN_NO_OFDM |		\
				 IEEE80211_CHAN_NO_80MHZ |		\
				 IEEE80211_CHAN_NO_160MHZ)

static int
mt7668_mcu_add_channels(struct sk_buff *skb, struct ieee80211_supported_band *sband)
{
	int i, n = 0;

	for (i = 0; i < sband->n_channels; i++) {
		struct ieee80211_channel *chan = &sband->channels[i];
		struct {
			__le16 hw_value;
			u8 rsv[2];
			__le32 flags;
		} __packed ch = {
			.hw_value = cpu_to_le16(chan->hw_value),
			.flags = cpu_to_le32(chan->flags & MT7668_CHAN_FLAGS),
		};

		if (chan->flags & IEEE80211_CHAN_DISABLED)
			continue;

		skb_put_data(skb, &ch, sizeof(ch));
		n++;
	}

	return n;
}

static int mt7668_mcu_set_channel_domain(struct mt76_phy *phy)
{
	struct mt76_dev *dev = phy->dev;
	struct {
		__le32 country_code;
		u8 bw_2g;
		u8 bw_5g;
		u8 rsv0[2];
		u8 n_2ch;
		u8 n_5ch;
		u8 rsv1[2];
	} __packed *hdr;
	struct sk_buff *skb;
	int n_chan = 0;

	if (phy->cap.has_2ghz)
		n_chan += phy->sband_2g.sband.n_channels;
	if (phy->cap.has_5ghz)
		n_chan += phy->sband_5g.sband.n_channels;

	skb = mt76_mcu_msg_alloc(dev, NULL, sizeof(*hdr) + n_chan * 8);
	if (!skb)
		return -ENOMEM;

	hdr = skb_put_zero(skb, sizeof(*hdr));
	hdr->country_code = mt7668_country_code(dev);

	if (phy->cap.has_2ghz)
		hdr->n_2ch = mt7668_mcu_add_channels(skb, &phy->sband_2g.sband);
	if (phy->cap.has_5ghz)
		hdr->n_5ch = mt7668_mcu_add_channels(skb, &phy->sband_5g.sband);

	return mt76_mcu_skb_send_msg(dev, skb, MT7668_CMD(SET_DOMAIN_INFO),
				     false);
}

#define MT7668_TXPOWER_NO_LIMIT		63
#define MT7668_TXPOWER_MAX_CHAN		32

struct mt7668_chan_power_limit {
	u8 chan;
	u8 rsv[3];
	u8 cck[2];	/* 5.5/11M, 1/2M */
	u8 ofdm[5];	/* 6/9M, 12/18M, 24/36M, 48M, 54M */
	u8 ht20[6];	/* MCS 0, 1-2, 3-4, 5, 6, 7 */
	u8 ht40[7];	/* MCS 0, 1-2, 3-4, 5, 6, 7, 32 */
	u8 vht20[7];	/* MCS 0, 1-2, 3-4, 5-6, 7, 8, 9 */
	u8 bw_delta[6];
	u8 nss_delta;
	u8 rsv2[2];
} __packed;

static u8 mt7668_power(const s8 *val, int n)
{
	s8 min = MT7668_TXPOWER_NO_LIMIT;
	int i;

	for (i = 0; i < n; i++)
		min = min_t(s8, min, val[i]);

	return clamp_t(s8, min, 0, MT7668_TXPOWER_NO_LIMIT);
}

static void
mt7668_fill_power_limit(struct mt7668_chan_power_limit *entry,
			struct mt76_power_limits *limits)
{
	const s8 *mcs20 = limits->mcs[0], *mcs40 = limits->mcs[1];

	entry->cck[0] = mt7668_power(&limits->cck[2], 2);
	entry->cck[1] = mt7668_power(&limits->cck[0], 2);

	entry->ofdm[0] = mt7668_power(&limits->ofdm[0], 2);
	entry->ofdm[1] = mt7668_power(&limits->ofdm[2], 2);
	entry->ofdm[2] = mt7668_power(&limits->ofdm[4], 2);
	entry->ofdm[3] = mt7668_power(&limits->ofdm[6], 1);
	entry->ofdm[4] = mt7668_power(&limits->ofdm[7], 1);

	entry->ht20[0] = mt7668_power(&mcs20[0], 1);
	entry->ht20[1] = mt7668_power(&mcs20[1], 2);
	entry->ht20[2] = mt7668_power(&mcs20[3], 2);
	entry->ht20[3] = mt7668_power(&mcs20[5], 1);
	entry->ht20[4] = mt7668_power(&mcs20[6], 1);
	entry->ht20[5] = mt7668_power(&mcs20[7], 1);

	entry->ht40[0] = mt7668_power(&mcs40[0], 1);
	entry->ht40[1] = mt7668_power(&mcs40[1], 2);
	entry->ht40[2] = mt7668_power(&mcs40[3], 2);
	entry->ht40[3] = mt7668_power(&mcs40[5], 1);
	entry->ht40[4] = mt7668_power(&mcs40[6], 1);
	entry->ht40[5] = mt7668_power(&mcs40[7], 1);
	entry->ht40[6] = mt7668_power(&mcs40[0], 1);

	entry->vht20[0] = mt7668_power(&mcs20[0], 1);
	entry->vht20[1] = mt7668_power(&mcs20[1], 2);
	entry->vht20[2] = mt7668_power(&mcs20[3], 2);
	entry->vht20[3] = mt7668_power(&mcs20[5], 2);
	entry->vht20[4] = mt7668_power(&mcs20[7], 1);
	entry->vht20[5] = mt7668_power(&mcs20[8], 1);
	entry->vht20[6] = mt7668_power(&mcs20[9], 1);
}

static int
mt7668_mcu_set_band_power_limit(struct mt76_phy *phy,
				struct ieee80211_supported_band *sband,
				struct mt76_power_limits *limits)
{
	struct mt76_dev *dev = phy->dev;
	struct {
		u8 n_chan;
		u8 band;
		u8 rsv[2];
		__le32 country_code;
	} __packed *hdr;
	struct sk_buff *skb = NULL;
	int i, ret;

	BUILD_BUG_ON(sizeof(struct mt7668_chan_power_limit) != 40);

	for (i = 0; i < sband->n_channels; i++) {
		struct ieee80211_channel *chan = &sband->channels[i];
		struct mt7668_chan_power_limit *entry;
		s8 tx_power;

		if (chan->flags & IEEE80211_CHAN_DISABLED)
			continue;

		if (!skb) {
			skb = mt76_mcu_msg_alloc(dev, NULL, sizeof(*hdr) +
						 MT7668_TXPOWER_MAX_CHAN *
						 sizeof(*entry));
			if (!skb)
				return -ENOMEM;

			hdr = skb_put_zero(skb, sizeof(*hdr));
			hdr->band = mt7668_band(sband->band);
			hdr->country_code = mt7668_country_code(dev);
		}

		/* regulatory and user limit in 0.5 dBm, narrowed by the board
		 * limits
		 */
		tx_power = min_t(int, 2 * chan->max_power,
				 MT7668_TXPOWER_NO_LIMIT);
		if (phy->hw->conf.power_level > 0)
			tx_power = min_t(int, tx_power,
					 2 * phy->hw->conf.power_level);
		mt76_get_rate_power_limits(phy, chan, limits, tx_power);

		entry = skb_put(skb, sizeof(*entry));
		memset(entry, MT7668_TXPOWER_NO_LIMIT, sizeof(*entry));
		entry->chan = chan->hw_value;
		mt7668_fill_power_limit(entry, limits);

		if (++hdr->n_chan < MT7668_TXPOWER_MAX_CHAN)
			continue;

		ret = mt76_mcu_skb_send_msg(dev, skb,
				MT7668_CMD(SET_COUNTRY_POWER_LIMIT), false);
		skb = NULL;
		if (ret)
			return ret;
	}

	if (!skb)
		return 0;

	return mt76_mcu_skb_send_msg(dev, skb,
				     MT7668_CMD(SET_COUNTRY_POWER_LIMIT), false);
}

static int mt7668_mcu_set_power_limit(struct mt76_phy *phy)
{
	struct mt76_power_limits *limits;
	int ret = 0;

	limits = kzalloc_obj(*limits);
	if (!limits)
		return -ENOMEM;

	if (phy->cap.has_2ghz)
		ret = mt7668_mcu_set_band_power_limit(phy, &phy->sband_2g.sband,
						      limits);
	if (!ret && phy->cap.has_5ghz)
		ret = mt7668_mcu_set_band_power_limit(phy, &phy->sband_5g.sband,
						      limits);

	kfree(limits);

	return ret;
}

int mt7668_mcu_set_regd(struct mt76_phy *phy)
{
	int ret;

	ret = mt7668_mcu_set_channel_domain(phy);
	if (ret)
		return ret;

	return mt7668_mcu_set_power_limit(phy);
}

int mt7668_mcu_power_off(struct mt7615_dev *dev)
{
	struct {
		u8 power_mode;
		u8 rsv[3];
	} __packed req = {
		.power_mode = 1,
	};

	return mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(NIC_POWER_CTRL),
				 &req, sizeof(req), false);
}
EXPORT_SYMBOL_GPL(mt7668_mcu_power_off);

int mt7668_mcu_efuse_read(struct mt7615_dev *dev, u32 offset, u8 *data)
{
	struct {
		__le32 addr;
		__le32 valid;
		u8 data[16];
	} __packed req = {
		.addr = cpu_to_le32(round_down(offset, 16)),
	}, *res;
	struct sk_buff *skb;
	int ret;

	ret = mt76_mcu_send_and_get_msg(&dev->mt76,
					MCU_EXT_QUERY(EFUSE_ACCESS),
					&req, sizeof(req), true, &skb);
	if (ret)
		return ret;

	res = (void *)(skb->data + sizeof(struct mt7615_mcu_rxd));
	if (le32_to_cpu(res->valid))
		memcpy(data, res->data, sizeof(res->data));
	else
		memset(data, 0, sizeof(res->data));

	dev_kfree_skb(skb);

	return 0;
}
EXPORT_SYMBOL_GPL(mt7668_mcu_efuse_read);

#define MT7668_RX_FILTER_DIRECTED	BIT(0)
#define MT7668_RX_FILTER_MULTICAST	BIT(1)
#define MT7668_RX_FILTER_ALL_MULTICAST	BIT(2)
#define MT7668_RX_FILTER_BROADCAST	BIT(3)
#define MT7668_RX_FILTER_PROMISC	BIT(5)

static int mt7668_mcu_set_rx_filter(struct mt7615_dev *dev, u32 filter)
{
	struct {
		__le32 filter;
		u8 per_bss;
		u8 bss_idx;
		u8 rsv[2];
		__le32 bss_mgmt_filter;
		u8 rsv2[56];
	} __packed req = {
		.filter = cpu_to_le32(filter),
	};

	return mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(SET_RX_FILTER),
				 &req, sizeof(req), false);
}

static void mt7668_configure_filter(struct ieee80211_hw *hw,
				    unsigned int changed_flags,
				    unsigned int *total_flags, u64 multicast)
{
	struct mt7615_dev *dev = mt7615_hw_dev(hw);
	u32 filter = MT7668_RX_FILTER_DIRECTED | MT7668_RX_FILTER_BROADCAST |
		     MT7668_RX_FILTER_MULTICAST;

	*total_flags &= FIF_ALLMULTI | FIF_OTHER_BSS;

	if (*total_flags & FIF_ALLMULTI)
		filter |= MT7668_RX_FILTER_ALL_MULTICAST;
	if (*total_flags & FIF_OTHER_BSS)
		filter |= MT7668_RX_FILTER_PROMISC;

	mt7615_mutex_acquire(dev);
	mt7668_mcu_set_rx_filter(dev, filter);
	mt7615_mutex_release(dev);
}

int mt7668_mcu_basic_config(struct mt7615_dev *dev)
{
	struct {
		u8 native_80211;
		u8 assert_path;
		u8 debug_level;
		u8 rsv;
		__le16 rx_csum;
		__le16 tx_csum;
		u8 segment;
		u8 rsv2[3];
	} __packed req = {
		/* data frames are passed as 802.3 and translated by the CR4 */
		.native_80211 = 0,
	};

	struct {
		u8 enable;
		u8 wmm_band_bitmap;
		u8 update_next_ch_req;
		u8 rsv[33];
	} __packed dbdc = {};
	int ret;

	ret = mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(BASIC_CONFIG),
				&req, sizeof(req), false);
	if (ret)
		return ret;

	/* single band operation */
	return mt76_mcu_send_msg(&dev->mt76, MT7668_CMD(SET_DBDC_PARMS),
				 &dbdc, sizeof(dbdc), false);
}
EXPORT_SYMBOL_GPL(mt7668_mcu_basic_config);

/* 802.3 data frames: the CR4 performs the 802.11 encapsulation */
void mt7668_mac_write_txwi_8023(struct mt7615_dev *dev, __le32 *txwi,
				struct sk_buff *skb, struct mt76_wcid *wcid,
				struct ieee80211_vif *vif,
				struct ieee80211_key_conf *key, int pid,
				enum mt76_txq_id qid)
{
	struct mt76_vif_link *mvif = vif ? (struct mt76_vif_link *)vif->drv_priv
					 : NULL;
	u8 tid = skb->priority & IEEE80211_QOS_CTL_TID_MASK;
	u8 omac_idx = mvif ? mvif->omac_idx : 0;
	u8 wmm_idx = mvif ? mvif->wmm_idx : 0;
	u8 q_idx, hdr_info = 0;
	u32 val;

	if (qid >= MT_TXQ_PSD)
		q_idx = MT_LMAC_ALTX0;
	else
		q_idx = wmm_idx * MT7615_MAX_WMM_SETS +
			mt7615_lmac_mapping(dev, skb_get_queue_mapping(skb));

	/* ethertype offset in words, counted from the 4 byte PSE header */
	val = FIELD_PREP(MT_TXD0_TX_BYTES, skb->len + MT7668_TXD_DATA_SIZE) |
	      FIELD_PREP(MT_TXD0_ETH_TYPE_OFFSET, (4 + 2 * ETH_ALEN) / 2) |
	      FIELD_PREP(MT_TXD0_P_IDX, MT_TX_PORT_IDX_LMAC) |
	      FIELD_PREP(MT_TXD0_Q_IDX, q_idx);
	txwi[0] = cpu_to_le32(val);

	if (get_unaligned_be16(&skb->data[2 * ETH_ALEN]) >= ETH_P_802_3_MIN)
		hdr_info |= BIT(4);	/* Ethernet II */

	val = MT_TXD1_LONG_FORMAT |
	      FIELD_PREP(MT_TXD1_WLAN_IDX, wcid->idx) |
	      FIELD_PREP(MT_TXD1_HDR_FORMAT, MT_HDR_FORMAT_802_3) |
	      FIELD_PREP(MT_TXD1_HDR_INFO, hdr_info) |
	      FIELD_PREP(MT_TXD1_TID, tid) |
	      FIELD_PREP(MT_TXD1_PKT_FMT, MT_TX_TYPE_CT) |
	      FIELD_PREP(MT_TXD1_OWN_MAC, omac_idx);
	txwi[1] = cpu_to_le32(val);

	/* in station mode group addressed frames still go to the AP */
	txwi[2] = 0;
	if (vif && vif->type != NL80211_IFTYPE_STATION &&
	    is_multicast_ether_addr(skb->data))
		txwi[2] |= cpu_to_le32(MT_TXD2_MULTICAST);

	val = FIELD_PREP(MT_TXD3_REM_TX_COUNT, 30);
	if (key)
		val |= MT_TXD3_PROTECT_FRAME;
	txwi[3] = cpu_to_le32(val);
	txwi[4] = 0;
	/* every tx status costs an SDIO transfer, only ask for the ones a
	 * frame is waiting for
	 */
	txwi[5] = 0;
	if (pid >= MT_PACKET_ID_FIRST)
		txwi[5] = cpu_to_le32(MT_TXD5_TX_STATUS_HOST |
				      FIELD_PREP(MT_TXD5_PID, pid));
	txwi[6] = 0;
	txwi[7] = 0;

	/* TXD append for the CR4: cut-through with TXD, bss index */
	memset(&txwi[8], 0, MT7668_TXD_APPEND_SIZE);
	txwi[8] = cpu_to_le32(FIELD_PREP(GENMASK(15, 0), 1));
	txwi[9] = cpu_to_le32(mvif ? mvif->idx : 0);
}

/* The data path of the firmware only takes 802.3 frames, convert the ones
 * mac80211 did not encapsulate itself (e.g. EAPOL frames)
 */
int mt7668_tx_to_8023(struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	int hdrlen = ieee80211_hdrlen(hdr->frame_control);
	struct ethhdr eth;
	u8 *payload;

	if (info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP ||
	    !ieee80211_is_data_present(hdr->frame_control))
		return 0;

	/* the payload must not have been encrypted by mac80211 */
	if (ieee80211_has_protected(hdr->frame_control) &&
	    !info->control.hw_key)
		return -EINVAL;

	if (skb->len < hdrlen + sizeof(rfc1042_header) + 2)
		return -EINVAL;

	ether_addr_copy(eth.h_dest, ieee80211_get_DA(hdr));
	ether_addr_copy(eth.h_source, ieee80211_get_SA(hdr));

	payload = skb->data + hdrlen;
	if (ether_addr_equal(payload, rfc1042_header) ||
	    ether_addr_equal(payload, bridge_tunnel_header)) {
		eth.h_proto = get_unaligned((__be16 *)(payload + ETH_ALEN));
		skb_pull(skb, hdrlen + ETH_ALEN + 2);
	} else {
		eth.h_proto = htons(skb->len - hdrlen);
		skb_pull(skb, hdrlen);
	}

	memcpy(skb_push(skb, sizeof(eth)), &eth, sizeof(eth));
	info->flags |= IEEE80211_TX_CTL_HW_80211_ENCAP;

	return 0;
}
EXPORT_SYMBOL_GPL(mt7668_tx_to_8023);

int mt7668_reverse_hdr_trans(struct sk_buff *skb, u16 hdr_gap)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct ethhdr *eth_hdr = (struct ethhdr *)(skb->data + hdr_gap);
	struct mt7615_sta *msta = (struct mt7615_sta *)status->wcid;
	__le32 *rxd = (__le32 *)skb->data;
	struct ieee80211_vif *vif;
	struct ieee80211_hdr hdr;
	u16 frame_control;
	const u8 *bssid;

	if (!(le32_to_cpu(rxd[0]) & MT_RXD0_NORMAL_GROUP_4))
		return -EINVAL;

	if (!msta || !msta->vif)
		return -EINVAL;

	vif = container_of((void *)msta->vif, struct ieee80211_vif, drv_priv);
	bssid = vif->type == NL80211_IFTYPE_STATION ? vif->bss_conf.bssid :
						      vif->addr;
	if (!bssid)
		return -EINVAL;

	frame_control = le32_get_bits(rxd[4], MT_RXD4_FRAME_CONTROL);
	hdr.frame_control = cpu_to_le16(frame_control);
	hdr.seq_ctrl = cpu_to_le16(le32_get_bits(rxd[6], MT_RXD6_SEQ_CTRL));
	hdr.duration_id = 0;

	switch (frame_control & (IEEE80211_FCTL_TODS |
				 IEEE80211_FCTL_FROMDS)) {
	case IEEE80211_FCTL_FROMDS:
		ether_addr_copy(hdr.addr1, eth_hdr->h_dest);
		ether_addr_copy(hdr.addr2, bssid);
		ether_addr_copy(hdr.addr3, eth_hdr->h_source);
		break;
	case IEEE80211_FCTL_TODS:
		ether_addr_copy(hdr.addr1, bssid);
		ether_addr_copy(hdr.addr2, eth_hdr->h_source);
		ether_addr_copy(hdr.addr3, eth_hdr->h_dest);
		break;
	case 0:
		ether_addr_copy(hdr.addr1, eth_hdr->h_dest);
		ether_addr_copy(hdr.addr2, eth_hdr->h_source);
		ether_addr_copy(hdr.addr3, bssid);
		break;
	default:
		return -EINVAL;
	}

	skb_pull(skb, hdr_gap + sizeof(struct ethhdr) - 2);
	if (eth_hdr->h_proto == cpu_to_be16(ETH_P_AARP) ||
	    eth_hdr->h_proto == cpu_to_be16(ETH_P_IPX))
		ether_addr_copy(skb_push(skb, ETH_ALEN), bridge_tunnel_header);
	else if (be16_to_cpu(eth_hdr->h_proto) >= ETH_P_802_3_MIN)
		ether_addr_copy(skb_push(skb, ETH_ALEN), rfc1042_header);
	else
		skb_pull(skb, 2);

	if (ieee80211_has_order(hdr.frame_control))
		memcpy(skb_push(skb, IEEE80211_HT_CTL_LEN), &rxd[7],
		       IEEE80211_HT_CTL_LEN);

	if (ieee80211_is_data_qos(hdr.frame_control)) {
		__le16 qos_ctrl;

		qos_ctrl = cpu_to_le16(le32_get_bits(rxd[6], MT_RXD6_QOS_CTL));
		memcpy(skb_push(skb, IEEE80211_QOS_CTL_LEN), &qos_ctrl,
		       IEEE80211_QOS_CTL_LEN);
	}

	memcpy(skb_push(skb, sizeof(hdr) - ETH_ALEN), &hdr,
	       sizeof(hdr) - ETH_ALEN);

	return 0;
}

/* The firmware accepts block ack agreements on its own and reports them,
 * the rx reordering is left to the host.
 */
bool mt7668_mcu_rx_event(struct mt7615_dev *dev, struct sk_buff *skb)
{
	struct mt7615_mcu_rxd *rxd = (struct mt7615_mcu_rxd *)skb->data;

	if (rxd->eid != MT7668_EVENT_RX_ADDBA &&
	    rxd->eid != MT7668_EVENT_RX_DELBA)
		return false;

	skb_queue_tail(&dev->ba_event_list, skb);
	queue_work(dev->mt76.wq, &dev->ba_work);

	return true;
}

void mt7668_ba_work(struct work_struct *work)
{
	struct mt7615_dev *dev = container_of(work, struct mt7615_dev, ba_work);
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&dev->ba_event_list)) != NULL) {
		struct mt7615_mcu_rxd *rxd = (struct mt7615_mcu_rxd *)skb->data;
		struct {
			u8 sta_idx;
			u8 dialog_token;
			__le16 param;
			__le16 timeout;
			__le16 ssn;
		} __packed *addba;
		struct {
			u8 sta_idx;
			u8 tid;
			u8 rsv[2];
		} __packed *delba;
		struct mt76_wcid *wcid;
		u8 eid = rxd->eid;

		skb_pull(skb, sizeof(*rxd));
		if (skb->len < (eid == MT7668_EVENT_RX_ADDBA ? sizeof(*addba) :
							       sizeof(*delba)))
			goto next;

		addba = (void *)skb->data;
		delba = (void *)skb->data;

		mt7615_mutex_acquire(dev);

		rcu_read_lock();
		wcid = mt76_wcid_ptr(dev, addba->sta_idx);
		rcu_read_unlock();

		if (wcid && wcid->sta && eid == MT7668_EVENT_RX_ADDBA) {
			struct mt7615_sta *msta;
			u16 param = le16_to_cpu(addba->param);
			u16 ssn, last, size;
			u8 tid;

			msta = container_of(wcid, struct mt7615_sta, wcid);
			tid = u16_get_bits(param, IEEE80211_ADDBA_PARAM_TID_MASK);
			size = u16_get_bits(param, IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK);
			ssn = IEEE80211_SEQ_TO_SN(le16_to_cpu(addba->ssn));

			/* frames of the session may have been passed up before
			 * this event got here, start the window after them
			 */
			last = msta->rx_last_seq[tid];
			if (last != U16_MAX &&
			    ieee80211_sn_less_eq(ssn, IEEE80211_SEQ_TO_SN(last)))
				ssn = ieee80211_sn_inc(IEEE80211_SEQ_TO_SN(last));

			mt76_rx_aggr_start(&dev->mt76, wcid, tid, ssn,
					   size ? size : IEEE80211_MAX_AMPDU_BUF_HT);
		} else if (wcid && wcid->sta) {
			mt76_rx_aggr_stop(&dev->mt76, wcid, delba->tid);
		}

		mt7615_mutex_release(dev);
next:
		dev_kfree_skb(skb);
	}
}

void mt7668_init_ops(struct ieee80211_ops *ops)
{
	ops->config = mt7668_config;
	ops->conf_tx = mt7668_conf_tx;
	ops->set_rts_threshold = mt7668_set_rts_threshold;
	ops->set_coverage_class = mt7668_set_coverage_class;
	ops->sta_rate_tbl_update = mt7668_sta_rate_tbl_update;
	ops->hw_scan = mt7668_hw_scan;
	ops->configure_filter = mt7668_configure_filter;
	ops->bss_info_changed = mt7668_bss_info_changed;
	ops->set_key = mt7668_set_key;
	/* the firmware needs the AP station record before authentication */
	ops->sta_state = mt76_sta_state;
	ops->sta_add = NULL;
	ops->sta_remove = NULL;
	ops->mgd_prepare_tx = mt7668_mgd_prepare_tx;
	ops->mgd_complete_tx = mt7668_mgd_complete_tx;
	ops->cancel_hw_scan = mt7668_cancel_hw_scan;
	ops->sched_scan_start = NULL;
	ops->sched_scan_stop = NULL;
	/* no unified command offloads or rate power tables in the firmware */
#ifdef CONFIG_PM
	ops->set_rekey_data = NULL;
#endif
	ops->set_sar_specs = NULL;
	/* no MAC register access through the firmware */
	ops->get_tsf = NULL;
	ops->set_tsf = NULL;
	ops->offset_tsf = NULL;
}
EXPORT_SYMBOL_GPL(mt7668_init_ops);
