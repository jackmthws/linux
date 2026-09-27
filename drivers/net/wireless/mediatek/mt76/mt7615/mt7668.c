// SPDX-License-Identifier: BSD-3-Clause-Clear
/* MT7668 support
 *
 * The MT7668 runs a "gen3" station firmware that predates the connac
 * unified commands: the host describes interfaces, BSSes and stations with
 * the legacy command set while scan, remain-on-channel and power save are
 * offloaded to the firmware.
 */

#include "mt7615.h"
#include "mcu.h"
#include "mac.h"

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
