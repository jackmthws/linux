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
