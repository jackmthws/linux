// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020 MediaTek Inc.
 *
 * Author: Felix Fietkau <nbd@nbd.name>
 *	   Lorenzo Bianconi <lorenzo@kernel.org>
 *	   Sean Wang <sean.wang@mediatek.com>
 */
#include <linux/kernel.h>
#include <linux/mmc/sdio_func.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/unaligned.h>

#include "../sdio.h"
#include "mt7615.h"
#include "mac.h"
#include "mcu.h"
#include "regs.h"

static u32 mt7668s_read_wcir(struct mt76_dev *dev)
{
	struct sdio_func *func = dev->sdio.func;
	u32 val;

	sdio_claim_host(func);
	val = sdio_readl(func, MCR_WCIR, NULL);
	sdio_release_host(func);

	return val;
}

void mt7668s_mcu_power_off(struct mt7615_dev *dev)
{
	u32 val;

	if (!(mt7668s_read_wcir(&dev->mt76) & WCIR_WLAN_READY))
		return;

	if (mt7668_mcu_power_off(dev) ||
	    readx_poll_timeout(mt7668s_read_wcir, &dev->mt76, val,
			       !(val & WCIR_WLAN_READY), 5000, 2000000))
		dev_warn(dev->mt76.dev, "Failed to power off the firmware\n");
}

static int mt7668s_load_firmware(struct mt7615_dev *dev)
{
	u32 val;
	int ret;

	/* the firmware is still running after a driver reload */
	mt7668s_mcu_power_off(dev);

	ret = mt7668_load_firmware(dev);
	if (ret)
		return ret;

	/* the N9 and CR4 take a while to come up after the download */
	ret = readx_poll_timeout(mt7668s_read_wcir, &dev->mt76, val,
				 val & WCIR_WLAN_READY, 5000, 10000000);
	if (ret)
		dev_err(dev->mt76.dev, "Timeout for initializing firmware\n");

	return ret;
}

static int mt7668s_mcu_get_nic_capability(struct mt7615_dev *dev)
{
	struct mt76_sdio *sdio = &dev->mt76.sdio;
	struct {
		__le16 n_element;
		u8 rsv[2];
	} __packed *hdr;
	struct sk_buff *skb;
	int ret, i;

	ret = mt76_mcu_send_and_get_msg(&dev->mt76, MCU_CE_QUERY(GET_NIC_CAPAB),
					NULL, 0, true, &skb);
	if (ret)
		return ret;

	skb_pull(skb, sizeof(struct mt7615_mcu_rxd));
	hdr = (void *)skb->data;
	if (skb->len < sizeof(*hdr)) {
		ret = -EINVAL;
		goto out;
	}
	skb_pull(skb, sizeof(*hdr));

	for (i = 0; i < le16_to_cpu(hdr->n_element); i++) {
		struct {
			__le32 type;
			__le32 len;
		} __packed *tlv = (void *)skb->data;
		struct {
			__le32 mcu_total;
			__le32 mcu_unit;
			__le32 lmac_total;
			__le32 lmac_unit;
		} __packed *res;
		int len;

		if (skb->len < sizeof(*tlv))
			break;
		skb_pull(skb, sizeof(*tlv));

		len = le32_to_cpu(tlv->len);
		if (skb->len < len)
			break;

		if (le32_to_cpu(tlv->type) == MT_NIC_CAP_TX_EFUSE_ADDR &&
		    len >= 8) {
			u32 start = get_unaligned_le32(skb->data);
			u32 end = get_unaligned_le32(skb->data + 4);

			if (end >= start) {
				dev->ee_buf_start = start;
				dev->ee_buf_len = end - start + 1;
			}
		}

		if (le32_to_cpu(tlv->type) == MT_NIC_CAP_TX_RESOURCE &&
		    len >= sizeof(*res)) {
			res = (void *)skb->data;
			sdio->pse_mcu_quota_max = le32_to_cpu(res->mcu_total);
			/* this query consumed one mcu resource */
			sdio->sched.pse_mcu_quota = sdio->pse_mcu_quota_max - 1;
			sdio->sched.pse_data_quota = le32_to_cpu(res->lmac_total);
			sdio->sched.ple_data_quota = le32_to_cpu(res->lmac_total);
		}
		skb_pull(skb, len);
	}
out:
	dev_kfree_skb(skb);

	return ret;
}

static int mt7663s_mcu_init_sched(struct mt7615_dev *dev)
{
	struct mt76_sdio *sdio = &dev->mt76.sdio;
	u32 txdwcnt;

	if (is_mt7668(&dev->mt76)) {
		/* conservative defaults, updated from the nic capability */
		sdio->sched.pse_data_quota = 64;
		sdio->sched.ple_data_quota = 64;
		sdio->sched.pse_mcu_quota = 7;
		sdio->pse_mcu_quota_max = 7;
		sdio->sched.pse_page_size = 2048;
		sdio->sched.deficit = 0;
		return 0;
	}

	sdio->sched.pse_data_quota = mt76_get_field(dev, MT_PSE_PG_HIF0_GROUP,
						    MT_HIF0_MIN_QUOTA);
	sdio->sched.pse_mcu_quota = mt76_get_field(dev, MT_PSE_PG_HIF1_GROUP,
						   MT_HIF1_MIN_QUOTA);
	sdio->sched.ple_data_quota = mt76_get_field(dev, MT_PLE_PG_HIF0_GROUP,
						    MT_HIF0_MIN_QUOTA);
	sdio->sched.pse_page_size = MT_PSE_PAGE_SZ;
	txdwcnt = mt76_get_field(dev, MT_PP_TXDWCNT,
				 MT_PP_TXDWCNT_TX1_ADD_DW_CNT);
	sdio->sched.deficit = txdwcnt << 2;

	return 0;
}

static int
mt7663s_mcu_send_message(struct mt76_dev *mdev, struct sk_buff *skb,
			 int cmd, int *seq)
{
	struct mt7615_dev *dev = container_of(mdev, struct mt7615_dev, mt76);
	int ret;

	mt7615_mcu_fill_msg(dev, skb, cmd, seq);
	ret = mt76_tx_queue_skb_raw(dev, mdev->q_mcu[MT_MCUQ_WM], skb, 0);
	if (ret)
		return ret;

	mt76_queue_kick(dev, mdev->q_mcu[MT_MCUQ_WM]);

	return ret;
}

static int __mt7663s_mcu_drv_pmctrl(struct mt7615_dev *dev)
{
	struct sdio_func *func = dev->mt76.sdio.func;
	struct mt76_phy *mphy = &dev->mt76.phy;
	struct mt76_connac_pm *pm = &dev->pm;
	u32 status;
	int ret;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_CLR, MCR_WHLPCR, NULL);

	ret = readx_poll_timeout(mt76s_read_pcr, &dev->mt76, status,
				 status & WHLPCR_IS_DRIVER_OWN, 2000, 1000000);
	if (ret < 0) {
		dev_err(dev->mt76.dev, "Cannot get ownership from device");
	} else {
		clear_bit(MT76_STATE_PM, &mphy->state);

		pm->stats.last_wake_event = jiffies;
		pm->stats.doze_time += pm->stats.last_wake_event -
				       pm->stats.last_doze_event;
	}
	sdio_release_host(func);

	return ret;
}

static int mt7663s_mcu_drv_pmctrl(struct mt7615_dev *dev)
{
	struct mt76_phy *mphy = &dev->mt76.phy;
	int ret = 0;

	mutex_lock(&dev->pm.mutex);

	if (test_bit(MT76_STATE_PM, &mphy->state))
		ret = __mt7663s_mcu_drv_pmctrl(dev);

	mutex_unlock(&dev->pm.mutex);

	return ret;
}

static int mt7663s_mcu_fw_pmctrl(struct mt7615_dev *dev)
{
	struct sdio_func *func = dev->mt76.sdio.func;
	struct mt76_phy *mphy = &dev->mt76.phy;
	struct mt76_connac_pm *pm = &dev->pm;
	int ret = 0;
	u32 status;

	mutex_lock(&pm->mutex);

	if (mt76_connac_skip_fw_pmctrl(mphy, pm))
		goto out;

	sdio_claim_host(func);

	sdio_writel(func, WHLPCR_FW_OWN_REQ_SET, MCR_WHLPCR, NULL);

	ret = readx_poll_timeout(mt76s_read_pcr, &dev->mt76, status,
				 !(status & WHLPCR_IS_DRIVER_OWN), 2000, 1000000);
	if (ret < 0) {
		dev_err(dev->mt76.dev, "Cannot set ownership to device");
		clear_bit(MT76_STATE_PM, &mphy->state);
	} else {
		pm->stats.last_doze_event = jiffies;
		pm->stats.awake_time += pm->stats.last_doze_event -
					pm->stats.last_wake_event;
	}

	sdio_release_host(func);
out:
	mutex_unlock(&pm->mutex);

	return ret;
}

int mt7663s_mcu_init(struct mt7615_dev *dev)
{
	static const struct mt76_mcu_ops mt7663s_mcu_ops = {
		.headroom = sizeof(struct mt7615_mcu_txd),
		.tailroom = MT_USB_TAIL_SIZE,
		.mcu_skb_send_msg = mt7663s_mcu_send_message,
		.mcu_parse_response = mt7615_mcu_parse_response,
		.mcu_rr = mt76_connac_mcu_reg_rr,
		.mcu_wr = mt76_connac_mcu_reg_wr,
	};
	struct mt7615_mcu_ops *mcu_ops;
	int ret;

	ret = __mt7663s_mcu_drv_pmctrl(dev);
	if (ret)
		return ret;

	dev->mt76.mcu_ops = &mt7663s_mcu_ops;

	if (is_mt7668(&dev->mt76)) {
		ret = mt7668s_load_firmware(dev);
	} else {
		ret = mt76_get_field(dev, MT_CONN_ON_MISC,
				     MT_TOP_MISC2_FW_N9_RDY);
		if (ret) {
			mt7615_mcu_restart(&dev->mt76);
			if (!mt76_poll_msec(dev, MT_CONN_ON_MISC,
					    MT_TOP_MISC2_FW_N9_RDY, 0, 500))
				return -EIO;
		}

		ret = __mt7663_load_firmware(dev);
	}
	if (ret)
		return ret;

	mcu_ops = devm_kmemdup(dev->mt76.dev, dev->mcu_ops, sizeof(*mcu_ops),
			       GFP_KERNEL);
	if (!mcu_ops)
		return -ENOMEM;

	mcu_ops->set_drv_ctrl = mt7663s_mcu_drv_pmctrl;
	mcu_ops->set_fw_ctrl = mt7663s_mcu_fw_pmctrl;
	dev->mcu_ops = mcu_ops;

	ret = mt7663s_mcu_init_sched(dev);
	if (ret)
		return ret;

	set_bit(MT76_STATE_MCU_RUNNING, &dev->mphy.state);

	if (is_mt7668(&dev->mt76)) {
		ret = mt7668s_mcu_get_nic_capability(dev);
		if (ret)
			return ret;

		ret = mt7668_mcu_basic_config(dev);
		if (ret)
			return ret;
	}

	return 0;
}
