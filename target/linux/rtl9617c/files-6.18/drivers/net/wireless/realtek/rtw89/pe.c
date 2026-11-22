// SPDX-License-Identifier: GPL-2.0-only
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>
#include <net/mac80211.h>
#include <linux/rtl9617c/pe/rx-geometry.h>
#include <linux/rtl9617c/pe/tx-ownership.h>
#include <linux/rtl9617c/pe/traffic-flow.h>
#include <linux/rtl9617c/pe/amsdu-queue.h>
#include <linux/rtl9617c/pe/qos.h>
#include "pe_probe.h"
#include "rtl9617c_ni.h"
#include "core.h"
#include "pe.h"
#include "pci.h"

static bool rtw89_pe_enable;
module_param_named(pe_enable, rtw89_pe_enable, bool, 0444);
MODULE_PARM_DESC(pe_enable, "Enable RTL9617C PE hardware data path offload");

#define RTW89_PE_TX_ENTRIES	256
#define RTW89_PE_TX_STOP	(RTW89_PE_TX_ENTRIES - 32)
#define RTW89_PE_TX_WAKE	(RTW89_PE_TX_ENTRIES / 2)
#define RTW89_PE_TX_PAGES	RTL_AX_NI_ID_END
#define RTW89_PE_TX_HEADERS	(RTW89_PE_TX_PAGES * 128)
#define RTW89_PE_TX_RING_BYTES	(6 * RTW89_PE_TX_ENTRIES * 8)
#define RTW89_PE_TX_WD_BYTES	(6 * RTL_AX_TX_WD_PER_RING * 128)
#define RTW89_PE_RX_ENTRIES	RTL_AX_RX_ENTRIES
#define RTW89_PE_RX_BUFFERS	RTL_AX_RX_BUFFERS
#define RTW89_PE_RX_BUFFER_BYTES RTL_AX_RXQ_BUFFER_BYTES
#define RTW89_PE_RPQ_BUFFER_BYTES RTL_AX_RPQ_BUFFER_BYTES
#define RTW89_PE_FORWARD_BYTES	(RTW89_PE_RX_ENTRIES * RTW89_PE_RPQ_BUFFER_BYTES)
#define RTW89_PE_INDICATION_REG	0x30b0
#define RTW89_PE_IRQ_INDICATION	(BIT(29) | BIT(24))
#define RTW89_PE_SLOT0_BAR	0xb1000000
#define RTW89_PE_SLOT1_BAR	0xb2000000
#define RTW89_PE_TX_SCHED	0xc398

static const u32 rtw89_pe_tx_indices[6] = { 0x1058, 0x105c, 0x1060, 0x1064, 0x1078, 0x107c };
static const u32 rtw89_pe_tx_channels[6] = { 0, 1, 2, 3, 8, 9 };
static const u32 rtw89_pe_tx_desa[6] = { 0x1230, 0x1238, 0x1240, 0x1248, 0x1270, 0x1278 };
static const u32 rtw89_pe_tx_numbers[6] = { 0x1024, 0x1026, 0x1028, 0x102a, 0x1034, 0x1036 };
static const u32 rtw89_pe_tx_bdram[6] = { 0x1300, 0x1304, 0x1308, 0x130c, 0x1320, 0x1324 };
static const u8 rtw89_pe_tid_indicators[8] = { 0, 0, 1, 1, 0, 1, 0, 1 };

struct rtw89_pe_rx_payload {
	u8 *data;
	dma_addr_t dma;
	struct sk_buff *skb;
};

struct rtw89_pe_tx_slot {
	struct sk_buff *skb;
	dma_addr_t dma;
	unsigned int bytes;
	unsigned int id;
	u8 ring;
	u8 key_index;
	u8 macid;
	u8 tid;
	bool encrypted;
	bool pe_sequence;
	bool firmware_rate;
	bool quota_counted;
};

struct rtw89_pe_shortcut_seen {
	u32 frames;
	u32 bytes;
	u32 msdus;
};

struct rtw89_pe {
	struct rtw89_dev *rtwdev;
	struct device *dma_device;
	struct pe_probe tx;
	struct pe_probe rx;
	bool attached;
	bool running;
	bool tx_active;
	bool rx_owned;
	bool pool_initialized;
	unsigned int slot;
	u32 tx_command;
	u32 rx_command;
	unsigned int tx_producer;
	DECLARE_BITMAP(tx_pending, RTW89_PE_TX_ENTRIES);
	struct rtw89_pe_tx_slot tx_slots[RTW89_PE_TX_ENTRIES];
	unsigned int tx_occupied;
	unsigned int tx_producer_ring[6];
	bool tx_queues_stopped;
	bool tx_paused;
	u32 scheduler_saved;
	bool checksum_enabled;
	u8 *tx_ring;
	u8 *tx_pages;
	u8 *tx_headers;
	dma_addr_t tx_ring_dma;
	dma_addr_t tx_pages_dma;
	dma_addr_t tx_headers_dma;
	bool peer_qos[128];
	bool peer_client[128];
	bool peer_asleep[128];
	bool peer_authorized[128];
	bool peer_preload[128];
	bool peer_offloaded[128];
	u32 peer_rates[128];
	u8 peer_bw[128];
	u32 wmm_quota;
	u32 ac_pending[128][4];
	u32 ac_seen[4];
	u8 wmm_streams;
	spinlock_t lock;
	wait_queue_head_t wait;
	u8 *pe_forward;
	dma_addr_t pe_forward_dma;
	struct rtw89_pe_rx_payload *payloads;
	u32 *rx_addresses;
	dma_addr_t rx_addresses_dma;
	u8 *rx_descriptors;
	dma_addr_t rx_descriptors_dma;
	u8 *rpq_buffers;
	dma_addr_t rpq_buffers_dma;
	u16 rx_slot_ids[RTW89_PE_RX_ENTRIES];
	unsigned int rx_consumer;
	unsigned int rx_tag;
	u32 dfs_epoch[4];
	void *uplink_states;
	dma_addr_t uplink_states_dma;
	struct mutex uplink_lock;
	struct ieee80211_key_conf *keys[128];
	u8 uplink_trigger_tids[128];
	u16 uplink_pending_tids[128];
	struct rtw89_pe_shortcut_seen uplink_seen[128][16];
	u32 uplink_wifi_id;
	u32 uplink_forwarded_seen;
	struct device *ni_dev;
	struct net_device *route_dev;
	unsigned int ni_cpu;
	unsigned int ni_eq;
	bool ni_active;
	u32 pe_rdu_seen[2];
	u64 pe_captured;
	u64 pe_rx_delivered;
	u64 pe_rx_malformed;
	u64 tx_submitted;
	u64 tx_completed;
	u64 tx_full;
	struct delayed_work work;
	struct wiphy_delayed_work traffic_work;
};

static u8 *rtw89_pe_tx_mailbox(struct rtw89_pe *pe)
{
	return pe->tx.memory + PE_PROBE_MAILBOX;
}

static u8 *rtw89_pe_rx_mailbox(struct rtw89_pe *pe)
{
	return pe->rx.memory + PE_PROBE_MAILBOX;
}

static u32 rtw89_pe_tx_read(struct rtw89_pe *pe, unsigned int word)
{
	return get_unaligned_le32(rtw89_pe_tx_mailbox(pe) + word * 4);
}

static void rtw89_pe_tx_write(struct rtw89_pe *pe, unsigned int word, u32 value)
{
	put_unaligned_le32(value, rtw89_pe_tx_mailbox(pe) + word * 4);
}

static u32 rtw89_pe_rx_read(struct rtw89_pe *pe, unsigned int word)
{
	return get_unaligned_le32(rtw89_pe_rx_mailbox(pe) + word * 4);
}

static void rtw89_pe_rx_write(struct rtw89_pe *pe, unsigned int word, u32 value)
{
	put_unaligned_le32(value, rtw89_pe_rx_mailbox(pe) + word * 4);
}

static struct rtw89_pe *rtw89_pe_of(struct rtw89_dev *rtwdev)
{
	return rtwdev->pe;
}

bool rtw89_pe_active(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);

	return pe && READ_ONCE(pe->tx_active);
}

static void rtw89_pe_wake(struct rtw89_pe *pe)
{
	if (READ_ONCE(pe->running))
		mod_delayed_work(system_wq, &pe->work, 0);
}

static void rtw89_pe_dma_pause(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;

	rtw89_write32_set(rtwdev, R_AX_HAXI_DMA_STOP1,
			  B_AX_STOP_ACH0 | B_AX_STOP_ACH1 | B_AX_STOP_ACH2 |
			  B_AX_STOP_ACH3 | B_AX_STOP_CH8 | B_AX_STOP_CH9 |
			  B_AX_STOP_RPQ | B_AX_STOP_RXQ);
	rtw89_write32_set(rtwdev, R_AX_HAXI_DMA_STOP2, B_AX_TX_STOP2_ALL);
}

static void rtw89_pe_dma_resume(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;

	rtw89_write32_clr(rtwdev, R_AX_HAXI_DMA_STOP1,
			  B_AX_STOP_ACH0 | B_AX_STOP_ACH1 | B_AX_STOP_ACH2 |
			  B_AX_STOP_ACH3 | B_AX_STOP_CH8 | B_AX_STOP_CH9 |
			  B_AX_STOP_RPQ | B_AX_STOP_RXQ);
	rtw89_write32_clr(rtwdev, R_AX_HAXI_DMA_STOP2, B_AX_TX_STOP2_ALL);
}

static int rtw89_pe_rx_configure(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	u32 last;
	int ret;
	int i;

	ret = read_poll_timeout(rtw89_read32, last, !(last & 3), 10, 100000,
				false, rtwdev, R_AX_HAXI_DMA_BUSY3);
	if (ret)
		return ret;
	rtw89_write32(rtwdev, R_AX_RXBD_RWPTR_CLR_V1, 3);
	for (i = 0; i < 2; i++) {
		u32 desa = i ? pe->rpq_buffers_dma : pe->rx_descriptors_dma;

		ret = read_poll_timeout(rtw89_read32, last, !(last & 0x3ff03ff),
					10, 100000, false, rtwdev,
					R_AX_RXQ_RXBD_IDX_V1 + i * 4);
		if (ret)
			return ret;
		rtw89_write16(rtwdev, R_AX_RXQ_RXBD_NUM_V1 + i * 2, RTW89_PE_RX_ENTRIES);
		rtw89_write32(rtwdev, R_AX_RXQ_RXBD_DESA_L_V1 + i * 8, desa | 0x80000000U);
		rtw89_write32(rtwdev, R_AX_RXQ_RXBD_DESA_H_V1 + i * 8, 0);
	}
	return 0;
}

static int rtw89_pe_tx_hw_configure(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	u32 last;
	int ret;
	int ring;

	rtw89_write32_set(rtwdev, R_AX_HAXI_DMA_STOP1,
			  GENMASK(11, 8) | BIT(16) | BIT(17));
	ret = read_poll_timeout(rtw89_read32, last,
				!(last & (GENMASK(11, 8) | BIT(16) | BIT(17))),
				10, 100000, false, rtwdev, R_AX_HAXI_DMA_BUSY1);
	if (ret)
		return ret;
	rtw89_write32(rtwdev, R_AX_TXBD_RWPTR_CLR1, GENMASK(3, 0) | BIT(8) | BIT(9));
	for (ring = 0; ring < 6; ring++) {
		unsigned int channel = rtw89_pe_tx_channels[ring];

		ret = read_poll_timeout(rtw89_read32, last, !(last & 0x3ff03ff),
					10, 100000, false, rtwdev,
					rtw89_pe_tx_indices[ring]);
		if (ret)
			return ret;
		rtw89_write32(rtwdev, rtw89_pe_tx_desa[ring],
			      lower_32_bits(pe->tx_ring_dma + ring * RTW89_PE_TX_ENTRIES * 8) |
			      0x80000000U);
		rtw89_write32(rtwdev, rtw89_pe_tx_desa[ring] + 4, 0);
		rtw89_write16(rtwdev, rtw89_pe_tx_numbers[ring], RTW89_PE_TX_ENTRIES);
		rtw89_write32(rtwdev, rtw89_pe_tx_bdram[ring],
			      channel * 5 | 5U << 8 | (channel < 8 ? 2U : 1U) << 16);
	}
	return 0;
}

static void rtw89_pe_tx_dma_free(struct rtw89_pe *pe)
{
	if (pe->tx_headers)
		dma_free_coherent(pe->dma_device, RTW89_PE_TX_HEADERS,
				  pe->tx_headers, pe->tx_headers_dma);
	if (pe->tx_pages)
		dma_free_coherent(pe->dma_device, RTW89_PE_TX_WD_BYTES,
				  pe->tx_pages, pe->tx_pages_dma);
	if (pe->tx_ring)
		dma_free_coherent(pe->dma_device, RTW89_PE_TX_RING_BYTES,
				  pe->tx_ring, pe->tx_ring_dma);
	pe->tx_headers = NULL;
	pe->tx_pages = NULL;
	pe->tx_ring = NULL;
}

static int rtw89_pe_tx_dma_alloc(struct rtw89_pe *pe)
{
	pe->tx_ring = dma_alloc_coherent(pe->dma_device, RTW89_PE_TX_RING_BYTES,
					 &pe->tx_ring_dma, GFP_KERNEL);
	pe->tx_pages = dma_alloc_coherent(pe->dma_device, RTW89_PE_TX_WD_BYTES,
					  &pe->tx_pages_dma, GFP_KERNEL);
	pe->tx_headers = dma_alloc_coherent(pe->dma_device, RTW89_PE_TX_HEADERS,
					    &pe->tx_headers_dma, GFP_KERNEL);
	if (!pe->tx_ring || !pe->tx_pages || !pe->tx_headers) {
		rtw89_pe_tx_dma_free(pe);
		return -ENOMEM;
	}
	memset(pe->tx_ring, 0, RTW89_PE_TX_RING_BYTES);
	memset(pe->tx_pages, 0, RTW89_PE_TX_WD_BYTES);
	return 0;
}

static int rtw89_pe_tx_context_start(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	u32 status;
	int ret;

	put_unaligned_le32(pe->slot ? RTW89_PE_SLOT1_BAR : RTW89_PE_SLOT0_BAR,
			   pe->tx.memory + PE_PROBE_MAILBOX + 8);
	put_unaligned_le32(pe->tx_ring_dma, pe->tx.memory + PE_PROBE_MAILBOX + 44);
	put_unaligned_le32(pe->tx_pages_dma, pe->tx.memory + PE_PROBE_MAILBOX + 48);
	put_unaligned_le32(pe->tx_headers_dma, pe->tx.memory + PE_PROBE_MAILBOX + 56);
	rtl_ax_tx_ownership_init(pe->tx.memory, pe->slot ? 1024 : 2048);
	dma_wmb();
	ret = pe_probe_start(&pe->tx);
	if (ret)
		return ret;
	ret = read_poll_timeout(get_unaligned_le32, status, status == PE_PROBE_MAGIC,
				10, 100000, false, pe->tx.memory + PE_PROBE_MAILBOX);
	if (ret)
		return ret;
	WRITE_ONCE(pe->tx_active, true);
	pe->checksum_enabled = !!(rtw89_read32(rtwdev, 0x8830) & BIT(0));
	return 0;
}

static int rtw89_pe_tx_context_stop(struct rtw89_pe *pe)
{
	int ret;

	if (!READ_ONCE(pe->tx_active))
		return 0;
	WRITE_ONCE(pe->tx_active, false);
	ret = pe_probe_stop(&pe->tx);
	return ret;
}

static int rtw89_pe_rx_buffer_alloc(struct rtw89_pe *pe, unsigned int bytes,
				    struct rtw89_pe_rx_payload *payload)
{
	struct sk_buff *skb = alloc_skb(bytes + NET_SKB_PAD, GFP_KERNEL);
	dma_addr_t dma;

	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, NET_SKB_PAD);
	put_unaligned_le32(0, skb->data);
	dma = dma_map_single(pe->dma_device, skb->data, bytes, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(pe->dma_device, dma)) {
		kfree_skb(skb);
		return -EIO;
	}
	payload->data = skb->data;
	payload->dma = dma;
	payload->skb = skb;
	return 0;
}

static void rtw89_pe_rx_buffers_free(struct rtw89_pe *pe)
{
	unsigned int id;

	if (pe->payloads) {
		for (id = 0; id < RTW89_PE_RX_BUFFERS; id++)
			if (pe->payloads[id].skb) {
				dma_unmap_single(pe->dma_device, pe->payloads[id].dma,
						 RTW89_PE_RX_BUFFER_BYTES, DMA_BIDIRECTIONAL);
				dev_kfree_skb_any(pe->payloads[id].skb);
			}
	}
	kfree(pe->payloads);
	pe->payloads = NULL;
	if (pe->rx_addresses)
		dma_free_coherent(pe->dma_device, RTW89_PE_RX_BUFFERS * sizeof(u32),
				  pe->rx_addresses, pe->rx_addresses_dma);
	if (pe->rx_descriptors)
		dma_free_coherent(pe->dma_device, RTW89_PE_RX_ENTRIES * 8,
				  pe->rx_descriptors, pe->rx_descriptors_dma);
	if (pe->rpq_buffers)
		dma_free_coherent(pe->dma_device, RTW89_PE_FORWARD_BYTES,
				  pe->rpq_buffers, pe->rpq_buffers_dma);
	pe->rx_addresses = NULL;
	pe->rx_descriptors = NULL;
	pe->rpq_buffers = NULL;
}

static int rtw89_pe_rx_buffers_alloc(struct rtw89_pe *pe)
{
	unsigned int id;
	int ret;

	pe->payloads = kcalloc(RTW89_PE_RX_BUFFERS, sizeof(*pe->payloads), GFP_KERNEL);
	if (!pe->payloads)
		return -ENOMEM;
	pe->rx_addresses = dma_alloc_coherent(pe->dma_device, RTW89_PE_RX_BUFFERS * sizeof(u32),
					      &pe->rx_addresses_dma, GFP_KERNEL);
	pe->rx_descriptors = dma_alloc_coherent(pe->dma_device, RTW89_PE_RX_ENTRIES * 8,
						&pe->rx_descriptors_dma, GFP_KERNEL);
	pe->rpq_buffers = dma_alloc_coherent(pe->dma_device, RTW89_PE_FORWARD_BYTES,
					     &pe->rpq_buffers_dma, GFP_KERNEL);
	if (!pe->rx_addresses || !pe->rx_descriptors || !pe->rpq_buffers) {
		rtw89_pe_rx_buffers_free(pe);
		return -ENOMEM;
	}
	memset(pe->rpq_buffers, 0, RTW89_PE_FORWARD_BYTES);
	for (id = 0; id < RTW89_PE_RX_BUFFERS; id++) {
		ret = rtw89_pe_rx_buffer_alloc(pe, RTW89_PE_RX_BUFFER_BYTES, &pe->payloads[id]);
		if (ret) {
			rtw89_pe_rx_buffers_free(pe);
			return ret;
		}
		pe->rx_addresses[id] = cpu_to_le32(pe->payloads[id].dma);
	}
	for (id = 0; id < RTW89_PE_RX_ENTRIES; id++) {
		u8 *entry = pe->rx_descriptors + id * 8;

		put_unaligned_le32(RTW89_PE_RX_BUFFER_BYTES, entry);
		put_unaligned_le32(lower_32_bits(pe->payloads[id].dma), entry + 4);
		pe->rx_slot_ids[id] = id;
	}
	dma_wmb();
	return 0;
}

static int rtw89_pe_rx_context_start(struct rtw89_pe *pe)
{
	u8 *mailbox = rtw89_pe_rx_mailbox(pe);
	u8 *tx_mailbox = rtw89_pe_tx_mailbox(pe);
	bool mapped[RTW89_PE_RX_BUFFERS] = {};
	unsigned int i, idle = 0;
	int ret;

	pe->rx_owned = true;
	pe->rx_command = 0;
	for (i = 0; i < RTW89_PE_RX_ENTRIES; i++) {
		put_unaligned_le32(pe->rx_slot_ids[i], pe->rx.memory + RTL_AX_RX_SLOT_MAP + i * 4);
		mapped[pe->rx_slot_ids[i]] = true;
	}
	if (!pe->pool_initialized) {
		memset(pe->rx.memory + RTL_AX_RX_NI_TAIL, 0, 16);
		for (i = 0; i < RTW89_PE_RX_BUFFERS; i++)
			if (!mapped[i])
				put_unaligned_le32(i, pe->rx.memory + RTL_AX_RX_IDLE_IDS + idle++ * 4);
		put_unaligned_le32(idle, mailbox + RTL_AX_RX_IDLE_COUNT * 4);
		pe->pool_initialized = true;
	}
	memset(pe->rx.memory + RTL_AX_RX_WORK_STATUS, 0, 0x800);
	memset(pe->rx.memory + RTL_AX_RX_REORDER_SEARCH, 0, 12);
	for (i = RTL_AX_RX_WORK_WRITE; i <= RTL_AX_RX_WORK_READ; i++)
		put_unaligned_le32(0, mailbox + i * 4);
	for (i = 0; i < 2; i++) {
		put_unaligned_le32(pe->dfs_epoch[i], mailbox + (RTL_AX_PE_DFS_EPOCH + i) * 4);
		put_unaligned_le32(0, mailbox + (RTL_AX_RX_RDU + i) * 4);
		pe->pe_rdu_seen[i] = 0;
		pe->dfs_epoch[2 + i] = 0;
	}
	put_unaligned_le32(0, mailbox + RTL_AX_RX_ARM_BARRIER * 4);
	put_unaligned_le32(pe->rx_descriptors_dma, mailbox + 134 * 4);
	put_unaligned_le32(pe->rx_consumer, mailbox + 324);
	put_unaligned_le32(pe->rx_tag, mailbox + 328);
	put_unaligned_le32(pe->rx_consumer, mailbox + 332);
	put_unaligned_le32(pe->rx_consumer, mailbox + 336);
	put_unaligned_le32(pe->rx_consumer, mailbox + RTL_AX_RX_HW_PRODUCER * 4);
	put_unaligned_le32(0, mailbox + 376);
	put_unaligned_le32(0, mailbox + 380);
	put_unaligned_le32(pe->rx_consumer, tx_mailbox + 280);
	put_unaligned_le32(pe->rx_tag, tx_mailbox + 284);
	put_unaligned_le32(pe->pe_forward_dma, tx_mailbox + 288);
	put_unaligned_le32(0, tx_mailbox + 292);
	put_unaligned_le32(0, tx_mailbox + 296);
	put_unaligned_le32(get_unaligned_le32(tx_mailbox + 8), mailbox + 8);
	put_unaligned_le32(lower_32_bits(pe->tx.dma), mailbox + 187 * 4);
	put_unaligned_le32(pe->rx_command & ~1U, mailbox + 12);
	put_unaligned_le32(get_unaligned_le32(tx_mailbox + 256), mailbox + 256);
	put_unaligned_le32(get_unaligned_le32(mailbox + 268), mailbox + 264);
	put_unaligned_le32(get_unaligned_le32(mailbox + 268), mailbox + 276);
	put_unaligned_le32(pe->dfs_epoch[1], tx_mailbox + (RTL_AX_PE_DFS_EPOCH + 1) * 4);
	dma_wmb();
	put_unaligned_le32(pe->rpq_buffers_dma, tx_mailbox + 272);
	put_unaligned_le32(0, tx_mailbox + 320);
	put_unaligned_le32(pe->rx_addresses_dma, mailbox + 320);
	rtw89_pe_tx_write(pe, 193, 0);
	rtw89_pe_tx_write(pe, 194, 0);
	rtw89_write32(pe->rtwdev, R_AX_HAXI_HISR00, 0);
	rtw89_write32(pe->rtwdev, RTW89_PE_INDICATION_REG, RTW89_PE_IRQ_INDICATION);
	ret = pe_probe_start(&pe->rx);
	if (ret) {
		pe->rx_owned = false;
		return ret;
	}
	put_unaligned_le32(pe->rx.dma + PE_PROBE_MAILBOX,
			   tx_mailbox + RTL_AX_RX_EVENT_CONTEXT * 4);
	dma_wmb();
	rtw89_pe_wake(pe);
	return 0;
}

static void rtw89_pe_rx_idle_put(struct rtw89_pe *pe, u32 id)
{
	struct rtw89_pe_rx_payload *payload = &pe->payloads[id];
	u32 count = get_unaligned_le32(pe->rx.memory + 0x2000 + RTL_AX_RX_IDLE_COUNT * 4);

	WRITE_ONCE(*(__le32 *)payload->data, 0);
	dma_sync_single_for_device(pe->dma_device, payload->dma,
				   RTW89_PE_RX_BUFFER_BYTES, DMA_BIDIRECTIONAL);
	put_unaligned_le32(id, pe->rx.memory + RTL_AX_RX_IDLE_IDS + count * 4);
	put_unaligned_le32(count + 1, pe->rx.memory + 0x2000 + RTL_AX_RX_IDLE_COUNT * 4);
}

static void rtw89_pe_rx_tail_recycle(struct rtw89_pe *pe)
{
	u8 *memory = pe->rx.memory;
	u32 read = get_unaligned_le32(memory + 0x216c);
	unsigned int i;

	for (i = 0; i < 2; i++) {
		u8 *held = memory + RTL_AX_RX_NI_TAIL + i * 8;
		u32 id = get_unaligned_le32(held);

		if (!id || (s32)((read - get_unaligned_le32(held + 4) - 2) << 1) < 0)
			continue;
		rtw89_pe_rx_idle_put(pe, id - 1);
		put_unaligned_le32(0, held);
	}
}

static void rtw89_pe_rx_work_recycle(struct rtw89_pe *pe)
{
	u8 *mailbox = rtw89_pe_rx_mailbox(pe);
	u8 *memory = pe->rx.memory;
	u32 read = get_unaligned_le32(mailbox + RTL_AX_RX_WORK_READ * 4);
	u32 process = get_unaligned_le32(mailbox + RTL_AX_RX_WORK_PROCESS * 4);

	rtw89_pe_rx_tail_recycle(pe);
	while (read != process) {
		u32 owner = get_unaligned_le32(memory + RTL_AX_RX_WORK_STATUS + read * 4);
		u32 id = get_unaligned_le32(memory + RTL_AX_RX_WORK_IDS + read * 4) & ~RTL_AX_RX_WORK_OLD;

		if ((owner & BIT(31)) &&
		    (s32)((get_unaligned_le32(mailbox + 364) - (owner & 0x7fffffff) - 2) << 1) < 0) {
			unsigned int i = get_unaligned_le32(memory + RTL_AX_RX_NI_TAIL) ? 1 : 0;

			put_unaligned_le32(id + 1, memory + RTL_AX_RX_NI_TAIL + i * 8);
			put_unaligned_le32(owner & 0x7fffffff, memory + RTL_AX_RX_NI_TAIL + i * 8 + 4);
		} else {
			rtw89_pe_rx_idle_put(pe, id);
		}
		put_unaligned_le32(0, memory + RTL_AX_RX_WORK_STATUS + read * 4);
		read = (read + 1) & 255;
	}
	put_unaligned_le32(read, mailbox + RTL_AX_RX_WORK_READ * 4);
}

static void rtw89_pe_uplink_publish(struct rtw89_pe *pe, struct ieee80211_sta *sta,
				    struct ieee80211_key_conf *key, unsigned int macid,
				    unsigned int tid)
{
	u8 *state = pe->uplink_states + (macid * 16 + tid) * 32;
	u16 next;
	u8 pn[6];

	if (!ieee80211_rx_shortcut_snapshot(sta, key, tid, &next, pn))
		return;
	put_unaligned_le32((u32)pn[2] << 24 | (u32)pn[3] << 16 | (u32)pn[4] << 8 | pn[5], state + 4);
	put_unaligned_le32((u32)pn[0] << 8 | pn[1], state + 8);
	dma_wmb();
	put_unaligned_le32(BIT(31) | next, state);
	pe->uplink_pending_tids[macid] &= ~BIT(tid);
}

static void rtw89_pe_uplink_sync(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	u8 *memory = pe->rx.memory;
	unsigned int macid, tid;
	u32 forwarded;
	bool changed, retry = false;

	if (!pe->uplink_wifi_id || !pe->uplink_states)
		return;
	mutex_lock(&pe->uplink_lock);
	forwarded = get_unaligned_le32(memory + 0x2180);
	changed = forwarded != pe->uplink_forwarded_seen;
	if (changed)
		dma_rmb();
	local_bh_disable();
	rcu_read_lock();
	for (macid = 1; macid < 128; macid++) {
		struct ieee80211_key_conf *key = pe->keys[macid];
		struct ieee80211_sta *sta;

		if (!key)
			continue;
		sta = ieee80211_find_sta_by_ifaddr(rtwdev->hw,
						   pe->tx.memory + 0xe400 + macid * 8, NULL);
		for (tid = 0; sta && tid < 16; tid++) {
			u8 *state = pe->uplink_states + (macid * 16 + tid) * 32;
			struct rtw89_pe_shortcut_seen *seen = &pe->uplink_seen[macid][tid];
			u32 guard, snapshot[6], count;
			u8 pn[6];

			if (!changed || get_unaligned_le32(state + 12) == seen->frames)
				goto resume;
			guard = get_unaligned_le32(state + 24);
			if (guard & 1) {
				retry = true;
				continue;
			}
			dma_rmb();
			for (u32 i = 0; i < 6; i++)
				snapshot[i] = get_unaligned_le32(state + i * 4);
			dma_rmb();
			if (guard != get_unaligned_le32(state + 24)) {
				retry = true;
				continue;
			}
			count = snapshot[3] - seen->frames;
			if (!count)
				goto resume;
			pn[0] = snapshot[2] >> 8;
			pn[1] = snapshot[2];
			pn[2] = snapshot[1] >> 24;
			pn[3] = snapshot[1] >> 16;
			pn[4] = snapshot[1] >> 8;
			pn[5] = snapshot[1];
			ieee80211_rx_shortcut_sync(sta, key, tid, snapshot[0] & 4095, pn,
						   min_t(u32, count, 2048));
			ieee80211_rx_shortcut_account(sta, tid, count,
						      snapshot[5] - seen->msdus,
						      snapshot[4] - seen->bytes);
			seen->frames = snapshot[3];
			seen->bytes = snapshot[4];
			seen->msdus = snapshot[5];
resume:
			if ((pe->uplink_pending_tids[macid] & BIT(tid)) &&
			    (get_unaligned_le32(pe->uplink_states + 0x10000 + macid * 4) & BIT(31)))
				if (!rtw89_pe_uplink_publish(pe, sta, key, macid, tid))
					retry = true;
		}
	}
	rcu_read_unlock();
	local_bh_enable();
	if (!retry)
		pe->uplink_forwarded_seen = forwarded;
	mutex_unlock(&pe->uplink_lock);
	if (retry)
		rtw89_pe_wake(pe);
}

static void rtw89_pe_uplink_seed(struct rtw89_pe *pe, u8 *frame, unsigned int bytes)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	unsigned int macid, tid;
	u16 fc;

	if (!pe->uplink_wifi_id || !pe->uplink_states || bytes < 24)
		return;
	fc = get_unaligned_le16(frame);
	if ((fc & 0x00fc) == 0x0084) {
		tid = frame[17] >> 4;
	} else {
		if (bytes < 54 || ((fc & 0x47ff) != 0x4188 && (fc & 0x47ff) != 0x4288) ||
		    frame[22] & 15)
			return;
		tid = frame[24] & 15;
	}
	mutex_lock(&pe->uplink_lock);
	for (macid = 1; macid < 128; macid++)
		if (pe->keys[macid] && !memcmp(frame + 10, pe->tx.memory + 0xe400 + macid * 8, 6))
			break;
	if (macid == 128) {
		mutex_unlock(&pe->uplink_lock);
		return;
	}
	pe->uplink_pending_tids[macid] |= BIT(tid);
	rcu_read_lock();
	{
		struct ieee80211_sta *sta;

		sta = ieee80211_find_sta_by_ifaddr(rtwdev->hw, frame + 10, NULL);
		if (!sta || !rtw89_pe_uplink_publish(pe, sta, pe->keys[macid], macid, tid))
			put_unaligned_le32(0, pe->uplink_states + (macid * 16 + tid) * 32);
	}
	rcu_read_unlock();
	mutex_unlock(&pe->uplink_lock);
}

static void rtw89_pe_rx_deliver(struct rtw89_pe *pe, unsigned int work)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	struct rtw89_rx_desc_info desc_info = {};
	struct rtw89_pe_rx_payload *payload;
	struct sk_buff *skb;
	u8 *buffer, *frame;
	u32 item;
	dma_addr_t dma;

	item = get_unaligned_le32(pe->rx.memory + RTL_AX_RX_WORK_IDS + work * 4);
	payload = &pe->payloads[item & ~RTL_AX_RX_WORK_OLD];
	dma = payload->dma;
	buffer = payload->data;
	rtw89_pe_uplink_sync(pe);
	dma_sync_single_for_cpu(pe->dma_device, dma, RTW89_PE_RX_BUFFER_BYTES, DMA_BIDIRECTIONAL);
	rtw89_core_query_rxdesc(rtwdev, &desc_info, buffer, 4);
	if (!desc_info.ready || desc_info.pkt_size > RTW89_PE_RX_BUFFER_BYTES) {
		pe->pe_rx_malformed++;
	} else {
		frame = buffer + desc_info.offset + desc_info.rxd_len;
		skb = dev_alloc_skb(desc_info.pkt_size);
		if (!skb) {
			pe->pe_rx_malformed++;
		} else {
			skb_put_data(skb, frame, desc_info.pkt_size);
			rtw89_core_rx(rtwdev, &desc_info, skb);
			rtw89_pe_uplink_seed(pe, frame, desc_info.pkt_size);
			pe->pe_rx_delivered++;
		}
	}
	dma_sync_single_for_device(pe->dma_device, dma, RTW89_PE_RX_BUFFER_BYTES, DMA_BIDIRECTIONAL);
	dma_wmb();
	put_unaligned_le32(BIT(30), pe->rx.memory + RTL_AX_RX_WORK_STATUS + work * 4);
}

static void rtw89_pe_rx_work_drain(struct rtw89_pe *pe)
{
	u8 *mailbox = rtw89_pe_rx_mailbox(pe);
	u32 consumer = get_unaligned_le32(mailbox + 380);
	u32 budget = 64;

	while (budget-- && consumer != get_unaligned_le32(mailbox + 376)) {
		u32 work;

		dma_rmb();
		work = get_unaligned_le32(pe->rx.memory + RTL_AX_RX_ARM_RING + consumer * 4);
		rtw89_pe_rx_deliver(pe, work);
		consumer = (consumer + 1) & 255;
		dma_wmb();
		put_unaligned_le32(consumer, mailbox + 380);
	}
}

static void rtw89_pe_tx_complete(struct rtw89_pe *pe, struct rtw89_pe_tx_slot *slot,
				 unsigned int status, bool polluted)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	struct ieee80211_tx_info *info;

	dma_unmap_single(rtwdev->dev, slot->dma, slot->bytes, DMA_TO_DEVICE);
	info = IEEE80211_SKB_CB(slot->skb);
	ieee80211_tx_info_clear_status(info);
	if (slot->firmware_rate)
		info->status.rates[0].idx = -1;
	if (!status && !polluted)
		info->flags |= info->flags & IEEE80211_TX_CTL_NO_ACK ?
			IEEE80211_TX_STAT_NOACK_TRANSMITTED : IEEE80211_TX_STAT_ACK;
	info->status.rates[0].count = 1;
	if (info->flags & IEEE80211_TX_CTL_AMPDU) {
		info->flags |= IEEE80211_TX_STAT_AMPDU;
		info->status.ampdu_len = 1;
		info->status.ampdu_ack_len = !!(info->flags & IEEE80211_TX_STAT_ACK);
	}
	ieee80211_tx_status_ni(rtwdev->hw, slot->skb);
}

static void rtw89_pe_tx_report(struct rtw89_pe *pe, u8 *buffer, unsigned int bytes)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	unsigned int offset;
	unsigned long flags;

	for (offset = 0; offset + 4 <= bytes; offset += 4) {
		u32 report = get_unaligned_le32(buffer + offset);
		unsigned int id = (report >> 16) & 0xfff;
		unsigned int status = (report >> 13) & 7;
		unsigned int qsel = (report >> 8) & 31;
		unsigned int ring = qsel < 8 ? qsel & 3 : qsel == 0x12 ? 4 : qsel == 0x11 ? 5 : 6;
		struct rtw89_pe_tx_slot slot;
		bool polluted = !!(report & BIT(31));

		if (id >= RTW89_PE_TX_ENTRIES || !test_bit(id, pe->tx_pending) ||
		    pe->tx_slots[id].ring != ring)
			continue;
		spin_lock_irqsave(&pe->lock, flags);
		slot = pe->tx_slots[id];
		pe->tx_slots[id].skb = NULL;
		if (slot.quota_counted && pe->ac_pending[slot.macid][ring])
			pe->ac_pending[slot.macid][ring]--;
		if (slot.quota_counted) {
			put_unaligned_le32(pe->ac_pending[slot.macid][ring],
					   pe->tx.memory + RTL_AX_TX_ARM_AC_PENDING +
					   (slot.macid * 4 + ring) * 4);
			dma_wmb();
		}
		__clear_bit(id, pe->tx_pending);
		if (pe->tx_occupied)
			pe->tx_occupied--;
		pe->tx_completed++;
		if (pe->tx_queues_stopped && pe->running && !pe->tx_paused &&
		    pe->tx_occupied <= RTW89_PE_TX_WAKE) {
			pe->tx_queues_stopped = false;
			ieee80211_wake_queues(rtwdev->hw);
		}
		spin_unlock_irqrestore(&pe->lock, flags);
		if (slot.pe_sequence)
			((struct ieee80211_hdr *)slot.skb->data)->seq_ctrl =
				get_unaligned((__le16 *)(pe->tx_headers + id * 128 + 22));
		rtw89_pe_tx_complete(pe, &slot, status, polluted);
		wake_up_all(&pe->wait);
	}
}

static void rtw89_pe_rx_forward_drain(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	struct rtw89_rx_desc_info desc_info = {};
	u8 *mailbox = rtw89_pe_tx_mailbox(pe);
	u32 consumer = get_unaligned_le32(mailbox + 296);
	u8 *buffer;
	u32 info, wd, written, bytes, offset, type;
	u32 budget = 64;

	while (budget-- && consumer != get_unaligned_le32(mailbox + 292)) {
		struct sk_buff *skb;
		bool old;

		dma_rmb();
		buffer = pe->pe_forward + consumer * RTW89_PE_RPQ_BUFFER_BYTES;
		info = get_unaligned_le32(buffer);
		wd = get_unaligned_le32(buffer + 4);
		written = info & 0x3fff;
		bytes = wd & 0x3fff;
		type = (wd >> 24) & 15;
		old = rtl_ax_rx_epoch_old(&pe->dfs_epoch[3], consumer);
		if (type == 8 && old)
			goto advance;
		if (type == 7) {
			offset = 4 + (wd & BIT(31) ? 32 : 16) + ((wd >> 14) & 3) * 2 +
				 ((wd >> 28) & 7) * 16;
			if ((wd & BIT(23)) && type != 1)
				offset += 4;
			if ((info & 0xc000) == 0xc000 && offset <= written &&
			    bytes <= written - offset)
				rtw89_pe_tx_report(pe, buffer + offset, bytes);
			goto advance;
		}
		if ((info & 0xc000) != 0xc000 || written > RTW89_PE_RPQ_BUFFER_BYTES) {
			pe->pe_rx_malformed++;
			goto advance;
		}
		rtw89_core_query_rxdesc(rtwdev, &desc_info, buffer, 4);
		if (!desc_info.ready || desc_info.pkt_size > RTW89_PE_RPQ_BUFFER_BYTES) {
			pe->pe_rx_malformed++;
			goto advance;
		}
		skb = dev_alloc_skb(desc_info.pkt_size);
		if (skb) {
			skb_put_data(skb, buffer + desc_info.offset + desc_info.rxd_len,
				     desc_info.pkt_size);
			rtw89_core_rx(rtwdev, &desc_info, skb);
			pe->pe_rx_delivered++;
		} else {
			pe->pe_rx_malformed++;
		}
advance:
		consumer = (consumer + 1) & 255;
		dma_mb();
		put_unaligned_le32(consumer, mailbox + 296);
	}
}

static void rtw89_pe_rdu_sync(struct rtw89_pe *pe)
{
	unsigned long flags;
	unsigned int i;

	spin_lock_irqsave(&pe->lock, flags);
	for (i = 0; i < 2; i++)
		pe->pe_rdu_seen[i] = get_unaligned_le32(pe->rx.memory + 0x2000 +
							(RTL_AX_RX_RDU + i) * 4);
	pe->pe_captured += get_unaligned_le32(pe->rx.memory + 0x2158);
	spin_unlock_irqrestore(&pe->lock, flags);
}

static void rtw89_pe_drain(struct rtw89_pe *pe)
{
	rtw89_pe_rx_forward_drain(pe);
	rtw89_pe_rx_work_drain(pe);
	rtw89_pe_uplink_sync(pe);
	rtw89_pe_rdu_sync(pe);
	rtw89_pe_rx_work_recycle(pe);
}

static void rtw89_pe_work(struct work_struct *work)
{
	struct rtw89_pe *pe = container_of(to_delayed_work(work), struct rtw89_pe, work);
	unsigned long flags;
	bool retry = false;

	if (!READ_ONCE(pe->running) || !pe->rx_owned)
		return;
	rtw89_pe_drain(pe);
	retry = get_unaligned_le32(pe->rx.memory + 0x2178) !=
		get_unaligned_le32(pe->rx.memory + 0x217c);
	retry |= get_unaligned_le32(pe->tx.memory + 0x2124) !=
		 get_unaligned_le32(pe->tx.memory + 0x2128);
	spin_lock_irqsave(&pe->lock, flags);
	if (pe->running) {
		rtw89_write32(pe->rtwdev, RTW89_PE_INDICATION_REG, RTW89_PE_IRQ_INDICATION);
		if (retry)
			mod_delayed_work(system_wq, &pe->work, 0);
	}
	spin_unlock_irqrestore(&pe->lock, flags);
}

static irqreturn_t rtw89_pe_event_interrupt(int irq, void *context)
{
	struct rtw89_pe *pe = context;
	unsigned long flags;

	spin_lock_irqsave(&pe->lock, flags);
	rtw89_pe_tx_write(pe, 264, rtw89_pe_tx_read(pe, 276));
	put_unaligned_le32(get_unaligned_le32(pe->rx.memory + 0x2114),
			   pe->rx.memory + 0x2108);
	rtw89_pe_wake(pe);
	spin_unlock_irqrestore(&pe->lock, flags);
	return IRQ_HANDLED;
}

static void __iomem *rtw89_pe_event_timer;
static unsigned int rtw89_pe_event_irq;
static bool rtw89_pe_event_ready;
static DEFINE_MUTEX(rtw89_pe_event_lock);

static void rtw89_pe_event_release(struct rtw89_pe *pe)
{
	mutex_lock(&rtw89_pe_event_lock);
	if (!rtw89_pe_event_ready)
		goto unlock;
	rtw89_pe_tx_write(pe, 256, 0);
	dma_wmb();
	synchronize_irq(rtw89_pe_event_irq);
	free_irq(rtw89_pe_event_irq, pe);
	writel(0, rtw89_pe_event_timer + 4);
	writel(0, rtw89_pe_event_timer + 12);
	writel(1, rtw89_pe_event_timer + 20);
	writel(0, rtw89_pe_event_timer);
	iounmap(rtw89_pe_event_timer);
	rtw89_pe_event_timer = NULL;
	rtw89_pe_event_ready = false;
unlock:
	mutex_unlock(&rtw89_pe_event_lock);
}

static int rtw89_pe_event_prepare(struct rtw89_pe *pe)
{
	struct device_node *node;
	struct irq_domain *domain;
	u32 saved[4];
	int ret = 0;

	mutex_lock(&rtw89_pe_event_lock);
	if (!rtw89_pe_event_timer) {
		node = of_find_node_by_path("/soc/interrupt-controller@f4329004");
		if (!node) {
			ret = -ENODEV;
			goto unlock;
		}
		domain = irq_find_host(node);
		of_node_put(node);
		if (!domain) {
			ret = -ENODEV;
			goto unlock;
		}
		rtw89_pe_event_irq = irq_create_mapping(domain, 5);
		if (!rtw89_pe_event_irq) {
			ret = -ENODEV;
			goto unlock;
		}
		rtw89_pe_event_timer = ioremap(0xf43290b0, 36);
		if (!rtw89_pe_event_timer) {
			ret = -ENOMEM;
			goto unlock;
		}
		saved[0] = readl(rtw89_pe_event_timer);
		saved[1] = readl(rtw89_pe_event_timer + 4);
		saved[2] = readl(rtw89_pe_event_timer + 12);
		saved[3] = readl(rtw89_pe_event_timer + 16);
		if (saved[1] || saved[2] || saved[3]) {
			iounmap(rtw89_pe_event_timer);
			rtw89_pe_event_timer = NULL;
			ret = -EBUSY;
			goto unlock;
		}
		ret = request_irq(rtw89_pe_event_irq, rtw89_pe_event_interrupt,
				  IRQF_NO_AUTOEN, "rtw89-pe-event", pe);
		if (ret) {
			iounmap(rtw89_pe_event_timer);
			rtw89_pe_event_timer = NULL;
			goto unlock;
		}
		writel(1, rtw89_pe_event_timer + 20);
		enable_irq(rtw89_pe_event_irq);
		rtw89_pe_event_ready = true;
	}
	rtw89_pe_tx_write(pe, 260, 0);
	rtw89_pe_tx_write(pe, 264, rtw89_pe_tx_read(pe, 268));
	rtw89_pe_tx_write(pe, 276, rtw89_pe_tx_read(pe, 268));
	rtw89_pe_tx_write(pe, 256, 0xb00290b0);
	dma_wmb();
unlock:
	mutex_unlock(&rtw89_pe_event_lock);
	return ret;
}

static struct device *rtw89_pe_ni_device(void)
{
	struct device *dev;

	dev = bus_find_device_by_name(&platform_bus_type, NULL, "rtl9617c-ni");
	if (IS_ERR_OR_NULL(dev))
		return NULL;
	return dev;
}

static int rtw89_pe_ni_prepare(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	struct rtl9617c_wifi_radio_info info = {};
	struct list_head *pos;
	int ret;

	if (!pe->ni_dev)
		return -ENODEV;
	ret = rtl9617c_ni_wifi_radio_attach(pe->ni_dev, pe->slot, &info);
	if (ret)
		return ret;
	pe->ni_cpu = info.cpu;
	pe->ni_eq = info.eq;
	pe->ni_active = true;
	rtw89_pe_tx_write(pe, 114, 0x7000 + pe->ni_cpu * 32);
	rtw89_pe_tx_write(pe, 115, 0x7100 + pe->ni_cpu * 32);
	rtw89_pe_tx_write(pe, 116, 0x6368 + pe->ni_cpu * 8);
	rtw89_pe_tx_write(pe, 117, pe->ni_eq);
	rtw89_pe_tx_write(pe, 167, info.epp_shift);
	rtw89_pe_tx_write(pe, 100, info.epp_base);
	rtw89_pe_tx_write(pe, 104, info.epp_cursor);
	for (u32 i = 0; i < 8; i++)
		put_unaligned_le32(info.epp_cursor, pe->tx.memory + 0x11c00 + i * 4);
	list_for_each(pos, &rtwdev->rtwvifs_list) {
		struct rtw89_vif *rtwvif = list_entry(pos, struct rtw89_vif, list);
		struct ieee80211_vif *vif = rtwvif_to_vif(rtwvif);
		int id;

		if (vif->type != NL80211_IFTYPE_AP || !vif->netdev)
			continue;
		id = rtl9617c_ni_wifi_id(pe->ni_dev, vif->netdev);
		if (id < 0)
			continue;
		pe->uplink_wifi_id = id;
		break;
	}
	return 0;
}

static void rtw89_pe_ni_release(struct rtw89_pe *pe)
{
	if (!pe->ni_active)
		return;
	rtl9617c_ni_wifi_radio_detach(pe->ni_dev, pe->slot);
	pe->ni_active = false;
	pe->uplink_wifi_id = 0;
}

static void rtw89_pe_route_peer(struct rtw89_pe *pe, unsigned int macid, bool add)
{
	unsigned int destination = add ? 16 + pe->ni_cpu : 0;

	if (!pe->route_dev || !pe->ni_dev || !macid || macid >= 128)
		return;
	rtl9617c_ni_wifi_peer_route(pe->ni_dev, pe->route_dev,
				    pe->tx.memory + 0xe400 + macid * 8, destination);
}

static int rtw89_pe_tx_pause(struct rtw89_pe *pe)
{
	u32 consumed, acknowledged, pe_command;
	int ret;

	if (!READ_ONCE(pe->tx_active))
		return 0;
	ret = read_poll_timeout(get_unaligned_le32, consumed,
				consumed == pe->tx_producer,
				10, 100000, false, pe->tx.memory + PE_PROBE_MAILBOX + 36);
	if (ret)
		return ret;
	pe_command = pe->tx_command + 2;
	put_unaligned_le32(pe_command, pe->tx.memory + PE_PROBE_MAILBOX + 12);
	dma_wmb();
	ret = read_poll_timeout(get_unaligned_le32, acknowledged,
				acknowledged == pe_command,
				10, 100000, false, pe->tx.memory + PE_PROBE_MAILBOX + 16);
	if (!ret)
		pe->tx_command = pe_command;
	return ret;
}

static void rtw89_pe_tx_open(struct rtw89_pe *pe)
{
	unsigned long flags;

	if (!READ_ONCE(pe->tx_active))
		return;
	spin_lock_irqsave(&pe->lock, flags);
	pe->tx_command += 2;
	put_unaligned_le32(pe->tx_command | 1, pe->tx.memory + PE_PROBE_MAILBOX + 12);
	dma_wmb();
	pe->tx_paused = false;
	if (pe->tx_queues_stopped && pe->tx_occupied <= RTW89_PE_TX_WAKE) {
		pe->tx_queues_stopped = false;
		ieee80211_wake_queues(pe->rtwdev->hw);
	}
	spin_unlock_irqrestore(&pe->lock, flags);
}

int rtw89_pe_pause(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	u32 acknowledged, command;
	unsigned long flags;
	int ret;

	if (!pe || !READ_ONCE(pe->attached))
		return 0;
	spin_lock_irqsave(&pe->lock, flags);
	pe->tx_paused = true;
	ieee80211_stop_queues(rtwdev->hw);
	spin_unlock_irqrestore(&pe->lock, flags);
	synchronize_net();
	ret = rtw89_pe_tx_pause(pe);
	if (ret)
		return ret;
	if (READ_ONCE(pe->rx_owned)) {
		command = pe->rx_command + 2;
		put_unaligned_le32(command, pe->rx.memory + 0x200c);
		dma_wmb();
		ret = read_poll_timeout(get_unaligned_le32, acknowledged,
					acknowledged == command,
					10, 100000, false, pe->rx.memory + 0x2010);
		if (ret)
			return ret;
		pe->rx_command = command;
	}
	spin_lock_irqsave(&pe->lock, flags);
	pe->scheduler_saved = rtw89_read32(rtwdev, RTW89_PE_TX_SCHED) & 0x3ffff;
	rtw89_write32_mask(rtwdev, RTW89_PE_TX_SCHED, 0x3ffff, 0);
	spin_unlock_irqrestore(&pe->lock, flags);
	return 0;
}

void rtw89_pe_open(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);

	if (!pe || !READ_ONCE(pe->attached))
		return;
	rtw89_write32_mask(rtwdev, RTW89_PE_TX_SCHED, 0x3ffff, pe->scheduler_saved | BIT(8));
	rtw89_pe_tx_open(pe);
	if (READ_ONCE(pe->rx_owned)) {
		pe->rx_command += 2;
		put_unaligned_le32(pe->rx_command | 1, pe->rx.memory + 0x200c);
		dma_wmb();
	}
}

static bool rtw89_pe_tx_slot_pending(struct rtw89_pe *pe, unsigned int macid,
				     unsigned int tid, unsigned int key, bool by_key)
{
	unsigned int id;
	bool pending = false;

	for_each_set_bit(id, pe->tx_pending, RTW89_PE_TX_ENTRIES) {
		if (by_key ? pe->tx_slots[id].encrypted &&
			     pe->tx_slots[id].key_index == key :
			     pe->tx_slots[id].macid == macid &&
			     (tid == IEEE80211_NUM_TIDS || pe->tx_slots[id].tid == tid)) {
			pending = true;
			break;
		}
	}
	return pending;
}

int rtw89_pe_flush_key(struct rtw89_dev *rtwdev, unsigned int index)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	int ret;

	if (!pe || !READ_ONCE(pe->tx_active))
		return 0;
	rtw89_pe_tx_write(pe, 78, rtw89_pe_tx_read(pe, 78) + 1);
	dma_wmb();
	ret = wait_event_timeout(pe->wait,
				 !rtw89_pe_tx_slot_pending(pe, 0, IEEE80211_NUM_TIDS,
							   index, true),
				 msecs_to_jiffies(1000)) ? 0 : -ETIMEDOUT;
	rtw89_pe_tx_write(pe, 78, rtw89_pe_tx_read(pe, 78) - 1);
	return ret;
}

int rtw89_pe_wait_station(struct rtw89_dev *rtwdev, unsigned int macid, unsigned int tid)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	int ret;

	if (!pe || !READ_ONCE(pe->tx_active))
		return 0;
	rtw89_pe_tx_write(pe, 78, rtw89_pe_tx_read(pe, 78) + 1);
	dma_wmb();
	ret = wait_event_timeout(pe->wait,
				 !rtw89_pe_tx_slot_pending(pe, macid, tid, 0, false),
				 msecs_to_jiffies(1000)) ? 0 : -ETIMEDOUT;
	rtw89_pe_tx_write(pe, 78, rtw89_pe_tx_read(pe, 78) - 1);
	return ret;
}

static void rtw89_pe_tx_slots_release(struct rtw89_pe *pe)
{
	struct rtw89_dev *rtwdev = pe->rtwdev;
	unsigned int id;

	for (id = 0; id < RTW89_PE_TX_ENTRIES; id++) {
		if (!pe->tx_slots[id].skb)
			continue;
		dma_unmap_single(rtwdev->dev, pe->tx_slots[id].dma,
				 pe->tx_slots[id].bytes, DMA_TO_DEVICE);
		ieee80211_free_txskb(rtwdev->hw, pe->tx_slots[id].skb);
		pe->tx_slots[id].skb = NULL;
	}
}

static int rtw89_pe_rx_context_stop(struct rtw89_pe *pe)
{
	u8 *mailbox = rtw89_pe_rx_mailbox(pe);
	u8 *tx_mailbox = rtw89_pe_tx_mailbox(pe);
	unsigned long flags;
	unsigned int i;

	if (!pe->rx_owned)
		return 0;
	cancel_delayed_work_sync(&pe->work);
	do {
		rtw89_pe_rx_forward_drain(pe);
	} while (get_unaligned_le32(tx_mailbox + 296) != get_unaligned_le32(tx_mailbox + 292));
	do {
		rtw89_pe_rx_work_drain(pe);
	} while (get_unaligned_le32(mailbox + 380) != get_unaligned_le32(mailbox + 376));
	rtw89_pe_uplink_sync(pe);
	rtw89_pe_rx_work_recycle(pe);
	for (i = 0; i < RTW89_PE_RX_ENTRIES; i++)
		pe->rx_slot_ids[i] = get_unaligned_le32(pe->rx.memory +
							RTL_AX_RX_SLOT_MAP + i * 4);
	pe->rx_consumer = get_unaligned_le32(mailbox + 324);
	pe->rx_tag = get_unaligned_le32(mailbox + 328);
	dma_wmb();
	rtw89_write16(pe->rtwdev, R_AX_RXQ_RXBD_IDX_V1, pe->rx_consumer);
	dma_sync_single_for_cpu(pe->dma_device, pe->rpq_buffers_dma, RTW89_PE_FORWARD_BYTES,
				DMA_BIDIRECTIONAL);
	put_unaligned_le32(0, tx_mailbox + 272);
	put_unaligned_le32(0, tx_mailbox + RTL_AX_RX_EVENT_CONTEXT * 4);
	put_unaligned_le32(0, mailbox + 320);
	dma_wmb();
	for (i = 0; i < 2; i++)
		pe->dfs_epoch[i] = get_unaligned_le32((i ? tx_mailbox : mailbox) +
						      (RTL_AX_PE_DFS_EPOCH + i) * 4);
	spin_lock_irqsave(&pe->lock, flags);
	pe->rx_owned = false;
	spin_unlock_irqrestore(&pe->lock, flags);
	return 0;
}

static int rtw89_pe_tx_context_release(struct rtw89_pe *pe)
{
	int ret;

	ret = rtw89_pe_tx_pause(pe);
	if (ret)
		return ret;
	rtw89_pe_rx_context_stop(pe);
	rtw89_pe_tx_slots_release(pe);
	if (pe->tx.memory) {
		ret = pe_probe_stop(&pe->tx);
		if (ret)
			return ret;
	}
	return 0;
}

static void rtw89_pe_peer_tables_clear(struct rtw89_pe *pe, unsigned int macid)
{
	memset(pe->tx.memory + 0x10000 + macid * 8 * 4, 0, 8 * 4);
	memset(pe->tx.memory + 0xd000 + macid * 32, 0, 32);
	memset(pe->tx.memory + 0x12000 + macid * 8 * 4, 0, 8 * 4);
	memset(pe->tx.memory + 0xe400 + macid * 8, 0, 8);
	memset(pe->tx.memory + 0xe800 + macid * 16, 0, 16);
	memset(pe->tx.memory + RTL_AX_NI_PS_CANCEL + macid * 8, 0, 8);
	memset(pe->tx.memory + RTL_AX_NI_PS_DONE + macid * 8, 0, 8);
	put_unaligned_le32(0, pe->tx.memory + RTL_AX_NI_PS_VERSION + macid * 4);
	put_unaligned_le32(0, pe->tx.memory + RTL_AX_NI_PS_TIMEOUT + macid * 4);
	memset(pe->tx.memory + 0x18000 + macid * 32, 0, 32);
	put_unaligned_le32(0, pe->tx.memory + 0xe200 + macid * 4);
	memset(pe->tx.memory + RTL_AX_TX_PEER_FLOWS + macid * 256, 0, 256);
	memset(pe->tx.memory + RTL_AX_TX_AMSDU_QUEUES + macid * 128, 0, 128);
	put_unaligned_le32(0, pe->tx.memory + 0x11a00 + macid * 4);
	memset(pe->ac_pending[macid], 0, sizeof(pe->ac_pending[macid]));
	pe->peer_qos[macid] = false;
	pe->peer_client[macid] = false;
	pe->peer_asleep[macid] = false;
	pe->peer_authorized[macid] = false;
	pe->peer_preload[macid] = false;
	pe->peer_offloaded[macid] = false;
	pe->peer_rates[macid] = 0;
	pe->peer_bw[macid] = 0;
	dma_wmb();
}

static void rtw89_pe_traffic_work(struct wiphy *wiphy, struct wiphy_delayed_work *work)
{
	struct rtw89_pe *pe = container_of(work, struct rtw89_pe, traffic_work);
	struct rtw89_dev *rtwdev = pe->rtwdev;
	unsigned int macid;
	u32 ac[4] = {};
	u8 streams = 0;
	u32 quota;

	if (!READ_ONCE(pe->tx_active))
		return;
	for (macid = 1; macid < 128; macid++) {
		struct ieee80211_sta *sta;
		u32 policy;

		if (!(get_unaligned_le32(pe->tx.memory + 0xd000 + macid * 32 + 16) & BIT(16)))
			continue;
		for (unsigned int tid = 0; tid < 8; tid++)
			ac[rtw89_pe_tid_ac[tid]] += get_unaligned_le32(pe->tx.memory +
				RTL_AX_NI_TX_ACTIVITY + (macid * 8 + tid) * 4);
		rcu_read_lock();
		sta = ieee80211_find_sta_by_ifaddr(rtwdev->hw,
						   pe->tx.memory + 0xe400 + macid * 8, NULL);
		if (sta && sta->cur && sta->cur->max_amsdu_len) {
			u32 bytes = min_t(u32, sta->cur->max_amsdu_len, 10896);
			u8 num = sta->max_amsdu_subframes;

			policy = rtl_ax_amsdu_queue_policy(bytes, num, 0, 0, 0, 0);
			put_unaligned_le32(policy, pe->tx.memory + RTL_AX_TX_PEER_AMSDU + macid * 4);
			dma_wmb();
		}
		rcu_read_unlock();
	}
	for (unsigned int i = 0; i < 4; i++) {
		if ((u32)(ac[i] - pe->ac_seen[i]) > 500) {
			streams++;
			pe->ac_seen[i] = ac[i];
		}
	}
	if (streams > 1) {
		pe->wmm_streams = max(pe->wmm_streams, streams);
		quota = (pe->slot ? 1024 : 2048) / max(pe->wmm_streams, 1U);
	} else if (!streams) {
		pe->wmm_streams = 1;
		quota = 0;
	} else {
		quota = pe->wmm_streams > 1 ?
			(pe->slot ? 1024 : 2048) / pe->wmm_streams : 0;
	}
	spin_lock_bh(&pe->lock);
	pe->wmm_quota = quota;
	spin_unlock_bh(&pe->lock);
	put_unaligned_le32(quota, pe->tx.memory + RTL_AX_TX_WMM_QUOTA);
	dma_wmb();
	wiphy_delayed_work_queue(wiphy, &pe->traffic_work, 2 * HZ);
}

int rtw89_pe_tx_request(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx_req->skb);
	struct ieee80211_hdr *header = (void *)tx_req->skb->data;
	struct rtw89_tx_desc_info *desc_info = &tx_req->desc_info;
	struct rtw89_pe_tx_slot *slot;
	u32 request[8 + RTL_AX_TX_WP_ADDRESS_MAX * 2] = {};
	u32 packet_bytes, header_bytes;
	unsigned int id, next, ring, tid = 0, macid;
	unsigned long flags;
	bool encap, pe_sequence, data_frame;
	bool template_ready = false;
	u8 original_header[36];
	unsigned int original_header_bytes;
	dma_addr_t dma;
	u32 request_flags, key = 0;
	int ret;

	if (!READ_ONCE(pe->tx_active))
		return -EOPNOTSUPP;
	macid = desc_info->mac_id;
	encap = !!(info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP);
	data_frame = encap || ieee80211_is_data_present(header->frame_control);
	pe_sequence = !encap && macid && ieee80211_is_data_qos(header->frame_control) &&
		      ieee80211_is_data_present(header->frame_control) &&
		      !ieee80211_has_morefrags(header->frame_control) &&
		      !(le16_to_cpu(header->seq_ctrl) & 15);
	header_bytes = encap ? (pe->peer_qos[macid] ? 26 : 24) :
		       ieee80211_hdrlen(header->frame_control);
	packet_bytes = encap ? tx_req->skb->len + header_bytes + 8 - 14 : tx_req->skb->len;
	original_header_bytes = encap ? ETH_HLEN : pe_sequence ? header_bytes : 0;
	if (packet_bytes > 0x3fff)
		return -EMSGSIZE;
	if (desc_info->ch_dma < RTW89_TXCH_ACH4) {
		ring = desc_info->ch_dma;
		if (!encap && ieee80211_is_data_qos(header->frame_control))
			tid = *ieee80211_get_qos_ctl(header) & 7;
	} else if (desc_info->ch_dma == RTW89_TXCH_CH8) {
		ring = 4;
	} else if (desc_info->ch_dma == RTW89_TXCH_CH9) {
		ring = 5;
	} else {
		return -EOPNOTSUPP;
	}
	if (skb_is_nonlinear(tx_req->skb) && skb_linearize(tx_req->skb))
		return -ENOMEM;
	if (DIV_ROUND_UP(tx_req->skb->len, RTL_AX_TX_WP_FRAGMENT_BYTES) >
	    RTL_AX_TX_WP_ADDRESS_MAX - (encap || pe_sequence))
		return -EMSGSIZE;
	if (original_header_bytes)
		memcpy(original_header, tx_req->skb->data, original_header_bytes);
	dma = dma_map_single(rtwdev->dev, tx_req->skb->data, tx_req->skb->len, DMA_TO_DEVICE);
	if (dma_mapping_error(rtwdev->dev, dma))
		return -ENOMEM;
	spin_lock_irqsave(&pe->lock, flags);
	if (!READ_ONCE(pe->running)) {
		ret = -ENETDOWN;
		goto unmap;
	}
	if (macid && data_frame && ring < 4 && pe->wmm_quota &&
	    pe->ac_pending[macid][ring] + get_unaligned_le32(pe->tx.memory +
	    RTL_AX_TX_NI_AC_PENDING + (macid * 4 + ring) * 4) >= pe->wmm_quota) {
		ret = -ENOSPC;
		goto unmap;
	}
	id = find_first_zero_bit(pe->tx_pending, RTW89_PE_TX_ENTRIES);
	next = (pe->tx_producer_ring[ring] + 1) & (RTW89_PE_TX_ENTRIES - 1);
	if (id == RTW89_PE_TX_ENTRIES) {
		pe->tx_full++;
		ret = -ENOSPC;
		goto unmap;
	}
	request_flags = (encap ? tid : ieee80211_is_ctl(header->frame_control) ? 0 :
			 le16_to_cpu(header->seq_ctrl) >> 4) |
			rtw89_pe_tid_indicators[tid] << 12 |
			!!(info->flags & IEEE80211_TX_CTL_NO_ACK) << 13 |
			(encap && pe->peer_client[macid] ? 0 :
			 is_multicast_ether_addr(encap ? tx_req->skb->data : header->addr1)) << 14 |
			pe->checksum_enabled << 17 | macid << 24 | encap << 18 |
			pe->peer_client[macid] << 23;
	if (pe_sequence)
		request_flags = (request_flags & ~0xfffU) | tid | BIT(22);
	if (info->control.hw_key) {
		key = info->control.hw_key->hw_key_idx << 16 |
		      info->control.hw_key->keyidx << 24;
		request_flags |= BIT(16);
	}
	request[0] = id;
	request[1] = ring | pe->tx_producer_ring[ring] << 8 | next << 16;
	request[2] = packet_bytes | header_bytes << 16 | 1U << 24;
	request[3] = desc_info->data_rate & 0x1ff;
	request[3] |= (u32)pe->peer_bw[macid] << 16;
	if (encap)
		request[3] |= pe->peer_rates[macid] & (BIT(21) | BIT(22));
	if (encap && (get_unaligned_le32(pe->tx.memory + 0xe200 + macid * 4) & BIT(17)))
		request[3] |= BIT(20);
	if (!encap && macid && READ_ONCE(pe->peer_authorized[macid]) &&
	    !(info->flags & (IEEE80211_TX_CTL_INJECTED | IEEE80211_TX_CTL_RATE_CTRL_PROBE |
	     IEEE80211_TX_CTL_USE_MINRATE | IEEE80211_TX_CTL_TX_OFFCHAN)) &&
	    !(info->control.flags & (IEEE80211_TX_CTRL_RATE_INJECT |
	     IEEE80211_TX_CTRL_PORT_CTRL_PROTO | IEEE80211_TX_CTRL_DONT_USE_RATE_MASK)) &&
	    data_frame && !is_multicast_ether_addr(header->addr1) &&
	    (get_unaligned_le32(pe->tx.memory + 0xe200 + macid * 4) & BIT(17)))
		request[3] = (pe->peer_rates[macid] & ~BIT(31)) | BIT(20);
	if (original_header_bytes)
		memcpy(pe->tx_headers + id * 128, original_header, original_header_bytes);
	request[4] = request_flags;
	request[5] = (desc_info->agg_en ? desc_info->ampdu_num : 0) |
		     desc_info->ampdu_density << 8 | key |
		     (pe->peer_preload[macid] ? RTL_AX_TX_AGG_PRELOAD : 0);
	request[8] = lower_32_bits(dma);
	request[9] = tx_req->skb->len;
	if (encap) {
		memcpy(pe->tx.memory + 0xd000 + macid * 32, request, 32);
		if (pe->peer_rates[macid] & BIT(31))
			put_unaligned_le32(pe->peer_rates[macid] & ~BIT(31),
					   pe->tx.memory + 0xd000 + macid * 32 + 12);
		if (!pe->peer_client[macid])
			memcpy(pe->tx.memory + 0xe400 + macid * 8, tx_req->skb->data, 6);
	}
	if (!encap && !tid && pe_sequence && (request_flags & BIT(16)) &&
	    READ_ONCE(pe->peer_authorized[macid]) && info->control.vif &&
	    info->control.vif->type == NL80211_IFTYPE_AP &&
	    ieee80211_has_fromds(header->frame_control) &&
	    !ieee80211_has_tods(header->frame_control) &&
	    !(info->flags & (IEEE80211_TX_CTL_NO_ACK | IEEE80211_TX_CTL_NO_PS_BUFFER)) &&
	    !(info->control.flags & IEEE80211_TX_CTRL_PS_RESPONSE)) {
		u32 peer[8] = { 0, 0, 26U << 16,
			pe->peer_rates[macid] & ~BIT(31),
			macid << 24 | BIT(18) | BIT(16) | pe->checksum_enabled << 17 |
			pe->peer_client[macid] << 23,
			(desc_info->agg_en ? desc_info->ampdu_num : 0) |
			desc_info->ampdu_density << 8 | key |
			(pe->peer_preload[macid] ? RTL_AX_TX_AGG_PRELOAD : 0), 0, 0 };

		memcpy(pe->tx.memory + 0xd000 + macid * 32, peer, sizeof(peer));
		memcpy(pe->tx.memory + 0xe400 + macid * 8, header->addr1, ETH_ALEN);
		template_ready = true;
	}
	memcpy(pe->tx.memory + 0x4000 + pe->tx_producer * 128, request,
	       (8 + 2) * sizeof(*request));
	slot = &pe->tx_slots[id];
	slot->skb = tx_req->skb;
	slot->dma = dma;
	slot->bytes = tx_req->skb->len;
	slot->id = id;
	slot->ring = ring;
	slot->pe_sequence = pe_sequence;
	slot->macid = macid;
	slot->tid = encap ? tid : ieee80211_is_data_qos(header->frame_control) ?
		    tid : IEEE80211_NUM_TIDS;
	slot->encrypted = !!info->control.hw_key;
	slot->key_index = info->control.hw_key ? info->control.hw_key->hw_key_idx : 0;
	slot->firmware_rate = !!(request[3] & BIT(20));
	slot->quota_counted = macid && data_frame && ring < 4;
	if (slot->quota_counted) {
		pe->ac_pending[macid][ring]++;
		put_unaligned_le32(pe->ac_pending[macid][ring],
				   pe->tx.memory + RTL_AX_TX_ARM_AC_PENDING +
				   (macid * 4 + ring) * 4);
	}
	__set_bit(id, pe->tx_pending);
	pe->tx_occupied++;
	pe->tx_producer_ring[ring] = next;
	pe->tx_submitted++;
	dma_wmb();
	pe->tx_producer = (pe->tx_producer + 1) & 255;
	put_unaligned_le32(pe->tx_producer, pe->tx.memory + PE_PROBE_MAILBOX + 32);
	dma_wmb();
	if (pe->tx_occupied >= RTW89_PE_TX_STOP && !pe->tx_queues_stopped) {
		pe->tx_queues_stopped = true;
		ieee80211_stop_queues(rtwdev->hw);
	}
	spin_unlock_irqrestore(&pe->lock, flags);
	if (template_ready && !READ_ONCE(pe->peer_offloaded[macid]))
		WRITE_ONCE(pe->peer_offloaded[macid], true);
	return 0;
unmap:
	spin_unlock_irqrestore(&pe->lock, flags);
	dma_unmap_single(rtwdev->dev, dma, tx_req->skb->len, DMA_TO_DEVICE);
	return ret;
}

int rtw89_pe_rx_poll(struct rtw89_dev *rtwdev, int budget)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	unsigned long flags;
	u64 delivered;

	if (!pe || !READ_ONCE(pe->attached) || !pe->rx_owned)
		return 0;
	delivered = READ_ONCE(pe->pe_rx_delivered);
	rtw89_pe_drain(pe);
	delivered = READ_ONCE(pe->pe_rx_delivered) - delivered;
	spin_lock_irqsave(&pe->lock, flags);
	if (pe->tx_queues_stopped && pe->running && !pe->tx_paused &&
	    pe->tx_occupied <= RTW89_PE_TX_WAKE) {
		pe->tx_queues_stopped = false;
		ieee80211_wake_queues(rtwdev->hw);
	}
	spin_unlock_irqrestore(&pe->lock, flags);
	return min_t(int, delivered, budget);
}

void rtw89_pe_rx_intr_mask(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;

	if (!pe || !READ_ONCE(pe->tx_active))
		return;
	rtwpci->intrs[0] &= ~(B_AX_RXDMA_INT_EN | B_AX_RXP1DMA_INT_EN |
			      B_AX_RPQDMA_INT_EN | B_AX_RXDMA_STUCK_INT_EN |
			      B_AX_RDU_INT_EN | B_AX_RPQBD_FULL_INT_EN);
}

void rtw89_pe_rate_report(struct rtw89_dev *rtwdev, u8 macid, const struct rtw89_ra_report *report)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct ieee80211_sta *sta;
	u32 rate, caps;
	unsigned long flags;

	if (!pe || !READ_ONCE(pe->tx_active) || !macid || macid >= 128)
		return;
	if (report->txrate.flags & RATE_INFO_FLAGS_EHT_MCS)
		return;
	rate = report->hw_rate & 0x1ff;
	switch (report->txrate.bw) {
	case RATE_INFO_BW_40:
		pe->peer_bw[macid] = 1;
		break;
	case RATE_INFO_BW_80:
		pe->peer_bw[macid] = 2;
		break;
	case RATE_INFO_BW_160:
		pe->peer_bw[macid] = 3;
		break;
	default:
		pe->peer_bw[macid] = 0;
		break;
	}
	rate |= (u32)pe->peer_bw[macid] << 16;
	rcu_read_lock();
	sta = ieee80211_find_sta_by_ifaddr(rtwdev->hw, pe->tx.memory + 0xe400 + macid * 8, NULL);
	if (!sta) {
		rcu_read_unlock();
		return;
	}
	if (report->txrate.flags & RATE_INFO_FLAGS_HE_MCS) {
		if (sta->deflink.he_cap.he_cap_elem.phy_cap_info[1] &
		    IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD)
			rate |= BIT(21);
	} else if (report->txrate.flags & RATE_INFO_FLAGS_VHT_MCS) {
		if (sta->deflink.vht_cap.cap & IEEE80211_VHT_CAP_RXLDPC)
			rate |= BIT(21);
	} else if (report->txrate.flags & RATE_INFO_FLAGS_MCS) {
		if (sta->deflink.ht_cap.cap & IEEE80211_HT_CAP_LDPC_CODING)
			rate |= BIT(21);
	}
	if (sta->deflink.smps_mode == IEEE80211_SMPS_DYNAMIC)
		rate |= BIT(22);
	caps = BIT(17) | min_t(unsigned int, sta->cur->max_amsdu_len,
	       sta->deflink.he_cap.has_he && sta->cur->max_amsdu_len >= 11454 ? 10896 :
	       sta->cur->max_amsdu_len >= 7935 ? 7433 : 3793) << 18;
	if (report->txrate.flags & RATE_INFO_FLAGS_VHT_MCS ||
	    report->txrate.flags & RATE_INFO_FLAGS_MCS) {
		caps |= sta->deflink.ht_cap.mcs.rx_mask[0] |
			(u32)sta->deflink.ht_cap.mcs.rx_mask[1] << 8;
		if (report->txrate.flags & RATE_INFO_FLAGS_SHORT_GI)
			caps |= BIT(16);
	}
	rcu_read_unlock();
	spin_lock_irqsave(&pe->lock, flags);
	pe->peer_rates[macid] = rate | BIT(31);
	put_unaligned_le32(rate, pe->tx.memory + 0xd000 + macid * 32 + 12);
	put_unaligned_le32(caps, pe->tx.memory + 0xe200 + macid * 4);
	dma_wmb();
	spin_unlock_irqrestore(&pe->lock, flags);
}

void rtw89_pe_ba_session(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
			 struct ieee80211_sta *sta, struct ieee80211_ampdu_params *params)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	unsigned int macid = rtw89_sta_get_main_macid(sta_to_rtwsta(sta));
	unsigned int tid = params->tid;

	if (!pe || !READ_ONCE(pe->tx_active) || !macid || macid >= 128)
		return;
	switch (params->action) {
	case IEEE80211_AMPDU_RX_START:
		mutex_lock(&pe->uplink_lock);
		if (pe->uplink_states)
			put_unaligned_le32(params->buf_size,
					   pe->uplink_states + (macid * 16 + tid) * 32 + 28);
		dma_wmb();
		mutex_unlock(&pe->uplink_lock);
		break;
	case IEEE80211_AMPDU_RX_STOP:
		mutex_lock(&pe->uplink_lock);
		if (pe->uplink_states)
			put_unaligned_le32(0,
					   pe->uplink_states + (macid * 16 + tid) * 32 + 28);
		dma_wmb();
		mutex_unlock(&pe->uplink_lock);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		put_unaligned_le32(params->buf_size,
				   pe->tx.memory + 0x12000 + (macid * 8 + tid) * 4);
		dma_wmb();
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		put_unaligned_le32(0, pe->tx.memory + 0x12000 + (macid * 8 + tid) * 4);
		dma_wmb();
		break;
	default:
		break;
	}
}

void rtw89_pe_key(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
		  struct ieee80211_sta *sta, struct ieee80211_key_conf *key, bool added)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	unsigned int macid = 0;
	unsigned int tid;

	if (!pe || !READ_ONCE(pe->tx_active))
		return;
	if (sta)
		macid = rtw89_sta_get_main_macid(sta_to_rtwsta(sta));
	else if (vif)
		macid = rtw89_vif_get_main_macid(vif_to_rtwvif(vif));
	if (!macid || macid >= 128)
		return;
	mutex_lock(&pe->uplink_lock);
	if (pe->uplink_states) {
		put_unaligned_le32(0, pe->uplink_states + 0x10000 + macid * 4);
		dma_wmb();
	}
	pe->keys[macid] = added ? key : NULL;
	pe->uplink_pending_tids[macid] = 0;
	if (added && pe->uplink_states && pe->uplink_wifi_id) {
		for (tid = 0; tid < 16; tid++)
			memset(pe->uplink_states + (macid * 16 + tid) * 32, 0, 28);
		memset(pe->uplink_seen[macid], 0, sizeof(pe->uplink_seen[macid]));
	}
	mutex_unlock(&pe->uplink_lock);
}

void rtw89_pe_sta_add(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct rtw89_sta *rtwsta = sta_to_rtwsta(sta);
	unsigned int macid = rtw89_sta_get_main_macid(rtwsta);

	if (!pe || !READ_ONCE(pe->tx_active) || !macid || macid >= 128)
		return;
	rtw89_pe_peer_tables_clear(pe, macid);
	put_unaligned_le32(26U << 16, pe->tx.memory + 0xd000 + macid * 32 + 8);
	memcpy(pe->tx.memory + 0xe400 + macid * 8, sta->addr, ETH_ALEN);
	put_unaligned_le32(macid << 24 | BIT(18) | BIT(16),
			   pe->tx.memory + 0xd000 + macid * 32 + 16);
	dma_wmb();
}

void rtw89_pe_sta_remove(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
			 struct ieee80211_sta *sta)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct rtw89_sta *rtwsta = sta_to_rtwsta(sta);
	unsigned int macid = rtw89_sta_get_main_macid(rtwsta);

	if (!pe || !READ_ONCE(pe->tx_active) || !macid || macid >= 128)
		return;
	rtw89_pe_route_peer(pe, macid, false);
	rtw89_pe_peer_tables_clear(pe, macid);
	mutex_lock(&pe->uplink_lock);
	if (pe->uplink_states)
		put_unaligned_le32(0, pe->uplink_states + 0x10000 + macid * 4);
	pe->keys[macid] = NULL;
	dma_wmb();
	mutex_unlock(&pe->uplink_lock);
}

void rtw89_pe_sta_assoc(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
			struct ieee80211_sta *sta, bool associated)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct rtw89_sta *rtwsta = sta_to_rtwsta(sta);
	unsigned int macid = rtw89_sta_get_main_macid(rtwsta);

	if (!pe || !READ_ONCE(pe->tx_active) || !macid || macid >= 128)
		return;
	WRITE_ONCE(pe->peer_authorized[macid], associated);
	if (associated) {
		if (!pe->route_dev && vif->netdev) {
			dev_hold(vif->netdev);
			pe->route_dev = vif->netdev;
		}
		if (pe->uplink_wifi_id) {
			put_unaligned_le32(1, pe->tx.memory + 0x11a00 + macid * 4);
			dma_wmb();
			rtw89_pe_route_peer(pe, macid, true);
		}
	} else {
		put_unaligned_le32(0, pe->tx.memory + 0x11a00 + macid * 4);
		dma_wmb();
		rtw89_pe_route_peer(pe, macid, false);
	}
}

void rtw89_pe_ap_address(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);

	if (!pe || !READ_ONCE(pe->tx_active))
		return;
	memcpy(pe->tx.memory + PE_PROBE_MAILBOX + 64, vif->addr, 6);
	dma_wmb();
}

int rtw89_pe_init(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe;
	int ret;

	if (!rtw89_pe_enable)
		return -EOPNOTSUPP;
	pe = kzalloc(sizeof(*pe), GFP_KERNEL);
	if (!pe)
		return -ENOMEM;
	pe->rtwdev = rtwdev;
	pe->slot = rtwdev->chip->chip_id == RTL8852C ? 0 : 1;
	spin_lock_init(&pe->lock);
	mutex_init(&pe->uplink_lock);
	init_waitqueue_head(&pe->wait);
	INIT_DELAYED_WORK(&pe->work, rtw89_pe_work);
	wiphy_delayed_work_init(&pe->traffic_work, rtw89_pe_traffic_work);
	rtwdev->pe = pe;
	pe->ni_dev = rtw89_pe_ni_device();
	ret = pe_probe_alloc(&pe->tx, pe->slot, 1);
	if (ret)
		goto err;
	pe->dma_device = &pe->tx.device->dev;
	ret = pe_probe_alloc(&pe->rx, pe->slot, 0);
	if (ret)
		goto err;
	return 0;
err:
	rtw89_pe_exit(rtwdev);
	return ret;
}

void rtw89_pe_exit(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);

	if (!pe)
		return;
	rtwdev->pe = NULL;
	if (pe->dma_device) {
		rtw89_pe_tx_dma_free(pe);
		rtw89_pe_rx_buffers_free(pe);
	}
	pe_probe_free(&pe->tx);
	pe_probe_free(&pe->rx);
	if (pe->ni_dev)
		put_device(pe->ni_dev);
	kfree(pe);
}

int rtw89_pe_attach(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	unsigned long flags;
	int ret;

	if (!pe || READ_ONCE(pe->attached))
		return pe ? 0 : -ENODEV;
	ret = rtw89_pe_tx_dma_alloc(pe);
	if (ret)
		goto err;
	ret = rtw89_pe_rx_buffers_alloc(pe);
	if (ret)
		goto err;
	pe->pe_forward = dma_alloc_coherent(pe->dma_device, RTW89_PE_FORWARD_BYTES,
					    &pe->pe_forward_dma, GFP_KERNEL);
	if (!pe->pe_forward) {
		ret = -ENOMEM;
		goto err;
	}
	pe->uplink_states = dma_alloc_coherent(pe->dma_device, SZ_128K,
					       &pe->uplink_states_dma, GFP_KERNEL);
	if (!pe->uplink_states) {
		ret = -ENOMEM;
		goto err;
	}
	memset(pe->uplink_states, 0, SZ_128K);
	rtw89_pe_ni_prepare(pe);
	rtw89_pe_dma_pause(pe);
	ret = rtw89_pe_tx_hw_configure(pe);
	if (ret)
		goto err;
	ret = rtw89_pe_rx_configure(pe);
	if (ret)
		goto err;
	ret = rtw89_pe_tx_context_start(pe);
	if (ret)
		goto err;
	ret = rtw89_pe_event_prepare(pe);
	if (ret)
		goto err;
	ret = rtw89_pe_rx_context_start(pe);
	if (ret)
		goto err;
	spin_lock_irqsave(&rtwpci->irq_lock, flags);
	rtw89_chip_config_intr_mask(rtwdev, RTW89_PCI_INTR_MASK_NORMAL);
	rtw89_chip_enable_intr(rtwdev, rtwpci);
	spin_unlock_irqrestore(&rtwpci->irq_lock, flags);
	pe->running = true;
	WRITE_ONCE(pe->attached, true);
	rtw89_pe_tx_open(pe);
	rtw89_pe_wake(pe);
	wiphy_delayed_work_queue(rtwdev->hw->wiphy, &pe->traffic_work, 2 * HZ);
	return 0;
err:
	rtw89_pe_detach(rtwdev);
	return ret;
}

void rtw89_pe_detach(struct rtw89_dev *rtwdev)
{
	struct rtw89_pe *pe = rtw89_pe_of(rtwdev);
	struct rtw89_pci *rtwpci = (struct rtw89_pci *)rtwdev->priv;
	unsigned long flags;
	unsigned int macid;
	int ret;

	if (!pe || !READ_ONCE(pe->attached))
		return;
	WRITE_ONCE(pe->attached, false);
	spin_lock_irqsave(&pe->lock, flags);
	pe->running = false;
	spin_unlock_irqrestore(&pe->lock, flags);
	wiphy_delayed_work_cancel(rtwdev->hw->wiphy, &pe->traffic_work);
	ret = rtw89_pe_tx_context_release(pe);
	if (ret)
		return;
	rtw89_pe_event_release(pe);
	for (macid = 1; macid < 128; macid++)
		if (pe->peer_authorized[macid] ||
		    get_unaligned_le32(pe->tx.memory + 0x11a00 + macid * 4))
			rtw89_pe_route_peer(pe, macid, false);
	if (pe->route_dev) {
		dev_put(pe->route_dev);
		pe->route_dev = NULL;
	}
	rtw89_pe_ni_release(pe);
	rtw89_pe_tx_dma_free(pe);
	rtw89_pe_rx_buffers_free(pe);
	if (pe->pe_forward) {
		dma_free_coherent(pe->dma_device, RTW89_PE_FORWARD_BYTES,
				  pe->pe_forward, pe->pe_forward_dma);
		pe->pe_forward = NULL;
	}
	if (pe->uplink_states) {
		dma_free_coherent(pe->dma_device, SZ_128K,
				  pe->uplink_states, pe->uplink_states_dma);
		pe->uplink_states = NULL;
	}
	pe->pool_initialized = false;
	pe->tx_producer = 0;
	pe->tx_occupied = 0;
	pe->tx_paused = false;
	pe->tx_queues_stopped = false;
	bitmap_zero(pe->tx_pending, RTW89_PE_TX_ENTRIES);
	memset(pe->tx_producer_ring, 0, sizeof(pe->tx_producer_ring));
	memset(pe->tx_slots, 0, sizeof(pe->tx_slots));
	memset(pe->keys, 0, sizeof(pe->keys));
	memset(pe->ac_seen, 0, sizeof(pe->ac_seen));
	pe->wmm_streams = 0;
	spin_lock_irqsave(&rtwpci->irq_lock, flags);
	rtw89_chip_config_intr_mask(rtwdev, RTW89_PCI_INTR_MASK_NORMAL);
	rtw89_chip_enable_intr(rtwdev, rtwpci);
	spin_unlock_irqrestore(&rtwpci->irq_lock, flags);
	ieee80211_wake_queues(rtwdev->hw);
	rtw89_pe_dma_resume(pe);
}
