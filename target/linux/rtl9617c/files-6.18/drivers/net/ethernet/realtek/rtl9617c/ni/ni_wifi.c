// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/export.h>
#include <linux/iopoll.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/gro.h>

#include "ni.h"
#include "fe/fe_priv.h"
#include "rtl9617c-wifi-format.h"

#define RTL_WIFI_UPLINK_DMA_BYTES	(RTL_NI_WIFI_UPLINK_ENTRIES * \
					 sizeof(struct rtl_ni_dma_desc))
#define RTL_WIFI_UPLINK_ORDER		10

int rtl9617c_ni_wifi_attach(struct device *dev,
			    struct rtl9617c_ni_wifi_endpoint *endpoint)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	unsigned int id;
	int ret;

	ASSERT_RTNL();
	if (!ni->fe || !ni->qm.wifi_ready)
		return -EOPNOTSUPP;
	for (id = 1; id <= RTL_NI_WIFI_IDS; id++)
		if (!rcu_access_pointer(ni->wifi[id]))
			break;
	if (id > RTL_NI_WIFI_IDS)
		return -ENOSPC;
	ret = rtl_ni_engine_get(ni);
	if (ret)
		return ret;
	ret = rtl_fe_add_wifi_port(ni->fe, endpoint->netdev, id);
	if (ret) {
		rtl_ni_engine_put(ni);
		return ret;
	}
	dev_hold(endpoint->netdev);
	rcu_assign_pointer(ni->wifi[id], endpoint);
	return id;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_wifi_attach);

int rtl9617c_ni_wifi_detach(struct device *dev, unsigned int id)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	struct rtl9617c_ni_wifi_endpoint *endpoint;
	int ret;

	ASSERT_RTNL();
	if (id > RTL_NI_WIFI_IDS)
		return -EINVAL;
	endpoint = rcu_access_pointer(ni->wifi[id]);
	if (!endpoint)
		return -ENODEV;

	rtl_fe_flush_port(ni->fe, endpoint->netdev);
	ret = rtl_ni_dma_vp_drain_wait(&ni->dma);
	if (ret)
		return ret;
	usleep_range(1000, 2000);
	napi_disable(&ni->napi);
	local_bh_disable();
	rtl_ni_qm_poll(ni, &ni->napi, 1024);
	napi_gro_flush(&ni->napi, false);
	netif_receive_skb_list(&ni->napi.gro.rx_list);
	ni->napi.gro.rx_count = 0;
	local_bh_enable();
	rcu_assign_pointer(ni->wifi[id], NULL);
	napi_enable(&ni->napi);
	napi_schedule(&ni->napi);
	synchronize_net();
	dev_put(endpoint->netdev);
	rtl_ni_engine_put(ni);
	return 0;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_wifi_detach);

int rtl9617c_ni_wifi_id(struct device *dev, struct net_device *netdev)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	unsigned int id;
	int ret = -ENODEV;

	rcu_read_lock();
	for (id = 1; id <= RTL_NI_WIFI_IDS; id++) {
		struct rtl9617c_ni_wifi_endpoint *endpoint =
			rcu_dereference(ni->wifi[id]);

		if (endpoint && endpoint->netdev == netdev) {
			ret = id;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_wifi_id);

bool rtl9617c_ni_wifi_enabled(struct device *dev)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);

	return ni->fe && rtl_fe_is_enabled(ni->fe);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_wifi_enabled);

int rtl9617c_ni_wifi_peer_route(struct device *dev, struct net_device *netdev,
				const u8 *address, unsigned int destination)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);

	return rtl_fe_wifi_peer_route(ni->fe, netdev, address, destination);
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_wifi_peer_route);

int rtl9617c_ni_wifi_lookup(struct device *dev, struct sk_buff *skb,
			    unsigned int id)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&ni->tx_lock, flags);
	ret = rtl_ni_dma_wifi_xmit(&ni->dma, skb, id);
	spin_unlock_irqrestore(&ni->tx_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(rtl9617c_ni_wifi_lookup);

int rtl9617c_ni_wifi_radio_attach(struct device *dev, unsigned int slot,
				  struct rtl9617c_wifi_radio_info *info)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	struct rtl_ni_wifi_radio *radio;
	void *uplink;
	dma_addr_t uplink_dma;
	unsigned int cpu, eq, vp;
	int ret;

	if (slot >= RTL_NI_WIFI_RADIOS)
		return -EINVAL;
	mutex_lock(&ni->lock);
	radio = &ni->wifi_radio[slot];
	if (radio->active) {
		mutex_unlock(&ni->lock);
		return -EBUSY;
	}
	if (!ni->qm.wifi_ready) {
		mutex_unlock(&ni->lock);
		return -EAGAIN;
	}
	uplink = dmam_alloc_coherent(ni->dev, RTL_WIFI_UPLINK_DMA_BYTES,
				     &uplink_dma, GFP_KERNEL);
	if (!uplink) {
		mutex_unlock(&ni->lock);
		return -ENOMEM;
	}
	memset(uplink, 0, RTL_WIFI_UPLINK_DMA_BYTES);
	cpu = 3 - slot;
	eq = RTL_NI_QM_PE_EQ + slot;
	vp = RTL_NI_WIFI_VP_FIRST + slot;
	ret = rtl_ni_dma_wifi_vp_start(&ni->dma, vp, uplink_dma,
				       RTL_WIFI_UPLINK_ORDER, &info->vp_regs);
	if (ret) {
		dmam_free_coherent(ni->dev, RTL_WIFI_UPLINK_DMA_BYTES, uplink,
				   uplink_dma);
		mutex_unlock(&ni->lock);
		return ret;
	}
	radio->uplink = uplink;
	radio->uplink_dma = uplink_dma;
	radio->vp = vp;
	radio->cpu = cpu;
	radio->eq = eq;
	radio->active = true;
	mutex_unlock(&ni->lock);

	info->vp = vp;
	info->uplink_dma = uplink_dma;
	info->cpu = cpu;
	info->eq = eq;
	info->epp_prod_reg = RTL_QM_CPUEPP_FIFO_WRPTR(cpu * 8);
	info->epp_cons_reg = RTL_QM_CPUEPP_FIFO_RDPTR(cpu * 8);
	info->epp_base_reg = RTL_QM_CPUEPP_FIFO_PADDR_START(cpu * 8);
	info->eq_push_reg = RTL_QM_CPU_PUSH_RDY0 + cpu * 8;
	info->epp_shift = RTL_NI_WIFI_EPP_SHIFT;
	info->epp_base = rtl_ni_read(ni, RTL_QM_CPUEPP_FIFO_PADDR_START(cpu * 8));
	info->epp_cursor = rtl_ni_read(ni, RTL_QM_CPUEPP_FIFO_RDPTR(cpu * 8));
	info->vp_read = readl(info->vp_regs + DMA_VP_READ) &
			(RTL_NI_WIFI_UPLINK_ENTRIES - 1);
	return 0;
}

void rtl9617c_ni_wifi_radio_detach(struct device *dev, unsigned int slot)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	struct rtl_ni_wifi_radio *radio;

	if (slot >= RTL_NI_WIFI_RADIOS)
		return;
	mutex_lock(&ni->lock);
	radio = &ni->wifi_radio[slot];
	if (!radio->active) {
		mutex_unlock(&ni->lock);
		return;
	}
	rtl_ni_dma_wifi_vp_stop(&ni->dma, radio->vp);
	dmam_free_coherent(ni->dev, RTL_WIFI_UPLINK_DMA_BYTES, radio->uplink,
			   radio->uplink_dma);
	memset(radio, 0, sizeof(*radio));
	mutex_unlock(&ni->lock);
}

u32 rtl9617c_ni_wifi_vp_read(struct device *dev, unsigned int slot)
{
	struct rtl9617c_ni *ni = dev_get_drvdata(dev);
	struct rtl_ni_wifi_radio *radio;

	if (slot >= RTL_NI_WIFI_RADIOS)
		return 0;
	radio = &ni->wifi_radio[slot];
	if (!radio->active)
		return 0;
	return rtl_ni_dma_wifi_vp_reg_read(ni, radio->vp);
}
