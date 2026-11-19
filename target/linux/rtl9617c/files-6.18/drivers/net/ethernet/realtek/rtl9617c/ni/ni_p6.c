// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/phy/phy.h>

#include "ni.h"

#define P6_RESET_BLOCKS			0x102001c0
#define P6_RESET_SERDES			BIT(31)
#define XGE_COM_RX_RESET		BIT(15)
#define XGE_COM_TX_RESET		BIT(14)
#define XGE_COM_IFACE_RESET		BIT(13)
#define XGE_COM_MODE			GENMASK(6, 4)
#define XGE_TX_2_KEEP			(~(RTL_NI_XGE_TX2_READ_THR | \
					   RTL_NI_XGE_TX2_FIFO_AFULL))
#define XGE_TX_2_INIT			(FIELD_PREP(RTL_NI_XGE_TX2_READ_THR, 10) | \
					 FIELD_PREP(RTL_NI_XGE_TX2_FIFO_AFULL, 10))
#define XGE_RX_CLEAR			(RTL_NI_XGE_RX_DROP_SHORT | \
					 RTL_NI_XGE_RX_PAUSE_TERM | \
					 RTL_NI_XGE_RX_PAUSE_EXTRACT | \
					 RTL_NI_XGE_RX_FCS_CHK_EN)
#define XGE_RX_INIT			(RTL_NI_XGE_RX_PROMIS | \
					 RTL_NI_XGE_RX_DROP_SHORT | \
					 RTL_NI_XGE_RX_PAUSE_TERM | \
					 RTL_NI_XGE_RX_PAUSE_EXTRACT | \
					 RTL_NI_XGE_RX_LEN_CHK_EN | \
					 RTL_NI_XGE_RX_LEN_CHK_PAUSE | \
					 RTL_NI_XGE_RX_LEN_CHK_PAD | \
					 RTL_NI_XGE_RX_FCS_CHK_EN | \
					 RTL_NI_XGE_RX_CRC_ERR_FATAL)
#define XGE_TX_INIT			(FIELD_PREP(RTL_NI_XGE_TX_IFG_MODE, 1) | \
					 RTL_NI_XGE_TX_PAUSE_REQ_EN | \
					 RTL_NI_XGE_TX_PAUSE_AUTO_XON)

static void rtl_ni_p6_mac_config(struct rtl9617c_ni *ni)
{
	u32 qm, val;

	rtl_ni_rmw(ni, RTL_L2TM_ES_CTRL, RTL_L2TM_ES_CTRL_P6, 0);
	qm = rtl_ni_read(ni, RTL_QM_ES_CTRL);
	rtl_ni_write(ni, RTL_QM_ES_CTRL, qm & ~RTL_QM_ES_NI_P6);
	rtl_ni_rmw(ni, RTL_NI_GLB_NITX_MISC_CFG, 0,
		   RTL_NI_GLB_NITX_XGE6_TX_DRAIN);

	/* Toggle gige_mode + inf_sel while resetting XGE MAC */
	val = rtl_ni_read(ni, RTL_NI_XGE_MISC_CONFIG) &
	      ~RTL_NI_XGE_MISC_INF_SEL;
	rtl_ni_write(ni, RTL_NI_XGE_MISC_CONFIG,
		     val | RTL_NI_XGE_MISC_GIGE_MODE);
	rtl_ni_write(ni, RTL_NI_XGE_MISC_CONFIG,
		     val | RTL_NI_XGE_MISC_GIGE_MODE |
		     RTL_NI_XGE_MISC_INF_SEL);
	usleep_range(10000, 11000);

	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_TX, RTL_NI_XGE_TX_IFG_MODE, 0);
	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_TX, 0,
		   FIELD_PREP(RTL_NI_XGE_TX_IFG_MODE, 1));
	val = rtl_ni_read(ni, RTL_NI_XGE_MAC_CFG_TX_2);
	rtl_ni_write(ni, RTL_NI_XGE_MAC_CFG_TX_2, (val & XGE_TX_2_KEEP) | XGE_TX_2_INIT);

	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_COM, XGE_COM_IFACE_RESET | XGE_COM_MODE,
		   XGE_COM_RX_RESET | XGE_COM_TX_RESET);
	usleep_range(10000, 11000);
	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_COM, XGE_COM_RX_RESET | XGE_COM_TX_RESET |
		   XGE_COM_IFACE_RESET | XGE_COM_MODE, 0);

	val = rtl_ni_read(ni, RTL_NI_XGE_MISC_CONFIG) &
	      ~(RTL_NI_XGE_MISC_GIGE_MODE | RTL_NI_XGE_MISC_INF_SEL);
	rtl_ni_write(ni, RTL_NI_XGE_MISC_CONFIG, val);
	rtl_ni_write(ni, RTL_NI_XGE_MISC_CONFIG, val | RTL_NI_XGE_MISC_INF_XFI);
	rtl_ni_rmw(ni, RTL_NI_GLB_NITX_MISC_CFG,
		   RTL_NI_GLB_NITX_XGE6_TX_DRAIN, 0);

	rtl_ni_rmw(ni, RTL_L2TM_ES_CTRL, 0, RTL_L2TM_ES_CTRL_P6);
	rtl_ni_write(ni, RTL_QM_ES_CTRL, qm | RTL_QM_ES_NI_P6);
}

static void rtl_ni_p6_iface_select(struct rtl9617c_ni *ni)
{
	u32 val;

	rtl_ni_rmw(ni, RTL_NI_GLB_NITX_MISC_CFG, 0,
		   RTL_NI_GLB_NITX_XGE6_TX_DRAIN);
	val = rtl_ni_read(ni, RTL_NI_XGE_MISC_CONFIG) &
	      ~(RTL_NI_XGE_MISC_GIGE_MODE | RTL_NI_XGE_MISC_INF_SEL);
	rtl_ni_write(ni, RTL_NI_XGE_MISC_CONFIG, val);
	/* Keep gige_mode set for 2.5G SGMII / HiSGMII operation (inf_sel = 1) */
	rtl_ni_write(ni, RTL_NI_XGE_MISC_CONFIG,
		     val | RTL_NI_XGE_MISC_GIGE_MODE |
		     RTL_NI_XGE_MISC_INF_SGMII);
	usleep_range(10000, 11000);

	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_COM, 0, XGE_COM_IFACE_RESET);
	usleep_range(10000, 11000);
	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_COM, XGE_COM_IFACE_RESET, 0);
	rtl_ni_rmw(ni, RTL_NI_GLB_NITX_MISC_CFG,
		   RTL_NI_GLB_NITX_XGE6_TX_DRAIN, 0);
}

static int rtl_ni_p6_serdes(struct rtl9617c_ni *ni, phy_interface_t interface)
{
	struct rtl9617c_ni_port *port = ni->ports[RTL_NI_PORT_P6];
	int ret;

	writel(readl(ni->reset) | P6_RESET_SERDES, ni->reset);
	udelay(1);
	writel(readl(ni->reset) & ~P6_RESET_SERDES, ni->reset);

	ret = phy_set_mode_ext(port->serdes, PHY_MODE_ETHERNET, interface);
	if (ret)
		dev_warn(ni->dev, "P6 SerDes %s setup failed: %d\n",
			 phy_modes(interface), ret);
	return ret;
}

int rtl_ni_p6_bringup(struct rtl9617c_ni *ni)
{
	struct rtl9617c_ni_port *port = ni->ports[RTL_NI_PORT_P6];
	int ret;

	if (!port || !port->serdes || ni->p6_ready)
		return 0;

	if (!ni->serdes_on) {
		ret = phy_power_on(port->serdes);
		if (ret) {
			dev_warn(ni->dev, "P6 SerDes power on failed: %d\n", ret);
			return ret;
		}
		ni->serdes_on = true;
	}

	writel(readl(ni->reset) | P6_RESET_BLOCKS, ni->reset);
	writel(readl(ni->reset) | P6_RESET_SERDES, ni->reset);
	msleep(50);
	writel(readl(ni->reset) & ~P6_RESET_SERDES, ni->reset);
	usleep_range(1000, 2000);

	ret = rtl_ni_p6_serdes(ni, port->interface);

	rtl_ni_p6_mac_config(ni);
	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_COM,
		   RTL_NI_XGE_MAC_CFG_COM_CLR_ON_RD |
		   RTL_NI_XGE_MAC_CFG_COM_RT_MIB_EN,
		   RTL_NI_XGE_MAC_CFG_COM_RT_MIB_EN);
	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_RX, XGE_RX_CLEAR, XGE_RX_INIT);
	rtl_ni_rmw(ni, RTL_NI_XGE_MAC_CFG_TX, XGE_TX_INIT, XGE_TX_INIT);
	rtl_ni_write(ni, RTL_NI_GLB_INTF_RST_CONFIG, 0);
	rtl_ni_p6_iface_select(ni);

	ni->p6_ready = !ret;
	return ret;
}

int rtl_ni_p6_set_interface(struct rtl9617c_ni *ni, phy_interface_t interface)
{
	struct rtl9617c_ni_port *port = ni->ports[RTL_NI_PORT_P6];
	int ret;

	if (!port->serdes || port->interface == interface)
		return 0;

	ret = rtl_ni_p6_serdes(ni, interface);
	if (ret)
		return ret;
	port->interface = interface;
	rtl_ni_p6_mac_config(ni);
	rtl_ni_p6_iface_select(ni);
	return 0;
}
