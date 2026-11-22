// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/io.h>
#include <linux/ip.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/rcupdate.h>
#include <linux/unaligned.h>

#include "ni.h"
#include "rtl9617c-wifi-format.h"

#define QM_EQ_PROFILE_CPU0		RTL_QM_EQ_PROFILE(RTL_NI_QM_EQ)
#define QM_DQ_EQ_PRIVATE		1
#define QM_DQ_EQ_SHARED			2
#define QM_DQ_BID_BASE			512
#define QM_LAN_DQ_PORT			(8 + RTL_NI_PORT_P6)
#define QM_LAN_DQ_EQ_PROFILE		0
#define QM_LAN_DQ_CREDIT_PROFILE	2
#define QM_LAN_DQ_VOQ_PROFILE		5
#define QM_LAN_DQ_EQ_PRIVATE		0
#define QM_LAN_DQ_EQ_SHARED		8
#define QM_LAN_DQ_SRAM_BASE		0x80000000U
#define QM_LAN_DQ_SRAM_BUFS		244U
#define QM_LAN_DQ_SRAM_BID_BASE		4352U
#define QM_WIFI_FIFO_PROFILE(n)		(6U + (n))
#define QM_LAN_DQ_DDR_BUFS		10588U
#define QM_LAN_DQ_DDR_BID_BASE		5796U
#define QM_EQ_CFG2_HEAD_DEFAULT		FIELD_PREP(RTL_QM_EQ_CFG2_REFILL_THS, 0xff)
#define QM_EQ_CFG2_BUFSZ_512		3U
#define QM_EQ_CFG2_BUFSZ_2048		5U
#define QM_EQ_CFG3_NONCPU		FIELD_PREP(RTL_QM_EQ_CFG3_CACHE, 1)
#define QM_VOQ_WEIGHT_LAN_DQ		(FIELD_PREP(RTL_TE_CB_VOQ_D1_PRVT, 25) | \
					 FIELD_PREP(RTL_TE_CB_VOQ_D1_GRPHTH, 0x3fff) | \
					 FIELD_PREP(RTL_TE_CB_VOQ_D1_GRPLTH, 0x3ff))
#define QM_VOQ_THRSH_FLAGS_LAN_DQ	FIELD_PREP(RTL_TE_CB_VOQ_D0_GRPLTH, 0xf)
#define QM_CPU_BURST_UNLIMITED		(FIELD_PREP(RTL_TE_CB_PORT_GRPHTH, 0x3fff) | \
					 FIELD_PREP(RTL_TE_CB_PORT_GRPLTH, 0x3fff))
#define QM_WAN_PORT_FIRST		16
#define QM_WAN_PORT_LAST		32
#define QM_CPU_PORT			16
#define QM_RESET_BIT			BIT(5)
#define QM_EPP_WRITE_MASK		GENMASK(23, 0)
#define QM_CMD_EQ			GENMASK(3, 0)
#define QM_CMD_VALID			(BIT(4) | BIT(6))
#define QM_CMD_L4_CSUM_ERR		BIT(5)
#define QM_CMD_ADDR			GENMASK(31, 7)
#define QM_HDR_EXT			BIT(31)
#define QM_HDR_POL			GENMASK(26, 18)
#define QM_HDR_LEN			GENMASK(28, 15)
#define QM_HDR_SOURCE			GENMASK(14, 9)
#define QM_SOURCE_PON			7
#define QM_SOURCE_PON_LLID		32
#define QM_EQ_CFG_DESC			(FIELD_PREP(RTL_QM_EQ_CFG3_CACHE_EOS, 6) | \
					 RTL_QM_EQ_CFG3_ACD_CMD | \
					 FIELD_PREP(RTL_QM_EQ_CFG3_DOMAIN, 2) | \
					 FIELD_PREP(RTL_QM_EQ_CFG3_CACHE, 6))
#define QM_ATTRIBUTE_CPU		(FIELD_PREP(RTL_QM_AXI_ATTRIB_TOP_BIT, 2) | \
					 RTL_QM_AXI_ATTRIB_ACE_CMD | \
					 FIELD_PREP(RTL_QM_AXI_ATTRIB_DOMAIN, 2) | \
					 FIELD_PREP(RTL_QM_AXI_ATTRIB_CACHE, 6))
#define QM_ATTRIBUTE_CPU_ENTRY		48
#define QM_ES_CTRL_RUN			(RTL_QM_ES_TX_EN | \
					 FIELD_PREP(RTL_QM_ES_CPUEPP_TIMER_MAX, 1) | \
					 FIELD_PREP(RTL_QM_ES_INCCFG_ERR, 6) | \
					 FIELD_PREP(RTL_QM_ES_INCCFG_PKT, 2) | \
					 FIELD_PREP(RTL_QM_ES_NI_EN, 0xff) | \
					 FIELD_PREP(RTL_QM_ES_CPU_EN, 1))
#define L2TE_CB_FREECNT_INIT		(RTL_L2TE_CB_FREECNT_CNT1_MSB | \
					 FIELD_PREP(RTL_L2TE_CB_FREECNT_CNT1, 0xe30) | \
					 RTL_L2TE_CB_FREECNT_CNT0_MSB)
#define L2TE_CB_FREECNT_ENTRIES		16
#define QM_RING_ADDR_MASK		(RTL_NI_QM_RING_SIZE - 1)

static int rtl_ni_qm_table_write(struct rtl9617c_ni *ni, unsigned int reg,
				 u32 index)
{
	return rtl_ne_table_write(ni->regs, reg, index);
}

static int rtl_ni_qm_port_map(struct rtl9617c_ni *ni, u32 index, u32 val)
{
	rtl_ni_write(ni, RTL_L2FE_ARB_PDPID_MAP_TBL_DATA,
		     FIELD_PREP(RTL_L2FE_ARB_PDPID_MAP_PDPID, val));
	return rtl_ni_qm_table_write(ni, RTL_L2FE_ARB_PDPID_MAP_TBL_ACCESS,
				     index);
}

static int rtl_ni_qm_attribute(struct rtl9617c_ni *ni, unsigned int entry,
			       u32 val)
{
	rtl_ni_write(ni, RTL_QM_AXI_ATTRIB_DATA0, val);
	return rtl_ni_qm_table_write(ni, RTL_QM_AXI_ATTRIB_ACCESS, entry);
}

static int rtl_ni_qm_pon_map(struct rtl9617c_ni *ni)
{
	unsigned int port, flags;
	int ret;

	for (flags = 0; flags < 256; flags += 64)
		for (port = 32; port < 64; port++) {
			ret = rtl_ni_qm_port_map(ni, flags | port, 8);
			if (ret)
				return ret;
		}
	return 0;
}

static int rtl_ni_qm_push(struct rtl9617c_ni *ni, u32 addr, unsigned int eq)
{
	u32 status;
	int ret;

	ret = regmap_read_poll_timeout_atomic(ni->regs, RTL_QM_EQM_PA_REQ(eq),
					      status,
					      status & RTL_QM_EQM_PA_REQ_CNT,
					      1, 10000);
	if (ret)
		return ret;
	ret = regmap_read_poll_timeout_atomic(ni->regs, RTL_QM_CPU_PUSH_RDY0,
					      status,
					      status & RTL_QM_CPU_PUSH_RDY,
					      1, 10000);
	if (ret)
		return ret;
	rtl_ni_write(ni, RTL_QM_CPU_PUSH_PADDR0,
		     (addr & RTL_QM_CPU_PUSH_ADDR) |
		     FIELD_PREP(RTL_QM_CPU_PUSH_EQID, eq));
	return 0;
}

static int rtl_ni_qm_try_push(struct rtl9617c_ni *ni, u32 addr, unsigned int eq)
{
	if (!(rtl_ni_read(ni, RTL_QM_EQM_PA_REQ(eq)) & RTL_QM_EQM_PA_REQ_CNT) ||
	    !(rtl_ni_read(ni, RTL_QM_CPU_PUSH_RDY0) & RTL_QM_CPU_PUSH_RDY))
		return -EAGAIN;
	rtl_ni_write(ni, RTL_QM_CPU_PUSH_PADDR0,
		     (addr & RTL_QM_CPU_PUSH_ADDR) |
		     FIELD_PREP(RTL_QM_CPU_PUSH_EQID, eq));
	return 0;
}

static void rtl_ni_qm_refill_add(struct rtl_ni_qm_refill *refill, u32 cmd)
{
	unsigned int eq = FIELD_GET(QM_CMD_EQ, cmd) - RTL_NI_QM_EQ;
	unsigned int tail = (refill->head[eq] + refill->count[eq]) %
			    RTL_NI_QM_EQ_BUFS;

	refill->addr[eq][tail] = cmd & QM_CMD_ADDR;
	refill->count[eq]++;
	refill->pending++;
}

static void rtl_ni_qm_refill_drain(struct rtl9617c_ni *ni, unsigned int budget)
{
	struct rtl_ni_qm_refill *refill = &ni->qm.refill;
	unsigned int eq, done = 0;

	for (eq = 0; eq < RTL_NI_QM_EQS; eq++) {
		unsigned int limit = budget / 2;

		while (refill->count[eq] && limit-- && done++ < budget) {
			if (rtl_ni_qm_try_push(ni, refill->addr[eq][refill->head[eq]],
					       eq + RTL_NI_QM_EQ))
				break;
			refill->head[eq] = (refill->head[eq] + 1) % RTL_NI_QM_EQ_BUFS;
			refill->count[eq]--;
			refill->pending--;
		}
	}
}

static int rtl_ni_qm_ingress(struct rtl9617c_ni *ni, unsigned int port)
{
	static const u32 ilpb[] = {
		RTL_L2FE_ILPB_D0_8021P_MARK |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D0_INNER_1P_SEL, 2) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D0_DSCP_SEL, 2) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D0_COS_SEL, 2) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D0_COS_CTRL, 7),
		RTL_L2FE_ILPB_D1_STA_MOVE_EN |
		RTL_L2FE_ILPB_D1_SA_MOVE_DIS_FWD |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D1_SPCL_PKT_IDX, 1) |
		RTL_L2FE_ILPB_D1_CLS_EN |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D1_CLS_LEN, 6) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D1_FLOWID_SEL, 7) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D1_TOP_1P_SEL, 2) |
		RTL_L2FE_ILPB_D1_CHG_1P_POP |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D1_1P_MARK_CTRL, 3),
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D2_INR_VID_SEL, 3) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D2_S_TPID_MATCH, 2) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D2_C_TPID_MATCH, 8) |
		RTL_L2FE_ILPB_D2_TOP_S_TPID_EN |
		RTL_L2FE_ILPB_D2_TOP_C_TPID_EN |
		RTL_L2FE_ILPB_D2_INR_C_TPID_EN |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D2_OT_TPID_MATCH, 8) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D2_STP_MODE, 3),
		RTL_L2FE_ILPB_D3_SA_MISS_FWD |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D3_UNKWN_POL_IDX, 1) |
		FIELD_PREP_CONST(RTL_L2FE_ILPB_D3_VLAN_CMD_SEL, 3),
		RTL_L2FE_ILPB_D4_UNKWN_POL_MODE,
	};
	static const u32 key[] = { 0x00007ef0, 0, 0, 0, 0, 0x02800000, 0x0001fbc0,
				   0, 0, 0, 0, 0x0a000000, 0x00000a40 };
	static const u32 fib[] = {
		0,
		0,
		RTL_L2FE_CLE_FIB2_PERMIT_0 |
		RTL_L2FE_CLE_FIB2_PERMIT_VLD_0 |
		FIELD_PREP_CONST(RTL_L2FE_CLE_FIB2_STP_MODE_0, 3),
		FIELD_PREP_CONST(RTL_L2FE_CLE_FIB3_LDPID_0, QM_CPU_PORT) |
		RTL_L2FE_CLE_FIB3_DP_VLD_0,
		0,
	};
	static const u32 cpu_map[] = {
		QM_CPU_PORT | RTL_L2FE_ARB_PDPID_MAP_MY_MAC,
		QM_CPU_PORT | RTL_L2FE_ARB_PDPID_MAP_POL,
		QM_CPU_PORT | RTL_L2FE_ARB_PDPID_MAP_POL |
		RTL_L2FE_ARB_PDPID_MAP_MY_MAC,
	};
	unsigned int i;
	int ret;

	if (port >= RTL_NI_GE_PORTS)
		port = RTL_NI_PORT_P6;

	for (i = 0; i < 256; i += 64) {
		ret = rtl_ni_qm_port_map(ni, i | port, i & 64 ? 8 : port);
		if (ret)
			return ret;
	}

	rtl_ni_write(ni, RTL_L2FE_PP_IPPB_DATA,
		     FIELD_PREP(RTL_L2FE_PP_IPPB_LSPID, port));
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_PP_IPPB_ACCESS, port);
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(ilpb); i++)
		rtl_ni_write(ni, RTL_L2FE_PP_ILPB_DATA(i), ilpb[i]);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_PP_ILPB_ACCESS, port);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(key); i++)
		rtl_ni_write(ni, RTL_L2FE_CLE_IGR_KEY_DATA(i), key[i]);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_CLE_IGR_KEY_ACCESS, 0);
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(fib); i++)
		rtl_ni_write(ni, RTL_L2FE_CLE_IGR_FIB_DATA(i), fib[i]);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_CLE_IGR_FIB_ACCESS, 0);
	if (ret)
		return ret;

	ret = rtl_ni_qm_port_map(ni, QM_CPU_PORT, 9);
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(cpu_map); i++) {
		ret = rtl_ni_qm_table_write(ni,
					    RTL_L2FE_ARB_PDPID_MAP_TBL_ACCESS,
					    cpu_map[i]);
		if (ret)
			return ret;
	}

	rtl_ni_write(ni, RTL_L2FE_PONCLE_KEY_DATA0,
		     ~FIELD_PREP(RTL_L2FE_PONCLE_KEY0_LSPID, port));
	rtl_ni_write(ni, RTL_L2FE_PONCLE_KEY_DATA1, ~0U);
	rtl_ni_write(ni, RTL_L2FE_PONCLE_KEY_DATA2, ~0U);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_PONCLE_KEY_ACCESS, port);
	if (ret)
		return ret;
	rtl_ni_write(ni, RTL_L2FE_PONCLE_KEY_DATA0,
		     (u32)~RTL_L2FE_PONCLE_KEY0_LSPID |
		     FIELD_PREP(RTL_L2FE_PONCLE_KEY0_LSPID, port));
	rtl_ni_write(ni, RTL_L2FE_PONCLE_KEY_DATA1, ~0U);
	rtl_ni_write(ni, RTL_L2FE_PONCLE_KEY_DATA2, ~0U);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_PONCLE_KEY_ACCESS,
				    RTL_L2FE_PONCLE_KEY_TCAM_MASK | port);
	if (ret)
		return ret;
	rtl_ni_write(ni, RTL_L2FE_PONCLE_FIB_DATA0, 0);
	rtl_ni_write(ni, RTL_L2FE_PONCLE_FIB_DATA1,
		     FIELD_PREP(RTL_L2FE_PONCLE_FIB1_FWD_ACT, 3) |
		     FIELD_PREP(RTL_L2FE_PONCLE_FIB1_FWD_ID, QM_CPU_PORT));
	rtl_ni_write(ni, RTL_L2FE_PONCLE_FIB_DATA2,
		     RTL_L2FE_PONCLE_FIB2_COS_ACT);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_PONCLE_FIB_ACCESS, port);
	if (ret)
		return ret;
	rtl_ni_write(ni, RTL_L2FE_PLC_ELPB_DATA0, RTL_L2FE_PLC_ELPB_STP_STATUS);
	rtl_ni_write(ni, RTL_L2FE_PLC_ELPB_DATA1, 0);
	ret = rtl_ni_qm_table_write(ni, RTL_L2FE_PLC_ELPB_ACCESS, QM_CPU_PORT);
	if (ret)
		return ret;

	rtl_ni_rmw(ni, RTL_NI_GLB_NIRX_L3FE_DEMUX_CFG1, GENMASK(15, 0), 0);
	rtl_ni_rmw(ni, RTL_NI_GLB_NIRX_L3FE_DPQ_DEMUX_CFG1, GENMASK(15, 0), 0);
	rtl_ni_rmw(ni, RTL_L2FE_PLC_DPID_FWD_CTRL, 0,
		   RTL_L2FE_PLC_VID_FFF_FWD | RTL_L2FE_PLC_UNKVLAN_FWD);
	return 0;
}

/**
 * rtl_ni_qm_eq_cfg - Program an empty queue pool with descriptors latched first.
 * @ni: Network interface state.
 * @eq: Empty queue index (0..15).
 * @cfg0: Word 0 (base address and enable bit), written after cfg1..cfg4.
 * @cfg1: Word 1 ((buf_count << 16) | bid_base).
 * @cfg2: Word 2 (head flags and buffer size code).
 * @cfg3: Word 3 (AXI/descriptor attributes).
 * @cfg4: Word 4 (pool extension flags).
 */
static void rtl_ni_qm_eq_cfg(struct rtl9617c_ni *ni, unsigned int eq,
			     u32 cfg0, u32 cfg1, u32 cfg2, u32 cfg3, u32 cfg4)
{
	unsigned int base = RTL_QM_EQ_CFG0(eq);

	rtl_ni_write(ni, base + 4, cfg1);
	rtl_ni_write(ni, base + 8, cfg2);
	rtl_ni_write(ni, base + 12, cfg3);
	rtl_ni_write(ni, base + 16, cfg4);
	wmb();
	rtl_ni_write(ni, base, cfg0);
}

/**
 * rtl_ni_qm_lan_deepq - Initialize dedicated EQ0/EQ8 deep queue for 2.5G LAN1.
 * @ni: Network interface state.
 *
 * High-rate 10G PON -> 2.5G XGE6 microbursts overflow L2TM's shared SRAM
 * buffer pool (~3651 cells). Offloading that flow onto L3QM port 14 backed
 * by private SRAM (EQ0) + reserved DDR (EQ8) absorbs bursts without tail drop.
 */
static int rtl_ni_qm_lan_deepq(struct rtl9617c_ni *ni)
{
	struct rtl_ni_qm *qm = &ni->qm;
	unsigned int count = qm->lan_dq_bufs;
	unsigned int low = count / 3;
	unsigned int high = (count * 2) / 3;
	unsigned int mid = count / 2;
	unsigned int voq_start = QM_LAN_DQ_PORT * RTL_NI_QM_VOQS;
	unsigned int shift = QM_LAN_DQ_PORT * 2;
	unsigned int voq;
	int ret;

	if (!count)
		return 0;

	rtl_ni_qm_eq_cfg(ni, QM_LAN_DQ_EQ_PRIVATE,
			 QM_LAN_DQ_SRAM_BASE | RTL_QM_EQ_CFG0_EN,
			 FIELD_PREP(RTL_QM_EQ_CFG1_TOTAL_BUFS, QM_LAN_DQ_SRAM_BUFS) |
			 FIELD_PREP(RTL_QM_EQ_CFG1_BID_START, QM_LAN_DQ_SRAM_BID_BASE),
			 QM_EQ_CFG2_HEAD_DEFAULT |
			 FIELD_PREP(RTL_QM_EQ_CFG2_BUFSZ, QM_EQ_CFG2_BUFSZ_512),
			 QM_EQ_CFG3_NONCPU, 0);
	rtl_ni_qm_eq_cfg(ni, QM_LAN_DQ_EQ_SHARED,
			 lower_32_bits(qm->lan_dq_dma) | RTL_QM_EQ_CFG0_EN,
			 FIELD_PREP(RTL_QM_EQ_CFG1_TOTAL_BUFS, count) |
			 FIELD_PREP(RTL_QM_EQ_CFG1_BID_START, QM_LAN_DQ_DDR_BID_BASE),
			 QM_EQ_CFG2_HEAD_DEFAULT |
			 FIELD_PREP(RTL_QM_EQ_CFG2_BUFSZ, QM_EQ_CFG2_BUFSZ_2048),
			 QM_EQ_CFG3_NONCPU, 0);

	rtl_ni_write(ni, RTL_QM_EQ_PROFILE(QM_LAN_DQ_EQ_PROFILE),
		     FIELD_PREP(RTL_QM_EQ_PROF_EQP0, QM_LAN_DQ_EQ_PRIVATE) |
		     FIELD_PREP(RTL_QM_EQ_PROF_EQP1, QM_LAN_DQ_EQ_SHARED));
	rtl_ni_write(ni, RTL_QM_DEST_PORT_EQ_CFG(QM_LAN_DQ_PORT),
		     QM_LAN_DQ_EQ_PROFILE);
	rtl_ni_write(ni, RTL_QM_SCH_CFG(QM_LAN_DQ_PORT), RTL_QM_SCH_VOQ_EN);
	rtl_ni_write(ni, RTL_QM_VOQ3_0_WEIGHT_RATIO_CFG(QM_LAN_DQ_PORT), 0);
	rtl_ni_write(ni, RTL_QM_VOQ3_0_WEIGHT_RATIO_CFG(QM_LAN_DQ_PORT) + 4, 0);

	rtl_ni_write(ni, RTL_TE_CB_PORT_THRSH_PROFILE(QM_LAN_DQ_CREDIT_PROFILE),
		     FIELD_PREP(RTL_TE_CB_PORT_LTH, low) |
		     FIELD_PREP(RTL_TE_CB_PORT_HTH, high));
	rtl_ni_write(ni, RTL_TE_CB_PORT_GRPTHRSH_PROFILE(QM_LAN_DQ_CREDIT_PROFILE),
		     QM_CPU_BURST_UNLIMITED);
	rtl_ni_rmw(ni, RTL_TE_CB_PORT_THRSH_SELECT0, GENMASK(1, 0) << shift,
		   QM_LAN_DQ_CREDIT_PROFILE << shift);

	rtl_ni_write(ni, RTL_TE_CB_PORT_FREECNT_DATA,
		     FIELD_PREP(RTL_TE_CB_FREECNT_CNT0, QM_LAN_DQ_SRAM_BUFS) |
		     RTL_TE_CB_FREECNT_CNT0_MSB |
		     FIELD_PREP(RTL_TE_CB_FREECNT_CNT1, count) |
		     RTL_TE_CB_FREECNT_CNT1_MSB);
	ret = rtl_ni_qm_table_write(ni, RTL_TE_CB_PORT_FREECNT_ACCESS,
				    QM_LAN_DQ_PORT);
	if (ret)
		return ret;

	rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA2, 0);
	rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA1,
		     QM_VOQ_WEIGHT_LAN_DQ);
	rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA0,
		     FIELD_PREP(RTL_TE_CB_VOQ_D0_LTH, low) |
		     FIELD_PREP(RTL_TE_CB_VOQ_D0_HTH, mid) |
		     QM_VOQ_THRSH_FLAGS_LAN_DQ);
	ret = rtl_ni_qm_table_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_ACCESS,
				    QM_LAN_DQ_VOQ_PROFILE);
	if (ret)
		return ret;

	for (voq = voq_start; voq < voq_start + RTL_NI_QM_VOQS; voq++) {
		rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_SELECT_DATA,
			     QM_LAN_DQ_VOQ_PROFILE);
		ret = rtl_ni_qm_table_write(ni,
					    RTL_TE_CB_VOQ_THRSH_SELECT_ACCESS,
					    voq);
		if (ret)
			return ret;
	}
	return 0;
}

static int rtl_ni_qm_deepq(struct rtl9617c_ni *ni)
{
	unsigned int count = RTL_NI_DQ_BUFS;
	unsigned int low = (count * 2) / 3;
	unsigned int high = low * 2;
	unsigned int pool, port, voq;
	u32 base = lower_32_bits(ni->qm.dq_dma);
	int ret;

	rtl_ni_rmw(ni, RTL_QM_ES_CTRL1, RTL_QM_ES_CTRL1_PUC_EN, 0);
	for (pool = 0; pool < 2; pool++) {
		unsigned int cfg = RTL_QM_EQ_CFG0(QM_DQ_EQ_PRIVATE + pool);

		rtl_ni_write(ni, cfg,
			     (base + pool * count * RTL_NI_DQ_BUF_SIZE) |
			     RTL_QM_EQ_CFG0_EN);
		rtl_ni_write(ni, cfg + 4,
			     FIELD_PREP(RTL_QM_EQ_CFG1_TOTAL_BUFS, count) |
			     FIELD_PREP(RTL_QM_EQ_CFG1_BID_START,
					QM_DQ_BID_BASE + pool * count));
		rtl_ni_write(ni, cfg + 8,
			     FIELD_PREP(RTL_QM_EQ_CFG2_BUFSZ,
					QM_EQ_CFG2_BUFSZ_2048));
		rtl_ni_write(ni, cfg + 12, QM_EQ_CFG_DESC);
		rtl_ni_write(ni, cfg + 16, 2);
	}
	rtl_ni_write(ni, RTL_QM_EQ_PROFILE(1),
		     FIELD_PREP(RTL_QM_EQ_PROF_EQP0, QM_DQ_EQ_PRIVATE) |
		     FIELD_PREP(RTL_QM_EQ_PROF_EQP1, QM_DQ_EQ_SHARED));
	rtl_ni_rmw(ni, RTL_QM_UPPER_LDPID_MAP, RTL_QM_UPPER_LDPID_MAP_MASK,
		   RTL_QM_UPPER_LDPID_PON_EN |
		   FIELD_PREP(RTL_QM_UPPER_LDPID_PON_OFFSET, 2));
	rtl_ni_rmw(ni, RTL_QM_BUFFER_CNTL,
		   RTL_QM_BUF_CNTL_JUMBO_EN | RTL_QM_BUF_CNTL_ALT_EQ_EN, 0);
	rtl_ni_write(ni, RTL_TE_CB_PORT_THRSH_PROFILE(3),
		     FIELD_PREP(RTL_TE_CB_PORT_LTH, low) |
		     FIELD_PREP(RTL_TE_CB_PORT_HTH, high));
	rtl_ni_write(ni, RTL_TE_CB_PORT_GRPTHRSH_PROFILE(3),
		     QM_CPU_BURST_UNLIMITED);
	rtl_ni_write(ni, RTL_TE_CB_PORT_THRSH_SELECT1, ~0U);
	rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA2, 0);
	rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA1,
		     QM_VOQ_WEIGHT_LAN_DQ);
	rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA0,
		     FIELD_PREP(RTL_TE_CB_VOQ_D0_LTH, low) |
		     FIELD_PREP(RTL_TE_CB_VOQ_D0_HTH, count) |
		     QM_VOQ_THRSH_FLAGS_LAN_DQ);
	ret = rtl_ni_qm_table_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_ACCESS, 3);
	if (ret)
		return ret;

	for (port = QM_WAN_PORT_FIRST; port < QM_WAN_PORT_LAST; port++) {
		rtl_ni_write(ni, RTL_QM_DEST_PORT_EQ_CFG(port), 1);
		rtl_ni_write(ni, RTL_QM_SCH_CFG(port), RTL_QM_SCH_VOQ_EN);
		rtl_ni_write(ni, RTL_QM_VOQ3_0_WEIGHT_RATIO_CFG(port),
			     0x01010101);
		rtl_ni_write(ni, RTL_QM_VOQ3_0_WEIGHT_RATIO_CFG(port) + 4,
			     0x01010101);
		rtl_ni_write(ni, RTL_TE_CB_PORT_FREECNT_DATA,
			     FIELD_PREP(RTL_TE_CB_FREECNT_CNT0, count) |
			     RTL_TE_CB_FREECNT_CNT0_MSB |
			     FIELD_PREP(RTL_TE_CB_FREECNT_CNT1, count) |
			     RTL_TE_CB_FREECNT_CNT1_MSB);
		ret = rtl_ni_qm_table_write(ni, RTL_TE_CB_PORT_FREECNT_ACCESS,
					    port);
		if (ret)
			return ret;
		for (voq = port * 8; voq < port * 8 + 8; voq++) {
			rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_SELECT_DATA, 3);
			ret = rtl_ni_qm_table_write(ni,
						    RTL_TE_CB_VOQ_THRSH_SELECT_ACCESS,
						    voq);
			if (ret)
				return ret;
		}
	}
	return rtl_ni_qm_lan_deepq(ni);
}

static void rtl_ni_qm_axi_reorder(struct rtl9617c_ni *ni)
{
	static const struct {
		u16 offset;
		u32 ctrl;
		u32 user;
		u32 id;
	} ch[] = {
		{ 0x000, 15, BIT(31) | 12, BIT(31) | 13 },
		{ 0x400, 15, BIT(31) | 12, BIT(31) | 13 },
		{ 0x480, 2, BIT(31) | 8, BIT(31) | 9 },
	};
	void __iomem *base = ni->qm.axi;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ch); i++) {
		void __iomem *reg = base + ch[i].offset;

		writel(ch[i].ctrl, reg);
		writel(ch[i].user, reg + 0x04);
		writel(BIT(28), reg + 0x08);
		writel(BIT(28), reg + 0x0c);
		writel(ch[i].id, reg + 0x10);
	}
}

static int rtl_ni_qm_cpu_credits(struct rtl9617c_ni *ni)
{
	u32 select = rtl_ni_read(ni, RTL_TE_CB_PORT_THRSH_SELECT0);
	unsigned int profile, cpu, voq;
	int ret;

	for (profile = 0; profile < 2; profile++) {
		unsigned int count = profile ? RTL_NI_QM_PE_BUFS - 4 : RTL_NI_QM_EQ_BUFS;

		rtl_ni_write(ni, RTL_TE_CB_PORT_THRSH_PROFILE(profile),
			     FIELD_PREP(RTL_TE_CB_PORT_HTH, count / 8) |
			     FIELD_PREP(RTL_TE_CB_PORT_LTH, count / 64));
		rtl_ni_write(ni, RTL_TE_CB_PORT_GRPTHRSH_PROFILE(profile),
			     QM_CPU_BURST_UNLIMITED);
	}

	for (cpu = 0; cpu < 4; cpu++) {
		unsigned int count0, count1, eq_profile;

		if (cpu == 1)
			continue;
		profile = cpu ? 1 : 0;
		count0 = cpu ? RTL_NI_QM_PE_BUFS - 4 : RTL_NI_QM_EQ_BUFS;
		count1 = cpu ? 0 : RTL_NI_QM_EQ_BUFS;
		eq_profile = cpu ? cpu + 4 : RTL_NI_QM_EQ;

		if (cpu) {
			unsigned int eq = RTL_NI_QM_PE_EQ + (3 - cpu);

			rtl_ni_write(ni, RTL_QM_EQ_PROFILE(eq_profile),
				     FIELD_PREP(RTL_QM_EQ_PROF_EQP0, eq) |
				     FIELD_PREP(RTL_QM_EQ_PROF_EQP1, 15));
			rtl_ni_write(ni, RTL_QM_DEST_PORT_EQ_CFG(cpu),
				     eq_profile);
		}
		rtl_ni_write(ni, RTL_TE_CB_PORT_FREECNT_DATA,
			     FIELD_PREP(RTL_TE_CB_FREECNT_CNT0, count0) |
			     RTL_TE_CB_FREECNT_CNT0_MSB |
			     FIELD_PREP(RTL_TE_CB_FREECNT_CNT1, count1) |
			     RTL_TE_CB_FREECNT_CNT1_MSB);
		ret = rtl_ni_qm_table_write(ni, RTL_TE_CB_PORT_FREECNT_ACCESS,
					    cpu);
		if (ret)
			return ret;
		select = (select & ~(3U << (cpu * 2))) | (profile << (cpu * 2));

		rtl_ni_write(ni, RTL_TE_CB_EQ_PROFILE_THRSH(eq_profile),
			     FIELD_PREP(RTL_TE_CB_EQ_TH0, 12) |
			     FIELD_PREP(RTL_TE_CB_EQ_TH1, 12));
		for (voq = cpu * 8; voq < cpu * 8 + 8; voq++) {
			if (cpu)
				rtl_ni_write(ni, RTL_QM_CPU_EPP_FIFO0_CFG(voq),
					     eq_profile);
			rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_SELECT_DATA,
				     cpu == 3 ? 4 : profile);
			ret = rtl_ni_qm_table_write(ni,
						    RTL_TE_CB_VOQ_THRSH_SELECT_ACCESS,
						    voq);
			if (ret)
				return ret;
		}
	}

	for (profile = 0; profile < 3; profile++) {
		unsigned int count = profile ? RTL_NI_QM_PE_BUFS - 4 : RTL_NI_QM_EQ_BUFS;

		rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA2, 0);
		rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA1,
			     FIELD_PREP(RTL_TE_CB_VOQ_D1_PRVT,
					profile == 1 ? 12 : 3));
		rtl_ni_write(ni, RTL_TE_CB_VOQ_THRSH_PROFILE_DATA0,
			     FIELD_PREP(RTL_TE_CB_VOQ_D0_HTH, count * 7 / 8) |
			     FIELD_PREP(RTL_TE_CB_VOQ_D0_LTH, count * 6 / 8));
		ret = rtl_ni_qm_table_write(ni,
					    RTL_TE_CB_VOQ_THRSH_PROFILE_ACCESS,
					    profile == 2 ? 4 : profile);
		if (ret)
			return ret;
	}
	rtl_ni_write(ni, RTL_TE_CB_PORT_THRSH_SELECT0, select);
	return 0;
}

/**
 * rtl_ni_qm_lan_dq_alloc - Claim reserved DDR pool for XGE6 (LAN1) deep queue.
 * @ni: Network interface state.
 *
 * Looks up optional "memory-region" on the NI device-tree node. When absent,
 * LAN deep queue remains disabled cleanly.
 */
static int rtl_ni_qm_lan_dq_alloc(struct rtl9617c_ni *ni)
{
	struct rtl_ni_qm *qm = &ni->qm;
	size_t size = (size_t)QM_LAN_DQ_DDR_BUFS * RTL_NI_DQ_BUF_SIZE;
	struct device_node *np;
	struct resource region;

	np = of_parse_phandle(ni->dev->of_node, "memory-region", 0);
	if (!np)
		return 0;

	if (of_address_to_resource(np, 0, &region)) {
		of_node_put(np);
		return -EINVAL;
	}
	of_node_put(np);
	if (resource_size(&region) < size ||
	    upper_32_bits(region.start + size - 1))
		return -ENOSPC;

	qm->lan_dq = memremap(region.start, size, MEMREMAP_WB);
	if (!qm->lan_dq)
		return -ENOMEM;

	qm->lan_dq_dma = dma_map_single(ni->dev, qm->lan_dq, size,
					DMA_BIDIRECTIONAL);
	if (dma_mapping_error(ni->dev, qm->lan_dq_dma) ||
	    upper_32_bits(qm->lan_dq_dma)) {
		if (!dma_mapping_error(ni->dev, qm->lan_dq_dma))
			dma_unmap_single(ni->dev, qm->lan_dq_dma, size,
					 DMA_BIDIRECTIONAL);
		memunmap(qm->lan_dq);
		qm->lan_dq = NULL;
		return -EFAULT;
	}

	qm->lan_dq_size = size;
	qm->lan_dq_bufs = QM_LAN_DQ_DDR_BUFS;
	return 0;
}

static void rtl_ni_qm_lan_dq_free(struct rtl9617c_ni *ni)
{
	struct rtl_ni_qm *qm = &ni->qm;

	if (!qm->lan_dq)
		return;
	dma_unmap_single(ni->dev, qm->lan_dq_dma, qm->lan_dq_size,
			 DMA_BIDIRECTIONAL);
	memunmap(qm->lan_dq);
	qm->lan_dq = NULL;
	qm->lan_dq_dma = 0;
	qm->lan_dq_size = 0;
	qm->lan_dq_bufs = 0;
}

int rtl_ni_qm_alloc(struct rtl9617c_ni *ni)
{
	struct rtl_ni_qm *qm = &ni->qm;
	int ret;

	qm->buf = dma_alloc_noncoherent(ni->dev, RTL_NI_QM_BUFS * RTL_NI_QM_BUF_SIZE,
					&qm->buf_dma, DMA_FROM_DEVICE, GFP_KERNEL);
	if (!qm->buf)
		return -ENOMEM;
	qm->wifi_buf = dma_alloc_noncoherent(ni->dev,
					     RTL_NI_QM_PE_BUFS * RTL_NI_QM_BUF_SIZE,
					     &qm->wifi_buf_dma, DMA_BIDIRECTIONAL,
					     GFP_KERNEL);
	qm->wifi_ring = dmam_alloc_coherent(ni->dev,
					    RTL_NI_WIFI_RADIOS * 8 * RTL_NI_WIFI_EPP_BYTES,
					    &qm->wifi_ring_dma, GFP_KERNEL);
	qm->ring = dmam_alloc_coherent(ni->dev, RTL_NI_QM_RING_SIZE * RTL_NI_QM_VOQS,
				       &qm->ring_dma, GFP_KERNEL);
	qm->dq = dmam_alloc_coherent(ni->dev, RTL_NI_DQ_SIZE, &qm->dq_dma,
				     GFP_KERNEL);
	if (!qm->wifi_buf || !qm->wifi_ring || !qm->ring || !qm->dq) {
		rtl_ni_qm_free(ni);
		return -ENOMEM;
	}
	ret = rtl_ni_qm_lan_dq_alloc(ni);
	if (ret) {
		rtl_ni_qm_free(ni);
		return ret;
	}
	return 0;
}

void rtl_ni_qm_free(struct rtl9617c_ni *ni)
{
	struct rtl_ni_qm *qm = &ni->qm;

	rtl_ni_qm_lan_dq_free(ni);
	if (qm->wifi_buf) {
		dma_free_noncoherent(ni->dev,
				     RTL_NI_QM_PE_BUFS * RTL_NI_QM_BUF_SIZE,
				     qm->wifi_buf, qm->wifi_buf_dma,
				     DMA_BIDIRECTIONAL);
		qm->wifi_buf = NULL;
	}
	if (!qm->buf)
		return;
	dma_free_noncoherent(ni->dev, RTL_NI_QM_BUFS * RTL_NI_QM_BUF_SIZE, qm->buf,
			     qm->buf_dma, DMA_FROM_DEVICE);
	qm->buf = NULL;
}

static int rtl_ni_qm_lan_dq_wait_pool(struct rtl9617c_ni *ni, unsigned int eq,
				      unsigned int expected)
{
	u32 mon, free;
	int ret;

	ret = regmap_read_poll_timeout(ni->regs, RTL_QM_MONITOR1_EQ(eq),
				       mon,
				       (mon & RTL_QM_EQM_PA_REQ_CNT) == expected,
				       10, 100000);
	if (ret)
		return ret;
	return regmap_read_poll_timeout(ni->regs, RTL_QM_EQM_PA_REQ(eq), free,
					!(free & RTL_QM_EQM_PA_REQ_CNT),
					10, 100000);
}

static int rtl_ni_qm_lan_dq_wait_flush(struct rtl9617c_ni *ni)
{
	int ret;

	if (!ni->qm.lan_dq_bufs)
		return 0;

	ret = rtl_ni_qm_lan_dq_wait_pool(ni, QM_LAN_DQ_EQ_PRIVATE,
					 QM_LAN_DQ_SRAM_BUFS);
	if (ret)
		return ret;
	return rtl_ni_qm_lan_dq_wait_pool(ni, QM_LAN_DQ_EQ_SHARED,
					  ni->qm.lan_dq_bufs);
}

static void rtl_ni_qm_lan_dq_enable(struct rtl9617c_ni *ni, bool enable)
{
	rtl_ni_rmw(ni, RTL_NI_GLB_INTERNAL_PORT_ID_CFG,
		   RTL_NI_GLB_L3QMRX_TO_LAN,
		   enable ? RTL_NI_GLB_L3QMRX_TO_LAN : 0);
	rtl_ni_rmw(ni, RTL_NI_L3QMRX_DEMUX_CFG0, RTL_NI_L3QMRX_DEMUX_P6,
		   enable ? RTL_NI_L3QMRX_DEMUX_P6 : 0);
	rtl_ni_rmw(ni, RTL_QM_ES_CTRL2, RTL_QM_ES_CTRL2_LAN_EN,
		   enable ? RTL_QM_ES_CTRL2_LAN_EN : 0);
}

int rtl_ni_qm_start(struct rtl9617c_ni *ni)
{
	struct rtl_ni_qm *qm = &ni->qm;
	unsigned int i;
	u32 val;
	int ret;

	qm->ready = false;
	rtl_ni_rmw(ni, RTL_TE_CB_CTRL, RTL_TE_CB_SCAN_EN, 0);
	rtl_ni_rmw(ni, RTL_QM_RMU0_CTRL, RTL_QM_RMU0_RX_EN, 0);
	rtl_ni_rmw(ni, RTL_QM_ES_CTRL, RTL_QM_ES_TX_EN, 0);

	writel(readl(ni->reset) | QM_RESET_BIT, ni->reset);
	usleep_range(1000, 2000);
	writel(readl(ni->reset) & ~QM_RESET_BIT, ni->reset);
	ret = regmap_read_poll_timeout(ni->regs, RTL_QM_PHY_PORT_STS, val,
				       val & RTL_QM_PHY_PORT_INIT_DONE,
				       1, 100000);
	if (ret)
		return ret;

	memset(&qm->refill, 0, sizeof(qm->refill));
	rtl_ni_rmw(ni, RTL_QM_RMU0_CTRL, RTL_QM_RMU0_RX_EN, 0);
	rtl_ni_rmw(ni, RTL_QM_ES_CTRL, RTL_QM_ES_TX_EN, 0);
	rtl_ni_write(ni, RTL_QM_EPP64_P3_0_INT_EN, 0);
	rtl_ni_write(ni, RTL_QM_EPP64_P7_4_INT_EN, 0);

	for (i = 0; i < RTL_NI_QM_VOQS; i++) {
		qm->read[i] = rtl_ni_read(ni, RTL_QM_CPUEPP_FIFO_WRPTR(i)) &
			      QM_RING_ADDR_MASK;
		rtl_ni_write(ni, RTL_QM_CPUEPP_FIFO_RDPTR(i), qm->read[i]);
	}
	rtl_ni_read(ni, RTL_QM_CPUEPP_FIFO_RDPTR(0));
	rtl_ni_qm_axi_reorder(ni);
	memset(qm->ring, 0, RTL_NI_QM_RING_SIZE * RTL_NI_QM_VOQS);
	dma_sync_single_for_device(ni->dev, qm->buf_dma,
				   RTL_NI_QM_BUFS * RTL_NI_QM_BUF_SIZE,
				   DMA_FROM_DEVICE);
	if (qm->lan_dq_bufs)
		dma_sync_single_for_device(ni->dev, qm->lan_dq_dma,
					   qm->lan_dq_size, DMA_BIDIRECTIONAL);

	for (i = 0; i < 16; i++) {
		rtl_ni_write(ni, RTL_QM_EQ_CFG0(i), 0);
		rtl_ni_write(ni, RTL_QM_EQ_CFG0(i) + 4, 0);
	}
	for (i = 0; i < RTL_NI_QM_EQS; i++) {
		unsigned int cfg = RTL_QM_EQ_CFG0(RTL_NI_QM_EQ + i);

		rtl_ni_write(ni, cfg, RTL_QM_EQ_CFG0_EN);
		rtl_ni_write(ni, cfg + 4,
			     FIELD_PREP(RTL_QM_EQ_CFG1_TOTAL_BUFS, RTL_NI_QM_EQ_BUFS) |
			     FIELD_PREP(RTL_QM_EQ_CFG1_BID_START, i * RTL_NI_QM_EQ_BUFS));
		rtl_ni_write(ni, cfg + 8,
			     FIELD_PREP(RTL_QM_EQ_CFG2_BUFSZ, QM_EQ_CFG2_BUFSZ_2048) |
			     RTL_QM_EQ_CFG2_CPU_EQ |
			     FIELD_PREP(RTL_QM_EQ_CFG2_REFILL_THS, 24));
		rtl_ni_write(ni, cfg + 12, QM_EQ_CFG_DESC);
		rtl_ni_write(ni, cfg + 16, 2);
	}
	for (i = 0; i < RTL_NI_WIFI_RADIOS; i++) {
		unsigned int cfg = RTL_QM_EQ_CFG0(RTL_NI_QM_PE_EQ + i);

		rtl_ni_write(ni, cfg, RTL_QM_EQ_CFG0_EN);
		rtl_ni_write(ni, cfg + 4,
			     FIELD_PREP(RTL_QM_EQ_CFG1_TOTAL_BUFS, RTL_NI_QM_PE_EQ_BUFS) |
			     FIELD_PREP(RTL_QM_EQ_CFG1_BID_START,
					RTL_NI_QM_PE_BID_START + i * RTL_NI_QM_PE_EQ_BUFS));
		rtl_ni_write(ni, cfg + 8,
			     FIELD_PREP(RTL_QM_EQ_CFG2_BUFSZ, QM_EQ_CFG2_BUFSZ_2048) |
			     RTL_QM_EQ_CFG2_CPU_EQ |
			     FIELD_PREP(RTL_QM_EQ_CFG2_REFILL_THS, 24));
		rtl_ni_write(ni, cfg + 12, QM_EQ_CFG_DESC);
		rtl_ni_write(ni, cfg + 16, 2);
	}

	ret = rtl_ni_qm_deepq(ni);
	if (ret)
		return ret;

	rtl_ni_write(ni, QM_EQ_PROFILE_CPU0,
		     FIELD_PREP(RTL_QM_EQ_PROF_EQP0, RTL_NI_QM_EQ) |
		     FIELD_PREP(RTL_QM_EQ_PROF_EQP1, RTL_NI_QM_EQ + 1));
	rtl_ni_write(ni, RTL_QM_DEST_PORT_EQ_CFG(0), RTL_NI_QM_EQ);
	rtl_ni_write(ni, RTL_QM_DEST_PORT_PKT_BUF_CFG(0),
		     FIELD_PREP(RTL_QM_PKT_BUF_HEAD_FIRST, RTL_NI_QM_HEADROOM / 16) |
		     FIELD_PREP(RTL_QM_PKT_BUF_TAIL_FIRST, RTL_NI_QM_TAILROOM / 16) |
		     FIELD_PREP(RTL_QM_PKT_BUF_HEAD_REST, RTL_NI_QM_HEADROOM / 16) |
		     FIELD_PREP(RTL_QM_PKT_BUF_TAIL_REST, RTL_NI_QM_TAILROOM / 16));
	rtl_ni_write(ni, RTL_QM_HDM_WRITE_PROTECT,
		     RTL_QM_HDM_WRITE_PROTECT_UNLOCK);
	wmb();
	rtl_ni_write(ni, RTL_QM_EQ_CFG_LOAD, RTL_QM_EQ_CFG_LOAD_ALL);
	wmb();
	udelay(50);
	rtl_ni_write(ni, RTL_QM_EQ_CFG_LOAD, 0);
	rtl_ni_write(ni, RTL_QM_HDM_WRITE_PROTECT, 0);
	ret = rtl_ni_qm_lan_dq_wait_flush(ni);
	if (ret)
		return ret;

	for (i = 0; i < 16; i++) {
		ret = rtl_ni_qm_attribute(ni, i, 0);
		if (ret)
			return ret;
	}
	ret = rtl_ni_qm_attribute(ni, QM_ATTRIBUTE_CPU_ENTRY, QM_ATTRIBUTE_CPU);
	if (ret)
		return ret;

	rtl_ni_rmw(ni, RTL_QM_AXIM2_CONFIG,
		   RTL_QM_AXIM2_WR_CACHELINE | RTL_QM_AXIM2_RD_CACHELINE,
		   FIELD_PREP(RTL_QM_AXIM2_RD_OUTTRANS, 15) |
		   FIELD_PREP(RTL_QM_AXIM2_WR_OUTTRANS, 15));
	rtl_ni_rmw(ni, RTL_QM_EPP, 0, RTL_QM_EPP_CMD_MODE);
	rtl_ni_write(ni, RTL_QM_CPU_EPP0_CFG, 0);

	rtl_ni_rmw(ni, RTL_QM_CPU_EPP_FIFO_CFG_PROFILE(RTL_NI_QM_EQ),
		   RTL_QM_EPP_FIFO_CFG_MASK,
		   FIELD_PREP(RTL_QM_EPP_FIFO_SIZE, RTL_NI_QM_RING_SIZE / 16) |
		   FIELD_PREP(RTL_QM_EPP_FIFO_TIMER_THS, 15) |
		   FIELD_PREP(RTL_QM_EPP_FIFO_HIGH_THS, 2));
	for (i = 0; i < RTL_NI_QM_VOQS; i++) {
		rtl_ni_write(ni, RTL_QM_CPU_EPP_FIFO0_CFG(i), RTL_NI_QM_EQ);
		rtl_ni_write(ni, RTL_QM_CPUEPP_FIFO_PADDR_START(i),
			     qm->ring_dma + i * RTL_NI_QM_RING_SIZE);
	}
	for (i = 0; i < RTL_NI_QM_BUFS; i++) {
		ret = rtl_ni_qm_push(ni, qm->buf_dma + i * RTL_NI_QM_BUF_SIZE,
				     RTL_NI_QM_EQ + i / RTL_NI_QM_EQ_BUFS);
		if (ret)
			return ret;
	}

	for (i = 0; i < RTL_NI_WIFI_RADIOS; i++) {
		unsigned int cpu = 3 - i, profile = QM_WIFI_FIFO_PROFILE(i);

		rtl_ni_write(ni, RTL_QM_DEST_PORT_PKT_BUF_CFG(cpu),
			     FIELD_PREP(RTL_QM_PKT_BUF_HEAD_FIRST, RTL_NI_QM_HEADROOM / 16) |
			     FIELD_PREP(RTL_QM_PKT_BUF_TAIL_FIRST, RTL_NI_QM_TAILROOM / 16) |
			     FIELD_PREP(RTL_QM_PKT_BUF_HEAD_REST, RTL_NI_QM_HEADROOM / 16) |
			     FIELD_PREP(RTL_QM_PKT_BUF_TAIL_REST, RTL_NI_QM_TAILROOM / 16));
		rtl_ni_rmw(ni, RTL_QM_CPU_EPP_FIFO_CFG_PROFILE(profile),
			   RTL_QM_EPP_FIFO_CFG_MASK,
			   FIELD_PREP(RTL_QM_EPP_FIFO_SIZE, RTL_NI_WIFI_EPP_BYTES / 16) |
			   FIELD_PREP(RTL_QM_EPP_FIFO_TIMER_THS, 15) |
			   FIELD_PREP(RTL_QM_EPP_FIFO_HIGH_THS, 2));
		for (unsigned int cos = 0; cos < 8; cos++) {
			dma_addr_t ring = qm->wifi_ring_dma +
					  (i * 8 + cos) * RTL_NI_WIFI_EPP_BYTES;

			rtl_ni_write(ni, RTL_QM_CPUEPP_FIFO_PADDR_START(cpu * 8 + cos),
				     ring);
			rtl_ni_write(ni, RTL_QM_CPUEPP_FIFO_RDPTR(cpu * 8 + cos),
				     rtl_ni_read(ni, RTL_QM_CPUEPP_FIFO_WRPTR(cpu * 8 + cos)) &
				     QM_EPP_WRITE_MASK);
		}
	}
	for (unsigned int pool = 0; pool < RTL_NI_WIFI_RADIOS; pool++) {
		for (i = 0; i < RTL_NI_QM_PE_EQ_BUFS - 4; i++) {
			ret = rtl_ni_qm_push(ni,
					     qm->wifi_buf_dma +
					     (pool * RTL_NI_QM_PE_EQ_BUFS + i) *
					     RTL_NI_QM_BUF_SIZE,
					     RTL_NI_QM_PE_EQ + pool);
			if (ret)
				return ret;
		}
	}

	ret = rtl_ni_qm_cpu_credits(ni);
	if (ret)
		return ret;
	rtl_ni_write(ni, RTL_QM_SCH_CFG(0), RTL_QM_SCH_VOQ_EN);
	rtl_ni_rmw(ni, RTL_NI_GLB_INTERNAL_PORT_ID_CFG,
		   RTL_NI_GLB_L3QMRX_DEMUX_SEL, 0);
	rtl_ni_qm_lan_dq_enable(ni, qm->lan_dq_bufs > 0);

	for (i = 0; i < RTL_NI_PORTS; i++) {
		if (!ni->ports[i])
			continue;
		ret = rtl_ni_qm_ingress(ni, i);
		if (ret)
			return ret;
	}
	ret = rtl_ni_qm_pon_map(ni);
	if (ret)
		return ret;

	for (i = 0; i < L2TE_CB_FREECNT_ENTRIES; i++) {
		rtl_ni_write(ni, RTL_L2TE_CB_PORT_FREECNT_DATA,
			     L2TE_CB_FREECNT_INIT);
		ret = rtl_ni_qm_table_write(ni,
					    RTL_L2TE_CB_PORT_FREECNT_ACCESS, i);
		if (ret)
			return ret;
	}

	rtl_ni_rmw(ni, RTL_L2TM_ES_CTRL, 0, BIT(8) | BIT(9));
	rtl_ni_write(ni, RTL_L2TM_ES_SCH_CFG0(8),
		     FIELD_PREP(RTL_L2TM_ES_SCH_VOQ_EN, 0xff) |
		     FIELD_PREP(RTL_L2TM_ES_SCH_SPEED, 6));
	rtl_ni_write(ni, RTL_L2TM_ES_SCH_CFG0(9),
		     FIELD_PREP(RTL_L2TM_ES_SCH_VOQ_EN, 0xff) |
		     FIELD_PREP(RTL_L2TM_ES_SCH_SPEED, 6));
	rtl_ni_rmw(ni, RTL_TE_CB_CTRL, 0, RTL_TE_CB_SCAN_EN);
	rtl_ni_rmw(ni, RTL_TE_GLB_CTRL, 0, RTL_TE_GLB_TAILDROP_EN);
	rtl_ni_write(ni, RTL_QM_ES_CTRL, QM_ES_CTRL_RUN);
	rtl_ni_rmw(ni, RTL_QM_ES_CTRL1, 0, RTL_QM_ES_CTRL1_PUC_EN);
	rtl_ni_rmw(ni, RTL_QM_RMU0_CTRL, 0, RTL_QM_RMU0_RX_EN);
	qm->wifi_ready = true;
	qm->ready = true;
	return 0;
}

void rtl_ni_qm_stop(struct rtl9617c_ni *ni)
{
	ni->qm.wifi_ready = false;
	ni->qm.ready = false;
	if (ni->qm.lan_dq_bufs)
		rtl_ni_qm_lan_dq_enable(ni, false);
	rtl_ni_rmw(ni, RTL_TE_CB_CTRL, RTL_TE_CB_SCAN_EN, 0);
	rtl_ni_rmw(ni, RTL_QM_ES_CTRL1, RTL_QM_ES_CTRL1_PUC_EN, 0);
	rtl_ni_rmw(ni, RTL_QM_RMU0_CTRL, RTL_QM_RMU0_RX_EN, 0);
	rtl_ni_rmw(ni, RTL_QM_ES_CTRL, RTL_QM_ES_TX_EN, 0);
}

static bool rtl_ni_rx_csum_valid(u32 cmd, const u8 *frame, unsigned int len)
{
	const struct iphdr *ip;
	unsigned int total, payload;
	const u8 *l4;

	if ((cmd & QM_CMD_L4_CSUM_ERR) || len < ETH_HLEN + sizeof(*ip) + 8 ||
	    get_unaligned_be16(frame + 12) != ETH_P_IP)
		return false;

	ip = (const struct iphdr *)(frame + ETH_HLEN);
	if (frame[ETH_HLEN] != 0x45 || (frame[ETH_HLEN + 6] & 0x3f) ||
	    frame[ETH_HLEN + 7])
		return false;

	total = get_unaligned_be16(&ip->tot_len);
	if (total < sizeof(*ip) + 8 || total > len - ETH_HLEN)
		return false;
	payload = total - sizeof(*ip);
	l4 = frame + ETH_HLEN + sizeof(*ip);

	switch (ip->protocol) {
	case IPPROTO_TCP:
		return payload >= 20 && (l4[12] >> 4) >= 5 &&
		       (l4[12] >> 4) * 4 <= payload;
	case IPPROTO_UDP:
		return get_unaligned_be16(l4 + 4) == payload && (l4[6] || l4[7]);
	default:
		return false;
	}
}

static void rtl_ni_qm_retire(struct rtl9617c_ni *ni, unsigned int voq, u32 cmd,
			     bool refill)
{
	struct rtl_ni_qm *qm = &ni->qm;

	qm->read[voq] = (qm->read[voq] + RTL_NI_QM_CMD_SIZE) & QM_RING_ADDR_MASK;
	mb();
	rtl_ni_write(ni, RTL_QM_CPUEPP_FIFO_RDPTR(voq), qm->read[voq]);
	if (refill) {
		u32 offset = (cmd & QM_CMD_ADDR) - lower_32_bits(qm->buf_dma);

		dma_sync_single_for_device(ni->dev, qm->buf_dma + offset,
					   RTL_NI_QM_BUF_SIZE, DMA_FROM_DEVICE);
		rtl_ni_qm_refill_add(&qm->refill, cmd);
	}
}

static void rtl_ni_qm_deliver(struct rtl9617c_ni *ni, struct napi_struct *napi,
			      struct sk_buff *skb, u32 cmd, u32 h0, u32 h1,
			      bool csum, unsigned int wifi_id, bool forwarded)
{
	unsigned int source = FIELD_GET(QM_HDR_SOURCE, h1);
	struct rtl9617c_ni_endpoint *endpoint;
	struct rtl9617c_ni_wifi_endpoint *wifi;
	struct net_device *dev;

	rcu_read_lock();
	if (wifi_id) {
		wifi = wifi_id <= RTL_NI_WIFI_IDS ?
		       rcu_dereference(ni->wifi[wifi_id]) : NULL;
		if (wifi && netif_running(wifi->netdev)) {
			skb->priority = h1 & 7;
			wifi->receive(wifi, napi, skb, forwarded);
		} else {
			atomic_long_inc(&ni->rx_dropped);
			dev_kfree_skb_any(skb);
		}
		rcu_read_unlock();
		return;
	}
	if (source >= RTL_NI_PORTS) {
		endpoint = rcu_dereference(ni->pon);
		if (endpoint && (source == QM_SOURCE_PON ||
				 source >= QM_SOURCE_PON_LLID)) {
			if (csum && rtl_ni_rx_csum_valid(cmd, skb->data, skb->len))
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			endpoint->receive(endpoint, napi, skb,
					  source | (FIELD_GET(QM_HDR_POL, h0) << 8));
		} else {
			atomic_long_inc(&ni->rx_dropped);
			dev_kfree_skb_any(skb);
		}
		rcu_read_unlock();
		return;
	}

	dev = rcu_dereference(ni->rx_dev[source]);
	if (!dev || !netif_running(dev)) {
		atomic_long_inc(&ni->rx_dropped);
		dev_kfree_skb_any(skb);
		rcu_read_unlock();
		return;
	}
	if (csum && (dev->features & NETIF_F_RXCSUM) &&
	    rtl_ni_rx_csum_valid(cmd, skb->data, skb->len))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = eth_type_trans(skb, dev);
	DEV_STATS_INC(dev, rx_packets);
	DEV_STATS_ADD(dev, rx_bytes, skb->len + ETH_HLEN);
	napi_gro_receive(napi, skb);
	rcu_read_unlock();
}

int rtl_ni_qm_poll(struct rtl9617c_ni *ni, struct napi_struct *napi, int budget)
{
	struct rtl_ni_qm *qm = &ni->qm;
	bool csum = rtl_ni_read(ni, RTL_FE_CAM_DATA_AUX) & RTL_FE_CAM_AUX_L4_CSUM;
	int voq, count = 0;

	rtl_ni_qm_refill_drain(ni, NAPI_POLL_WEIGHT);

	for (voq = RTL_NI_QM_VOQS - 1; voq >= 0 && count < budget; voq--) {
		bool nonempty = rtl_ni_read(ni, RTL_QM_CPU_EPP_STATUS0) &
				BIT(voq);
		unsigned int wr = rtl_ni_read(ni, RTL_QM_CPUEPP_FIFO_WRPTR(voq)) &
				  QM_EPP_WRITE_MASK;
		bool full = qm->read[voq] == wr && nonempty;

		while ((qm->read[voq] != wr || full) && count < budget) {
			void *entry = qm->ring + voq * RTL_NI_QM_RING_SIZE +
				      qm->read[voq];
			unsigned int eq, len, hdr, wifi_id = 0;
			bool forwarded = false, refill, wifi_eq;
			struct sk_buff *skb;
			u32 cmd, offset, h0, h1, length_word;
			void *data;

			full = false;
			dma_rmb();
			cmd = get_unaligned_le32(entry);
			length_word = get_unaligned_le32(entry + 4);
			eq = FIELD_GET(QM_CMD_EQ, cmd);
			wifi_eq = eq == RTL_NI_QM_PE_EQ || eq == RTL_NI_QM_PE_EQ + 1;
			if (!wifi_eq && eq >= RTL_NI_QM_EQ &&
			    eq < RTL_NI_QM_EQ + RTL_NI_QM_EQS &&
			    qm->refill.count[eq - RTL_NI_QM_EQ] == RTL_NI_QM_EQ_BUFS)
				break;

			count++;
			if (wifi_eq) {
				offset = (cmd & QM_CMD_ADDR) -
					 lower_32_bits(qm->wifi_buf_dma);
				if (offset >= RTL_NI_QM_PE_BUFS * RTL_NI_QM_BUF_SIZE) {
					atomic_long_inc(&ni->rx_errors);
					rtl_ni_qm_retire(ni, voq, cmd, false);
					continue;
				}
				dma_sync_single_for_cpu(ni->dev,
							qm->wifi_buf_dma + offset,
							RTL_NI_QM_BUF_SIZE,
							DMA_FROM_DEVICE);
				data = qm->wifi_buf + offset + RTL_NI_QM_HEADROOM;
				wifi_id = rtl_wifi_epp_id(length_word);
				forwarded = !!wifi_id;
				refill = false;
			} else {
				offset = (cmd & QM_CMD_ADDR) - lower_32_bits(qm->buf_dma);
				if (offset >= RTL_NI_QM_BUFS * RTL_NI_QM_BUF_SIZE ||
				    (eq != RTL_NI_QM_EQ && eq != RTL_NI_QM_EQ + 1)) {
					atomic_long_inc(&ni->rx_errors);
					rtl_ni_qm_retire(ni, voq, cmd, false);
					continue;
				}
				dma_sync_single_for_cpu(ni->dev, qm->buf_dma + offset,
							RTL_NI_QM_BUF_SIZE, DMA_FROM_DEVICE);
				data = qm->buf + offset + RTL_NI_QM_HEADROOM;
				refill = true;
			}
			h0 = get_unaligned_be32(data);
			h1 = get_unaligned_be32(data + 4);
			hdr = (h0 & QM_HDR_EXT) ? 16 : 8;
			len = FIELD_GET(QM_HDR_LEN, h1);
			if (h0 & QM_HDR_EXT)
				len -= 8;
			if (forwarded) {
				int payload = rtl_wifi_epp_length(length_word,
					RTL_NI_QM_DATA_SIZE - RTL_WIFI_INTERNAL_BYTES);

				if (payload < 0) {
					atomic_long_inc(&ni->rx_errors);
					rtl_ni_qm_retire(ni, voq, cmd, false);
					continue;
				}
				len = payload;
				hdr = RTL_WIFI_INTERNAL_BYTES;
			} else if (!wifi_eq && (h0 & QM_HDR_EXT) &&
				   FIELD_GET(QM_HDR_SOURCE, h1) == RTL_WIFI_SOURCE) {
				u32 metadata = get_unaligned_be32(data + 12);

				if (((metadata >> 8) & 15) != 15)
					wifi_id = metadata & 255;
			}
			if ((cmd & QM_CMD_VALID) != QM_CMD_VALID || len < ETH_HLEN ||
			    len > RTL_NI_QM_DATA_SIZE - hdr) {
				atomic_long_inc(&ni->rx_errors);
				rtl_ni_qm_retire(ni, voq, cmd, refill);
				continue;
			}

			skb = napi_alloc_skb(napi, len);
			if (!skb) {
				atomic_long_inc(&ni->rx_dropped);
				rtl_ni_qm_retire(ni, voq, cmd, refill);
				continue;
			}
			skb_put_data(skb, data + hdr, len);
			rtl_ni_qm_retire(ni, voq, cmd, refill);
			rtl_ni_qm_deliver(ni, napi, skb, cmd, h0, h1, csum,
					  wifi_id, forwarded);
		}
	}

	rtl_ni_qm_refill_drain(ni, NAPI_POLL_WEIGHT);
	return count;
}
