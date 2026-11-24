#!/usr/bin/env python3
"""Compile the real FE DS-Lite/6RD flow offload, CLS 0x14 and LPB gate."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c'
regs_h = (DRIVER / 'rtl9617c_regs.h').read_text()
fe_hw_h = (DRIVER / 'fe/fe_hw.h').read_text()
fe_hw_c = (DRIVER / 'fe/fe_hw.c').read_text()
fe_priv_h = (DRIVER / 'fe/fe_priv.h').read_text()
fe_tunnel_h = (DRIVER / 'fe/fe_tunnel.h').read_text()
fe_tunnel_c = (DRIVER / 'fe/fe_tunnel.c').read_text()
fe_main_c = (DRIVER / 'fe/fe_main.c').read_text()


def grab_function(text, signature):
    start = text.index(signature)
    depth = 0
    seen = False
    for i in range(start, len(text)):
        ch = text[i]
        if ch == '{':
            depth += 1
            seen = True
        elif ch == '}':
            depth -= 1
            if seen and depth == 0:
                return text[start:i + 1]
    raise AssertionError('unterminated function: ' + signature)


def grab_define(text, name):
    m = re.search(r'^#define\s+' + re.escape(name) + r'(?:\([^)]*\))?[ \t]+[^\n]*(?:\\\n[^\n]*)*',
                  text, re.M)
    if not m:
        raise AssertionError('missing define: ' + name)
    return m.group(0)


defines = []
for name in ('RTL_NI_INDIRECT_BUSY', 'RTL_NI_INDIRECT_BUSY_LOW',
             'RTL_NI_INDIRECT_ACCESS', 'RTL_NI_INDIRECT_WRITE',
             'RTL_FE_INTERFACE_CMD', 'RTL_FE_INTERFACE_DATA',
             'RTL_FE_CLASSIFIER_CMD', 'RTL_FE_CLASSIFIER_DATA',
             'RTL_FE_LPB_CFG', 'RTL_FE_LPB_PROFILE', 'RTL_FE_LPB_TABLE'):
    defines.append(grab_define(regs_h, name))

for line in fe_hw_h.splitlines():
    if (line.startswith('#define RTL_FE_CLS_') or
            line.startswith('#define RTL_FE_PP_DUAL_') or
            line.startswith('#define RTL_FE_L3PP_L2TP_') or
            line.startswith('#define RTL_FE_L3PE_') or
            line.startswith('#define RTL_FE_LPB_') or
            line.startswith('#define RTL_FE_CLASSIFIER_') or
            line.startswith('#define RTL_FE_DUAL_') or
            line.startswith('#define RTL_FE_CACHE_') or
            line.startswith('#define RTL_FE_SYNC_') or
            line.startswith('#define RTL_FE_FDB_')):
        defines.append(line)

for name in ('FE_INTERFACES', 'FE_COUNTERS', 'FE_LPB_ENTRIES',
             'FE_SOURCE_P6', 'FE_SOURCE_PON'):
    defines.append(grab_define(fe_priv_h, name))

for line in fe_tunnel_h.splitlines():
    if (line.startswith('#define RTL_FE_DUAL_') or
            line.startswith('#define RTL_FE_PPP_TUN_') or
            line.startswith('#define RTL_FE_EIF_')):
        defines.append(line)

for name in ('FE_CLASSIFIER_BASE', 'FE_MAP_BASE', 'FE_MAP_SIDES',
             'FE_LPB_SIDES', 'FE_INTERFACE_INIT', 'FE_INTERFACE_SMAC_SHIFT'):
    defines.append(grab_define(fe_main_c, name))

# Extract CLS helpers & constants from fe_hw.c.
cls_hw_start = fe_hw_c.index('#define RTL_FE_CLS_LOW_MASK(')
cls_hw_end = fe_hw_c.index('int rtl_fe_smac_read(')
cls_hw_code = fe_hw_c[cls_hw_start:cls_hw_end]

# Extract dual-header core & dual_hdr param helper from fe_tunnel.c.
tun_start = fe_tunnel_c.index('/* --- testable core ---')
tun_end = fe_tunnel_c.index('/* --- debugfs --- */')
tun_core_code = fe_tunnel_c[tun_start:tun_end]
tun_flag_block = (
    'static bool rtl_fe_tunnel_flow_enable;\n' +
    grab_function(fe_tunnel_c, 'bool rtl_fe_tunnel_flow_enabled(') + '\n' +
    'static bool rtl_fe_vpn_offload_enable = true;\n' +
    grab_function(fe_tunnel_c, 'bool rtl_fe_vpn_offload_enabled(') + '\n'
)

hw_helpers = '\n\n'.join((
    grab_function(fe_hw_c, 'void rtl_fe_bits_set('),
    grab_function(fe_hw_c, 'void rtl_fe_classify_hash('),
    grab_function(fe_hw_c, 'void rtl_fe_ingress_lpb('),
    grab_function(fe_hw_c, 'static int rtl_fe_table_read('),
    grab_function(fe_hw_c, 'static int rtl_fe_table_write('),
))

main_helpers = '\n\n'.join((
    grab_function(fe_main_c, 'static void rtl_fe_save_dual_hdr('),
    grab_function(fe_main_c, 'static void rtl_fe_write_l2tp_sport('),
    grab_function(fe_main_c, 'static void rtl_fe_program_dual_hdr('),
    grab_function(fe_main_c, 'static int rtl_fe_setup_lpb('),
    grab_function(fe_main_c, 'static u32 rtl_fe_interface_value('),
    grab_function(fe_main_c, 'static int rtl_fe_interface_bind_slot('),
    grab_function(fe_main_c, 'static int rtl_fe_interface_get('),
    grab_function(fe_main_c, 'static int rtl_fe_interface_put('),
    grab_function(fe_main_c, 'static void rtl_fe_l2tp_sport_put('),
    grab_function(fe_main_c, 'static int rtl_fe_tunnel_teardown('),
    grab_function(fe_main_c, 'static u16 rtl_fe_tunnel_busy_phys_mask('),
    grab_function(fe_main_c, 'static int rtl_fe_l2tp_sport_get('),
    grab_function(fe_main_c, 'static int rtl_fe_install_tunnel_cls('),
    grab_function(fe_main_c, 'static bool rtl_fe_tunnel_type_enabled('),
    grab_function(fe_main_c, 'static int rtl_fe_install_tunnel('),
))

prefix = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELD_PREP(mask, val) (((u32)(val) << __builtin_ctz(mask)) & (mask))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define BIT(n) (1UL << (n))
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (63 - (h))))
#define READ_ONCE(x) (x)

/* Unused indirect command placeholders referenced only by register comparison. */
#define RTL_FE_CACHE_CMD 0x3900
#define RTL_FE_SYNC_CMD 0x3904

struct mutex { int unused; };
#define mutex_lock(m) do { (void)(m); } while (0)
#define mutex_unlock(m) do { (void)(m); } while (0)
static inline void udelay(unsigned int usec) { (void)usec; }
static inline void wmb(void) { }
static inline void rmb(void) { }

enum rtl_fe_dual_type {
	RTL_FE_DUAL_TYPE_NONE = 0,
	RTL_FE_DUAL_TYPE_IP4INIP6 = 1,
	RTL_FE_DUAL_TYPE_VXLAN = 6,
	RTL_FE_DUAL_TYPE_6RD = 7,
	RTL_FE_DUAL_TYPE_MAPT = 8,
	RTL_FE_DUAL_TYPE_L2TP = 9,
	RTL_FE_DUAL_TYPE_PPTP = 10,
};
#define RTL_FE_DUAL_OWNER_NONE 0
#define RTL_FE_DUAL_OWNER_DEBUGFS 1
#define RTL_FE_DUAL_OWNER_FLOW 2

enum rtl_fe_rule_kind {
	RTL_FE_RULE_IPV4,
	RTL_FE_RULE_IPV6,
	RTL_FE_RULE_BRIDGE,
};

struct rtl_fe_port {
	unsigned int source;
};

struct rtl_fe_rule {
	enum rtl_fe_rule_kind kind;
	struct rtl_fe_port *input;
	u8 tunnel_type;
	bool tunnel_decap;
	u8 tunnel_af;
	u8 tunnel_ppp_len;
	u8 tunnel_flags;
	u16 tunnel_sport;
	u16 tunnel_dport;
	u16 tunnel_tid;
	u16 tunnel_sid;
	u16 tunnel_peer_tid;
	u16 tunnel_peer_sid;
	u32 tunnel_gre_seq;
	u32 tunnel_gre_ack;
	u8 tunnel_src[16];
	u8 tunnel_dst[16];
};

struct rtl_fe_interface {
	unsigned int source_mac;
	unsigned int pppoe;
	unsigned int users;
	bool counted;
	u32 saved;
};

struct rtl_fe_flow {
	unsigned int counter;
	unsigned int source_mac;
	unsigned int pppoe;
	bool interface_owned;
	bool tunnel_owned;
	u8 dual_index;
	u16 l2tp_alt_sport;
	bool counted;
};

struct rtl_fe_dual_slot { unsigned char owner; unsigned char type; };

struct rtl_fe_dual_control {
	u32 rep_ip_len_diff_pad_ctrl;
	u32 rep_len_diff1_pad_ctrl;
	u32 rep_len_diff2_pad_ctrl;
	u32 hdr_fmt;
	u32 hdr_len;
	u32 mtu_diff;
	u32 ppp_ip_ver_ost;
	u32 rep_ip_en;
	u32 rep_ip_ver;
	u32 rep_len_ost1;
	u32 rep_len_diff1;
	u32 rep_len_ost2;
	u32 rep_len_diff2;
	u32 ip4_ost;
	u32 gre_seq_ack_ost;
	u32 gre_mod_fld;
	u32 ip6_oft;
	u32 rep_ip_dscp_en;
	u32 rep_ip_ecn_en;
	u32 rep_ip_len;
	u32 rep_ip_len_diff;
	u32 rep_ip_ptc;
	u32 rep_ip_ttl;
	u32 mapt_pre_len;
	u32 map_drf_ver;
	u32 sixrd_dip_pre_len;
	u32 sixrd_dip_suf_str_bit;
	u32 dsl_uc_chk;
	u32 dsl_mc_chk;
	u32 l4sum_rec;
	u32 vxlan_sp_ost;
	u32 inr_to_out_fld;
	u32 tos_hsh_sel;
	u32 mc_mac_map;
};

struct rtl_fe_dual_fmr {
	u64 prefix;
	u32 psid_str_ost;
	u32 psid_end_ost;
	u32 psid_refill;
	u32 pref_len;
	u32 drf_ver;
};

struct rtl_fe_eif_slot {
	u32 param_hash;
	u8 hash;
	u8 phys;
	u8 refs;
	bool used;
};

struct rtl_fe_tunnel_session {
	bool active;
	bool decap;
	bool cls_active;
	enum rtl_fe_dual_type type;
	u8 af;
	u8 ppp_len;
	u8 flags;
	u16 sport;
	u16 dport;
	u16 tid;
	u16 sid;
	u16 peer_tid;
	u16 peer_sid;
	unsigned int refs;
	unsigned int cls_profile;
	unsigned int cls_index;
	u32 param_hash;
	u8 src[RTL_FE_DUAL_DSLITE_ADDR_LEN];
	u8 dst[RTL_FE_DUAL_DSLITE_ADDR_LEN];
};

struct rtl_fe_tunnel_key {
	enum rtl_fe_dual_type type;
	bool decap;
	u8 af;
	u8 ppp_len;
	u8 flags;
	u16 sport;
	u16 dport;
	u16 tid;
	u16 sid;
	u16 peer_tid;
	u16 peer_sid;
	u32 gre_seq;
	u32 gre_ack;
	unsigned int cls_profile;
	u32 param_hash;
	u8 src[RTL_FE_DUAL_DSLITE_ADDR_LEN];
	u8 dst[RTL_FE_DUAL_DSLITE_ADDR_LEN];
};

struct rtl_fe_tunnel_binding {
	unsigned int dual_index;
	unsigned int hash_eif;
	unsigned int phys_eif;
	unsigned int cls_index;
	bool need_cls_program;
};

struct rtl_fe_tunnel {
	struct rtl_fe *fe;
	struct mutex lock;
	unsigned long content[1];
	unsigned long control[1];
	unsigned long fmr[1];
	unsigned long cls_pairs[RTL_FE_DUAL_CLS_PROFILES][1];
	struct rtl_fe_dual_slot content_slot[16];
	struct rtl_fe_dual_slot control_slot[16];
	struct rtl_fe_dual_slot fmr_slot[3];
	struct rtl_fe_eif_slot eif[64];
	struct rtl_fe_tunnel_session sessions[16];
	bool ready;
	char last[1024];
};

struct mock {
	u32 dual_window[16];
	u32 dual_content[16][16];
	u32 dual_control[16][16];
	u32 dual_fmr[3][16];
	u32 cls_window[RTL_FE_CLS_KEY_WORDS];
	u32 cls_key[RTL_FE_CLS_KEY_ENTRIES][RTL_FE_CLS_KEY_WORDS];
	u32 fib_window[RTL_FE_CLASSIFIER_WORDS];
	u32 fib[2048][RTL_FE_CLASSIFIER_WORDS];
	u32 eif_window;
	u32 eif[FE_INTERFACES];
	u32 lpb[4][FE_LPB_SIDES];
	u32 lpb_cfg;
	u32 lpb_profile;
	u32 map[2][FE_MAP_SIDES];
	u32 dual_dos_en;
	bool dual_dos_written;
	u32 l2tp_sport;
	u32 gre_ack[16];
	u32 gre_seq[16];
	u32 ipv4_id[16];
	bool lpb3_written;
	u32 indirect_ops[64];
	unsigned int indirect_n;
	int dual_fail_after;
	int indirect_fail_after;
	int fail_cls_key_idx;
};

struct rtl_fe {
	struct mock *mock;
	struct rtl_fe_tunnel *tunnel;
	struct rtl_fe_interface interfaces[FE_INTERFACES];
	unsigned long counters[1];
	u32 lpb3_saved[RTL_FE_LPB_WORDS];
	u32 dual_dos_saved;
	u32 l2tp_sport_saved;
	u16 l2tp_alt_sport;
	unsigned int l2tp_alt_refs;
	bool dual_hdr_active;
};

static int test_bit(unsigned int nr, const unsigned long *addr)
{
	return !!(addr[nr / 64] & (1UL << (nr % 64)));
}

static void __set_bit(unsigned int nr, unsigned long *addr)
{
	addr[nr / 64] |= 1UL << (nr % 64);
}

static void __clear_bit(unsigned int nr, unsigned long *addr)
{
	addr[nr / 64] &= ~(1UL << (nr % 64));
}

static unsigned long find_first_zero_bit(const unsigned long *addr,
					 unsigned long size)
{
	unsigned long i;

	for (i = 0; i < size; i++)
		if (!(addr[i / 64] & (1UL << (i % 64))))
			return i;
	return size;
}

static u32 rtl_fe_read(struct rtl_fe *fe, unsigned int reg)
{
	struct mock *m = fe->mock;
	unsigned int idx;

	if (reg == RTL_FE_DUAL_CMD) {
		if (m->dual_fail_after == 0)
			return RTL_FE_DUAL_BUSY;
		if (m->dual_fail_after > 0)
			m->dual_fail_after--;
		return 0;
	}
	if (reg >= 0x354c && reg <= 0x3588)
		return m->dual_window[(0x3588 - reg) / 4];
	if (reg >= 0x3384 && reg <= RTL_FE_CLS_KEY_DATA)
		return m->cls_window[(RTL_FE_CLS_KEY_DATA - reg) / 4];
	if (reg >= 0x33b4 && reg <= RTL_FE_CLASSIFIER_DATA)
		return m->fib_window[(RTL_FE_CLASSIFIER_DATA - reg) / 4];
	if (reg == RTL_FE_INTERFACE_DATA)
		return m->eif_window;
	if (reg == RTL_FE_PP_DUAL_DOS_EN)
		return m->dual_dos_en;
	if (reg == RTL_FE_L3PP_L2TP_SPORT)
		return m->l2tp_sport;
	if (reg >= RTL_FE_L3PE_GRE_ACK(0) && reg <= RTL_FE_L3PE_GRE_ACK(15))
		return m->gre_ack[(reg - RTL_FE_L3PE_GRE_ACK(0)) / 4];
	if (reg >= RTL_FE_L3PE_GRE_SEQ(0) && reg <= RTL_FE_L3PE_GRE_SEQ(15))
		return m->gre_seq[(reg - RTL_FE_L3PE_GRE_SEQ(0)) / 4];
	if (reg >= RTL_FE_L3PE_IPV4_ID(0) && reg <= RTL_FE_L3PE_IPV4_ID(15))
		return m->ipv4_id[(reg - RTL_FE_L3PE_IPV4_ID(0)) / 4];
	if (reg >= RTL_FE_LPB_TABLE(0, 0) && reg <= RTL_FE_LPB_TABLE(2, 2)) {
		idx = (reg - RTL_FE_LPB_TABLE(0, 0)) / 4;
		return m->lpb[1 + idx / 3][idx % 3];
	}
	if (reg == RTL_FE_LPB_CFG)
		return m->lpb_cfg;
	if (reg == RTL_FE_LPB_PROFILE)
		return m->lpb_profile;
	assert(0);
	return 0;
}

static void rtl_fe_write(struct rtl_fe *fe, unsigned int reg, u32 val)
{
	struct mock *m = fe->mock;
	unsigned int idx, sel;

	if (reg == RTL_FE_DUAL_CMD) {
		idx = val & RTL_FE_DUAL_INDEX_MASK;
		sel = val & (RTL_FE_DUAL_SEL_CONTROL | RTL_FE_DUAL_SEL_FMR);
		if (val & RTL_FE_DUAL_WRITE) {
			if (sel == RTL_FE_DUAL_SEL_CONTROL)
				memcpy(m->dual_control[idx], m->dual_window, 64);
			else if (sel == RTL_FE_DUAL_SEL_FMR)
				memcpy(m->dual_fmr[idx & 7], m->dual_window, 64);
			else
				memcpy(m->dual_content[idx], m->dual_window, 64);
		} else {
			if (sel == RTL_FE_DUAL_SEL_CONTROL)
				memcpy(m->dual_window, m->dual_control[idx], 64);
			else if (sel == RTL_FE_DUAL_SEL_FMR)
				memcpy(m->dual_window, m->dual_fmr[idx & 7], 64);
			else
				memcpy(m->dual_window, m->dual_content[idx], 64);
		}
		return;
	}
	if (reg >= 0x354c && reg <= 0x3588) {
		m->dual_window[(0x3588 - reg) / 4] = val;
		return;
	}
	if (reg >= 0x3384 && reg <= RTL_FE_CLS_KEY_DATA) {
		m->cls_window[(RTL_FE_CLS_KEY_DATA - reg) / 4] = val;
		return;
	}
	if (reg >= 0x33b4 && reg <= RTL_FE_CLASSIFIER_DATA) {
		m->fib_window[(RTL_FE_CLASSIFIER_DATA - reg) / 4] = val;
		return;
	}
	if (reg == RTL_FE_INTERFACE_DATA) {
		m->eif_window = val;
		return;
	}
	if (reg == RTL_FE_PP_DUAL_DOS_EN) {
		m->dual_dos_en = val;
		m->dual_dos_written = true;
		return;
	}
	if (reg == RTL_FE_L3PP_L2TP_SPORT) {
		m->l2tp_sport = val;
		return;
	}
	if (reg >= RTL_FE_L3PE_GRE_ACK(0) && reg <= RTL_FE_L3PE_GRE_ACK(15)) {
		m->gre_ack[(reg - RTL_FE_L3PE_GRE_ACK(0)) / 4] = val;
		return;
	}
	if (reg >= RTL_FE_L3PE_GRE_SEQ(0) && reg <= RTL_FE_L3PE_GRE_SEQ(15)) {
		m->gre_seq[(reg - RTL_FE_L3PE_GRE_SEQ(0)) / 4] = val;
		return;
	}
	if (reg >= RTL_FE_L3PE_IPV4_ID(0) && reg <= RTL_FE_L3PE_IPV4_ID(15)) {
		m->ipv4_id[(reg - RTL_FE_L3PE_IPV4_ID(0)) / 4] = val;
		return;
	}
	if (reg >= RTL_FE_LPB_TABLE(0, 0) && reg <= RTL_FE_LPB_TABLE(2, 2)) {
		idx = (reg - RTL_FE_LPB_TABLE(0, 0)) / 4;
		m->lpb[1 + idx / 3][idx % 3] = val;
		if (1 + idx / 3 == 3)
			m->lpb3_written = true;
		return;
	}
	if (reg == RTL_FE_LPB_PROFILE) {
		m->lpb_profile = val;
		return;
	}
	assert(0);
}

static void rtl_fe_rmw(struct rtl_fe *fe, unsigned int reg, u32 clear, u32 set)
{
	u32 val = rtl_fe_read(fe, reg);
	if (reg == RTL_FE_LPB_CFG)
		fe->mock->lpb_cfg = (val & ~clear) | set;
	else
		rtl_fe_write(fe, reg, (val & ~clear) | set);
}

static int rtl_fe_indirect(struct rtl_fe *fe, unsigned int reg, u32 cmd)
{
	struct mock *m = fe->mock;
	unsigned int idx;
	bool write = !!(cmd & RTL_NI_INDIRECT_WRITE);

	if (m->indirect_n < 64)
		m->indirect_ops[m->indirect_n++] = (reg << 16) | (write ? 0x8000U : 0) | (cmd & 0x3fffU);
	if (m->indirect_fail_after == 0)
		return -ETIMEDOUT;
	if (m->indirect_fail_after > 0)
		m->indirect_fail_after--;

	if (reg == RTL_FE_CLS_KEY_CMD) {
		idx = cmd & 0xffU;
		assert(idx < RTL_FE_CLS_KEY_ENTRIES);
		if (m->fail_cls_key_idx >= 0 && (int)idx == m->fail_cls_key_idx && write)
			return -ETIMEDOUT;
		if (write)
			memcpy(m->cls_key[idx], m->cls_window, sizeof(m->cls_window));
		else
			memcpy(m->cls_window, m->cls_key[idx], sizeof(m->cls_window));
		return 0;
	}
	if (reg == RTL_FE_CLASSIFIER_CMD) {
		idx = cmd & 0x7ffU;
		assert(idx < 2048);
		if (write)
			memcpy(m->fib[idx], m->fib_window, sizeof(m->fib_window));
		else
			memcpy(m->fib_window, m->fib[idx], sizeof(m->fib_window));
		return 0;
	}
	if (reg == RTL_FE_INTERFACE_CMD) {
		idx = cmd & 0x1fU;
		assert(idx < FE_INTERFACES);
		if (write)
			m->eif[idx] = m->eif_window;
		else
			m->eif_window = m->eif[idx];
		return 0;
	}
	assert(0);
	return -EINVAL;
}

static int rtl_fe_map_write(struct rtl_fe *fe, unsigned int index, u32 value)
{
	fe->mock->map[index & 1][index >> 6] = value;
	return 0;
}

/* Prototypes needed before tun_core_code / main_helpers */
int rtl_fe_classifier_write(struct rtl_fe *fe, unsigned int index,
			    const u32 words[RTL_FE_CLASSIFIER_WORDS]);
int rtl_fe_cls_write_6rd(struct rtl_fe *fe, unsigned int key_index,
			 const u8 outer_sa[4], const u8 outer_da[4],
			 unsigned int igr_l3_if_idx);
int rtl_fe_cls_write_dslite(struct rtl_fe *fe, unsigned int key_index,
			    const u8 outer_sa[16], unsigned int igr_l3_if_idx);
int rtl_fe_cls_write_l2tp(struct rtl_fe *fe, unsigned int key_index,
			  bool is_ipv6, const u8 outer_da[16],
			  u16 tid, u16 sid, unsigned int igr_l3_if_idx);
int rtl_fe_cls_write_pptp(struct rtl_fe *fe, unsigned int key_index,
			  bool is_ipv6, const u8 outer_da[16],
			  u16 call_id, unsigned int igr_l3_if_idx);
int rtl_fe_cls_clear_pair(struct rtl_fe *fe, unsigned int key_index);
bool rtl_fe_tunnel_phys_busy(struct rtl_fe *fe, unsigned int phys);
int rtl_fe_tunnel_flow_get(struct rtl_fe *fe,
			   const struct rtl_fe_tunnel_key *key,
			   u16 busy_phys_mask,
			   struct rtl_fe_tunnel_binding *binding);
int rtl_fe_tunnel_flow_mark_cls(struct rtl_fe *fe, unsigned int dual_index);
int rtl_fe_tunnel_flow_cls_info(struct rtl_fe *fe, unsigned int dual_index,
				bool *is_last, bool *cls_active,
				unsigned int *cls_index);
void rtl_fe_tunnel_flow_cls_cleared(struct rtl_fe *fe, unsigned int dual_index);
int rtl_fe_tunnel_flow_put(struct rtl_fe *fe, unsigned int dual_index);
'''

tests = r'''
static void setup(struct rtl_fe *fe, struct rtl_fe_tunnel *t, struct mock *m)
{
	unsigned int i;

	memset(fe, 0, sizeof(*fe));
	memset(t, 0, sizeof(*t));
	memset(m, 0, sizeof(*m));
	fe->mock = m;
	fe->tunnel = t;
	t->fe = fe;
	t->ready = true;
	m->dual_dos_en = 0xdeadbeefU;
	m->lpb[3][0] = 0x11111111U;
	m->lpb[3][1] = 0x22222222U;
	m->lpb[3][2] = 0x33333333U;
	for (i = 0; i < FE_INTERFACES; i++)
		m->eif[i] = 0xa0000000U | i;
	m->dual_fail_after = -1;
	m->indirect_fail_after = -1;
	m->fail_cls_key_idx = -1;
}

static void test_cls_vectors_and_order(void)
{
	/* Exact 22-word KEY7 (DS-Lite) and KEY6 (6RD) vectors verified against
	 * ca-ne.ko + fc_8277c.ko (AArch64 emulation of aal_l3_cls_add).
	 */
	static const u8 dsl_sa[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01
	};
	static const u8 sixrd_sa[4] = { 0x11, 0x22, 0x33, 0x44 };
	static const u8 sixrd_da[4] = { 0x55, 0x66, 0x77, 0x88 };
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	u32 even[RTL_FE_CLS_KEY_WORDS], odd[RTL_FE_CLS_KEY_WORDS];
	u32 fib0[RTL_FE_CLASSIFIER_WORDS], fib1[RTL_FE_CLASSIFIER_WORDS];
	unsigned int i, fib_idx;

	setup(&fe, &t, &m);
	rtl_fe_cls_pack_dslite(even, odd, dsl_sa);
	assert(even[0] == 0xffffffffU);
	assert(even[1] == 0xffffffffU);
	assert(even[2] == 0x1fffff0fU);
	assert(even[3] == 0x407ffffeU);
	assert(even[4] == 0xddeeff01U);
	assert(even[5] == 0x99aabbccU);
	assert(even[6] == 0x55667788U);
	assert(even[7] == 0x11223344U);
	assert(even[8] == 0xffffffffU);
	assert(even[9] == 0x0001ffffU);
	assert(even[10] == 0x0f380000U);
	assert(odd[0] == 0xffffffffU && odd[1] == 0xffffffffU &&
	       odd[2] == 0xffffffffU && odd[3] == 0xffffffffU &&
	       odd[4] == 0xffffffffU);
	assert(odd[5] == 0xffffffffU && odd[6] == 0xfffffff7U &&
	       odd[7] == 0x0480007fU && odd[8] == 0x001fff80U);
	assert(odd[9] == 0U && odd[10] == 0U);

	rtl_fe_cls_pack_6rd(even, odd, sixrd_sa, sixrd_da);
	assert(even[0] == 0xffffffffU);
	assert(even[1] == 0x1e0fffffU);
	assert(even[2] == 0x599de204U);
	assert(even[3] == 0x00000015U);
	assert(even[4] == 0U && even[5] == 0U);
	assert(even[6] == 0x19a20800U);
	assert(even[7] == 0x00000891U);
	assert(even[8] == 0U && even[9] == 0U);
	assert(even[10] == 0x0e380000U);
	for (i = 0; i <= 4; i++)
		assert(odd[i] == 0xffffffffU);
	assert(odd[5] == 0xbfffffffU);
	assert(odd[6] == 0xffffffffU);
	assert(odd[7] == 0x00280003U);
	assert(odd[8] == 0x07fffffcU);
	assert(odd[9] == 0U && odd[10] == 0U);

	/* FIB0 preserves incoming lspid (bit 208=0), routes to mcgid=16 (bit 158)
	 * and sets IGR EIF 35.
	 */
	rtl_fe_cls_pack_dual_fib(fib0, fib1, 35);
	assert((((fib0[4] >> 30) | (fib0[5] << 2)) & 0x3ffU) == 16U);
	assert(((fib0[5] >> 29) & 1U) == 1U); /* bit 189 igr_l3_if_idx_vld */
	assert((((fib0[5] >> 30) | (fib0[6] << 2)) & 0x3fU) == 35U); /* bits 195:190 */
	assert(((fib0[6] >> 16) & 1U) == 0U); /* bit 208 lspid_vld cleared */
	for (i = 0; i < RTL_FE_CLASSIFIER_WORDS; i++)
		assert(fib1[i] == 0U);

	/* Write ordering: FIB0 (524), FIB1 (525), ODD (131), EVEN (130). */
	m.indirect_n = 0;
	fib_idx = rtl_fe_cls_dual_fib_index(130);
	assert(fib_idx == 524);
	assert(rtl_fe_cls_write_6rd(&fe, 130, sixrd_sa, sixrd_da, 35) == 0);
	assert(m.indirect_n == 4);
	assert(m.indirect_ops[0] == ((RTL_FE_CLASSIFIER_CMD << 16) | 0x8000U | fib_idx));
	assert(m.indirect_ops[1] == ((RTL_FE_CLASSIFIER_CMD << 16) | 0x8000U | (fib_idx + 1)));
	assert(m.indirect_ops[2] == ((RTL_FE_CLS_KEY_CMD << 16) | 0x8000U | 131U));
	assert(m.indirect_ops[3] == ((RTL_FE_CLS_KEY_CMD << 16) | 0x8000U | 130U));
	assert((m.cls_key[130][10] & (1U << 27)) != 0);

	/* Clear ordering: EVEN zeroed first before ODD and FIB0/FIB1. */
	m.indirect_n = 0;
	assert(rtl_fe_cls_clear_pair(&fe, 130) == 0);
	assert(m.indirect_n == 4);
	assert(m.indirect_ops[0] == ((RTL_FE_CLS_KEY_CMD << 16) | 0x8000U | 130U));
	assert(m.indirect_ops[1] == ((RTL_FE_CLS_KEY_CMD << 16) | 0x8000U | 131U));
	assert(m.indirect_ops[2] == ((RTL_FE_CLASSIFIER_CMD << 16) | 0x8000U | fib_idx));
	assert(m.indirect_ops[3] == ((RTL_FE_CLASSIFIER_CMD << 16) | 0x8000U | (fib_idx + 1)));

	/* If writing EVEN fails, ODD must be wiped clean too. */
	setup(&fe, &t, &m);
	m.fail_cls_key_idx = 0;
	assert(rtl_fe_cls_write_dslite(&fe, 0, dsl_sa, 32) == -ETIMEDOUT);
	assert(m.cls_key[1][0] == 0U && m.cls_key[0][10] == 0U);
}

static void test_lpb_and_dual_dos_gating(void)
{
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	u32 expected_lpb3[RTL_FE_LPB_WORDS];

	/* Default (dual_hdr=0): 0x3348 and LPB_TBL_3 are completely untouched. */
	setup(&fe, &t, &m);
	rtl_fe_tunnel_flow_enable = false;
	fe.dual_hdr_active = rtl_fe_tunnel_flow_enabled();
	assert(!fe.dual_hdr_active);
	assert(rtl_fe_setup_lpb(&fe) == 0);
	assert(!m.dual_dos_written && !m.lpb3_written);
	assert(m.dual_dos_en == 0xdeadbeefU);
	assert(m.lpb[3][0] == 0x11111111U && m.lpb[3][1] == 0x22222222U &&
	       m.lpb[3][2] == 0x33333333U);
	/* LPB_TBL_1 (Eth) = profile 1, LPB_TBL_2 (PON) = profile 0. */
	assert(((m.lpb[1][1] >> (42 - 32)) & 0xfU) == 1U);
	assert(((m.lpb[2][1] >> (42 - 32)) & 0xfU) == 0U);

	/* Opt-in (dual_hdr=1): saves originals and arms 0x3348 + LPB_TBL_3. */
	setup(&fe, &t, &m);
	rtl_fe_tunnel_flow_enable = true;
	fe.dual_hdr_active = rtl_fe_tunnel_flow_enabled();
	rtl_fe_save_dual_hdr(&fe);
	assert(rtl_fe_setup_lpb(&fe) == 0);
	assert(fe.dual_dos_saved == 0xdeadbeefU);
	assert(fe.lpb3_saved[0] == 0x11111111U &&
	       fe.lpb3_saved[1] == 0x22222222U &&
	       fe.lpb3_saved[2] == 0x33333333U);
	assert(m.dual_dos_written && m.lpb3_written);
	assert(m.dual_dos_en == RTL_FE_PP_DUAL_DOS_EN_ALL);
	rtl_fe_ingress_lpb(expected_lpb3, 0, RTL_FE_CLS_MCGID_L3FE);
	rtl_fe_bits_set(expected_lpb3, RTL_FE_LPB_CLS_PROFILE_BIT,
			RTL_FE_LPB_CLS_PROFILE_WIDTH, 1);
	assert(memcmp(m.lpb[3], expected_lpb3, sizeof(expected_lpb3)) == 0);
}

static void test_dslite_6rd_flow_lifecycle(void)
{
	static const u8 dsl_br[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				       0, 0, 0, 0, 0, 0, 0, 0xfe };
	static const u8 dsl_ce[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				       0, 0, 0, 0, 0, 0, 0, 0x01 };
	static const u8 rd_br[4] = { 198, 51, 100, 2 };
	static const u8 rd_ce[4] = { 203, 0, 113, 1 };
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	struct rtl_fe_port port_pon = { .source = FE_SOURCE_PON };
	struct rtl_fe_port port_eth = { .source = 0 };
	struct rtl_fe_port port_p6 = { .source = FE_SOURCE_P6 };
	struct rtl_fe_rule rule = { };
	struct rtl_fe_flow f_dsl_dec_pon = { }, f_dsl_dec_eth = { };
	struct rtl_fe_flow f_dsl_enc1 = { }, f_dsl_enc2 = { }, f_dsl_enc3 = { };
	struct rtl_fe_flow f_6rd_dec = { }, f_6rd_enc = { };
	struct rtl_fe_flow f_norm[20] = { };
	struct rtl_fe_tunnel_binding b = { };
	unsigned int i;

	/* Enable runtime lazy activation from dual_hdr_active == false. */
	setup(&fe, &t, &m);
	rtl_fe_tunnel_flow_enable = true;

	/* 1. DS-Lite DECAP from PON -> cls_profile=0 (CAM 0), dual_idx=0, LAN EIF=0. */
	rule.kind = RTL_FE_RULE_IPV4;
	rule.input = &port_pon;
	rule.tunnel_type = RTL_FE_DUAL_TYPE_IP4INIP6;
	rule.tunnel_decap = true;
	memcpy(rule.tunnel_src, dsl_br, 16);
	memcpy(rule.tunnel_dst, dsl_ce, 16);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_dsl_dec_pon, &b) == 0);
	assert(fe.dual_hdr_active && m.dual_dos_en == RTL_FE_PP_DUAL_DOS_EN_ALL);
	assert(fe.dual_dos_saved == 0xdeadbeefU && m.lpb3_written);
	assert(b.dual_index == 0 && b.hash_eif == 32 && b.phys_eif == 16);
	assert(b.cls_index == 0);
	assert(f_dsl_dec_pon.tunnel_owned && f_dsl_dec_pon.interface_owned);
	assert(f_dsl_dec_pon.counter == 0);
	assert((m.cls_key[0][10] & (1U << 27)) != 0);
	assert((((m.fib[4][5] >> 30) | (m.fib[4][6] << 2)) & 0x3fU) == 32U);

	/* 2. DS-Lite DECAP from Eth WAN (port 0) -> cls_profile=1 (CAM 128), dual_idx=1, LAN EIF=1. */
	rule.input = &port_eth;
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_dsl_dec_eth, &b) == 0);
	assert(b.dual_index == 1 && b.hash_eif == 33 && b.phys_eif == 17);
	assert(b.cls_index == 128);
	assert(f_dsl_dec_eth.counter == 1);
	assert((m.cls_key[128][10] & (1U << 27)) != 0);
	assert((((m.fib[rtl_fe_cls_dual_fib_index(128)][5] >> 30) |
		 (m.fib[rtl_fe_cls_dual_fib_index(128)][6] << 2)) & 0x3fU) == 33U);

	/* 3. Normal EIF exhaustion fills 2..15 first, skips tunnel rows 16 & 17, gets 18! */
	for (i = 0; i < 15; i++) {
		f_norm[i].source_mac = i % 14;
		f_norm[i].pppoe = 3U | ((0x200 + i) << 2);
		assert(rtl_fe_interface_get(&fe, &f_norm[i]) == 0);
	}
	assert(f_norm[0].counter == 2);
	assert(f_norm[13].counter == 15);
	assert(f_norm[14].counter == 18); /* Skips 16 and 17! */

	/* 4. DS-Lite ENCAP from LAN (sid upper bits 0x4567) skips busy 16,17,18 -> dual_idx=3! */
	memset(&rule, 0, sizeof(rule));
	rule.kind = RTL_FE_RULE_IPV4;
	rule.input = &port_eth;
	rule.tunnel_type = RTL_FE_DUAL_TYPE_IP4INIP6;
	rule.tunnel_decap = false;
	memcpy(rule.tunnel_src, dsl_ce, 16);
	memcpy(rule.tunnel_dst, dsl_br, 16);
	f_dsl_enc1.source_mac = 2;
	f_dsl_enc1.pppoe = 3U | (0x4567U << 2);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_dsl_enc1, &b) == 0);
	assert(b.dual_index == 3 && b.hash_eif == 35 && b.phys_eif == 19);
	assert(f_dsl_enc1.counter == 19 && f_dsl_enc1.interface_owned);
	assert(m.eif[19] == rtl_fe_interface_value(&f_dsl_enc1));
	assert(m.dual_content[3][0] == RTL_FE_DUAL_DSLITE_WORD0);

	/* Same SMAC+PPPoE+outer IPs reuses dual_idx=3 and physical EIF 19. */
	f_dsl_enc2.source_mac = 2;
	f_dsl_enc2.pppoe = 3U | (0x4567U << 2);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_dsl_enc2, &b) == 0);
	assert(b.dual_index == 3 && fe.interfaces[19].users == 2 &&
	       t.sessions[3].refs == 2);

	/* Differing only in upper PPPoE sid bits (0x8567 vs 0x4567) must NOT collide! */
	f_dsl_enc3.source_mac = 2;
	f_dsl_enc3.pppoe = 3U | (0x8567U << 2);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_dsl_enc3, &b) == 0);
	assert(b.dual_index == 4 && b.hash_eif == 36 && b.phys_eif == 20);
	assert(fe.interfaces[20].users == 1);

	/* 5. Free slot 2 via normal put, then install 6RD DECAP (P6 eth -> cls_profile=1, CAM 130) & ENCAP. */
	assert(rtl_fe_interface_put(&fe, &f_norm[0]) == 0);
	assert(rtl_fe_interface_put(&fe, &f_norm[1]) == 0);
	memset(&rule, 0, sizeof(rule));
	rule.kind = RTL_FE_RULE_IPV6;
	rule.input = &port_p6;
	rule.tunnel_type = RTL_FE_DUAL_TYPE_6RD;
	rule.tunnel_decap = true;
	memcpy(rule.tunnel_src, rd_br, 4);
	memcpy(rule.tunnel_dst, rd_ce, 4);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_6rd_dec, &b) == 0);
	assert(b.dual_index == 5 && b.cls_index == 130);
	assert(f_6rd_dec.counter == 2); /* Reuses freed LAN EIF 2! */
	assert((m.cls_key[130][10] & (1U << 27)) != 0);

	rule.tunnel_decap = false;
	memcpy(rule.tunnel_src, rd_ce, 4);
	memcpy(rule.tunnel_dst, rd_br, 4);
	f_6rd_enc.source_mac = 1;
	f_6rd_enc.pppoe = 3U | (0x1234U << 2);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_6rd_enc, &b) == 0);
	assert(b.dual_index == 6 && b.hash_eif == 38 && b.phys_eif == 22);
	assert(m.dual_content[6][0] == RTL_FE_DUAL_6RD_WORD0);
	assert(m.dual_content[6][2] == RTL_FE_DUAL_6RD_WORD2);

	/* 6. Refcounted shared teardown then timeout+retry teardown on DECAP. */
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_enc1) == 0);
	assert(!f_dsl_enc1.tunnel_owned && t.sessions[3].refs == 1 && t.sessions[3].active);
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_enc2) == 0);
	assert(!t.sessions[3].active);
	assert(rtl_fe_interface_put(&fe, &f_dsl_enc1) == 0);
	assert(rtl_fe_interface_put(&fe, &f_dsl_enc2) == 0);
	assert(m.eif[19] == (0xa0000000U | 19U));

	/* Timeout clearing CLS during teardown retains ownership for cleanup retry. */
	m.indirect_fail_after = 0;
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_dec_eth) == -ETIMEDOUT);
	assert(f_dsl_dec_eth.tunnel_owned && t.sessions[1].cls_active);
	m.indirect_fail_after = -1;
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_dec_eth) == 0);
	assert(!f_dsl_dec_eth.tunnel_owned && !t.sessions[1].active);
	assert(m.cls_key[128][10] == 0U);
	assert(rtl_fe_interface_put(&fe, &f_dsl_dec_eth) == 0);

	/* Clean remaining tunnel flows. */
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_dec_pon) == 0);
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_enc3) == 0);
	assert(rtl_fe_tunnel_teardown(&fe, &f_6rd_dec) == 0);
	assert(rtl_fe_tunnel_teardown(&fe, &f_6rd_enc) == 0);
	assert(!t.content[0] && !t.control[0] && !t.cls_pairs[0][0] && !t.cls_pairs[1][0]);

	/* Install failure in CLS write rolls back via rtl_fe_tunnel_teardown. */
	setup(&fe, &t, &m);
	memset(&rule, 0, sizeof(rule));
	rule.kind = RTL_FE_RULE_IPV4;
	rule.input = &port_pon;
	rule.tunnel_type = RTL_FE_DUAL_TYPE_IP4INIP6;
	rule.tunnel_decap = true;
	memcpy(rule.tunnel_src, dsl_br, 16);
	memcpy(rule.tunnel_dst, dsl_ce, 16);
	memset(&f_dsl_dec_pon, 0, sizeof(f_dsl_dec_pon));
	m.fail_cls_key_idx = 0;
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_dsl_dec_pon, &b) == -ETIMEDOUT);
	assert(f_dsl_dec_pon.tunnel_owned && !t.sessions[0].cls_active);
	m.fail_cls_key_idx = -1;
	assert(rtl_fe_tunnel_teardown(&fe, &f_dsl_dec_pon) == 0);
	assert(!f_dsl_dec_pon.tunnel_owned && !t.sessions[0].active &&
	       !t.content[0] && !t.control[0] && !t.cls_pairs[0][0]);
	assert(rtl_fe_interface_put(&fe, &f_dsl_dec_pon) == 0);
}

static void test_l2tp_pptp_flow_lifecycle(void)
{
	const u8 wan_ip[4] = { 10, 1, 2, 3 };
	const u8 peer1[4] = { 20, 4, 5, 6 };
	const u8 peer2[4] = { 20, 4, 5, 7 };
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	struct rtl_fe_port port_eth = { .source = 0 };
	struct rtl_fe_rule rule = { };
	struct rtl_fe_flow f_l2tp_enc = { }, f_l2tp_dec = { };
	struct rtl_fe_flow f_l2tp_busy = { }, f_pptp_enc1 = { }, f_pptp_enc2 = { };
	struct rtl_fe_flow f_pptp_dec = { };
	struct rtl_fe_tunnel_binding b = { };

	assert(rtl_fe_tunnel_type_enabled(RTL_FE_DUAL_TYPE_L2TP));
	assert(rtl_fe_tunnel_type_enabled(RTL_FE_DUAL_TYPE_PPTP));
	assert(!rtl_fe_tunnel_type_enabled(RTL_FE_DUAL_TYPE_VXLAN));

	setup(&fe, &t, &m);
	m.l2tp_sport = 0x06a506a5U;

	/* L2TP encap with alt sport 50000 -> programs L3PP_L2TP_SPORT[31:16]. */
	rule.kind = RTL_FE_RULE_IPV6;
	rule.input = &port_eth;
	rule.tunnel_type = RTL_FE_DUAL_TYPE_L2TP;
	rule.tunnel_af = AF_INET;
	rule.tunnel_ppp_len = 4;
	rule.tunnel_sport = 50000;
	rule.tunnel_dport = 1701;
	rule.tunnel_tid = 0x1111;
	rule.tunnel_sid = 0x2222;
	rule.tunnel_peer_tid = 0x3333;
	rule.tunnel_peer_sid = 0x4444;
	memcpy(rule.tunnel_src, wan_ip, 4);
	memcpy(rule.tunnel_dst, peer1, 4);
	f_l2tp_enc.source_mac = 2;
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_l2tp_enc, &b) == 0);
	assert(m.l2tp_sport == ((50000U << 16) | 1701U));
	assert(m.ipv4_id[b.dual_index] == (0x1000U + b.dual_index));

	/* Second L2TP DECAP with same alt sport shares alt_sport ref, writes KEY7 DIP. */
	rule.tunnel_decap = true;
	rule.tunnel_sport = 1701;
	rule.tunnel_dport = 50000;
	memcpy(rule.tunnel_src, peer1, 4);
	memcpy(rule.tunnel_dst, wan_ip, 4);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_l2tp_dec, &b) == 0);
	assert(fe.l2tp_alt_refs == 2);
	/* Even[4] == BE32(wan_ip), Even[5..7] == 0 (IPv4 DIP mask=32). */
	assert(m.cls_key[b.cls_index][4] == 0x0a010203U && m.cls_key[b.cls_index][5] == 0U);

	/* Third L2TP flow with different alt sport 50001 -> -EBUSY, no leak. */
	rule.tunnel_dport = 50001;
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_l2tp_busy, &b) == -EBUSY);
	assert(fe.l2tp_alt_refs == 2 && !f_l2tp_busy.l2tp_alt_sport);
	assert(rtl_fe_interface_put(&fe, &f_l2tp_busy) == 0);

	/* PPTP encap sets initial GRE_SEQ + IPV4_ID; 2nd flow reuses without overwriting GRE_SEQ. */
	memset(&rule, 0, sizeof(rule));
	rule.kind = RTL_FE_RULE_IPV4;
	rule.input = &port_eth;
	rule.tunnel_type = RTL_FE_DUAL_TYPE_PPTP;
	rule.tunnel_af = AF_INET;
	rule.tunnel_ppp_len = 2;
	rule.tunnel_flags = RTL_FE_PPP_TUN_F_SEQ;
	rule.tunnel_tid = 101;
	rule.tunnel_peer_tid = 202;
	rule.tunnel_gre_seq = 500;
	memcpy(rule.tunnel_src, wan_ip, 4);
	memcpy(rule.tunnel_dst, peer2, 4);
	f_pptp_enc1.source_mac = 3;
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_pptp_enc1, &b) == 0);
	assert(m.gre_seq[b.dual_index] == 500U);
	m.gre_seq[b.dual_index] = 777U;
	rule.tunnel_gre_seq = 516;
	f_pptp_enc2.source_mac = 3;
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_pptp_enc2, &b) == 0);
	assert(b.dual_index == f_pptp_enc1.dual_index && m.gre_seq[b.dual_index] == 777U);

	/* PPTP decap programs CLS KEY7. */
	rule.tunnel_decap = true;
	memcpy(rule.tunnel_src, peer2, 4);
	memcpy(rule.tunnel_dst, wan_ip, 4);
	assert(rtl_fe_install_tunnel(&fe, &rule, &f_pptp_dec, &b) == 0);
	assert(m.cls_key[b.cls_index][4] == 0x0a010203U);

	/* Teardown restores L3PP_L2TP_SPORT[31:16] back to 1701 after both L2TP flows leave. */
	assert(rtl_fe_tunnel_teardown(&fe, &f_l2tp_enc) == 0);
	assert(rtl_fe_interface_put(&fe, &f_l2tp_enc) == 0);
	assert(m.l2tp_sport == ((50000U << 16) | 1701U));
	assert(rtl_fe_tunnel_teardown(&fe, &f_l2tp_dec) == 0);
	assert(rtl_fe_interface_put(&fe, &f_l2tp_dec) == 0);
	assert(fe.l2tp_alt_refs == 0 && m.l2tp_sport == ((1701U << 16) | 1701U));

	assert(rtl_fe_tunnel_teardown(&fe, &f_pptp_enc1) == 0);
	assert(rtl_fe_interface_put(&fe, &f_pptp_enc1) == 0);
	assert(rtl_fe_tunnel_teardown(&fe, &f_pptp_enc2) == 0);
	assert(rtl_fe_interface_put(&fe, &f_pptp_enc2) == 0);
	assert(rtl_fe_tunnel_teardown(&fe, &f_pptp_dec) == 0);
	assert(rtl_fe_interface_put(&fe, &f_pptp_dec) == 0);
}

int main(void)
{
	(void)rtl_fe_dual_parse_hex;
	test_cls_vectors_and_order();
	test_lpb_and_dual_dos_gating();
	test_dslite_6rd_flow_lifecycle();
	test_l2tp_pptp_flow_lifecycle();
	puts("PASS: KEY6/KEY7/FIB0 vectors == ca-ne.ko, CLS/FIB write & clear "
	     "order, 0x3348/LPB_TBL_3 dual_hdr gating, PON vs Eth cls_profile "
	     "0/1, DS-Lite & 6RD & L2TP/PPTP encap/decap lifecycle & retry rollback");
	return 0;
}
'''

program = '\n'.join(defines) + '\n' + prefix + hw_helpers + '\n' + cls_hw_code + '\n' + tun_core_code + '\n' + tun_flag_block + '\n' + main_helpers + '\n' + tests

with tempfile.TemporaryDirectory(prefix='pt1500-tunnel-flow-') as directory:
    test = Path(directory) / 'flow.c'
    binary = Path(directory) / 'flow'
    test.write_text(program)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-I', str(DRIVER), str(test),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env=dict(os.environ))
