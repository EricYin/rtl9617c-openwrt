#!/usr/bin/env python3
"""Compile the real dual-header table manager against a mock NE window.

The mock models the shared 0x3548 data window: it records the exact register
write order, decodes the command word into one of the three tables and serves
read commands from the stored entry.  Everything from the "testable core"
marker in fe_tunnel.c up to the debugfs marker is compiled unchanged, so the
packers, allocators and hardware access sequence are the production code.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/fe'
source = (DRIVER / 'fe_tunnel.c').read_text()
header = (DRIVER / 'fe_tunnel.h').read_text()
hardware = (DRIVER / 'fe_hw.h').read_text()

start = source.index('/* --- testable core ---')
end = source.index('/* --- debugfs --- */')
functions = source[start:end]

# Control table field layout, transcribed independently from spec
# phase0-re3-dualhdr-mc-napt6 §1.4.  The test asserts that the header macros
# and the expected word values both agree with this table.
FIELDS = {
    'rep_ip_len_diff_pad_ctrl': (127, 1),
    'rep_len_diff1_pad_ctrl': (126, 1),
    'rep_len_diff2_pad_ctrl': (125, 1),
    'hdr_fmt': (123, 2),
    'hdr_len': (116, 7),
    'mtu_diff': (109, 7),
    'ppp_ip_ver_ost': (102, 7),
    'rep_ip_en': (101, 1),
    'rep_ip_ver': (100, 1),
    'rep_len_ost1': (93, 7),
    'rep_len_diff1': (86, 7),
    'rep_len_ost2': (79, 7),
    'rep_len_diff2': (72, 7),
    'ip4_ost': (65, 7),
    'gre_seq_ack_ost': (58, 7),
    'gre_mod_fld': (56, 2),
    'ip6_oft': (49, 7),
    'rep_ip_dscp_en': (48, 1),
    'rep_ip_ecn_en': (47, 1),
    'rep_ip_len': (46, 1),
    'rep_ip_len_diff': (39, 7),
    'rep_ip_ptc': (38, 1),
    'rep_ip_ttl': (37, 1),
    'mapt_pre_len': (34, 3),
    'map_drf_ver': (33, 1),
    'sixrd_dip_pre_len': (28, 5),
    'sixrd_dip_suf_str_bit': (22, 6),
    'dsl_uc_chk': (19, 3),
    'dsl_mc_chk': (18, 1),
    'l4sum_rec': (17, 1),
    'vxlan_sp_ost': (10, 7),
    'inr_to_out_fld': (2, 8),
    'tos_hsh_sel': (1, 1),
    'mc_mac_map': (0, 1),
}

# The 34 fields must cover bit0..bit127 exactly once.
covered = [0] * 128
for bit, width in FIELDS.values():
    for position in range(bit, bit + width):
        assert covered[position] == 0, position
        covered[position] = 1
assert all(covered)

# Cross-check the C header macros against the independent table above.
for field, (bit, width) in FIELDS.items():
    cname = field.upper()
    match = re.search(r'^#define RTL_FE_DUAL_CTRL_%s_BIT\s+(\d+)$' % cname,
                      header, re.M)
    assert match, cname
    assert int(match.group(1)) == bit, (field, match.group(1), bit)
    match = re.search(r'^#define RTL_FE_DUAL_CTRL_%s_WIDTH\s+(\d+)$' % cname,
                      header, re.M)
    assert match, cname
    assert int(match.group(1)) == width, (field, match.group(1), width)

NONE = 0x7f

# Values measured from _rtk_fc_dualHeader_ctrl_setupIP4InIP6/6RD/MAPT
# (spec §3.2).  Every other field is zero.
DSLITE = {
    'hdr_fmt': 0,
    'hdr_len': 40,
    'ppp_ip_ver_ost': NONE,
    'rep_ip_en': 1,
    'rep_ip_ver': 1,
    'rep_len_ost1': NONE,
    'rep_len_ost2': NONE,
    'ip4_ost': NONE,
    'gre_seq_ack_ost': NONE,
    'ip6_oft': 0,
    'rep_ip_len': 1,
    'dsl_mc_chk': 1,
    'vxlan_sp_ost': NONE,
    'inr_to_out_fld': 0x30,
    'mc_mac_map': 1,
}

SIXRD = {
    'hdr_fmt': 0,
    'hdr_len': 20,
    'mtu_diff': 0,
    'ppp_ip_ver_ost': NONE,
    'rep_ip_en': 1,
    'rep_ip_ver': 0,
    'rep_len_ost1': 2,
    'rep_len_diff1': 20,
    'rep_len_ost2': NONE,
    'rep_len_diff2': 16,
    'ip4_ost': 0,
    'gre_seq_ack_ost': NONE,
    'ip6_oft': NONE,
    'rep_ip_dscp_en': 1,
    'rep_ip_ecn_en': 1,
    'rep_ip_len': 1,
    'rep_ip_len_diff': 20,
    'sixrd_dip_suf_str_bit': 32,
    'vxlan_sp_ost': NONE,
    'inr_to_out_fld': 0xb0,
}

# hdr_len, rep_ip_en/ver, rep_len_ost1/2, rep_len_diff1/2 and ip4_ost are
# caller parameters in the OEM MAP-T setup, so the preset keeps the offset
# sentinels and leaves hdr_len at zero.
MAPT = {
    'hdr_fmt': 0,
    'hdr_len': 0,
    'ppp_ip_ver_ost': NONE,
    'rep_len_ost1': NONE,
    'rep_len_ost2': NONE,
    'ip4_ost': NONE,
    'gre_seq_ack_ost': 120,
    'ip6_oft': 30,
    'rep_ip_dscp_en': 1,
    'rep_ip_ecn_en': 1,
    'rep_ip_len_diff': 1,
    'rep_ip_ptc': 1,
    'rep_ip_ttl': 1,
    'mapt_pre_len': 7,
    'map_drf_ver': 1,
    'sixrd_dip_pre_len': 31,
    'sixrd_dip_suf_str_bit': 48,
    'vxlan_sp_ost': NONE,
    'inr_to_out_fld': 0x80,
}


def words_for(values):
    words = [0, 0, 0, 0]
    for field, (bit, width) in FIELDS.items():
        value = values.get(field, 0)
        assert value < (1 << width), (field, value, width)
        for index in range(width):
            if value & (1 << index):
                position = bit + index
                words[position // 32] |= 1 << (position % 32)
    return words


def c_array(name, words):
    body = ', '.join('0x%08xU' % word for word in words)
    return 'static const u32 %s[4] = { %s };\n' % (name, body)


def check_function(name, values):
    lines = ['static void check_control_fields_%s(const struct '
             'rtl_fe_dual_control *c)' % name, '{']
    for field in FIELDS:
        lines.append('\tassert(c->%s == %dU);' % (field, values.get(field, 0)))
    lines.append('}')
    return '\n'.join(lines) + '\n'


defines = []
for line in hardware.splitlines():
    if (line.startswith('#define RTL_FE_DUAL_') or
            line.startswith('#define RTL_FE_L3PP_L2TP_SPORT') or
            line.startswith('#define RTL_FE_L3PE_') or
            line.startswith('#define RTL_FE_CLS_KEY_PROFILE_ENTRIES')):
        defines.append(line)
for line in header.splitlines():
    if (line.startswith('#define RTL_FE_DUAL_CTRL_') or
            line.startswith('#define RTL_FE_DUAL_FMR_') or
            line.startswith('#define RTL_FE_DUAL_OST_NONE') or
            line.startswith('#define RTL_FE_DUAL_DSLITE_') or
            line.startswith('#define RTL_FE_DUAL_6RD_') or
            line.startswith('#define RTL_FE_DUAL_HASH_EIF_BASE') or
            line.startswith('#define RTL_FE_DUAL_CLS_') or
            line.startswith('#define RTL_FE_PPP_TUN_') or
            line.startswith('#define RTL_FE_EIF_HASH_INDICES') or
            line.startswith('#define RTL_FE_EIF_PHYS_ROWS') or
            line.startswith('#define RTL_FE_EIF_EXCLUSIVE_ROWS') or
            line.startswith('#define RTL_FE_EIF_ALIAS_')):
        defines.append(line)

prefix = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define BIT(n) (1UL << (n))

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

struct rtl_fe;
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

struct mock {
	u32 window[16];
	u32 content[16][16];
	u32 control[16][16];
	u32 fmr[3][16];
	u32 gre_ack[16];
	u32 gre_seq[16];
	u32 ipv4_id[16];
	u32 cmds[256];
	unsigned int cmd_n;
	unsigned int order[512];
	unsigned int order_n;
	int busy;
	int fail_busy;
	int corrupt_write;
};

struct rtl_fe_eif_slot {
	unsigned int param_hash;
	unsigned char hash;
	unsigned char phys;
	unsigned char refs;
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

struct rtl_fe {
	struct mock *mock;
	struct rtl_fe_tunnel *tunnel;
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

	if (reg == RTL_FE_DUAL_CMD) {
		if (m->fail_busy)
			return RTL_FE_DUAL_BUSY;
		if (m->busy > 0) {
			m->busy--;
			return RTL_FE_DUAL_BUSY;
		}
		return 0;
	}
	if (reg >= RTL_FE_L3PE_GRE_ACK(0) && reg <= RTL_FE_L3PE_GRE_ACK(15))
		return m->gre_ack[(reg - RTL_FE_L3PE_GRE_ACK(0)) / 4];
	if (reg >= RTL_FE_L3PE_GRE_SEQ(0) && reg <= RTL_FE_L3PE_GRE_SEQ(15))
		return m->gre_seq[(reg - RTL_FE_L3PE_GRE_SEQ(0)) / 4];
	if (reg >= RTL_FE_L3PE_IPV4_ID(0) && reg <= RTL_FE_L3PE_IPV4_ID(15))
		return m->ipv4_id[(reg - RTL_FE_L3PE_IPV4_ID(0)) / 4];
	assert(reg >= 0x354c && reg <= 0x3588 && !((reg - 0x354c) % 4));
	return m->window[(0x3588 - reg) / 4];
}

static void rtl_fe_write(struct rtl_fe *fe, unsigned int reg, u32 value)
{
	struct mock *m = fe->mock;
	u32 (*table)[16];
	unsigned int index = value & 0xf;
	u32 select = value & 0x30;

	m->order[m->order_n++] = reg;
	if (reg >= RTL_FE_L3PE_GRE_ACK(0) && reg <= RTL_FE_L3PE_GRE_ACK(15)) {
		m->gre_ack[(reg - RTL_FE_L3PE_GRE_ACK(0)) / 4] = value;
		return;
	}
	if (reg >= RTL_FE_L3PE_GRE_SEQ(0) && reg <= RTL_FE_L3PE_GRE_SEQ(15)) {
		m->gre_seq[(reg - RTL_FE_L3PE_GRE_SEQ(0)) / 4] = value;
		return;
	}
	if (reg >= RTL_FE_L3PE_IPV4_ID(0) && reg <= RTL_FE_L3PE_IPV4_ID(15)) {
		m->ipv4_id[(reg - RTL_FE_L3PE_IPV4_ID(0)) / 4] = value;
		return;
	}
	if (reg != RTL_FE_DUAL_CMD) {
		assert(reg >= 0x354c && reg <= 0x3588 && !((reg - 0x354c) % 4));
		m->window[(0x3588 - reg) / 4] = value;
		return;
	}

	m->cmds[m->cmd_n++] = value;
	switch (select) {
	case 0x00:
		table = m->content;
		assert(index < 16);
		break;
	case 0x10:
		table = m->control;
		assert(index < 16);
		break;
	case 0x20:
		table = m->fmr;
		assert(index < 3);
		break;
	default:
		assert(0);
		return;
	}

	if (value & RTL_FE_DUAL_WRITE) {
		memcpy(table[index], m->window, sizeof(m->window));
		if (m->corrupt_write)
			table[index][0] ^= 1U;
	} else {
		memcpy(m->window, table[index], sizeof(m->window));
	}
	m->busy = 2;
}

static void setup(struct rtl_fe *fe, struct rtl_fe_tunnel *t, struct mock *m)
{
	memset(m, 0, sizeof(*m));
	memset(t, 0, sizeof(*t));
	memset(fe, 0, sizeof(*fe));
	fe->mock = m;
	fe->tunnel = t;
	t->fe = fe;
}
'''

expected = (
    c_array('expected_dslite', words_for(DSLITE)) +
    c_array('expected_6rd', words_for(SIXRD)) +
    c_array('expected_mapt', words_for(MAPT)) +
    check_function('dslite', DSLITE) +
    check_function('6rd', SIXRD) +
    check_function('mapt', MAPT)
)

tests = r'''
static void test_eif_alias(void)
{
	unsigned int hash;
	int phys;

	for (hash = 0; hash < 64; hash++) {
		phys = rtl_fe_eif_phys(hash);
		assert(phys == (hash < 32 ? (int)hash :
				16 + (int)(hash & 0xf)));
	}
	assert(rtl_fe_eif_phys(32) == 16);
	assert(rtl_fe_eif_phys(47) == 31);
	assert(rtl_fe_eif_phys(48) == 16);
	assert(rtl_fe_eif_phys(63) == 31);
	assert(rtl_fe_eif_phys(64) == -EINVAL);
	assert(rtl_fe_eif_phys(0xffffffffU) == -EINVAL);
}

static void test_alloc_free(void)
{
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	unsigned int index, i;
	u32 words[16] = {0};

	setup(&fe, &t, &m);
	for (i = 0; i < 16; i++) {
		index = 0xdead;
		assert(rtl_fe_dual_content_alloc(&fe, &index,
						 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
		assert(index == i);
		assert(t.content_slot[i].owner == RTL_FE_DUAL_OWNER_DEBUGFS);
		assert(t.content_slot[i].type == RTL_FE_DUAL_TYPE_NONE);
	}
	index = 0xdead;
	assert(rtl_fe_dual_content_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == -ENOSPC);
	assert(index == 0xdead);
	assert(rtl_fe_dual_content_free(&fe, 5) == 0);
	assert(t.content_slot[5].owner == RTL_FE_DUAL_OWNER_NONE);
	assert(rtl_fe_dual_content_free(&fe, 5) == -ENOENT);
	assert(rtl_fe_dual_content_free(&fe, 16) == -EINVAL);
	assert(rtl_fe_dual_content_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(index == 5);
	assert(rtl_fe_dual_content_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_NONE) == -EINVAL);
	assert(rtl_fe_dual_content_alloc(&fe, &index, 99) == -EINVAL);
	assert(rtl_fe_dual_content_write(&fe, 6, NULL) == -EINVAL);
	assert(rtl_fe_dual_content_write(&fe, 16, words) == -EINVAL);

	setup(&fe, &t, &m);
	for (i = 0; i < 16; i++) {
		index = 0xdead;
		assert(rtl_fe_dual_control_alloc(&fe, &index,
						 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
		assert(index == i);
	}
	assert(rtl_fe_dual_control_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == -ENOSPC);
	assert(rtl_fe_dual_control_free(&fe, 15) == 0);
	assert(rtl_fe_dual_control_free(&fe, 15) == -ENOENT);
	assert(rtl_fe_dual_control_free(&fe, 16) == -EINVAL);

	for (i = 0; i < 3; i++) {
		index = 0xdead;
		assert(rtl_fe_dual_fmr_alloc(&fe, &index,
					     RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
		assert(index == i);
	}
	index = 0xdead;
	assert(rtl_fe_dual_fmr_alloc(&fe, &index,
				     RTL_FE_DUAL_OWNER_DEBUGFS) == -ENOSPC);
	assert(index == 0xdead);
	assert(rtl_fe_dual_fmr_free(&fe, 1) == 0);
	assert(rtl_fe_dual_fmr_free(&fe, 1) == -ENOENT);
	assert(rtl_fe_dual_fmr_free(&fe, 3) == -EINVAL);
	assert(rtl_fe_dual_fmr_write(&fe, 3, words) == -EINVAL);
	assert(rtl_fe_dual_fmr_read(&fe, 3, words) == -EINVAL);
}

static void test_write_and_read(void)
{
	static const unsigned int expected_order[16] = {
		0x3588, 0x3584, 0x3580, 0x357c, 0x3578, 0x3574, 0x3570,
		0x356c, 0x3568, 0x3564, 0x3560, 0x355c, 0x3558, 0x3554,
		0x3550, 0x354c,
	};
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	u32 words[16], out[16];
	unsigned int index, i;

	setup(&fe, &t, &m);
	for (i = 0; i < 16; i++)
		words[i] = 0x10000000U + i * 0x01010101U;
	assert(rtl_fe_dual_content_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(index == 0);
	assert(rtl_fe_dual_content_write(&fe, 0, words) == 0);
	/* 16 data words, the write command word, then the read-back command. */
	assert(m.order_n == 18);
	for (i = 0; i < 16; i++)
		assert(m.order[i] == expected_order[i]);
	assert(m.order[16] == RTL_FE_DUAL_CMD);
	assert(m.order[17] == RTL_FE_DUAL_CMD);
	assert(m.cmd_n == 2);
	assert(m.cmds[0] == (RTL_FE_DUAL_CMD_WRITE |
			     RTL_FE_DUAL_SEL_CONTENT));
	assert(m.cmds[1] == (RTL_FE_DUAL_CMD_READ |
			     RTL_FE_DUAL_SEL_CONTENT));
	for (i = 0; i < 16; i++)
		assert(m.content[0][i] == words[i]);
	memset(out, 0, sizeof(out));
	assert(rtl_fe_dual_content_read(&fe, 0, out) == 0);
	assert(memcmp(out, words, sizeof(words)) == 0);
	assert(rtl_fe_dual_content_write(&fe, 1, words) == -ENOENT);
	assert(rtl_fe_dual_content_read(&fe, 1, out) == -ENOENT);
	assert(rtl_fe_dual_content_read(&fe, 16, out) == -EINVAL);

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_control_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_control_write(&fe, 0, words) == 0);
	assert(m.cmd_n == 2);
	assert(m.cmds[0] == (RTL_FE_DUAL_CMD_WRITE |
			     RTL_FE_DUAL_SEL_CONTROL));
	assert(m.cmds[1] == (RTL_FE_DUAL_CMD_READ |
			     RTL_FE_DUAL_SEL_CONTROL));
	for (i = 0; i < 16; i++)
		assert(m.control[0][i] == words[i]);
	assert(rtl_fe_dual_control_read(&fe, 0, out) == 0);
	assert(memcmp(out, words, sizeof(words)) == 0);

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_fmr_alloc(&fe, &index,
				     RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_fmr_write(&fe, 0, words) == 0);
	assert(t.fmr_slot[0].type == RTL_FE_DUAL_TYPE_MAPT);
	assert(m.cmd_n == 2);
	assert(m.cmds[0] == (RTL_FE_DUAL_CMD_WRITE |
			     RTL_FE_DUAL_SEL_FMR));
	assert(m.cmds[1] == (RTL_FE_DUAL_CMD_READ |
			     RTL_FE_DUAL_SEL_FMR));
	for (i = 0; i < 16; i++)
		assert(m.fmr[0][i] == words[i]);
	assert(rtl_fe_dual_fmr_read(&fe, 0, out) == 0);
	assert(memcmp(out, words, sizeof(words)) == 0);
}

static void test_timeout_and_eio(void)
{
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	unsigned int index;
	u32 words[16] = {0}, out[16];

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_content_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	m.fail_busy = 1;
	assert(rtl_fe_dual_content_write(&fe, 0, words) == -ETIMEDOUT);
	assert(m.cmd_n == 1);

	m.fail_busy = 0;
	m.busy = 0;
	m.corrupt_write = 1;
	assert(rtl_fe_dual_content_write(&fe, 0, words) == -EIO);

	m.corrupt_write = 0;
	m.fail_busy = 1;
	assert(rtl_fe_dual_content_read(&fe, 0, out) == -ETIMEDOUT);
}

static void test_hex_content(void)
{
	static const char pattern[] = "0123456789abcdef";
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	char hex[130];
	u32 words[16], out[16];
	unsigned int index, i;

	memset(hex, 0, sizeof(hex));
	for (i = 0; i < 128; i++)
		hex[i] = pattern[i % 16];
	assert(strlen(hex) == 128);
	assert(rtl_fe_dual_parse_hex(hex, words) == 0);
	for (i = 0; i < 16; i++)
		assert(words[i] == (i % 2 ? 0x89abcdefU : 0x01234567U));

	hex[127] = '\0';
	assert(rtl_fe_dual_parse_hex(hex, words) == -EINVAL);
	hex[127] = 'f';
	hex[128] = '0';
	assert(rtl_fe_dual_parse_hex(hex, words) == -EINVAL);
	hex[128] = '\0';
	hex[0] = 'g';
	assert(rtl_fe_dual_parse_hex(hex, words) == -EINVAL);
	hex[0] = '0';

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_content_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_parse_hex(hex, words) == 0);
	assert(rtl_fe_dual_content_write(&fe, 0, words) == 0);
	memset(out, 0, sizeof(out));
	assert(rtl_fe_dual_content_read(&fe, 0, out) == 0);
	assert(memcmp(out, words, sizeof(words)) == 0);
}

static void test_control_pack(void)
{
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	struct rtl_fe_dual_control c;
	u32 words[16] = {1, 2, 3, 4, 5};
	unsigned int index, i;

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_control_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_control_set_type(&fe, 0,
					    RTL_FE_DUAL_TYPE_IP4INIP6) == 0);
	assert(t.control_slot[0].type == RTL_FE_DUAL_TYPE_IP4INIP6);
	assert(memcmp(m.control[0], expected_dslite, 16) == 0);
	for (i = 4; i < 16; i++)
		assert(m.control[0][i] == 0);
	rtl_fe_dual_control_unpack(m.control[0], &c);
	check_control_fields_dslite(&c);
	rtl_fe_dual_control_pack(words, &c);
	assert(memcmp(words, expected_dslite, 16) == 0);

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_control_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_control_set_type(&fe, 0,
					    RTL_FE_DUAL_TYPE_6RD) == 0);
	assert(t.control_slot[0].type == RTL_FE_DUAL_TYPE_6RD);
	assert(memcmp(m.control[0], expected_6rd, 16) == 0);
	rtl_fe_dual_control_unpack(m.control[0], &c);
	check_control_fields_6rd(&c);
	rtl_fe_dual_control_pack(words, &c);
	assert(memcmp(words, expected_6rd, 16) == 0);

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_control_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_control_set_type(&fe, 0,
					    RTL_FE_DUAL_TYPE_MAPT) == 0);
	assert(t.control_slot[0].type == RTL_FE_DUAL_TYPE_MAPT);
	assert(memcmp(m.control[0], expected_mapt, 16) == 0);
	rtl_fe_dual_control_unpack(m.control[0], &c);
	check_control_fields_mapt(&c);
	rtl_fe_dual_control_pack(words, &c);
	assert(memcmp(words, expected_mapt, 16) == 0);

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_control_alloc(&fe, &index,
					 RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_control_set_type(&fe, 0,
					    RTL_FE_DUAL_TYPE_VXLAN) ==
	       -EOPNOTSUPP);
	assert(rtl_fe_dual_control_set_type(&fe, 1,
					    RTL_FE_DUAL_TYPE_IP4INIP6) ==
	       -ENOENT);
	assert(rtl_fe_dual_control_set_type(&fe, 16,
					    RTL_FE_DUAL_TYPE_IP4INIP6) ==
	       -EINVAL);
	memset(words, 0, sizeof(words));
	words[0] = 0xdeadbeefU;
	assert(rtl_fe_dual_control_write(&fe, 0, words) == 0);
	assert(t.control_slot[0].type == RTL_FE_DUAL_TYPE_NONE);
	assert(m.control[0][0] == 0xdeadbeefU);
}

static void test_fmr_pack(void)
{
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	struct rtl_fe_dual_fmr f, g;
	u32 words[16], out[16];
	unsigned int index, i;

	memset(&f, 0, sizeof(f));
	f.prefix = 0x20010db800000001ULL;
	f.psid_str_ost = 3;
	f.psid_end_ost = 7;
	f.psid_refill = 1;
	f.pref_len = 0x2a;
	f.drf_ver = 1;
	rtl_fe_dual_fmr_pack(words, &f);
	assert(words[0] == 0x00000001U);
	assert(words[1] == 0x20010db8U);
	assert(words[2] == 0x00015573U);
	for (i = 3; i < 16; i++)
		assert(words[i] == 0);
	rtl_fe_dual_fmr_unpack(words, &g);
	assert(g.prefix == f.prefix);
	assert(g.psid_str_ost == 3);
	assert(g.psid_end_ost == 7);
	assert(g.psid_refill == 1);
	assert(g.pref_len == 0x2a);
	assert(g.drf_ver == 1);

	setup(&fe, &t, &m);
	assert(rtl_fe_dual_fmr_alloc(&fe, &index,
				     RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_fmr_write(&fe, 0, words) == 0);
	assert(t.fmr_slot[0].type == RTL_FE_DUAL_TYPE_MAPT);
	assert(m.fmr[0][2] == 0x00015573U);
	memset(out, 0, sizeof(out));
	assert(rtl_fe_dual_fmr_read(&fe, 0, out) == 0);
	assert(memcmp(out, words, sizeof(words)) == 0);
}

static void test_content_templates(void)
{
	static const u8 src[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 1 };
	static const u8 dst[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				    0, 0, 0, 0, 0, 0, 0, 2 };
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	u32 src_words[4], dst_words[4];
	unsigned int control, content, i;

	memcpy(src_words, src, sizeof(src_words));
	memcpy(dst_words, dst, sizeof(dst_words));

	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_dslite(&fe, false, src, dst, &control,
					    &content) == 0);
	assert(t.control_slot[control].owner == RTL_FE_DUAL_OWNER_FLOW);
	assert(t.control_slot[control].type == RTL_FE_DUAL_TYPE_IP4INIP6);
	assert(t.content_slot[content].owner == RTL_FE_DUAL_OWNER_FLOW);
	assert(t.content_slot[content].type == RTL_FE_DUAL_TYPE_IP4INIP6);
	assert(memcmp(m.control[control], expected_dslite, 16) == 0);
	for (i = 4; i < 16; i++)
		assert(m.control[control][i] == 0);
	assert(m.content[content][0] == RTL_FE_DUAL_DSLITE_WORD0);
	assert(m.content[content][1] == RTL_FE_DUAL_DSLITE_WORD1);
	for (i = 0; i < 4; i++) {
		assert(m.content[content][2 + i] == src_words[i]);
		assert(m.content[content][6 + i] == dst_words[i]);
	}
	for (i = 10; i < 16; i++)
		assert(m.content[content][i] == 0);

	/* Decap keeps the same Control but carries no Content bytes. */
	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_dslite(&fe, true, src, dst, &control,
					    &content) == 0);
	assert(memcmp(m.control[control], expected_dslite, 16) == 0);
	for (i = 0; i < 16; i++)
		assert(m.content[content][i] == 0);

	/* 6RD: encap Content carries 20-byte IPv4 header template; decap is zero. */
	static const u8 v4_src[4] = { 198, 51, 100, 1 };
	static const u8 v4_dst[4] = { 203, 0, 113, 2 };
	u32 v4_src_word, v4_dst_word;

	memcpy(&v4_src_word, v4_src, sizeof(v4_src_word));
	memcpy(&v4_dst_word, v4_dst, sizeof(v4_dst_word));

	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_6rd(&fe, false, v4_src, v4_dst, &control,
					 &content) == 0);
	assert(t.control_slot[control].type == RTL_FE_DUAL_TYPE_6RD);
	assert(t.content_slot[content].type == RTL_FE_DUAL_TYPE_6RD);
	assert(memcmp(m.control[control], expected_6rd, 16) == 0);
	for (i = 4; i < 16; i++)
		assert(m.control[control][i] == 0);
	assert(m.content[content][0] == RTL_FE_DUAL_6RD_WORD0);
	assert(m.content[content][1] == 0);
	assert(m.content[content][2] == RTL_FE_DUAL_6RD_WORD2);
	assert(m.content[content][3] == v4_src_word);
	assert(m.content[content][4] == v4_dst_word);
	for (i = 5; i < 16; i++)
		assert(m.content[content][i] == 0);

	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_6rd(&fe, true, v4_src, v4_dst, &control,
					 &content) == 0);
	assert(memcmp(m.control[control], expected_6rd, 16) == 0);
	for (i = 0; i < 16; i++)
		assert(m.content[content][i] == 0);
}

static void test_clear_on_free(void)
{
	u8 src[16] = {0}, dst[16] = {0};
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	u32 words[16];
	unsigned int control, content, i;

	/* Control must be cleared before Content (RE-7 §7.2/§7.3). */
	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_dslite(&fe, false, src, dst, &control,
					    &content) == 0);
	assert(m.cmd_n == 4);
	assert(rtl_fe_dual_control_free(&fe, control) == 0);
	assert(m.cmd_n == 6);
	assert(m.cmds[4] == (RTL_FE_DUAL_CMD_WRITE |
			     RTL_FE_DUAL_SEL_CONTROL));
	assert(m.cmds[5] == (RTL_FE_DUAL_CMD_READ |
			     RTL_FE_DUAL_SEL_CONTROL));
	for (i = 0; i < 16; i++)
		assert(m.control[control][i] == 0);
	assert(m.content[content][0] == RTL_FE_DUAL_DSLITE_WORD0);
	assert(rtl_fe_dual_content_free(&fe, content) == 0);
	assert(m.cmd_n == 8);
	assert(m.cmds[6] == (RTL_FE_DUAL_CMD_WRITE |
			     RTL_FE_DUAL_SEL_CONTENT));
	for (i = 0; i < 16; i++)
		assert(m.content[content][i] == 0);
	assert(!test_bit(control, t.control));
	assert(!test_bit(content, t.content));

	/* A failed clear must keep the slot allocated for a later retry. */
	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_dslite(&fe, false, src, dst, &control,
					    &content) == 0);
	m.fail_busy = 1;
	assert(rtl_fe_dual_control_free(&fe, control) == -ETIMEDOUT);
	assert(test_bit(control, t.control));
	m.fail_busy = 0;
	m.busy = 0;
	assert(rtl_fe_dual_control_free(&fe, control) == 0);

	/* clear_on_free=0 releases bookkeeping without touching hardware. */
	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_dslite(&fe, false, src, dst, &control,
					    &content) == 0);
	rtl_fe_dual_clear_on_free = false;
	assert(rtl_fe_dual_control_free(&fe, control) == 0);
	assert(m.control[control][0] == expected_dslite[0]);
	assert(!test_bit(control, t.control));
	rtl_fe_dual_clear_on_free = true;

	/* The ordered release helper is idempotent and clears both tables. */
	setup(&fe, &t, &m);
	assert(rtl_fe_tunnel_program_dslite(&fe, false, src, dst, &control,
					    &content) == 0);
	assert(rtl_fe_tunnel_release(&fe, control, content) == 0);
	assert(rtl_fe_tunnel_release(&fe, control, content) == 0);
	assert(!test_bit(control, t.control));
	assert(!test_bit(content, t.content));
	assert(rtl_fe_dual_content_read(&fe, content, words) == -ENOENT);
	for (i = 0; i < 16; i++) {
		assert(m.control[control][i] == 0);
		assert(m.content[content][i] == 0);
	}

	/* FMR clears with 0xffffffff, not zero (RE-7 §7.1). */
	setup(&fe, &t, &m);
	memset(words, 0x5a, sizeof(words));
	assert(rtl_fe_dual_fmr_alloc(&fe, &control,
				     RTL_FE_DUAL_OWNER_DEBUGFS) == 0);
	assert(rtl_fe_dual_fmr_write(&fe, control, words) == 0);
	assert(rtl_fe_dual_fmr_free(&fe, control) == 0);
	for (i = 0; i < 16; i++)
		assert(m.fmr[control][i] == 0xffffffffU);
	assert(!test_bit(control, t.fmr));
}

static void test_eif_arbitration(void)
{
	const unsigned int param_a = 0xa5a50001U;
	const unsigned int param_b = 0xa5a50002U;
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	unsigned int hash, phys, i;

	/* Full 0..63 mapping and refcount groups. */
	setup(&fe, &t, &m);
	for (hash = 0; hash < 64; hash++) {
		assert(rtl_fe_eif_alloc(&fe, hash, param_a, &phys) == 0);
		assert(phys == (hash < 32 ? hash : 16 + (hash & 0xf)));
		assert(t.eif[hash].used);
		assert(t.eif[hash].hash == hash);
		assert(t.eif[hash].phys == phys);
		assert(t.eif[hash].param_hash == param_a);
	}
	for (hash = 0; hash < 64; hash++)
		assert(t.eif[hash].refs == (hash < 16 ? 1 : 3));
	assert(rtl_fe_eif_alloc(&fe, 0, param_a, &phys) == -EBUSY);
	assert(rtl_fe_eif_alloc(&fe, 63, param_a, &phys) == -EBUSY);
	assert(m.cmd_n == 0 && m.order_n == 0);

	/* 16+x / 32+x / 48+x three-way sharing and ordered release. */
	setup(&fe, &t, &m);
	assert(rtl_fe_eif_alloc(&fe, 16, param_a, &phys) == 0);
	assert(phys == 16 && t.eif[16].refs == 1);
	assert(rtl_fe_eif_alloc(&fe, 32, param_a, &phys) == 0);
	assert(phys == 16 && t.eif[16].refs == 2 && t.eif[32].refs == 2);
	assert(rtl_fe_eif_alloc(&fe, 48, param_a, &phys) == 0);
	assert(phys == 16 && t.eif[16].refs == 3 &&
	       t.eif[32].refs == 3 && t.eif[48].refs == 3);
	assert(rtl_fe_eif_free(&fe, 32) == 0);
	assert(!t.eif[32].used && t.eif[32].refs == 0);
	assert(t.eif[16].refs == 2 && t.eif[48].refs == 2);
	assert(rtl_fe_eif_free(&fe, 16) == 0);
	assert(t.eif[48].refs == 1);
	assert(rtl_fe_eif_free(&fe, 48) == 0);
	assert(!t.eif[48].used && t.eif[48].refs == 0);
	assert(t.eif[48].phys == 0 && t.eif[48].param_hash == 0);
	assert(rtl_fe_eif_free(&fe, 48) == -ENOENT);
	assert(m.cmd_n == 0 && m.order_n == 0);

	/* Alias-first, then the 16+x owner, then a mismatching param. */
	setup(&fe, &t, &m);
	assert(rtl_fe_eif_alloc(&fe, 48, param_a, &phys) == 0);
	assert(phys == 16 && t.eif[48].refs == 1);
	assert(rtl_fe_eif_alloc(&fe, 16, param_a, &phys) == 0);
	assert(phys == 16 && t.eif[48].refs == 2 && t.eif[16].refs == 2);
	assert(rtl_fe_eif_alloc(&fe, 32, param_b, &phys) == -EBUSY);
	assert(!t.eif[32].used && t.eif[16].refs == 2);

	/* Mismatch from either side. */
	setup(&fe, &t, &m);
	assert(rtl_fe_eif_alloc(&fe, 16, param_b, &phys) == 0);
	assert(rtl_fe_eif_alloc(&fe, 32, param_a, &phys) == -EBUSY);
	assert(rtl_fe_eif_alloc(&fe, 48, param_b, &phys) == 0);

	/* Rows 0..15 are exclusive; same hash cannot be allocated twice. */
	setup(&fe, &t, &m);
	assert(rtl_fe_eif_alloc(&fe, 0, param_a, &phys) == 0);
	assert(phys == 0 && t.eif[0].refs == 1);
	assert(rtl_fe_eif_alloc(&fe, 0, param_a, &phys) == -EBUSY);
	assert(rtl_fe_eif_free(&fe, 0) == 0);
	assert(!t.eif[0].used && t.eif[0].refs == 0);
	assert(rtl_fe_eif_free(&fe, 0) == -ENOENT);

	/* Bounds and fresh-table zero state. */
	setup(&fe, &t, &m);
	for (i = 0; i < 64; i++) {
		assert(!t.eif[i].used);
		assert(t.eif[i].hash == 0);
		assert(t.eif[i].phys == 0);
		assert(t.eif[i].refs == 0);
		assert(t.eif[i].param_hash == 0);
	}
	assert(rtl_fe_eif_alloc(&fe, 64, param_a, &phys) == -EINVAL);
	assert(rtl_fe_eif_alloc(&fe, 0xffffffffU, param_a, &phys) == -EINVAL);
	assert(rtl_fe_eif_free(&fe, 64) == -EINVAL);
	assert(rtl_fe_eif_free(&fe, 1) == -ENOENT);
	assert(m.cmd_n == 0 && m.order_n == 0);
}

static void test_flow_sessions(void)
{
	static const u8 src6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 1 };
	static const u8 dst6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				     0, 0, 0, 0, 0, 0, 0, 9 };
	static const u8 src4[4] = { 198, 51, 100, 10 };
	static const u8 dst4[4] = { 203, 0, 113, 20 };
	struct rtl_fe fe;
	struct rtl_fe_tunnel t;
	struct mock m;
	struct rtl_fe_tunnel_key key = { };
	struct rtl_fe_tunnel_binding b1 = { }, b2 = { }, b3 = { };
	bool is_last = false, cls_active = false;
	unsigned int cls_index = 0;

	/* Decap pair sharing (refs=2), CLS slot lifecycle and busy phys mask. */
	setup(&fe, &t, &m);
	key.type = RTL_FE_DUAL_TYPE_IP4INIP6;
	key.decap = true;
	key.cls_profile = 1;
	key.param_hash = 0;
	memcpy(key.src, src6, 16);
	memcpy(key.dst, dst6, 16);

	/* Slot 0 blocked via busy_phys_mask (16) -> must select dual_index 1. */
	assert(rtl_fe_tunnel_flow_get(&fe, &key, BIT(0), &b1) == 0);
	assert(b1.dual_index == 1 && b1.phys_eif == 17 && b1.hash_eif == 33);
	assert(b1.cls_index == RTL_FE_CLS_KEY_PROFILE_ENTRIES);
	assert(b1.need_cls_program);
	assert(rtl_fe_tunnel_phys_busy(&fe, 17));
	assert(!rtl_fe_tunnel_phys_busy(&fe, 16));
	assert(rtl_fe_tunnel_flow_mark_cls(&fe, b1.dual_index) == 0);

	/* Second flow matching same outer decap key reuses session & EIF 33. */
	assert(rtl_fe_tunnel_flow_get(&fe, &key, BIT(0), &b2) == 0);
	assert(b2.dual_index == 1 && b2.phys_eif == 17 && b2.hash_eif == 33);
	assert(!b2.need_cls_program && t.sessions[1].refs == 2);

	/* First put decrements refcount while CLS stays active. */
	assert(rtl_fe_tunnel_flow_cls_info(&fe, 1, &is_last, &cls_active,
					   &cls_index) == 0);
	assert(!is_last && cls_active && cls_index == b1.cls_index);
	assert(rtl_fe_tunnel_flow_put(&fe, 1) == 0);
	assert(t.sessions[1].refs == 1 && t.sessions[1].active);

	/* Last put refused until caller disarms CLS and marks it cleared. */
	assert(rtl_fe_tunnel_flow_put(&fe, 1) == -EBUSY);
	rtl_fe_tunnel_flow_cls_cleared(&fe, 1);
	assert(rtl_fe_tunnel_flow_put(&fe, 1) == 0);
	assert(!t.sessions[1].active && !rtl_fe_tunnel_phys_busy(&fe, 17));
	assert(!test_bit(0, t.control) && !test_bit(1, t.control));

	/* Encap 6RD with matching param_hash reuses session; differing param
	 * hash picks next slot; write timeout rolls back slot, EIF and CLS bit.
	 */
	memset(&key, 0, sizeof(key));
	key.type = RTL_FE_DUAL_TYPE_6RD;
	key.decap = false;
	key.param_hash = 0x00881234U;
	memcpy(key.src, src4, 4);
	memcpy(key.dst, dst4, 4);
	assert(rtl_fe_tunnel_flow_get(&fe, &key, 0, &b1) == 0);
	assert(b1.dual_index == 0 && b1.phys_eif == 16 && b1.hash_eif == 32);
	assert(!b1.need_cls_program);

	key.param_hash = 0x00991234U;
	assert(rtl_fe_tunnel_flow_get(&fe, &key, 0, &b3) == 0);
	assert(b3.dual_index == 1 && b3.phys_eif == 17 && b3.hash_eif == 33);
	assert(rtl_fe_tunnel_flow_put(&fe, b3.dual_index) == 0);
	assert(rtl_fe_tunnel_flow_put(&fe, b1.dual_index) == 0);

	/* Timeout while programming decap rolls back CLS pair and tables. */
	key.decap = true;
	key.cls_profile = 0;
	key.param_hash = 0;
	m.fail_busy = 1;
	assert(rtl_fe_tunnel_flow_get(&fe, &key, 0, &b3) == -ETIMEDOUT);
	assert(!t.sessions[0].active && !t.eif[32].used &&
	       !test_bit(0, t.cls_pairs[0]) && !test_bit(0, t.control) &&
	       !test_bit(0, t.content));
}

int main(void)
{
	test_eif_alias();
	test_eif_arbitration();
	test_alloc_free();
	test_write_and_read();
	test_timeout_and_eio();
	test_hex_content();
	test_control_pack();
	test_content_templates();
	test_clear_on_free();
	test_fmr_pack();
	test_flow_sessions();
	puts("PASS: dual-header 16/16/3 allocation, reversed word sequence, "
	     "command words, read-back, timeout/EIO, corrected DS-Lite/6RD/"
	     "MAP-T Control literals, DS-Lite/6RD Content templates, "
	     "clear-on-free order/timeout/FMR fill, FMR word2, EIF alias "
	     "0..63 mapping/arbitration/refcount/free, flow session sharing "
	     "and rollback, 128-hex Content boundary");
	return 0;
}
'''

program = '\n'.join(defines) + '\n' + prefix + expected + '\n' + functions + tests

with tempfile.TemporaryDirectory(prefix='pt1500-tunnel-table-') as directory:
    test = Path(directory) / 'tunnel.c'
    binary = Path(directory) / 'tunnel'
    test.write_text(program)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-I', str(DRIVER), str(test),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env=dict(os.environ))
