#!/usr/bin/env python3
"""Compile the Host Policing core from ni_te_flow.c against a mock regmap.

The model under test is the fc_8277c one (phase2-re10-hostpol-final.md):
32 MAC entries, a pool of 32 virtual meters, POL1 slots 0xA0 + vmeter for
rate limited directions and the fixed MIB slots 0xC0/0xE0 + index for
counting-only ones.

Extracted from the driver:
  * the L3TE flow policer block (rate encoding, profile RMW, bank cfg);
  * the host policing block (MAC table, vmeter pool, POL1 resolution,
    lookup priority, MIB accumulation).
Only te_read()/te_write() and the bitmap primitives are substituted.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/ni'
source = (DRIVER / 'ni_te_flow.c').read_text()
header = (DRIVER / 'ni_te_flow.h').read_text()

pol_start = source.index('static int te_policer_encode_rate(')
pol_end = source.index('static int te_group_depth_ready(', pol_start)
policer_block = source[pol_start:pol_end]

hp_start = source.index('/* ==== BEGIN hostpol logic')
hp_end = source.index('/* ==== END hostpol logic')
hostpol_block = source[hp_start:hp_end]

_lines = header.splitlines()
_defs = []
_i = 0
while _i < len(_lines):
    if (_lines[_i].startswith('#define L3TE_') or
            _lines[_i].startswith('#define RTL_TE_')):
        _chunk = [_lines[_i]]
        while _chunk[-1].rstrip().endswith('\\') and _i + 1 < len(_lines):
            _i += 1
            _chunk.append(_lines[_i])
        _defs.append('\n'.join(_chunk))
    _i += 1
defines = '\n'.join(_defs) + '\n'

profile = re.search(r'struct rtl_te_policer_profile \{.*?\n\};', header,
                    re.S).group(0)
entry = re.search(r'struct rtl_te_hostpol \{.*?\n\};', header, re.S).group(0)
mib = re.search(r'struct rtl_te_hostpol_mib \{.*?\n\};', header, re.S).group(0)

prefix_head = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (63 - (h))))
#define GENMASK_ULL(h, l) (((~0ULL) << (l)) & (~0ULL >> (63 - (h))))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __maybe_unused __attribute__((unused))
#define __set_bit(i, b) ((b)[(i) / 64] |= (1UL << ((i) % 64)))
#define __clear_bit(i, b) ((b)[(i) / 64] &= ~(1UL << ((i) % 64)))
#define test_bit(i, b) (((b)[(i) / 64] >> ((i) % 64)) & 1UL)
#define udelay(x) ((void)(x))
#define wmb() do { } while (0)
#define rmb() do { } while (0)
/* POL1 counter-clear register: the fc_8277c path never writes it */
#define L3TE_POL_CNT_CLEAR_ACC 0x9138u
'''

prefix_body = r'''
struct rtl_te_flow {
	u32 regs[0x10000 / 4];
	unsigned long flow_slots[L3TE_POL_FLOW_SLOTS / 64];
	unsigned long group_slots[L3TE_POL_GRP_SLOTS / 64];
	struct rtl_te_hostpol hostpol[RTL_TE_HOSTPOL_ENTRIES];
	u32 seq[192];
	unsigned int nseq;
	unsigned int accesses;
	bool stall;
	bool group64_ready;
	bool pm_ready;
	bool ro_glb_ctrl;
};

struct te_table {
	u32 acc;
	unsigned int idx_bits;
	unsigned int words;
	unsigned int slots;
	u32 *mem;
};

static u32 mock_flow_tab[L3TE_POL_FLOW_SLOTS][3];
static u32 mock_grp_tab[L3TE_POL_GRP_SLOTS][3];
static u32 mock_sel_tab[L3TE_WRED_QUEUES][L3TE_WRED_SEL_WORDS];
static u32 mock_wred_tab[L3TE_WRED_PROFILES][L3TE_WRED_PROF_WORDS];
static u32 mock_mib_tab[L3TE_POL_FLOW_SLOTS][L3TE_POL_MIB_WORDS];

static struct te_table mock_tables[] = {
	{ L3TE_POL_FLOW_ACC, L3TE_POL_FLOW_IDX_BITS, 3, L3TE_POL_FLOW_SLOTS,
	  &mock_flow_tab[0][0] },
	{ L3TE_POL_GRP_ACC, L3TE_POL_GRP_IDX_BITS, 3, L3TE_POL_GRP_SLOTS,
	  &mock_grp_tab[0][0] },
	{ L3TE_WRED_SEL_ACC, L3TE_WRED_SEL_IDX_BITS, L3TE_WRED_SEL_WORDS,
	  L3TE_WRED_QUEUES, &mock_sel_tab[0][0] },
	{ L3TE_WRED_PROF_ACC, L3TE_WRED_PROF_IDX_BITS, L3TE_WRED_PROF_WORDS,
	  L3TE_WRED_PROFILES, &mock_wred_tab[0][0] },
};

static unsigned int find_first_zero_bit(const unsigned long *bits,
					unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		if (!((bits[i / 64] >> (i % 64)) & 1UL))
			return i;
	return count;
}

static u32 te_read(struct rtl_te_flow *te, u32 off)
{
	if (off >= sizeof(te->regs)) { fprintf(stderr, "bad read %#x\n", off); abort(); }
	return te->regs[off / 4];
}

static void te_write(struct rtl_te_flow *te, u32 off, u32 val)
{
	unsigned int i, j;

	if (off >= sizeof(te->regs)) { fprintf(stderr, "bad write %#x\n", off); abort(); }
	if (te->nseq < ARRAY_SIZE(te->seq))
		te->seq[te->nseq++] = off;
	te->accesses++;
	if (te->ro_glb_ctrl && off == L3TE_TE_GLB_CTRL)
		return;
	te->regs[off / 4] = val;

	/* POL1 counter window: 0x973C command, nine ascending data words */
	if (off == L3TE_POL_MIB_ACC) {
		unsigned int idx;

		if (te->stall || !(val & L3TE_IND_BUSY))
			return;
		idx = val & ((1u << L3TE_POL_MIB_IDX_BITS) - 1u);
		assert(idx < L3TE_POL_FLOW_SLOTS);
		assert(!(te->regs[L3TE_PM_CTRL / 4] & L3TE_PM_CTRL_DISABLE));
		for (i = 0; i < L3TE_POL_MIB_WORDS; i++)
			te->regs[L3TE_POL_MIB_DATA(i) / 4] = mock_mib_tab[idx][i];
		if (te->regs[L3TE_PM_CTRL / 4] & L3TE_PM_CTRL_AUTO_CLR)
			memset(mock_mib_tab[idx], 0, sizeof(mock_mib_tab[idx]));
		te->regs[L3TE_POL_MIB_ACC / 4] = val & ~((u32)L3TE_IND_BUSY);
		return;
	}

	/* POL1 counter clear register: the driver must never write it */
	if (off == L3TE_POL_CNT_CLEAR_ACC) {
		if (te->stall || !(val & L3TE_IND_BUSY))
			return;
		te->regs[L3TE_POL_CNT_CLEAR_ACC / 4] = val &
						      ~((u32)L3TE_IND_BUSY);
		return;
	}

	for (i = 0; i < ARRAY_SIZE(mock_tables); i++)
		if (mock_tables[i].acc == off)
			break;
	if (i == ARRAY_SIZE(mock_tables))
		return;
	if (te->stall || !(val & L3TE_IND_BUSY))
		return;
	{
		struct te_table *t = &mock_tables[i];
		unsigned int idx = val & ((1u << t->idx_bits) - 1u);

		assert(idx < t->slots);
		for (j = 0; j < t->words; j++) {
			u32 addr = off + 4u * (t->words - j);

			if (val & L3TE_IND_WRITE)
				t->mem[idx * t->words + j] = te->regs[addr / 4];
			else
				te->regs[addr / 4] = t->mem[idx * t->words + j];
		}
		te->regs[off / 4] = val & ~((u32)L3TE_IND_BUSY);
	}
}

static void mock_reset(struct rtl_te_flow *te)
{
	static const u32 idle[3] = { 0xffffffffu, 0xffffffffu, 0x00000fffu };
	unsigned int i;

	memset(te, 0, sizeof(*te));
	/* Hardware TE_PM_CTRL reset default: mem_disable=1, auto_clr=1 */
	te->regs[L3TE_PM_CTRL / 4] = 0x00001ca0u;
	memset(mock_flow_tab, 0, sizeof(mock_flow_tab));
	memset(mock_grp_tab, 0, sizeof(mock_grp_tab));
	memset(mock_sel_tab, 0, sizeof(mock_sel_tab));
	memset(mock_wred_tab, 0, sizeof(mock_wred_tab));
	memset(mock_mib_tab, 0, sizeof(mock_mib_tab));
	for (i = 0; i < L3TE_POL_FLOW_SLOTS; i++)
		memcpy(&mock_flow_tab[i][0], idle, sizeof(idle));
	for (i = 0; i < L3TE_POL_GRP_SLOTS; i++)
		memcpy(&mock_grp_tab[i][0], idle, sizeof(idle));
}

static void mac_from_index(u8 mac[RTL_TE_HOSTPOL_ALEN], unsigned int i)
{
	mac[0] = 0x02;
	mac[1] = 0x00;
	mac[2] = 0x00;
	mac[3] = (u8)(i >> 16);
	mac[4] = (u8)(i >> 8);
	mac[5] = (u8)i;
}

'''

tests = r'''
static void profile_of(struct rtl_te_flow *te, unsigned int slot,
		       struct rtl_te_policer_profile *p)
{
	u32 words[3];

	assert(te_pol_profile_read(te, L3TE_POL_FLOW_ACC,
				   L3TE_POL_FLOW_IDX_BITS, slot, words) == 0);
	te_policer_unpack(words, p);
}

static bool profile_is_sentinel(struct rtl_te_flow *te, unsigned int slot)
{
	struct rtl_te_policer_profile p;

	profile_of(te, slot, &p);
	return p.cir_hi == 0xffff && p.cir_lo == 0x3ff &&
	       p.pir_hi == 0xffff && p.pir_lo == 0x3ff;
}

static int add_locked(struct rtl_te_flow *te, const u8 mac[RTL_TE_HOSTPOL_ALEN],
		      u32 ingress, u32 egress)
{
	return te_hostpol_add_locked(te, mac, ingress, egress,
				     RTL_TE_HOSTPOL_VMETER_AUTO,
				     RTL_TE_HOSTPOL_VMETER_AUTO);
}
static void test_constants(void)
{
	assert(RTL_TE_HOSTPOL_ENTRIES == 32);
	assert(RTL_TE_HOSTPOL_VMETERS == 32);
	assert(RTL_TE_HOSTPOL_SLOT_BASE == 0xA0);
	assert(RTL_TE_HOSTPOL_SLOT_END == 0xFF);
	assert(RTL_TE_FLOW_SLOT_COUNT == 0xA0);
	assert(RTL_TE_HOSTPOL_RATE_BASE == 0xA0);
	assert(RTL_TE_HOSTPOL_MIB_IN_BASE == 0xC0);
	assert(RTL_TE_HOSTPOL_MIB_EG_BASE == 0xE0);
	/* 160..191 rate slots, 192..223 / 224..255 fixed MIB slots */
	assert(RTL_TE_HOSTPOL_RATE_BASE + RTL_TE_HOSTPOL_VMETERS - 1u == 0xBFu);
	assert(RTL_TE_HOSTPOL_MIB_IN_BASE + RTL_TE_HOSTPOL_ENTRIES - 1u == 0xDFu);
	assert(RTL_TE_HOSTPOL_MIB_EG_BASE + RTL_TE_HOSTPOL_ENTRIES - 1u == 0xFFu);
	assert(RTL_TE_HOSTPOL_RATE_MAX == 0x1F3FFFFu);
}

static void test_rate_entry(void)
{
	struct rtl_te_policer_profile p;
	struct rtl_te_flow te;
	const struct rtl_te_hostpol *h;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	bool limited = false;
	u16 slot;
	int entry;

	mock_reset(&te);
	mac_from_index(mac, 1);
	assert(add_locked(&te, mac, 1000, 2000) == 0);

	entry = te_hostpol_find(&te, mac);
	assert(entry == 0);
	h = &te.hostpol[entry];
	assert(h->used);
	assert(h->vmeter[0] == 0 && h->vmeter[1] == 1);
	assert(h->pol1[0] == 0xA0 && h->pol1[1] == 0xA1);
	assert(te_hostpol_used(&te) == 1);
	assert(te_hostpol_vmeters_used(&te) == 2);

	profile_of(&te, 0xA0, &p);
	assert(p.cir_hi * 500 + p.cir_lo == 1000);
	assert(p.pir_hi * 500 + p.pir_lo == 1000);
	profile_of(&te, 0xA1, &p);
	assert(p.cir_hi * 500 + p.cir_lo == 2000);
	assert((te.regs[L3TE_POL_FLOW_CFG(0xA0) / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_ON);

	assert(te_hostpol_lookup_locked(&te, mac, RTL_TE_HOSTPOL_DIR_INGRESS,
					&slot, &limited) == 0);
	assert(slot == 0xA0 && limited);
	assert(te_hostpol_lookup_locked(&te, mac, RTL_TE_HOSTPOL_DIR_EGRESS,
					&slot, &limited) == 0);
	assert(slot == 0xA1 && limited);

	/* the flow policer must not hand out 0xA0..0xFF */
	assert(RTL_TE_HOSTPOL_SLOT_BASE >= RTL_TE_FLOW_SLOT_COUNT);
}

static void test_count_only_entry(void)
{
	struct rtl_te_policer_profile p;
	struct rtl_te_flow te;
	const struct rtl_te_hostpol *h;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	bool limited = true;
	u16 slot;
	int entry;

	mock_reset(&te);
	mac_from_index(mac, 7);
	assert(add_locked(&te, mac, 0, 0) == 0);

	entry = te_hostpol_find(&te, mac);
	assert(entry == 0);
	h = &te.hostpol[entry];
	assert(h->vmeter[0] == RTL_TE_HOSTPOL_VMETER_NONE);
	assert(h->vmeter[1] == RTL_TE_HOSTPOL_VMETER_NONE);
	assert(h->pol1[0] == 0xC0 + entry);
	assert(h->pol1[1] == 0xE0 + entry);
	assert(te_hostpol_vmeters_used(&te) == 0);

	/* counting-only slots still carry the unlimited profile so they count */
	assert(!profile_is_sentinel(&te, 0xC0 + entry));
	profile_of(&te, 0xC0 + entry, &p);
	assert(p.cir_hi * 500 + p.cir_lo == RTL_TE_HOSTPOL_RATE_MAX);

	/* the G3 decision binds the egress MIB slot for a counting entry */
	assert(te_hostpol_lookup_locked(&te, mac, RTL_TE_HOSTPOL_DIR_INGRESS,
					&slot, &limited) == 0);
	assert(slot == 0xE0 + entry && !limited);
	assert(te_hostpol_lookup_locked(&te, mac, RTL_TE_HOSTPOL_DIR_EGRESS,
					&slot, &limited) == 0);
	assert(slot == 0xE0 + entry && !limited);
}

static void test_mixed_direction(void)
{
	struct rtl_te_flow te;
	const struct rtl_te_hostpol *h;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	bool limited = false;
	u16 slot;
	int entry;

	/* ingress limited, egress counting only */
	mock_reset(&te);
	mac_from_index(mac, 3);
	assert(add_locked(&te, mac, 5000, 0) == 0);
	entry = te_hostpol_find(&te, mac);
	h = &te.hostpol[entry];
	assert(h->pol1[0] == 0xA0);
	assert(h->pol1[1] == 0xE0 + entry);
	assert(te_hostpol_vmeters_used(&te) == 1);

	assert(te_hostpol_lookup_locked(&te, mac, 0, &slot, &limited) == 0);
	assert(slot == 0xA0 && limited);
	assert(te_hostpol_lookup_locked(&te, mac, 1, &slot, &limited) == 0);
	assert(slot == 0xE0 + entry && !limited);

	/* ingress counting only, egress limited: the G3 decision must fall
	 * back to the egress rate slot */
	mock_reset(&te);
	mac_from_index(mac, 4);
	assert(add_locked(&te, mac, 0, 6000) == 0);
	entry = te_hostpol_find(&te, mac);
	h = &te.hostpol[entry];
	assert(h->pol1[0] == 0xC0 + entry);
	assert(h->pol1[1] == 0xA0);
	assert(te_hostpol_lookup_locked(&te, mac, 0, &slot, &limited) == 0);
	assert(slot == 0xA0 && limited);
	assert(te_hostpol_lookup_locked(&te, mac, 1, &slot, &limited) == 0);
	assert(slot == 0xA0 && limited);
}

static void test_lookup_priority(void)
{
	struct rtl_te_flow te;
	u8 a[RTL_TE_HOSTPOL_ALEN], b[RTL_TE_HOSTPOL_ALEN];
	u8 c[RTL_TE_HOSTPOL_ALEN], missing[RTL_TE_HOSTPOL_ALEN];
	bool limited;
	u16 slot;

	mock_reset(&te);
	mac_from_index(a, 1);
	mac_from_index(b, 2);
	mac_from_index(c, 3);
	mac_from_index(missing, 9);

	assert(add_locked(&te, a, 1000, 2000) == 0);	/* both limited */
	assert(add_locked(&te, b, 0, 2000) == 0);	/* egress only */
	assert(add_locked(&te, c, 0, 0) == 0);		/* counting only */

	assert(te_hostpol_lookup_locked(&te, a, 0, &slot, &limited) == 0);
	assert(slot == 0xA0 && limited);		/* ingress wins */
	assert(te_hostpol_lookup_locked(&te, b, 0, &slot, &limited) == 0);
	assert(slot == te.hostpol[1].pol1[1] && limited);	/* egress rate */
	assert(te_hostpol_lookup_locked(&te, c, 0, &slot, &limited) == 0);
	assert(slot == RTL_TE_HOSTPOL_MIB_EG_BASE + 2 && !limited);

	assert(te_hostpol_lookup_locked(&te, missing, 0, &slot, &limited) ==
	       -ENOENT);
	assert(te_hostpol_lookup_locked(&te, a, 2, &slot, &limited) == -EINVAL);
}

static void test_duplicate_mac(void)
{
	struct rtl_te_flow te;
	u8 mac[RTL_TE_HOSTPOL_ALEN];

	mock_reset(&te);
	mac_from_index(mac, 5);
	assert(add_locked(&te, mac, 1000, 1000) == 0);
	assert(add_locked(&te, mac, 2000, 2000) == -EEXIST);
	assert(te_hostpol_used(&te) == 1);
	assert(te_hostpol_vmeters_used(&te) == 2);
}

static void test_vmeter_exhaustion(void)
{
	struct rtl_te_flow te;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	unsigned int i;

	mock_reset(&te);
	/* 16 entries x 2 directions = the whole 32 vmeter pool */
	for (i = 0; i < 16; i++) {
		mac_from_index(mac, i);
		assert(add_locked(&te, mac, 1000 + i, 2000 + i) == 0);
	}
	assert(te_hostpol_used(&te) == 16);
	assert(te_hostpol_vmeters_used(&te) == 32);

	mac_from_index(mac, 16);
	assert(add_locked(&te, mac, 1000, 2000) == -ENOSPC);
	/* one direction is enough to exhaust it */
	assert(add_locked(&te, mac, 1000, 0) == -ENOSPC);
	/* a counting-only entry still fits: it uses no vmeter */
	assert(add_locked(&te, mac, 0, 0) == 0);
	assert(te_hostpol_vmeters_used(&te) == 32);
	assert(add_locked(&te, mac, 0, 0) == -EEXIST);

	/* deleting one rate entry returns two vmeters */
	mac_from_index(mac, 0);
	assert(te_hostpol_del_locked(&te, mac) == 0);
	assert(te_hostpol_vmeters_used(&te) == 30);
	mac_from_index(mac, 17);
	assert(add_locked(&te, mac, 1000, 2000) == 0);
	assert(te_hostpol_vmeters_used(&te) == 32);
}

static void test_vmeter_explicit(void)
{
	const struct rtl_te_hostpol *h;
	struct rtl_te_flow te;
	u8 a[RTL_TE_HOSTPOL_ALEN], b[RTL_TE_HOSTPOL_ALEN];
	u8 c[RTL_TE_HOSTPOL_ALEN];
	int entry;

	mock_reset(&te);
	mac_from_index(a, 1);
	mac_from_index(b, 2);
	mac_from_index(c, 3);

	/* both directions may share one virtual meter */
	assert(te_hostpol_add_locked(&te, a, 1000, 1000, 5, 5) == 0);
	entry = te_hostpol_find(&te, a);
	h = &te.hostpol[entry];
	assert(h->pol1[0] == 0xA5 && h->pol1[1] == 0xA5);
	assert(te_hostpol_vmeters_used(&te) == 1);

	/* another entry may not steal it */
	assert(te_hostpol_add_locked(&te, b, 1000, 0, 5,
				     RTL_TE_HOSTPOL_VMETER_AUTO) == -EBUSY);
	assert(te_hostpol_add_locked(&te, c, 1000, 0, 32,
				     RTL_TE_HOSTPOL_VMETER_AUTO) == -EINVAL);
	assert(te_hostpol_used(&te) == 1);

	assert(te_hostpol_add_locked(&te, b, 1000, 0, 7,
				     RTL_TE_HOSTPOL_VMETER_AUTO) == 0);
	assert(te.hostpol[te_hostpol_find(&te, b)].pol1[0] == 0xA7);
	assert(te_hostpol_vmeters_used(&te) == 2);
}

static void test_delete_releases(void)
{
	struct rtl_te_flow te;
	u8 mac[RTL_TE_HOSTPOL_ALEN];

	mock_reset(&te);
	mac_from_index(mac, 6);
	assert(add_locked(&te, mac, 1000, 2000) == 0);
	assert(te_hostpol_del_locked(&te, mac) == 0);
	assert(te_hostpol_used(&te) == 0);
	assert(te_hostpol_vmeters_used(&te) == 0);
	assert(profile_is_sentinel(&te, 0xA0));
	assert(profile_is_sentinel(&te, 0xA1));
	assert(te_hostpol_del_locked(&te, mac) == -ENOENT);

	/* the pool is reusable */
	mac_from_index(mac, 8);
	assert(add_locked(&te, mac, 3000, 4000) == 0);
	assert(te.hostpol[0].pol1[0] == 0xA0);
	assert(te.hostpol[0].pol1[1] == 0xA1);
}

static void test_entry_exhaustion(void)
{
	struct rtl_te_flow te;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	unsigned int i;

	mock_reset(&te);
	for (i = 0; i < RTL_TE_HOSTPOL_ENTRIES; i++) {
		mac_from_index(mac, i);
		assert(add_locked(&te, mac, 0, 0) == 0);
	}
	assert(te_hostpol_used(&te) == 32);
	assert(te_hostpol_vmeters_used(&te) == 0);
	mac_from_index(mac, RTL_TE_HOSTPOL_ENTRIES);
	assert(add_locked(&te, mac, 0, 0) == -ENOSPC);
}

static void test_mib(void)
{
	struct rtl_te_hostpol_mib raw[RTL_TE_HOSTPOL_DIRS];
	struct rtl_te_hostpol_mib mib;
	struct rtl_te_flow te;
	unsigned int before;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	u64 rx, tx;

	mock_reset(&te);
	assert(te.regs[L3TE_PM_CTRL / 4] & L3TE_PM_CTRL_DISABLE);
	mac_from_index(mac, 1);
	assert(add_locked(&te, mac, 1000, 2000) == 0);
	/* First hostpol add lazily clears mem_disable and keeps auto_clr */
	assert(te.pm_ready);
	assert(!(te.regs[L3TE_PM_CTRL / 4] & L3TE_PM_CTRL_DISABLE));
	assert(te.regs[L3TE_PM_CTRL / 4] & L3TE_PM_CTRL_AUTO_CLR);

	/* cnt[4] = total_bytes (data[3][3:0] << 32 | data[4]),
	 * cnt[5] = red_bytes   (data[2][7:0] << 28 | data[3] >> 4).
	 * Place small counts in data[4] / (data[3] >> 4).
	 */
	mock_mib_tab[0xA0][4] = 500;
	mock_mib_tab[0xA0][3] = (300u << L3TE_POL_MIB_C4_LO_SHIFT);
	mock_mib_tab[0xA1][4] = 900;
	mock_mib_tab[0xA1][3] = (400u << L3TE_POL_MIB_C4_LO_SHIFT);

	assert(te_hostpol_mib_sample_locked(&te, 0, &rx, &tx, raw) == 0);
	assert(raw[0].cnt[4] == 500 && raw[0].cnt[5] == 300);
	assert(raw[1].cnt[4] == 900 && raw[1].cnt[5] == 400);
	assert(rx == 200 && tx == 500);
	assert(te.hostpol[0].last_delta[0] == 200);
	assert(te.hostpol[0].last_delta[1] == 500);
	/* auto-clear drained the hardware words on read */
	assert(mock_mib_tab[0xA0][4] == 0 && mock_mib_tab[0xA1][4] == 0);

	/* raw read works and drains too */
	mock_mib_tab[0xA0][4] = 75;
	assert(te_hostpol_mib_raw_locked(&te, 0, 0, &mib) == 0);
	assert(mib.cnt[4] == 75);
	assert(mock_mib_tab[0xA0][4] == 0);

	/* a second sample accumulates the new deltas */
	mock_mib_tab[0xA0][4] = 600;
	mock_mib_tab[0xA0][3] = (350u << L3TE_POL_MIB_C4_LO_SHIFT);
	mock_mib_tab[0xA1][4] = 500;
	assert(te_hostpol_mib_get_locked(&te, 0, &rx, &tx) == 0);
	assert(rx == 200 + 250 && tx == 500 + 500);

	/* clear drains once and zeroes the software accumulation */
	before = te.nseq;
	assert(te_hostpol_mib_clear_locked(&te, 0) == 0);
	assert(te.hostpol[0].rx == 0 && te.hostpol[0].tx == 0);
	assert(te.nseq == before + 2);	/* one MIB request per direction */
	/* no hardware counter-clear register is ever written */
	{
		unsigned int i;

		for (i = 0; i < te.nseq; i++)
			assert(te.seq[i] != L3TE_POL_CNT_CLEAR_ACC);
	}

	/* unknown entry */
	assert(te_hostpol_mib_get_locked(&te, 1, &rx, &tx) == -ENOENT);
}

static void test_mib_36bit_delta(void)
{
	struct rtl_te_flow te;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	u64 rx, tx;

	mock_reset(&te);
	mac_from_index(mac, 2);
	assert(add_locked(&te, mac, 1000, 1000) == 0);

	/* Exercise 36-bit total_bytes (cnt[4]) and red_bytes (cnt[5]):
	 * cnt[4] = 0x2_0000_0000ULL, cnt[5] = 0x0_1000_0010ULL
	 * -> delta = 0x1_efff_fff0ULL (exceeds 32 bits).
	 */
	mock_mib_tab[0xA0][3] = 0x2u;		/* cnt[4][35:32]=2, cnt[5][27:0]=0 */
	mock_mib_tab[0xA0][4] = 0x0u;
	mock_mib_tab[0xA0][2] = 0x1u;		/* cnt[5][35:28]=1 */
	mock_mib_tab[0xA0][3] |= (0x10u << L3TE_POL_MIB_C4_LO_SHIFT);
	mock_mib_tab[0xA1][4] = 0;
	mock_mib_tab[0xA1][3] = 0;

	assert(te_hostpol_mib_get_locked(&te, 0, &rx, &tx) == 0);
	assert(rx == 0x1effffff0ULL);
	assert(te.hostpol[0].last_delta[0] == 0x1effffff0ULL);
	assert(tx == 0);

	/* an inverted sample is ignored rather than wrapping */
	mock_mib_tab[0xA0][4] = 0x10u;
	mock_mib_tab[0xA0][3] = (0x20u << L3TE_POL_MIB_C4_LO_SHIFT);
	assert(te_hostpol_mib_get_locked(&te, 0, &rx, &tx) == 0);
	assert(rx == 0x1effffff0ULL);	/* unchanged */
	assert(te.hostpol[0].last_delta[0] == 0);
}

static void test_no_writes_by_default(void)
{
	struct rtl_te_flow te;
	u8 mac[RTL_TE_HOSTPOL_ALEN];
	bool limited;
	u16 slot;

	mock_reset(&te);
	mac_from_index(mac, 1);
	/* table queries and a lookup on an empty table never touch a register */
	assert(te_hostpol_used(&te) == 0);
	assert(te_hostpol_vmeters_used(&te) == 0);
	assert(te_hostpol_find(&te, mac) == -ENOENT);
	assert(te_hostpol_lookup_locked(&te, mac, 0, &slot, &limited) ==
	       -ENOENT);
	assert(te.accesses == 0);
	assert(te.nseq == 0);
	/* and the reserved host window is outside the flow policer range */
	assert(RTL_TE_HOSTPOL_SLOT_BASE >= RTL_TE_FLOW_SLOT_COUNT);
}

static void test_flow_pool_separation(void)
{
	struct rtl_te_flow te;
	unsigned int i, slot;

	mock_reset(&te);
	/* POL1 0xA0..0xFF belongs to host policing: the flow allocator stops
	 * at 160 slots and never returns a host slot. */
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT; i++) {
		assert(te_flow_alloc_locked(&te, 1000000ull, 1000000ull,
					    0x100u, 0x100u, &slot) == 0);
		assert(slot == i);
	}
	assert(te_flow_alloc_locked(&te, 1000000ull, 1000000ull, 0x100u,
				    0x100u, &slot) == -ENOSPC);
	assert(te_flow_update_locked(&te, 0, 2000000ull, 2000000ull, 0x200u,
				     0x200u) == 0);
	assert(te_flow_free_locked(&te, 0) == 0);
	assert(te_flow_alloc_locked(&te, 1000000ull, 1000000ull, 0x100u,
				    0x100u, &slot) == 0 && slot == 0);
	assert(te_flow_update_locked(&te, 200, 2000000ull, 2000000ull, 0x200u,
				     0x200u) == -EINVAL);
}

int main(void)
{
	test_constants();
	test_rate_entry();
	test_count_only_entry();
	test_mixed_direction();
	test_lookup_priority();
	test_duplicate_mac();
	test_vmeter_exhaustion();
	test_vmeter_explicit();
	test_delete_releases();
	test_entry_exhaustion();
	test_mib();
	test_mib_36bit_delta();
	test_flow_pool_separation();
	test_no_writes_by_default();
	puts("PASS: host policing 32 entries / 32 vmeters: rate slots 0xA0+v, "
	     "fixed MIB slots 0xC0/0xE0+idx, duplicate MAC refused, vmeter "
	     "exhaustion, lookup priority, 36 bit total_bytes-red_bytes delta, "
	     "lazy TE_PM_CTRL enable, no hardware clear write, no writes by default");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-hostpol-') as directory:
    test = Path(directory) / 'hostpol.c'
    binary = Path(directory) / 'hostpol'
    test.write_text(prefix_head + defines + '\n' + profile + '\n' + entry + '\n' +
                    mib + '\n' + prefix_body + policer_block + hostpol_block +
                    tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(test), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)