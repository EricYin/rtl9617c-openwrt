#!/usr/bin/env python3
"""Compile the L3TE policer slot logic from ni_te_flow.c against a mock regmap.

The extracted region is the real driver code: rate splitting, profile packing,
the idle sentinel test, the indirect DATA0..DATA2 walker, the 32 slot cfg bank
scan and the flow/group allocators. Only te_read()/te_write() and the bitmap
primitives are substituted.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/ni'
source = (DRIVER / 'ni_te_flow.c').read_text()
header = (DRIVER / 'ni_te_flow.h').read_text()

start = source.index('/* ==== BEGIN test-extractable logic')
end = source.index('/* ==== END test-extractable logic')
functions = source[start:end]

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
profile = re.search(r'struct rtl_te_policer_profile \{.*?\n\};', header, re.S).group(0)

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
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (63 - (h))))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __set_bit(i, b) ((b)[(i) / 64] |= (1UL << ((i) % 64)))
#define __clear_bit(i, b) ((b)[(i) / 64] &= ~(1UL << ((i) % 64)))
#define test_bit(i, b) (((b)[(i) / 64] >> ((i) % 64)) & 1UL)
#define udelay(x) ((void)(x))
#define wmb() do { } while (0)
#define rmb() do { } while (0)
'''

prefix_body = r'''
struct rtl_te_flow {
	u32 regs[0x10000 / 4];
	unsigned long flow_slots[L3TE_POL_FLOW_SLOTS / 64];
	unsigned long group_slots[L3TE_POL_GRP_SLOTS / 64];
	bool stall;
	bool group64_ready;
	bool ro_glb_ctrl;
	int accesses;
	u32 last_cmd;
	u32 last_acc;
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
	assert(!(off & 3u));
	assert(off < sizeof(te->regs));
	return te->regs[off / 4];
}

static void te_write(struct rtl_te_flow *te, u32 off, u32 val)
{
	unsigned int i, j;

	if (off >= sizeof(te->regs)) { fprintf(stderr, "bad off %#x\n", off); abort(); }
	if (te->ro_glb_ctrl && off == L3TE_TE_GLB_CTRL)
		return;			/* write-protected depth register */
	te->regs[off / 4] = val;
	te->accesses++;
	/* only an ACCESS register address can start a table transfer: data
	 * words legitimately carry BIT(31) in their payload.
	 */
	for (i = 0; i < ARRAY_SIZE(mock_tables); i++)
		if (mock_tables[i].acc == off)
			break;
	if (i == ARRAY_SIZE(mock_tables))
		return;
	te->last_cmd = val;
	te->last_acc = off;
	if (te->stall || !(val & L3TE_IND_BUSY))
		return;
	{
		struct te_table *t = &mock_tables[i];
		unsigned int idx;

		idx = val & ((1u << t->idx_bits) - 1u);
		assert(idx < t->slots);
		for (j = 0; j < t->words; j++) {
			u32 addr = off + 4u * (t->words - j);

			if (val & L3TE_IND_WRITE)
				t->mem[idx * t->words + j] = te->regs[addr / 4];
			else
				te->regs[addr / 4] = t->mem[idx * t->words + j];
		}
		/* completion: clear BUSY, keep the rest of the command word */
		te->regs[off / 4] = val & ~((u32)L3TE_IND_BUSY);
	}
}

static void mock_reset(struct rtl_te_flow *te)
{
	/* An untouched hardware profile entry reads back with the four rate
	 * fields all ones (that is exactly what the vendor idle test checks),
	 * so the mock powers up the policer tables in that state.
	 */
	static const u32 idle[3] = { 0xffffffffu, 0xffffffffu, 0x00000fffu };
	unsigned int i;

	memset(te, 0, sizeof(*te));
	memset(mock_flow_tab, 0, sizeof(mock_flow_tab));
	memset(mock_grp_tab, 0, sizeof(mock_grp_tab));
	memset(mock_sel_tab, 0, sizeof(mock_sel_tab));
	memset(mock_wred_tab, 0, sizeof(mock_wred_tab));
	for (i = 0; i < L3TE_POL_FLOW_SLOTS; i++)
		memcpy(&mock_flow_tab[i][0], idle, sizeof(idle));
	for (i = 0; i < L3TE_POL_GRP_SLOTS; i++)
		memcpy(&mock_grp_tab[i][0], idle, sizeof(idle));
}

static void mock_put(u32 *tab, unsigned int words, unsigned int idx,
		     const u32 *values)
{
	memcpy(&tab[idx * words], values, words * sizeof(u32));
}

static void mock_expect(const u32 *tab, unsigned int words, unsigned int idx,
			const u32 *values)
{
	assert(memcmp(&tab[idx * words], values, words * sizeof(u32)) == 0);
}
'''

tests = r'''
static void test_rate_and_pack(void)
{
	struct rtl_te_policer_profile p, back;
	u32 words[3], sentinel[3];

	assert(L3TE_POL_RATE_MAX_KBPS == 32767999u);
	assert(te_policer_encode_rate(1000000ull, &p.cir_hi, &p.cir_lo) == 0);
	assert(p.cir_hi == 2 && p.cir_lo == 0);
	assert(te_policer_encode_rate(1000499ull, &p.cir_hi, &p.cir_lo) == 0);
	assert(p.cir_hi == 2 && p.cir_lo == 1);
	assert(te_policer_encode_rate(0ull, &p.cir_hi, &p.cir_lo) == -ERANGE);
	assert(te_policer_encode_rate(32768000000ull, &p.cir_hi, &p.cir_lo) ==
	       -ERANGE);
	assert(te_policer_encode_rate(32767999000ull, &p.cir_hi, &p.cir_lo) == 0);
	assert(p.cir_hi == 0xffff && p.cir_lo == 499);

	assert(te_policer_encode(980000ull, 1960000ull, 0x800, 0xabc, &p) == 0);
	assert(p.cir_hi == 1 && p.cir_lo == 480);
	assert(p.pir_hi == 3 && p.pir_lo == 460);
	te_policer_pack(&p, words);
	assert(words[0] == 0x5e0u);
	assert(words[1] == 0x37320u);
	assert(words[2] == 0xabcu);
	te_policer_unpack(words, &back);
	assert(back.cir_lo == 480 && back.cir_hi == 1 && back.cbs == 0x800);
	assert(back.pir_lo == 460 && back.pir_hi == 3 && back.pbs == 0xabc);
	assert(!te_policer_idle(words));

	te_policer_sentinel(sentinel);
	assert(sentinel[0] == 0xffffffffu);
	assert(sentinel[1] == 0xffffffffu);
	assert(sentinel[2] == 0x00000fffu);
	assert(te_policer_idle(sentinel));

	/* one live field is enough to make an entry look used */
	te_policer_unpack(sentinel, &back);
	back.cir_lo = 0x3fe;
	te_policer_pack(&back, words);
	assert(!te_policer_idle(words));
}

static void test_flow_slots(void)
{
	struct rtl_te_policer_profile p;
	struct rtl_te_flow te;
	unsigned int i, slot;
	u32 words[3], sentinel[3];
	int ret;

	mock_reset(&te);
	assert(L3TE_POL_FLOW_SLOTS == 256u);
	assert(L3TE_POL_FLOW_CFG(0) == 0x9108u);
	assert(L3TE_POL_FLOW_CFG(31) == 0x9108u);
	assert(L3TE_POL_FLOW_CFG(32) == 0x910cu);
	assert(L3TE_POL_FLOW_CFG(255) == 0x9124u);

	/* POL1 0xA0..0xFF belongs to host policing, so only 160 slots */
	assert(RTL_TE_FLOW_SLOT_COUNT == 160u);
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT; i++) {
		u64 cir = (u64)(i + 1) * 1000ull;
		u64 pir = (u64)(i + 2) * 1000ull;

		ret = te_flow_alloc_locked(&te, cir, pir, 0x100u + i, 0x200u + i,
					   &slot);
		if (ret) {
			fprintf(stderr, "alloc %u failed: %d\n", i, ret);
			abort();
		}
		assert(slot == i);
		assert(test_bit(i, te.flow_slots));
	}
	assert(te.flow_slots[0] == ~0UL);
	assert(te.flow_slots[1] == ~0UL);
	assert(te.flow_slots[2] == 0xffffffffUL);	/* bits 128..159 */
	assert(te.flow_slots[3] == 0UL);		/* reserved window untouched */

	ret = te_flow_alloc_locked(&te, 1000ull, 2000ull, 512, 512, &slot);
	assert(ret == -ENOSPC);

	/* every bank that holds a flow slot must now read "on" */
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT / L3TE_POL_BANK_SLOTS; i++)
		assert((te.regs[(0x9108u + 4u * i) / 4] & L3TE_POL_CFG_TYPE) ==
		       L3TE_POL_CFG_TYPE_ON);

	/* DATA0 really sits at the highest address of the entry */
	assert(te_policer_encode(1000000ull, 2000000ull, 0x123, 0x456,
				 &p) == 0);
	te_policer_pack(&p, words);
	assert(te_pol_profile_write(&te, L3TE_POL_FLOW_ACC,
				    L3TE_POL_FLOW_IDX_BITS, 0, words) == 0);
	assert(te.regs[L3TE_POL_FLOW_DATA0 / 4] == words[0]);
	assert(te.regs[L3TE_POL_FLOW_DATA1 / 4] == words[1]);
	assert(te.regs[L3TE_POL_FLOW_DATA2 / 4] == words[2]);
	/* ACCESS command: bit31 start, bit30 write, low bits = index */
	assert(te.last_acc == L3TE_POL_FLOW_ACC);
	assert(te.last_cmd == (L3TE_IND_BUSY | L3TE_IND_WRITE));

	/* update rewrites only the profile */
	ret = te_flow_update_locked(&te, 0, 3000000ull, 4000000ull, 0x200, 0x300);
	assert(ret == 0);
	assert(te_pol_profile_read(&te, L3TE_POL_FLOW_ACC,
				   L3TE_POL_FLOW_IDX_BITS, 0, words) == 0);
	te_policer_unpack(words, &p);
	assert(p.cir_hi * L3TE_POL_RATE_DIVISOR + p.cir_lo == 3000);
	assert(p.pir_hi * L3TE_POL_RATE_DIVISOR + p.pir_lo == 4000);
	assert(p.cbs == 0x200 && p.pbs == 0x300);
	assert(te_flow_update_locked(&te, L3TE_POL_FLOW_SLOTS, 3000000ull,
				     4000000ull, 0x200, 0x300) == -EINVAL);

	te_policer_sentinel(sentinel);
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT; i++) {
		ret = te_flow_free_locked(&te, i);
		assert(ret == 0);
		assert(!test_bit(i, te.flow_slots));
		mock_expect(&mock_flow_tab[0][0], 3, i, sentinel);
	}
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT / L3TE_POL_BANK_SLOTS; i++)
		assert((te.regs[(0x9108u + 4u * i) / 4] & L3TE_POL_CFG_TYPE) ==
		       L3TE_POL_CFG_TYPE_OFF);

	/* double free, out of range, and update of a released slot */
	assert(te_flow_free_locked(&te, 0) == -EINVAL);
	assert(te_flow_free_locked(&te, 255) == -EINVAL);
	assert(te_flow_free_locked(&te, 256) == -EINVAL);
	assert(te_flow_update_locked(&te, 0, 3000000ull, 4000000ull, 0x200,
				     0x300) == -EINVAL);
}

static void test_bank_sharing(void)
{
	struct rtl_te_policer_profile p;
	struct rtl_te_flow te;
	unsigned int slot;
	u32 live[3], sentinel[3], cfg;
	int ret;

	mock_reset(&te);
	/* a foreign (not allocated here) live profile in slot 5 of bank 0 */
	assert(te_policer_encode(5000000ull, 6000000ull, 0x400, 0x500,
				 &p) == 0);
	te_policer_pack(&p, live);
	mock_put(&mock_flow_tab[0][0], 3, 5, live);
	te_policer_sentinel(sentinel);

	/* cfg still "off": the bank cannot be enabled without disturbing slot 5 */
	ret = te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512, &slot);
	assert(ret == -EBUSY);
	assert(!test_bit(0, te.flow_slots));
	mock_expect(&mock_flow_tab[0][0], 3, 0, sentinel);
	assert((te.regs[L3TE_POL_FLOW_CFG(0) / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);

	/* cfg already "on" with an unrelated preserved bit: keep the write out */
	cfg = L3TE_POL_CFG_TYPE_ON | BIT(3);
	te.regs[L3TE_POL_FLOW_CFG(0) / 4] = cfg;
	ret = te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512, &slot);
	assert(ret == 0 && slot == 0);
	assert(te.regs[L3TE_POL_FLOW_CFG(0) / 4] == cfg);

	/* freeing while a sibling lives must not clear the shared cfg */
	assert(te_flow_free_locked(&te, 0) == 0);
	assert(te.regs[L3TE_POL_FLOW_CFG(0) / 4] == cfg);
	mock_expect(&mock_flow_tab[0][0], 3, 0, sentinel);

	/* once the bank is idle again the cfg type goes back to off */
	mock_put(&mock_flow_tab[0][0], 3, 5, sentinel);
	assert(te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				    &slot) == 0);
	assert(slot == 0);
	assert(te_flow_free_locked(&te, 0) == 0);
	assert(te.regs[L3TE_POL_FLOW_CFG(0) / 4] == BIT(3));

	/* the next bank is independent */
	assert(te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				    &slot) == 0);
	assert(slot == 0);
	assert(te_flow_free_locked(&te, 0) == 0);
}

static void test_group_slots(void)
{
	struct rtl_te_flow te;
	unsigned int i, slot;
	u32 sentinel[3];
	int ret;

	mock_reset(&te);
	assert(L3TE_POL_GRP_SLOTS == 64u);
	assert(L3TE_POL_GRP_CFG(0) == 0x9144u);
	assert(L3TE_POL_GRP_CFG(31) == 0x9144u);
	assert(L3TE_POL_GRP_CFG(32) == 0x9148u);
	assert(L3TE_POL_GRP_CFG(63) == 0x9148u);

	for (i = 0; i < L3TE_POL_GRP_SLOTS; i++) {
		ret = te_group_alloc_locked(&te, (u64)(i + 1) * 1000ull,
					    (u64)(i + 2) * 1000ull,
					    0x100u + i, 0x100u + i, &slot);
		assert(ret == 0 && slot == i);
	}
	assert(te.group_slots[0] == ~0UL);
	ret = te_group_alloc_locked(&te, 1000ull, 2000ull, 512, 512, &slot);
	assert(ret == -ENOSPC);
	assert((te.regs[0x9144u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_ON);
	assert((te.regs[0x9148u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_ON);

	te_policer_sentinel(sentinel);
	for (i = 0; i < L3TE_POL_GRP_SLOTS; i++) {
		assert(te_group_free_locked(&te, i) == 0);
		mock_expect(&mock_grp_tab[0][0], 3, i, sentinel);
	}
	assert((te.regs[0x9144u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);
	assert((te.regs[0x9148u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);

	assert(te_group_free_locked(&te, 0) == -EINVAL);
	assert(te_group_free_locked(&te, 64) == -EINVAL);
	assert(te_group_update_locked(&te, 0, 1000ull, 2000ull, 512, 512) ==
	       -EINVAL);
}

static void test_wred_sel(void)
{
	struct rtl_te_flow te;
	u32 words[2];
	unsigned int f;

	mock_reset(&te);
	memset(words, 0, sizeof(words));
	for (f = 0; f < L3TE_WRED_SEL_FIELDS; f++)
		te_wred_sel_field_set(words, f, 0x1f);
	assert(words[0] == 0xffffffffu);
	assert(words[1] == 0x000000ffu);
	for (f = 0; f < L3TE_WRED_SEL_FIELDS; f++)
		assert(te_wred_sel_field_get(words, f) == 0x1f);

	/* field 6 straddles word0[31:30] and word1[2:0] */
	memset(words, 0, sizeof(words));
	te_wred_sel_field_set(words, 6, 0x15);	/* 0b10101 */
	assert(te_wred_sel_field_get(words, 6) == 0x15);
	assert((words[0] >> 30) == 0x1);
	assert((words[1] & 0x7) == 0x5);

	/* RMW keeps every other field of the entry intact */
	mock_sel_tab[3][0] = 0xffffffffu;
	mock_sel_tab[3][1] = 0x000000ffu;
	assert(te_wred_sel_update_locked(&te, 3, 2, 7) == 0);
	assert(te_wred_sel_field_get(mock_sel_tab[3], 2) == 7);
	for (f = 0; f < L3TE_WRED_SEL_FIELDS; f++)
		if (f != 2)
			assert(te_wred_sel_field_get(mock_sel_tab[3], f) == 0x1f);

	/* one entry per queue, no aliasing below 64 */
	assert(te_wred_sel_update_locked(&te, 1, 0, 9) == 0);
	assert(te_wred_sel_field_get(mock_sel_tab[1], 0) == 9);
	assert(te_wred_sel_field_get(mock_sel_tab[3], 0) == 0x1f);
}

static void test_wred_profile_words(void)
{
	struct rtl_te_flow te;
	u32 in[L3TE_WRED_PROF_WORDS];
	u32 out[L3TE_WRED_PROF_WORDS];
	unsigned int i;

	mock_reset(&te);
	for (i = 0; i < L3TE_WRED_PROF_WORDS; i++)
		in[i] = 0x11111111u * (i + 1);
	assert(te_table_access(&te, L3TE_WRED_PROF_ACC, L3TE_WRED_PROF_IDX_BITS,
			       true, 9, in, L3TE_WRED_PROF_WORDS) == 0);
	assert(te.regs[L3TE_WRED_PROF_DATA(0) / 4] == in[0]);
	assert(te.regs[L3TE_WRED_PROF_DATA(7) / 4] == in[7]);
	memset(out, 0, sizeof(out));
	assert(te_table_access(&te, L3TE_WRED_PROF_ACC, L3TE_WRED_PROF_IDX_BITS,
			       false, 9, out, L3TE_WRED_PROF_WORDS) == 0);
	assert(memcmp(in, out, sizeof(in)) == 0);
}

static void test_limits_and_timeout(void)
{
	struct rtl_te_flow te;
	unsigned int slot;
	u32 sentinel[3];
	int ret;

	mock_reset(&te);
	assert(te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 0, 512,
				    &slot) == -EINVAL);
	assert(te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 0,
				    &slot) == -EINVAL);
	assert(te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 0x1000, 512,
				    &slot) == -EINVAL);
	assert(te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 0x1000,
				    &slot) == -EINVAL);
	assert(te_flow_alloc_locked(&te, 3000000ull, 2000000ull, 512, 512,
				    &slot) == -EINVAL);
	assert(te_flow_alloc_locked(&te, 40000000000ull, 40000000000ull, 512,
				    512, &slot) == -ERANGE);
	assert(!te.flow_slots[0]);

	/* a stuck BUSY bit must fail cleanly and leave the slot untouched */
	te.stall = true;
	ret = te_flow_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512, &slot);
	assert(ret == -ETIMEDOUT);
	assert(!test_bit(0, te.flow_slots));
	te_policer_sentinel(sentinel);
	assert((te.regs[L3TE_POL_FLOW_CFG(0) / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);
}

static void test_group_bank_sharing(void)
{
	struct rtl_te_policer_profile p;
	struct rtl_te_flow te;
	unsigned int slot;
	u32 live[3], sentinel[3];

	mock_reset(&te);
	te_policer_sentinel(sentinel);
	assert(te_policer_encode(5000000ull, 6000000ull, 0x400, 0x500,
				 &p) == 0);
	te_policer_pack(&p, live);

	/* a live foreign profile in group 5 (cfg bank 0) with cfg still off
	 * means the bank cannot be enabled without disturbing it
	 */
	mock_put(&mock_grp_tab[0][0], 3, 5, live);
	assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				     &slot) == -EBUSY);
	assert(!test_bit(0, te.group_slots));
	assert((te.regs[0x9144u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);

	/* a live profile in bank 1 must not disturb an allocation in bank 0 */
	mock_put(&mock_grp_tab[0][0], 3, 40, live);
	mock_put(&mock_grp_tab[0][0], 3, 5, sentinel);
	assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				     &slot) == 0);
	assert(slot == 0);
	assert((te.regs[0x9144u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_ON);
	assert((te.regs[0x9148u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);

	/* a second group in the same bank keeps the shared cfg untouched */
	{
		u32 cfg = te.regs[0x9144u / 4];

		assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512,
					     512, &slot) == 0);
		assert(slot == 1);
		assert(te.regs[0x9144u / 4] == cfg);
	}
}

static void test_group_depth_lazy(void)
{
	struct rtl_te_flow te;
	unsigned int slot;
	u32 sentinel[3];

	mock_reset(&te);
	te_policer_sentinel(sentinel);
	/* nothing touches 0x9004 until a group policer is actually requested */
	assert(L3TE_TE_GLB_CTRL == 0x9004u);
	assert(te.regs[L3TE_TE_GLB_CTRL / 4] == 0);
	assert(!te.group64_ready);
	assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				     &slot) == 0);
	assert(slot == 0);
	assert(te.group64_ready);
	assert(te.regs[L3TE_TE_GLB_CTRL / 4] == L3TE_TE_GLB_POL_GRP_64);

	/* the depth is written once, not on every allocation */
	mock_reset(&te);
	te.regs[L3TE_TE_GLB_CTRL / 4] = L3TE_TE_GLB_POL_GRP_64;
	assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				     &slot) == 0);
	assert(te.regs[L3TE_TE_GLB_CTRL / 4] == L3TE_TE_GLB_POL_GRP_64);

	/* rtl_te_flow_init() already saw bit25 set: no write at all */
	mock_reset(&te);
	te.group64_ready = true;
	assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				     &slot) == 0);
	assert(te.regs[L3TE_TE_GLB_CTRL / 4] == 0);

	/* read-back failure is a clean -EIO: no slot, profile or cfg written */
	mock_reset(&te);
	te.ro_glb_ctrl = true;
	assert(te_group_alloc_locked(&te, 1000000ull, 2000000ull, 512, 512,
				     &slot) == -EIO);
	assert(!te.group64_ready);
	assert(!test_bit(0, te.group_slots));
	mock_expect(&mock_grp_tab[0][0], 3, 0, sentinel);
	assert((te.regs[0x9144u / 4] & L3TE_POL_CFG_TYPE) ==
	       L3TE_POL_CFG_TYPE_OFF);
}

int main(void)
{
	test_rate_and_pack();
	test_flow_slots();
	test_bank_sharing();
	test_group_slots();
	test_group_depth_lazy();
	test_wred_sel();
	test_wred_profile_words();
	test_limits_and_timeout();
	test_group_bank_sharing();
	puts("PASS: L3TE policer rate split/pack, 160 flow (0..159) + 64 group "
	     "slots, "
	     "cfg bank sentinel scan, double free, ENOSPC/ERANGE/EINVAL, "
	     "DATA0 ordering, WRED select field RMW");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-te-policer-') as directory:
    test = Path(directory) / 'te.c'
    binary = Path(directory) / 'te'
    test.write_text(prefix_head + defines + '\n' + profile + '\n' +
                    prefix_body + functions + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(test), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)