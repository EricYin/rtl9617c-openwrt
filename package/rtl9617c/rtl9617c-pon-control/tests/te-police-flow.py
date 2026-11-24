#!/usr/bin/env python3
"""Compile the FE FLOW_ACTION_POLICE glue against the real L3TE allocator.

Two regions of shipped driver code are extracted and linked together:

  * fe/fe_main.c  - rtl_fe_police_encode()/alloc()/free(), the tc action
                    translation and the per-flow slot bookkeeping.
  * ni/ni_te_flow.c - the 256 slot L3TE allocator (same test-extractable block
                    that tests/te-policer.py uses), so slot reuse, the bank
                    sentinel scan and ENOSPC are the real thing, not a stub.

Only te_read()/te_write(), the bitmap primitives and the two public
rtl_te_policer_* entry points are substituted.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c'
fe_source = (DRIVER / 'fe/fe_main.c').read_text()
ni_source = (DRIVER / 'ni/ni_te_flow.c').read_text()
ni_header = (DRIVER / 'ni/ni_te_flow.h').read_text()

def grab_function(source, signature):
    """Return one function definition, including its body."""
    start = source.index(signature)
    depth = 0
    seen = False
    for i in range(start, len(source)):
        ch = source[i]
        if ch == '{':
            depth += 1
            seen = True
        elif ch == '}':
            depth -= 1
            if seen and depth == 0:
                return source[start:i + 1]
    raise AssertionError('unterminated function: ' + signature)


fe_block = ''.join(grab_function(fe_source, signature) + '\n\n'
                   for signature in (
                       'static int rtl_fe_police_encode(',
                       'static int rtl_fe_police_alloc(',
                       'static int rtl_fe_police_free(',
                   ))

ni_start = ni_source.index('static int te_policer_encode_rate(')
ni_end = ni_source.index('static int te_group_depth_ready(', ni_start)
ni_block = ni_source[ni_start:ni_end]

_lines = ni_header.splitlines()
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
profile = re.search(r'struct rtl_te_policer_profile \{.*?\n\};', ni_header,
                    re.S).group(0)

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

/* enum flow_action_id values from include/net/flow_offload.h */
#define FLOW_ACTION_ACCEPT 0
#define FLOW_ACTION_DROP 1
'''

scaffold = r'''
struct rtl_te_flow {
	u32 regs[0x10000 / 4];
	unsigned long flow_slots[L3TE_POL_FLOW_SLOTS / 64];
	unsigned long group_slots[L3TE_POL_GRP_SLOTS / 64];
	bool stall;
	bool group64_ready;
	bool ro_glb_ctrl;
	int accesses;
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
	if (off >= sizeof(te->regs)) { fprintf(stderr, "bad off %#x\n", off); abort(); }
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
	for (i = 0; i < ARRAY_SIZE(mock_tables); i++)
		if (mock_tables[i].acc == off)
			break;
	if (i == ARRAY_SIZE(mock_tables))
		return;
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
		te->regs[off / 4] = val & ~((u32)L3TE_IND_BUSY);
	}
}

static void mock_reset(struct rtl_te_flow *te)
{
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

static void mock_expect(const u32 *tab, unsigned int words, unsigned int idx,
			const u32 *values)
{
	assert(memcmp(&tab[idx * words], values, words * sizeof(u32)) == 0);
}
'''

shims = r'''
/* Public entry points the FE glue links against, mapped onto the real
 * allocator extracted from ni_te_flow.c above. */
static int rtl_te_policer_alloc(struct rtl_te_flow *te, u64 cir_bps,
				u64 pir_bps, u32 cbs_bytes, u32 pbs_bytes,
				u8 *slot)
{
	unsigned int idx;
	int ret;

	ret = te_flow_alloc_locked(te, cir_bps, pir_bps, cbs_bytes, pbs_bytes,
				   &idx);
	if (!ret)
		*slot = (u8)idx;
	return ret;
}

static int rtl_te_policer_free(struct rtl_te_flow *te, u8 slot)
{
	return te_flow_free_locked(te, slot);
}
'''

tests = r'''
static void test_encode(void)
{
	u32 kbps = 0, burst = 0;

	/* the only accepted terminal actions */
	assert(rtl_fe_police_encode(125000ull, 1500, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) == 0);
	assert(kbps == 1000 && burst == 1500);

	/* anything else is refused */
	assert(rtl_fe_police_encode(125000ull, 1500, FLOW_ACTION_ACCEPT,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) ==
	       -EOPNOTSUPP);
	assert(rtl_fe_police_encode(125000ull, 1500, FLOW_ACTION_DROP,
				    FLOW_ACTION_DROP, &kbps, &burst) ==
	       -EOPNOTSUPP);

	/* rate: zero, rounding and the encodable maximum */
	assert(rtl_fe_police_encode(0ull, 1500, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) ==
	       -EOPNOTSUPP);
	assert(rtl_fe_police_encode(125001ull, 1500, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) == 0);
	assert(kbps == 1001);
	assert(rtl_fe_police_encode(4095999875ull, 1500, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) == 0);
	assert(kbps == L3TE_POL_RATE_MAX_KBPS);
	assert(rtl_fe_police_encode(4095999876ull, 1500, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) ==
	       -EOPNOTSUPP);

	/* burst: the 12 bit field, 0 is rejected by the hardware profile */
	assert(rtl_fe_police_encode(125000ull, 0, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) ==
	       -EOPNOTSUPP);
	assert(rtl_fe_police_encode(125000ull, 1, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) == 0);
	assert(rtl_fe_police_encode(125000ull, 4095, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) == 0);
	assert(rtl_fe_police_encode(125000ull, 4096, FLOW_ACTION_DROP,
				    FLOW_ACTION_ACCEPT, &kbps, &burst) ==
	       -EOPNOTSUPP);
}

static void test_slot_lifecycle(void)
{
	struct rtl_te_policer_profile prof;
	struct rtl_te_flow te;
	u8 slot = 0xaa;
	bool owned = false;
	u32 words[3];
	u32 sentinel[3];
	int calls;

	mock_reset(&te);
	te_policer_sentinel(sentinel);

	assert(rtl_fe_police_alloc(&te, 1000, 1500, &slot, &owned) == 0);
	assert(owned && slot == 0);
	assert(test_bit(0, te.flow_slots));
	assert(te.regs[L3TE_POL_FLOW_CFG(0) / 4] & L3TE_POL_CFG_TYPE);

	/* the requested kbps/burst really reached the profile entry */
	assert(te_pol_profile_read(&te, L3TE_POL_FLOW_ACC,
				   L3TE_POL_FLOW_IDX_BITS, 0, words) == 0);
	te_policer_unpack(words, &prof);
	assert(prof.cir_hi * 500u + prof.cir_lo == 1000);
	assert(prof.pir_hi * 500u + prof.pir_lo == 1000);
	assert(prof.cbs == 1500 && prof.pbs == 1500);

	/* a rate change goes through the same slot */
	assert(te_flow_update_locked(&te, 0, 3000000ull, 3000000ull, 2048,
				     2048) == 0);
	assert(te_pol_profile_read(&te, L3TE_POL_FLOW_ACC,
				   L3TE_POL_FLOW_IDX_BITS, 0, words) == 0);
	te_policer_unpack(words, &prof);
	assert(prof.cir_hi * 500u + prof.cir_lo == 3000);
	assert(prof.cbs == 2048 && prof.pbs == 2048);
	/* ... but never for a slot this flow does not own */
	assert(te_flow_update_locked(&te, 1, 3000000ull, 3000000ull, 2048,
				     2048) == -EINVAL);

	/* install failure / delete: the slot goes back to the pool */
	assert(rtl_fe_police_free(&te, slot, &owned) == 0);
	assert(!owned);
	assert(!test_bit(0, te.flow_slots));
	mock_expect(&mock_flow_tab[0][0], 3, 0, sentinel);
	assert((te.regs[L3TE_POL_FLOW_CFG(0) / 4] & L3TE_POL_CFG_TYPE) == 0);

	/* double free is a no-op and must not touch the hardware again */
	calls = te.accesses;
	assert(rtl_fe_police_free(&te, slot, &owned) == 0);
	assert(!owned);
	assert(te.accesses == calls);

	/* rollback leaves slot 0 free: the next flow gets it again */
	assert(rtl_fe_police_alloc(&te, 2000, 512, &slot, &owned) == 0);
	assert(owned && slot == 0);

	/* a flow can never own two slots */
	assert(rtl_fe_police_alloc(&te, 2000, 512, &slot, &owned) == -EEXIST);
	assert(rtl_fe_police_free(&te, slot, &owned) == 0);
}

static void test_no_police(void)
{
	struct rtl_te_flow te;
	u8 slot = 0;
	bool owned = false;

	mock_reset(&te);
	/* a flow without FLOW_ACTION_POLICE never reaches this code, and the
	 * bookkeeping defaults must make it a hard no-op if it ever does */
	assert(rtl_fe_police_free(&te, slot, &owned) == 0);
	assert(te.accesses == 0);
	assert(!te.flow_slots[0]);

	/* alloc with no police layer available is refused, not ignored */
	assert(rtl_fe_police_alloc(NULL, 1000, 1500, &slot, &owned) ==
	       -EOPNOTSUPP);
	assert(!owned);
	owned = true;
	assert(rtl_fe_police_free(NULL, slot, &owned) == 0);
	assert(!owned);
}

static void test_exhaustion(void)
{
	struct rtl_te_flow te;
	u8 slot[RTL_TE_FLOW_SLOT_COUNT + 1];
	bool owned[RTL_TE_FLOW_SLOT_COUNT + 1];
	unsigned int i;

	/* POL1 0xA0..0xFF is reserved for host policing */
	assert(RTL_TE_FLOW_SLOT_COUNT == 160u);
	mock_reset(&te);
	memset(slot, 0, sizeof(slot));
	memset(owned, 0, sizeof(owned));
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT; i++) {
		assert(rtl_fe_police_alloc(&te, 1000, 512, &slot[i], &owned[i]) ==
		       0);
		assert(owned[i]);
		assert(slot[i] == i);
	}
	assert(rtl_fe_police_alloc(&te, 1000, 512,
				   &slot[RTL_TE_FLOW_SLOT_COUNT],
				   &owned[RTL_TE_FLOW_SLOT_COUNT]) == -ENOSPC);
	assert(!owned[RTL_TE_FLOW_SLOT_COUNT]);

	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT; i++)
		assert(rtl_fe_police_free(&te, slot[i], &owned[i]) == 0);
	for (i = 0; i < RTL_TE_FLOW_SLOT_COUNT / 64; i++)
		assert(!te.flow_slots[i]);
}

int main(void)
{
	test_encode();
	test_slot_lifecycle();
	test_no_police();
	test_exhaustion();
	puts("PASS: FE FLOW_ACTION_POLICE encode (rate/burst bounds, drop/accept "
	     "only), real 256 slot allocator lifecycle, rollback reuse, double "
	     "free no-op, no-police no-op, ENOSPC");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-te-police-flow-') as directory:
    test = Path(directory) / 'police.c'
    binary = Path(directory) / 'police'
    test.write_text(prefix_head + defines + '\n' + profile + '\n' + scaffold +
                    ni_block + shims + fe_block + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(test), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)