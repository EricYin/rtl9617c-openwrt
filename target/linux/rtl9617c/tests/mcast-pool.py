#!/usr/bin/env python3
"""Compile the MCGID/MCE/ARB-FIB pool core with a deterministic MMIO mock.

The block between the "mcast-pool-core" markers in fe_mcast.c is compiled
verbatim; only the register backend and the struct layout it touches are
mocked here.  This exercises the real allocation, reference counting,
reverse-order teardown, capacity and write/read-back code paths.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
FE = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/fe'
REGS = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/rtl9617c_regs.h'

source = (FE / 'fe_mcast.c').read_text()
private = (FE / 'fe_mcast.h').read_text()
hw = (FE / 'fe_hw.h').read_text()
regs = REGS.read_text()

start = source.index('/* --- mcast-pool-core: begin')
end = source.index('/* --- mcast-pool-core: end --- */')
core = source[start:end]


def defines(text, names):
    lines = []
    for name in names:
        match = re.search(r'^#define\s+' + name + r'\b.*$', text, re.M)
        assert match, 'missing #define ' + name
        lines.append(match.group(0))
    return '\n'.join(lines)


limits = '\n'.join((
    defines(hw, ('RTL_FE_MCE_ENTRIES', 'RTL_FE_MCE_CMD', 'RTL_FE_MCE_DATA0',
                 'RTL_FE_MCE_DATA1', 'RTL_FE_ARB_MC_FIB_ENTRIES',
                 'RTL_FE_ARB_MC_FIB_CMD', 'RTL_FE_ARB_MC_FIB_DATA0',
                 'RTL_FE_ARB_MC_FIB_DATA1', 'RTL_FE_ARB_MC_FIB_DATA2',
                 'RTL_FE_MCAST_POLL_COUNT')),
    defines(private, ('RTL_FE_MCAST_MCGIDS', 'RTL_FE_MCAST_MCES',
                      'RTL_FE_MCAST_FIBS', 'RTL_FE_MCAST_PORTS',
                      'RTL_FE_MCAST_MASK_BYTES', 'RTL_FE_MCAST_NONE')),
    defines(regs, ('RTL_NI_INDIRECT_BUSY', 'RTL_NI_INDIRECT_ACCESS',
                   'RTL_NI_INDIRECT_WRITE')),
))

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define BITS_TO_LONGS(nr) (((nr) + 63) / 64)
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define udelay(usec) ((void)(usec))

struct rtl_fe_mcgid {
	u16 users;
	u16 hw_index;
	u16 prev_index;
};

struct rtl_fe_mce {
	u16 mcgid;
	u8 used;
};

struct rtl_fe_fib {
	u16 mcgid;
	u8 port;
	u8 used;
	u32 words[3];
};

struct rtl_fe_mcast {
	unsigned long mcgids[BITS_TO_LONGS(RTL_FE_MCAST_MCGIDS)];
	struct rtl_fe_mcgid mcgid[RTL_FE_MCAST_MCGIDS];
	struct rtl_fe_mce mce[RTL_FE_MCAST_MCES];
	struct rtl_fe_fib fib[RTL_FE_MCAST_FIBS];
};

#define LOG_MAX 65536

struct rtl_fe {
	struct rtl_fe_mcast *mcast;
	u32 stage[3];
	u32 mce_store[RTL_FE_MCAST_MCES][2];
	u32 fib_store[RTL_FE_MCAST_FIBS][3];
	unsigned long calls;
	unsigned long busy_after;
	int corrupt;
};

struct cmd_log {
	unsigned int reg;
	unsigned int val;
};

static struct rtl_fe g_fe;
static struct rtl_fe_mcast g_mcast;
static struct cmd_log g_log[LOG_MAX];
static unsigned int g_log_n;

static unsigned long find_first_zero_bit(const unsigned long *bits,
					 unsigned long count)
{
	unsigned long i;

	for (i = 0; i < count; i++)
		if (!(bits[i / 64] & BIT(i % 64)))
			return i;
	return count;
}

static void __set_bit(unsigned int bit, unsigned long *bits)
{
	bits[bit / 64] |= BIT(bit % 64);
}

static void __clear_bit(unsigned int bit, unsigned long *bits)
{
	bits[bit / 64] &= ~BIT(bit % 64);
}

static bool test_bit(unsigned int bit, const unsigned long *bits)
{
	return !!(bits[bit / 64] & BIT(bit % 64));
}

static void mock_reset(void)
{
	unsigned int i;

	memset(&g_fe, 0, sizeof(g_fe));
	memset(&g_mcast, 0, sizeof(g_mcast));
	memset(g_log, 0, sizeof(g_log));
	g_log_n = 0;
	for (i = 0; i < RTL_FE_MCAST_MCGIDS; i++) {
		g_mcast.mcgid[i].hw_index = RTL_FE_MCAST_NONE;
		g_mcast.mcgid[i].prev_index = RTL_FE_MCAST_NONE;
	}
	g_fe.mcast = &g_mcast;
}

static void mock_log(unsigned int reg, unsigned int val)
{
	assert(g_log_n < LOG_MAX);
	g_log[g_log_n].reg = reg;
	g_log[g_log_n].val = val;
	g_log_n++;
}

static bool mock_busy(unsigned int reg)
{
	return g_fe.busy_after && g_fe.calls >= g_fe.busy_after &&
	       (reg == RTL_FE_MCE_CMD || reg == RTL_FE_ARB_MC_FIB_CMD);
}

static u32 rtl_fe_read(struct rtl_fe *fe, unsigned int reg)
{
	fe->calls++;
	if (mock_busy(reg))
		return BIT(31);
	switch (reg) {
	case RTL_FE_MCE_CMD:
	case RTL_FE_ARB_MC_FIB_CMD:
		return 0;
	case RTL_FE_MCE_DATA0:
		return fe->stage[0];
	case RTL_FE_MCE_DATA1:
		return fe->stage[1];
	case RTL_FE_ARB_MC_FIB_DATA0:
		return fe->stage[0];
	case RTL_FE_ARB_MC_FIB_DATA1:
		return fe->stage[1];
	case RTL_FE_ARB_MC_FIB_DATA2:
		return fe->stage[2];
	default:
		assert(0);
	}
	return 0;
}

static void rtl_fe_write(struct rtl_fe *fe, unsigned int reg, u32 val)
{
	unsigned int index = 0;
	unsigned int i;

	fe->calls++;
	switch (reg) {
	case RTL_FE_MCE_DATA0:
	case RTL_FE_ARB_MC_FIB_DATA0:
		fe->stage[0] = val;
		return;
	case RTL_FE_MCE_DATA1:
	case RTL_FE_ARB_MC_FIB_DATA1:
		fe->stage[1] = val;
		return;
	case RTL_FE_ARB_MC_FIB_DATA2:
		fe->stage[2] = val;
		return;
	case RTL_FE_MCE_CMD:
	case RTL_FE_ARB_MC_FIB_CMD:
		break;
	default:
		assert(0);
		return;
	}

	mock_log(reg, val);
	if (reg == RTL_FE_MCE_CMD) {
		index = val & 0xff;
		assert(index < RTL_FE_MCAST_MCES);
		for (i = 0; i < 2; i++) {
			if (val & BIT(30))
				fe->mce_store[index][i] =
					fe->stage[i] ^ (u32)fe->corrupt;
			else
				fe->stage[i] = fe->mce_store[index][i];
		}
	} else {
		index = val & 0x3f;
		assert(index < RTL_FE_MCAST_FIBS);
		for (i = 0; i < 3; i++) {
			if (val & BIT(30))
				fe->fib_store[index][i] =
					fe->stage[i] ^ (u32)fe->corrupt;
			else
				fe->stage[i] = fe->fib_store[index][i];
		}
	}
}

static unsigned int fib_owned(u16 mcgid)
{
	unsigned int i, count = 0;

	for (i = 0; i < RTL_FE_MCAST_FIBS; i++)
		if (g_mcast.fib[i].used && g_mcast.fib[i].mcgid == mcgid)
			count++;
	return count;
}

static unsigned int mce_used(void)
{
	unsigned int i, count = 0;

	for (i = 0; i < RTL_FE_MCAST_MCES; i++)
		if (g_mcast.mce[i].used)
			count++;
	return count;
}

static unsigned int mce_index(u16 mcgid)
{
	return g_mcast.mcgid[mcgid].hw_index;
}

static u64 mce_members(unsigned int index)
{
	return (u64)g_fe.mce_store[index][0] |
	       ((u64)g_fe.mce_store[index][1] << 32);
}
'''

tests = r'''
static void bitmap_full_and_duplicate_free(void)
{
	u16 id;
	unsigned int i;
	unsigned long after;

	mock_reset();
	for (i = 0; i < RTL_FE_MCAST_MCGIDS; i++) {
		assert(!rtl_fe_mcast_alloc_locked(&g_fe, &id));
		assert(id == i);
	}
	assert(rtl_fe_mcast_alloc_locked(&g_fe, &id) == -ENOSPC);
	assert(g_mcast.mcgid[RTL_FE_MCAST_MCGIDS - 1].users == 1);

	/* A freed id is reusable and a second free is rejected. */
	assert(!rtl_fe_mcast_free_locked(&g_fe, 0));
	assert(rtl_fe_mcast_free_locked(&g_fe, 0) == -EINVAL);
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &id) && id == 0);
	after = find_first_zero_bit(g_mcast.mcgids, RTL_FE_MCAST_MCGIDS);
	assert(after == RTL_FE_MCAST_MCGIDS);

	/* Boundary checks: 1024 and 0xffff are not MCGIDs. */
	assert(rtl_fe_mcast_free_locked(&g_fe, RTL_FE_MCAST_MCGIDS) == -EINVAL);
	assert(rtl_fe_mcast_free_locked(&g_fe, 0xffff) == -EINVAL);
	assert(rtl_fe_mcast_program_locked(&g_fe, RTL_FE_MCAST_MCGIDS, NULL,
					   NULL) == -EINVAL);

	for (i = 0; i < RTL_FE_MCAST_MCGIDS; i++)
		assert(!rtl_fe_mcast_free_locked(&g_fe, i));
	assert(!g_mcast.mcgids[0]);
	assert(mce_used() == 0);
}

static void teardown_is_reverse_order(void)
{
	static const u32 words[3] = { 0x11223344, 0x55667788, 0x99aabbcc };
	u8 ports[RTL_FE_MCAST_MASK_BYTES] = { 0x0d };	/* ports 0, 2, 3 */
	unsigned int start, i, last_fib = 0, first_mce = 0, mce_read = 0;
	u16 id;

	mock_reset();
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &id) && id == 0);
	assert(!rtl_fe_mcast_program_locked(&g_fe, id, ports, words));
	assert(mce_index(id) == 0);
	assert(fib_owned(id) == 3);
	assert(mce_members(0) == 0x7);
	assert(g_fe.fib_store[0][0] == words[0]);

	start = g_log_n;
	assert(!rtl_fe_mcast_free_locked(&g_fe, id));
	assert(fib_owned(id) == 0);
	assert(mce_used() == 0);
	assert(mce_index(id) == RTL_FE_MCAST_NONE);
	assert(g_mcast.mcgid[id].prev_index == RTL_FE_MCAST_NONE);
	assert(!g_mcast.mcgids[0]);

	/* ARB MC FIB deletes must all precede the MCE delete, and the MCE
	 * entry must have been read first (OEM free order). */
	for (i = start; i < g_log_n; i++) {
		if (g_log[i].reg == RTL_FE_ARB_MC_FIB_CMD &&
		    (g_log[i].val & BIT(30)))
			last_fib = i + 1;
		if (g_log[i].reg == RTL_FE_MCE_CMD &&
		    (g_log[i].val & BIT(30)) && !first_mce)
			first_mce = i + 1;
		if (g_log[i].reg == RTL_FE_MCE_CMD &&
		    !(g_log[i].val & BIT(30)) && !mce_read)
			mce_read = i + 1;
	}
	assert(last_fib && first_mce > last_fib);
	assert(mce_read && mce_read < last_fib);
}

static void program_membership_and_reuse(void)
{
	static const u32 a[3] = { 0xa0, 0xa1, 0xa2 };
	static const u32 b[3] = { 0xb0, 0xb1, 0xb2 };
	u8 a_ports[RTL_FE_MCAST_MASK_BYTES] = { 0x03 };	/* ports 0, 1 */
	u8 b_ports[RTL_FE_MCAST_MASK_BYTES] = { 0x04 };	/* port 2 */
	u8 a_reduced[RTL_FE_MCAST_MASK_BYTES] = { 0x02 };	/* port 1 */
	u16 ga, gb;

	mock_reset();
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &ga));
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &gb));
	assert(!rtl_fe_mcast_program_locked(&g_fe, ga, a_ports, a));
	assert(!rtl_fe_mcast_program_locked(&g_fe, gb, b_ports, b));
	assert(fib_owned(ga) == 2 && fib_owned(gb) == 1);
	assert(mce_members(mce_index(ga)) == 0x3);
	assert(mce_members(mce_index(gb)) == 0x4);

	/* Rebuilding a group releases its old members and keeps the MCE slot. */
	assert(!rtl_fe_mcast_program_locked(&g_fe, ga, a_reduced, a));
	assert(mce_index(ga) == 0);
	assert(fib_owned(ga) == 1 && fib_owned(gb) == 1);
	assert(mce_members(0) == 0x1);
	assert(mce_members(1) == 0x4);

	/* An empty mask keeps the group alive with a zero bitmap. */
	u8 none[RTL_FE_MCAST_MASK_BYTES] = { 0 };

	assert(!rtl_fe_mcast_program_locked(&g_fe, gb, none, NULL));
	assert(fib_owned(gb) == 0 && mce_members(mce_index(gb)) == 0);

	assert(!rtl_fe_mcast_free_locked(&g_fe, ga));
	assert(!rtl_fe_mcast_free_locked(&g_fe, gb));
	assert(mce_used() == 0 && !g_mcast.mcgids[0]);
}

static void mce_capacity(void)
{
	u8 none[RTL_FE_MCAST_MASK_BYTES] = { 0 };
	u16 ids[257];
	unsigned int i;

	mock_reset();
	for (i = 0; i <= RTL_FE_MCAST_MCES; i++)
		assert(!rtl_fe_mcast_alloc_locked(&g_fe, &ids[i]));
	for (i = 0; i < RTL_FE_MCAST_MCES; i++)
		assert(!rtl_fe_mcast_program_locked(&g_fe, ids[i], none, NULL));
	assert(mce_used() == RTL_FE_MCAST_MCES);
	assert(rtl_fe_mcast_program_locked(&g_fe, ids[RTL_FE_MCAST_MCES],
					   none, NULL) == -ENOSPC);
	assert(mce_index(ids[RTL_FE_MCAST_MCES]) == RTL_FE_MCAST_NONE);

	/* Releasing one binding makes exactly one slot reusable. */
	assert(!rtl_fe_mcast_free_locked(&g_fe, ids[7]));
	assert(mce_used() == RTL_FE_MCAST_MCES - 1);
	assert(!rtl_fe_mcast_program_locked(&g_fe, ids[RTL_FE_MCAST_MCES],
					    none, NULL));
	assert(mce_index(ids[RTL_FE_MCAST_MCES]) == 7);
}

static void fib_capacity(void)
{
	static const u32 words[3] = { 1, 2, 3 };
	u8 all[RTL_FE_MCAST_MASK_BYTES];
	u8 one[RTL_FE_MCAST_MASK_BYTES] = { 1 };
	u16 ga, gb;
	unsigned int i;

	memset(all, 0xff, sizeof(all));
	mock_reset();
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &ga));
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &gb));
	assert(!rtl_fe_mcast_program_locked(&g_fe, ga, all, words));
	assert(fib_owned(ga) == RTL_FE_MCAST_FIBS);
	assert(rtl_fe_mcast_program_locked(&g_fe, gb, one, words) == -ENOSPC);
	/* The capacity check runs before the MCE binding is taken. */
	assert(mce_index(gb) == RTL_FE_MCAST_NONE);

	assert(!rtl_fe_mcast_free_locked(&g_fe, ga));
	assert(!rtl_fe_mcast_program_locked(&g_fe, gb, one, words));
	assert(fib_owned(gb) == 1);
	assert(!rtl_fe_mcast_free_locked(&g_fe, gb));

	/* 64 member entries is a hard table limit, not a per-group one: two
	 * groups of 33 ports cannot coexist. */
	u16 gc;

	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &gc));
	assert(!rtl_fe_mcast_program_locked(&g_fe, gc, all, words));
	for (i = 0; i < RTL_FE_MCAST_FIBS; i++)
		assert(g_mcast.fib[i].used);
}

static void write_readback_failure(void)
{
	static const u32 words[3] = { 0xdeadbeef, 0x12345678, 0x9abcdef0 };
	u8 ports[RTL_FE_MCAST_MASK_BYTES] = { 1 };
	u16 g;

	mock_reset();
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &g));
	g_fe.corrupt = 1;
	assert(rtl_fe_mcast_program_locked(&g_fe, g, ports, words) == -EIO);
	assert(fib_owned(g) == 0);

	g_fe.corrupt = 0;
	assert(!rtl_fe_mcast_member_set_locked(&g_fe, g, -1, words));
	assert(fib_owned(g) == 1);

	g_fe.corrupt = 1;
	assert(rtl_fe_mcast_member_set_locked(&g_fe, g, 5, words) == -EIO);
	assert(!g_mcast.fib[5].used);
	assert(fib_owned(g) == 1);
}

static void timeout_and_retry(void)
{
	static const u32 words[3] = { 1, 1, 1 };
	u8 ports[RTL_FE_MCAST_MASK_BYTES] = { 1 };
	u16 g;

	mock_reset();
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &g));
	g_fe.busy_after = g_fe.calls + 1;
	assert(rtl_fe_mcast_program_locked(&g_fe, g, ports, words) == -ETIMEDOUT);
	assert(fib_owned(g) == 0);
	g_fe.busy_after = 0;

	assert(!rtl_fe_mcast_program_locked(&g_fe, g, ports, words));
	assert(fib_owned(g) == 1);

	/* A failed free keeps the reference so the caller can retry. */
	g_fe.busy_after = g_fe.calls + 1;
	assert(rtl_fe_mcast_free_locked(&g_fe, g) == -ETIMEDOUT);
	assert(g_mcast.mcgid[g].users == 1);
	assert(g_mcast.mcgids[0]);
	g_fe.busy_after = 0;
	assert(!rtl_fe_mcast_free_locked(&g_fe, g));
	assert(!g_mcast.mcgids[0] && fib_owned(g) == 0 && mce_used() == 0);
}

static void member_slot_rules(void)
{
	static const u32 w1[3] = { 1, 2, 3 };
	static const u32 w2[3] = { 4, 5, 6 };
	u16 g, other;

	mock_reset();
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &g));
	assert(!rtl_fe_mcast_alloc_locked(&g_fe, &other));

	/* Explicit out-of-range slot and foreign slot are rejected. */
	assert(rtl_fe_mcast_member_set_locked(&g_fe, g, RTL_FE_MCAST_FIBS,
					      w1) == -EINVAL);
	assert(!rtl_fe_mcast_member_set_locked(&g_fe, g, 0, w1));
	assert(rtl_fe_mcast_member_set_locked(&g_fe, other, 0, w2) == -EBUSY);

	/* "set" auto mode refuses an ambiguous group with two members. */
	assert(!rtl_fe_mcast_member_set_locked(&g_fe, g, 1, w2));
	assert(rtl_fe_mcast_member_set_locked(&g_fe, g, -1, w1) == -EINVAL);
	assert(mce_members(mce_index(g)) == 0x3);

	assert(!rtl_fe_mcast_free_locked(&g_fe, g));
	assert(!g_mcast.fib[0].used && !g_mcast.fib[1].used);
	assert(!rtl_fe_mcast_free_locked(&g_fe, other));
}

int main(void)
{
	bitmap_full_and_duplicate_free();
	teardown_is_reverse_order();
	program_membership_and_reuse();
	mce_capacity();
	fib_capacity();
	write_readback_failure();
	timeout_and_retry();
	member_slot_rules();
	puts("PASS: actual MCGID/MCE/ARB-FIB pool core; 1024/256/64 capacity; "
	     "duplicate free EINVAL; reverse teardown order; write/read-back "
	     "EIO; timeout retry ownership");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-mcast-pool-') as directory:
    test = Path(directory) / 'mcast.c'
    binary = Path(directory) / 'mcast'
    test.write_text(limits + '\n' + prefix + core + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(test), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)