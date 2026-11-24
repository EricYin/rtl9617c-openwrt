#!/usr/bin/env python3
"""Compile the L2/L3 DoS logic from ni_te_flow.c against a mock regmap.

The extracted region is the shipped code: the RE-9 final per-type field tables
(pol_id / th / en), the 64 bit window read-modify-write used for the fields
that cross a register boundary, the dos_type_en field accessors, the OEM
double write on enable, the masked blit and the trap/drop packing.
Only te_read()/te_write() and the bitmap-free helpers are substituted.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/ni'
source = (DRIVER / 'ni_te_flow.c').read_text()
header = (DRIVER / 'ni_te_flow.h').read_text()

start = source.index('/* ==== BEGIN dos logic')
end = source.index('/* ==== END dos logic')
functions = source[start:end]

# #define blocks with backslash continuations must be kept whole
_lines = header.splitlines()
_defs = []
_i = 0
while _i < len(_lines):
    if _lines[_i].startswith('#define L3TE_DOS_'):
        _chunk = [_lines[_i]]
        while _chunk[-1].rstrip().endswith('\\') and _i + 1 < len(_lines):
            _i += 1
            _chunk.append(_lines[_i])
        _defs.append('\n'.join(_chunk))
    _i += 1
defines = '\n'.join(_defs) + '\n'

import re
enum = re.search(r'enum rtl_dos_type \{.*?\n\};', header, re.S).group(0)
evt = re.search(r'struct rtl_te_dos_evt \{.*?\n\};', header, re.S).group(0)

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
#define wmb() do { } while (0)
#define rmb() do { } while (0)
'''

prefix_body = r'''
struct rtl_te_flow {
	u32 regs[0x10000 / 4];
	u32 seq[64];
	unsigned int nseq;
	unsigned int accesses;
};

static u32 te_read(struct rtl_te_flow *te, u32 off)
{
	if (off >= sizeof(te->regs) || (off & 3)) {
		fprintf(stderr, "bad read %#x\n", off);
		abort();
	}
	return te->regs[off / 4];
}

static void te_write(struct rtl_te_flow *te, u32 off, u32 val)
{
	if (off >= sizeof(te->regs) || (off & 3)) {
		fprintf(stderr, "bad write %#x\n", off);
		abort();
	}
	if (te->nseq < ARRAY_SIZE(te->seq))
		te->seq[te->nseq++] = off;
	te->accesses++;
	te->regs[off / 4] = val;
}

static void mock_reset(struct rtl_te_flow *te)
{
	memset(te, 0, sizeof(*te));
}

static void mock_fill(struct rtl_te_flow *te, u32 l3_base, u32 l2_base)
{
	unsigned int i;

	/* distinctive pattern so neighbour preservation is visible */
	for (i = 0; i < L3TE_DOS_CFG_REGS; i++)
		te->regs[(l3_base + 4 * i) / 4] = 0xa5a5a5a5u;
	for (i = 0; i < L3TE_DOS_L2_CFG_REGS; i++)
		te->regs[(l2_base + 4 * i) / 4] = 0x5a5a5a5au;
}
'''

tests = r'''
/* stream offset of a field inside its block image */
static unsigned int field_off(const struct te_dos_field *f,
			      unsigned int base)
{
	return (f->reg - base) / 4u * 32u + f->lsb;
}

#define TE_DOS_L3_SLICES te_dos_l3_slice, ARRAY_SIZE(te_dos_l3_slice)
#define TE_DOS_L2_SLICES te_dos_l2_slice, ARRAY_SIZE(te_dos_l2_slice)

/* mask bit index whose slice is exactly (off, width), or -1 */
static int slice_bit(const struct te_dos_slice *tab, unsigned int count,
		     unsigned int off, unsigned int width)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		if (tab[i].off == off && tab[i].width == width)
			return (int)i;
	return -1;
}

static void test_slice_tables(void)
{
	unsigned int i, off, total;

	assert(ARRAY_SIZE(te_dos_l3_slice) == 37);
	assert(ARRAY_SIZE(te_dos_l2_slice) == 21);

	off = 0;
	total = 0;
	for (i = 0; i < ARRAY_SIZE(te_dos_l3_slice); i++) {
		assert(te_dos_l3_slice[i].off == off);
		off += te_dos_l3_slice[i].width;
		total += te_dos_l3_slice[i].width;
	}
	assert(total == 288 && off == 288);
	assert(TE_DOS_L3_MASK_ALL == GENMASK_ULL(36, 0));

	off = 0;
	total = 0;
	for (i = 0; i < ARRAY_SIZE(te_dos_l2_slice); i++) {
		assert(te_dos_l2_slice[i].off == off);
		off += te_dos_l2_slice[i].width;
		total += te_dos_l2_slice[i].width;
	}
	assert(total == 144 && off == 144);
	assert(TE_DOS_L2_MASK_ALL == GENMASK_ULL(20, 0));
}

static void mark(unsigned char *used, unsigned int off, unsigned int width,
		 const char *what)
{
	unsigned int i;

	for (i = 0; i < width; i++) {
		if (used[off + i]) {
			fprintf(stderr, "overlap at bit %u (%s)\n", off + i, what);
			abort();
		}
		used[off + i] = 1;
	}
}

/* RE-9 section 3: pol_bit(t)=3t (t<=2) else 2t+3; th_bit=pol_bit+1;
 * en_bit=pol_bit+(t<=2?2:1). */
static unsigned int pol_bit(unsigned int t)
{
	return t <= 2 ? 3 * t : 2 * t + 3;
}

static void test_l3_field_table(void)
{
	static unsigned char used[288];
	unsigned int t, i, n = 0;

	assert(ARRAY_SIZE(te_dos_l3_types) == 16);
	memset(used, 0, sizeof(used));

	for (t = 0; t < RTL_DOS_TYPE_MAX; t++) {
		const struct te_dos_type_desc *d = &te_dos_l3_types[t];

		assert(d->pol.width == 9);
		assert(d->en.width == 1);
		/* the RE-9 field table and the RE-5 mask bit table must agree:
		 * pol_id is mask bit pol_bit(t), en the next slot of its group */
		assert(slice_bit(TE_DOS_L3_SLICES, field_off(&d->pol, TE_DOS_L3_BASE), 9) == (int)pol_bit(t));
		assert(slice_bit(TE_DOS_L3_SLICES, field_off(&d->en, TE_DOS_L3_BASE), 1) == (int)(pol_bit(t) + (t <= 2 ? 2u : 1u)));
		mark(used, field_off(&d->pol, TE_DOS_L3_BASE), 9, "pol");
		mark(used, field_off(&d->en, TE_DOS_L3_BASE), 1, "en");

		if (t <= 2) {
			assert(d->th.width == 16);
			assert(slice_bit(TE_DOS_L3_SLICES, field_off(&d->th, TE_DOS_L3_BASE), 16) == (int)(pol_bit(t) + 1u));
			mark(used, field_off(&d->th, TE_DOS_L3_BASE), 16, "th");
		} else {
			assert(d->th.width == 0);
		}
	}

	/* the wide flag must match the physical register crossing */
	assert(!te_dos_l3_types[RTL_DOS_TYPE_ICMP_FLOOD].pol.wide);
	assert(te_dos_l3_types[RTL_DOS_TYPE_FIN_FLOOD].pol.wide);
	assert(te_dos_l3_types[RTL_DOS_TYPE_UDP_BOMB].pol.wide);
	assert(te_dos_l3_types[RTL_DOS_TYPE_XMA_SCAN].pol.wide);
	assert(te_dos_l3_types[RTL_DOS_TYPE_LAND_ATTACKS].pol.wide);
	assert(te_dos_l3_types[RTL_DOS_TYPE_SYN_FLOOD].th.wide);
	assert(!te_dos_l3_types[RTL_DOS_TYPE_FIN_FLOOD].th.wide);

	/* type fields tile 0..207, then type_en 208..223 and the mask 224..287 */
	for (i = 0; i < 208; i++)
		n += used[i] ? 1u : 0u;
	assert(n == 208);
	assert(!used[208] && !used[223] && !used[224]);
	assert(L3TE_DOS_TYPE_EN == 0x3304);
	assert(field_off(&(struct te_dos_field){ .reg = L3TE_DOS_TYPE_EN,
						 .lsb = L3TE_DOS_TYPE_EN_SHIFT,
						 .width = 16 },
			 TE_DOS_L3_BASE) == 208);
	assert(field_off(&(struct te_dos_field){ .reg = L3TE_DOS_PORT_MASK_LO,
						 .lsb = 0, .width = 64 },
			 TE_DOS_L3_BASE) == 224);
}

static void test_l2_field_table(void)
{
	static unsigned char used[144];
	unsigned int t, i, n = 0;

	assert(ARRAY_SIZE(te_dos_l2_types) == 16);
	memset(used, 0, sizeof(used));

	for (t = 0; t < RTL_DOS_TYPE_MAX; t++) {
		const struct te_dos_type_desc *d = &te_dos_l2_types[t];

		assert(d->pol.width == 0);	/* L2 has no pol_id */
		assert(d->en.width == 1);
		/* every enable/th maps onto exactly one L2 mask bit */
		assert(slice_bit(TE_DOS_L2_SLICES, field_off(&d->en, TE_DOS_L2_BASE), 1) >= 0);
		mark(used, field_off(&d->en, TE_DOS_L2_BASE), 1, "l2 en");
		if (t <= 2) {
			assert(d->th.width == 16);
			assert(slice_bit(TE_DOS_L2_SLICES, field_off(&d->th, TE_DOS_L2_BASE), 16) >= 0);
			mark(used, field_off(&d->th, TE_DOS_L2_BASE), 16,
			     "l2 th");
		} else {
			assert(d->th.width == 0);
		}
	}
	assert(te_dos_l2_types[RTL_DOS_TYPE_FIN_FLOOD].th.wide);
	assert(!te_dos_l2_types[RTL_DOS_TYPE_SYN_FLOOD].th.wide);

	/* en bits sit at 0x1220[16] and 0x1224[1..31] */
	assert(field_off(&te_dos_l2_types[0].en, TE_DOS_L2_BASE) == 16);
	assert(field_off(&te_dos_l2_types[1].en, TE_DOS_L2_BASE) == 33);
	assert(field_off(&te_dos_l2_types[15].en, TE_DOS_L2_BASE) == 63);

	/* 64 type bits, then type_en 64..79 and the port mask 80..143 */
	for (i = 0; i < 64; i++)
		n += used[i] ? 1u : 0u;
	assert(n == 64);
	assert(!used[64] && !used[80]);
	assert(L3TE_DOS_L2_TYPE_EN == 0x1228);
	assert(field_off(&(struct te_dos_field){ .reg = L3TE_DOS_L2_TYPE_EN,
						 .lsb = 0, .width = 16 },
			 TE_DOS_L2_BASE) == 64);
}

static void test_field_extract(void)
{
	u32 img[L3TE_DOS_CFG_REGS] = { 0 };

	/* icmp pol_id = img[0][8:0] */
	img[0] = 0x1ffu;
	assert(te_dos_field_extract(img, TE_DOS_L3_BASE,
				    &te_dos_l3_types[0].pol) == 0x1ff);

	/* fin pol_id = img[0][31:26] | img[1][2:0] */
	img[0] = 0xfc000000u;
	img[1] = 0x7u;
	assert(te_dos_field_extract(img, TE_DOS_L3_BASE,
				    &te_dos_l3_types[1].pol) == 0x1ff);

	/* syn th = img[1][31:29] | img[2][12:0] */
	img[1] = 0xe0000000u;
	img[2] = 0x1fffu;
	assert(te_dos_field_extract(img, TE_DOS_L3_BASE,
				    &te_dos_l3_types[2].th) == 0xffff);

	/* land pol_id = img[5][31:28] | img[6][4:0] */
	img[5] = 0xf0000000u;
	img[6] = 0x1fu;
	assert(te_dos_field_extract(img, TE_DOS_L3_BASE,
				    &te_dos_l3_types[14].pol) == 0x1ff);

	/* missing field reads as zero */
	assert(te_dos_field_extract(img, TE_DOS_L3_BASE,
				    &te_dos_l3_types[3].th) == 0);
}

static void test_field_apply(void)
{
	struct te_dos_field narrow = { .reg = 0x32ec, .lsb = 26, .width = 9,
				       .wide = false };
	struct te_dos_field wide = { .reg = 0x32ec, .lsb = 26, .width = 9,
				     .wide = true };
	u32 img[2];
	u64 window;

	/* narrow: bits 26..31 of the word, the rest is the neighbour value */
	window = 0xffffffffffffffffull;
	te_dos_field_apply(&window, &narrow, 0);
	assert(window == 0xfffffff803ffffffull);

	window = 0;
	te_dos_field_apply(&window, &narrow, 0x1ff);
	assert(window == 0x7fc000000ull);

	/* wide: stream bits 26..34, i.e. 6 bits in the low word and 3 in the
	 * high word of the pair */
	window = 0;
	te_dos_field_apply(&window, &wide, 0x155);
	assert((u32)window == ((0x155u << 26) & 0xffffffffu));
	assert((u32)(window >> 32) == (0x155u >> 6));
	img[0] = (u32)window;
	img[1] = (u32)(window >> 32);
	assert(te_dos_field_extract(img, TE_DOS_L3_BASE, &wide) == 0x155);

	/* a full scale value fills the field exactly */
	window = 0;
	te_dos_field_apply(&window, &wide, 0x1ff);
	assert((u32)window == 0xfc000000u);
	assert((u32)(window >> 32) == 0x7u);
}

static void test_field_write_registers(void)
{
	struct rtl_te_flow te;
	struct te_dos_field narrow = { .reg = 0x32ec, .lsb = 26, .width = 9,
				       .wide = false };
	struct te_dos_field wide = { .reg = 0x32ec, .lsb = 26, .width = 9,
				     .wide = true };

	mock_reset(&te);
	te.regs[0x32ec / 4] = 0xa5a5a5a5u;
	assert(te_dos_field_write(&te, &narrow, 0x155) == 0);
	assert(te.nseq == 1 && te.seq[0] == 0x32ec);
	assert((te.regs[0x32ec / 4] & 0xfc000000u) ==
	       ((0x155u & 0x3fu) << 26));
	assert((te.regs[0x32ec / 4] & 0x03ffffffu) == 0x01a5a5a5u);

	/* wide: two ascending writes, both words keep their other bits */
	mock_reset(&te);
	te.regs[0x32ec / 4] = 0xa5a5a5a5u;
	te.regs[0x32f0 / 4] = 0x5a5a5a5au;
	assert(te_dos_field_write(&te, &wide, 0x155) == 0);
	assert(te.nseq == 2);
	assert(te.seq[0] == 0x32ec && te.seq[1] == 0x32f0);
	assert((te.regs[0x32ec / 4] & 0xfc000000u) == (0x15u << 26));
	assert((te.regs[0x32ec / 4] & 0x03ffffffu) == 0x01a5a5a5u);
	assert((te.regs[0x32f0 / 4] & 0x7u) == 0x5u);
	assert((te.regs[0x32f0 / 4] & ~0x7u) == (0x5a5a5a5au & ~0x7u));

	/* out of range values are refused */
	assert(te_dos_field_write(&te, &narrow, 0x200) == -EINVAL);
	assert(te_dos_field_write(&te, &te_dos_l3_types[3].th, 1) ==
	       -EOPNOTSUPP);
}

/* the six fields that physically cross a register boundary */
static void test_cross_register_fields(void)
{
	struct rtl_te_flow te;

	mock_reset(&te);
	mock_fill(&te, TE_DOS_L3_BASE, TE_DOS_L2_BASE);

	/* fin_flood pol_id 0x155: 3 low bits -> 0x32f0[2:0], 6 high -> [31:26] */
	assert(te_dos_field_write(&te, &te_dos_l3_types[1].pol, 0x155) == 0);
	assert((te.regs[0x32ec / 4] & 0xfc000000u) == (0x15u << 26));
	assert((te.regs[0x32ec / 4] & 0x03ffffffu) == 0x01a5a5a5u);
	assert((te.regs[0x32f0 / 4] & 0x7u) == 0x5u);

	/* syn_flood th 0xabcd: 3 bits -> [31:29], 13 bits -> 0x32f4[12:0] */
	mock_reset(&te);
	mock_fill(&te, TE_DOS_L3_BASE, TE_DOS_L2_BASE);
	assert(te_dos_field_write(&te, &te_dos_l3_types[2].th, 0xabcd) == 0);
	assert((te.regs[0x32f0 / 4] >> 29) == 5u);
	assert((te.regs[0x32f4 / 4] & 0x1fffu) == (0xabcd >> 3));
	assert((te.regs[0x32f4 / 4] & ~0x1fffu) ==
	       (0xa5a5a5a5u & ~0x1fffu));

	/* udp_bomb pol_id 0x1ff: 8 bits -> 0x32f4[31:24], 1 -> 0x32f8[0] */
	mock_reset(&te);
	mock_fill(&te, TE_DOS_L3_BASE, TE_DOS_L2_BASE);
	assert(te_dos_field_write(&te, &te_dos_l3_types[4].pol, 0x1ff) == 0);
	assert((te.regs[0x32f4 / 4] >> 24) == 0xffu);
	assert((te.regs[0x32f8 / 4] & 1u) == 1u);

	/* xma_scan pol_id 0x1ff: 2 bits -> 0x32fc[31:30], 7 -> 0x3300[6:0] */
	mock_reset(&te);
	mock_fill(&te, TE_DOS_L3_BASE, TE_DOS_L2_BASE);
	assert(te_dos_field_write(&te, &te_dos_l3_types[11].pol, 0x1ff) == 0);
	assert((te.regs[0x32fc / 4] >> 30) == 3u);
	assert((te.regs[0x3300 / 4] & 0x7fu) == 0x7fu);

	/* land_attacks pol_id 0x1ff: 4 bits -> 0x3300[31:28], 5 -> 0x3304[4:0] */
	mock_reset(&te);
	mock_fill(&te, TE_DOS_L3_BASE, TE_DOS_L2_BASE);
	assert(te_dos_field_write(&te, &te_dos_l3_types[14].pol, 0x1ff) == 0);
	assert((te.regs[0x3300 / 4] >> 28) == 0xfu);
	assert((te.regs[0x3304 / 4] & 0x1fu) == 0x1fu);
	/* smac_eq_dmac pol_id (0x3304[14:6]) untouched */
	assert(((te.regs[0x3304 / 4] >> 6) & 0x1ffu) ==
	       ((0xa5a5a5a5u >> 6) & 0x1ffu));
}

static void test_type_enable_double_write(void)
{
	struct rtl_te_flow te;

	/* udp_bomb (k=4): en bit 0x32f8[1], dos_type_en 0x3304[20] */
	mock_reset(&te);
	te.regs[0x3304 / 4] = 0x00010000u;	/* type 0 already on */
	te.regs[0x32f8 / 4] = 0;
	assert(te_dos_type_enable(&te, false, RTL_DOS_TYPE_UDP_BOMB, true) == 0);
	assert((te.regs[0x32f8 / 4] & 0x2u) == 0x2u);
	/* type 4 -> dos_type_en bit 16 + 4 = register bit 20 */
	assert((te.regs[0x3304 / 4] & (0x10000u | 0x100000u)) ==
	       (0x10000u | 0x100000u));
	assert((te.regs[0x3304 / 4] & ~0x110000u) == 0);

	assert(te_dos_type_enable(&te, false, RTL_DOS_TYPE_UDP_BOMB, false) == 0);
	assert((te.regs[0x32f8 / 4] & 0x2u) == 0);
	assert((te.regs[0x3304 / 4] & 0x100000u) == 0);
	assert((te.regs[0x3304 / 4] & 0x10000u) == 0x10000u);	/* type 0 kept */

	/* smac_eq_dmac (k=15) has both its enable and the type_en bit in
	 * 0x3304: enable -> [15], type_en -> [31] */
	mock_reset(&te);
	te.regs[0x3304 / 4] = 0x12340000u;
	assert(te_dos_type_enable(&te, false, RTL_DOS_TYPE_SMAC_EQ_DMAC,
				  true) == 0);
	assert((te.regs[0x3304 / 4] & 0x8000u) == 0x8000u);
	assert((te.regs[0x3304 / 4] & 0x80000000u) == 0x80000000u);
	assert((te.regs[0x3304 / 4] & 0x12340000u) == 0x12340000u);

	/* L2 type 0: en 0x1220[16], type_en 0x1228[0], port mask kept */
	mock_reset(&te);
	te.regs[0x1228 / 4] = 0xffff0000u;	/* port mask */
	assert(te_dos_type_enable(&te, true, RTL_DOS_TYPE_ICMP_FLOOD, true) == 0);
	assert((te.regs[0x1220 / 4] & 0x10000u) == 0x10000u);
	assert((te.regs[0x1228 / 4] & 0xffffu) == 1u);
	assert((te.regs[0x1228 / 4] & 0xffff0000u) == 0xffff0000u);

	/* no threshold means no channel for it */
	assert(te_dos_type_enable(&te, false, RTL_DOS_TYPE_SYN_WITH_DATA,
				  true) == 0);
}

static void test_type_en_field(void)
{
	struct rtl_te_flow te;

	mock_reset(&te);
	/* L3: 0x3304[31:16] only; [15:0] belongs to land/smac */
	te.regs[0x3304 / 4] = 0xa5a50000u;
	te_dos_type_en_write(&te, false, 0xbeef);
	assert(te.regs[0x3304 / 4] == 0xbeef0000u);
	assert(te_dos_type_en_read(&te, false) == 0xbeef);
	te_dos_type_en_write(&te, false, 0x0001);
	assert((te.regs[0x3304 / 4] & 0xffffu) == 0);
	assert(te_dos_type_en_read(&te, false) == 1);

	/* L2: 0x1228[15:0], port mask kept */
	mock_reset(&te);
	te.regs[0x1228 / 4] = 0xdead0000u;
	te_dos_type_en_write(&te, true, 0xffff);
	assert(te.regs[0x1228 / 4] == 0xdeadffffu);
	assert(te_dos_type_en_read(&te, true) == 0xffff);

	/* the whole-block writer must not touch the port mask either */
	mock_reset(&te);
	te.regs[0x1228 / 4] = 0x12340000u;
	te_dos_type_en_write(&te, true, 0x000f);
	assert(te.regs[0x1228 / 4] == 0x1234000fu);
}

static void test_evt_fields(void)
{
	struct rtl_te_dos_evt e = {
		.ldpid = 0x2a,
		.cos = 5,
		.keep_orig = true,
		.t0 = true,
		.timer = { 1, 2, 3, 4, 5 },
	};
	struct rtl_te_dos_evt back = { };
	u32 bits, mask;

	bits = te_dos_evt_bits(L3TE_DOS_EVT_F_ALL, &e);
	assert(bits == 0x54321b6au);

	mask = te_dos_evt_mask(L3TE_DOS_EVT_F_ALL);
	assert(mask == 0xfffffbffu);	/* bit 10 (reserved) is not writable */
	assert(!(mask & BIT(10)));
	assert((mask & L3TE_DOS_EVT_T0) == 0x800);
	assert((mask & L3TE_DOS_EVT_TIMER(0)) == 0xf000);
	assert((mask & L3TE_DOS_EVT_TIMER(4)) == 0xf0000000);

	/* only the selected fields contribute */
	assert(te_dos_evt_bits(L3TE_DOS_EVT_F_COS, &e) == (5u << 6));
	assert(te_dos_evt_bits(L3TE_DOS_EVT_F_T0, &e) == 0x800);
	assert(te_dos_evt_bits(0, &e) == 0);
	assert(te_dos_evt_mask(L3TE_DOS_EVT_F_TIMER(2)) == 0x00f00000u);

	te_dos_evt_unpack(bits, &back);
	assert(back.ldpid == e.ldpid && back.cos == e.cos);
	assert(back.keep_orig && !back.reserved && back.t0);
	assert(!memcmp(back.timer, e.timer, sizeof(e.timer)));

	/* reserved is decoded but never packed */
	e.reserved = true;
	assert(!(te_dos_evt_bits(L3TE_DOS_EVT_F_ALL, &e) & BIT(10)));

	/* the L2 selector covers only the three trap fields */
	assert(L3TE_DOS_EVT_F_L2_ALL ==
	       (L3TE_DOS_EVT_F_LDPID | L3TE_DOS_EVT_F_COS |
	        L3TE_DOS_EVT_F_KEEP_ORIG));
}

static void test_type_table(void)
{
	static const char *const expect[] = {
		"icmp_flood", "fin_flood", "syn_flood", "syn_with_data",
		"udp_bomb", "ping_of_death", "icmp_fragment", "tcp_frag_error",
		"tcp_short_hdr", "syn1024", "null_scan", "xma_scan",
		"syn_fin_scan", "blat_attacks", "land_attacks", "smac_eq_dmac",
	};
	unsigned int i, j;

	assert(RTL_DOS_TYPE_MAX == 16);
	for (i = 0; i < RTL_DOS_TYPE_MAX; i++) {
		assert(te_dos_type_name[i]);
		assert(!strcmp(te_dos_type_name[i], expect[i]));
		assert(te_dos_type_index(expect[i]) == (int)i);
		for (j = i + 1; j < RTL_DOS_TYPE_MAX; j++)
			assert(strcmp(te_dos_type_name[i],
				      te_dos_type_name[j]));
	}
	assert(te_dos_type_index("SYN_FLOOD") == -EINVAL);
	assert(te_dos_type_index("") == -EINVAL);
}

static void test_blit_and_write_order(void)
{
	struct rtl_te_flow te;
	u32 img[L3TE_DOS_CFG_REGS];
	u32 src[L3TE_DOS_CFG_REGS];
	u32 l2[L3TE_DOS_L2_CFG_REGS];
	u32 src2[L3TE_DOS_L2_CFG_REGS];
	unsigned int i;

	mock_reset(&te);
	for (i = 0; i < L3TE_DOS_CFG_REGS; i++) {
		img[i] = 0x11111111u * (i + 1);
		src[i] = 0xffffffffu;
	}

	/* mask 0 changes nothing and never touches a register */
	te_dos_blit(img, te_dos_l3_slice, ARRAY_SIZE(te_dos_l3_slice), 0, src);
	assert(img[0] == 0x11111111u);
	assert(te.accesses == 0);

	/* mask bit 0 = 0x32ec[8:0] */
	te_dos_blit(img, te_dos_l3_slice, ARRAY_SIZE(te_dos_l3_slice),
		    BIT_ULL(0), src);
	assert((img[0] & 0x1ffu) == 0x1ffu);
	assert((img[0] & ~0x1ffu) == (0x11111111u & ~0x1ffu));
	assert(img[1] == 0x22222222u);

	/* mask bit 3 spans 0x32ec[31:26] and 0x32f0[2:0] */
	img[0] = img[1] = 0;
	te_dos_blit(img, te_dos_l3_slice, ARRAY_SIZE(te_dos_l3_slice),
		    BIT_ULL(3), src);
	assert(img[0] == 0xfc000000u);
	assert(img[1] == 0x7u);
	assert(img[2] == 0x33333333u);	/* untouched */

	/* L2 mask bit 4 = 0x1224[17:2] (16 bit) */
	mock_reset(&te);
	memset(l2, 0, sizeof(l2));
	memset(src2, 0, sizeof(src2));
	src2[1] = 0x0003fffcu;
	te_dos_blit(l2, te_dos_l2_slice, ARRAY_SIZE(te_dos_l2_slice),
		    BIT_ULL(4), src2);
	assert(l2[0] == 0);
	assert(l2[1] == 0x0003fffcu);
	assert(te.accesses == 0);

	/* the register write walk is ascending over the whole block */
	mock_reset(&te);
	te_dos_write(&te, false, src, L3TE_DOS_CFG_REGS);
	assert(te.nseq == L3TE_DOS_CFG_REGS);
	for (i = 0; i < te.nseq; i++)
		assert(te.seq[i] == L3TE_DOS_CFG(i));
	for (i = 1; i < te.nseq; i++)
		assert(te.seq[i] > te.seq[i - 1]);
}

static void test_flood(void)
{
	struct rtl_te_flow te;

	mock_reset(&te);
	te.regs[L3TE_DOS_FLOOD_CNT / 4] = 0xfffff800u | 0x7ffu;
	assert((te_dos_flood_read(&te, false) & L3TE_DOS_FLOOD_CNT_MASK) ==
	       0x7ff);
	te_dos_flood_clear_reg(&te, false);
	assert(te.regs[L3TE_DOS_FLOOD_CNT / 4] == 0xfffff800u);

	mock_reset(&te);
	te.regs[L3TE_DOS_L2_FLOOD_CNT / 4] = 0xfffffc00u | 0x3ffu;
	assert((te_dos_flood_read(&te, true) & L3TE_DOS_L2_FLOOD_CNT_MASK) ==
	       0x3ff);
	te_dos_flood_clear_reg(&te, true);
	assert(te.regs[L3TE_DOS_L2_FLOOD_CNT / 4] == 0xfffffc00u);
}

static void test_no_writes_by_default(void)
{
	struct rtl_te_flow te;
	u32 img[L3TE_DOS_CFG_REGS];
	u32 l2[L3TE_DOS_L2_CFG_REGS];

	mock_reset(&te);
	mock_fill(&te, TE_DOS_L3_BASE, TE_DOS_L2_BASE);
	te_dos_read(&te, false, img, L3TE_DOS_CFG_REGS);
	te_dos_read(&te, true, l2, L3TE_DOS_L2_CFG_REGS);
	assert(img[0] == 0xa5a5a5a5u);
	assert(l2[0] == 0x5a5a5a5au);
	assert(te_dos_type_en_read(&te, false) == 0xa5a5u);
	assert(te.accesses == 0 && te.nseq == 0);
}

int main(void)
{
	test_slice_tables();
	test_l3_field_table();
	test_l2_field_table();
	test_field_extract();
	test_field_apply();
	test_field_write_registers();
	test_cross_register_fields();
	test_type_enable_double_write();
	test_type_en_field();
	test_evt_fields();
	test_type_table();
	test_blit_and_write_order();
	test_flood();
	test_no_writes_by_default();
	puts("PASS: RE-9 DoS field tables (208+16+64 bit tile), cross-register "
	     "pol_id/th RMW, OEM double write on enable, 16 bit type_en at "
	     "0x3304[31:16]/0x1228[15:0], t0/t1..t5 trap layout, blit order, "
	     "no writes by default");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-dos-table-') as directory:
    test = Path(directory) / 'dos.c'
    binary = Path(directory) / 'dos'
    test.write_text(prefix_head + defines + '\n' + enum + '\n' + evt + '\n' +
                    prefix_body + functions + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(test), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)