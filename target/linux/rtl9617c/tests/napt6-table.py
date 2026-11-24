#!/usr/bin/env python3
"""Compile the real NAPTV6 packer and NPTv6 prefix table against a mock NE.

The independent field table below is transcribed from RE-6 §3.  The script
checks that the C table matches it bit-for-bit before compiling, then the C
test sets every field, packs, and checks the exact global bit slice.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/fe'
source = (DRIVER / 'fe_napt6.c').read_text()
header = (DRIVER / 'fe_napt6.h').read_text()
hardware = (DRIVER / 'fe_hw.h').read_text()
hw_source = (DRIVER / 'fe_hw.c').read_text()

start = source.index('/* --- testable core ---')
end = source.index('/* --- debugfs --- */')
functions = source[start:end]

hw_fields = re.search(
    r'static const struct rtl_fe_field_layout rtl_fe_action_fields.*?^\};',
    hw_source, re.S | re.M).group(0)
hw_bits = re.search(
    r'void rtl_fe_bits_set\(.*?\nvoid rtl_fe_action_build\(.*?^\}',
    hw_source, re.S | re.M).group(0)
hw_types = re.search(
    r'enum rtl_fe_action_field \{.*?\n\};', hardware, re.S).group(0)
hw_layout = re.search(
    r'struct rtl_fe_field_layout \{.*?\n\};.*?struct rtl_fe_vlan \{.*?\n\};.*?struct rtl_fe_action \{.*?\n\};',
    hardware, re.S).group(0)

FIELDS = [
    ('l4_dp_vld', 0, 1),
    ('l4_dp', 1, 16),
    ('ip_da_l_vld', 17, 1),
    ('ip_da_l_32', 18, 32),
    ('mrr_vld', 50, 1),
    ('mrr_en', 51, 1),
    ('no_drop_vld', 52, 1),
    ('no_drop', 53, 1),
    ('dpid_vld', 54, 1),
    ('dpid_pri', 55, 1),
    ('permit', 56, 1),
    ('deepq', 57, 1),
    ('mcgid_ldpid', 58, 10),
    ('mc', 68, 1),
    ('mdata_byte_vld', 69, 1),
    ('mdata_byte', 70, 8),
    ('l3_if_vld', 78, 1),
    ('smac_trans', 79, 1),
    ('igr_l3_if_idx', 80, 6),
    ('egr_l3_if_idx', 86, 6),
    ('l3_if_counter_en', 92, 1),
    ('ip_ttl_dec', 93, 1),
    ('ip_ttl_zero_discard_en', 94, 1),
    ('ip_addr_vld', 95, 1),
    ('ip_type', 96, 1),
    ('ip_addr', 97, 32),
    ('ip_addr_napt6', 129, 1),
    ('mac_da_idx_vld', 130, 1),
    ('mac_da_idx', 131, 13),
    ('chk_msk_ptr', 144, 6),
    ('cache_ctrl', 150, 2),
    ('pop_l3_vld', 152, 1),
    ('pop_l3_chk_ecn_en', 153, 1),
    ('pop_l3_en', 154, 1),
    ('t2_ctrl_vld', 155, 1),
    ('t2_ctrl', 156, 4),
    ('ldpid_offset_msb', 160, 1),
    ('ip_dscp_update_en', 161, 1),
    ('ip_dscp', 162, 6),
    ('cos_update_en', 168, 1),
    ('cos', 169, 3),
    ('inner_8021p_update_en', 172, 1),
    ('inner_8021p', 173, 3),
    ('top_8021p_update_en', 176, 1),
    ('top_8021p', 177, 3),
    ('inner_dei', 180, 1),
    ('inner_vid', 181, 12),
    ('inner_tpid_enc', 193, 3),
    ('top_dei', 196, 1),
    ('top_vid', 197, 12),
    ('top_tpid_enc', 209, 3),
    ('vlan_cnt', 212, 2),
    ('vlan_vld', 214, 1),
    ('pol_vld', 215, 1),
    ('pol_en', 216, 1),
    ('pol_id', 217, 8),
    ('pol2_id_enable', 225, 1),
    ('pol2_id', 226, 6),
    ('pol3_id_enable', 232, 1),
    ('pol3_id', 233, 6),
    ('pppoe_vld', 239, 1),
    ('pppoe_set', 240, 1),
    ('l4_port', 241, 16),
    ('ip_mtu_enc_vld', 257, 1),
    ('ip_mtu_enc', 258, 4),
    ('modify_vlan_only_vld', 262, 1),
    ('modify_vlan_only', 263, 1),
    ('six_rd_dip_remap_or_fmr_idx_vld', 264, 1),
    ('six_rd_dip_remap_or_fmr_idx', 265, 2),
    ('vxlan_sport_msb15', 267, 6),
    ('vxlan_sport_update_en', 273, 1),
    ('ip_addr_h_96_vld', 274, 1),
    ('ip_addr_h_96_1', 275, 32),
    ('ip_addr_h_96_2', 307, 32),
    ('ip_addr_h_96_3', 339, 32),
]

# 371 bits, no gaps or overlaps.
covered = [0] * 371
for _, bit, width in FIELDS:
    for position in range(bit, bit + width):
        assert covered[position] == 0, position
        covered[position] = 1
assert all(covered)

# The C field table must match the independent transcription exactly.
c_entries = re.findall(
    r'RTL_FE_NAPT6_FIELD\(([a-z0-9_]+),\s*(\d+),\s*(\d+)\)', functions)
assert len(c_entries) == len(FIELDS), len(c_entries)
for c_entry, py_entry in zip(c_entries, FIELDS):
    assert c_entry[0] == py_entry[0], (c_entry, py_entry)
    assert int(c_entry[1]) == py_entry[1], (c_entry, py_entry)
    assert int(c_entry[2]) == py_entry[2], (c_entry, py_entry)

struct_fields = '\n'.join('\tu32 %s;' % name for name, _, _ in FIELDS)

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
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
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct mutex { int unused; };
#define mutex_lock(m) do { (void)(m); } while (0)
#define mutex_unlock(m) do { (void)(m); } while (0)
static inline void wmb(void) { }
static inline void rmb(void) { }

struct mock {
	u32 window[32];		/* NE+0x3A24 .. NE+0x3AA0 */
	int corrupt_write;
	unsigned int writes;
};

struct rtl_fe_naptv6_action {
''' + struct_fields + r'''
};

struct rtl_fe_npt6_prefix {
	u64 prefix;
	u16 refs;
};

struct rtl_fe_napt6 {
	struct mutex lock;
	struct rtl_fe_npt6_prefix prefixes[RTL_FE_NPT6_PREFIX_ENTRIES];
	u32 action_words[RTL_FE_NAPT6_ACTION_WORDS];
	struct rtl_fe_naptv6_action action;
	bool action_valid;
	char last[1024];
};

struct rtl_fe {
	struct mock *mock;
	struct rtl_fe_napt6 *napt6;
};

static u32 rtl_fe_read(struct rtl_fe *fe, unsigned int reg)
{
	struct mock *m = fe->mock;
	unsigned int index;

	assert(reg >= RTL_FE_NPT6_PREFIX_DATA);
	assert(reg < RTL_FE_NPT6_PREFIX_END);
	assert(!((reg - RTL_FE_NPT6_PREFIX_DATA) % 4));
	index = (reg - RTL_FE_NPT6_PREFIX_DATA) / 4;
	return m->window[index];
}

static void rtl_fe_write(struct rtl_fe *fe, unsigned int reg, u32 value)
{
	struct mock *m = fe->mock;
	unsigned int index;

	assert(reg >= RTL_FE_NPT6_PREFIX_DATA);
	assert(reg < RTL_FE_NPT6_PREFIX_END);
	assert(!((reg - RTL_FE_NPT6_PREFIX_DATA) % 4));
	index = (reg - RTL_FE_NPT6_PREFIX_DATA) / 4;
	m->window[index] = m->corrupt_write ? value ^ 1U : value;
	m->writes++;
}

static void setup(struct rtl_fe *fe, struct rtl_fe_napt6 *n, struct mock *m)
{
	memset(m, 0, sizeof(*m));
	memset(n, 0, sizeof(*n));
	memset(fe, 0, sizeof(*fe));
	fe->mock = m;
	fe->napt6 = n;
}

static u32 field_value(unsigned int index, unsigned int width)
{
	u32 value = 0x9e3779b1U * (index + 1);

	if (width < 32)
		value &= (1U << width) - 1;
	return value;
}
'''

tests = r'''
static void test_fields(void)
{
	struct rtl_fe_naptv6_action a, b;
	u32 words[RTL_FE_NAPT6_ACTION_WORDS];
	unsigned int i;

	assert(RTL_FE_NAPT6_ACTION_BITS == 371);
	assert(ARRAY_SIZE(rtl_fe_napt6_fields) == 75);

	/* Zero input must produce a fully zero 48-byte image. */
	memset(&a, 0, sizeof(a));
	memset(words, 0xff, sizeof(words));
	rtl_fe_napt6_pack(words, &a);
	for (i = 0; i < RTL_FE_NAPT6_ACTION_WORDS; i++)
		assert(words[i] == 0);

	/* All-ones must set exactly the 371 defined bits. */
	memset(&a, 0xff, sizeof(a));
	rtl_fe_napt6_pack(words, &a);
	for (i = 0; i < 11; i++)
		assert(words[i] == 0xffffffffU);
	assert(words[11] == 0x0007ffffU);
	rtl_fe_napt6_unpack(words, &b);
	for (i = 0; i < ARRAY_SIZE(rtl_fe_napt6_fields); i++) {
		const struct rtl_fe_napt6_field *field = &rtl_fe_napt6_fields[i];
		u32 value = *(u32 *)((u8 *)&b + field->offset);

		assert(value == ((field->width == 32) ? 0xffffffffU :
				 (1U << field->width) - 1));
	}

	/* Each field individually: exact slice, no neighbour spill. */
	for (i = 0; i < ARRAY_SIZE(rtl_fe_napt6_fields); i++) {
		const struct rtl_fe_napt6_field *field = &rtl_fe_napt6_fields[i];
		u32 value = field_value(i, field->width);

		memset(&a, 0, sizeof(a));
		*(u32 *)((u8 *)&a + field->offset) = value;
		memset(words, 0, sizeof(words));
		rtl_fe_napt6_pack(words, &a);
		assert(rtl_fe_napt6_bits_get(words, field->bit, field->width) ==
		       value);
		memset(&b, 0xff, sizeof(b));
		rtl_fe_napt6_unpack(words, &b);
		assert(*(u32 *)((u8 *)&b + field->offset) == value);
	}
}

static void test_prefix_table(void)
{
	const u64 prefix = 0x1122334455667788ULL;
	struct rtl_fe fe;
	struct rtl_fe_napt6 n;
	struct mock m;
	unsigned int index, refs, i;
	u64 read;

	setup(&fe, &n, &m);
	assert(rtl_fe_napt6_prefix_add(&fe, prefix, &index) == 0);
	assert(index == 0);
	assert(m.window[0] == 0x55667788U);
	assert(m.window[1] == 0x11223344U);
	assert(n.prefixes[0].refs == 1);
	assert(n.prefixes[0].prefix == prefix);

	/* Same prefix shares the slot and increments the refcount. */
	assert(rtl_fe_napt6_prefix_add(&fe, prefix, &index) == 0);
	assert(index == 0);
	assert(n.prefixes[0].refs == 2);
	assert(rtl_fe_napt6_prefix_get(&fe, 0, &read, &refs) == 0);
	assert(read == prefix && refs == 2);

	for (i = 1; i < RTL_FE_NPT6_PREFIX_ENTRIES; i++) {
		assert(rtl_fe_napt6_prefix_add(&fe, 0x1000 + i, &index) == 0);
		assert(index == i);
		assert(n.prefixes[i].refs == 1);
	}
	assert(rtl_fe_napt6_prefix_add(&fe, 0xdeadbeef, &index) == -ENOSPC);

	/* Two references: first decrements, second writes zero. */
	assert(rtl_fe_napt6_prefix_del(&fe, 0) == 0);
	assert(n.prefixes[0].refs == 1);
	assert(m.window[0] == 0x55667788U);
	assert(rtl_fe_napt6_prefix_del(&fe, 0) == 0);
	assert(n.prefixes[0].refs == 0);
	assert(m.window[0] == 0);
	assert(m.window[1] == 0);
	assert(rtl_fe_napt6_prefix_get(&fe, 0, &read, &refs) == 0);
	assert(read == 0 && refs == 0);
	assert(rtl_fe_napt6_prefix_del(&fe, 0) == -ENOENT);
	assert(rtl_fe_napt6_prefix_del(&fe, RTL_FE_NPT6_PREFIX_ENTRIES) ==
	       -EINVAL);
	assert(rtl_fe_napt6_prefix_get(&fe, RTL_FE_NPT6_PREFIX_ENTRIES, &read,
				       &refs) == -EINVAL);
}

static void test_prefix_readback_failure(void)
{
	struct rtl_fe fe;
	struct rtl_fe_napt6 n;
	struct mock m;
	unsigned int index;

	setup(&fe, &n, &m);
	m.corrupt_write = 1;
	assert(rtl_fe_napt6_prefix_add(&fe, 0x0123456789abcdefULL, &index) ==
	       -EIO);
	assert(n.prefixes[0].refs == 0);
	assert(n.prefixes[0].prefix == 0);
}

static void test_hw_napt6_action_pack(void)
{
	struct rtl_fe_naptv6_action dec;
	struct rtl_fe_action act;
	u32 words[RTL_FE_ACTION_MAX_WORDS];
	u32 norm[RTL_FE_ACTION_WORDS];

	assert(RTL_FE_ACTION_GROUPS == 0x00140000U);
	assert(RTL_FE_ACTION_GROUPS_NAPT6 == 0x0114000aU);
	assert(RTL_FE_ACTION_WIDTH_256 == 3U);
	assert(RTL_FE_ACTION_WIDTH_384 == 4U);

	memset(&act, 0, sizeof(act));
	act.destination = 0x19;
	act.mac_da_index = 42;
	act.ingress_interface = 3;
	act.egress_interface = 7;
	act.cos = 5;
	act.check_mask = 63;
	act.translate = 1;
	act.translate_destination = 1;	/* DNAT6 */
	act.translate_ipv6 = true;
	act.address6[0] = 0x20010db8U;	/* MSB -> ip_addr_h_96_3 */
	act.address6[1] = 0x11223344U;	/*     -> ip_addr_h_96_2 */
	act.address6[2] = 0x55667788U;	/*     -> ip_addr_h_96_1 */
	act.address6[3] = 0x99aabbccU;	/* LSB -> ip_addr */
	act.port = 8443;
	act.mirror = true;
	act.dscp_set = true;
	act.dscp = 46;
	act.mtu_set = 1;
	act.mtu_index = 2;
	act.vlan_set = 1;
	act.vlan_count = 1;
	act.vlan[0].vid = 100;
	act.vlan[0].tpid = 1;
	act.vlan[0].priority = 3;

	rtl_fe_action_build_mode(words, &act, true);
	rtl_fe_action_set_mode(words, RTL_FE_POL_VLD, 1, true);
	rtl_fe_action_set_mode(words, RTL_FE_POL_EN, 1, true);
	rtl_fe_action_set_mode(words, RTL_FE_POL_ID, 0xA2, true);
	rtl_fe_napt6_unpack(words, &dec);

	assert(dec.l4_dp_vld == 0 && dec.ip_da_l_vld == 0);
	assert(dec.mrr_vld == 1 && dec.mrr_en == 1);
	assert(dec.dpid_vld == 1 && dec.dpid_pri == 1 && dec.permit == 1);
	assert(dec.mcgid_ldpid == 0x19);
	assert(dec.ip_ttl_dec == 1 && dec.ip_ttl_zero_discard_en == 1);
	assert(dec.ip_addr_vld == 1 && dec.ip_type == 1 && dec.ip_addr_napt6 == 1);
	assert(dec.ip_addr == 0x99aabbccU);
	assert(dec.ip_addr_h_96_vld == 1);
	assert(dec.ip_addr_h_96_1 == 0x55667788U);
	assert(dec.ip_addr_h_96_2 == 0x11223344U);
	assert(dec.ip_addr_h_96_3 == 0x20010db8U);
	assert(dec.l4_port == 8443);
	assert(dec.pol_vld == 1 && dec.pol_en == 1 && dec.pol_id == 0xA2);
	assert(dec.ip_dscp_update_en == 1 && dec.ip_dscp == 46);
	assert(dec.cos_update_en == 1 && dec.cos == 5);
	assert(dec.vlan_vld == 1 && dec.vlan_cnt == 1 && dec.top_vid == 100);
	assert(dec.ip_mtu_enc_vld == 1 && dec.ip_mtu_enc == 2);

	/* Normal mode leaves words[8..11] clean and never sets h_96 bits. */
	act.translate_ipv6 = false;
	act.address = 0x0a000002U;
	rtl_fe_action_build_mode(words, &act, false);
	rtl_fe_action_build(norm, &act);
	assert(memcmp(words, norm, sizeof(norm)) == 0);
	assert(words[8] == 0 && words[9] == 0 && words[10] == 0 && words[11] == 0);
}

int main(void)
{
	test_fields();
	test_prefix_table();
	test_prefix_readback_failure();
	test_hw_napt6_action_pack();
	puts("PASS: NAPTV6 371-bit field packing (75 fields, zero/default, "
	     "all-ones, per-field slices, round-trip), fe_hw 384-bit DNAT6/PAT "
	     "pack == RE-6 unpack, NPTv6 prefix table 16 entries/refcount/EIO");
	return 0;
}
'''

defines = [line for line in header.splitlines()
           if line.startswith('#define RTL_FE_NAPT6_')]
defines += [line for line in hardware.splitlines()
            if (line.startswith('#define RTL_FE_NPT6_PREFIX_') or
                line.startswith('#define RTL_FE_ACTION_') or
                line.startswith('#define RTL_FE_CACHE_WIDTH_') or
                line.startswith('#define RTL_FE_IP_ADDR_'))]
program = ('\n'.join(defines) + '\n' + prefix + '\n' + hw_types + '\n' +
           hw_layout + '\n' + hw_fields + '\n' + hw_bits + '\n' +
           functions + tests)

with tempfile.TemporaryDirectory(prefix='pt1500-napt6-') as directory:
    test = Path(directory) / 'napt6.c'
    binary = Path(directory) / 'napt6'
    test.write_text(program)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-I', str(DRIVER), str(test),
                    '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env=dict(os.environ))