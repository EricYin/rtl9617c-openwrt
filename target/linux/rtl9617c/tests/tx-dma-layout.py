#!/usr/bin/env python3
"""Host-test the OEM TX buffer header packing and the TX offload encoders.

Slices the region between the BEGIN/END markers of ni_dma.c, together with the
real header_a / lso_para0 bit maps and the real structs from ni.h, then compiles
it for the host and checks:

  * OEM word offsets: lso_para0 @+0, lso_para1 @+4, header_a @+8 (64-bit LE)
  * header_a bit fields: cos, ldpid, lspid, pkt_size, fe_bypass, hdr_type
  * byte identity with the pre-S1 encoder in both layout modes (S1 is a
    structure change only), and with hdr_a_full=0 in general
  * the S4 checksum enables and the OEM UDP checksum precompute
  * the S5 segmentation enables and the GSO MSS
  * every switch defaults to off, and an off switch changes nothing

Evidence: phase0-re1-dmalso-ace-fbm.md sections 1.6, 2.2, 2.3, 2.5, 6 and
ca_ni_start_xmit_buf.constprop.0 @0x1aabf0 (re-checked: lso_para1 carries the
payload length, hdr_len is only added to the descriptor length field).
"""
from pathlib import Path
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
NI = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/ni'
source = (NI / 'ni_dma.c').read_text()
private = (NI / 'ni.h').read_text()
public = NI.parent / 'rtl9617c_ni.h'


def struct_of(text, name):
    start = text.index('struct ' + name + ' {')
    end = text.index('\n};', start) + len('\n};')
    return text[start:end] + '\n'


# Every offload switch must ship off: the feature is only advertised for an
# explicit parameter, so an unmodified boot sends exactly the pre-S4 bytes.
for name, pattern in (
        ('hdr_a_full', r'^static bool hdr_a_full(?: = (?:true|false))?;$'),
        ('tx_csum', r'^bool rtl_ni_tx_csum(?: = (?:true|false))?;$'),
        ('tso', r'^bool rtl_ni_tso(?: = (?:true|false))?;$'),
        ('tso_v6', r'^bool rtl_ni_tso_v6(?: = (?:true|false))?;$'),
        ):
    match = re.search(pattern, source, re.M)
    if not match:
        sys.exit('%s declaration not found' % name)
    if 'true' in match.group(0):
        sys.exit('%s must default to 0' % name)
if not re.search(r'^static bool hdr_layout_oem = true;$', source, re.M):
    sys.exit('hdr_layout_oem must keep defaulting to 1 (byte-identical)')
if 'tso_v6' not in source or 'netif_set_tso_max_size' not in (NI / 'ni_port.c').read_text():
    sys.exit('ni_port.c does not advertise the offloads')

region = source[source.index('/* BEGIN rtl-ni-tx-hdr'):
                source.index('/* END rtl-ni-tx-hdr')]
fields = '\n'.join(re.findall(
    r'^#define (?:RTL_NI_(?:HDR_A|LSO_PARA0)_[A-Z0-9_]+|RTL_NI_DMA_(?:BUF_SIZE|HDR_LEN)|'
    r'RTL_NI_TX_GSO_MAX)\s+.*$', private, re.M))
types = (struct_of(private, 'rtl_ni_tx_hdr') +
         struct_of(private, 'rtl_ni_tx_l4info') +
         struct_of(private, 'rtl_ni_tx_offload') +
         struct_of(public.read_text(), 'rtl9617c_ni_frame'))


# --- reference packets for the UDP precompute -------------------------------
def ip_checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


PAYLOAD = bytes(range(0x40, 0x4C))
SRC4, DST4 = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
SRC6 = bytes.fromhex('20010db8000000000000000000000001')
DST6 = bytes.fromhex('20010db8000000000000000000000002')

udp4 = bytearray(b'\x02' * 6 + b'\x04' * 6 + b'\x08\x00')
udp4 += bytes([0x45, 0x00]) + (20 + 8 + len(PAYLOAD)).to_bytes(2, 'big')
udp4 += b'\x12\x34\x00\x00\x40\x11\x00\x00' + SRC4 + DST4
udp4 += (0x1111).to_bytes(2, 'big') + (0x2222).to_bytes(2, 'big')
udp4 += (8 + len(PAYLOAD)).to_bytes(2, 'big') + b'\xbe\xef'
udp4 += PAYLOAD
_udp4_csum = ip_checksum(SRC4 + DST4 + bytes([0, 17]) +
                         (8 + len(PAYLOAD)).to_bytes(2, 'big') +
                         bytes(udp4[34:40]) + b'\x00\x00' + bytes(udp4[42:]))

udp6 = bytearray(b'\x02' * 6 + b'\x04' * 6 + b'\x86\xdd')
udp6 += b'\x60\x00\x00\x00' + (8 + len(PAYLOAD)).to_bytes(2, 'big')
udp6 += bytes([17, 64]) + SRC6 + DST6
udp6 += (0x1111).to_bytes(2, 'big') + (0x2222).to_bytes(2, 'big')
udp6 += (8 + len(PAYLOAD)).to_bytes(2, 'big') + b'\xbe\xef'
udp6 += PAYLOAD
_udp6_csum = ip_checksum(SRC6 + DST6 + (8 + len(PAYLOAD)).to_bytes(4, 'big') +
                         bytes([0, 0, 0, 17]) +
                         bytes(udp6[54:60]) + b'\x00\x00' + bytes(udp6[62:]))


def carray(name, data):
    body = ', '.join('0x%02x' % b for b in data)
    return 'static const u8 %s[] = {%s};\n' % (name, body)


packets = (carray('udp4_pkt', udp4) + carray('udp6_pkt', udp6) +
           '#define UDP4_CSUM 0x%04x\n#define UDP6_CSUM 0x%04x\n'
           % (_udp4_csum, _udp6_csum) +
           '#define UDP4_L3 14\n#define UDP4_L4 34\n'
           '#define UDP6_L3 14\n#define UDP6_L4 54\n')

prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(n) (1U << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h, l) (((~0U) >> (31 - (h))) & (~0U << (l)))
#define GENMASK_ULL(h, l) (((~0ULL) >> (63 - (h))) & (~0ULL << (l)))
#define FIELD_PREP(mask, val) \
	((((uint64_t)(val)) << __builtin_ctzll((uint64_t)(mask))) & ((uint64_t)(mask)))
static void put_unaligned_le32(u32 value, void *ptr)
{
	u8 *p = ptr;

	p[0] = (u8)value;
	p[1] = (u8)(value >> 8);
	p[2] = (u8)(value >> 16);
	p[3] = (u8)(value >> 24);
}
static void put_unaligned_le64(u64 value, void *ptr)
{
	put_unaligned_le32((u32)value, ptr);
	put_unaligned_le32((u32)(value >> 32), (u8 *)ptr + 4);
}
'''

# The spec field maps are asserted independently of the header, so a silent
# edit of either side breaks the test instead of agreeing with itself.
checks = r'''
_Static_assert(RTL_NI_HDR_A_COS == 0x7ULL << 32, "cos[34:32]");
_Static_assert(RTL_NI_HDR_A_LDPID == 0x3fULL << 35, "ldpid[40:35]");
_Static_assert(RTL_NI_HDR_A_LSPID == 0x3fULL << 41, "lspid[46:41]");
_Static_assert(RTL_NI_HDR_A_PKT_SIZE == 0x3fffULL << 47, "pkt_size[60:47]");
_Static_assert(RTL_NI_HDR_A_FE_BYPASS == 1ULL << 61, "fe_bypass[61]");
_Static_assert(RTL_NI_HDR_A_HDR_TYPE == 3ULL << 62, "hdr_type[63:62]");
_Static_assert(RTL_NI_HDR_A_PKT_SIZE_MAX == 0x3fff, "pkt_size width");
_Static_assert(RTL_NI_LSO_PARA0_SEGMENT_SIZE == 0x3fff, "segment_size[13:0]");
_Static_assert(RTL_NI_LSO_PARA0_UNKNOWN_TAG_EN == 1U << 24, "unknown_tag_en[24]");
_Static_assert(RTL_NI_LSO_PARA0_SEGMENT_EN == 1U << 25, "segment_en[25]");
_Static_assert(RTL_NI_LSO_PARA0_IPV4_EN == 1U << 26, "ipv4_en[26]");
_Static_assert(RTL_NI_LSO_PARA0_IPV6_EN == 1U << 27, "ipv6_en[27]");
_Static_assert(RTL_NI_LSO_PARA0_TCP_EN == 1U << 28, "tcp_en[28]");
_Static_assert(RTL_NI_LSO_PARA0_UDP_EN == 1U << 29, "udp_en[29]");
_Static_assert(RTL_NI_LSO_PARA0_BYPASS_EN == 1U << 30, "bypass_en[30]");
_Static_assert(RTL_NI_LSO_PARA0_LENFIX_EN == 1U << 31, "lenfix_en[31]");
_Static_assert(sizeof(struct rtl_ni_tx_hdr) == 16, "16-byte buffer header");
/* A super-packet plus its buffer header must fit one descriptor buffer. */
_Static_assert(RTL_NI_TX_GSO_MAX + RTL_NI_DMA_HDR_LEN == RTL_NI_DMA_BUF_SIZE,
	       "gso_max_size vs descriptor buffer");
_Static_assert(RTL_NI_TX_GSO_MAX <= RTL_NI_HDR_A_PKT_SIZE_MAX,
	       "pkt_size must hold a super-packet");
'''

tests = r'''
#define HDR_LEN		16
#define DMA_HDR_LOW_LEN	GENMASK(28, 15)

struct frame_case {
	const char *name;
	u32 high;
	u32 low;
	unsigned int len;
};

/*
 * Real call sites: ni_port egress, EPON OAM, OMCI, a GPON drain and a GPON
 * data path (oam.c, omci.c/omci_channel.c, gpon.c, path_data.c).
 */
static const struct frame_case frames[] = {
	{"ge-egress", BIT(13), (16 << 9) | (0 << 3) | BIT(29), 64},
	{"p6-egress", BIT(13), (16 << 9) | (6 << 3) | BIT(29), 1518},
	{"oam", 0, 7 | (15 << 3) | (17 << 9) | BIT(29), 60},
	{"omci", BIT(13), 7 | (15 << 3) | (17 << 9) | BIT(29) | (64 << 15), 64},
	{"gpon-drain", BIT(13) | (8 << 18), BIT(29) | (17 << 9) | ((32 + 3) << 3) | 1, 1280},
	{"path-data", BIT(30) | (5 << 18), (16 << 9) | BIT(29) | 2 | ((32 + 1) << 3), 1518},
	{"runt-padded", BIT(13), (16 << 9) | BIT(29), 60},
};

/* Verbatim pre-S1 encoder: what the driver wrote before the S1 change. */
static void legacy_encode(u8 *buf, u32 high, u32 low_in, unsigned int len)
{
	u32 low = low_in;

	memset(buf, 0, HDR_LEN);
	put_unaligned_le32(len, buf + 4);
	put_unaligned_le32(high, buf + 8);
	if (!(low & DMA_HDR_LOW_LEN))
		low |= len << 15;
	put_unaligned_le32(low, buf + 12);
}

static u32 le32(const u8 *p)
{
	return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static u64 le64(const u8 *p)
{
	return (u64)le32(p) | (u64)le32(p + 4) << 32;
}

static struct rtl9617c_ni_frame frame_of(const struct frame_case *c)
{
	struct rtl9617c_ni_frame frame = {
		.header_high = c->high,
		.header_low = c->low,
	};

	return frame;
}

static void test_word_offsets(void)
{
	u8 oem[HDR_LEN], legacy[HDR_LEN], reference[HDR_LEN];
	struct rtl_ni_tx_hdr hdr;

	for (unsigned int i = 0; i < sizeof(frames) / sizeof(frames[0]); i++) {
		const struct frame_case *c = &frames[i];
		struct rtl9617c_ni_frame frame = frame_of(c);

		rtl_ni_tx_hdr_build(&hdr, &frame, c->len, true);
		/* No offload by default: no enable bit, payload length in para1. */
		assert(hdr.lso_para0 == 0);
		assert(hdr.lso_para1 == (c->len & 0xffff));
		rtl_ni_tx_hdr_write(oem, &hdr, true);

		/* OEM layout: lso_para0 @+0, lso_para1 @+4, header_a @+8. */
		assert(le32(oem + 0) == 0);
		assert(le32(oem + 4) == (c->len & 0xffff));
		assert(le64(oem + 8) == hdr.header_a);
		assert(le32(oem + 8) == c->high);
		assert(le32(oem + 12) == (u32)(hdr.header_a >> 32));
		assert((le64(oem + 8) & RTL_NI_HDR_A_PKT_SIZE) >> 47 == c->len);

		/* S1 must not move a byte: both modes match the pre-S1 writer. */
		legacy_encode(reference, c->high, c->low, c->len);
		assert(!memcmp(oem, reference, HDR_LEN));
		rtl_ni_tx_hdr_write(legacy, &hdr, false);
		assert(!memcmp(legacy, reference, HDR_LEN));
		assert(!memcmp(legacy, oem, HDR_LEN));
	}
}

static void test_header_a_fields(void)
{
	struct rtl9617c_ni_frame frame = {
		.header_high = BIT(13),
		.header_low = 5 | (0x2a << 3) | (0x11 << 9) | BIT(29) | (2U << 30),
	};
	struct rtl_ni_tx_hdr hdr;
	u64 a;

	rtl_ni_tx_hdr_build(&hdr, &frame, 0x1234, true);
	a = hdr.header_a;
	assert((a & RTL_NI_HDR_A_COS) >> 32 == 5);
	assert((a & RTL_NI_HDR_A_LDPID) >> 35 == 0x2a);
	assert((a & RTL_NI_HDR_A_LSPID) >> 41 == 0x11);
	assert((a & RTL_NI_HDR_A_PKT_SIZE) >> 47 == 0x1234);
	assert((a & RTL_NI_HDR_A_FE_BYPASS) >> 61 == 1);
	assert((a & RTL_NI_HDR_A_HDR_TYPE) >> 62 == 2);
	/* The low half carries the low word unchanged, including bit 13. */
	assert((u32)a == BIT(13));
	/* lso_para0 must stay a plain, non-segmented descriptor. */
	assert(hdr.lso_para0 == 0);
}

static void test_pkt_size_policy(void)
{
	struct rtl9617c_ni_frame frame = {.header_high = BIT(13)};
	struct rtl_ni_tx_hdr hdr;
	u64 base, a;

	/* hdr_a_full=0 keeps the pre-S2 rule: a caller-supplied pkt_size wins
	 * and an empty field is filled from the descriptor length.  This is the
	 * shipped default, so a padded OMCI frame keeps its old value. */
	frame.header_low = (64 << 15);
	rtl_ni_tx_hdr_build(&hdr, &frame, 1280, false);
	assert((hdr.header_a & RTL_NI_HDR_A_PKT_SIZE) >> 47 == 64);
	frame.header_low = (16 << 9) | BIT(29);
	rtl_ni_tx_hdr_build(&hdr, &frame, 1518, false);
	assert((hdr.header_a & RTL_NI_HDR_A_PKT_SIZE) >> 47 == 1518);

	/* hdr_a_full=1 makes pkt_size authoritative for every frame. */
	frame.header_low = (64 << 15);
	base = ((u64)frame.header_low << 32) | BIT(13);
	rtl_ni_tx_hdr_build(&hdr, &frame, 1280, true);
	a = hdr.header_a;
	assert((a & RTL_NI_HDR_A_PKT_SIZE) >> 47 == 1280);
	/* Everything outside pkt_size is preserved. */
	assert((u32)a == BIT(13));
	assert((a & ~RTL_NI_HDR_A_PKT_SIZE) == (base & ~RTL_NI_HDR_A_PKT_SIZE));
}

static void put_be16(u8 *p, u16 value)
{
	p[0] = (u8)(value >> 8);
	p[1] = (u8)value;
}

static void eth_hdr(u8 *pkt, u16 proto)
{
	memset(pkt, 0, 256);
	memset(pkt, 0x02, 6);
	memset(pkt + 6, 0x04, 6);
	put_be16(pkt + 12, proto);
}

static void ipv4_hdr(u8 *pkt, unsigned int off, u8 proto, u16 total, u16 frag)
{
	pkt[off] = 0x45;
	put_be16(pkt + off + 2, total);
	put_be16(pkt + off + 6, frag);
	pkt[off + 8] = 64;
	pkt[off + 9] = proto;
}

static void ipv6_hdr(u8 *pkt, unsigned int off, u8 next, u16 plen)
{
	pkt[off] = 0x60;
	put_be16(pkt + off + 4, plen);
	pkt[off + 6] = next;
}

static void tcp_hdr(u8 *pkt, unsigned int off, u8 words)
{
	pkt[off + 12] = (u8)(words << 4);
}

static void udp_hdr(u8 *pkt, unsigned int off, u16 len, u16 csum)
{
	put_be16(pkt + off + 4, len);
	put_be16(pkt + off + 6, csum);
}

static void test_parser_ipv4(void)
{
	struct rtl_ni_tx_l4info info;
	u8 pkt[256];

	/* IPv4 + TCP, 10 payload bytes. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 50, 0);
	tcp_hdr(pkt, 34, 5);
	assert(rtl_ni_tx_l4_parse(pkt, 64, &info) == 0);
	assert(info.ipv4 && !info.ipv6 && !info.pppoe && info.tcp && !info.udp);
	assert(info.l3_off == 14 && info.l4_off == 34 && info.l4_len == 10);
	assert(info.ip_len == 50 && info.ip_proto == RTL_NI_IPPROTO_TCP);

	/* IPv4 + UDP with a checksum, then without one. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_UDP, 34, 0);
	udp_hdr(pkt, 34, 14, 0xbeef);
	assert(rtl_ni_tx_l4_parse(pkt, 48, &info) == 0);
	assert(info.udp && !info.tcp && info.udp_csum_present);
	assert(info.l4_off == 34 && info.l4_len == 6 && info.ip_len == 34);

	udp_hdr(pkt, 34, 14, 0);
	assert(rtl_ni_tx_l4_parse(pkt, 48, &info) == 0);
	assert(info.udp && !info.udp_csum_present);

	/* IP options shift the L4 header: ihl=6 -> 24 bytes of IP header. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 56, 0);
	pkt[14] = 0x46;
	tcp_hdr(pkt, 38, 5);
	assert(rtl_ni_tx_l4_parse(pkt, 70, &info) == 0);
	assert(info.tcp && info.l3_off == 14 && info.l4_off == 38 && info.l4_len == 12);

	/* VLAN-tagged IPv4 + TCP: one tag shifts everything by four. */
	eth_hdr(pkt, RTL_NI_ETH_P_8021Q);
	put_be16(pkt + 14, 0x0064);
	put_be16(pkt + 16, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 18, RTL_NI_IPPROTO_TCP, 50, 0);
	tcp_hdr(pkt, 38, 5);
	assert(rtl_ni_tx_l4_parse(pkt, 68, &info) == 0);
	assert(info.tcp && info.l3_off == 18 && info.l4_off == 38 && info.l4_len == 10);
}

static void test_parser_ipv6(void)
{
	struct rtl_ni_tx_l4info info;
	u8 pkt[256];

	/* IPv6 with one hop-by-hop header, then TCP with 4 payload bytes. */
	eth_hdr(pkt, RTL_NI_ETH_P_IPV6);
	ipv6_hdr(pkt, 14, RTL_NI_IPV6_EXT_HOP, 32);
	pkt[54] = RTL_NI_IPPROTO_TCP;
	pkt[55] = 0;
	tcp_hdr(pkt, 62, 5);
	assert(rtl_ni_tx_l4_parse(pkt, 86, &info) == 0);
	assert(info.ipv6 && !info.ipv4 && info.tcp);
	assert(info.l3_off == 14 && info.l4_off == 62 && info.l4_len == 4);
	assert(info.ip_len == 72 && info.ip_proto == RTL_NI_IPPROTO_TCP);

	/* Plain IPv6 + UDP. */
	eth_hdr(pkt, RTL_NI_ETH_P_IPV6);
	ipv6_hdr(pkt, 14, RTL_NI_IPPROTO_UDP, 14);
	udp_hdr(pkt, 54, 14, 0x1234);
	assert(rtl_ni_tx_l4_parse(pkt, 68, &info) == 0);
	assert(info.udp && info.l4_off == 54 && info.l4_len == 6 && info.ip_len == 54);
}

static void test_parser_pppoe(void)
{
	struct rtl_ni_tx_l4info info;
	u8 pkt[256];

	/* PPPoE session carrying IPv4/UDP. */
	eth_hdr(pkt, RTL_NI_ETH_P_PPP_SES);
	pkt[14] = RTL_NI_PPPOE_VT;
	pkt[15] = 0;
	put_be16(pkt + 16, 0x1234);
	put_be16(pkt + 18, 2 + 34);
	put_be16(pkt + 20, RTL_NI_PPP_IP);
	ipv4_hdr(pkt, 22, RTL_NI_IPPROTO_UDP, 34, 0);
	udp_hdr(pkt, 42, 14, 0);
	assert(rtl_ni_tx_l4_parse(pkt, 56, &info) == 0);
	assert(info.pppoe && info.ipv4 && info.udp && !info.ipv6);
	assert(info.l3_off == 22 && info.l4_off == 42 && info.l4_len == 6 && info.ip_len == 34);

	/* PPPoE carrying IPv6/TCP. */
	eth_hdr(pkt, RTL_NI_ETH_P_PPP_SES);
	pkt[14] = RTL_NI_PPPOE_VT;
	put_be16(pkt + 18, 2 + 60);
	put_be16(pkt + 20, RTL_NI_PPP_IPV6);
	ipv6_hdr(pkt, 22, RTL_NI_IPPROTO_TCP, 20);
	tcp_hdr(pkt, 62, 5);
	assert(rtl_ni_tx_l4_parse(pkt, 82, &info) == 0);
	assert(info.pppoe && info.ipv6 && info.tcp);
	assert(info.l3_off == 22 && info.l4_off == 62 && info.l4_len == 0);
}

static void test_parser_rejects(void)
{
	struct rtl_ni_tx_l4info info;
	u8 pkt[256];

	/* Not IP at all. */
	eth_hdr(pkt, 0x0806);
	assert(rtl_ni_tx_l4_parse(pkt, 42, &info) == -EOPNOTSUPP);
	assert(!info.ipv4 && !info.ipv6 && !info.tcp && !info.udp);

	/* IPv4 fragment (MF set) and a non-first fragment. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 40, 0x2000);
	assert(rtl_ni_tx_l4_parse(pkt, 54, &info) == -EOPNOTSUPP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 40, 0x00b0);
	assert(rtl_ni_tx_l4_parse(pkt, 54, &info) == -EOPNOTSUPP);

	/* ICMP is IP but has no L4 port space to offload. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, 1, 28, 0);
	assert(rtl_ni_tx_l4_parse(pkt, 42, &info) == -EOPNOTSUPP);

	/* IPv6 fragment extension header. */
	eth_hdr(pkt, RTL_NI_ETH_P_IPV6);
	ipv6_hdr(pkt, 14, RTL_NI_IPPROTO_FRAG, 8);
	assert(rtl_ni_tx_l4_parse(pkt, 62, &info) == -EOPNOTSUPP);

	/* PPPoE with a non-IP PPP protocol. */
	eth_hdr(pkt, RTL_NI_ETH_P_PPP_SES);
	pkt[14] = RTL_NI_PPPOE_VT;
	put_be16(pkt + 18, 2 + 20);
	put_be16(pkt + 20, 0xc021);
	assert(rtl_ni_tx_l4_parse(pkt, 42, &info) == -EOPNOTSUPP);

	/* Truncated and malformed headers. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	assert(rtl_ni_tx_l4_parse(pkt, 10, &info) == -EINVAL);
	assert(rtl_ni_tx_l4_parse(pkt, 30, &info) == -EINVAL);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 60, 0);
	assert(rtl_ni_tx_l4_parse(pkt, 30, &info) == -EINVAL);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 40, 0);
	tcp_hdr(pkt, 34, 4);
	assert(rtl_ni_tx_l4_parse(pkt, 54, &info) == -EINVAL);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_UDP, 34, 0);
	udp_hdr(pkt, 34, 4, 0x1111);
	assert(rtl_ni_tx_l4_parse(pkt, 48, &info) == -EINVAL);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_UDP, 34, 0);
	udp_hdr(pkt, 34, 60, 0x1111);
	assert(rtl_ni_tx_l4_parse(pkt, 48, &info) == -EINVAL);
}

/* ---- S4: checksum offload bits and the OEM UDP precompute ---------------- */

static u32 pseudo_udp_sum(const u8 *frame, unsigned int l3, unsigned int l4,
			  unsigned int udp_len, bool v4)
{
	u32 sum = rtl_ni_csum_add(frame + l3 + (v4 ? 12 : 8), v4 ? 8 : 32, 0);

	sum += udp_len;
	sum += 17;
	return rtl_ni_csum_add(frame + l4, udp_len, sum);
}

static void test_csum_offload(void)
{
	struct rtl_ni_tx_offload csum = {.csum = true};
	struct rtl_ni_tx_offload off = {0};
	struct rtl_ni_tx_l4info info;
	u32 para0 = 0xdeadbeef;
	u8 pkt[256];

	/* IPv4/TCP: OEM always enables segment_en with L2 MTU (14 + 1500 = 1514),
	 * and leaves TCP checksum field untouched for hardware. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 50, 0);
	tcp_hdr(pkt, 34, 5);
	pkt[34 + 16] = 0xbe;
	pkt[34 + 17] = 0xef;
	assert(rtl_ni_tx_offload_prepare(pkt, 64, &csum, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1514) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV4_EN |
			 RTL_NI_LSO_PARA0_TCP_EN));
	assert(pkt[34 + 16] == 0xbe && pkt[34 + 17] == 0xef);

	/* 60-byte padded IPv4/TCP FIN/ACK (14 + 40 = 54 < 60): sets lenfix_en. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 40, 0);
	tcp_hdr(pkt, 34, 5);
	assert(rtl_ni_tx_offload_prepare(pkt, 60, &csum, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1514) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV4_EN |
			 RTL_NI_LSO_PARA0_TCP_EN |
			 RTL_NI_LSO_PARA0_LENFIX_EN));

	/* IPv6/TCP. */
	eth_hdr(pkt, RTL_NI_ETH_P_IPV6);
	ipv6_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 20);
	tcp_hdr(pkt, 54, 5);
	assert(rtl_ni_tx_offload_prepare(pkt, 74, &csum, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1514) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV6_EN |
			 RTL_NI_LSO_PARA0_TCP_EN));

	/* Both switches off: nothing is enabled, and the caller keeps the plain
	 * descriptor. */
	para0 = 0xdeadbeef;
	assert(rtl_ni_tx_offload_prepare(pkt, 74, &off, &para0) == -EOPNOTSUPP);
	assert(para0 == 0);

	/* UDP with a zero checksum is not offloaded (OEM leaves it alone), and
	 * the frame stays byte-identical. */
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_UDP, 34, 0);
	udp_hdr(pkt, 34, 14, 0);
	{
		u8 copy[48];

		memcpy(copy, pkt, 48);
		assert(rtl_ni_tx_offload_prepare(pkt, 48, &csum, &para0) == -EOPNOTSUPP);
		assert(para0 == 0);
		assert(!memcmp(copy, pkt, 48));
	}

	/* ICMP, fragments and non-IP frames are declined. */
	ipv4_hdr(pkt, 14, 1, 28, 0);
	assert(rtl_ni_tx_offload_prepare(pkt, 42, &csum, &para0) == -EOPNOTSUPP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 40, 0x2000);
	assert(rtl_ni_tx_offload_prepare(pkt, 54, &csum, &para0) == -EOPNOTSUPP);
	eth_hdr(pkt, 0x0806);
	assert(rtl_ni_tx_offload_prepare(pkt, 42, &csum, &para0) == -EOPNOTSUPP);

	/* The classifier result is what drives the enables. */
	assert(rtl_ni_tx_l4_parse(pkt, 42, &info) == -EOPNOTSUPP);
}

static void test_udp_precompute(void)
{
	struct rtl_ni_tx_offload csum = {.csum = true};
	u8 frame[128];
	u32 para0 = 0;

	/* IPv4/UDP: the OEM precomputes the checksum and writes it back. */
	memcpy(frame, udp4_pkt, sizeof(udp4_pkt));
	assert(rtl_ni_tx_offload_prepare(frame, sizeof(udp4_pkt), &csum, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1514) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV4_EN |
			 RTL_NI_LSO_PARA0_UDP_EN));
	assert(((frame[UDP4_L4 + 6] << 8) | frame[UDP4_L4 + 7]) == UDP4_CSUM);
	/* A correct checksum folds the whole pseudo-header sum to zero. */
	assert(rtl_ni_csum_fold(pseudo_udp_sum(frame, UDP4_L3, UDP4_L4,
					       8 + 12, true)) == 0);
	/* Nothing outside the checksum field moved. */
	assert(!memcmp(frame, udp4_pkt, UDP4_L4 + 6));
	assert(!memcmp(frame + UDP4_L4 + 8, udp4_pkt + UDP4_L4 + 8,
		       sizeof(udp4_pkt) - UDP4_L4 - 8));

	/* IPv6/UDP. */
	memcpy(frame, udp6_pkt, sizeof(udp6_pkt));
	assert(rtl_ni_tx_offload_prepare(frame, sizeof(udp6_pkt), &csum, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1514) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV6_EN |
			 RTL_NI_LSO_PARA0_UDP_EN));
	assert(((frame[UDP6_L4 + 6] << 8) | frame[UDP6_L4 + 7]) == UDP6_CSUM);
	assert(rtl_ni_csum_fold(pseudo_udp_sum(frame, UDP6_L3, UDP6_L4,
					       8 + 12, false)) == 0);
}

/* ---- S5: IPv4/TCP segmentation ------------------------------------------- */

static void test_tso_offload(void)
{
	struct rtl_ni_tx_offload tso = {.segment = true, .csum = true, .gso_size = 1436};
	struct rtl_ni_tx_offload tso6 = {.segment = true, .csum = true,
					 .segment_ipv6 = true, .gso_size = 1436};
	struct rtl_ni_tx_offload bad = {.segment = true, .csum = true, .gso_size = 0};
	struct rtl_ni_tx_offload huge = {.segment = true, .csum = true, .gso_size = 0x4000};
	u32 para0 = 0;
	u8 pkt[2048];

	/* IPv4/TCP super-packet: segment_size = total L2 frame size
	 * (14 Eth + 20 IP + 20 TCP + 1436 MSS = 1490), no UDP bit. */
	memset(pkt, 0, sizeof(pkt));
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 2018, 0);
	tcp_hdr(pkt, 34, 5);
	pkt[34 + 16] = 0xbe;
	pkt[34 + 17] = 0xef;
	assert(rtl_ni_tx_offload_prepare(pkt, 2032, &tso, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1490) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV4_EN |
			 RTL_NI_LSO_PARA0_TCP_EN));
	assert((para0 & RTL_NI_LSO_PARA0_SEGMENT_SIZE) == 1490);
	assert(!(para0 & (RTL_NI_LSO_PARA0_UDP_EN | RTL_NI_LSO_PARA0_IPV6_EN |
			  RTL_NI_LSO_PARA0_LENFIX_EN)));
	/* The TCP checksum field is left to the hardware. */
	assert(pkt[34 + 16] == 0xbe && pkt[34 + 17] == 0xef);

	/* IPv4/TCP with 12-byte timestamps (doff=8 -> 32 B TCP hdr) + MSS 1448:
	 * 14 + 20 + 32 + 1448 = 1514. */
	{
		struct rtl_ni_tx_offload tso_ts = {.segment = true, .csum = true,
						   .gso_size = 1448, .mtu = 1500};

		memset(pkt, 0, sizeof(pkt));
		eth_hdr(pkt, RTL_NI_ETH_P_IP);
		ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 2018, 0);
		tcp_hdr(pkt, 34, 8);
		assert(rtl_ni_tx_offload_prepare(pkt, 2032, &tso_ts, &para0) == 0);
		assert((para0 & RTL_NI_LSO_PARA0_SEGMENT_SIZE) == 1514);
	}

	/* UDP cannot be segmented yet. */
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_UDP, 34, 0);
	udp_hdr(pkt, 34, 14, 0xbeef);
	para0 = 0xdeadbeef;
	assert(rtl_ni_tx_offload_prepare(pkt, 48, &tso, &para0) == -EOPNOTSUPP);
	assert(para0 == 0);

	/* IPv6 super-packets need tso_v6 (14 Eth + 40 IPv6 + 20 TCP + 1436 = 1510). */
	memset(pkt, 0, sizeof(pkt));
	eth_hdr(pkt, RTL_NI_ETH_P_IPV6);
	ipv6_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 20);
	tcp_hdr(pkt, 54, 5);
	assert(rtl_ni_tx_offload_prepare(pkt, 74, &tso, &para0) == -EOPNOTSUPP);
	assert(rtl_ni_tx_offload_prepare(pkt, 74, &tso6, &para0) == 0);
	assert(para0 == (FIELD_PREP(RTL_NI_LSO_PARA0_SEGMENT_SIZE, 1510) |
			 RTL_NI_LSO_PARA0_SEGMENT_EN |
			 RTL_NI_LSO_PARA0_IPV6_EN |
			 RTL_NI_LSO_PARA0_TCP_EN));

	/* An inconsistent MSS is rejected instead of being truncated. */
	memset(pkt, 0, sizeof(pkt));
	eth_hdr(pkt, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt, 14, RTL_NI_IPPROTO_TCP, 40, 0);
	tcp_hdr(pkt, 34, 5);
	assert(rtl_ni_tx_offload_prepare(pkt, 64, &bad, &para0) == -EINVAL);
	assert(rtl_ni_tx_offload_prepare(pkt, 64, &huge, &para0) == -EINVAL);
	assert(para0 == 0);
}

static void test_offload_header(void)
{
	struct rtl9617c_ni_frame frame = {.header_high = BIT(13),
					  .header_low = (16 << 9) | BIT(29)};
	struct rtl_ni_tx_offload tso = {.segment = true, .csum = true, .gso_size = 1436};
	struct rtl_ni_tx_hdr hdr;
	u8 pkt[2048 + HDR_LEN], oem[HDR_LEN];
	u32 para0 = 0;

	memset(pkt + HDR_LEN, 0, 2032);
	eth_hdr(pkt + HDR_LEN, RTL_NI_ETH_P_IP);
	ipv4_hdr(pkt + HDR_LEN, 14, RTL_NI_IPPROTO_TCP, 40, 0);
	tcp_hdr(pkt + HDR_LEN, 34, 5);
	assert(rtl_ni_tx_offload_prepare(pkt + HDR_LEN, 2032, &tso, &para0) == 0);

	/* An offloaded frame forces an authoritative pkt_size even with
	 * hdr_a_full at its default 0. */
	rtl_ni_tx_hdr_build(&hdr, &frame, 2032, false || para0 != 0);
	hdr.lso_para0 = para0;
	rtl_ni_tx_hdr_write(oem, &hdr, true);
	assert(le32(oem + 0) == para0);
	assert((le32(oem + 0) & RTL_NI_LSO_PARA0_SEGMENT_EN) != 0);
	/* lso_para1 stays the payload length, not payload + 16. */
	assert(le32(oem + 4) == 2032);
	assert((le64(oem + 8) & RTL_NI_HDR_A_PKT_SIZE) >> 47 == 2032);
	assert(2032 + HDR_LEN <= RTL_NI_DMA_BUF_SIZE);

	/* Without offload, the same frame keeps the plain descriptor. */
	rtl_ni_tx_hdr_build(&hdr, &frame, 2032, false);
	hdr.lso_para0 = 0;
	rtl_ni_tx_hdr_write(oem, &hdr, true);
	assert(le32(oem + 0) == 0);
	assert(le32(oem + 4) == 2032);
	assert((le64(oem + 8) & RTL_NI_HDR_A_PKT_SIZE) >> 47 == 2032);
}

int main(void)
{
	test_word_offsets();
	test_header_a_fields();
	test_pkt_size_policy();
	test_parser_ipv4();
	test_parser_ipv6();
	test_parser_pppoe();
	test_parser_rejects();
	test_csum_offload();
	test_udp_precompute();
	test_tso_offload();
	test_offload_header();
	puts("PASS: OEM header words (lso_para0@+0, lso_para1@+4, header_a@+8); "
	     "header_a cos/ldpid/lspid/pkt_size/fe_bypass/hdr_type; S1 byte identity "
	     "with the pre-S1 encoder; S2 pkt_size policy; S3 classifier; "
	     "S4 csum enables + OEM UDP precompute; S5 segment_en/gso_size; "
	     "all offload switches default off and change nothing");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-tx-dma-layout-') as directory:
    test = Path(directory) / 'layout.c'
    binary = Path(directory) / 'layout'
    test.write_text(prefix + fields + '\n' + types + packets + checks + region + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I', str(NI), str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env=dict(os.environ))