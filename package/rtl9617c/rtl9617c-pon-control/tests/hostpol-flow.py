#!/usr/bin/env python3
"""Compile the FE Host Policing binding from fe_main.c against a mock MAC table.

Extracted from the driver:
  * rtl_fe_flow_pol_id(), rtl_fe_hostpol_lookup(), rtl_fe_hostpol_bind() and
    rtl_fe_police_bind() - the whole binding decision;
  * rtl_fe_police_free() - to prove a borrowed host slot is never released.
Only rtl_te_hostpol_lookup()/rtl_te_policer_free() are substituted.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c'
source = (DRIVER / 'fe/fe_main.c').read_text()
header = (DRIVER / 'ni/ni_te_flow.h').read_text()


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


bind_block = grab_function(source, 'static int rtl_fe_flow_pol_id(') + '\n\n'
for signature in ('static int rtl_fe_hostpol_lookup(',
                  'static int rtl_fe_hostpol_bind(',
                  'static int rtl_fe_police_bind('):
    bind_block += grab_function(source, signature) + '\n\n'
police_free = grab_function(source, 'static int rtl_fe_police_free(')

defines = '\n'.join(re.findall(r'^#define RTL_TE_HOSTPOL_[^\n]*$', header, re.M))

prefix = r'''
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

#define ETH_ALEN 6

enum rtl_fe_rule_kind {
	RTL_FE_RULE_IPV4,
	RTL_FE_RULE_IPV6,
	RTL_FE_RULE_BRIDGE,
};

struct rtl_te_flow {
	int unused;
};

struct rtl_fe {
	struct rtl_te_flow *te;
};

struct rtl_fe_rule {
	enum rtl_fe_rule_kind kind;
	u8 source[ETH_ALEN];
	u8 destination[ETH_ALEN];
};

struct rtl_fe_flow {
	u8 pol_slot;
	bool pol_owned;
	bool pol_host;
	bool pol_bound;
};

/* --- mock MAC table ------------------------------------------------- */
#define MOCK_HOSTS 8

struct mock_host {
	u8 mac[ETH_ALEN];
	u8 slot[2];		/* 0xff = that direction has no slot */
	int used;
};

static struct mock_host mock_hosts[MOCK_HOSTS];
static unsigned int mock_lookups;
static unsigned int mock_frees;

static void mock_reset(void)
{
	memset(mock_hosts, 0, sizeof(mock_hosts));
	mock_lookups = 0;
	mock_frees = 0;
}

static void mock_add(const u8 mac[ETH_ALEN], u8 ingress, u8 egress)
{
	struct mock_host *h = &mock_hosts[0];
	unsigned int i;

	for (i = 0; i < MOCK_HOSTS; i++)
		if (!mock_hosts[i].used) {
			h = &mock_hosts[i];
			break;
		}
	assert(!h->used);
	h->used = 1;
	memcpy(h->mac, mac, ETH_ALEN);
	h->slot[0] = ingress;
	h->slot[1] = egress;
}

static int rtl_te_hostpol_lookup(struct rtl_te_flow *te, const u8 mac[ETH_ALEN],
				 u8 dir, u8 *slot)
{
	unsigned int i;

	(void)te;
	mock_lookups++;
	assert(dir < 2);
	for (i = 0; i < MOCK_HOSTS; i++) {
		struct mock_host *h = &mock_hosts[i];

		if (!h->used || memcmp(h->mac, mac, ETH_ALEN))
			continue;
		if (h->slot[dir] == 0xff)
			return -EOPNOTSUPP;
		*slot = h->slot[dir];
		return 0;
	}
	return -ENOENT;
}

static int rtl_te_policer_free(struct rtl_te_flow *te, u8 slot)
{
	(void)te;
	(void)slot;
	mock_frees++;
	return 0;
}
'''

tests = r'''
static void set_mac(u8 mac[ETH_ALEN], u8 last)
{
	mac[0] = 0x02;
	mac[1] = 0x00;
	mac[2] = 0x00;
	mac[3] = 0x00;
	mac[4] = 0x00;
	mac[5] = last;
}

static void test_no_entries(void)
{
	struct rtl_fe_flow flow = { };
	struct rtl_fe_rule rule = { .kind = RTL_FE_RULE_IPV4 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };

	mock_reset();
	set_mac(rule.source, 1);
	set_mac(rule.destination, 2);

	assert(rtl_fe_police_bind(&fe, &rule, &flow) == 0);
	assert(!flow.pol_bound && !flow.pol_host && !flow.pol_owned);
	assert(rtl_fe_flow_pol_id(&flow) == -1);
	assert(mock_lookups == 2);	/* ingress miss, egress miss */
}

static void test_ingress_hit(void)
{
	struct rtl_fe_flow flow = { };
	struct rtl_fe_rule rule = { .kind = RTL_FE_RULE_IPV4 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };

	mock_reset();
	set_mac(rule.source, 1);
	set_mac(rule.destination, 2);
	mock_add(rule.source, 5, 6);

	assert(rtl_fe_police_bind(&fe, &rule, &flow) == 0);
	assert(flow.pol_bound && flow.pol_host && !flow.pol_owned);
	assert(flow.pol_slot == 5);
	assert(rtl_fe_flow_pol_id(&flow) == 5);
	/* the ingress hit short-circuits: no egress lookup */
	assert(mock_lookups == 1);
}

static void test_egress_fallback(void)
{
	struct rtl_fe_flow flow = { };
	struct rtl_fe_rule rule = { .kind = RTL_FE_RULE_IPV6 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };

	mock_reset();
	set_mac(rule.source, 1);
	set_mac(rule.destination, 2);
	/* only the destination has an entry */
	mock_add(rule.destination, 8, 9);

	assert(rtl_fe_police_bind(&fe, &rule, &flow) == 0);
	assert(flow.pol_bound && flow.pol_host);
	assert(flow.pol_slot == 9);	/* egress direction slot */
	assert(mock_lookups == 2);
}

static void test_both_directions_present(void)
{
	struct rtl_fe_flow flow = { };
	struct rtl_fe_rule rule = { .kind = RTL_FE_RULE_IPV4 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };

	mock_reset();
	set_mac(rule.source, 1);
	set_mac(rule.destination, 2);
	mock_add(rule.source, 3, 4);
	mock_add(rule.destination, 10, 11);

	/* ingress wins when both MACs have entries */
	assert(rtl_fe_police_bind(&fe, &rule, &flow) == 0);
	assert(flow.pol_slot == 3);
	assert(mock_lookups == 1);
}

static void test_explicit_police_wins(void)
{
	struct rtl_fe_flow flow = { .pol_owned = true, .pol_slot = 3 };
	struct rtl_fe_rule rule = { .kind = RTL_FE_RULE_IPV4 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };

	mock_reset();
	set_mac(rule.source, 1);
	set_mac(rule.destination, 2);
	mock_add(rule.source, 5, 6);

	assert(rtl_fe_police_bind(&fe, &rule, &flow) == 0);
	assert(flow.pol_slot == 3);		/* untouched */
	assert(flow.pol_owned && !flow.pol_host && flow.pol_bound);
	assert(rtl_fe_flow_pol_id(&flow) == 3);
	assert(mock_lookups == 0);		/* the table is never consulted */
}

static void test_bridge_and_missing_te(void)
{
	struct rtl_fe_flow flow = { };
	struct rtl_fe_rule bridge = { .kind = RTL_FE_RULE_BRIDGE };
	struct rtl_fe_rule l3 = { .kind = RTL_FE_RULE_IPV4 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };
	struct rtl_fe empty = { .te = NULL };

	mock_reset();
	set_mac(bridge.source, 1);
	set_mac(bridge.destination, 2);
	mock_add(bridge.source, 5, 6);
	set_mac(l3.source, 3);
	set_mac(l3.destination, 4);
	mock_add(l3.source, 7, 8);

	/* bridge flows are not bound */
	assert(rtl_fe_police_bind(&fe, &bridge, &flow) == 0);
	assert(!flow.pol_bound);
	assert(mock_lookups == 0);

	/* no host policing layer at all */
	assert(rtl_fe_police_bind(&empty, &l3, &flow) == 0);
	assert(!flow.pol_bound);
	assert(mock_lookups == 0);
}

static void test_delete_keeps_host_slot(void)
{
	struct rtl_fe_flow flow = { };
	struct rtl_fe_rule rule = { .kind = RTL_FE_RULE_IPV4 };
	struct rtl_te_flow te = { 0 };
	struct rtl_fe fe = { .te = &te };
	u8 slot = 0;

	mock_reset();
	set_mac(rule.source, 1);
	set_mac(rule.destination, 2);
	mock_add(rule.source, 12, 13);

	assert(rtl_fe_police_bind(&fe, &rule, &flow) == 0);
	assert(flow.pol_slot == 12 && !flow.pol_owned);

	/* the delete path only frees owned slots: a borrowed host slot survives */
	assert(rtl_fe_police_free(fe.te, flow.pol_slot, &flow.pol_owned) == 0);
	assert(mock_frees == 0);
	assert(flow.pol_host && flow.pol_bound);
	/* and the MAC table entry is still there for the next flow */
	assert(rtl_te_hostpol_lookup(fe.te, rule.source,
				     RTL_TE_HOSTPOL_DIR_INGRESS, &slot) == 0);
	assert(slot == 12);

	/* an owned slot is released exactly once */
	flow.pol_owned = true;
	flow.pol_host = false;
	assert(rtl_fe_police_free(fe.te, 12, &flow.pol_owned) == 0);
	assert(mock_frees == 1);
	assert(rtl_fe_police_free(fe.te, 12, &flow.pol_owned) == 0);
	assert(mock_frees == 1);
}

static void test_pol_id(void)
{
	struct rtl_fe_flow flow = { };

	assert(rtl_fe_flow_pol_id(&flow) == -1);
	flow.pol_bound = true;
	flow.pol_slot = 0;	/* slot 0 is a valid host slot */
	assert(rtl_fe_flow_pol_id(&flow) == 0);
	flow.pol_slot = 191;
	assert(rtl_fe_flow_pol_id(&flow) == 191);
	/* an owned slot is bound as well (install sets pol_bound for it) */
	flow.pol_owned = true;
	flow.pol_slot = 42;
	assert(rtl_fe_flow_pol_id(&flow) == 42);
}

int main(void)
{
	test_no_entries();
	test_ingress_hit();
	test_egress_fallback();
	test_both_directions_present();
	test_explicit_police_wins();
	test_bridge_and_missing_te();
	test_delete_keeps_host_slot();
	test_pol_id();
	puts("PASS: FE host policing binding: ingress SA hit, egress DA fallback, "
	     "explicit police wins, bridge/no-te skipped, borrowed slot never "
	     "freed, pol_id -1 when unbound");
	return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='pt1500-hostpol-flow-') as directory:
    test = Path(directory) / 'hostpol_flow.c'
    binary = Path(directory) / 'hostpol_flow'
    test.write_text(prefix + defines + '\n' + bind_block + police_free + '\n' +
                    tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1',
                    '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(test), '-o', str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)