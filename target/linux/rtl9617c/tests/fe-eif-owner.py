#!/usr/bin/env python3
"""Compile the actual EIF owner functions with deterministic local MMIO mocks."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
DRIVER = ROOT / 'target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/fe'
source = (DRIVER / 'fe_main.c').read_text()
private = (DRIVER / 'fe_priv.h').read_text()
start = source.index('static u32 rtl_fe_interface_value(')
end = source.index('static unsigned int rtl_fe_mtu_shift(', start)
functions = source[start:end]
limits = '\n'.join(re.search(r'^#define ' + name + r'\s+.*$', text, re.M).group(0)
                   for text, names in ((private, ('FE_INTERFACES', 'FE_COUNTERS')),
                                       (source, ('FE_INTERFACE_INIT', 'FE_INTERFACE_SMAC_SHIFT')))
                   for name in names)

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
typedef uint32_t u32;
#define RTL_FE_INTERFACE_CMD 0x3000U
#define RTL_FE_INTERFACE_DATA 0x3004U
#define RTL_NI_INDIRECT_ACCESS 0x80000000U
#define RTL_NI_INDIRECT_WRITE 0x40000000U
#define BIT(n) (1UL << (n))
'''
scaffold = r'''
struct rtl_fe_interface {
 unsigned int users, saved, source_mac, pppoe;
 bool counted;
};
struct rtl_fe_flow {
 unsigned int counter, source_mac, pppoe, ingress_session;
 bool bridge, counted, interface_owned;
};
struct rtl_fe {
 struct rtl_fe_interface interfaces[FE_INTERFACES];
 unsigned long counters[(FE_INTERFACES + 63) / 64];
 unsigned long busy_phys[(FE_INTERFACES + 63) / 64];
 unsigned int words[32], staging, command, calls, fail_at;
};
static bool test_bit(unsigned int bit, const unsigned long *bits)
{ return !!(bits[bit / 64] & BIT(bit % 64)); }
static bool rtl_fe_tunnel_phys_busy(struct rtl_fe *fe, unsigned int phys)
{ return phys < FE_INTERFACES && test_bit(phys, fe->busy_phys); }
static unsigned int find_first_zero_bit(const unsigned long *bits, unsigned int count)
{
 for (unsigned int i = 0; i < count; i++)
  if (!(bits[i / 64] & BIT(i % 64))) return i;
 return count;
}
static void __set_bit(unsigned int bit, unsigned long *bits)
{ bits[bit / 64] |= BIT(bit % 64); }
static void __clear_bit(unsigned int bit, unsigned long *bits)
{ bits[bit / 64] &= ~BIT(bit % 64); }
static unsigned int rtl_fe_read(struct rtl_fe *fe, unsigned int reg)
{
 assert(reg == RTL_FE_INTERFACE_DATA);
 return fe->staging;
}
static void rtl_fe_write(struct rtl_fe *fe, unsigned int reg, unsigned int value)
{
 assert(reg == RTL_FE_INTERFACE_DATA);
 fe->staging = value;
}
static int rtl_fe_indirect(struct rtl_fe *fe, unsigned int reg, unsigned int command)
{
 unsigned int index = command & 31;
 assert(reg == RTL_FE_INTERFACE_CMD);
 assert(!(command & ~(RTL_NI_INDIRECT_ACCESS | RTL_NI_INDIRECT_WRITE | 31U)));
 fe->command = command;
 fe->calls++;
 if (fe->calls == fe->fail_at) return -ETIMEDOUT;
 if (command & RTL_NI_INDIRECT_WRITE) fe->words[index] = fe->staging;
 else fe->staging = fe->words[index];
 return 0;
}
'''
tests = r'''
static void exhaust_and_share(void)
{
 struct rtl_fe fe = {0};
 struct rtl_fe_flow flows[35] = {0};
 unsigned int calls;
 assert(FE_INTERFACES == 32);
 for (unsigned int i = 0; i < 32; i++) fe.words[i] = 0xf0000000U | i;
 for (unsigned int i = 0; i < 32; i++) {
  flows[i].source_mac = i % 15;
  flows[i].pppoe = 3U | ((0x100 + i) << 2);
  assert(rtl_fe_interface_get(&fe, &flows[i]) == 0);
  assert(flows[i].counter == i && flows[i].counted && flows[i].interface_owned);
  assert(fe.interfaces[i].users == 1);
  assert(fe.words[i] == ((1U << 23) | (1U << 18) |
         ((flows[i].source_mac + 1) << 19) | flows[i].pppoe));
 }
 calls = fe.calls;
 flows[32].source_mac = flows[7].source_mac;
 flows[32].pppoe = flows[7].pppoe;
 assert(rtl_fe_interface_get(&fe, &flows[32]) == 0);
 assert(flows[32].counter == 7 && !flows[32].counted);
 assert(fe.calls == calls && fe.interfaces[7].users == 2);
 flows[33].source_mac = 14;
 flows[33].pppoe = 3U | (0x333 << 2);
 assert(rtl_fe_interface_get(&fe, &flows[33]) == -ENOSPC);
 assert(fe.calls == calls && !flows[33].interface_owned);
 assert(rtl_fe_interface_put(&fe, &flows[7]) == 0);
 assert(fe.calls == calls && !fe.interfaces[7].counted);
 flows[34].source_mac = flows[7].source_mac;
 flows[34].pppoe = flows[7].pppoe;
 assert(rtl_fe_interface_get(&fe, &flows[34]) == 0);
 assert(flows[34].counter == 7 && flows[34].counted);
 assert(rtl_fe_interface_put(&fe, &flows[32]) == 0 && fe.calls == calls);
 assert(rtl_fe_interface_put(&fe, &flows[34]) == 0);
 assert(fe.words[7] == (0xf0000000U | 7) && !fe.interfaces[7].users);
 assert(find_first_zero_bit(fe.counters, FE_INTERFACES) == 7);
 for (unsigned int i = 0; i < 32; i++) {
  if (i == 7) continue;
  assert(rtl_fe_interface_put(&fe, &flows[i]) == 0);
  assert(fe.words[i] == (0xf0000000U | i));
 }
 assert(!fe.counters[0]);
}
static void failures_retain_ownership(void)
{
 struct rtl_fe fe = {0};
 struct rtl_fe_flow flow = {0};
 fe.fail_at = 1;
 assert(rtl_fe_interface_get(&fe, &flow) == -ETIMEDOUT);
 assert(!flow.interface_owned && !fe.counters[0] && !fe.interfaces[0].users);
 memset(&fe, 0, sizeof(fe));
 fe.words[0] = 0xaabbccdd;
 assert(rtl_fe_interface_get(&fe, &flow) == 0);
 fe.fail_at = fe.calls + 1;
 assert(rtl_fe_interface_put(&fe, &flow) == -ETIMEDOUT);
 assert(fe.counters[0] == 1 && fe.interfaces[0].users == 1 && fe.interfaces[0].counted);
 fe.fail_at = 0;
 assert(rtl_fe_interface_put(&fe, &flow) == 0);
 assert(!fe.counters[0] && !fe.interfaces[0].users && fe.words[0] == 0xaabbccdd);
}
static void tunnel_phys_rows_skipped(void)
{
 struct rtl_fe fe = {0};
 struct rtl_fe_flow flows[20] = {0};
 unsigned int i;

 for (i = 0; i < 16; i++) {
  flows[i].source_mac = i % 15;
  flows[i].pppoe = 3U | ((0x400 + i) << 2);
  assert(rtl_fe_interface_get(&fe, &flows[i]) == 0);
  assert(flows[i].counter == i);
 }
 __set_bit(16, fe.busy_phys);
 __set_bit(17, fe.busy_phys);
 flows[16].source_mac = 1;
 flows[16].pppoe = 3U | (0x500 << 2);
 assert(rtl_fe_interface_get(&fe, &flows[16]) == 0);
 assert(flows[16].counter == 18);

 /* Busy tunnel row is not shared even if parameters match after bind. */
 assert(rtl_fe_interface_bind_slot(&fe, &flows[17], 16) == 0);
 flows[18].source_mac = flows[17].source_mac;
 flows[18].pppoe = flows[17].pppoe;
 flows[18].counter = 0;
 assert(rtl_fe_interface_get(&fe, &flows[18]) == 0);
 assert(flows[18].counter != 16);
 assert(rtl_fe_interface_bind_slot(&fe, &flows[19], 32) == -EINVAL);
}
int main(void)
{
 exhaust_and_share();
 failures_retain_ownership();
 tunnel_phys_rows_skipped();
 puts("PASS: actual fe_interface_get/put; 32 unique owners; compatible sharing; incompatible 33rd ENOSPC; last-owner restore; failure ownership; tunnel phys busy skipped");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='pt1500-eif-owner-') as directory:
    test = Path(directory) / 'owner.c'
    binary = Path(directory) / 'owner'
    test.write_text(prefix + limits + '\n' + scaffold + functions + tests)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I', str(DRIVER), str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env=dict(os.environ))
