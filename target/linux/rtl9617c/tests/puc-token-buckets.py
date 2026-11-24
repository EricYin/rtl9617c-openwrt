#!/usr/bin/env python3
"""Exercise the actual PUC initializer with a register-transaction model."""
from pathlib import Path
import subprocess,tempfile
ROOT = Path(__file__).resolve().parents[4]
P = Path('target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/pon/data/puc.c')
source = (ROOT / P).read_text()
start=source.index('int rtl_puc_token_buckets(');end=source.index('\nunsigned int rtl_puc_bp_read',start);function=source[start:end]
harness=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CIR_ACCESS 0x81c4
#define CIR_DATA1 0x81c8
#define CIR_DATA0 0x81cc
#define PIR_ACCESS 0x81ec
#define PIR_DATA1 0x81f0
#define PIR_DATA0 0x81f4
struct rtl9617c_pon { unsigned char *mac; };
static unsigned char registers[65536];
static uint32_t written[2][256][2];
static bool committed[2][256];
static int fail_queue=-1,fail_bank=-1,commits;
static void writel(uint32_t value,void *address) { memcpy(address,&value,4); }
static uint32_t get(unsigned reg){uint32_t v;memcpy(&v,registers+reg,4);return v;}
static int rtl_puc_access(struct rtl9617c_pon *p,unsigned int reg,unsigned int queue,bool write)
{
    assert(p->mac==registers && write && queue<256);
    assert(reg==CIR_ACCESS || reg==PIR_ACCESS);
    int bank=reg==PIR_ACCESS;
    if((int)queue==fail_queue && bank==fail_bank)return -ETIMEDOUT;
    assert(!committed[bank][queue]);committed[bank][queue]=true;commits++;
    written[bank][queue][0]=get(reg+8);written[bank][queue][1]=get(reg+4);return 0;
}
'''+function+r'''
static void reset(void){memset(registers,0,sizeof(registers));memset(written,0,sizeof(written));memset(committed,0,sizeof(committed));commits=0;fail_queue=fail_bank=-1;}
static void exact(unsigned bank,unsigned queue)
{
    uint32_t low=written[bank][queue][0], high=written[bank][queue][1];
    assert(committed[bank][queue]);
    if(bank){
        assert((low&1023)==1023);assert(((low>>10)&65535)==65535);
        assert(((low>>26)|((high&63)<<6))==4095);
        assert(((high>>6)&3)==2 && !(high&0x100));
        assert(low==UINT32_MAX && high==0xbf);
    } else assert(low==0 && high==0x80); /* OEM AAL CIR init unchanged. */
}
int main(void)
{
    struct rtl9617c_pon pon={registers};
    for(unsigned first=0;first<=256;first+=(first==0?8:first==8?248:1)) {
        reset();assert(rtl_puc_token_buckets(&pon,first)==0);assert(commits==2*(256-(int)first));
        for(unsigned q=0;q<256;q++)for(unsigned b=0;b<2;b++) {
            if(q<first)assert(!committed[b][q]);else exact(b,q);
        }
        if(first==256)break;
    }
    reset();fail_queue=5;fail_bank=1;assert(rtl_puc_token_buckets(&pon,0)==-ETIMEDOUT);assert(commits==11);
    assert(committed[0][5]&&!committed[1][5]&&!committed[0][6]);
    reset();fail_queue=8;fail_bank=0;assert(rtl_puc_token_buckets(&pon,8)==-ETIMEDOUT);assert(commits==0);
    puts("PASS: EPON 256 queues, ITU reserved queues, exact OEM fields, empty range and both failure boundaries");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='pt1500-pir-test-') as td:
    p=Path(td);(p/'test.c').write_text(harness)
    subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(p/'test.c'),'-o',str(p/'test')],check=True)
    r=subprocess.run([str(p/'test')],capture_output=True,text=True,check=True);print(r.stdout,flush=True)
