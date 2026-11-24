# L3PE Dual-Header 隧道 / 硬件组播 / NAPT6 规格书（Phase 0 RE-3）

状态：只读逆向测绘，**未在设备上验证**。所有寄存器写入结论均来自静态反汇编。
标注为 UNKNOWN 的条目表示当前语料无法确认，不得作为实现依据。

## 0. 方法与地址约定

### 0.1 语料

| 项目 | 路径 | 备注 |
|---|---|---|
| ca-ne.ko | scratch/stock-probe/lib/modules/5.10.70/extra/ca-ne.ko | SHA-256 a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e |
| fc_mgr.ko | .../rtl86900/FleetConntrackDriver/fc_mgr.ko | 2226536 B，2554 符号，未 strip |
| rtk_igmp_hook.ko | .../rtl86900/igmpHookModule/rtk_igmp_hook.ko | 304784 B |
| default_scfg.txt | /opt/ubiwork/cfg/default_scfg.txt | 823 行，root:root，需 sudo 读 |

重要：docs/rtl9617c/PT1500_AUTH_PIR.md 引用的 ca-ne.ko 是另一个构建
（SHA 71b3056af3217b08c96f5284f066614766286793141c9f69ad8ecb0f6b7275d4），
其中 fe_l3e_if_tbl_table @0x27cec0 的绝对地址**不适用于**本次语料。
本文所有 ca-ne.ko 地址均在本次语料内重新定位。

### 0.2 地址约定（必读）

三个 .ko 都是 **ET_REL / AArch64 / 无 DWARF**，sh_addr 全为 0，
因此 nm 给出的是**段内偏移**，不同段各自从 0 开始（.text / .data / .bss 独立计数）。

REA / Ghidra（image_base 0x100000，.text 文件偏移 0x80）换算：

    REA_addr = nm_section_offset + 0xFFFC0

ca-ne.ko 与 fc_mgr.ko 的 .text 均在文件偏移 0x80，故同一公式适用。
例：nm 0x6b0a0 -> REA 0x16b060。

本文一律写 nm 段内偏移并注明段名，避免与其它构建混淆。

### 0.3 全局寄存器窗口

OEM 固件在调试字符串里把 NE 寄存器窗口标为 0xf430xxxx
（例 "0xf43011dc" 等于开源 rtl9617c_regs.h 的 RTL_L2FE_PP_IPPB_ACCESS = 0x11dc）。
由此确定：

    NE_REG_BASE = 0xf4300000     # g_ne_reg_iobase 指向该窗口

本文寄存器偏移一律相对该窗口，即 g_ne_reg_iobase + off。

### 0.4 本次测绘的关键结构性发现

ca-ne.ko 提供的是**表与寄存器原语**，隧道的策略语义在 fc_mgr.ko。
证据：aal_pe_dual_control_entry_add / aal_pe_dual_content_entry_add /
aal_pe_dual_fmr_entry_add 在 ca-ne.ko 内 procedure_callers 返回**空**，
且均在 __ksymtab 中导出；而 fc_mgr.ko 内有完整的
rtk_fc_dualHash_* 与 _rtk_fc_dualHeader_ctrl_setup* 实现（地址见 §3）。

---

## 1. Dual-Header 三表全规格

### 1.1 三张表的描述符（.data 实测）

三表共用 generic table 框架（描述符 0xa8 字节）：
+0x00 table_id、+0x08 名字指针、+0x10 条目数、+0x1c 条目字节数、
+0x20 寄存器基址、+0x24 每次搬运 word 数、+0x28 起为操作函数表。

| 表 | 符号 | 位置 | table_id | 条目数 | 字节/条 | word/条 | 寄存器基址 |
|---|---|---|---|---|---|---|---|
| DUAL HEADER (Content) | l3pe_dual_content_tbl | .data+0x32f8 | 31 (0x1f) | 16 | 64 | 16 | 0xf4303548 |
| DUAL CONTROL | l3pe_dual_control_tbl | .data+0x33a0 | 32 (0x20) | 16 | 64 | 16 | 0xf4303548 |
| DUAL FMR | l3pe_dual_fmr_tbl | .data+0x3448 | 33 (0x21) | 3 | 64 | 16 | 0xf4303548 |

名字字符串位于 .rodata.str1.8+0x15338 / +0x15318 / +0x15300：
"L3FE PE DUAL HEADER TABLE" / "L3FE PE DUAL CONTROL TABLE" / "L3FE PE DUAL FMR TABLE"。

三表**共用一个 64 字节数据窗口**，靠命令字里的选择位区分，
这解释了描述符 +0x20 三者完全相同。

### 1.2 寄存器访问序列

- __l3pe_dual_hw_entry_set   @ .text+0x6a390
- __l3pe_dual_hw_entry_get   @ .text+0x6a4c0
- __l3pe_dual_hw_entry_clear @ .text+0x6a270

写序列（hw_entry_set 实测）：

1. 边界检查 idx < desc->entry_count(+0x10)，否则返回 -9
2. 从影子缓存 desc+0x88 取第 idx 条记录（stride 0x18 = 24 B）；
   记录 +0x00 = 指向 16-word 条目缓冲的指针，+0x08 = refcount；
   指针为空返回 -8
3. 倒序写 16 个 word（buf[0] 写到最高地址）：
       for i in 0..15:  NE[0x3548 + (16-i)*4] = buf[i]
   即 buf[0] -> 0x3588 ... buf[15] -> 0x354C
4. 写命令字到 NE[0x3548]，轮询 bit31 直到清零

命令字编码（hw_entry_set 与 hw_entry_clear 两份实现一致）：

| 表 | 读命令 | 写命令 | 索引范围 |
|---|---|---|---|
| Content (0x1f) | 0x80000000 或 (idx and 0xF) | 0xC0000000 或 (idx and 0xF) | 0..15 |
| Control (0x20) | 0x80000000 或 (idx and 0xF) | 0xC0000010 或 (idx and 0xF) | 0..15 |
| FMR (0x21) | 0x80000000 或 (idx and 0x7) | 0xC0000020 或 (idx and 0x7) | 0..2 有效，索引空间 8 |

位含义：bit31 = start/busy（写 1 启动，轮询到 0 完成）；bit30 = 写标志；
bit5 选 FMR；bit4 选 Control；两者皆 0 选 Content；bit3:0 为索引（FMR 仅 bit2:0）。

超时：轮询计数 1000 (0x3e8)，超时返回 -11。数据访问前后有 dmb oshst / dmb oshld。

hw_entry_clear 的特殊点：table_id == 0x21 (FMR) 时写 0xFFFFFFFF，
Content / Control 写 0x00000000。

### 1.3 Content 表（DUAL HEADER TABLE）

16 条 x 64 字节。__l3pe_dual_tbl_entry_print @ .text.unlikely+0xa06c
对每条**原样打印 16 个 32-bit word**，不做任何字段解码。

结论：Content 表存放**待插入的双头原始字节**，由硬件直接搬进报文；
协议语义完全由 Control 表的 hdr_fmt / hdr_len / *_ost 描述。
ca-ne.ko 内部没有 Content 字段级定义，故其位域为 **UNKNOWN（设计上不透明数据）**。

### 1.4 Control 表完整位域（本次核心成果）

有效位域**只有 128 bit（word0..word3）**，word4..word15 保留。
34 个字段**无缝填满 bit0..bit127 且无空洞**，是位域反推正确性的强证据
（hw_entry_set 仍搬 16 个 word，但 __l3pe_dual_control_tbl_entry_print
@ .text.unlikely+0xa2b4 只解码前 4 个 word）。

字段名取自 .rodata.str1.8 的 "dual_ctrl_*" 打印串；
位域由该 print 函数里逐条 ldr xN,[sp,#0x48 或 #0x50] + ubfx #shift,#width 反推。

word 与绝对 bit：buffer 小端，word0 = bit0..31、word1 = 32..63、
word2 = 64..95、word3 = 96..127。

| bit | 宽 | 字段 | 说明 / 实测值 |
|---|---|---|---|
| 127 | 1 | rep_ip_len_diff_pad_ctrl | 长度补偿 pad |
| 126 | 1 | rep_len_diff1_pad_ctrl | 同上(ost1) |
| 125 | 1 | rep_len_diff2_pad_ctrl | 同上(ost2) |
| 124..123 | 2 | hdr_fmt | 双头格式；DS-Lite=0、6RD=2 |
| 122..116 | 7 | hdr_len | 双头总长；DS-Lite=40、6RD=64 |
| 115..109 | 7 | mtu_diff | MTU 差；6RD=15 |
| 108..102 | 7 | ppp_ip_ver_ost | PPP IP 版本偏移；未用=0x7F |
| 101 | 1 | rep_ip_en | 是否改写外层 IP 头 |
| 100 | 1 | rep_ip_ver | 改写后 IP 版本 |
| 99..93 | 7 | rep_len_ost1 | 长度1 偏移；未用=0x7F |
| 92..86 | 7 | rep_len_diff1 | 长度1 差值 |
| 85..79 | 7 | rep_len_ost2 | 长度2 偏移；未用=0x7F |
| 78..72 | 7 | rep_len_diff2 | 长度2 差值 |
| 71..65 | 7 | ip4_ost | 内层 IPv4 头偏移；未用=0x7F |
| 64..58 | 7 | gre_seq_ack_ost | GRE seq/ack 偏移；未用=0x7F |
| 57..56 | 2 | gre_mod_fld | GRE 修改字段选择 |
| 55..49 | 7 | ip6_oft | 外层 IPv6 头偏移 |
| 48 | 1 | rep_ip_dscp_en | 改写 DSCP |
| 47 | 1 | rep_ip_ecn_en | 改写 ECN |
| 46 | 1 | rep_ip_len | 改写外层 IP 长度 |
| 45..39 | 7 | rep_ip_len_diff | 外层长度差值 |
| 38 | 1 | rep_ip_ptc | 改写 protocol |
| 37 | 1 | rep_ip_ttl | 改写 TTL / HopLimit |
| 36..34 | 3 | mapt_pre_len | MAP-T 前缀长（编码值，见 §3.4） |
| 33 | 1 | map_drf_ver | MAP Default Rule Format 版本 |
| 32..28 | 5 | 6rd_dip_pre_len | 6RD DIP 前缀长（MAP-T 复用） |
| 27..22 | 6 | 6rd_dip_suf_str_bit | 6RD 后缀起始 bit（MAP-T 复用） |
| 21..19 | 3 | dsl_uc_chk | DS-Lite 单播校验级别 |
| 18 | 1 | dsl_mc_chk | DS-Lite 组播校验（DS-Lite = 1） |
| 17 | 1 | l4sum_rec | L4 checksum 重算 |
| 16..10 | 7 | vxlan_sp_ost | VXLAN source port 偏移；未用=0x7F |
| 9..2 | 8 | inr_to_out_fld | inner->outer 字段映射（DS-Lite=0x30、6RD=0xB0、MAP-T=0x10） |
| 1 | 1 | tos_hsh_sel | hash 用 TOS/TC 选择 |
| 0 | 1 | mc_mac_map | 组播 MAC 映射（DS-Lite = 1） |

0x7F (127) 是 7-bit 字段的 N/A 哨兵值，多处未用字段均取 0x7F。

### 1.5 FMR 表（DUAL FMR TABLE）

__l3pe_dual_fmr_tbl_entry_print @ .text.unlikely+0xa6b0 给出字段名。
FMR 是 **MAP-T Forwarding Mapping Rule**（PSID 系列字段为决定性证据）。

| 位置 | 字段 | 说明 |
|---|---|---|
| word0..word1 (64 bit) | fmr_pre_addr | IPv6 前缀地址，打印为 0x08 加两段 %08x |
| word2 bit3:0 (bit64..67) | fmr_psid_str_ost | PSID 起始 bit 偏移 |
| word2 bit7:4 (bit68..71) | fmr_psid_end_ost | PSID 结束 bit 偏移 |
| word2 bit8 (bit72) | fmr_psid_refill | PSID 重填使能 |
| word2 bit15:9 (bit73..79) | fmr_pref_len | 前缀长度（7 bit） |
| word2 bit16 (bit80) | fmr_drf_ver | Default Rule Format 版本 |

word3..word15 保留。FMR 描述符声明 3 条有效条目，索引空间 8。

### 1.6 初始化 / 写入序列

注册：

- aal_l3pe_dual_content_tbl_init @ .text+0x6b0a0（exit 0x6b0d0）
- aal_l3pe_dual_control_tbl_init @ .text+0x6b0f0（exit 0x6b120）
- aal_l3pe_dual_fmr_tbl_init     @ .text+0x6b140（exit 0x6b170）

三者同一模板：desc+0x78 = 0（清 avail/registered 标志），
再调 __aal_table_register(desc->table_id, desc)；exit 调 __aal_table_unregister。

**关键：aal_l3pe_init @ .text+0x6b3a0 并不初始化 Dual-Header 三表。** 它只做：

    aal_mtu_lock 初始化
    for i in 0..15: mtu_table[i] = {0,0}; aal_l3pe_mtu_size_set(i, 0)
    aal_l3pe_pe_config_init()
    aal_l3pe_cntr_cfg_set(0, 0xfff)

Dual-Header 表由各自 *_tbl_init 单独注册，随后由 fc_mgr.ko 通过导出的
aal_pe_dual_*_entry_add() 逐条写入。

### 1.7 函数地址总表（ca-ne.ko，.text 段内偏移）

| 函数 | 偏移 | 函数 | 偏移 |
|---|---|---|---|
| __l3pe_dual_tbl_entry_add | 0x699a0 | __l3pe_dual_control_tbl_entry_add | 0x699d0 |
| __l3pe_dual_fmr_tbl_entry_add | 0x69a00 | aal_pe_dual_content_entry_add | 0x69a60 |
| __l3pe_dual_tbl_entry_add_by_idx | 0x69a30 | __l3pe_dual_control_tbl_entry_add_by_idx | 0x69b40 |
| aal_pe_dual_control_entry_add | 0x69b70 | __l3pe_dual_fmr_tbl_entry_add_by_idx | 0x69ba0 |
| aal_pe_dual_fmr_entry_add | 0x69bd0 | aal_pe_dual_content_entry_del | 0x69c60 |
| aal_pe_dual_control_entry_del | 0x69c80 | aal_pe_dual_fmr_entry_del | 0x69cb0 |
| __l3pe_dual_tbl_entry_set | 0x69ce0 | __l3pe_dual_control_tbl_entry_set | 0x69d10 |
| __l3pe_dual_fmr_tbl_entry_set | 0x69d40 | __l3pe_dual_tbl_entry_get | 0x69d70 |
| __l3pe_dual_control_tbl_entry_get | 0x69da0 | __l3pe_dual_fmr_tbl_entry_get | 0x69dd0 |
| __l3pe_dual_tbl_entry_get_by_idx | 0x69e00 | aal_pe_dual_content_entry_get | 0x69e30 |
| aal_pe_dual_control_entry_get | 0x69f20 | __l3pe_dual_fmr_tbl_entry_get_by_idx | 0x69f50 |
| aal_pe_dual_fmr_entry_get | 0x69f80 | aal_pe_dual_content_table_flush | 0x6a010 |
| aal_pe_dual_control_table_flush | 0x6a030 | aal_pe_dual_fmr_table_flush | 0x6a050 |
| __l3pe_dual_tbl_get_avail_count | 0x6a070 | __l3pe_dual_control_tbl_get_avail_count | 0x6a090 |
| __l3pe_dual_fmr_tbl_get_avail_count | 0x6a0b0 | __l3pe_dual_fmr_tbl_table_flush | 0x6a160 |
| __l3pe_dual_tbl_table_flush | 0x6a180 | __l3pe_dual_control_tbl_table_flush | 0x6a1a0 |
| __l3pe_dual_fmr_tbl_entry_del | 0x6a1c0 | __l3pe_dual_control_tbl_entry_del | 0x6a1f0 |
| __l3pe_dual_tbl_entry_del | 0x6a220 | __l3pe_dual_control_tbl_entry_get_by_idx | 0x6a240 |
| __l3pe_dual_hw_entry_clear | 0x6a270 | __l3pe_dual_hw_entry_set | 0x6a390 |
| __l3pe_dual_hw_entry_get | 0x6a4c0 | aal_l3pe_dual_content_tbl_init | 0x6b0a0 |
| aal_l3pe_dual_control_tbl_init | 0x6b0f0 | aal_l3pe_dual_fmr_tbl_init | 0x6b140 |

print 函数（.text.unlikely 段）：
__l3pe_dual_tbl_entry_print 0xa06c、__l3pe_dual_control_tbl_entry_print 0xa2b4、
__l3pe_dual_fmr_tbl_entry_print 0xa6b0。

---

## 2. 物理 EIF 32..63 双头映射规则

### 2.1 硬件容量：32 物理行（已确证）

- 表：fe_l3e_if_tbl_table @ .data+0x3c28
  table_id = **13 (0x0d)**，条目数 = **32 (0x20)**，1 word/条，4 字节/条，
  寄存器基址 = 0xf4303000。
- 寄存器：L3FE_GLB_EGRESS_L3_IF_TBL_ACCESS 的 addr 字段为 **5 bit（addr[4:0]）**，
  即物理行号 0..31。此结论与 PT1500_AUTH_PIR.md 的表述一致，
  且本次在自有语料内独立复核了 32 这个数字（描述符 +0x10 = 0x20）。
- 访问方式：该表属 generic table，经间接访问寄存器对
  **0xf430b058（数据）/ 0xf430b060（控制，bit31 = start）** 读写；
  超时日志字符串即 "0xf430b058" / "0xf430b060"。
  相关函数：_entry_add 0x6e230、_entry_add_by_idx 0x6e200、_entry_get 0x6e180、
  _entry_get_by_idx 0x6e150、_entry_set 0x6e1b0、_entry_del 0x6e1e0、
  _table_flush 0x6e130、_get_avail_count 0x6e110、_entry_print 0xba18、
  aal_fe_l3e_if_tbl_init 0x6e260 / exit 0x6e290（均在 ca-ne.ko .text）。

### 2.2 hash 逻辑索引 -> 物理行 映射表（决定性证据）

fc_mgr.ko **.rodata+0x5640**，符号 **hashIntfIdx2HwIntfIdx_mapping**，
64 字节 u8 表：

    idx  0..15 -> 0..15
    idx 16..31 -> 16..31
    idx 32..47 -> 16..31     (32->16, 33->17, ... 47->31)
    idx 48..63 -> 16..31     (48->16, 49->17, ... 63->31)

实测原始字节：

    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f

等价公式：

    phys = (hash < 32) ? hash : (16 + (hash & 0x0F))

### 2.3 冲突约束（由映射表直接推出）

1. 物理行 0..15：**只服务 hash 0..15**，一对一，无双头语义，无争用。
2. 物理行 16..31：**被 3 个 hash 索引共享**
   （16+x、32+x、48+x，其中 x = 0..15）。
   三个 hash 索引落在同一物理行，故该行只能保存**一份**参数，
   即三者必须具备**完全相同**的 EIF 参数才能共存。
3. 因此 Dual-Header 隧道与普通流在物理行 16..31 上**互斥**：
   若普通流已占用某一行且参数不同，后续双头隧道无法插入（或反之）。
   这与 PT1500_AUTH_PIR.md "with ownership and compatible sharing tracked
   separately from flow counters" 的描述吻合：共享必须"兼容"。
4. 开源对照：fe_priv.h 定义 FE_INTERFACES = 32、FE_COUNTERS = 32，
   即开源驱动只使用 0..31，**不触碰 32..63 的双头别名**；
   该别名只由 OEM 的 fc_mgr.ko 通过上述映射表使用。

### 2.4 双头语义的其它线索

- rtk_fc_dualHdr_has_double_l2 @ .text+0x46ed0（fc_mgr.ko）
- rtk_fc_dual_4To6_isXLAT @ .text+0x46e40
- _rtk_fc_dualHeader_g3ExtraInfo_setting @ .text+0x184e0
- _rtk_fc_flow_hashIndex_byDualPktOuterHdr（字符串可见，地址未确证）
- rtk_fc_netif_dualHashKey_config_byPktHdr @ .text+0xa1150
- rtk_fc_netif_update_dualinfo_by_dualHashKey @ .text+0xa1900
- rtk_fc_dualHashKey @ .text+0xa1060，rtk_fc_dualHashKey_remap_MAPT_XLAT @ .text+0xa1040

推论（**derived，非 observed**）：hash 索引 32..63 用于"按外层头再哈希"的
双头通路，即同一个物理 EIF 行对普通流与双头流呈现不同哈希键。

---

## 3. 隧道类型 / 硬件动作 / hash key 组合

### 3.1 双头类型枚举（fc_mgr.ko .data 实测，字符串逐条解出）

dualHdrType_name @ .data+0x16f8（短名，10 项）
name_of_dualHdrType @ .data+0x1748（长名，10 项）

| 值 | 短名 | 长名（enum） | 协议栈语义 |
|---|---|---|---|
| 0 | NONE | RTK_FC_DUALTYPE_NONE | 无隧道 |
| 1 | DSLITE | RTK_FC_DUALTYPE_IP4INIP6 | IPv4-in-IPv6（DS-Lite） |
| 2 | PPTP | RTK_FC_DUALTYPE_PPTP | PPP over GRE / IPv4 |
| 3 | L2TP | RTK_FC_DUALTYPE_L2TP | L2TPv2 over UDP / IPv4 |
| 4 | IPSEC | RTK_FC_DUALTYPE_IPSEC | IPsec 隧道模式 |
| 5 | GRE_ETH_BR | RTK_FC_DUALTYPE_GRE_ETH_BR | Ethernet-in-GRE 桥接 |
| 6 | VXLAN | RTK_FC_DUALTYPE_VXLAN | Ethernet-in-UDP-VXLAN |
| 7 | 6RD | RTK_FC_DUALTYPE_6RD | IPv6-in-IPv4（6RD） |
| 8 | MAPT | RTK_FC_DUALTYPE_MAPT | IPv4-in-IPv6（MAP-T） |
| 9 | END | RTK_FC_DUALTYPE_XLAT464 | 同槽位：短名数组放哨兵 END，长名数组放 XLAT464 |

注：类型 9 在两个数组里分别是 "END" 与 "XLAT464"，
说明短名数组把 END 当作计数哨兵，而长名数组列出了实际类型 XLAT464。
两者**不可混用**，实现时以长名为准。

**SRV6 存在但不在上述枚举内**：fc_mgr.ko 有
_rtk_fc_dualHeader_dual_ctrl_setupSRV6 @ .text+0xa0200
与 _rtk_fc_flow_setupSRV6 @ .text+0xa0680，
说明该枚举（本语料构建）之后又扩展了 SRV6，或 SRV6 走独立的类型编号（UNKNOWN）。

### 3.2 各类型的 Control 表实测取值

方法：反汇编 fc_mgr.ko 的 _rtk_fc_dualHeader_ctrl_setupXxx，
读出其向 64 字节栈缓冲写入的字面量，再用 §1.4 的位域表解码。
dst 缓冲区均为 64 字节、先整体清零，故未写字段为 0。

| 字段 | DS-Lite (IP4InIP6) | 6RD | MAP-T |
|---|---|---|---|
| hdr_fmt | **0** | **2** | 0（由入参合并，见下） |
| hdr_len | **40** | **64** | 入参相关 |
| mtu_diff | 0 | 15 | 0 |
| ppp_ip_ver_ost | 0x7F (N/A) | 120 | 0x7F (N/A) |
| rep_ip_en / rep_ip_ver | 1 / 1 | 0 / 0 | 入参 |
| rep_len_ost1 / rep_len_diff1 | 0x7F / 0 | 2 / 20 | 入参 |
| rep_len_ost2 / rep_len_diff2 | 0x7F / 0 | 0x7F / 16 | 入参 |
| ip4_ost | 0x7F | 0 | 入参 |
| gre_seq_ack_ost | 0x7F | 0x7F | 120 |
| gre_mod_fld | 0 | 0 | 0 |
| ip6_oft | 0 | 0x7F | 30 |
| rep_ip_dscp_en / ecn_en / len | 0 / 0 / 1 | 1 / 1 / 1 | 1 / 1 / 0 |
| rep_ip_len_diff | 0 | 20 | 1 |
| rep_ip_ptc / rep_ip_ttl | 0 / 0 | 0 / 0 | 1 / 1 |
| mapt_pre_len | 0 | 0 | 7 |
| map_drf_ver | 0 | 0 | 1 |
| 6rd_dip_pre_len | 0 | 0 | 31 |
| 6rd_dip_suf_str_bit | 0 | 32 | 48 |
| dsl_uc_chk / dsl_mc_chk | 0 / 1 | 0 / 0 | 0 / 0 |
| l4sum_rec | 0 | 0 | 0 |
| vxlan_sp_ost | 0x7F | 0x7F | 0x7F |
| inr_to_out_fld | **0x30** | **0xB0** | **0x10** |
| tos_hsh_sel / mc_mac_map | 0 / 1 | 0 / 0 | 0 / 0 |

函数地址（fc_mgr.ko .text）：

- _rtk_fc_dualHeader_ctrl_setupIP4InIP6 @ 0x9a2f0（下一条 0x9a400 为 _rtk_fc_flow_setupIP4InIP6）
- _rtk_fc_dualHeader_ctrl_setup6RD     @ 0x9e330（rtk_fc_dual_control_content_set6RD @ 0x9e2f0，
  _rtk_fc_flow_setup6RD @ 0x9e440）
- _rtk_fc_dualHeader_ctrl_setupMAPT    @ 0x995c0（_rtk_fc_flow_setupMAPT @ 0x99750）
- _rtk_fc_dualHeader_ctrl_setupL2TP    @ 0x98890（_rtk_fc_flow_setupL2TP @ 0x98aa0）
- _rtk_fc_dualHeader_ctrl_setupPPTP    @ 0x97af0（_rtk_fc_flow_setupPPTP @ 0x97ca0）

MAP-T 的 6rd_dip_pre_len=31 / 6rd_dip_suf_str_bit=48 属**字段复用**：
同一 5-bit / 6-bit 域在 MAP-T 模式下承载 IPv4 前缀长与 PSID 起始 bit。
此处语义为 **derived**（依字段名与 PSID 语义推断），未经设备验证。

### 3.3 VXLAN 专用寄存器与 hash 组合

VXLAN 走**独立入口**，config 由以下函数完成（ca-ne.ko .text）：

| 函数 | 偏移 | 寄存器 | 宽度 |
|---|---|---|---|
| aal_l3pe_vxlan_hash1_sport_range_set / get | 0x69000 / 0x69050 | NE+0x35EC | 20 bit (0xfffff) |
| aal_l3pe_vxlan_hash2_ptn_set / get (idx=1) | 0x690c0 / 0x691e0 | NE+0x35F0 | 20 bit (0xfffff) |
| aal_l3pe_vxlan_hash2_ptn_set / get (idx=2) | 同上 | NE+0x35F4 | 24 bit (0xffffff) |
| aal_l3pe_vxlan_hash2_ptn_set / get (idx=3) | 同上 | NE+0x35F8 | 24 bit (0xffffff) |
| aal_l3pp_vxlan_dport_set / get | 0x6d20 / 0x6f60 | — | — |

aal_l3pe_vxlan_hash2_ptn_set(idx, val) 的索引选择为：
idx=0 -> 0x35EC，idx=1 -> 0x35F0，idx=2 -> 0x35F4，idx=3 -> 0x35F8；
idx > 3 静默返回 0（不写寄存器、不报错）——这是一个**易错点**。

VXLAN 在 action 侧的字段（开源对照 rtl9617c fe_hw.h 的 enum rtl_fe_action_field）：
**RTL_FE_VXLAN_SPORT_MSB** 与 **RTL_FE_VXLAN_SPORT_UPDATE_EN**，
紧随 RTL_FE_DIP_REMAP_VLD / RTL_FE_DIP_REMAP 之后。
即"源端口高位置位 + 源端口更新使能"是 action 级开关，
配合 Control 表的 vxlan_sp_ost（bit16..10）定位 UDP source port 字段。

VXLAN 侧函数（fc_mgr.ko .text）：

- rtk_fc_dualHash_VXLAN @ 0x93cd0
- rtk_fc_netif_dual_set_VXLAN @ 0x95820
- rtk_fc_dual_control_entry_setVXLAN @ 0x9ea90
- _rtk_fc_dualHeader_dual_ctrl_setupVXLAN @ 0x9ed20
- rtk_fc_dual_control_content_setVXLAN @ 0x9f340
- _rtk_fc_dualHeader_dual_content_setupVXLAN @ 0x9f5a0
- _rtk_fc_flow_setupVXLAN @ 0x9f6d0
- rtk_fc_netdev_check_vxlan_dev @ 0x9a20、rtk_fc_netdev_get_vxlan_dev_vni @ 0x9ae0

### 3.4 各类型实现方式分类（结论）

**必须走 Dual-Header（Control+Content 双表编程）**：

- DS-Lite / IP4InIP6（hdr_fmt 0，hdr_len 40）
- 6RD（hdr_fmt 2，hdr_len 64）
- MAP-T（Control + FMR 三表联动；FMR 表只有 3 条，故 MAP-T 规则上限受 FMR 约束）
- VXLAN（Content 表存外层头，Control 表 + hash2 ptn 寄存器）
- GRE_ETH_BR、L2TP、PPTP、IPSEC、XLAT464、SRV6
  —— 均有各自的 _rtk_fc_dualHeader_ctrl_setup* / dualHash_* 实现

**只需外层透传、无需双头改写**：本语料中**未发现**此类实现。
所有 10 个类型都有 Control 表编程路径。UNKNOWN：是否存在纯软件路径。

**硬件不支持的**：无法从静态证据断言"不支持任何协议"，只能给出容量边界（见 §3.5）。

### 3.5 硬容量边界（由字段宽度直接推出）

| 约束 | 位宽 | 上限 | 影响 |
|---|---|---|---|
| hdr_len | 7 bit | 127 字节 | 双头总长不能超过 127 B；IPv6 外层 40 + IPv4 内层 20 = 60 可行 |
| Control 表条目 | — | 16 | 同时可编程的双头 profile 上限 16 |
| Content 表条目 | — | 16 | 同时可编程的双头内容上限 16 |
| FMR 表条目 | — | 3 | MAP-T 规则上限 3（索引空间 8） |
| mtu_diff | 7 bit | 127 | 隧道 MTU 差值上限 |
| 各 *_ost 偏移 | 7 bit | 127 | 双头内字段偏移不得超过 127 |

### 3.6 与 Linux 6.18 flow offload 的对接点

- FLOW_DISSECTOR_KEY_ENC_CONTROL / ENC_IP / ENC_TCP_UDP：
  对应 Control 表的 hdr_fmt（外层 IP 版本）、ip6_oft/ip4_ost（外层头定位）、
  vxlan_sp_ost（外层 UDP sport 定位）、以及 VXLAN_SPORT_UPDATE_EN。
- FLOW_ACTION_TUNNEL_ENCAP：对应 Content 表写入外层头模板 +
  Control 表 hdr_len / *_ost / rep_* 系列。
- FLOW_ACTION_TUNNEL_DECAP：对应 hdr_len 与 ip4_ost/ip6_oft 的"剥离长度/偏移"语义。
- 需要内核侧提供但当前 OEM 语料无对应物的能力（见 §7）：
  按 tunnel id 分配/回收 Control+Content 条目、FMR 条目管理、
  以及 EIF 物理行 16..31 的兼容共享仲裁。

---

## 4. 硬件组播：MCGID / ARB MC FIB

### 4.1 三层索引结构（本次测绘的主要结论）

    软件 MCGID (0..1023)
        -> MCE index 表 (ni_mce_indx_table, 256 条 x 2 word)
             -> 每条约 64-bit 位图，指向 ARB MC FIB 条目
                  -> l2fe_arb_fib_table (64 条 x 3 word) 承载端口掩码/VLAN 等

证据链：aal_hw_mcgid_free 里 generic_entry_get_by_idx(ni_mce_indx_table, hw_idx, buf)
后用 1 << i（i < 0x40 = 64）逐位遍历并调用 _aal_arb_mc_fib_action_del(i)，
最后 generic_entry_del(ni_mce_indx_table, hw_idx)。64 恰好等于 ARB MC FIB 条目数。

### 4.2 软件 MCGID 表

符号 swMcgid @ ca-ne.ko **.bss+0x2098**，1024 条（0x400），步长 14 字节：

| 偏移 | 类型 | 含义 |
|---|---|---|
| +0x00 | u8 | in_use 标志 |
| +0x02 | u16 | cur_hw_mcgid（0xFFFF = 无） |
| +0x04 | u16 | prev_hw_mcgid（换绑时保存） |
| +0x06 | 4 B | 交给 ni_mce_indx_table 的条目数据区 |
| +0x0A | u16 | 保留/清零 |
| +0x0C | u16 | 保留/清零 |

- aal_sw_mcgid_alloc @ .text+0x4ee70：加锁后**线性扫描 0..0x3FF**，
  找到空闲项置 in_use=1、cur 与 prev 置 0xFFFF、+0x0A/+0x0C 清零，返回索引；
  全满返回 0xfffffffe (-2)。
- aal_sw_mcgid_free @ .text+0x4fe70

### 4.3 硬件 MCGID（MCE index）生命周期

- aal_hw_mcgid_new @ .text+0x4fcc0
  1) MCGID 必须 < 0x400 且 sw 项 in_use，否则 -12
  2) 若该 MCGID 的 MCE 引用计数为 0（+0x06 处 u64 == 0），
     直接复用/清理旧索引，返回 0
  3) 否则 generic_entry_add(ni_mce_indx_table, ...) 取新 MCE 索引，
     并把旧索引存进 +0x04，新索引写 +0x02
  4) 表未注册（DAT_002ad9c0 == 0）返回 -8
- aal_hw_mcgid_free @ .text+0x4fb10
  1) 校验 hw_idx 属于该 MCGID 的 cur 或 prev，否则 -12
  2) generic_entry_get_by_idx(ni_mce_indx_table, hw_idx, buf)
  3) 对 64-bit 位图中每个置位 i：_aal_arb_mc_fib_action_del(i)
  4) generic_entry_del(ni_mce_indx_table, hw_idx)
  5) cur 或 prev 置回 0xFFFF

**回收顺序（重要）**：先删 ARB MC FIB 动作，再删 MCE 索引，
最后清 MCGID；反向操作会留下悬挂的 MCE 索引。

### 4.4 表描述符

| 表 | 符号 | 位置 | table_id | 条目数 | word/条 | 字节/条 | 寄存器基址 |
|---|---|---|---|---|---|---|---|
| MCE index | ni_mce_indx_table | .data+0x12a8 | 14 (0x0e) | 256 | 2 | 8 | 0xf430aa64 |
| ARB MC FIB | l2fe_arb_fib_table | .data+0x1350 | 15 (0x0f) | 64 | 3 | 12 | 0xf4301634 |

### 4.5 ARB MC FIB 写序列（aal_arb_mc_fib_set @ .text+0x3ff80）

    idx 必须 < 0x40，否则返回 2
    1) NE[0x1634] = idx | 0x80000000        ; 读命令，bit31=start
       轮询 bit31 直到清零（10000 次，超时打印 "0xf4301634"）
    2) 读回三字：word0 = NE[0x1640]、word1 = NE[0x163C]、word2 = NE[0x1638]
    3) 按 chg_mask 逐字段修改（见 4.6）
    4) NE[0x1640] = word0；NE[0x163C] = word1；NE[0x1638] = word2
    5) NE[0x1634] = idx | 0xC0000000        ; 写命令，bit31=start，bit30=write
       轮询同 (1)

aal_arb_mc_fib_get @ .text+0x40480 为对应读接口。

### 4.6 ARB MC FIB 三字条目位域

由 chg_mask 的 27 个分支反推。条目为 96 bit，字段按"紧凑位串"排布：
word0 = bit0..31、word1 = 32..63、word2 = 64..95。

| mask 位 | 位域 | 宽 | 来源（输入 blob 位） |
|---|---|---|---|
| 0 | word0 bit1:0 | 2 | blob bit1:0 |
| 1 | word0 bit13:2 | 12 | blob bit13:2 |
| 2 | word0 bit14 | 1 | blob bit14 |
| 3 | word0 bit15 | 1 | blob bit15 |
| 4 | word0 bit17:16 | 2 | blob bit17:16 |
| 5 | word0 bit20:18 | 3 | blob bit20:18 |
| 6 | word0 bit21 | 1 | blob bit21 |
| 7 | word0 bit22 | 1 | blob bit22 |
| 8 | word0 bit31:23 | 9 | blob bit31:23 |
| 9 | word1 bit1:0 | 2 | blob bit33:32 |
| 10 | word1 bit13:2 | 12 | blob bit45:34 |
| 11 | word1 bit14 | 1 | blob bit46 |
| 12 | word1 bit16:15 | 2 | blob bit48:47 |
| 13 | word1 bit18:17 | 2 | blob bit50:49 |
| 14 | word1 bit21:19 | 3 | blob bit53:51 |
| 15 | word1 bit22 | 1 | blob bit54 |
| 16 | word1 bit23 | 1 | blob bit55 |
| 17 | word1 bit29:24 | 6 | blob bit61:56 |
| 18 | word1 bit30 | 1 | blob bit62 |
| 19 | word1 bit31 | 1 | blob bit63 |
| 20 | word2 bit0 | 1 | blob bit64 |
| 21 | word2 bit1 | 1 | blob bit65 |
| 22 | word2 bit4:2 | 3 | blob bit67:66 |
| 23 | word2 bit7:5 | 3 | blob bit70:68 |
| 24 | word2 bit9:8 | 2 | blob bit72:71 |
| 25 | word2 bit10 | 1 | blob bit73 |
| 26 | word2 bit11 | 1 | blob bit74 |

已用位 0..74（共 75 bit），word2 bit12..31 未定义。
**各字段的语义名 UNKNOWN**：ca-ne.ko 无 MC FIB 的字段名打印函数，
只有打包顺序可确证。开源驱动 fe_hw.h 的 enum rtl_fe_action_field 中
RTL_FE_MCGID / RTL_FE_MC / RTL_FE_MDATA_BYTE_VLD / RTL_FE_MDATA_BYTE
属于 **action** 字段而非本表，不可直接套用。

### 4.7 上层建表（_aal_arb_mc_fib_action_add @ .text+0x4f020）

- 先 aal_l2_vlan_default_cfg_get(0, buf) 取 4 个默认 TPID（local_38/36/34/32）
- word1 bit29:24 = (action[0] & 0x3F) —— 高位字段
- 若 action[+10] bit0 == 0 → word1 bit30 置 1；否则按 VLAN TPID 匹配结果
  在 word1 bit15:13 写 3-bit 编码，匹配失败打印 "error can not get expect tpid"
- 若 action[+2] bit11 置位 → 走 **MC→UC 转换**：
  调 aal_l2fe_pe_my_mac_add(0, ...) 添加目的 MAC，失败返回 0xc；
  成功后把 word2 的低位写成 (mac_idx & 7) << 2 | 0x402
- 条目最终 generic_entry_add(l2fe_arb_fib_table, entry, &idx)

### 4.8 VLAN 联动

- ca-ne.ko .bss+0x610 / +0x614：**g_vlan_mcgid_0 / g_vlan_mcgid_1**
  （两个全局 VLAN MCGID 持有者），说明 VLAN 侧存在按 VLAN 绑定的 MCGID。
  具体使用函数：UNKNOWN（仅确认符号与类型为 BSS 4 字节）。
- default_scfg.txt 实测组播相关配置：
  CFG_ID_L2_IGMP_SNOOPING = 1、CFG_ID_MC_MODE = 2、
  CFG_ID_MC_MAC_UC_CONV_MC = 1、CFG_ID_L2_UMC_DROP = 1、
  CFG_ID_LAN_2_LAN_MC = 1、CFG_ID_NE_DEFAULT_FLOW = 0xFFFF。

### 4.9 MCGID 保留区（任务要求的"避开 GEM/T-CONT/保留 index"）

**UNKNOWN。** 明确否证的部分：aal_sw_mcgid_alloc 线性扫描**全部 1024 项**，
代码中**没有任何保留位图或上界裁剪**；ca-ne.ko 与 fc_mgr.ko 中也没有
名为 reserved / gem / tcont 的 MCGID 相关符号。
因此"避开 GEM/T-CONT/保留 index"若成立，只可能由**闭源用户态 / rtk SDK**
约定，不在本次三个 .ko 语料内。

### 4.10 与 Linux MDB / IGMP snooping 的对接建议

- 内核侧 MDB 事件（br_mdb / switchdev）→ 软件 MCGID 分配（1024 项）
- 每个 MCGID → 1 个 MCE index（256 项）→ 最多 64 个 ARB MC FIB 成员条目
- 端口掩码与 VLAN 改写落在 ARB MC FIB 三字条目（§4.6）
- 删除必须遵循 §4.3 的逆序：ARB 动作 → MCE 索引 → MCGID
- rtk_igmp_hook.ko 提供 rt_igmpHook_* 导出（devConfig / brDevConfig /
  whiteList / groupToPsTbl / groupWeight / nextValidGroupStatistic），
  属内核 IGMP 报文旁路统计与白名单，不直接持有 MCGID；
  其 .text 符号的 nm 地址为各段独立从 0 起（多段），不能直接当绝对地址用。

---

## 5. IPv6 NAPT6

### 5.1 表达位置：action 字段，而非独立表

ca-ne.ko 的 L3PE 表清单里**没有** NAPT6 专用表；
NAPT6 以 **hash action 的一个字段**形式存在。

- 开源对照 rtl9617c fe_hw.h 的 enum rtl_fe_action_field 中
  **RTL_FE_IP_ADDR_NAPT6** 位于 RTL_FE_IP_ADDR 之后、
  RTL_FE_MAC_DA_IDX_VLD 之前（枚举序号 22，0 基）。
  相邻字段为 RTL_FE_IP_ADDR_VLD(19) / RTL_FE_IP_TYPE(20) / RTL_FE_IP_ADDR(21)。
- 即：先由 IP_ADDR_VLD/IP_TYPE 选中 IP 地址表条目，再由 IP_ADDR_NAPT6
  指明该条目在 NAPT6 语义下如何被解释（前缀/全地址/端口）。
  这与"NAPT6 与 IP 地址表 / NAT 槽位联动"的结构一致。

### 5.2 convert_act_flow_naptv6_mode（决定性证据）

- 符号 convert_act_flow_naptv6_mode @ fc_mgr.ko **.text+0x93250**
- 调用者写入的目标是一个 **action 结构**（param_2），覆盖字节 0x00..0x2E，
  即 word0..word11（48 字节区间内）。
- 行为：把输入描述符 param_1 的若干 8/16/32-bit 字段，按**固定位序**
  RMW 进 action 的各个 word。可确证的结构：

| action 位置 | 来源（param_1 偏移） | 说明 |
|---|---|---|
| word0 / +0x00 | +0x12, +0x13, +0x14 | mode 域，含 bit9 起的 7-bit 子域与 +0x14 的 bit6 标志 |
| +0x04..+0x07 | +0x1b, +0x17..+0x1a | 32-bit 打包字段（左移 0x12 后写入） |
| +0x08..+0x0B | +0x60（bit2..9）, +0x10 bit56 | 多个 1-bit 使能位 + 1 个 6-bit 域 |
| +0x0C..+0x0F | +0x6a（bit0..7）, +0x6b | 4 个 8-bit 段 |
| +0x10..+0x13 | +0x68 bit56/57, +0x6f, +0x70 | 含 6-bit 与 7-bit 域 |
| +0x14..+0x17 | +0x70 bit24..31, +0x74, +0x75, +0x76 | 端口范围相关 |
| +0x18..+0x1B | +0x70 bit56..59, +0x77, +0x78 | 同上 |
| +0x1C..+0x1F | +0x78 bit24..31, +0x7c, +0x7d | 同上 |
| +0x20..+0x23 | +0x78 bit56..62, +0x7f, +0x80 | 同上 |
| +0x24..+0x27 | +0x86..+0x8a | 一个 40-bit 地址前缀打包 |
| +0x28..+0x2B | +0x8e..+0x91 | 第二个 40-bit 地址前缀打包 |
| +0x2C..+0x2E | +0x8e bit7, +0x92 | 收尾字段 |

**字段语义名 UNKNOWN**：无打印函数、无字符串常量可交叉验证。
上表只描述"哪些输入字节进到 action 的哪个位置"，足以指导重实现，
但不足以给出人类可读的字段名。

### 5.3 其它 NAPT6 证据

- hash_flow_naptv6_support_mode @ fc_mgr.ko **.bss+0x7418**（全局开关）
- dump_HS_ACTGRP_FLOW_NAPTV6_MODE @ .text+0x16828（调试打印）
- 名称中的 HS_ACTGRP = hash action group；
  与开源 fe_hw.h 的 RTL_FE_ACTION_GROUPS = 0x00140000 属同一机制。

### 5.4 NAT66 / NPTv6 / DNAT6 可表达性

| 场景 | 可表达性 | 依据 |
|---|---|---|
| NAT66（1:1 全地址改写，双向） | **可表达** | IP_ADDR_NAPT6 + IP_ADDR 表条目；convert_act_flow_naptv6_mode 打包两个 40-bit 前缀域，足以容纳 /64 级前缀 |
| NPTv6（RFC 6296 前缀翻译） | **可表达，但需软件算校验和** | 硬件只做前缀替换；NPTv6 要求伪头校验和"中性"调整，需确认 l4sum_rec 是否覆盖（UNKNOWN） |
| DNAT6（目的地址改写） | **部分可表达** | 取决于 IP_ADDR_NAPT6 是否区分源/目的槽位；本语料 UNKNOWN |
| 端口翻译（NAPT6 的端口级 PAT） | **UNKNOWN** | convert_act_flow_naptv6_mode 打包了端口范围相关域（+0x74/+0x75/+0x76），但无字段名确证其为 PAT 端口映射 |
| 前缀长度任意（非 /64） | **受限** | FMR 的 fmr_pref_len 为 7-bit（≤127），Control 的 mapt_pre_len 仅 3-bit（编码值），任意长度需查表 |

CAM / SMAC / NAT 槽位编号与容量：**UNKNOWN**（本次三个 .ko 中未定位到
NAPT6 相关的表描述符；开源对照 fe_hw.h 只给出
RTL_FE_CAM_WORDS 5 / RTL_FE_SMAC_WORDS 5 / FE_CAM_PROTOCOLS 3，
不含 NAT 槽位定义）。

---

## 6. FE Flow MTU 表复核

### 6.1 结论：14 bit x 16 槽成立，寄存器布局已完全确证

- aal_l3pe_mtu_size_set  @ ca-ne.ko .text+0x6acf0
- aal_l3pe_mtu_size_add  @ .text+0x6ae90
- aal_l3pe_mtu_size_del  @ .text+0x6af70
- aal_l3pe_mtu_size_get  @ .text+0x68be0
- aal_l3pe_mtu_size_lookup @ .text+0x6a0d0
- aal_l3pe_init @ .text+0x6b3a0（16 槽全部清零）

寄存器：8 个 32-bit 寄存器，NE+0x3520 / 0x3524 / 0x3528 / 0x352c /
0x3530 / 0x3534 / 0x3538 / 0x353c。

每寄存器 2 槽：

| 槽索引 | 寄存器 | 位域 | 掩码 |
|---|---|---|---|
| 偶 (0,2,4,...,14) | 0x3520 + (i/2)*4 | bit13:0 | 0x00003FFF |
| 奇 (1,3,5,...,15) | 0x3520 + ((i-1)/2)*4 | bit29:16 | 0x3FFF0000 |

每寄存器 bit31:30 保留（set 时以 0xC0000000 掩码原样保留）。

精确映射（set 与 get 双向一致，互为交叉验证）：

    槽0  -> 0x3520 低      槽1  -> 0x3520 高
    槽2  -> 0x3524 低      槽3  -> 0x3524 高
    槽4  -> 0x3528 低      槽5  -> 0x3528 高
    槽6  -> 0x352c 低      槽7  -> 0x352c 高
    槽8  -> 0x3530 低      槽9  -> 0x3530 高
    槽10 -> 0x3534 低      槽11 -> 0x3534 高
    槽12 -> 0x3538 低      槽13 -> 0x3538 高
    槽14 -> 0x353c 低      槽15 -> 0x353c 高

### 6.2 软件侧

- mtu_table：16 条 x 8 字节，{u32 size; u32 refcount}
- add(mtu, &slot)：已存在则 refcount++ 并复用；否则找 refcount==0 的槽写入，
  调 set()，返回槽号；全满返回 -2；mtu >= 0x4000 返回 -12
- del(slot)：refcount--，归零时 set(slot, 0) 并清表项；未分配返回 -3
- lookup(mtu, &slot)：按 size 命中且 refcount != 0 返回槽号，否则 -3
- set/get 边界：slot > 0xf 返回 -9；value > 0x3fff 返回 -12

### 6.3 开源对照（独立确认）

rtl9617c_regs.h：

    #define RTL_FE_MTU(n)   (0x3520 + ((n) / 2) * 4)

与逆向结果**完全一致**（8 寄存器、2 槽/寄存器）。

### 6.4 关于 "LPB MRU 1700"

**无法确证，倾向否定。** 证据：

1. 三个 .ko 与开源驱动中**未出现 1700 这个常量**在 MTU/LPB 路径上。
2. 开源驱动里 LPB 是**ingress logical-port 绑定表**，不是 MRU：
   RTL_FE_LPB_WORDS = 3、FE_LPB_ENTRIES = 2、FE_LPB_SIDES = 3，
   rtl_fe_setup_lpb() 写 RTL_FE_LPB_TABLE(i, side) 与 RTL_FE_LPB_PROFILE
   （值 7 | 25<<8 | 1<<14 | 24<<16 | 2<<22 | 3<<24），与 MRU 无关。
3. ca-ne.ko 里带 MTU 语义的只有 §6.1 的 16 槽表与
   nic_egress_start_xmit_get_mtu（默认 mtu 0x5DC = 1500，
   把 seg_size 钳到 0x7FF = 2047）。

结论：**"LPB MRU 1700" 属 UNKNOWN / 疑似误记**，不得写入实现。

### 6.5 1536 MTU 是否有其它表项瓶颈

MTU 表本身**不是**瓶颈：14 bit 上限 16383，1536 富余。

需一并检查的其它位宽（均不阻塞 1536）：

| 位置 | 位宽 | 上限 | 对 1536 的影响 |
|---|---|---|---|
| aal_l3pe_mtu_size_set/get | 14 bit | 16383 | 无 |
| nic_egress_start_xmit_get_mtu seg_size | 11 bit 钳位 | 2047 | 无（1536 < 2047） |
| Control 表 hdr_len | 7 bit | 127 | 只影响双头长度，不影响 L3 MTU |
| Control 表 mtu_diff | 7 bit | 127 | 隧道场景需 1536 + 双头 <= 对端 MTU 时可能吃紧 |
| FMR fmr_pref_len | 7 bit | 127 | 与 MTU 无关 |
| ARB MC FIB | 75 bit 已用 | — | 与 MTU 无关 |

**真正的 1536 风险不在 MTU 表，而在隧道叠加**：
若 1536 + 双头（例如 6RD hdr_len = 64）超过物理口 MTU，
需要 mtu_diff 或分片策略配合，此处 mtu_diff 仅 7 bit（≤127），
1536+64=1600 仍在范围内，故 1536 可行。

---

## 7. 可实现 / 不可实现 / 需内核补丁 分类

前提：目标平台为 Linux 6.18 + 自研 rtl9617c 驱动（开源对照树），
需复刻 OEM 的 L3PE 硬件加速行为。

### 7.1 可直接实现（硬件已具备，只需驱动编程）

| 项目 | 依据 |
|---|---|
| 16 槽 Flow MTU 表（含引用计数） | §6，位宽与寄存器全确证，开源驱动已有 RTL_FE_MTU(n) |
| 32 物理 EIF 行（0..31） | §2，fe_l3e_if_tbl_table 32 条、addr[4:0] |
| hash 索引 32..63 -> 物理 16..31 的别名映射 | §2.2，映射表字节完全确证 |
| Dual-Header Control 表 34 字段编程 | §1.4，位域无缝覆盖 128 bit |
| Dual-Header Content 表（64 B 原始头） | §1.3 |
| FMR 表（MAP-T，3 条） | §1.5 |
| ARB MC FIB 三字条目 + 64 条容量 | §4.5/4.6 |
| MCE index 表 256 条 | §4.4 |
| 软件 MCGID 1024 项分配/释放 | §4.2/4.3 |
| VXLAN hash2 ptn 四个寄存器 | §3.3 |
| DS-Lite / 6RD / MAP-T 的 Control 表取值 | §3.2（实测字面量） |

### 7.2 不可实现 / 受硬容量限制

| 项目 | 限制 | 依据 |
|---|---|---|
| 超过 16 个并存双头 profile | Control 表 16 条 | §1.1 |
| 超过 16 段并存双头内容 | Content 表 16 条 | §1.1 |
| 超过 3 条 MAP-T FMR 规则 | FMR 表 3 条 | §1.1 |
| 双头总长 > 127 字节 | hdr_len 7 bit | §1.4 |
| 双头内字段偏移 > 127 字节 | 各 *_ost 7 bit | §1.4 |
| 单条 EIF 参数跨物理行 16..31 独立分配 | 3 个 hash 索引共享 1 物理行 | §2.3 |
| ARB MC FIB 超过 64 个成员条目 | 表 64 条 | §4.4 |
| MCE index 超过 256 | 表 256 条 | §4.4 |

注意：上表都是**容量/位宽**限制，不是"协议不支持"。
本次语料**无法**断言任何具体隧道协议"硬件不支持"——10 个类型都有编程路径。

### 7.3 需要内核 / 驱动补丁

| 项目 | 缺口 | 建议 |
|---|---|---|
| EIF 物理行 16..31 的**兼容共享仲裁** | OEM 有 ownership + compatible-sharing 记账，开源驱动完全没有 | 需新增 owner 表：记录每个物理行的参数指纹，冲突时拒绝或回退软件转发 |
| hash 索引 32..63 的分配器 | 开源驱动只用 0..31 | 需新增 32..63 的分配/回收，并与 §2.3 兼容性检查绑定 |
| Dual-Header 条目生命周期管理 | ca-ne.ko 只有 add/del/get/flush 原语，无抢占/老化 | 需在驱动内实现 16 条 Control/Content 的分配器 + refcount |
| MAP-T FMR 分配 | 只有 rtk_8277c_l3_pe_dual_fmr_add/get/del | 需 3 条容量的规则表与冲突检测 |
| NAPT6 字段语义 | convert_act_flow_naptv6_mode 只有位序，无字段名 | 需动态验证（设备上写读回）后才能用于 NAT66/NPTv6 |
| MCGID 保留区约定 | 三模块内无保留位图 | 若确需保留区，必须在驱动侧自行定义并保证不与闭源路径冲突 |
| LPB/MRU 1700 | 无任何证据 | 不要实现 |

---

## 8. UNKNOWN 清单（禁止猜测）

| # | 未确认项 | 尝试过的证据 | 结论 |
|---|---|---|---|
| U1 | Content 表 16 个 word 的字段语义 | __l3pe_dual_tbl_entry_print 原样打印、无字段名 | 设计上不透明，需设备写入后读回报文比对 |
| U2 | Control 表 word4..word15 是否真的未用 | 描述符声明 64 B/条，print 只解码 word0..3 | 需设备读回确认是否恒 0 |
| U3 | hdr_fmt 的 4 个取值完整语义 | 仅实测 DS-Lite=0、6RD=2 | 1、3 未知；与 IP 外层版本/隧道类型的完整映射未知 |
| U4 | MAP-T 的 mapt_pre_len=7 与 6rd_dip_pre_len=31 的确切编码 | 字段名为复用，无打印语义 | derived，需文档或设备验证 |
| U5 | ARB MC FIB 27 个字段的语义名 | ca-ne.ko 无该表的字段名打印 | 只有位序可确证 |
| U6 | MCGID 保留区（GEM/T-CONT/保留 index） | 分配器线性扫描全 1024 项，无保留逻辑 | 三模块内不存在；可能在闭源用户态 |
| U7 | NAPT6 action 字段的字段名 | 无打印、无字符串 | 只有位序（§5.2） |
| U8 | CAM / SMAC / NAT 槽位编号与容量 | 三模块内无 NAPT6 表描述符 | 未知 |
| U9 | DNAT6 是否可表达（源/目的槽位区分） | IP_ADDR_NAPT6 单字段 | 未知 |
| U10 | l4sum_rec 是否覆盖 NPTv6 的校验和中性调整 | 仅知为 1-bit 使能 | 未知 |
| U11 | SRV6 的类型编号 | 枚举 10 项不含 SRV6，但有 SRV6 实现函数 | 未知（可能后加或独立编号） |
| U12 | LPB MRU 1700 | 三模块与开源驱动均无 1700 常量；LPB 是 ingress 绑定表 | 疑似误记，否定 |
| U13 | g_vlan_mcgid_0/1 的读写者 | 只有 BSS 符号，无 xref 定位 | 未知 |
| U14 | "只需外层透传"的隧道类型是否存在 | 10 个类型都有 Control 编程路径 | 未发现；不能排除软件路径 |
| U15 | FC 侧 sw_mcgid/hw_mcgid（fc_mgr.ko .data+0x5288/0x528a）的用途 | 仅见 u16 全局量 | 未知，疑为计数/缓存 |

---

## 9. W8 的可行范围建议

W8 若目标是"复用 OEM L3PE 硬件能力"，建议按下列顺序推进，
并明确区分"能立刻做"与"必须先取证"。

### 9.1 W8 可安全纳入范围（证据充分）

1. **Flow MTU 表**：16 槽 / 14 bit / 8 寄存器 / 2 槽每寄存器，
   含引用计数与 lookup。开源驱动已有 RTL_FE_MTU(n) 宏，风险最低，建议先做。
2. **EIF 32 物理行**：只实现 0..31；显式拒绝 32..63，
   并在代码注释中记录 §2.2 的映射表与"别名不是额外物理资源"的结论。
3. **硬件组播骨架**：软件 MCGID（1024）-> MCE index（256）
   -> ARB MC FIB（64）三层，配 §4.6 的三字位序与 §4.3 的回收逆序。
   即使字段语义未全知，端口掩码写入路径可以按位序实现并用读回验证。
4. **Dual-Header Control 表 34 字段位域**：可作为寄存器定义直接落地，
   先只启用 DS-Lite / 6RD / MAP-T 三种（有实测字面量），
   其余类型保持未实现并返回 -EOPNOTSUPP。

### 9.2 W8 需要先取证才能纳入

1. **hash 索引 32..63 的双头通路**：映射表已确证，但"何时选 32..63"
   的判定条件（外层头再哈希的触发条件）未确证（U 见 §8）。
   建议先在设备上抓 rtk_fc_dualHashKey 的输入输出。
2. **VXLAN**：寄存器与 action 字段已知，但 Control/Content 的实际字节
   模板未取（rtk_fc_dual_control_content_setVXLAN 的填充值需要动态读回）。
3. **NAPT6**：只有位序，无字段名。**不建议**在 W8 承诺 NAT66/NPTv6 功能，
   最多做到"action 结构可按位序构造"并以设备读回验证。
4. **MAP-T 完整功能**：FMR 只有 3 条，需先确认产品需求是否 ≤3 条规则。

### 9.3 W8 应明确排除

- 任何依赖 LPB MRU 1700 的设计（§6.4，证据否定）。
- 声称"硬件不支持某隧道协议"的结论（无证据）。
- 复用物理行 16..31 而不做兼容性检查（会导致静默错配）。
- 假设 MCGID 存在保留区（§4.9，三模块内无此逻辑）。

### 9.4 建议的最小验证闭环（每项都要设备读回）

对每个寄存器写入，按"写 -> 读回 -> 与预期位域比对"三步验收；
本次所有结论均为**静态**推导，未做任何设备读写。
优先级：MTU 表 -> EIF 32 行 -> ARB MC FIB -> Dual-Header Control -> 其余。

---

## 10. 附：本次使用的工具链与可复现命令

- 符号/段/重定位：aarch64-linux-gnu-nm / readelf / objdump（WSL Ubuntu-24.04）
- 反汇编：python3 + capstone 5.0.7 + pyelftools 0.30，
  自建 reloc-aware 反汇编器把 adrp/add 的 .rela 项解析成字符串常量，
  从而把 printk 的字段名与 ubfx 位域一一对齐（这是 Control 表位域的来源）。
- 交叉验证：REA / Ghidra 12.1.4（image_base 0x100000）用于
  aal_l3pe_mtu_size_* / aal_arb_mc_fib_set / aal_l3pe_init /
  aal_sw_mcgid_alloc / aal_hw_mcgid_new / aal_hw_mcgid_free /
  convert_act_flow_naptv6_mode 的伪代码核对。

可复现要点：所有 .ko 的 .text 文件偏移均为 0x80，
故 nm 段内偏移 + 0xFFFC0 = Ghidra/REA 地址；
.data / .rodata 段内偏移需按各自段基址另算。
