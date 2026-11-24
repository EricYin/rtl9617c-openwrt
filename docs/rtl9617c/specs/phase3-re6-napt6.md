# Phase 3 RE-6：NAPT6 / NAT66 语义与槽位（只读逆向）

状态：只读静态逆向，**未在设备上验证**。每条结论给出模块 + 函数 + 地址/常量。
标 UNKNOWN 的条目表示当前语料无法确认，**不得作为实现依据**。

---

## 0. 语料、地址约定与一处重要更正

| 项目 | 值 |
|---|---|
| ca-ne.ko | SHA-256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e`，4 381 304 B |
| fc_mgr.ko | SHA-256 `10c4f7f0dc22762de96768e80cb90e7d4203c2b406fccf1197f4fdc2daace479` |

地址换算（两个 .ko 相同，已验证）：

    .text 文件偏移 0x80 → Ghidra/REA 0x100040
    REA_addr = nm_段内偏移(.text) + 0x100040
    文件偏移 = REA_addr − 0xFFFC0     （例：REA 0x272ae8 → file 0x172b28）

### 0.1 更正：NAPT6 相关代码全部在 **ca-ne.ko**，不在 fc_mgr.ko

`phase0-re3-dualhdr-mc-napt6.md` §5.2 写 `convert_act_flow_naptv6_mode @ fc_mgr .text+0x93250`
是**错误归属**。实测：

    nm /mnt/c/rea/fc_mgr.ko | grep -i naptv6      → 无任何符号
    nm /mnt/c/rea/ca-ne.ko  | grep -i naptv6      → 全部命中

ca-ne.ko 内的 NAPT6 符号（nm .text/.bss/.data 段内偏移）：

| 符号 | nm 偏移 | REA | 说明 |
|---|---|---|---|
| `convert_act_flow_naptv6_mode` | .text+0x93250 | **0x193290** | NAPTV6 12-word 打包器 |
| `convert_act_flow_nomal_mode` | .text+0x92d70 | 0x192db0 | 基准（G18+G20）打包器 |
| `aal_hash_action_update` | .text+0x9ac40 | 0x19ac80 | 唯一入口，决定 ACTGRP |
| `dump_HS_ACTGRP_FLOW_NAPTV6_MODE` | .text+0x136fb4 | 0x236ff4 | **字段名权威来源** |
| `aal_hash_actionGrpBitmask_length_get` | .text+0x941a0 | 0x1941e0 | 组→位宽表 |
| `aal_hash_action_mode_get/set` | .text+0x94440 / 0x9d590 | — | 全局模式开关 |
| `hash_flow_naptv6_support_mode` | .bss+0x7418 | — | 1 B 全局开关 |
| `npt6_prefix_addr_table` | .data+0x4258 | — | NPTv6 前缀表描述符 |
| `aal_hash_npt6_prefix_addr_entry_add/del/get` | .text+0x993b0 / 0x99530 / 0x99450 | — | 导出 API |
| `l3_cam_ip_addr_tbl` | .data+0x3b80 | — | CAM IP 地址表描述符 |

fc_mgr.ko 侧只有 **导入**（`nm -u fc_mgr.ko`）：
`aal_hash_action_update`、`aal_hash_actionGrpBitmask_get`、`aal_hash_actionGrpBitmask_length_get`、
`aal_hash_action_mode_get`、`aal_hash_npt6_prefix_addr_entry_add/del/get`。

→ 结论：**策略/表管理在 fc_mgr，action 编码与表原语在 ca-ne**。这与 §0.4 的总体分层一致。

---

## 1. 决定性模型：ACTGRP 是「字段组位掩码」，不是模式枚举

### 1.1 `aal_hash_actionGrpBitmask_length_get`（ca-ne .text+0x941a0）

函数体是一串 `tbz w0,#N` + `add w2,w2,#imm` 的加法，即：

    动作长度(bit) = Σ_{bit N 置位} group_len[N]

实测常量（反汇编硬编码立即数，非推断）：

| group bit | 长度(bit) | hex | 备注 |
|---|---|---|---|
| 0 | 150 | 0x96 | 基准组（名字 UNKNOWN）；**未置位时不计入** |
| 1 | 17 | 0x11 | = 0x272ae8 `<Group 1, L4 Dest Port ID>` |
| 2 | 17 | 0x11 | 名 UNKNOWN |
| 3 | 33 | 0x21 | = 0x272b30 `<Group 3, IP DA lsb32>` |
| 4 | 97 | 0x61 | 名 UNKNOWN（与 G24 同宽，镜像组） |
| 5 | 33 | 0x21 | 名 UNKNOWN |
| 6 | 97 | 0x61 | 名 UNKNOWN |
| 7 | 18 | 0x12 | |
| 8 | 20 | 0x14 | |
| 9 | 45 | 0x2d | |
| 10,11 | 49 | 0x31 | |
| 12..15 | 20 | 0x14 | |
| 16 | 22 | 0x16 | |
| 17 | 43 | 0x2b | |
| 18 | 19 | 0x13 | `0x272410 <Group 18, Dest Port ID>` |
| 19 | 39 | 0x27 | |
| 20 | 205 | 0xcd | `0x2724c8 <Group 20, Indexed>` |
| 21 | 33 | 0x21 | |
| 24 | 97 | 0x61 | `0x272b78 <Group 24, IP addr h 96>` |
| 22,23,25..31 | UNKNOWN（本次未读到） | | |

### 1.2 两个实际使用的组合

`aal_hash_action_update`（REA 0x19ac80）内：

    uVar2 = 0x140000;                                  // 基准
    if (hash_flow_naptv6_support_mode != 0) uVar2 = 0x114000a;

    0x00140000 = group 18 | group 20        → 19 + 205 = 224 bit = 7 word
    0x0114000a = group 1|3|18|20|24         → 17+33+19+205+97 = 371 bit

**224 与 371 都与本报告的独立位推导逐位吻合**（见 §2/§3），因此该「组合加法」模型是
被两条独立证据交叉确认的观测，而非猜测。

含义：
* 基准表（`hash_action_table`）的 action 只有 224 bit（28 B），与开源驱动的
  `rtl_fe_action_fields[]` 完全一致（其最高字段 `RTL_FE_VXLAN_SPORT_UPDATE_EN` = bit 223）。
* 打开 NAPTV6 后，**同一个 action 表的所有条目都改用 371 bit 的 NAPTV6 布局**
  （`aal_hash_action_update` 对 type==0 无条件走 `convert_act_flow_naptv6_mode`），
  并在 SW 影子表里逐条记下 ACTGRP 值（`hash_action_table + idx*0x18 + 0x10`）。
  硬件按 ACTGRP 决定解码布局，故**开关是全局的，不能逐条混用**。

`hash_action_group_check(action, actgrp)`（REA 0x195900）在打包前校验描述符自带的组掩码
与目标表一致；不一致会返回错误并打印
`"%s:%d hash action do not match hash group, action group from hash action: 0x%08x, supposed action group: 0x%08x"`
（ca-ne .rodata.str1.8）。

---

## 2. `RTL_FE_IP_ADDR_NAPT6` 的精确语义

### 2.1 位置（三种表述，全部有证据）

该字段属于 **Group 20**，是 Group 20 的第 60 位（0 基），宽 1 bit：

| 组合 | 全局 bit | word | 同 word 内位 |
|---|---|---|---|
| 基准 G18+G20（ACTGRP 0x140000） | **79** | word2 | bit15 |
| NAPTV6 G1+G3+G18+G20+G24（0x114000a） | **129** | word4 | bit1 |

推导依据两条：
1. `dump_HS_ACTGRP_FLOW_NAPTV6_MODE` 的打印：
   `printk(&DAT_002725c0, word2>>31 & 1, byte12 & 1, (byte)param_1[2]>>1 & 1)`
   对应格式串 `0x2725c0 = "6 ip_addr_vld(1): %d, ip_type(1): %d, ip_addr_napt6(1): %d"`
   → `ip_addr_vld` = bit 95、`ip_type` = bit 96、`ip_addr_napt6` = bit **129**。
2. 两个打包器对同一描述符位的落点一致：
   * 基准：`convert_act_flow_nomal_mode` 写 `word2 |= (u64@0x68 >> 0x38 & 1) << 0xF` → bit79
   * NAPTV6：`convert_act_flow_naptv6_mode` 写 `word4 |= (u64@0x68 >> 0x38 & 1) << 1` → bit129
   两者都是 **描述符 `0x6f` 的 bit0**（`0x68 + 7` 字节，位 0）。

### 2.2 语义：**地址改写解释模式位，不是独立表选择**

证据链：

1. 它紧跟在 32-bit `IP_ADDR` 之后（G20 布局：`ip_addr_vld`=loc26、`ip_type`=loc27、
   `ip_addr`=loc28..59、`ip_addr_napt6`=loc60），不是任何索引/表号字段。
2. NAPTV6 组合里它的置位同时伴随 G1（l4_dp）、G3（ip_da_l_32）、G24（ip_addr_h_96）
   三组的**载荷**存在；基准组合里这三组不存在，32-bit `ip_addr` 单独表达 IPv4 改写。
3. `aal_hash_action_update` 里 ACTGRP 与打包器一一对应，没有第二张「NAPT6 表」被选择；
   ca-ne.ko 的 L3PE 表清单里也没有 NAPT6 专用表（与 RE-3 §5.1 结论一致，但现在有字段级证据）。

因此：`IP_ADDR_NAPT6=1` 表示「该 flow 的地址改写按 NAPT6 语义解释：使用 G1/G3/G24 的
128-bit 地址 + L4 目的端口，而不是 G20 的 32-bit IPv4 地址」。
至于是「源」还是「目的」改写，见 §7（**方向位 UNKNOWN**）。

### 2.3 配合字段（同一 action 内的完整改写三元组）

| 基准 bit | NAPTV6 bit | 字段 | 宽 | 来源（描述符偏移） |
|---|---|---|---|---|
| 45 | 95 | `ip_addr_vld` | 1 | 0x6a bit6 |
| 46 | 96 | `ip_type` | 1 | 0x6a bit7 |
| 47..78 | 97..128 | `ip_addr` | 32 | u32 @ 0x6b（逐字节小端展开） |
| **79** | **129** | **`ip_addr_napt6`** | **1** | **0x6f bit0** |
| 191..206 | 241..256 | `l4_port` | 16 | u16 @ 0x7d |
| — | 0..16 | `l4_dp_vld` / `l4_dp` | 1+16 | 0x12 bit6 / 0x12 bit7+0x13+0x14[0..6] |
| — | 17..49 | `ip_da_l_vld` / `ip_da_l_32` | 1+32 | 0x17 bit0 / 0x17[1..7]+0x18+0x19+0x1a+0x1b bit0 |
| — | 274..370 | `ip_addr_h_96_vld` / `_1/_2/_3` | 1+96 | 0x86 bit6 / 0x86 bit7..0x92 |

`l4_port` 在两组布局里都存在（宽度/位置确定），说明 32-bit 地址 + 16-bit 端口是基准能力；
NAPT6 只是额外提供 96-bit 高地址与 16-bit L4 DP。

---

## 3. 12 段映射：`convert_act_flow_naptv6_mode @ ca-ne .text+0x93250`（REA 0x193290）

函数签名：`void convert_act_flow_naptv6_mode(long desc /*SW hash action entry*/, ulong *words /*48 B*/)`。
逐位 RMW 写入 `words[0..11]`，共 **371 bit**，其余 13 bit 未写（保留旧值）。
下表「源」全部是**描述符字节偏移/位**，由反汇编逐条读出；字段名来自 §1 的 dump 格式串。

### 3.1 word0（bit 0..31）

| 全局 bit | 字段名 | 宽 | 源（desc） |
|---|---|---|---|
| 0 | `l4_dp_vld` | 1 | 0x12 bit6 |
| 1..16 | `l4_dp` | 16 | 0x12 bit7, 0x13[0..7], 0x14[0..6] |
| 17 | `ip_da_l_vld` | 1 | 0x17 bit0 |
| 18..24 | `ip_da_l_32`[0..6] | 7 | 0x17[1..7] |
| 25..31 | `ip_da_l_32`[7..13] | 7 | 0x18[0..6] |

### 3.2 word1（bit 32..63）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 32 | `ip_da_l_32`[14] | 1 | 0x18 bit7 |
| 33..40 | `ip_da_l_32`[15..22] | 8 | 0x19 |
| 41..48 | `ip_da_l_32`[23..30] | 8 | 0x1a |
| 49 | `ip_da_l_32`[31] | 1 | 0x1b bit0 |
| 50 | `mrr_vld` | 1 | 0x60 bit2 |
| 51 | `mrr_en` | 1 | 0x60 bit3 |
| 52 | `no_drop_vld` | 1 | 0x60 bit4 |
| 53 | `no_drop` | 1 | 0x60 bit5 |
| 54 | `dpid_vld` | 1 | 0x60 bit6 |
| 55 | `dpid_pri` | 1 | 0x60 bit7 |
| 56 | `permit` | 1 | 0x61 bit0 |
| 57 | `deepq` | 1 | 0x61 bit1 |
| 58..63 | `mcgid/ldpid`[0..5] | 6 | 0x61[2..7] |

### 3.3 word2（bit 64..95）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 64..67 | `mcgid/ldpid`[6..9] | 4 | 0x62[0..3] |
| 68 | `mc` | 1 | 0x62 bit4 |
| 69 | `mdata_byte_vld` | 1 | 0x67 bit4 |
| 70..72 | `mdata_byte`[0..2] | 3 | 0x67[5..7] |
| 73..77 | `mdata_byte`[3..7] | 5 | 0x68[0..4] |
| 78 | `l3_if_vld` | 1 | 0x68 bit5 |
| 79 | `smac_trans` | 1 | 0x68 bit6 |
| 80..85 | `igr_l3_if_idx` | 6 | 0x68 bit7, 0x69[0..4] |
| 86..91 | `egr_l3_if_idx` | 6 | 0x69[5..7], 0x6a[0..2] |
| 92 | `l3_if_counter_en` | 1 | 0x6a bit3 |
| 93 | `ip_ttl_dec` | 1 | 0x6a bit4 |
| 94 | `ip_ttl_zero_discard_en` | 1 | 0x6a bit5 |
| 95 | `ip_addr_vld` | 1 | 0x6a bit6 |

### 3.4 word3（bit 96..127）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 96 | `ip_type` | 1 | 0x6a bit7 |
| 97..104 | `ip_addr`[0..7] | 8 | 0x6b |
| 105..112 | `ip_addr`[8..15] | 8 | 0x6c |
| 113..120 | `ip_addr`[16..23] | 8 | 0x6d |
| 121..127 | `ip_addr`[24..30] | 7 | 0x6e[0..6] |

### 3.5 word4（bit 128..159）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 128 | `ip_addr`[31] | 1 | 0x6e bit7 |
| **129** | **`ip_addr_napt6`** | 1 | 0x6f bit0 |
| 130 | `mac_da_idx_vld` | 1 | 0x6f bit1 |
| 131..136 | `mac_da_idx`[0..5] | 6 | 0x6f[2..7] |
| 137..143 | `mac_da_idx`[6..12] | 7 | 0x70[0..6] |
| 144..149 | `chk_msk_ptr` | 6 | 0x70 bit7, 0x71[0..4] |
| 150..151 | `cache_ctrl` | 2 | 0x71[5..6] |
| 152 | `pop_l3_vld` | 1 | 0x71 bit7 |
| 153 | `pop_l3_chk_ecn_en` | 1 | 0x72 bit0 |
| 154 | `pop_l3_en` | 1 | 0x72 bit1 |
| 155 | `t2_ctrl_vld` | 1 | 0x72 bit2 |
| 156..159 | `t2_ctrl` | 4 | 0x72[3..6] |

### 3.6 word5（bit 160..191）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 160 | `ldpid_offset_msb` | 1 | 0x72 bit7 |
| 161 | `ip_dscp_update_en` | 1 | 0x73 bit0 |
| 162..167 | `ip_dscp` | 6 | 0x73[1..6] |
| 168 | `cos_update_en` | 1 | 0x73 bit7 |
| 169..171 | `cos` | 3 | 0x74[0..2] |
| 172 | `inner_8021p_update_en` | 1 | 0x74 bit3 |
| 173..175 | `inner_8021p` | 3 | 0x74[4..6] |
| 176 | `top_8021p_update_en` | 1 | 0x74 bit7 |
| 177..179 | `top_8021p` | 3 | 0x75[0..2] |
| 180 | `inner_dei` | 1 | 0x75 bit3 |
| 181..188 | `inner_vid`[0..7] | 8 | 0x75[4..7], 0x76[0..3] |
| 189..191 | `inner_vid`[8..10] | 3 | 0x76[4..6] |

### 3.7 word6（bit 192..223）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 192 | `inner_vid`[11] | 1 | 0x76 bit7 |
| 193..195 | `inner_tpid_enc` | 3 | 0x77[0..2] |
| 196 | `top_dei` | 1 | 0x77 bit3 |
| 197..200 | `top_vid`[0..3] | 4 | 0x77[4..7] |
| 201..208 | `top_vid`[4..11] | 8 | 0x78 |
| 209..211 | `top_tpid_enc` | 3 | 0x79[0..2] |
| 212..213 | `vlan_cnt` | 2 | 0x79[3..4] |
| 214 | `vlan_vld` | 1 | 0x79 bit5 |
| 215 | `pol_vld` | 1 | 0x79 bit6 |
| 216 | `pol_en` | 1 | 0x79 bit7 |
| 217..223 | `pol_id`[0..6] | 7 | 0x7a[0..6] |

### 3.8 word7（bit 224..255）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 224 | `pol_id`[7] | 1 | 0x7a bit7 |
| 225 | `pol2_id_enable` | 1 | 0x7b bit0 |
| 226..231 | `pol2_id` | 6 | 0x7b[1..6] |
| 232 | `pol3_id_enable` | 1 | 0x7b bit7 |
| 233..238 | `pol3_id` | 6 | 0x7c[0..5] |
| 239 | `pppoe_vld` | 1 | 0x7c bit6 |
| 240 | `pppoe_set` | 1 | 0x7c bit7 |
| 241..248 | `l4_port`[0..7] | 8 | 0x7d |
| 249..255 | `l4_port`[8..14] | 7 | 0x7e[0..6] |

### 3.9 word8（bit 256..287）

| 全局 bit | 字段名 | 宽 | 源 |
|---|---|---|---|
| 256 | `l4_port`[15] | 1 | 0x7e bit7 |
| 257 | `ip_mtu_enc_vld` | 1 | 0x7f bit0 |
| 258..261 | `ip_mtu_enc` | 4 | 0x7f[1..4] |
| 262 | `modify_vlan_only_vld` | 1 | 0x7f bit5 |
| 263 | `modify_vlan_only` | 1 | 0x7f bit6 |
| 264 | `six_rd_dip_remap_or_fmr_idx_vld` | 1 | 0x7f bit7 |
| 265..266 | `six_rd_dip_remap_or_fmr_idx` | 2 | 0x80[0..1] |
| 267..272 | `vxlan_sport_msb15` | 6 | 0x80[2..7] |
| 273 | `vxlan_sport_update_en` | 1 | 0x81 bit0 |
| 274 | `ip_addr_h_96_vld` | 1 | 0x86 bit6 |

### 3.10 word8 尾部 ~ word11（bit 274..383）：Group 24 的 96 bit 地址

G24 从 bit274 起 97 bit（1 vld + 96 addr）。三个 32-bit lane 是把 0x86 bit7..0x92 当连续位流按 32/32/32 切开：_1 = 275..306（0x86[7], 0x87, 0x88, 0x89, 0x8a[0..6]）；_2 = 307..338（0x8a[7], 0x8b, 0x8c, 0x8d, 0x8e[0..6]）；_3 = 339..370（0x8e[7], 0x8f, 0x90, 0x91, 0x92[0..6]）。371..383 不写，保持旧值。


### 3.11 打包器与描述符的一致性校验

`convert_act_flow_nomal_mode` 对 G18+G20 的同一批描述符字段给出同样的相对顺序，
只是整体偏移 −50 bit。两个打包器互为交叉验证（同一 desc 位 → 同一语义字段），
这排除了「描述符字段被 NAPTV6 重新解释」的可能。

---

## 4. IPv6 地址 / 前缀的落地方式与槽位

### 4.1 128-bit 地址 = G24(96) + G3(32)，端口 = G1(16)

* `ip_addr_h_96_1/2/3`（96 bit）+ `ip_da_l_32`（32 bit）= **完整 128-bit 地址**，
  三个 32-bit 子字**按位流顺序**链接（不是三个独立字段），已由 §3.10 的位递推确认。
* `l4_dp`（16 bit）+ `l4_dp_vld`：L4 **目的**端口。
* 因此一条 NAPTV6 flow 的改写载荷 = 128-bit 地址 + 16-bit 目的端口，**全部内联在
  48 B action 里**，不需要外部 NAT 表。

### 4.2 `ip_addr`（32 bit）是字面地址，不是表索引

* 字段名就是 `ip_addr`（dump 0x272600 `"6 ip_addr(32): 0x%08x, l4_port(16): 0x%04x"`），
  宽 32 bit 与 IPv4 地址等宽。
* 开源驱动 `rtl_fe_action_build()`（fe_hw.c:140）以
  `RTL_FE_IP_ADDR ← action->address`、`IP_ADDR_VLD ← action->translate`
  `IP_TYPE ← action->translate_destination` 使用它，即字面地址 + 两个方向位。
* 该驱动的 `rtl_fe_action_fields[]` 与 OEM 基准布局**逐位一致**（本报告 §3 全表可对照），
  所以「字面地址」是该字段最可信的解释。**但 OEM 侧无字符串/寄存器文档直接确证，
  标 derived**。

### 4.3 NPTv6 前缀表：`npt6_prefix_addr_table`（ca-ne .data+0x4258）

描述符 168 B，实测 6 个非零 32-bit 字：

| 偏移 | 值 | 与 FMR 表（RE-3 §1.5：table id 33 / 3 entries / 16 words）对照后的推断 |
|---|---|---|
| +0x00 | 68 (0x44) | `table_id` = 68 |
| +0x10 | 16 (0x10) | `entry_count` = **16** |
| +0x1c | 8 (0x08) | 每访问寄存器块字数 / 或每条目字数 |
| +0x24 | 2 (0x02) | 每条目 **2 word = 64 bit** |
| +0xa4 | 36 (0x24) | 未知（寄存器/偏移类） |

**条目格式（有字符串级证据）**：`__npt6_prefix_addr_entry_print`（ca-ne .text+0x170f8）
打印 `"6prefix(64) = 0x%016llx"` 与 `"6index %04d, ref count %d"`，
且 `__npt6_prefix_addr_hw_entry_set`（.text+0x94570）以
`desc[+0x24]`（=2）为字数循环，把条目写入 `desc->base + ((w9 + (words*idx + k)) * 4) & ~0x3`，
随后把打包后的控制字写 `NE+0x3AA4`。
→ 条目 = **64-bit prefix + 控制/引用计数状态**；与 `prefix(64)` 打印吻合。

**容量结论**：NPTv6 前缀表 **16 条**（+0x10 = 16，配合 +0x24 = 2 word/条）。
标注：`entry_count` 的语义是从 FMR 表的同类描述符类比得到，**属 derived**；
一次 `debugfs` dump（`__npt6_prefix_addr_entry_print` 会打印 `index %04d, NOT USED`
遍历上界）即可确认。

**分配/回收顺序**：`aal_hash_npt6_prefix_addr_entry_add`（.text+0x993b0）直接转发
`generic_entry_add(.data+0x4258, ...)`；`generic_entry_add` 在表内线性找首个
`ref_count == 0` 槽（打印串 `"3%s: Out of range! Max is %u, but start_idx is %u."` 只在
越界时出现），`del` 走 `generic_entry_del` 做引用计数递减。**不是环形/位图分配器**。

### 4.4 CAM / SMAC / NAT 槽位

| 槽 | 字段 | 宽 | 结论 |
|---|---|---|---|
| CAM（MAC DA） | `mac_da_idx_vld` + `mac_da_idx` | 1+13 | 8192 条 MAC DA 表项，`l3_cam_mac_da_tbl`（.data+0x36e8）管理；与 NAT 无关 |
| SMAC | `smac_trans` | 1 | **纯使能位，无索引**（源 MAC 转换由 egress L3 IF 侧完成） |
| L3 IF | `igr/egr_l3_if_idx` | 6+6 | 64 个 L3 接口 |
| 掩码 | `chk_msk_ptr` | 6 | 64 条 mask；`aal_hash_action_update` 用 `(mask_id & 0x3f) << 7 | 0x2000` 写入 desc 0x70 |
| NAT 规则 | — | — | **没有独立的 NAT 槽表**；每条 flow 的改写内联在 48 B action 中 |
| IPv6 DIP remap / FMR | `six_rd_dip_remap_or_fmr_idx` | 2 | 4 选 1；FMR 表只有 3 条（table id 33），DIP remap 表条目数 UNKNOWN |

**「多少条 NAT 规则」的正确答案**：NAPT6/NAT66 的容量 = **flow 表容量**，不是 NAT 表容量。
ca-ne 的 `hash_action_table` 每条 48 B；开源头常量 65536 条 + 64 条 overflow + 32 条 default
（`RTL_FE_HASH_ENTRIES` / `RTL_FE_OVERFLOW_ENTRIES` / `RTL_FE_DEFAULT_ENTRIES`）。
OEM 运行时值在 `.data`：`l3fe_main_hash_action_table_entry_count`（+0x1660）、
`l3fe_main_hash_action_table_entry_length`（+0x165c）、`l3fe_main_hash_overflow_hash_fib_*`，
由 profile 在 init 时写入（具体 profile 值 UNKNOWN，需运行期读取）。

---

## 5. `l4sum_rec` 与 NPTv6 校验和中性

* `l4sum_rec` **不在 hash action 里**，它是 **Dual-Header Control 表**（隧道表，table id 32）
  的一个 1-bit 字段：`RTL_FE_DUAL_CTRL_L4SUM_REC_BIT = 17, WIDTH = 1`
  （fe_tunnel.h:159-160，来自 RE-3 §1.4 的 OEM 字段解码）。
* 该字段只在 dual-header/tunnel 改写路径生效（`rtl_fe_dual_control_pack()`，
  fe_tunnel.c:289）。NAPT6 走的是 L3FE hash-action 路径，**不经过 Control 表**。
* 12-word NAPTV6 action 里**没有任何 checksum 控制位**（§3 全表），基准布局也没有。
* 结论：**`l4sum_rec` 不覆盖 NPTv6 的校验和中性调整**。
  NPTv6 是否可用取决于 L3FE 改写级是否「整体重算」L4 校验和：
  静态语料无法证明。→ **UNKNOWN**，必须在设备上做一次 NPTv6 报文实验
  （或用 debugfs 读改写后的包）才能定论。
  参考：开源驱动注释（fe_main.c:721-725）假设「L3 改写级必然重算校验和」，
  但那是 IPv4 场景的推断，不能外推到 NPTv6 的前缀增量语义。

---

## 6. 与现有 `rtl_fe_parse_l3()` IPv6 路径的接入点

### 6.1 现状（fe_main.c:859-1160）

* 接受 `FLOW_DISSECTOR_KEY_IPV6_ADDRS`，但要求 **/128 精确掩码**（972-977）；
* IPv6 只允许 **DSCP mangle**（`FLOW_ACT_MANGLE_HDR_TYPE_IP6` → `rtl_fe_dscp_mangle`，
  该函数要求 `offset == 0` 且 mask ⊆ bit27..22，fe_main.c:739-742）；
* 任何 TCP/UDP 端口 mangle 在 IPv6 上直接拒绝（1098-1101）；
* `source_changed` / `destination_changed` 对 IPv6 被强制为 false（1122-1127），
  即 **当前完全没有 IPv6 地址改写能力**，`data->action.translate` 永远为 0。

### 6.2 需要新增的 flow dissector / action 键

| 需要 | 现状 | W7b 动作 |
|---|---|---|
| `FLOW_DISSECTOR_KEY_IPV6_ADDRS` | 已有 | 直接复用（128-bit 源/目的） |
| `FLOW_DISSECTOR_KEY_PORTS` | 已有 | 直接复用（PAT 端口来源） |
| `FLOW_DISSECTOR_KEY_BASIC`（ip_proto） | 已有 | 复用 |
| `FLOW_ACT_MANGLE_HDR_TYPE_IP6` 的 saddr/daddr | **被拒绝** | 新增：`offset == offsetof(struct ipv6hdr, saddr/daddr) && mask == 0` 时收集 128-bit 新地址 |
| `FLOW_ACTION_CT` + `FLOW_DISSECTOR_KEY_CT`（conntrack NAT 元数据） | **完全没有** | 若要支持 tc `ct nat` offload 必须新增；否则只能吃 pedit 形态的静态 mangle |
| `FLOW_DISSECTOR_KEY_ENC_*` | 一律拒绝（938-939） | 保持拒绝 |

### 6.3 必须拒绝（否则语义错或硬件不表达）

1. `hash_flow_naptv6_support_mode == 0` 时的任何 IPv6 地址改写 —— 基准布局没有
   128-bit 地址字段，写了也无法表达。
2. 非 /128 掩码的 IPv6 地址键（现状已拒）；非精确 L4 端口键（现状已拒）。
3. IPv6 + GRE / ENC_* / 非 TCP/UDP 组合（现状已拒）。
4. IPv6 端口 mangle：**除非**先证明 `l4_dp` 是 PAT 语义（见 §7）。
5. 同一 flow 同时改 IPv6 源与目的：action 里只有一套 `ip_da_l_32`/`ip_addr_h_96`，
   方向位只有一个 `ip_type`，**无法同时表达双向改写**（`source_changed &&
   destination_changed` 现状已拒，继续保持）。
6. 在前缀表未写入的情况下打开 NPTv6（`aal_hash_npt6_prefix_addr_entry_add` 未调用）。

---

## 7. 可实现性分类

### 可实现（有直接证据，可进 W7b）

| 项 | 证据 |
|---|---|
| NAPTV6 action 的 371-bit 打包（纯 bit-pack） | §3 全表，`convert_act_flow_naptv6_mode` 逐位反汇编 |
| ACTGRP 位掩码模型与两种组合 | §1，`aal_hash_actionGrpBitmask_length_get` 立即数 |
| 48 B（12 word）action 安装到 hash action 表 | `aal_hash_action_update` → `aal_entry_add_by_idx(10/0xb, 48B)` |
| 128-bit 地址（96+32）与 16-bit L4 DP 的字段可表达性 | §3/§4.1 |
| 全局模式开关的读写 | `aal_hash_action_mode_get`（导出）/ `aal_hash_action_mode_set` |
| NPT6 前缀表 16 条 + 线性 ref-count 分配 | `aal_hash_npt6_prefix_addr_entry_add` → `generic_entry_add` |

### 只能 raw / debugfs（硬件/表已存在，但无稳定内核接口或语义未定）

| 项 | 原因 |
|---|---|
| `hash_flow_naptv6_support_mode` 全局切换 | 无导出 setter；fc_mgr 只 import `mode_get`。切换会使**整表** action 布局变化，必须与表重建一起做 |
| NPT6 前缀表内容 | 只有 ca-ne 内部 API；prefix 长度/属性语义未解码（条目仅 print `prefix(64)` + ref count） |
| `six_rd_dip_remap_or_fmr_idx` | 2-bit 索引，FMR 表 3 条、DIP remap 条目数 UNKNOWN |

### 不可实现 / 缺证据（禁止写 action 代码）

| 项 | 结论 | 缺什么 |
|---|---|---|
| NPTv6（RFC 6296）校验和中性 | **不可判定** | 无任何 checksum 控制位；需设备实验（§5） |
| 端口 PAT（NAPT6） | **不可判定** | `l4_dp` 名为「L4 Dest Port ID」，但 `l4_dp_vld` + 与 `l4_port` 的关系无证据；dump 未给 PAT 语义 |
| DNAT6 / SNAT6 方向 | **UNKNOWN** | 只有一个 `ip_type` 方向位（基准里它表示 translate_destination）；NAPT6 布局下 `ip_type` 是否复用为方向位无证据 |
| 任意前缀长度（非 /64、非 /128） | **不可表达** | NAPTV6 action 里没有 prefix-length 字段；`mapt_pre_len`/`fmr_pref_len` 属于 dual-header 表，不在 action |
| 每流独立选择 v4/v6 action 布局 | **不可实现** | ACTGRP 由全局开关决定（§1.2） |

---

## 8. UNKNOWN 清单（禁止猜测）

| # | 问题 | 现状 |
|---|---|---|
| U1 | `ip_addr_napt6=1` 时 `ip_addr`(32) 与 `ip_da_l_32`(32) 各自代表什么（SA/DA？which 优先） | 只有字段名，无方向证据 |
| U2 | `ip_type` 在 NAPTV6 组合下是否仍是「目的方向」位 | 无证据 |
| U3 | `l4_dp` 是否 PAT（端口改写）还是仅键匹配端口 | 无证据 |
| U4 | L3FE 改写级是否重算 L4 校验和（决定 NPTv6 可用性） | 需设备实验 |
| U5 | group 0（150 bit）与 group 2/4/5/6/7..17/19/21/22/23/25+ 的字段语义 | 未解码 |
| U6 | `npt6_prefix_addr_table` 描述符 +0x00/+0x10/+0x1c/+0xa4 的精确语义 | 只有类比推断 |
| U7 | OEM 运行时 `hash_action_table_entry_count/length` 的具体值 | 运行期变量 |
| U8 | `six_rd_dip_remap` 表条目数与格式 | 未定位 |
| U9 | 371..373 三位的用途 | dump 不打印 |

---

## 9. W7b 开工所需证据（最小集）

1. **设备上确认 action 表宽度**：读 `l3fe_main_hash_action_table_entry_length`（ca-ne .data+0x165c）
   与 `hash_action_table_entry_length`（.bss+0x746e）；若 < 48 B，NAPT6 无法启用。
2. **确认全局开关的合法设置路径**：`aal_hash_action_mode_set` 的调用者（本语料内未见
   fc_mgr 调用；只有 `mode_get`），以及 `aal_scfg_read` 中对应的配置键名。
3. **一次 debugfs 双 dump**：分别以 `hash_flow_naptv6_support_mode=0/1` 装同一条 IPv4 flow，
   比对 `hash_action_dump`（0x23839c）与 `dump_HS_ACTGRP_FLOW_NAPTV6_MODE`（0x236ff4）
   的输出，确认 371-bit 布局在硬件侧被正确解码（这是唯一能证明 ACTGRP→布局映射的实验）。
4. **NPTv6 校验和实验**：一条 NPTv6 规则 + TCP 报文，抓取改写后报文的 L4 checksum，
   与 RFC 6296 中性值比对；这决定 U4。
5. **确认 `ip_da_l_32` / `ip_addr_h_96` 的方向**：构造仅改高 96 bit、仅改低 32 bit 两条规则，
   看哪一半出现在报文的 DA/SA。
6. `npt6_prefix_addr_table` 的 `ref_count`/`NOT USED` 遍历上界（确认 16 条）。

---

## 10. 附：关键地址/常量速查

    ca-ne.ko
      convert_act_flow_naptv6_mode          .text+0x93250   REA 0x193290
      convert_act_flow_nomal_mode           .text+0x92d70   REA 0x192db0
      aal_hash_action_update                .text+0x9ac40   REA 0x19ac80
      dump_HS_ACTGRP_FLOW_NAPTV6_MODE       .text+0x136fb4  REA 0x236ff4
      aal_hash_actionGrpBitmask_length_get  .text+0x941a0   REA 0x1941e0
      aal_hash_action_mode_get              .text+0x94440
      aal_hash_action_mode_set              .text+0x9d590
      aal_hash_npt6_prefix_addr_entry_add   .text+0x993b0
      __npt6_prefix_addr_hw_entry_set       .text+0x94570   (NE+0x3AA4)
      hash_flow_naptv6_support_mode         .bss+0x7418
      npt6_prefix_addr_table                .data+0x4258
      l3_cam_ip_addr_tbl                    .data+0x3b80
      hash_action_table                     .data+0x45a0
      ACTGRP 基准 0x00140000 / NAPTV6 0x0114000a   （aal_hash_action_update）

    格式串（REA，ca-ne .rodata.str1.8）
      0x272ae8  "<Group 1, L4 Dest Port ID>"
      0x272b08  " l4_dp: 0x%04x, l4_dp_vld: %u"
      0x272b30  "<Group 3, IP DA lsb32>"
      0x272b50  " ip_da_l_32: 0x%08x, ip_da_l_vld: %u"
      0x272410  "<Group 18, Dest Port ID>"
      0x2724c8  "<Group 20, Indexed>"
      0x2725c0  " ip_addr_vld(1): %d, ip_type(1): %d, ip_addr_napt6(1): %d"
      0x272600  " ip_addr(32): 0x%08x, l4_port(16): 0x%04x"
      0x2729c8  " six_rd_dip_remap_or_fmr_idx_vld(1): %d, six_rd_dip_remap_or_fmr_idx(2): %d"
      0x272b78  "<Group 24, IP addr h 96>"
      0x272b98  " ip_addr_h_96_vld(1): %d, ip_addr_h_96_3(32): ... _2 ... _1 ..."