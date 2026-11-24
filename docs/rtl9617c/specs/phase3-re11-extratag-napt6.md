# Phase 3 / RE-11：extra-tag 消费者 + ACL 0x14 + NAPT6 全局模式（只读逆向）

- 语料 `fc_8277c.ko` SHA-256 `a287e7930b4930f552ae6b2b799a0b35050ae166d1dab8da40717aae11653571`（2 091 056 B）
- 语料 `ca-ne.ko`    SHA-256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e`（4 381 304 B）
- 两个哈希实测一致；两个构建仓库只读，`/opt/rea-snap` 未访问。
- 前置阅读：`phase3-re8-extratag.md`（fc_mgr 版 extra-tag 表）、`phase3-re6-napt6.md`（G18/G20 与 NAPTV6 12 段）、`phase3-re7-dualhdr-content.md`（Content/Control/FMR 三表）。
- 状态：**纯静态逆向，未上机验证**。`observed` = objdump 字面量/REA 反编译逐条读出；`derived` = 多条 observed 推出的语义；`UNKNOWN` = 本语料无法确认，禁止在 W7c/W8c 中猜测填充。

> **重要：`fc_8277c.ko` 不是 `fc_mgr.ko` 的同一分支。**
> 结构体、extra-tag 表宽、ACL desc 长度、`aal_l3_cls_add` 的 rule 语义全都变了。
> 本报告所有结论只对 `fc_8277c.ko` 成立；引用 RE-6/RE-7/RE-8 时必须注明是旧语料（fc_mgr）结论。

---

## 0. 地址约定

| 记号 | 含义 |
|---|---|
| `fc+0xNNNN` | `nm -n fc_8277c.ko` 的 `.text` 节内偏移（该节 VMA=0，等于 objdump 地址） |
| `ne+0xNNNN` | `nm -n ca-ne.ko` 的 `.text` 节内偏移 |
| `REA` | 上述偏移 `+ 0x100040`（两模块通用，本次已用 REA 打开两者验证） |
| `fc_db+0xNNNN` | 驱动侧 `.bss` 数据库（**主机内存**，非 NE 寄存器） |
| `netif_rec(n)` | `fc_db + 0x806000 + n*0x228`（**stride 0x228**，旧语料是 0x168/0x942FB8；本语料已换布局） |
| `NE+0xNNNN` | ca-ne 内部寄存器窗口（`g_ne_reg_iobase`，本机为 `0xf4300000` 段） |

`fc_db` 基址由 `adrp fc_db` 取；`.bss` 总大小见 `readelf -S`（本语料未展开，不影响本文结论）。

---

## 1. 结论速览

1. **`rtk_fc_egress_extratagDecision`（fc+0x97C70）本身不消费 extra-tag 表**，它是"按 netif 的 dualType 分派到哪个 `*_by_egrPktHdr` 安装函数"的决策器；每个安装函数**同时**做两件事：
   - 用 `RTK_RG_ASIC_EXTRATAGACTION_ADD` 写**驱动侧软件动作程序**（9 word/条，`fc_db+0x927E8+idx*36`）；
   - 用 `aal_pe_dual_content_entry_add`（表 31）+ `_rtk_fc_dualHeader_ctrl_setup*`（表 32）写**硬件双头表**，再 `rtk_fc_flow_add` 装 flow。
2. **真正的 extra-tag 消费者是软件路径**：`rtk_fc_outerHdr_insert`（fc+0x92DD0）/`rtk_fc_outerHdr_remove`（fc+0x94140），其循环体就是被内联的 `_rtk_fc_applyExtraTagAction`（函数名见 assert 字符串）。调用链：
   `_rtk_fc_ingress_flowLearning → _rtk_fc_shortCutCheck → rtk_fc_outerHdr_{remove,insert}`。
   即：**extra-tag 表是"流学习/短路路径"的软件参考实现**，不是 ASIC 表；ADD 不写任何 NE 寄存器、不调任何 `aal_*`。
3. **ACL 保留规则类型 0x14 = `DUAL_HEADER_DS_CHECK`**（本语料枚举名为 `RTK_8277C_CLS_TYPE_DUAL_HEADER_DS_CHECK`）；
   `_rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc)` 的 **desc 是 0x30 B（不是旧语料的 0x38 B）**，输出索引在 **desc+0x28**；
   `desc[0]` 子类型 0..8，DS-Lite 用 **4/5**、6RD 用 **6**、PPTP=3、L2TP=0、MAPT=7/8。
4. **`aal_l3_cls_add(dev, type, key, rule)` 的第 4 个参数是「输出」而不是输入**（本语料 ca-ne `ne+0x87060`）：
   它返回 32-bit `{key_type[31:28], fib_mode[26:24], dev[23:20], key_tbl[19:4], key_idx[3:0]}`；
   `type` 只允许 0/1（**不是 0x14**）。0x14 只是 `_rtk_fc_g3_caAalClsRuleAdd` 的第 4 参（RSV_ACL 名字/引用槽提示）。
5. **NAPT6 全局开关存在且可写**：`aal_hash_action_mode_set(mode)` 把 `hash_flow_naptv6_support_mode` 置 `(mode==1)`，
   并把主 action 表与 overflow action 的宽度设为 **0x180 bit = 48 B**（mode=1）/ **0x100 bit = 32 B**（mode=0）。
   `0x180` 是 AAL 明确支持的宽度（`aal_hash_hash_overflowAction_size_set` 接受 0x40/0x80/0x100/0x180），
   **48 B entry 可行**（371 bit 布局 + 13 bit 余量）。
6. **但本语料内没有 mode_set 的调用者**：ca-ne 只有 `__ksymtab` 导出；fc_8277c/fc_mgr/ca-rtk/cli-drv/ca-plat-kernel 都**没有导入** `aal_hash_action_mode_set`（只有 `mode_get`）。
   → 全局切换在现有闭源集合里是"导出但无人调用"的能力，**W7c 不能靠改配置键打开**（配置键 "516" 只用于 hash bucket size，不选模式）。
7. W8c/W7c 可行性见 §6：**W8c 可做到"软件动作程序 + 软件封装路径 + 编码库/自测"，硬件 offload 封装仍只能靠 Content/Control 三表**；
   **W7c 只能做到"按 371-bit 布局打包 + 48 B 表项安装"，全局模式必须在设备上用 OEM 私有路径打开并验证**。

---

## 2. 问题 1：extra-tag 表在 fc_8277c 中的形态与消费者

### 2.1 驱动侧表的实际布局（`observed`）

```
fc_db + 0x925FE4   16 × 36 B  header 数组        [0x925FE4, 0x926224)
   +idx*36 +0x00  u8  vld            (写 acttype==1 字时置 1)
   +idx*36 +0x01  u8  content_ofs    (type1 字 bits[12:3] 的低 8 bit；10 bit 被截成 8 bit!)
   +idx*36 +0x02  u8  content_len    (type1 字 bits[20:13])
fc_db + 0x926224   16 × 64 B  content 区         [0x926224, 0x926624)
fc_db + 0x927E8    16 × 36 B  action 数组 (9 word/条)   [0x927E8, 0x92A28)
   +idx*36 +sub*4 (sub=0..8)  u32 动作字
```

证据（`RTK_RG_ASIC_EXTRATAGACTION_ADD` fc+0x85E00，`observed`）：

```
mov  x4, #0x97FA ; movk x4, #0x24, lsl #16     -> 0x2497FA（fc_db 的 word 索引）
add  x1, x4, w1                                -> + sub
mov  w4, #9                                    -> 每条 9 word = 36 B
umaddl x4, w0, w4, x1                          -> 0x2497FA + idx*9 + sub
str  w1, [x3, x4, lsl #2]                      -> fc_db + 0x927E8 + idx*36 + sub*4
if ((w & 0xE0000000) == 0x20000000) {          -> acttype==1
   x0 = fc_db + idx*0x24 + 0x925000
   strb 1,               [x0,#4068]            -> +0x925FE4+idx*36  vld
   strb (w>>3)&0x3FF,    [x0,#4069]            -> +1  ofs（截断为 u8）
   strb (w>>13)&0xFF,    [x0,#4070]            -> +2  len
}
return 0;
```

要点与旧语料（fc_mgr，10 word/40 B）的差异：

| 项 | fc_mgr（RE-8） | **fc_8277c（本报告）** |
|---|---|---|
| action 条宽 | 10 word = 40 B | **9 word = 36 B**（reader 只跑 8 条） |
| action 表基址 | `fc_db+0xBE3664` | **`fc_db+0x927E8`** |
| header 数组 | 与 action 同条目的前 8 B | **独立数组** `fc_db+0x925FE4`，同 stride 36 B |
| content 基址 | `fc_db+0xBE38E4` | **`fc_db+0x926224`** |
| idx 上界检查 | `cmp w0,#0xf; b.hi` → 返回 0x10005 | **无检查**（w0 原样参与寻址） |

`RTK_RG_ASIC_EXTRATAGACTION_DEL`（fc+0x85E80）只把 `[0x927E8+idx*36+sub*4]` 清 0；
`..._GET`（fc+0x85EC0）同样只读一个 word；`..._CONTENTBUFFER_SET`（fc+0x85F00）按 header 的 ofs/len 拷到 `0x926224+ofs`；
`..._CONTENTBUFFER_GET`（fc+0x85F50）的第一个参数是 **content 区字节偏移**（base 0x926224）。
`dump_extratag_table`（fc+0x1DD20）循环 **16 条 × 8 word**（`cmp w19,#8`；遇 `w & 0xE0000000 == 0` 提前退出），
然后按 `ofs = 0,0x40,…` 打印 16 × 64 B content —— 与上面的布局完全自洽。

`_rtk_fc_extraTagActionList_empty_find.part.0`（fc+0x8E0A0）**仍然恒返回 -1**（两个返回点都是 `mov w0,#0xffffffff`），
所以 netif ≥ 32（`slot = netif-0x10 > 0xF`）时 DS-Lite/6RD/PPTP/L2TP 建立仍然失败。

### 2.2 动作字编码（`observed`，与 RE-8 §3 同构）

`bits[31:29] = acttype`，`bits[28:0]` 按类型解释；全 0 字 = 终止符。

| acttype | 语义（dump 格式串） | 位域 |
|---|---|---|
| 1 | `inserttag bufoff/len` | `[12:3]`=bufoff(10) `[20:13]`=len(8) |
| 2 | `ethtran ethertype` | `[28:13]`=ethertype(16) |
| 3 | `updatelen pktoff/width/value/op` | `[28:21]`=pktoff `[20:13]`=width `[12:4]`=value `[3:2]`=op |
| 4 | `ipv4id` / `greseqack` | `[28:21]`=pktoff `[20:15]`=intfidx `bit11`=子类型 `bit13`=reduceseq `bit12`=reduceack |
| 5 | `l3chksum pktoff` | `[28:21]`=pktoff |
| 6 | `l4chksum pktoff` | `[28:21]`=pktoff |
| 7 | `outer_tag_len / udp_off / ppp_off / is_l2dual / is_v6 / ip_off` | 见 RE-8 §3.2（本语料 dump 同样解码） |

**新证据（acttype 4 的真实执行）**：`rtk_fc_outerHdr_insert` 内 acttype 4 分支：
`rtk_fc_dualHdrInfo_get(1, intfidx, &val)` → 取 GRE seq（`小端交换` 写入）+ `rtk_fc_dualHdrInfo_get(2, …)` → 取 IPv4 ID，
与 RE-8 的 `U7/U10` 部分吻合：**`rtk_fc_dualHdrInfo_get` 的第一个参数 1=GRE seq/ack，2=IPv4 ID**（`derived`，两处调用点一致）。

### 2.3 `rtk_fc_egress_extratagDecision`（fc+0x97C70）到底做什么

原型（实测寄存器用法）：`int rtk_fc_egress_extratagDecision(void *priv, u32 netif, u32 *out_dualType)`

```
rec = fc_db + 0x806000 + netif*0x228
if (rec[0x2C] == 0) return 0x10008;            // 该 netif 未配置双头
if (rec[0x0E] != 0) *out = rec[0x0E];           // 已经有 extratag_idx → 直接回填
if (priv[184] != rec[0x14]) { ... _rtk_fc_lut_find(priv[0]) ... }
switch (rec[0x14]) {                            // dualType
  case 1:  _rtk_fc_flow_setupDSLITE_by_egrPktHdr(priv, netif, lut_off);
  case 2:  _rtk_fc_flow_setupPPTP_by_egrPktHdr(...);
  case 3:  _rtk_fc_flow_setupL2TP_by_egrPktHdr(...);
  case 7:  _rtk_fc_flow_setup6RD_by_egrPktHdr(...);
  case 5:  /* VXLAN：在函数体内展开，复制外层头、算 hash、装 flow */
}
```
（`rec[0x0E]` = extratag_idx，`rec[0x14]` = dualType，`rec[0x2C]` = 已配置标志；由 §2.4 的安装函数写入同一组偏移反推。）

→ **它不读也不写 `0x927E8/0x925FE4/0x926224`**，只做分派。它的调用者是 `rtk_fc_egress_pathDecision`（fc+0xF408 段内，调用点 fc+0xFF7C）。

### 2.4 安装函数（`*_by_egrPktHdr`）实际写什么

以 `_rtk_fc_flow_setupDSLITE_by_egrPktHdr`（fc+0x8FA40）为例（`observed`，调用序列逐步）：

```
slot = netif - 0x10; if (slot > 0xF) slot = empty_find();   // 恒 -1
ADD(slot, 0, 0x20050000 | slot<<9);        // inserttag(bufoff=slot*64, len=40)
ADD(slot, 1, 0x50DBA000);                  // ethertype 0x86DD
ADD(slot, 2, 0x60804000);                  // updatelen(pktoff=4, width=2, value=0, op=0)
ADD(slot, 3, 0);                           // 终止符
CONTENTBUFFER_SET(slot, ipv6_hdr40);       // 0x60 / 0xffff0400 / src16 / dst16
aal_pe_dual_content_entry_add(slot, ipv6_hdr40);        // ★ 硬件表 31
_rtk_fc_dualHeader_ctrl_setupDsliteMape(slot, priv);    // ★ 硬件表 32
_rg_flowHashIPv6DstAddr_get(priv+0x28) / SrcAddr_get(priv+0x40) -> priv[136]/priv[140]
_rtk_fc_g3IgrExtraInfo_init(&ignored)
_rtk_fc_flow_hashIndex(...) -> hash
rtk_fc_flow_add(...)                       // ★ 装 flow（含 hash action）
netif_rec[0x0E] = slot                     // extratag_idx
per-hash 记录 [fc_db+0x200180+hash*64 + 0x0E] = (priv[0x148]==2)
```

（`ADD` 的 4 个 word 与 RE-8 §3.3 的 DS-Lite 常量**逐字相同**，说明动作程序编码跨构建稳定；变的是表位置/条宽。）

6RD 路径 `_rtk_fc_flow_setup6RD_by_egrPktHdr`（fc+0x97450）同构：
`0x20028000|slot<<9`、`0x41000000`、`0x60404140`、`0x80800800|(netif&0x3F)<<15`、`CONTENTBUFFER_SET(全 0)`、`aal_pe_dual_content_entry_add`、`_rtk_fc_dualHeader_ctrl_setup6RD`。

**结论（`observed`）**：extra-tag 表与硬件三表在同一函数里被**并列**写入，硬件路径只认 Content(31)/Control(32)/FMR(33)；
extra-tag 表不参与 ASIC 编程（ADD 内无 `aal_*`、无 NE 写、无 `fc_db` 物理地址下发）。

### 2.5 消费者：`rtk_fc_outerHdr_insert` / `_remove`（**本报告最关键的更正**）

```
rtk_fc_outerHdr_insert(fc+0x92DD0)   ← _rtk_fc_shortCutCheck+0x34C   ← _rtk_fc_ingress_flowLearning+0x1B0
rtk_fc_outerHdr_remove(fc+0x94140)   ← _rtk_fc_shortCutCheck+0x2C0   ← 同上
```

`rtk_fc_outerHdr_insert` 的取表代码（`observed`）：

```
w4 = []x2]                     // x2 = 指向 flow key 的指针
netif = (w4 >> 19) & 0x1F      // rec = fc_db + 0x806000 + netif*0x228
slot  = (w4 >> 15) & 0x0F
hdr   = fc_db + 0x925FE4 + slot*36
len   = hdr[+2]                // content length
for (k = 0; k < 8; k++) {
    w = *(u32*)(fc_db + 0x927E8 + slot*36 + k*4);      // = (0x2497FA + slot*9 + k)
    if ((w & 0xE0000000) == 0) break;                  // 终止符
    switch (w >> 29) { /* 1..7 按 §2.2 执行 */ }
}
```

动作执行的真实语义（`observed`，反编译 + 反汇编双重确认，函数名 `_rtk_fc_applyExtraTagAction` 见 assert 串）：

| acttype | 软件动作 |
|---|---|
| 1 | `skb_cow_head` 后在 `bufoff`（=content 区 offset，实际是 `slot*64`）处 `memcpy(len)` 插入；同时更新 `priv[0x38]`/`priv[0x60]` 的指针与长度 |
| 2 | 改外层 ethertype（`[28:13]`） |
| 3 | 在 `pktoff` 处按 `width` 写 `原长度 ± value`（`op` 位决定加/减；本语料只见 op=0 的加） |
| 4 | `bit11=1`：`rtk_fc_dualHdrInfo_get(2,intfidx)` → IPv4 ID；`bit11=0`：`dualHdrInfo_get(1,intfidx)` → GRE seq/ack（带 reduce 位） |
| 5 | 注释/调试打印 IP checksum 位置（不做重算，`derived`：本语料只看到打印 `actionbit 5 - ip checksum 0x%x`） |
| 6 | L4 checksum 位置（同上，只打印；且仅当 `ip_proto==0x11` 才继续） |
| 7 | 外层 tag/udp/ppp/ip 偏移（供后续定位，不直接改包） |

> `acttype 5/6` 在本语料里**只有调试打印**，没有看到真正重算校验和的代码路径 →
> **"软件路径是否重算 L3/L4 checksum"= UNKNOWN**（这正是 NPTv6 校验和中性争议的同一类问题）。

### 2.6 与 `RTK_RG_ASIC_EXTRATAGACTION_ADD` 的关系（一句话）

- `ADD/DEL/GET/CONTENTBUFFER_SET/GET` = 这张**软件动作程序**的写/读 API（fc_db 内的 9-word 指令 + 64 B 常量池）。
- **硬件路径 = `aal_pe_dual_content_entry_add`(表 31) + `_rtk_fc_dualHeader_ctrl_setup*`(表 32) + `rtk_fc_flow_add`（flow/hash action）**；
- **软件路径 = `rtk_fc_outerHdr_insert/remove` 解释执行同一张动作表**（在 `_rtk_fc_shortCutCheck` 里，针对未命中硬件 offload 的包）。
- 两者**没有交叉引用**：hash action（G18/G20）里也没有 extra-tag 索引（RE-6 全字段表 + 本语料 `rtk_fc_flow_add` 的入参结构一致）。

---

## 3. 问题 2：ACL 保留规则 0x14（DS-Lite / 6RD）

### 3.1 类型空间与名字（`observed`）

`fc+0xf3cf8` 的字符串表顺序：`RESET_L2_L3_CLS`、`L2_INGRESS_FORWARD_L3FE`、`L2_EGRESS_FORWARD_L3FE`、**`DUAL_HEADER_DS_CHECK`**、`RESERVED_SPECIAL_END`；
调试串里直接出现 `RTK_8277C_CLS_TYPE_DUAL_HEADER_DS_CHECK`（`fc+0xf2808`）与
`_rtk_rg_aclAndCfReservedRuleDelSpecial(RTK_8277C_CLS_TYPE_DUAL_HEADER_DS_CHECK, &pNetif->dualHdr_ds_clsIdx)`。
`AddSpecial` 的分派链上界是 `cmp w26,#0x14` → **0x14 合法且是最后一个特殊类型**。

`AddSpecial` 的 0x14 调用者（`objdump` 全量，`observed`）：

| 调用点 | 函数 | 子类型 |
|---|---|---|
| fc+0x8D2DC | `_rtk_fc_flow_updatePPTP_by_igrPktHdr` | 3 |
| fc+0x8D774 | `_rtk_fc_flow_updateL2TP_by_igrPktHdr` | 0 |
| fc+0x8DB00 | `_rtk_fc_flow_updateDSLITE_by_igrPktHdr` | **5 / 4**（DS-Lite / MAPE 分支） |
| fc+0x8E1EC | `rtk_fc_8277C_v6rd_downStream_reservedACL_add` | **6** |
| fc+0x91FBC / 0x92080 | `rtk_fc_mapt_accelerate` | **7 / 8** |
| fc+0xBF160 | `_rtk_fc_vxlan_8277C_downStream_reservedACL_add` | 5 |

### 3.2 desc 格式（`observed`，**0x30 B，输出在 +0x28**）

`_rtk_rg_aclAndCfReservedRuleAddSpecial(fc+0xA1F00)` 的 0x14 分支（fc+0xA2198）：

```
if (desc == NULL) return error;
q0 = ((u64*)desc)[0]; q1 = [1]; q2 = [2]; q3 = [3]; q4 = [4]; q5 = (u32)[5];
if ((u32)q0 > 8) { error/trace; }        // 子类型 0..8
```

即 **AddSpecial 只读 desc 的前 0x30 字节（6 个 u64）**，最后只用 `[5]` 的低 32 bit。
`subtype = desc[+0x00]`；子类型分派在 fc+0xA4004。

| 偏移 | 宽 | 含义 | 证据 |
|---|---|---|---|
| +0x00 | u32 | **子类型**（0=L2TP、3=PPTP、4=MAPE/DS-Lite-v2、5=DS-Lite、6=6RD、7/8=MAP-T） | 各 builder 写 `sub` |
| +0x04 | u32 | 0（保留） | builder 显式写 0 |
| +0x08 | u8 | **`aal_l3_cls_add` 的 type（0/1）**；builder 一律写 0 | 分派体 `ldrb w0,[desc+0x08]` → `_rtk_fc_g3_caAalClsRuleAdd` 第 1 参 |
| +0x09 | u8 | **intf mapping 索引**（6 bit），来自 `_rtk_fc_flow_intf_mapping_idx_get(netif)` | 6RD builder `strb w3,[sp,#69]`；分派体 `ubfiz w4,w4,#6,#6` |
| +0x0C..+0x1B | 16 B | 外层 IP 地址（4 × u32，**字节序反转**后展开） | 6RD 只填 8 B（`*(u64*)(priv+0x24)`）；DS-Lite 填满 16 B |
| +0x1C | u32 | 标志位（DS-Lite：bit0/1 来自 `priv+8`，bit14 来自 `priv+0x10`，bit2..13/15..26 来自 `priv+0x128`） | `_rtk_fc_flow_updateDSLITE_by_igrPktHdr` |
| +0x20..+0x27 | — | 0（builder 显式清） | 两个 builder 都 `stur xzr` |
| +0x28 | u32 | **输出**：AddSpecial 分配到的 ACL 规则索引 | 6RD builder 调用后 `ldr w2,[sp,#100]`（=desc+0x28）并写回 `*param_3` |

`_rtk_fc_flow_updateDSLITE_by_igrPktHdr`（fc+0x8D990）的 desc 组装（`observed`，反汇编）：

```
desc = sp+0x5C
desc[0x00] = 5 or 4
desc[0x04] = 0
desc[0x08] = 0
desc[0x09] = _rtk_fc_flow_intf_mapping_idx_get(netif)
desc[0x0C..0x1B] = bswap32(priv[0x08/0x0C/0x10/0x14])      // sub=5
                   或 bswap32(priv[0x18/0x1C/0x20/0x24])   // sub=4 (MAPE)
desc[0x1C] = flags（见上表）
desc[0x20] = 0
desc[0x28] = 0
_rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc)
netif/path6 表 [(&DAT_00a03fdc)[l3_if_idx*0x8a]] = desc[0x28]
_rtk_fc_g3IgrExtraInfo_init(desc)
flow_key |= 0x80001 ; flow_key[6] |= 0x10000000
RTK_RG_ASIC_FLOWPATH_SET(...)
```

`rtk_fc_8277C_v6rd_downStream_reservedACL_add(fc+0x8E190)`（`observed`）：

```
desc = sp+0x3C（先清到 0x5C）
desc[0x00] = 6
desc[0x09] = param_1                        // intf idx
desc[0x0C..0x13] = *(u64*)(param_2 + 0x24)  // 只填 8 B
desc[0x28] = 0
_rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc) → *param_3 = desc[0x28]
```

> **订正 RE-8**：旧语料 desc 是 0x38 B、输出在 +0x34；本语料 **0x30 B、输出在 +0x28**，且 +0x08 有明确语义（aal type）。
> 若要在 mainline 复刻，必须用本语料的 0x30 布局。

### 3.3 `_rtk_fc_g3_caAalClsRuleAdd` 与 `aal_l3_cls_add` 的真实签名（`observed`）

`_rtk_fc_g3_caAalClsRuleAdd`（fc+0x9D710）反汇编头：

```
w22 = w0        // type
x20 = x1        // key
x23 = x2        // rule
w24 = w3        // ref hint
_rtk_fc_g3_caAalClsAssignRuleRefIdx(key=x20, hint=w24, name=sp+0xD8, 16)
aal_l3_cls_add(0, w22, x20, x23)          // dev=0, type, key, rule
```

`aal_l3_cls_add`（ca-ne `ne+0x87060`，REA 0x1870A0）关键逻辑（`observed`）：

```
if (type > 1) return -9;                  // ★ type ∈ {0,1}，不是 0x14
if (!key || !rule) return -8;
if (key[0] > 0x0F) return -9;             // key word0 = key type (0..15)
if (key[1] > 0x03) return -9;             // key word1 = 0..3（key 子模式/长度档）
fib_mode = __l3_cls_fib_mode(key+0x89, &c8);
key_type = __l3_cls_key_type(key+2, c8, &cc);
... 分配 key 表槽（每个 key 占 1..2 个 HW entry，取决于 key_type） ...
__l3_cls_key_entry_update(key, key_type, key_idx, &hw_key);     // 生成 HW key（≈0x40 B）
__l3_cls_fib_entry_update(key+0x89, fib_mode, &fib);            // ★ 动作块来自 key+0x89
...
*rule = (c8 << 24) | (cc << 28) | key_idx | (key_tbl_idx << 4) | (dev << 20);
```

**因此**：

- **key**（≥ 0x89 B 的头部+匹配区，另有 +0x89 起的 FIB 块）= 头部 `{+0x00 key_type(≤0xF), +0x04 子模式(≤3), +0x08.. 匹配模式字}` + **`+0x89` 起的 FIB 动作块**（`__l3_cls_fib_entry_update` 的输入）。
  `aal_l3_cls_key_clean`（ca-ne `ne+0x82430`）把 `+0x00/+0x08/+0x20..+0x78` 部分填 `0xFF`、`+0x21=0xFC01`、`+0x33=0xC01F`、并把 `+0x23/+0x2B/+0x35/+0x3D` 等清 0 —— 这是"未指定字段 = don't care"的编码。
- **rule**（4 B）= **输出**：`{key_type[31:28], fib_mode[26:24], dev[23:20], key_tbl_idx[19:4], key_idx[3:0]}`。
  **不是**调用者提供的动作字。所谓 `aal_l3_cls_add(0, 0x14, key, rule)` 的 "0x14" 在本语料里**不存在**：
  第 2 参是 `desc+0x08`（builder 恒写 0），0x14 是 `_rtk_fc_g3_caAalClsRuleAdd` 的**第 4 参 ref hint**。
- `_rtk_fc_g3_caAalClsRuleAdd` 在 `aal_l3_cls_add` 失败时会把 `{vld, hint, key[0], rule[0], type, …}` 记进
  **SW 影子表 `fc_db+0x9587C8`（0x200 × 0x28 B）**，供后续 reflash；这也是"ACL 规则能被重放"的唯一 SW 记录。

### 3.4 DS-Lite / 6RD 真正生效还缺什么（`derived`）

按本语料的调用序列，一次完整的封装/解封装需要**四件套同时成立**：

1. **extra-tag 动作程序**（`fc_db+0x927E8+slot*36`，4 个字）+ content buffer → 供**软件路径**（`rtk_fc_outerHdr_insert`）使用；
2. **硬件 Content(31)/Control(32)**（+MAP-T 的 FMR(33)）→ 供**硬件 offload 路径**使用；
3. **ACL 保留规则 0x14**（subtype 4/5/6）→ 让"外层头匹配"的包进入双头处理/DS 检查；
   其中 key 的 `fib_mode/fib action`（key+0x89）与 `key[0]` 类型字段才是"命中后做什么"的载体，
   不是由 rule 传入 —— **这就是 RE-8 里 U3 的真正答案：rule 不是动作，acl 的 action 在 key 的 FIB 块里**；
4. **flow path 条目**：`RTK_RG_ASIC_FLOWPATH_SET` + `flow_key |= 0x80001`（bit0 + bit19? 见下）+ `flow_key[6] |= 0x10000000`；
   以及 per-netif `path6Idx`（`(&DAT_003fdf18)[netif*8]`）与 `dualHdr_ds_clsIdx` 的保存。

**仍缺（UNKNOWN，禁止猜）**：
- key 的 `+0x08` 起"匹配模式字"逐位语义（本语料只见 builder 写若干 word，未见字段名）；
- `key+0x89` 的 FIB 动作块格式（permit/trap/redirect 的位域）；
- `0x80001` / `0x10000000` 在 flow key 中的字段名（按 `dump_flow_p5Rawdata` 的打印，bit0 是 `vld`，
  `param_3[6]>>0x1c` 一带是 `mt/exTag` 相关，但未逐位对上）；
- DS-Lite 的 `desc+0x0C..0x1B` 到底是"外层 IPv6 源/目的"还是"内层地址"（与 Content 同源但用途未证）。

---

## 4. 问题 3：NAPT6 全局模式与 48 B 表宽

### 4.1 `aal_hash_action_mode_set`（ca-ne `ne+0x9D590`，REA 0x19D5D0）

反编译（`observed`）：

```c
int aal_hash_action_mode_set(dev, int mode)
{
    hash_flow_naptv6_support_mode = (mode == 1);
    u32 action_bits = (mode == 1) ? 0x180 : 0x100;      // 384 / 256 bit
    u32 bucket = 0;
    if (aal_scfg_read("516", 1, &bucket) != 0) {        // 配置键 "516"
        printk("Hash bucket size from scfg file is WRONG value %d\n", bucket);
        bucket = 8;
    }
    ret = aal_hash_hash_table_size_set(hash_table_entry_count, bucket, action_bits);
    if (!ret) ret = aal_hash_cache_init(hash_cache_fib_count);
    if (!ret) ret = aal_hash_hash_overflowAction_size_set(action_bits);
    return ret;
}
```

`aal_hash_hash_table_size_set`（ca-ne `.text.unlikely+0x16D40`）的参数语义（`observed`）：

| 参数 | 合法值 | 去向 |
|---|---|---|
| w0 `entry_count` | {0x200,0x400,0x800,0x1000,0x2000,0x4000,0x8000,**0x10000**} | `NE+0x3834` bits[4:2]（3-bit 深度编码） |
| w1 `bucket_size` | {4, 8, 0x10, 0x20}（默认 **8**，来自 scfg "516"） | `NE+0x3834` bits[1:0] |
| w2 `action_bits` | **0x100 / 0x180** | action 宽度（主表 + overflow） |

→ `mode_set` 的实参 = `(65536, 8, 0x180)`；0x10000 正好是允许集的上界，0x180 是允许的 action 宽度。
`0x180` 是**位宽**而不是字节数（与 ACTGRP 371 bit 同一单位，384 ≥ 371）。
**48 B entry 可行 = 由这条调用链直接证明，不需要推断。**

证据：
- 配置键字符串 `fc`/`ne` 的 `.rodata.str1.8` 偏移 0x1f4b0 = **`"516"`**（REA 0x2755E0 读回 `35 31 36 00`）；
  错误串 `"Hash bucket size from scfg file is WRONG value %d"` 紧随其后。
- `aal_hash_hash_overflowAction_size_set`（ne+0x94FF0）接受 **0x40 / 0x80 / 0x100 / 0x180** 四档，
  0x180 分支把 3-bit 编码写 `NE+0x3848`，并缓存到 `.data+0x41AC` → **0x180 是硬件合法 action 宽度**。
- `hash_flow_naptv6_support_mode` 位于 `.bss+0x7418`（`aal_hash_action_mode_get` ne+0x94440 读，
  `aal_hash_action_update` ne+0x9AC40 读；**唯一写者是 mode_set**）。

### 4.2 无人调用（决定性否定）

| 检查 | 结果 |
|---|---|
| `ca-ne.ko` 内部 `bl aal_hash_action_mode_set` | **0 处**（`get_call_graph` backward 只返回自身节点） |
| `__ksymtab` | `aal_hash_action_mode_set` / `mode_get` 都导出 |
| `fc_8277c.ko` 导入 | 只有 `aal_hash_action_mode_get`（`nm -u`） |
| `fc_mgr.ko` / `ca-rtk.ko` / `cli-drv.ko` / `ca-plat-kernel.ko` 导入 | **均无 `mode_set`**（`nm -u` 实测有效：ca-rtk 331 条、cli-drv 1494 条未定义符号，`grep -c hash_action` 均为 0） |

→ **开关路径 = 只有导出的 API**；没有 UCI/CLI/proc 包装，也没有默认调用。
`fc_8277c` 只在 `aal_hash_action_update` 里读它来决定 ACTGRP，所以"打开 NAPTV6"必须由外部模块/调试接口调用 mode_set，
而这在现有闭源集合里不存在 → **W7c 的全局切换必须有设备侧手段**（见 §6.2）。

### 4.3 ACTGRP 与位宽（`observed`，比 RE-6 更完整）

`aal_hash_actionGrpBitmask_length_get`（ne+0x941A0）逐位加法表（本次补全到 G22/G24）：

| group | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12..15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25..31 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| len(bit) | 0x96 | 0x11 | 0x11 | 0x21 | 0x61 | 0x21 | 0x61 | 0x12 | 0x14 | 0x2D | 0x31 | 0x31 | 0x14 | 0x16 | 0x2B | 0x13 | 0x27 | 0xCD | 0x21 | 0x0C | — | 0x61 | — |

- `0x00140000` = G18+G20 = 19+205 = **224 bit**（基准，7 word）
- `0x0114000A` = G1+G3+G18+G20+G24 = 17+33+19+205+97 = **371 bit**（NAPTV6）
- 384 bit（0x180）= 371 + 13 bit 余量 → **48 B 表项刚好装下**

### 4.4 表宽/容量：默认值 vs 运行期值（`observed`）

`ca-ne.ko` `.data` 初始化值（objdump -s 直接读出）：

| 符号 | 偏移 | 初值 | 含义 |
|---|---|---|---|
| `l3fe_main_hash_action_table_entry_length` | `.data+0x165C` | **0x20 = 32 B** | 默认每条 action 32 B（224 bit 基准） |
| `l3fe_main_hash_action_table_entry_count` | `.data+0x1660` | **0x00010000 = 65536** | 主表 64K 条 |
| `hash_action_table` 描述符 | `.data+0x45A0` | table_id=10, entry_count=0x10000, +0x1C=0x40 | AAL 表描述符 |
| `hash_action_table_entry_length` | `.bss+0x746E` | 运行期 | 由 `hash_table_size_set` 写 |
| `npt6_prefix_addr_table` | `.data+0x4258` | table_id=0x44, entry_count=0x10, +0x24=2 word | **16 条 × 64 bit 前缀** |

`aal_hash_action_update`（ne+0x9AC40）为每条 flow 准备 **0x30 B 栈缓冲** `auStack_48`，
按 mode 选 `convert_act_flow_nomal_mode`（224 bit）或 `convert_act_flow_naptv6_mode`（371 bit），
然后 `aal_entry_add_by_idx(10, buf, idx)`（主表）/`(0xb, buf, idx)`（overflow，按 bit16 区分）；
写入长度由表描述符的 entry_length 决定，SW 影子表在 `hash_action_table._136_8_ + idx*0x18 + 0x10` 记 `actgrp`。

**结论**：48 B 可行，但**是整个表的全局换宽**：
`mode_set` 会重设主表/overflow 宽度并 `aal_hash_cache_init` 重建 cache。
不能"每流单独选布局"（`hash_action_group_check` 会拒绝 actgrp 不匹配的 action）。

### 4.5 方向 / PAT / checksum 有没有新线索

| 项 | 结论 | 证据 |
|---|---|---|
| 方向（`ip_type`） | **仍 UNKNOWN**。NAPTV6 布局里 `ip_type` 在 bit96，仍是唯一方向位；G1/G3/G24 无方向字段 | `convert_act_flow_naptv6_mode` 全表与 RE-6 逐位一致 |
| PAT（`l4_dp`） | **仍 UNKNOWN**。`l4_dp_vld`=bit0、`l4_dp`=bit1..16 存在且为 16 bit；字段名仍是 `<Group 1, L4 Dest Port ID>`，无"改写"证据 | `dump_HS_ACTGRP_FLOW_NAPTV6_MODE` 格式串 |
| checksum | **仍 UNKNOWN**。371 bit 布局内**没有** checksum 控制位；软件路径 act5/6 只打印不重算（§2.5） | `convert_act_flow_naptv6_mode`、`rtk_fc_outerHdr_insert` |
| 新增线索 | `ca-ne` 有一条 `"DSLite/6RD: Outer IPDA and IPSA reverse path of forwarding check fail"`（`.rodata.str1.8` 0x1ae4e8 偏移）——说明 **ca-ne 侧对双头流有外层 IPDA/IPSA 反向路径校验**，这是"双头 flow 装得上但可能被拒"的检查点 | `strings -t x ca-ne.ko` |

---

## 5. 与旧报告（RE-6/RE-7/RE-8）的冲突清单

| # | 旧结论（fc_mgr 语料） | 本语料实测（fc_8277c） | 处理 |
|---|---|---|---|
| C1 | extra-tag 每条 40 B / 10 word，表 `fc_db+0xBE3664` | **36 B / 9 word**，表 `fc_db+0x927E8`；header 独立数组 `0x925FE4`；content `0x926224` | 以本语料为准；W8c 若照抄 RE-8 会写错地址 |
| C2 | extra-tag 表"只写、消费者 UNKNOWN" | **消费者已找到**：软件路径 `rtk_fc_outerHdr_insert/remove`（内联 `_rtk_fc_applyExtraTagAction`），由 `_rtk_fc_shortCutCheck` 调用 | 更新 U1 |
| C3 | ACL desc 0x38 B，输出 +0x34 | **0x30 B，输出 +0x28**；+0x08 = aal type | 必须按新布局 |
| C4 | `aal_l3_cls_add(0, 0x14, key, rule)`，rule 是规则输入 | **type ∈ {0,1}；rule 是 4 B 输出编码**；0x14 只是 ref hint；动作在 key+0x89 的 FIB 块 | RE-8 的 U3 关闭一半（读懂 rule），剩 FIB 块格式 |
| C5 | NAPTV6 前缀表 16 条（derived） | 仍是 16 条（`.data+0x4268` = 0x10, `+0x24`=2） | 保持 |
| C6 | 48 B entry 是否可行 → 待定 | **可行**：mode_set 用 0x180 bit；overflow size set 明确支持 0x180 | 关闭 |
| C7 | `netif_rec` stride 0x168 @0x942FB8 | **stride 0x228 @0x806000**；`+0x0E`=extratag_idx，`+0x14`=dualType，`+0x2C`=configured | 全部偏移重算 |

---

## 6. 可行性分类（W8c / W7c）

### 6.1 W8c：extra-tag 建模 / flow 安装

**A. 可以直接做（有完整证据）**

| 项 | 依据 | 风险 |
|---|---|---|
| extra-tag 编码/解码库（9 word、acttype 1..7、终止符） | §2.1/§2.2 + dump 格式串 | 低 |
| DS-Lite / 6RD 动作字常量回放（与 OEM 逐字一致） | §2.4 | 低 |
| `debugfs` dump/编程（16×36 B + 16×64 B） | ADD/DEL/GET/SET 语义 | 低 |
| **软件封装路径**：按动作表在 skb 上插外层头/改 ethertype/改长度 | §2.5（`rtk_fc_outerHdr_insert` 全流程） | 中（需 readback + act5/6 校验和策略） |
| Content(31)/Control(32) 硬件表写入 + clear-on-free 时序 | RE-7 + §2.4 | 中（需 readback） |
| ACL 保留规则 0x14 的 desc（0x30 B）+ subtype 4/5/6 + `AddSpecial` 调用 | §3.2 | 中（key 的 FIB 块未闭合） |
| 16 netif 上限（`slot = netif-0x10`，`empty_find` 恒 -1） | §2.1 | 低 |

**B. 只能 raw / debugfs / 设备 readback**

| 项 | 原因 |
|---|---|
| ACL key 的 `+0x08` 匹配模式字 与 `+0x89` FIB 动作块 | 只见 builder 写值，无语义；需 `aal_l3_cls_*` readback 或上机试 |
| `RTK_RG_ASIC_FLOWPATH_SET` 的 flow key 字段 | `0x80001`/`0x10000000` 未逐位命名 |
| 软件路径 act5/act6（L3/L4 checksum） | 本语料只有打印，无重算实现 |

**C. 不得实现（缺证据）**

| 项 | 原因 |
|---|---|
| "把 extra-tag 表写对就能让 ASIC 封装" | **不成立**：ASIC 路径只有 Content/Control（§2.4/§2.5） |
| 把 `netif_rec+0x0E`（extratag_idx）当硬件动作索引 | 它只是 SW 路径与调试用的 slot 号 |
| MAP-T > 3 条 | FMR 表硬上限 3（RE-7） |
| netif ≥ 32 的双头 | `empty_find` 恒 -1 |

**最小设备证据（W8c 收口）**
1. `debugfs extratag` dump 一次 OEM 的 DS-Lite/6RD netif：确认 16×36 B 内容与本文回放的 4 个 word 完全一致（唯一能证明理解正确的实验）。
2. 拆 Content/Control 后发包：若仍被封装 → 说明走的是软件路径（`rtk_fc_outerHdr_insert`）；若不再封装 → 硬件路径。
3. 抓 `rtk_fc_outerHdr_insert` 的 acttype 5/6 打印，确认它是否重算校验和（决定 act5/6 要不要我们补）。
4. ACL 规则 readback（`aal_l3_cls_*`）补 key/FIB 块。

### 6.2 W7c：NAPT6 启用

**A. 可以直接做**

| 项 | 依据 |
|---|---|
| 371-bit NAPTV6 action 打包（纯 bit-pack） | `convert_act_flow_naptv6_mode` 全表（RE-6 §3 + 本次复核） |
| ACTGRP 位掩码模型与两种组合（0x140000 / 0x114000A） | `aal_hash_actionGrpBitmask_length_get` 全表 |
| 48 B 表项安装到主表/overflow | `aal_hash_action_update` + `mode_set` 宽度 0x180 |
| NAPTV6/NAT66 的前缀表（16 条 × 64 bit） | `npt6_prefix_addr_table` + `aal_hash_npt6_prefix_addr_entry_add` |

**B. 只能 raw / debugfs**

| 项 | 原因 |
|---|---|
| **全局 `hash_flow_naptv6_support_mode=1`** | 只有 `aal_hash_action_mode_set`（导出但**无人调用**）；切换会重建整表，必须与 flow 重装一起做 |
| NPT6 前缀内容/长度语义 | 只有内部 API，条目只 print `prefix(64)` + ref count |
| `six_rd_dip_remap_or_fmr_idx` | 2-bit，FMR 表 3 条，DIP remap 条目数 UNKNOWN |

**C. 不得实现 / 缺证据**

| 项 | 缺什么 |
|---|---|
| NPTv6 校验和中性（RFC 6296） | 布局里无 checksum 控制位；软件路径 act5/6 也不重算 → 必须设备实验 |
| 端口 PAT（NAPT6） | `l4_dp` 是"Dest Port ID"，无改写语义证据 |
| DNAT6/SNAT6 方向 | 只有一个 `ip_type`，NAPTV6 下是否复用为方向位无证据 |
| 任意前缀长度 | NAPTV6 action 无 prefix-length 字段 |
| 每流独立选 v4/v6 布局 | ACTGRP 全局，`hash_action_group_check` 会拒绝混用 |

**最小设备证据（W7c 收口）**
1. **确认当前表宽**：读 `l3fe_main_hash_action_table_entry_length`（`ca-ne .data+0x165C`）与 `hash_action_table_entry_length`（`.bss+0x746E`）——若运行期已是 0x20，则必须先调用 `aal_hash_action_mode_set(dev,1)` 才能装 48 B。
2. **确认可切换**：在设备上找到调用 `aal_hash_action_mode_set` 的路径（OEM 私有模块 / 调试命令）；没有它，NAPT6 无法开启。
3. **双 dump 对比**：mode 0/1 下装同一条 IPv4 flow，比对 `hash_action_dump` 与 `dump_HS_ACTGRP_FLOW_NAPTV6_MODE`（0x19xx）输出，证明 371-bit 布局被硬件正确解码。
4. **校验和实验**：一条 NPTv6 规则 + TCP 报文，抓改写后的 L4 checksum 与 RFC 6296 中性值比对（决定 U4）。
5. 方向判定：分别只改高 96 bit / 只改低 32 bit，看哪一半出现在报文的 SA/DA。

---

## 7. UNKNOWN 清单（禁止猜测）

| # | 问题 | 现状 |
|---|---|---|
| U1 | `rtk_fc_outerHdr_insert` 与硬件 Content/Control 的**取舍条件**（哪些包走软件路径） | 只知由 `_rtk_fc_shortCutCheck` 调用，判定条件未展开 |
| U2 | `_rtk_fc_extraTagActionList_empty_find` 是否存在可用扫描实现 | 本语料仍恒 -1 |
| U3 | ACL key 的 `+0x08` 模式字 与 `+0x89` FIB 动作块逐位语义 | 只见 builder 写值 |
| U4 | `desc+0x1C` 标志位逐位语义 | 只见来源 |
| U5 | 子类型 1/2/7/8 之外的其它双头特性 | 未展开 |
| U6 | acttype 3 的 `op`（2 bit）在 ≠0 时的语义 | 只有 op=0 样本 |
| U7 | acttype 5/6 是否真的重算校验和 | 软件路径只打印 |
| U8 | NAPTV6 的 `ip_type` 方向、`l4_dp` 是否 PAT | 无证据 |
| U9 | `RTK_RG_ASIC_FLOWPATH_SET` 的 flow key 位域（0x80001 / 0x10000000） | 未逐位命名 |
| U10 | `mode_set` 的合法调用者/设备侧入口 | 本语料无调用者 |
| U11 | `ca-ne` 的 "Outer IPDA and IPSA reverse path of forwarding check fail" 具体判定 | 只见字符串，未定位函数 |

---

## 8. 复现命令

```sh
# 完整性
sha256sum /mnt/c/rea/fc_8277c.ko /mnt/c/rea/ca-ne.ko

# extra-tag API（9 word / 36 B / header / content）
aarch64-linux-gnu-objdump -dr --start-address=0x85e00 --stop-address=0x85fb0 /mnt/c/rea/fc_8277c.ko
aarch64-linux-gnu-objdump -dr --start-address=0x1dd20 --stop-address=0x1e0a0 /mnt/c/rea/fc_8277c.ko   # dump/解码
aarch64-linux-gnu-objdump -dr --start-address=0x8e0a0 --stop-address=0x8e170 /mnt/c/rea/fc_8277c.ko   # empty_find==-1

# 消费者
aarch64-linux-gnu-objdump -dr --start-address=0x92dd0 --stop-address=0x93100 /mnt/c/rea/fc_8277c.ko   # outerHdr_insert
aarch64-linux-gnu-objdump -dr --start-address=0x94140 --stop-address=0x94540 /mnt/c/rea/fc_8277c.ko   # outerHdr_remove
aarch64-linux-gnu-objdump -dr --start-address=0x69d00 --stop-address=0x6a080 /mnt/c/rea/fc_8277c.ko   # shortCutCheck

# 安装函数（动作字 + 硬件三表）
aarch64-linux-gnu-objdump -dr --start-address=0x8fa40 --stop-address=0x902c0 /mnt/c/rea/fc_8277c.ko   # DSLite
aarch64-linux-gnu-objdump -dr --start-address=0x97450 --stop-address=0x97c70 /mnt/c/rea/fc_8277c.ko   # 6RD
aarch64-linux-gnu-objdump -dr --start-address=0x97c70 --stop-address=0x98400 /mnt/c/rea/fc_8277c.ko   # egressDecision

# ACL 0x14
aarch64-linux-gnu-objdump -dr --start-address=0xa1f00 --stop-address=0xa2260 /mnt/c/rea/fc_8277c.ko   # AddSpecial 头/类型分派
aarch64-linux-gnu-objdump -dr --start-address=0xa3ff0 --stop-address=0xa4420 /mnt/c/rea/fc_8277c.ko   # subtype 分派 + key/rule
aarch64-linux-gnu-objdump -dr --start-address=0xa4bb0 --stop-address=0xa4d80 /mnt/c/rea/fc_8277c.ko   # sub 4/6 分支
aarch64-linux-gnu-objdump -dr --start-address=0x9d710 --stop-address=0x9d7f0 /mnt/c/rea/fc_8277c.ko   # RuleAdd → aal_l3_cls_add

# NAPT6（ca-ne）
aarch64-linux-gnu-objdump -dr --start-address=0x9d590 --stop-address=0x9d6e0 /mnt/c/rea/ca-ne.ko   # mode_set
aarch64-linux-gnu-objdump -s  -j .data --start-address=0x1600 --stop-address=0x1700 /mnt/c/rea/ca-ne.ko  # 0x20 / 0x10000
aarch64-linux-gnu-objdump -s  -j .data --start-address=0x45a0 --stop-address=0x4660 /mnt/c/rea/ca-ne.ko  # hash_action_table
REA: aal_hash_action_mode_set / aal_hash_action_update / aal_hash_actionGrpBitmask_length_get / convert_act_flow_naptv6_mode
```

### 地址速查

```
fc_8277c.ko
  RTK_RG_ASIC_EXTRATAGACTION_ADD          .text+0x85E00
  RTK_RG_ASIC_EXTRATAGACTION_DEL/GET      .text+0x85E80 / 0x85EC0
  RTK_RG_ASIC_EXTRATAGCONTENTBUFFER_*     .text+0x85F00 / 0x85F50
  dump_extratag_table                     .text+0x1DD20
  _rtk_fc_extraTagActionList_empty_find.part.0  .text+0x8E0A0  (恒 -1)
  _rtk_fc_flow_setupL2TP_by_egrPktHdr     .text+0x8EAA0
  _rtk_fc_flow_setupDSLITE_by_egrPktHdr   .text+0x8FA40
  _rtk_fc_flow_setupPPTP_by_egrPktHdr     .text+0x90CB0
  _rtk_fc_flow_setup6RD_by_egrPktHdr      .text+0x97450
  rtk_fc_outerHdr_insert                  .text+0x92DD0   (消费者)
  rtk_fc_outerHdr_remove                  .text+0x94140   (消费者)
  _rtk_fc_flow_updatePPTP_by_igrPktHdr    .text+0x8D060
  _rtk_fc_flow_updateDSLITE_by_igrPktHdr  .text+0x8D990
  rtk_fc_8277C_v6rd_downStream_reservedACL_add .text+0x8E190
  rtk_fc_egress_extratagDecision          .text+0x97C70
  _rtk_fc_flow_setupVXLAN (inline)        ~.text+0x97E64 起
  _rtk_rg_aclAndCfReservedRuleAddSpecial  .text+0xA1F00   (REA 0x1A1F40)
  _rtk_fc_g3_caAalClsRuleAdd              .text+0x9D710   (REA 0x19D750)
  _rtk_fc_g3_caAalClsAssignRuleRefIdx     .text+0x9D030
  _rtk_rg_aclAndCfReservedRuleDelSpecial  .text+0xA5900

fc_db 偏移（本语料）
  extra-tag header    0x925FE4  (16 × 36 B, vld/ofs/len)
  extra-tag content   0x926224  (16 × 64 B)
  extra-tag actions   0x927E8   (16 × 36 B = 9 word)
  ACL SW 影子表       0x9587C8  (0x200 × 0x28 B)
  per-hash 记录       0x200180  (stride 0x40)
  netif_rec(n)        0x806000 + n*0x228
    +0x0E extratag_idx (u8)   +0x14 dualType (u32)   +0x2C configured (u8)

ca-ne.ko
  aal_hash_action_mode_set               .text+0x9D590  (scfg "516")
  aal_hash_action_mode_get               .text+0x94440
  aal_hash_action_update                 .text+0x9AC40
  aal_hash_actionGrpBitmask_length_get   .text+0x941A0
  convert_act_flow_naptv6_mode           .text+0x93250
  aal_hash_hash_overflowAction_size_set  .text+0x94FF0  (0x40/0x80/0x100/0x180)
  aal_l3_cls_add                         .text+0x87060
  aal_l3_cls_key_clean                   .text+0x82430
  hash_flow_naptv6_support_mode          .bss+0x7418
  l3fe_main_hash_action_table_entry_length .data+0x165C = 0x20
  l3fe_main_hash_action_table_entry_count  .data+0x1660 = 0x10000
  npt6_prefix_addr_table                 .data+0x4258 (16 条 × 2 word)
```