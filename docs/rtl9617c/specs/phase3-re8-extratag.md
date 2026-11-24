# Phase 3 / RE-8：Dual-Header extra-tag action 表与 flow 绑定（只读逆向）

- 语料 `fc_mgr.ko` SHA-256 `10c4f7f0dc22762de96768e80cb90e7d4203c2b406fccf1197f4fdc2daace479`
- 语料 `ca-ne.ko`  SHA-256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e`
- 两个哈希均实测一致；`/opt/rea-snap` 未访问；两个构建仓库只读。
- 前置阅读：`phase3-re7-dualhdr-content.md`（Content/Control/FMR 三表）、`phase3-re6-napt6.md`（G18/G20 布局）。
- 状态：**纯静态逆向，未上机验证**。凡标 `observed` 的数值均由 objdump 字面量逐条读出；
  标 `derived` 的为由多条 observed 推出的语义；标 `UNKNOWN` 的禁止在 W8c 中猜测填充。

## 0. 地址约定

| 记号 | 含义 |
|---|---|
| `fc_mgr+0xNNNN` | `nm -n fc_mgr.ko` 的 `.text` 节内偏移（该节 VMA=0，等于 objdump 地址） |
| `ca-ne+0xNNNN` | 同上，`ca-ne.ko .text` |
| `REA` | 上述偏移 `+ 0x100040`（见 §10 速查表） |
| `NE+0xNNNN` | ca-ne 内部寄存器窗口基址（`0xf4300000` 段） |
| `fc_db+0xNNNN` | 驱动侧 `.bss` 数据库（`fc_db` = `.bss+0xc440`，`.bss` 总大小 `0xc5459c` ≈ 12.6 MB）。这是**主机内存**，不是 NE 寄存器 |
| `netif_rec(n)` | 每 netif 记录，`fc_db + 0x942FB8 + n*0x168`（stride 0x168；数组 **64 项**，范围 `0x942FB8..0x9489B8`，由 `rtk_fc_tables_init` 的 memset 循环上界实测） |

---

## 1. 结论速览（含对任务假设的一处更正）

1. **`RTK_RG_ASIC_EXTRATAGACTION_*` 不是 NE 寄存器表，而是驱动侧 `fc_db` 里的一张 16 项 × 40 B 的
   软件"外层头动作程序"表**（`fc_db+0xBE3664`），外加一块 16 × 64 B 的 content 暂存区
   （`fc_db+0xBE38E4`）。全语料**没有**任何 NE 命令字/数据字访问路径、没有 ca-ne 侧 descriptor、
   没有 `aal_*` 调用（证据见 §2.5）。任务书里"NE 偏移、命令字/数据字"的预期在这份语料中不成立。
2. 每条 entry = 8 B 表头（`vld` / content byte-offset / content len）+ **8 个 32 bit 命令字**。
   命令字高 3 bit 是 `acttype`（1..7），分别表示插入外层头、改 ethertype、改长度字段、
   改 IPv4 ID / GRE seq-ack、L3 校验和、L4 校验和、外层 tag 定位参数。**7 种类型的位域已全部解出并互相交叉验证**（§3）。
3. 真正的硬件封装路径是 RE-7 已闭合的 **Dual Content(31)/Control(32)/FMR(33)** 三表；
   extra-tag action 表是与之**并行**的软件描述（数据来源、写入顺序、索引都与三表一致）。
4. 表项索引 = `netif 参数 - 0x10`（0..15，固定映射，非通用分配器）；
   `netif_rec.extratag_idx`（+0x7C）记录它。`netif > 31` 时走
   `_rtk_fc_extraTagActionList_empty_find()`，而该函数在本构建中**恒返回 -1**（§2.6）→ 双头只支持 16 个 netif。
5. ACL reserved rule **类型 0x14 = `RTK_CLS_TYPE_DUAL_HEADER_DS_CHECK`**（保留规则类型空间的**最后一个**，21 个之一）。
   `_rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc)` 按 `desc[0]` 的子类型再分派，
   DS-Lite=4、6RD=6、PPTP=3、MAPT=7/8、L2TP=0；成功后把分配到的 ACL 规则索引写回 `desc+0x34`，
   调用者存进 `netif_rec+0x88`（`dualHdr_ds_clsIdx`）/`+0x8C`（`dualHdr_ds_extra_clsIdx`）。
6. **G18/G20 hash action 与 extra-tag 表没有任何字段关联**：224 bit 的基准 action 里没有 extra-tag 索引
   （RE-6 全字段表），dual-header flow setup 也从不调用 `aal_hash_action_update`。

---

## 2. 三个 API 的实现

### 2.1 `RTK_RG_ASIC_EXTRATAGACTION_ADD` — `fc_mgr+0x8DC70`（REA 0x18DCB0）

原型（实测）：

```c
/* w0 = entry idx (0..15), w1 = word index (0..7, 调用者传值), x2 = &word */
int RTK_RG_ASIC_EXTRATAGACTION_ADD(u32 idx, u32 sub, const u32 *word);
```

实现逐条（`observed`）：

```
cmp  w0, #0xf ; b.hi  -> 错误路径
x4 = 0x2F8D9B                      ; 既不是 0x8D9B，也不是指针；是 fc_db 的 **word 索引**
x1 = x4 + w1
w3 = 10                            ; 每条 entry = 10 word = 40 B
x1 = w1_of_x4 + idx*10             ; => x1 = 0x2F8D9B + sub + idx*10
w4 = *x2
str  w4, [fc_db + x1*4]            ; === fc_db + 0xBE366C + idx*40 + sub*4
if ((w4 & 0xE0000000) == 0x20000000) {       ; acttype == 1 (inserttag) 才更新表头
    fc_db[0xBE3664 + idx*40]      = 1;                       ; vld
    *(u16*)&fc_db[0xBE3666+idx*40] = (w4 >> 3)  & 0x3FF;     ; content byte offset
    fc_db[0xBE3668 + idx*40]       = (w4 >> 13) & 0xFF;      ; content length
}
return 0;
```

- **写序**：先把命令字写进 entry，再（仅 type1）写表头。三个表头字段是 3 次独立存储，无锁。
- **索引上界**：`idx > 15` → `_rtk_fc_tracelog_printf("invalid extra tag actionList: %d", idx)`
  并返回 **`0x00010005`**（`w19 = 5 | 1<<16`）。**`sub` 没有任何校验**（>7 会写到下一条 entry）。
- 表头只在写 type1 字时更新；写 type2..7 不会把 `vld` 置 1。
  因此"entry 有效"的充要条件是**至少写过一个 type1 字**（且它是最后写的）。

### 2.2 `..._DEL` — `fc_mgr+0x8DD80`（REA 0x18DDC0）

```c
/* w0 = idx, w1 = sub */
int RTK_RG_ASIC_EXTRATAGACTION_DEL(u32 idx, u32 sub)
{ fc_db[0x2F8D9B + sub + idx*10] = 0; return 0; }
```

**只清一个 word，不清表头、不清其余 7 个 word。** 唯一调用点
`rtk_fc_netif_dualConfig_del+0x1AC` 传 `(extratag_idx, 0)`，即只清掉 type1 字。
`vld` 与 `ofs/len` 仍然为旧值 → 释放后必须由驱动自己补清表头（W8c 必做，见 §7）。

### 2.3 `..._GET` / `..._CONTENTBUFFER_SET` / `..._CONTENTBUFFER_GET`

```c
/* GET: fc_mgr+0x8DDB0 */
int RTK_RG_ASIC_EXTRATAGACTION_GET(u32 idx, u32 sub, u32 *out)   /* out = fc_db[0x2F8D9B+sub+idx*10] */

/* SET: fc_mgr+0x8DDE0  —— 注意：len 不是参数，取自表头 */
int RTK_RG_ASIC_EXTRATAGCONTENTBUFFER_SET(u32 idx, const void *src)
{
    u16 ofs = *(u16*)&fc_db[0xBE3666 + idx*40];   /* type1 字 bits[12:3] */
    u8  len = fc_db[0xBE3668 + idx*40];           /* type1 字 bits[20:13] */
    memcpy(fc_db + 0xBE38E4 + ofs, src, len);
    return 0;
}

/* GET: fc_mgr+0x8DE30 —— 注意第一个参数是 **content 区字节偏移**，不是 entry idx */
int RTK_RG_ASIC_EXTRATAGCONTENTBUFFER_GET(u32 byte_off, u32 len, void *dst)
{ memcpy(dst, fc_db + 0xBE38E4 + byte_off, len); }
```

`dump_extratag_table`（`fc_mgr+0x28500`）对 16 条 entry × 8 word 调 GET 并逐 word 解码打印，
再按 `byte_off = 0, 0x40, 0x80, ...`（即 `idx*64`）打印 16 个 64 B content 块
（打印串 `"[Extra Tag Content Buffer %d]"`）。这是 SET/GET 两个不对称参数语义的**活证据**。

### 2.4 内存布局（`observed`，全部由字面量算出）

```
fc_db + 0xBE3664   16 × 40 B  action entries（总 0x280）
   entry(idx) = 0xBE3664 + idx*40
     +0x00  u8   vld            (写 type1 字时置 1)
     +0x01  u8   pad
     +0x02  u16  content_ofs    (type1 字 bits[12:3]，10 bit 字节偏移)
     +0x04  u8   content_len    (type1 字 bits[20:13]，8 bit 字节数)
     +0x05..0x07 pad
     +0x08  u32  action[0]
     +0x0C  u32  action[1]
     ...
     +0x24  u32  action[7]
fc_db + 0xBE38E4   16 × 64 B content buffer（总 0x400，紧接 action 表之后）
                   => 整个 extra-tag 块 = [0xBE3664, 0xBE3CE4)，0x680 B
```

**entry 里没有 control idx / direction / priority / 优先级字段。**
Control 槽索引由调用者约定为"与 entry 索引相同"（`netif-0x10`），
方向与优先级不在本表：方向由调用哪个 flow setup（上/下行）决定，优先级/命中由 ACL 规则与 hash flow 决定。

### 2.5 关键否定证据：没有 NE / ca-ne 访问路径 `observed`

| 检查 | 结果 |
|---|---|
| `nm ca-ne.ko \| grep -iE "extratag\|extra_tag"` | **无任何符号** |
| `strings ca-ne.ko \| grep -i extratag` | **无** |
| fc_mgr 内对 `0x2F8D9B` / `0xBE36xx` 的引用 | 只有 ADD/DEL/GET/SET 四个函数（`mov x4,#0x8D9B` 仅 3 处，全在 0x8DC70..0x8DE30） |
| `aal_*` 调用 | ADD/DEL/GET/SET **一个都没有**；也无 `rtk_ne_reg_write` |
| ca-ne 表描述符扫描（`.data` 全量，`base=0xf430xxxx`） | 只有 table 31/32/33（dual content/control/FMR，16/16/3 × 16 word）以及 13/18/19/20..30/34/36/69 等；**没有 16 × 40 B 或 16 × 8/10 word 的表** |
| `aal_table_flush` 调用点 | 只有 `AddSpecial` 内 flush table 18/19 与 `rtk_8277c_asic_flow_flush` flush table 68 — 与本表无关 |
| 唯一的读者 | `dump_extratag_table`（debug 打印）与 `..._GET`（也只被它调用） |

结论：这张表在 fc_mgr 内是**只写**的。它的消费者不在本语料内（可能是 ASIC 通过主机内存读取，
也可能是另一模块；`fc_db` 的物理地址确实会在 `_rtk_fc_pe_page_alloc` 一类的函数里被换算后交给下层，
但语料中没有找到把本区域基址编程给 ASIC 的代码）。
→ **"谁读它" = UNKNOWN**；W8c 不得假设它已被硬件消费。

### 2.6 `_rtk_fc_extraTagActionList_empty_find.part.0` — `fc_mgr+0x96BC0` `observed`

6 个调用点（GreEthBr `0x97164`、PPTP `0x98810`、L2TP `0x99538`、IP4InIP6 `0x9AC40`、
6RD `0x9E9F8`、VXLAN `0x9FFC8`）全部只在 **`slot = netif-0x10 > 0xF`** 时调用。
函数体只做两件事：检查 `fc_db[1436]/fc_db[1432]&0x20` 两个调试开关 → 可能 `tracelog` → **`return -1`**。
即本构建里"找空闲 extra-tag entry"**恒失败**：

- netif 16..31 → 直接用 `netif-0x10`，正常；
- netif ≥ 32 → `-1`，flow setup 返回 `-1`（`0xFFFFFFFF`），双头建立失败。

这解释了 `netif_rec.extratag_idx` 初值 `0xFF`、以及"双头最多 16 个 netif"的硬约束。
是否存在未内联的完整扫描实现 → **UNKNOWN**（symtab 中该符号只有 `.part.0`）。

---

## 3. action 表条目格式（`observed`，字段名来自 `dump_extratag_table` 的格式串）

### 3.1 命令字通用格式

```
bits[31:29] acttype   (0 = 空/终止；1..7 = 下表)
bits[28:0]  按 acttype 解释
```

`dump_extratag_table` 的循环在遇到 `(word & 0xE0000000) == 0` 时**停止**，所以
**全 0 word 是动作列表的终止符**，一条 entry 最多 8 条动作。

### 3.2 七种 acttype 的位域（全部实测）

| acttype | 名称（格式串原文） | 位域（宽） | 语义 |
|---|---|---|---|
| **1** | `inserttag bufoff:%d len:%d` | `bits[12:3]`=bufoff(10) `bits[20:13]`=len(8) | 在包中插入 content buffer 里 `len` 字节（来自 `fc_db+0xBE38E4+bufoff`） |
| **2** | `ethtran ethertype:0x%04x` | `bits[28:13]`=ethertype(16) | 改写外层 ethertype |
| **3** | `updatelen pktoff:%d width:%d value:%d op:%d` | `bits[28:21]`=pktoff(8) `bits[20:13]`=width(8) `bits[12:4]`=value(9) `bits[3:2]`=op(2) | 改长度字段：`pktoff` 处 `width` 字节的字段 = 原包长 + `value`（`derived`，由 DS-Lite/6RD 两组常量互证，见 §3.3） |
| **4** | bit11=1 → `ipv4id pktoff:%d, intfidx:%d`；bit11=0 → `greseqack pktoff:%d, intfidx:%d, reduceseq:%d, reduceack:%d` | `bits[28:21]`=pktoff(8) `bits[20:15]`=intfidx(6) `bit13`=reduceseq `bit12`=reduceack `bit11`=子类型 | 重写 IPv4 ID（按 intf 计数）/ GRE seq-ack |
| **5** | `l3chksum pktoff:%d` | `bits[28:21]`=pktoff(8) | L3 校验和位置 |
| **6** | `l4chksum pktoff:%d` | `bits[28:21]`=pktoff(8) | L4 校验和位置 |
| **7** | `outer_tag_len:%u, outer_udp_offset:%u, outer_ppp_offset:%u, is_l2dual:%u, outer_is_v6:%u, outer_ip_offset:%u` | `bits[6:0]`=outer_tag_len(7) `bits[13:7]`=outer_udp_offset(7) `bits[18:14]`=outer_ppp_offset(5) `bit19`=is_l2dual `bit20`=outer_is_v6 `bits[28:21]`=outer_ip_offset(8) | 描述外层头在包内的各段偏移（给软件路径/后续动作定位用） |

各类型的位域出处：`dump_extratag_table`（`fc_mgr+0x28570..0x2877C`）的 `ubfx` 立即数 + 格式串
（`.rodata.str1.8+0x9908/0x9928/0x9940/0x9970/0x9998/0x99d8/0x9a08/0x9a58/0x9a80/0x9aa8/0x9b28`），
并与三个 builder 交叉验证（§3.3/§3.4）。

### 3.3 DS-Lite（IP4InIP6）动作列表 `observed`

`_rtk_fc_flow_setupIP4InIP6` `fc_mgr+0x9A400`，`slot = netif_arg - 0x10`：

| sub | 值 | 解码 |
|---|---|---|
| 0 | `0x20050000 \| (slot<<9)` | act1 `inserttag(bufoff=slot*64, len=40)`；同时置 `vld=1` |
| 1 | `0x50DBA000` | act2 `ethtran 0x86DD`（外层变 IPv6） |
| 2 | `0x60804000` | act3 `updatelen(pktoff=4, width=2, value=0, op=0)` = IPv6 payload_len |
| 3 | `0` | **显式终止符** |

之后 `CONTENTBUFFER_SET(slot, buf)` 写入 §3.3 的 40 B 外层 IPv6 头
（`0x60 / 0xFFFF0400 / src16B / dst16B`，见 RE-7 §2.2）。

`derived`：act3 的 `value=0` 与 6RD 的 `value=20` 互为对照——
IPv6 Payload Length 不含外层头（+0），IPv4 Total Length 含 20 B 外层头（+20）。两者都与
`rep_len_ost1/rep_len_diff1`（RE-7 §3.3）自洽。

### 3.4 6RD 动作列表 `observed`

`_rtk_fc_flow_setup6RD` `fc_mgr+0x9E440`：

| sub | 值 | 解码 |
|---|---|---|
| 0 | `0x20028000 \| (slot<<9)` | act1 `inserttag(bufoff=slot*64, len=20)`（content 全 0） |
| 1 | `0x41000000` | act2 `ethtran 0x0800`（外层 IPv4） |
| 2 | `0x60404140` | act3 `updatelen(pktoff=2, width=2, value=20, op=0)` = IPv4 total_length |
| 3 | `0x80800800 \| ((netif&0x3F)<<15)` | act4 `ipv4id(pktoff=4, intfidx=netif)`（bit11=1） |
| 4..7 | **不写** | 无显式终止符 → 与 DS-Lite 的不对称（潜在残留动作，见 §8） |

Content 由 `rtk_fc_dual_control_content_set6RD`（`fc_mgr+0x9E2F0`）memset 成 64 B 全 0，
实际只用前 20 B（`hdr_len=20`）。

### 3.5 其他类型（抽样，用于交叉验证位域）

- **VXLAN**（`_rtk_fc_flow_setupVXLAN+0x420..0x590`，`fc_mgr+0x9FAF0..0x9FC60`）：
  `[0]=0x20000000|(slot<<9)|(hdr_len<<13)`；`[1]/[2]` 两个 act3 `updatelen(pktoff=off+4,width=2,value=Δ)`；
  `[3或4]=0xE0080000 | (hdr_len&0x7F) | (udp_off<<7) | (ppp_off<<14) | (ip_off<<21)`，
  若外层是 IPv6 再 `| 0x100000`（bit20）→ **完整验证了 act7 的六个字段**。
- **GRE_ETH_BR**（`_rtk_fc_flow_setupGreEthBr` `fc_mgr+0x96F00...`）：
  `[0]=act1`、`[1]=0x60004000|...`(act3 width=2)、`[2]=0xE0000000|...`(act7)，
  结构同 VXLAN，只是长度/偏移来源不同。

---

## 4. ACL reserved rule：类型 0x14

### 4.1 类型空间 `observed`

`_rtk_rg_aclAndCfReservedRuleDelSpecial`（`fc_mgr+0xA99A0`）开头
`cmp w19,#0x14; b.hi 错误` → 保留规则类型只有 **0..0x14 共 21 个**。
`_rtk_fc_acl_asic_init`（`fc_mgr+0xA50D0`）把一张模板表（含名字指针）搬到 `fc_db+0xC17xxx`，
名字串（`.rodata.str1.8+0x28dxx..0x28fxx`）按序为：

```
..._L2_L3_CLS, L2_INGRESS_FORWARD_PORT, L2_INGRESS_MC_FORWARD_L3FE,
L2_EGRESS_FORWARD_L3FE, DUAL_HEADER_DS_CHECK, RESERVED_SPECIAL_END, ...
```

`DUAL_HEADER_DS_CHECK` 是该序列里 `..._END` 之前的**最后一个有效类型**，
且 DelSpecial 的上界正好是 0x14 → **索引 0x14 = `RTK_CLS_TYPE_DUAL_HEADER_DS_CHECK`**。
DelSpecial 的调试串也直接写明了这个名字与 `pNetif->dualHdr_ds_clsIdx` / `..._extra_clsIdx` 的对应
（`.rodata.str1.8+0x28e30` 及其附近，见 §10）。

### 4.2 `_rtk_rg_aclAndCfReservedRuleAddSpecial` — `fc_mgr+0xACFF0`（REA 0x1AD030）

```c
/* w0 = 保留规则类型(0..0x14)，x1 = desc*（0x38 B，仅 0x14 用）*/
int _rtk_rg_aclAndCfReservedRuleAddSpecial(u32 type, const void *desc);
```

`type == 0x14` 分支（`0xAD10C..0xAD14C`）：

1. `desc == NULL` → 错误；
2. 把 **0x38 字节** desc 逐段拷到栈上（`sp+0x1D4`）；
3. `sub = ((u32*)desc)[0]`，`cmp sub,#0xD; b.ls` → 进入子类型分派（`0xAF2A0` 起）。

### 4.3 desc（0x38 B）布局（`observed`，由两个调用者拼装代码反推）

| 偏移 | 宽 | 内容 |
|---|---|---|
| +0x00 | u32 | **子类型**（0=L2TP、3=PPTP、4=DS-Lite/IP4InIP6、6=6RD、7=MAPT、8=MAPT-TCPflag0；1/2/5/9..0xD 未展开） |
| +0x04 | u32 | 0（保留） |
| +0x08 | u8 | 0 |
| +0x09 | u8 | `_rtk_fc_flow_intf_mapping_idx_get(netif_rec+0x78 的 int8)` 的结果（0..63 量级） |
| +0x0A | u8 | 1（DS-Lite 拼装时置 1） |
| +0x0C..+0x1B | 16 B | DS-Lite：4 个 **byte-reverse** 过的 u32（取自 `netif_rec+0x3C..0x5B` 的 16 B 地址区）；6RD：只用 +0x0C/+0x10 两个 u32 |
| +0x1C | u32 | 标志位（DS-Lite：bit0..1 来自 `[x24+312]&1`，bit14 来自 `[x24+312]` bit1，bit2..13/bit15..26 来自 `[x24+352]`；**逐位语义 UNKNOWN**） |
| +0x20..+0x33 | — | 调用者未写（栈残留；OEM 自身也不清零 → 见 §9 风险） |
| +0x34 | u32 | **输出**：AddSpecial 分配到的 ACL 规则索引 |

`AddSpecial` 成功返回 0；调用者把 `desc+0x34` 存入 netif：
`netif_rec+0x88`（`dualHdr_ds_clsIdx`）或 `+0x8C`（`dualHdr_ds_extra_clsIdx`）。

内部：`aal_l3_cls_key_clean()` → 拼 key/rule → `_rtk_fc_g3_caAalClsRuleAdd()`，
后者先 `_rtk_fc_g3_caAalClsAssignRuleRefIdx(key, ?, out, 0x10)`，
再 `aal_l3_cls_add(0, type=0x14, key, rule)`（`fc_mgr+0xA6030`，`observed`）。
**ACL key/rule 的内部 word 布局未逐位闭合 → UNKNOWN**（不在本任务闭合范围，但 W8c 若要走 ACL 路径必须补）。

### 4.4 删除

`_rtk_rg_aclAndCfReservedRuleDelSpecial(0x14, &netif->idx)`（`fc_mgr+0xA99A0`）：
`type > 0x14` 拒绝；类型掩码 `0x0010DC04`（bit2,10,11,12,14,20）走"特殊"分支（带 desc 指针的规则），
其余直接 `_rtk_fc_g3_caAalClsRuleDeleteReserveType(type)`，最后清
`fc_db[0xC17000 + type + 0xF8]` 的占用标志字节。

---

## 5. DS-Lite / 6RD 完整调用序列

### 5.1 入口链（`observed`）

```
rtk_fc_netif_dual_set_6RD   fc_mgr+0x95620   (w0=netif dev ptr, w1=up/down, w3=priv)
  -> _rtk_fc_flow_setup6RD  fc_mgr+0x9E440   (x0=dev, x1=priv, w2=sw netif idx)
       -> RTK_RG_ASIC_EXTRATAGACTION_ADD *4        (0x9E5D4/0x9E604/0x9E814/0x9E850)
       -> RTK_RG_ASIC_EXTRATAGCONTENTBUFFER_SET    (0x9E87C)
       -> aal_pe_dual_content_entry_add(slot, buf) (0x9E660)
       -> _rtk_fc_dualHeader_ctrl_setup6RD(slot, priv)   (0x9E330 -> 0x9E690)
       -> rtk_fc_dualHdrInfo_set(2, netif, ethertype)    (0x9E6D0)
       -> _rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, &desc{type=6,...})  (0x9E760)

rtk_fc_netif_dual_set_4in6  fc_mgr+0x96680
  -> _rtk_fc_flow_setupIP4InIP6 fc_mgr+0x9A400
       -> ADD x4 (0x9A5BC/0x9A90C/0x9A948/0x9A97C)
       -> CONTENTBUFFER_SET (0x9A9B0)
       -> aal_pe_dual_content_entry_add (0x9A61C)
       -> _rtk_fc_dualHeader_ctrl_setupIP4InIP6 (0x9A2F0 -> 0x9A64C)
       -> _rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, &desc{type=4,...}) (0x9A8A8)
```

索引关系（`observed`，三个表一致）：

```
sw netif idx (w2/w22)          = netif_dev->? 的"软件 netif 号"
netif_rec 索引 = (fc_db[0x9489B8 + sw_idx] >> 1) & 0x7F     // 每 sw netif 1 字节映射（hw netif 号）
slot = sw_idx - 0x10            // 0..15，越界则 empty_find 失败
netif_rec[+0x78] = sw_idx       // 由 rtk_fc_hwNetif_add_update_by_swNetif(0x90E10) 写入，删除时置 -1
Content idx = slot ; Control idx = slot ; extra-tag entry idx = slot ; content buf ofs = slot*64
```

### 5.2 DS-Lite（封装）逐步序列 `observed`

```
1. 读 netif_rec：+0x04 必须非 0（dual 已配置）；检查 dualType==1/2 分支
2. slot = netif-0x10（>0xF → empty_find → -1）
3. ADD(slot, 0, 0x20050000 | slot<<9)      ;; inserttag 40B @ slot*64
4. ADD(slot, 1, 0x50DBA000)                ;; ethertype -> 0x86DD
5. ADD(slot, 2, 0x60804000)                ;; updatelen(pktoff=4,w=2,val=0)
6. ADD(slot, 3, 0)                         ;; 终止符
7. CONTENTBUFFER_SET(slot, ipv6_hdr[40])   ;; 0x60 / 0xFFFF0400 / src / dst
8. netif_rec[+0x7C] = slot                 ;; extratag_idx
9. aal_pe_dual_content_entry_add(slot, ipv6_hdr)      ;; Content 表 id 31
10. _rtk_fc_dualHeader_ctrl_setupIP4InIP6(slot)       ;; Control 表 id 32，向量见 RE-7 §3.2
11. _rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc{sub=4})
12. netif_rec[+0x88] = desc+0x34           ;; dualHdr_ds_clsIdx
```

### 5.3 6RD（封装）逐步序列 `observed`

```
1. 同 5.2 的 netif_rec 检查；slot = netif-0x10
2. ADD(slot, 0, 0x20028000 | slot<<9)      ;; inserttag 20B @ slot*64
3. ADD(slot, 1, 0x41000000)                ;; ethertype -> 0x0800
4. ADD(slot, 2, 0x60404140)                ;; updatelen(pktoff=2,w=2,val=20)
5. ADD(slot, 3, 0x80800800 | netif<<15)    ;; ipv4id(pktoff=4,intfidx=netif)
6. CONTENTBUFFER_SET(slot, zeros[64])      ;; memset by rtk_fc_dual_control_content_set6RD
7. netif_rec[+0x7C] = slot                 ;; extratag_idx
8. aal_pe_dual_content_entry_add(slot, zeros)
9. _rtk_fc_dualHeader_ctrl_setup6RD(slot)  ;; Control 向量 0x0801FEC0/0xFCFFCA00/0x453F9001/0x01401FE0
10. rtk_fc_dualHdrInfo_set(2, netif, rev16(*(priv+96)+4))
11. _rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc{sub=6})
12. netif_rec[+0x88] = desc+0x34
```

### 5.4 删除 / 回收顺序 `observed`

`rtk_fc_netif_dualConfig_del(netif)` `fc_mgr+0x9D770`：

```
 0. if (netif_rec[+0x04] == 0) return 0;                      ;; 未配置双头
 1. if (netif_rec[+0x7C] != -1)                               ;; extratag_idx
        RTK_RG_ASIC_EXTRATAGACTION_DEL(idx, 0);               ;; 只清 word0
 2. if (netif_rec[+0x80] != -1)                               ;; path6 idx
        rtk_fc_flow_delete(idx); netif_rec[+0x80] = -1;
 3. slot = netif_rec[+0x78] - 0x10
    loop while ret == -4: aal_pe_dual_control_entry_del(slot)     ;; Control 先删
 4. loop count = netif_rec[+0x84]: aal_pe_dual_content_entry_del(slot)              ;; Content 后删（VXLAN 多槽）
 5. if (netif_rec[+0x88] != -1) _rtk_rg_aclAndCfReservedRuleDelSpecial(0x14, &+0x88); +0x88 = -1
 6. if (netif_rec[+0x8C] != -1) _rtk_rg_aclAndCfReservedRuleDelSpecial(0x14, &+0x8C); +0x8C = -1
 7. if (netif_rec[+0xA0] != -1) rtk_fc_mapet_hwfmr_del(...)   ;; MAP-T 专用
```

删除顺序要点：
- **extratag 动作条目最先删**（在 flow 删除之前）；
- Control 在 Content 之前（与 RE-7 §7.2/7.3 一致）；
- ACL 保留规则在 Control/Content 之后删；
- 但 step 1 的 DEL 只清 word0，**表头 `vld/ofs/len` 残留** → 见 §8 的 W8c 修正。

---

## 6. 与 hash action 表（G18/G20）的关系

| 问题 | 结论 | 依据 |
|---|---|---|
| extra-tag 索引是否出现在 224 bit 基准 action（G18+G20）？ | **否** | RE-6 §3/§3.11 全字段表；`convert_act_flow_nomal_mode` 的 12 段映射里无此字段 |
| dual-header flow setup 是否调用 `aal_hash_action_update`？ | **否** | `_rtk_fc_flow_setupIP4InIP6` / `_rtk_fc_flow_setup6RD` 内无该调用；它们只碰 extratag/Content/Control/ACL |
| 二者如何配合？ | 相互独立的两条链：内层 L3 改写（可含 NAT/NAPT6）走 hash action；外层头插入/剥离走 Content+Control（+ ACL 保留规则触发）。**没有交叉引用** | §5 调用序列 |
| 6RD 在 hash action 里的相关字段 | `six_rd_dip_remap_or_fmr_idx_vld/_idx`（2 bit，位于 NAPTV6 word8 bits 264..266 / 基准布局对应位置）——是"6RD 目的地址重映射/FMR 索引"，**不是** extra-tag 索引 | RE-6 §3.9、`0x2729c8` 格式串 |
| 是否会因 extra-tag 表而改变 ACTGRP 布局？ | **否**。ACTGRP 只由全局 `hash_flow_naptv6_support_mode` 决定（0x140000 / 0x114000a） | RE-6 §1.2 |

---

## 7. 驱动侧 API 草案

> 目标：把 §2/§3 中**已闭合**的部分做成可测试的抽象；未闭合字段一律显式保留 sentinel（0 / 0x7F），
> 不得填"看起来合理"的值。命名沿用 mainline `rtl_fe_*`。

```c
/* ---- 常量（全部 observed）---- */
#define RTL_FE_EXTRATAG_ENTRIES        16
#define RTL_FE_EXTRATAG_ENTRY_BYTES    40      /* 8 B header + 8 * u32 */
#define RTL_FE_EXTRATAG_WORDS          8
#define RTL_FE_EXTRATAG_CONTENT_BYTES  (16*64) /* 0x400 */
#define RTL_FE_EXTRATAG_CONTENT_SLOT   64

enum rtl_fe_extratag_act {
    RTL_FE_XT_INSERT_TAG = 1,   /* bufoff(10), len(8)          */
    RTL_FE_XT_ETH_TRAN   = 2,   /* ethertype(16)               */
    RTL_FE_XT_UPDATE_LEN = 3,   /* pktoff(8), width(8), value(9), op(2) */
    RTL_FE_XT_IPV4_ID    = 4,   /* bit11=1: pktoff(8), intfidx(6)        */
    RTL_FE_XT_GRE_SEQACK = 4,   /* bit11=0: pktoff, intfidx, rdseq, rdack */
    RTL_FE_XT_L3_CHKSUM  = 5,   /* pktoff(8) */
    RTL_FE_XT_L4_CHKSUM  = 6,   /* pktoff(8) */
    RTL_FE_XT_OUTER_TAG  = 7,   /* tag_len(7), udp_off(7), ppp_off(5),
                                   is_l2dual(1), is_v6(1), ip_off(8)    */
};

struct rtl_fe_extratag {
    u8   idx;                        /* 0..15 */
    u8   vld;                        /* entry header +0x00 */
    u16  content_ofs;                /* +0x02，type1 写入 */
    u8   content_len;                /* +0x04，type1 写入 */
    u32  words[RTL_FE_EXTRATAG_WORDS];
};

/* ---- 1) 分配 ---- */
/* OEM 语义：idx 由 netif 固定映射得到（slot = sw_netif - 0x10），不是通用分配器。
 * netif>=32 时 OEM 的 empty_find 恒失败，所以此处显式拒绝，而不是发明扫描语义。 */
int rtl_fe_extratag_alloc(struct rtl_fe *fe, unsigned int sw_netif, u8 *out_idx);
    /* 实现：if (sw_netif < 16 || sw_netif > 31) return -EOPNOTSUPP; *out_idx = sw_netif - 16; */

/* ---- 2) 编程一条 entry（含 content） ---- */
int rtl_fe_extratag_program(struct rtl_fe *fe, u8 idx,
                            const struct rtl_fe_extratag *t,
                            const void *content, unsigned int content_len);
    /* 必须按顺序：
     *   a) 校验 idx<16、content_ofs + content_len <= 0x400、t->words[0] 为 act1 且其
     *      bufoff/len 与 (content_ofs, content_len) 一致；
     *   b) 逐 word 写 entry+8+4*k（k=0..7），遇到全 0 视为终止，后续 word 也写 0；
     *   c) 写 header{vld=1, ofs, len}（OEM 在写 act1 时顺带写，等价）；
     *   d) memcpy content 到 content 区；
     *   e) readback 校验（若底层提供读接口）。 */

/* ---- 3) 绑定到 flow ---- */
int rtl_fe_extratag_bind_flow(struct rtl_fe *fe, u8 idx, unsigned int sw_netif);
    /* 已验证的绑定动作：
     *   - Content 表(slot=idx) 写 40/20 B 模板            （RE-7 §2.2/§2.3）
     *   - Control 表(slot=idx) 写常量向量                 （RE-7 §3.2/§3.3）
     *   - netif_rec[+0x7C] = idx                          （extratag_idx）
     *   - ACL 保留规则 type 0x14，desc{sub=4/6,...}，返回索引存 netif_rec[+0x88]
     * 其中 Content/Control 已闭合；ACL 规则 word 布局 UNKNOWN → 该步返回 -EOPNOTSUPP
     * 或走 debugfs，不得盲写。 */

int rtl_fe_extratag_unbind_flow(struct rtl_fe *fe, unsigned int sw_netif);
int rtl_fe_extratag_free(struct rtl_fe *fe, u8 idx);
    /* OEM 顺序：DEL(idx,0) -> flow delete -> Control del -> Content del -> ACL del
     * W8c 修正：DEL 之后还必须把 entry header(+0x00..+0x07) 与 words[1..7] 清零，
     * 因为 OEM 的 DEL 只清 word0。 */
```

**是否需要修改 `RTL_FE_ACTION_*` 或新增表？**

- **不需要**改 `enum rtl_fe_action_field`：224 bit 基准 action 与 extra-tag 无关（§6）。
- **需要新增**一张驱动内表（16 × 40 B + 1024 B content 区），但它**不能**假设已映射到硬件；
  建议做成 `debugfs` 可读写的 `extratag` 对象（与 OEM 的 `dump_extratag_table` 对齐），
  等设备证据证明"谁消费它"之后再决定是否接到 flow 路径。
- **真正让 DS-Lite/6RD 生效**仍然需要：Content/Control（里程碑 1 已有）+ hash flow entry +
  ACL 保留规则 0x14（缺规则 word 格式）。

---

## 8. W8c 可行范围

### 8.1 可以直接做的（有完整证据）

| 项 | 依据 | 风险 |
|---|---|---|
| extra-tag entry 的编码/解码库 + `debugfs` dump | §2/§3 全字段 | 低 |
| DS-Lite/6RD 的 action 列表常量回放（4 条 word） | §3.3/§3.4 | 低（纯编码） |
| 用 Content/Control 完成外层头插入（沿用 RE-7 Step1/2） | RE-7 | 中（需 readback） |
| 删除序列（含 OEM 顺序） | §5.4 | 低 |
| 16 netif 上限、slot=netif-0x10 的约束检查 | §2.6 | 低 |

### 8.2 不能做的（缺设备证据，禁止假装已生效）

1. **"extra-tag action 表接入 flow 就能让 DS-Lite/6RD 生效"——不成立。**
   全语料找不到该表的硬件消费者（§2.5）；即使我们把 16 × 40 B 写得和 OEM 一模一样，
   也无法证明 ASIC 会执行它。真正的硬件路径是 Content/Control 三表。
2. `netif_rec.extratag_idx`（+0x7C）**不能**当成"硬件动作索引"来用；
   它只在 OEM 的软件路径/调试里被读取（`rtk_fc_dual_hw_setting` 把它作为 out 参数返回，
   供 `outerHdrExtratagIdx` 记录）。
3. **ACL 规则 0x14 的 key/rule word 布局未闭合** → 无法在 mainline 里独立重建这条保留规则。
   若 DS-Lite/6RD 的 flow 需要 ACL 命中才会走双头路径，则这是 W8c 的**硬阻塞点**。
   需要补 `_rtk_fc_g3_caAalClsRuleAdd` / `aal_l3_cls_add`（ca-ne）的规则格式逆向。
4. **act3 的 `op`（2 bit）语义 UNKNOWN**：只见到 op=0 的两种用法；
   op≠0 的含义（set / add / sub?）没有样本。
5. **act4 的 `bit11=0`（greseqack）分支**只有打印格式，没有 builder 样本。

### 8.3 还缺什么设备证据（按优先级）

1. `debugfs extratag` 在设备上 dump 一次 OEM 建立的 DS-Lite/6RD netif：
   确认 16 × 40 B 内容与我们回放的 4 个 word 完全一致（这是唯一能证明我们理解正确的实验）。
2. 在同一 netif 上做一次发包实验：若拆掉 Content/Control 后报文不再被封装、
   而只拆 extra-tag action 表不影响封装 → 证明 §2.5 的"软件表"结论。
3. 读取 `fc_db` 中该区域的**物理地址是否被编程进任何 ASIC 寄存器**
   （在 OEM 驱动 init 后扫描 NE 寄存器窗口，找 `phys(fc_db)+0xBE3664` 或其页对齐值）。
4. ACL 规则 0x14 的 readback（`aal_l3_cls_get` 一类接口），补齐规则格式。

### 8.4 结论

- **W8c 的可行范围 = "可建模、可 dump、可验证编码"，但不包括"让 DS-Lite/6RD 在 mainline 上真正生效"。**
  真正生效仍取决于 RE-7 的三表 + 本报告的 ACL 规则 0x14；
  后者是当前唯一没有可复用规范的关键环节。
- 若 W8c 目标只是"把 OEM 的 extra-tag 语义固化成文档 + debugfs + 单元测试"，**可以安全完成**。

---

## 9. UNKNOWN 清单（禁止猜测）

| # | 问题 | 现状 |
|---|---|---|
| U1 | extra-tag action 表的**消费者**（ASIC？别的模块？） | 只写不读；无 NE/ca-ne 路径 → UNKNOWN |
| U2 | `_rtk_fc_extraTagActionList_empty_find` 是否存在可用的扫描实现 | symtab 只有 `.part.0`（恒 -1）；是否有热路径被内联/被裁掉 → UNKNOWN |
| U3 | ACL 规则 0x14 的 key/rule word 布局与各字段语义 | 只知 `aal_l3_cls_add(0, 0x14, key, rule)` 与 desc 外形 |
| U4 | desc+0x1C 标志位的逐位语义 | 只见位来源，未见语义 |
| U5 | 子类型 1/2/5/9..0xD 对应哪种双头/其它特性 | 未展开 |
| U6 | act3 的 `op`（2 bit）与 `value` 在 op≠0 时的语义 | 只有 op=0 样本 |
| U7 | act4 `greseqack` 的 reduceseq/reduceack 位序（bit12/13） | 反汇编参数序可读，但无 builder 交叉验证 |
| U8 | act5/act6（L3/L4 checksum）的 pktoff 语义与是否真由硬件执行 | 只有打印格式，无 builder |
| U9 | `netif_rec+0x38/+0x3C` 两个 u32（6RD 64-bit 配置）的字段拆分（前缀 vs BR 地址） | 只见 `priv+96` 的 +12/+16 |
| U10 | `rtk_fc_dualHdrInfo_set(2, ...)` 的第一个参数 2 的含义（方向？路径？） | 未解码 |
| U11 | `desc+0x0C..+0x1B` 16 B 在 DS-Lite 中的含义（IPv6 地址对？ACL key？） | 与 Content 的两个地址同源但用途未证 |
| U12 | ~~del 的 netif 参数是 sw 还是 hw idx~~ | **已解决**：dualConfig_del(n) 的 n 是 netif_rec(hw) 索引；Content/Control slot 由 netif_rec[+0x78]（sw idx，hwNetif_add_update_by_swNetif@0x910E8 写入）减 0x10 得到 |

---

## 10. 复现命令与地址速查

```sh
# 语料完整性
sha256sum /mnt/c/rea/fc_mgr.ko /mnt/c/rea/ca-ne.ko

# extra-tag 四个 API + 表头写入
aarch64-linux-gnu-objdump -dr --start-address=0x8dc70 --stop-address=0x8de70 /mnt/c/rea/fc_mgr.ko

# dump 解码（acttype 1..7 的位域/格式串）
aarch64-linux-gnu-objdump -dr --start-address=0x28500 --stop-address=0x28780 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -s -j .rodata.str1.8 --start-address=0x9900 --stop-address=0x9b60 /mnt/c/rea/fc_mgr.ko

# DS-Lite / 6RD 完整 setup
aarch64-linux-gnu-objdump -dr --start-address=0x9a400 --stop-address=0x9ad20 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -dr --start-address=0x9e440 --stop-address=0x9ea90 /mnt/c/rea/fc_mgr.ko

# ACL AddSpecial(0x14) 与 del
aarch64-linux-gnu-objdump -dr --start-address=0xacff0 --stop-address=0xad200 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -dr --start-address=0xaf2a0 --stop-address=0xb0050 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -dr --start-address=0xa99a0 --stop-address=0xa9a60 /mnt/c/rea/fc_mgr.ko

# 删除顺序
aarch64-linux-gnu-objdump -dr --start-address=0x9d770 --stop-address=0x9da40 /mnt/c/rea/fc_mgr.ko

# 表名与保留规则类型空间
aarch64-linux-gnu-objdump -s -j .rodata.str1.8 --start-address=0x28dd0 --stop-address=0x28f50 /mnt/c/rea/fc_mgr.ko
strings -t x /mnt/c/rea/fc_mgr.ko | grep -E "DUAL_HEADER_DS_CHECK|invalid extra tag"

# ca-ne 侧确认"没有 extratag"
nm /mnt/c/rea/ca-ne.ko | grep -i extratag ; strings /mnt/c/rea/ca-ne.ko | grep -i extratag
```

### 地址速查

```
fc_mgr.ko
  RTK_RG_ASIC_EXTRATAGACTION_ADD        .text+0x8DC70   REA 0x18DCB0
  RTK_RG_ASIC_EXTRATAGACTION_DEL        .text+0x8DD80   REA 0x18DDC0
  RTK_RG_ASIC_EXTRATAGACTION_GET        .text+0x8DDB0   REA 0x18DDF0
  RTK_RG_ASIC_EXTRATAGCONTENTBUFFER_SET .text+0x8DDE0   REA 0x18DE20
  RTK_RG_ASIC_EXTRATAGCONTENTBUFFER_GET .text+0x8DE30   REA 0x18DE70
  dump_extratag_table                   .text+0x28500   REA 0x128540
  _rtk_fc_extraTagActionList_empty_find.part.0  .text+0x96BC0  REA 0x196C00
  _rtk_fc_flow_setupGreEthBr            .text+0x96C40
  _rtk_fc_flow_setupPPTP                .text+0x97CA0
  _rtk_fc_flow_setupL2TP                .text+0x98AA0
  _rtk_fc_flow_setupMAPT                .text+0x99750
  _rtk_fc_dualHeader_ctrl_setupIP4InIP6 .text+0x9A2F0
  _rtk_fc_flow_setupIP4InIP6            .text+0x9A400   REA 0x19A440
  rtk_fc_dual_hw_setting                .text+0x9AD20
  rtk_fc_netif_dualConfig_del           .text+0x9D770   REA 0x19D7B0
  rtk_fc_hwNetif_add_update_by_swNetif  .text+0x90E10   ;; 写 netif_rec+0x78 = sw idx
  rtk_fc_dualInfoInit                   .text+0x9DB20
  rtk_fc_dual_control_content_set6RD    .text+0x9E2F0
  _rtk_fc_dualHeader_ctrl_setup6RD      .text+0x9E330   REA 0x19E370
  _rtk_fc_flow_setup6RD                 .text+0x9E440   REA 0x19E480
  _rtk_fc_flow_setupVXLAN               .text+0x9F6D0
  _rtk_rg_aclAndCfReservedRuleDelSpecial .text+0xA99A0
  _rtk_rg_aclAndCfReservedRuleAddSpecial .text+0xACFF0  REA 0x1AD030
  _rtk_fc_g3_caAalClsRuleAdd            .text+0xA6030
  rtk_fc_tables_init                    .text+0x905F0
  rtk_fc_netif_dual_set_6RD             .text+0x95620
  rtk_fc_netif_dual_set_4in6            .text+0x96680

fc_db 偏移（驱动 .bss）
  extra-tag entries        0xBE3664  (16 × 40 B)
  extra-tag content buffer 0xBE38E4  (16 × 64 B)
  netif_rec(n)             0x942FB8 + n*0x168
    +0x04 dual 已配置标志
    +0x3C 外层 IPv6 dst[16] / 6RD 64bit(u32@+0x38,+0x3C)
    +0x4C 外层 IPv6 src[16]
    +0x78 sw netif idx (int8,-1)   ;; rtk_fc_hwNetif_add_update_by_swNetif@0x910E8 写入；slot=此值-0x10
    +0x7C extratag_idx (int8,-1)
    +0x80 path6 idx (int32,-1)
    +0x84 content entry count (u8)
    +0x85 flags: bit2 content installed, bit3 control installed
    +0x88 dualHdr_ds_clsIdx (int32,-1)
    +0x8C dualHdr_ds_extra_clsIdx (int32,-1)
    +0xA0 FMR idx (int8,-1)
  netif 映射表             0x9489B8  (每 sw netif 1 B，bits[7:1]=hw netif)

ca-ne.ko
  l3pe_dual_content_tbl .data+0x32F8  table_id=31 entries=16 entry=64B words=16 base=0xF4303548
  l3pe_dual_control_tbl .data+0x33A0  table_id=32 entries=16 entry=64B words=16 base=0xF4303548
  l3pe_dual_fmr_tbl     .data+0x3448  table_id=33 entries=3  entry=64B words=16 base=0xF4303548
  （无 extratag 表描述符）
```