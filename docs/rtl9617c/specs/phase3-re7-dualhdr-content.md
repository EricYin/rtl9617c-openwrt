# Phase 3 / RE-7：Dual-Header Content 模板、VXLAN、EIF 仲裁

只读逆向 `fc_mgr.ko` + `ca-ne.ko`，为 W8b（flow action → 双头表项）提供可实现的规格。

- 语料 `fc_mgr.ko` SHA-256 `10c4f7f0dc22762de96768e80cb90e7d4203c2b406fccf1197f4fdc2daace479`
- 语料 `ca-ne.ko`  SHA-256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e`
- 两个哈希已实测校验一致；`/opt/rea-snap` 全程未访问；两个构建仓库只读。
- 参照 `phase0-re3-dualhdr-mc-napt6.md` §1/§2/§3，以及里程碑 1 的 `fe/fe_tunnel.c/.h`。

## 0. 地址约定（必读）

| 记号 | 含义 |
|---|---|
| `fc_mgr+0xNNNN` | `nm -n fc_mgr.ko` 的 `.text` 偏移；该节 VMA=0，故等于 objdump 地址 |
| `ca-ne+0xNNNN` | 同上，`ca-ne.ko .text` |
| `NE+0xNNNN` | ca-ne 内部 `adrp x0,48; ldr x0,[x0]` 取到的寄存器窗口基址（本机实测为 `0xf4300000` 段） |
| REA 地址 | `nm 偏移 + 0x100040`（Ghidra 载入基址） |

**重要**：本报告凡标 `observed` 的数值，均由 objdump 逐字面量读出并用 phase0 §1.4 位域表程序化解码复核；
凡标 `UNKNOWN` 的，语料内无足够证据，禁止在 W8b 中猜测填充。

---

## 1. 三表机械结构复核（与 phase0 一致，附两处订正）

数据窗口 `NE+0x3548`（命令字），数据字 `NE+0x354C..0x3588`（16 word，倒序）：

```
for i in 0..15: NE[0x3548 + (16-i)*4] = buf[i]   // buf[0] -> 0x3588, buf[15] -> 0x354C
NE[0x3548] = cmd;  poll bit31 == 0, 1000 次
```

命令字（`__l3pe_dual_hw_entry_set` ca-ne+0x6a390 / `_clear` ca-ne+0x6a270 两份实现一致）：

| 表 | table_id | 写命令 | 合法索引 |
|---|---|---|---|
| Content | 0x1F | `0xC0000000 \| (idx & 0xF)` | 0..15 |
| Control | 0x20 | `0xC0000010 \| (idx & 0xF)` | 0..15 |
| FMR | 0x21 | `0xC0000020 \| (idx & 0x7)` | 0..2 有效（索引空间 8） |

读命令为 `0x80000000` 形式。

### 1.1 订正 A：`aal_l3pe_vxlan_hash1_sport_range_set` 的寄存器是 `NE+0x35E8`，不是 0x35EC

`ca-ne+0x69000`（`aal_l3pe_vxlan_hash1_sport_range_set`）实测：

```
bfxil w2, w0, #0, #16      ; bits[15:0]  = 参数 0 (sport_min)
bfi   w0, w1, #16, #16     ; bits[31:16] = 参数 1 (sport_max)
str   w0, [NE + 0x35E8]
```

即 `0x35E8` 是一个 **两个 16 bit 半字组成的源端口区间**（低半 = 下界，高半 = 上界），
不是 phase0 §3.3 表里写的「0x35EC / 20 bit」。get 函数 `ca-ne+0x69050` 同样读写 0x35E8 并按 16 bit 拆分。

### 1.2 订正 B：`fc_mgr.ko` 根本不编程这些 VXLAN 寄存器

```
$ nm -u fc_mgr.ko | grep -i vxlan
                 U aal_l3pp_vxlan_dport_set          <-- 唯一的 VXLAN API
```

`aal_l3pe_vxlan_hash2_ptn_set` / `aal_l3pe_vxlan_hash1_sport_range_set` **不在 fc_mgr 的导入表里**，
objdump 全量扫描也只命中一处 VXLAN 调用（`fc_mgr+0xc05c4: bl aal_l3pp_vxlan_dport_set`）。
结论：hash1/hash2 pattern 由本语料之外的模块（推测 rtk.ko 或 ca-ne 内部 init）配置，或保持硬件默认。
**W8b 不应写这些寄存器**（见 §4.3）。

---

## 2. 每类隧道的 Content 模板

### 2.1 总表

Content 表存放「待插入的双头原始字节」，硬件按 Control 的 `hdr_fmt/hdr_len/*_ost` 解释。
**不透明数据、无字段级定义**（phase0 §1.3 已确立）。

| 类型 | Content 是否有固定字面量模板 | 证据 |
|---|---|---|
| **DS-Lite / IP4InIP6** | **是**（4 个 word 字面量 + 32 字节来自 tunnel 参数） | `fc_mgr+0x9a4a0..0x9a5a0`，见 §2.2 |
| **6RD** | **是：全 0**（64 字节全零） | `fc_mgr+0x9e2f0` `rtk_fc_dual_control_content_set6RD`，见 §2.3 |
| **MAP-T** | **否**（运行期构建，字面量未闭合） | 见 §2.4 |
| **VXLAN** | **否**（由 `rtk_fc_vxlan_get_outer_content` 从 tunnel 设备参数逐字段拼装）；可跨 **2 个 Content 槽** | `fc_mgr+0xbf540` + `fc_mgr+0x9f340`，见 §4 |
| **PPTP** | **否**（栈上构建后 `aal_pe_dual_content_entry_add`） | `fc_mgr+0x97fb0` |
| **L2TP** | **否**（同上，且先 del 再 add） | `fc_mgr+0x98dac..0x98db0` |
| **GRE_ETH_BR / IPSEC / XLAT464 / SRV6** | 未逐条展开（SRV6 有两槽，`fc_mgr+0xa0478/0xa0604`） | UNKNOWN |

Content add 调用点全集（objdump 全量扫描，共 9 处 + 1 处 FMR）：

```
fc_mgr+0x97fb0  flow_setupPPTP      fc_mgr+0x98db0  flow_setupL2TP
fc_mgr+0x9983c  flow_setupMAPT      fc_mgr+0x9a61c  flow_setupIP4InIP6
fc_mgr+0x9e660  (6RD 路径)           fc_mgr+0x9f398  content_setVXLAN (槽 0)
fc_mgr+0x9f528  content_setVXLAN (槽 1)  fc_mgr+0xa0478/0xa0604 (SRV6 两槽)
fc_mgr+0xc91e0  aal_pe_dual_fmr_entry_add (FMR)
```

### 2.2 DS-Lite：完整、已验证的 Content 模板 `observed`

构建点 `_rtk_fc_flow_setupIP4InIP6` `fc_mgr+0x9a4a0..0x9a5a0`（REA: `_rtk_fc_flow_setupIP4InIP6` @ 0x1aa330 段内）。
16 word 缓冲区基址 `sp+0xc8`，前 40 字节被填满，其余 24 字节为 0。

```
9a554: mov  w1, #0x60
9a558: str  w1, [sp, #200]        ; [buf+0]  = 0x00000060
9a55c: mov  w4, #0xffffff04
9a568: strh w4, [sp, #206]        ; [buf+6]  = 0x04, [buf+7] = 0xff
9a560: add  x1, x0, x2            ; x2 = fc_db + 0x943004
9a564: add  x0, x0, x3            ; x3 = fc_db + 0x942ff4
9a578: ldp  x2, x3, [x1]          ; 16 B @ record+0x10
9a57c: stp  x2, x3, [sp, #208]    ; -> buf[8..23]
9a580: ldp  x0, x1, [x0]          ; 16 B @ record+0x00
9a584: stp  x0, x1, [sp, #224]    ; -> buf[24..39]
```

`record = fc_db + 0x942ff4 + netif * 0x168`（stride 0x168）。

**Content word0..15 模板（DS-Lite）**

| word | 值 | 含义 |
|---|---|---|
| 0 | `0x00000060` | 外层 IPv6：version=6, TC/FlowLabel=0 |
| 1 | `0xFFFF0400` | payload_len=0（硬件填）, next_hdr=**0x04 (IPv4)**, hop_limit=**0xFF** |
| 2..3 | `record[0x10..0x1F]` | 外层 IPv6 **源地址**（16 B） |
| 4..5 | `record[0x00..0x0F]` | 外层 IPv6 **目的地址**（16 B） |
| 6..15 | `0x00000000` | 补零（hdr_len=40，只用前 40 B） |

**语义要点（重要）**：`next_hdr = 4` 表示这是**纯 IPv4-in-IPv6 封装，外层没有 UDP**
（不是 RFC 6333 的 DS-Lite softwire 形态）。枚举名 `RTK_FC_DUALTYPE_IP4INIP6` 与此一致。
`hop_limit = 0xFF` 是 OEM 常量。
→ 来自 tunnel key 的字段**只有两个 IPv6 地址**；其余全是常量。

### 2.3 6RD：Content 全零 `observed`

`rtk_fc_dual_control_content_set6RD` `fc_mgr+0x9e2f0`：

```
ldr  w1, [x1, #260]     ; netif 的 dualType 字段
cmp  w1, #0x7           ; 必须是 6RD
b.eq 9e304
mov  w0, #0            ; 类型不匹配：直接返回 0（不做任何事）
...
9e318: bl memset        ; memset(buf, 0, len)
```

即 **6RD 的 Content 条目 16 个 word 全部为 0**，外层 IPv4 头完全由硬件按 Control 描述合成。
这与 §3.3 求出的 `hdr_len=20`（外层 IPv4 头 20 B）自洽。
→ 来自 tunnel key 的字段**不出现在 Content 里**，全部通过 Control 的 6RD 字段从报文推导。

### 2.4 MAP-T：Content 未闭合 `UNKNOWN`

`_rtk_fc_flow_setupMAPT` 在 `fc_mgr+0x9983c` 调用 `aal_pe_dual_content_entry_add`，
缓冲区在函数前段构建，但分支依赖入参（前缀长/PSID），本次未展开到字面量级。
**W8b 不得猜测 MAP-T Content**；MAP-T 必须先用 §3.4 的 Control + FMR 三表联调，并上机 readback 才能定稿。

---

## 3. 各类 Control 字段推导

### 3.1 位域表可信度判定方法

用 phase0 §1.4 的 34 字段表对**原始 4 word** 做程序化解码，与 phase0 §3.2 的字段值比对。
DS-Lite 32 个字段**全部吻合**（含 `inr_to_out_fld=0x30`、`hdr_len=40`、`mc_mac_map=1`、`dsl_mc_chk=1`），
证明「位域表 + 原始字面量」这条链路正确。6RD 有 5 个字段不吻合（见 §3.3 订正 C）。

### 3.2 DS-Lite Control：原始向量 `observed`

`_rtk_fc_dualHeader_ctrl_setupIP4InIP6` `fc_mgr+0x9a2f0`，缓冲区 `sp+0x28`，先 `stp xzr,xzr` 清零 64 B：

```
9a374: mov  x5, #0xfcc1 ; movk #0x5,lsl16 ; movk #0x4000,lsl32 ; movk #0xfc00,lsl48
9a360: mov  x3, #0x80ff ; movk #0xe03f,lsl16 ; movk #0x1fff,lsl32 ; movk #0x280,lsl48
9a390: stp  x5, x2, [sp, #0x28]      ; word0..1 = x5, word2..3 = x2(=x3)
9a3a0: bl   aal_pe_dual_control_entry_add
```

| word | 值 |
|---|---|
| 0 | `0x0005FCC1` |
| 1 | `0xFC004000` |
| 2 | `0xE03F80FF` |
| 3 | `0x02801FFF` |
| 4..15 | `0x00000000` |

解码（与 phase0 §3.2 的 DS-Lite 列**完全一致**）：
`hdr_fmt=0`、`hdr_len=40`、`mtu_diff=0`、`ppp_ip_ver_ost=0x7F`、`rep_ip_en=1`、`rep_ip_ver=1`、
`rep_len_ost1=0x7F`、`rep_len_diff1=0`、`rep_len_ost2=0x7F`、`rep_len_diff2=0`、`ip4_ost=0x7F`、
`gre_seq_ack_ost=0x7F`、`gre_mod_fld=0`、`ip6_oft=0`、`rep_ip_dscp_en=0`、`rep_ip_ecn_en=0`、
`rep_ip_len=1`、`rep_ip_len_diff=0`、`rep_ip_ptc=0`、`rep_ip_ttl=0`、`mapt_pre_len=0`、`map_drf_ver=0`、
`6rd_dip_pre_len=0`、`6rd_dip_suf_str_bit=0`、`dsl_uc_chk=0`、`dsl_mc_chk=1`、`l4sum_rec=0`、
`vxlan_sp_ost=0x7F`、`inr_to_out_fld=0x30`、`tos_hsh_sel=0`、`mc_mac_map=1`。

**推导性质**：DS-Lite 的 Control **没有任何字段来自 tunnel key**，是一组纯常量。
tunnel 差异只体现在 Content 的两个 IPv6 地址上。这是 W8b 最容易落地的一类。

### 3.3 6RD Control：原始向量 `observed`（与 phase0 §3.2 冲突，订正 C）

`_rtk_fc_dualHeader_ctrl_setup6RD` `fc_mgr+0x9e330`：

```
9e344: mov  x3, #0x9001 ; movk #0x453f,lsl16 ; movk #0x1fe0,lsl32 ; movk #0x140,lsl48
9e36c: mov  x5, #0xfec0 ; movk #0x801,lsl16  ; movk #0xca00,lsl32 ; movk #0xfcff,lsl48
9e360: stp  xzr, xzr, [sp, #40]      ; 清 buf[0..15]
9e374: add  x1, sp, #0x28
9e394: stp  x5, x2, [sp, #40]        ; word0..1 = x5, word2..3 = x3
```

| word | 值 |
|---|---|
| 0 | `0x0801FEC0` |
| 1 | `0xFCFFCA00` |
| 2 | `0x453F9001` |
| 3 | `0x01401FE0` |
| 4..15 | `0x00000000` |

解码结果：

| 字段 | 本报告实测 | phase0 §3.2 | 判定 |
|---|---|---|---|
| hdr_fmt | **0** | 2 | **冲突** |
| hdr_len | **20** | 64 | **冲突** |
| mtu_diff | **0** | 15 | **冲突** |
| ppp_ip_ver_ost | **0x7F** | 120 | **冲突** |
| rep_ip_en / rep_ip_ver | **1 / 0** | 0 / 0 | **冲突** |
| rep_len_ost1 / rep_len_diff1 | 2 / 20 | 2 / 20 | 一致 |
| rep_len_ost2 / rep_len_diff2 | 0x7F / 16 | 0x7F / 16 | 一致 |
| ip4_ost | 0 | 0 | 一致 |
| gre_seq_ack_ost | 0x7F | 0x7F | 一致 |
| gre_mod_fld | 0 | 0 | 一致 |
| ip6_oft | 0x7F | 0x7F | 一致 |
| rep_ip_dscp_en/ecn_en/len | 1/1/1 | 1/1/1 | 一致 |
| rep_ip_len_diff | 20 | 20 | 一致 |
| rep_ip_ptc / rep_ip_ttl | 0 / 0 | 0 / 0 | 一致 |
| mapt_pre_len / map_drf_ver | 0 / 0 | 0 / 0 | 一致 |
| 6rd_dip_pre_len / suf_str_bit | 0 / 32 | 0 / 32 | 一致 |
| dsl_uc_chk / dsl_mc_chk | 0 / 0 | 0 / 0 | 一致 |
| l4sum_rec | 0 | 0 | 一致 |
| vxlan_sp_ost | 0x7F | 0x7F | 一致 |
| inr_to_out_fld | 0xB0 | 0xB0 | 一致 |
| tos_hsh_sel / mc_mac_map | 0 / 0 | 0 / 0 | 一致 |

**采信实测的理由（语义自洽性）**：
1. 6RD 外层是 IPv4，所以 `hdr_len = 20`（外层头长度）符合与 DS-Lite `hdr_len=40`（外层 IPv6 长度）相同的语义；
   phase0 的 64 既不是 20 也不是 20+40。
2. `rep_len_ost1=2 / rep_len_diff1=20` 正好是「IPv4 头 offset 2 的 total_length 字段 += 20」，
   20 就是被插入的内层 IPv6 头长度。语义完美吻合。
3. phase0 的 `ip4_ost=0` 与 `hdr_len=64`、`rep_ip_en=0` 三者互相矛盾：
   6RD 必须改写外层 IPv4 源地址（否则 `6rd_dip_suf_str_bit=32` 失去意义），`rep_ip_en` 必须为 1。
4. 任何对 `x3` 的简单移位都**不能**复现 phase0 的整行（例如把 word3 左移 4 位后 `mtu_diff` 得 8 而非 15），
   说明 phase0 的 6RD 行不是从这份字面量推出的，属转录/串行错误。

> **对 W8b 的直接影响**：里程碑 1 的 `rtl_fe_dual_control_preset_6rd()`（`fe/fe_tunnel.c:479-498`）
> 逐条照抄了 phase0 §3.2 的 6RD 行，因此 **hdr_fmt/hdr_len/mtu_diff/ppp_ip_ver_ost/rep_ip_en/rep_ip_ver 六个字段是错的**。
> 应按本表改为 `hdr_fmt=0, hdr_len=20, mtu_diff=0, ppp_ip_ver_ost=0x7F, rep_ip_en=1, rep_ip_ver=0`。

### 3.4 MAP-T Control：结构化但参数化 `derived`

`_rtk_fc_dualHeader_ctrl_setupMAPT` `fc_mgr+0x995c0`。基础向量：

```
995c4: mov  x5, #0x4060 ; movk #0xfc00,lsl16 ; movk #0x80ff,lsl32 ; movk #0xe03f,lsl48
995d8: mov  w6, #0x3f   ; movk w6, #0x1285, lsl16
```

→ 基础 word1=`0xFC004060`、word2=`0xE03F80FF`、word3=`0x1285003F`、word0=`0`。

随后按入参分派（注意 `cmp w2,#0x20; b.eq 0x99728`、`sub w4,w2,#0x28; cmp w4,#0x38` 两条前置分支）：

```
99654: ubfiz x1, x1, #33, #1        ; 参数1 bit0 -> word1 bit1 (map_drf_ver)
99670..99680: 注入 0x0003FE01 -> word0, 并 OR 0x1FC000000000 -> word3
```

落到「参数分支」时解码得：`hdr_fmt=2`、`hdr_len=40`、`mtu_diff=40`、`ppp_ip_ver_ost=0`、
`rep_ip_en=1`、`rep_ip_ver=1`、`rep_ip_len=1`、`rep_ip_ptc=1`、`rep_ip_ttl=1`、`map_drf_ver=1`、
`l4sum_rec=1`、`inr_to_out_fld=0x80`、`mc_mac_map=1`，其余为 0/0x7F。

**结论**：MAP-T 的 Control **确实由入参决定**，且 `inr_to_out_fld` 实测为 **0x80**（phase0 写的 0x10 未复现）。
哪些字段来自 tunnel key、哪些是常量，**未闭合 → UNKNOWN**。
MAP-T 另有硬约束：FMR 表只有 **3 条**（`l3pe_dual_fmr_tbl` 描述符 +0x10 = 3），
故 MAP-T 规则总数上限 3（索引空间 8，合法 0..2）。

### 3.5 PPTP / L2TP Control

`_rtk_fc_dualHeader_ctrl_setupPPTP` `fc_mgr+0x97af0`、`_rtk_fc_dualHeader_ctrl_setupL2TP` `fc_mgr+0x98890`。
两者均为编译器优化的多路 `bfi/ubfiz/and/orr` 位域拼装（PPTP 起始 `mov w3,#8`，随后 `add w3,w3,#0x14`
＝ 8/28 两档 hdr_len；L2TP 同构），**字面量到字段的映射未逐项闭合 → UNKNOWN**。
已确认的结构事实：
- PPTP 读 `netif+424` 与 `#1` 比较做分支（PPP 相关标志）。
- 两者都只写 Control（Content 由各自的 `flow_setup*` 另行构建，见 §2.1）。
- `_rtk_fc_flow_setupL2TP` 在 add 之前先 `aal_pe_dual_content_entry_del`（`fc_mgr+0x98da4`），
  即「覆盖写之前先删」的既有习惯。

---

## 4. VXLAN 专项

### 4.1 VXLAN 入口链（fc_mgr）

```
_rtk_fc_netif_dual_set_VXLAN          fc_mgr+0x95820
  -> _rtk_fc_dualHeader_dual_content_setupVXLAN  fc_mgr+0x9f5a0
       -> rtk_fc_vxlan_get_outer_content         fc_mgr+0xbf540   (构建外层头字节)
       -> rtk_fc_dual_control_content_setVXLAN   fc_mgr+0x9f340   (1 或 2 槽)
  -> _rtk_fc_dualHeader_dual_ctrl_setupVXLAN     fc_mgr+0x9ed20
       -> rtk_fc_dual_control_entry_setVXLAN     fc_mgr+0x9ea90   (Control 字面量在此)
rtk_fc_dualHash_VXLAN                 fc_mgr+0x93cd0
rtk_fc_netdev_check_vxlan_dev         fc_mgr+0x9a20 / _get_vxlan_dev_vni fc_mgr+0x9ae0
```

索引换算（`fc_mgr+0x9f620`、`0x9ed68`）：**Content 索引 = Control 索引 = `netif_idx − 0x10`**
（即 netif 16..31 映射到表槽 0..15）。

### 4.2 VXLAN Content：动态拼装 + 双槽溢写 `observed`

`rtk_fc_vxlan_get_outer_content(int len, void *priv)` `fc_mgr+0xbf540`：
`memset(priv+0x1f0, 0, len)` 之后按 priv 里的头部指针逐段拷贝：

| priv 偏移 | 内容 | 目标 |
|---|---|---|
| +0x78 | 以太网头（14 B 由两次 8 B 重叠拷贝完成） | buf[0..13] |
| +0x80 | 外层 IPv4 头前 4 B | buf[14..17] |
| +0x88 | IPv4 id/frag | buf[18..21] |
| +0x90 | IPv4 其余 + TTL/proto | 顺序写 4+2+2 B |
| +0x60 / +0x70 | 内层 IPv4 / IPv6 头（0x14 或 0x28 B） | 顺序 |
| +0x68 | UDP 头（`& 0xffffffffffff`，注释串 "Set outer udp checksum = 0!"） | 顺序 |
| +0x1b0 | 内层以太网头 8 B | 顺序 |

**没有固定字节模板**：`ethertype`（0x0800/0x86DD）、协议号、UDP 校验和 0 是常量，
MAC/IP/端口/VNI 全部来自 tunnel 设备参数。
返回值：成功 0；以下任一为真时返回 **`0xFFFFFFFF`（即 -1）**，这是 OEM 自己的「缺键即拒绝」：
- `priv == NULL`
- `priv+0x78 == NULL`（无以太网头信息）
- `priv+0x60 == NULL && priv+0x70 == NULL`（内层既非 IPv4 也非 IPv6）
- `priv+0x1b0 == NULL`（无内层以太网头）

`rtk_fc_dual_control_content_setVXLAN(idx, buf, len, 0x40)` `fc_mgr+0x9f340`：

```
min(len,64) 拷入 64 B 栈缓冲 -> aal_pe_dual_content_entry_add(idx, buf)
if (len > 0x40) { 再拷 buf+0x40 共 (len-0x40) B -> aal_pe_dual_content_entry_add(idx+1, ...) }
```

**结论**：VXLAN 外层头最长可跨**两个连续 Content 槽**（idx 与 idx+1），
所以 W8b 分配 VXLAN Content 时必须**成对预留**，且删除时也要删两槽（§7 已见 OEM 如此做）。

### 4.3 VXLAN Control 字段来源 `derived`

`rtk_fc_dual_control_entry_setVXLAN` `fc_mgr+0x9ea90`，缓冲区 `sp+0x38`：

```
9eae8: ldrb w3, [x22,#444]       ; 外层头长度
9eb00: and  w0, w0, #0xe000000f
9eafc: ubfiz w3, w3, #20, #7     ; -> bits 116..122 = hdr_len
9eaf0: mov  w1, #0x1fc0 ; movk w1, #0x800, lsl16   ; 0x08001FC0
9eb0c: orr  w1, w1, w0
9eb10: str  w1, [sp, #68]        ; -> word3 (buf offset 0x0c)
```

| 字段 | 来源 | 值 |
|---|---|---|
| `hdr_len` | `priv[444] & 0x7F` | 外层头字节数（与 Content 的 len 同一字段） |
| `hdr_fmt` | 字面量 `0x08001FC0` bit27 | **1** |
| `ppp_ip_ver_ost` | 同上 bits 102..108 | `0x7F`（N/A） |
| `rep_len_ost1` | `bfi x3,#29,#7` ← `0x12 + flags(priv[456])` | 0x12 起，随 flags 变化 |
| `rep_len_diff1` | `bfi w4,#22,#7` ← `0x26` 或 `0x3A`（由 `priv[456]` bit0 选） | 38 或 58 |
| `vxlan_sp_ost` | bits 10..17 由 `sbfiz x2,x2,#10,#8` 写入 | 见 §4.4 |
| `inr_to_out_fld` | `orr x2,x2,#0x1FC` + 参数 | 部分由 flags 决定 |

`priv[456]` 的三个位分别控制 rep_len_ost1 的追加量、rep_len_diff1 取值、以及 inr_to_out_fld 一位。

`_rtk_fc_dualHeader_dual_ctrl_setupVXLAN` `fc_mgr+0x9ed20` 完成前置检查与后置标志：
- 检查 `priv[8]` 的 7 bit（`ubfx #1,#7`）= hash 索引，取 `fc_db + hash*0x168 + 0x943000 + 61` 的标志字节；
- `tbz #3` → 若 **bit3 已置位表示 Control 已装过**，跳过（幂等）；
- 成功后 `orr #0x8` 置 **bit3**（`fc_mgr+0x9ee4c`）。
  对应地 Content 路径用 **bit2 (0x4)** 标记已装（`fc_mgr+0x9f650`）。
  → **每个 hash 记录有一字节标志：bit2=Content 已装，bit3=Control 已装。**

### 4.4 `vxlan_sp_ost` / `RTL_FE_VXLAN_SPORT_MSB` / `..._UPDATE_EN` 的配合

- `vxlan_sp_ost`（Control bits 16..10，7 bit，N/A=0x7F）＝**外层 UDP source port 在双头区内的字节偏移**，
  硬件据此定位并改写 UDP 源端口。
- `RTL_FE_VXLAN_SPORT_MSB` 与 `RTL_FE_VXLAN_SPORT_UPDATE_EN` **不是** Control 字段，而是 **FE action 字段**：
  开源 `fe/fe_hw.h:154-155` 的 `enum rtl_fe_action_field` 中紧跟 `RTL_FE_DIP_REMAP_VLD/RTL_FE_DIP_REMAP`
  之后，说明它们在 **L3 flow action** 侧。
- 配合关系（`derived`）：`..._UPDATE_EN` = 使能「按 hash 结果改写 VXLAN 源端口」；
  `..._SPORT_MSB` = 提供源端口高位/熵源选择；`vxlan_sp_ost` 告诉硬件字段位置；
  `NE+0x35E8` 的 sport 区间限定改写后的取值范围。
- 语义细节（MSB 的具体位宽、UPDATE_EN 与 hash1/hash2 的选择关系）**UNKNOWN**。

### 4.5 hash2 pattern 寄存器 0x35EC/0x35F0/0x35F4/0x35F8 `observed`

`aal_l3pe_vxlan_hash2_ptn_set(idx, val)` `ca-ne+0x690c0`：

| idx | 寄存器 | 掩码 | 写入宽度 |
|---|---|---|---|
| 0 | `NE+0x35EC` | `0xFFFFF` | **20 bit** |
| 1 | `NE+0x35F0` | `0xFFFFF` | **20 bit** |
| 2 | `NE+0x35F4` | `0xFFFFFF` | **24 bit** |
| 3 | `NE+0x35F8` | `0xFFFFFF` | **24 bit** |
| >3 | — | — | **静默返回 0，不写寄存器**（易错点） |

`aal_l3pe_vxlan_hash1_sport_range_set/get` `ca-ne+0x69000/0x69050` → `NE+0x35E8` 双 16 bit 区间（§1.1）。

**20/24 bit 模式的具体语义 = UNKNOWN**。已知事实：VNI 为 24 bit，因此 idx2/idx3 的 24 bit pattern
最可能承载 VNI；idx0/idx1 的 20 bit 疑似另一层熵源（如内层 IPv4 ID / 流标签），无证据。
**并且 fc_mgr 不编程这些寄存器（§1.2），W8b 不得写。**

---

## 5. EIF 仲裁（hash 32..63 / 物理行 16..31）

### 5.1 硬件容量与映射 `observed`

- `fe_l3e_if_tbl_table` @ `ca-ne .data+0x3c28`：table_id **13 (0x0d)**、条目数 **32 (0x20)**、
  1 word/条、寄存器基址 `0xf4303000`，经 `0xf430b058`(data)/`0xf430b060`(cmd) 访问。
  → 物理行 0..31。
- `hashIntfIdx2HwIntfIdx_mapping` @ `fc_mgr .rodata+0x5640`，64 B（本次独立 dump 复核）：

```
5640  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
5650  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
5660  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
5670  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
```

等价于 `phys = (hash < 32) ? hash : 16 + (hash & 0x0F)`。
→ 物理行 16..31 每行被 **3 个** hash 索引共享（`16+x`、`32+x`、`48+x`）。

### 5.2 关键否定结论：OEM 在本语料内**没有**实现这套仲裁 `observed`

两条独立证据：

1. **该表在 fc_mgr.ko 内没有任何代码引用**。
   `objdump -dr fc_mgr.ko` 共 4672 条 `.rodata` 重定位，检索 `rodata+0x5640`（精确）
   以及 adrp/add 拆分形式（`rodata+0x5000` + `rodata+0x640`）**均无命中**。
   → 该表是**未被引用的数据**。
2. **fc_mgr 从不触碰 EIF 表**：`nm -u fc_mgr.ko` 中没有 `aal_fe_l3e_if_tbl_*` 任何符号；
   它只用 `aal_pe_dual_{content,control,fmr}_entry_{add,del,get}` 操作三张双头表。

因此「物理行 16..31 的兼容共享判定 + refcount」**在 fc_mgr.ko 中没有实现**，
`phase0 §2.3` 的「共享必须兼容」是从映射表推出的**结构性推论（derived）**，不是 observed 行为。

### 5.3 hash 32..63 的触发条件

`rtk_fc_dualHashKey(int dualType, void *key)` `fc_mgr+0xa1060`：

- 对 key 结构（偏移 0x00..0x32）做 **XOR 折叠 + ADD 混合**，输出 16 bit 哈希（`and w0,#0xffff`）。
- 同时 `strb w3, [x1, #52]` 把 `dualType` 存回 key+52。
- `cmp w3,#0x8`（MAP-T）时有独立分支；MAP-T/XLAT 另有 `rtk_fc_dualHashKey_remap_MAPT_XLAT`
  `fc_mgr+0xa1040`（`(w0 & 0xffff) ^ (w0 >> 16)`，按 8 bit 参数决定是否再左移 16）。
- 配套：`rtk_fc_netif_dualHashKey_config_byPktHdr` `fc_mgr+0xa1150`、
  `rtk_fc_netif_update_dualinfo_by_dualHashKey` `fc_mgr+0xa1900`、
  `_rtk_fc_flow_hashIndex_byDualPktOuterHdr` `fc_mgr+0x42fd0`。

`derived`：正常流用 hash 0..31（开源驱动 `FE_INTERFACES=32` 也只用到 31）；
hash 32..63 是「按外层头再哈希」得到的**别名**，落在同一批物理行上。
**哪个函数把 hash 值选到 32..63、以及何时选，UNKNOWN**（本语料无可读判定逻辑）。

### 5.4 如何避免与普通流冲突（给 W8b 的工程结论）

因为 OEM 无实现、且物理行只有 32 条，W8b 必须自己建立仲裁。可安全采纳的最小方案：

1. **hash 0..15 与物理行 0..15 一对一，留给普通流**；双头隧道只用 hash 16..31（物理行 16..31）。
2. **绝不复用 32..63**：映射表证明 32..63 不带来任何额外物理行，用了只会引入「三个用户抢一行」的
   隐性冲突。里程碑 1 的 `rtl_fe_eif_phys()` 只做换算、不做分配，是正确的边界。
3. 物理行 16..31 的共享判据：**只有 EIF 参数（1 word）逐位相同才允许共享**，
   维护每行 refcount，refcount 归零才真正写回/清行。
4. 与普通流争用时**双头优先或普通流优先必须显式选定并记录**——OEM 无证据，属产品决策（UNKNOWN）。

---

## 6. FE flow action → 双头表项映射

### 6.1 映射表（`derived`，以 §2/§3/§4 的实测字段为锚）

| Linux flow API | 目标字段 | 适用类型 |
|---|---|---|
| `FLOW_DISSECTOR_KEY_ENC_CONTROL`（`enc_ip_version`, `addr_type`） | 选外层 IP 版本 → Content 的 version 半字节、Control 的 `hdr_fmt` 与 `ip4_ost`/`ip6_oft` 二选一 | 全部 |
| `FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS` | Content 外层 IPv4 src/dst（`rtk_fc_vxlan_get_outer_content` 的 priv+0x80/0x88/0x90 一路） | 6RD / VXLAN(IPv4 外层) |
| `FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS` | Content bytes 8..23 / 24..39 | DS-Lite / MAP-T |
| `FLOW_DISSECTOR_KEY_ENC_IP`（proto/tos/ttl） | `rep_ip_ptc` / `rep_ip_ttl` / `rep_ip_dscp_en` / `rep_ip_ecn_en` | MAP-T（实测 ptc=1, ttl=1） |
| `FLOW_DISSECTOR_KEY_ENC_TCP` / `ENC_UDP` | 外层 L4 存在性与协议号 → 决定 `hdr_len` 与 `l4sum_rec` | VXLAN / L2TP |
| `FLOW_DISSECTOR_KEY_ENC_PORTS`（`enc_src_port`） | `vxlan_sp_ost` 定位 + `RTL_FE_VXLAN_SPORT_UPDATE_EN` + `RTL_FE_VXLAN_SPORT_MSB` + `NE+0x35E8` 区间 | VXLAN |
| `FLOW_ACTION_TUNNEL_ENCAP`（`tunnel_key id` = VNI） | VXLAN 头 VNI 字节（`priv+0x1b0` 内层以太网之后） | VXLAN |
| `FLOW_ACTION_TUNNEL_DECAP` | 反向：`hdr_len` + `ip4_ost`/`ip6_oft` 的剥离语义；Content 通常置零（6RD 即全零） | 全部 |
| 隧道 MTU / `dst_mtu` | `mtu_diff`（7 bit，上限 127） | 6RD（实测 0）等 |

### 6.2 哪些键缺失时必须拒绝（有 OEM 依据）

`rtk_fc_vxlan_get_outer_content` 的 `0xFFFFFFFF` 返回就是 OEM 的拒绝条件（§4.2），可据此定规则：

| 类型 | 必须存在的键 | 依据 |
|---|---|---|
| **VXLAN** | `ENC_CONTROL`（外层版本）、`ENC_IPV4_ADDRS` 或 `ENC_IPV6_ADDRS`、`ENC_UDP`+`ENC_PORTS`（sport/dport）、`TUNNEL_ENCAP` 的 VNI、以及内层 L2/L3 头信息 | `fc_mgr+0xbf540` 的四个 NULL 检查 |
| **DS-Lite / MAP-T** | 外层 IPv6 src+dst（否则 Content 两个 16 B 段无来源） | `fc_mgr+0x9a578` 两次 16 B 载入 |
| **6RD** | 外层 IPv4 src/dst + `6rd_dip_pre_len`/`suf_str_bit` 类参数 | §3.3 的 6RD 字段 |
| **全部** | Control 槽与 Content 槽都分配成功（**成对**）；VXLAN 还需 idx+1 | §4.2、§7 |

**硬性拒绝**（不可绕过）：`hdr_len > 127`（7 bit）、任一 `*_ost > 127`（7 bit）、
`mtu_diff > 127`、Control/Content 槽耗尽（各 16）、MAP-T FMR 耗尽（3）。
这些是字段宽度推出的**确定上限**，不是经验值。

---

## 7. clear-on-free 时序

### 7.1 `__l3pe_dual_hw_entry_clear` ca-ne+0x6a270 实测

```
cbz  x0, -> -1                      ; desc NULL
ldr  x2,[x0,#136]; cbz -> -1        ; 数据窗口基址
ldr  w2,[x0,#16];  cmp w2,w1; b.ls -> -9   ; idx >= entry_count -> -EINVAL
loop i in 0..word_count-1:          ; word_count = desc[+36] = 16
    w5 = (table_id == 0x21) ? 0xFFFFFFFF : 0    ; csetm w5, eq
    NE[base + ((word_count - i) << 2)] = w5
cmd = table 0x20 ? (0xC0000010 | idx&0xF)
    : table 0x21 ? (0xC0000020 | idx&0x7)
    : (table 0x1F ? (0xC0000000 | idx&0xF) : 0)
NE[base] = cmd ; poll bit31 == 0, 计数 1000 -> 超时 -11
```

**结论：clear-on-free 可用，且不需要任何特殊寄存器。**
它就是「把 16 个 word 写成 0（FMR 表写成 0xFFFFFFFF）后写写命令字」，
与正常写入同一路径 —— 我们的 `rtl_fe_dual_hw_write(fe, sel, idx, 全零数组)` 等价于 OEM 的 clear。
注意 **FMR 的清零值是 0xFFFFFFFF 而不是 0**，W8b 若复用同一 helper 必须按表区分。

### 7.2 先清哪张表：**先 Control，后 Content** `observed`

`rtk_fc_netif_dualConfig_del` `fc_mgr+0x9d770` 的调用顺序：

```
9d830: bl aal_pe_dual_control_entry_del     <-- 1st  Control
9d864: bl aal_pe_dual_content_entry_del     <-- 2nd  Content (槽 idx)
9d884: bl aal_pe_dual_content_entry_del     <-- 3rd  Content (槽 idx+1, VXLAN >64B 溢写槽)
```

### 7.3 为什么必须是这个顺序（`derived`，重要安全点）

**把 Control 清成全 0 并不等于「关闭」。** 全 0 解码为 `hdr_fmt=0, hdr_len=0, 所有 *_ost=0`，
而 DS-Lite 本身就是 `hdr_fmt=0` —— 即「零 Control」是一个**语法合法**的 profile，
清掉它不会让硬件把这个槽当成未使用。因此：

1. **真正的安全来自先删 flow 条目**（让没有任何 action 再引用这个槽）；表内清零只是卫生。
2. 在 flow 已删的前提下，先 Control 后 Content 与 OEM 一致；
   若在 flow 未删的窗口内必须动，**先 Control 后 Content** 至少能让硬件立刻停止按旧描述改写外层头，
   而残留的 Content 字节不会被解释。
3. 反向顺序（先 Content）会出现「Control 仍指向一个按旧 hdr_len 解释、但内容已清零」的窗口，
   可能把全零外层头注入报文 —— 这是我们必须避免的。

**W8b 强制时序**：`删 flow entry` → `Control 清 0` → `Content 清 0`（VXLAN 再清 idx+1）→ `释放 refcount/位图`。

---

## 8. 可实现性分类与 W8b 分步建议

### 8.1 分类

**A. 可实现（Content 模板 + 字段映射齐备）**

| 项 | 依据 | 备注 |
|---|---|---|
| **DS-Lite / IP4InIP6** | §2.2 完整 Content 向量 + §3.2 完整 Control 向量；Control 全常量 | **最安全，建议第一个做** |
| **6RD** | §2.3 Content 全零 + §3.3 完整 Control 向量 | 但必须先修正里程碑 1 的 6RD preset（§3.3 订正 C） |
| **通用表管理/清表** | §7 全路径实测 | 已由里程碑 1 覆盖，补 clear-on-free 与时序即可 |

**B. 只能 raw / debugfs（结构已知、字面量未闭合）**

| 项 | 原因 |
|---|---|
| **VXLAN** | Content 由 tunnel 参数动态拼装（无固定模板，§4.2）；Control 多个字段来自 `priv[444]/priv[456]` 的私有布局；且 Content 成对占用。可用 debugfs `content-raw`/`control-raw` + 上机 readback 验证，但不宜直接进 flow 路径 |
| **MAP-T** | Control 参数化未闭合（§3.4）、Content 未闭合（§2.4）+ FMR 仅 3 条 |
| **PPTP / L2TP** | Control 位域拼装未逐项闭合（§3.5） |
| **GRE_ETH_BR / IPSEC / XLAT464 / SRV6** | 本次未展开 |
| **EIF hash 32..63 别名** | OEM 无实现（§5.2），任何「自动仲裁」都是我们发明的语义 |

**C. 不可实现 / 不得实现（缺证据）**

| 项 | 原因 |
|---|---|
| `NE+0x35EC/0x35F0/0x35F4/0x35F8` 的 20/24 bit pattern 语义 | 语义 UNKNOWN 且 fc_mgr 从不编程（§1.2、§4.5）→ **禁止写** |
| `RTL_FE_VXLAN_SPORT_MSB` 位宽/取值语义 | 仅知是 action 字段，语义 UNKNOWN |
| 物理行 16..31 的「兼容共享 + refcount」 | OEM 无实现（§5.2）；只能按 §5.4 自建 |
| MAP-T 超过 3 条规则 | FMR 表硬上限 3 |
| `hdr_len > 127` 或 `*_ost > 127` | 字段宽度硬上限 |

### 8.2 给 W8b 的分步实现建议

**Step 0（前置修复，必须先做）**
修正 `fe/fe_tunnel.c` 的 `rtl_fe_dual_control_preset_6rd()`（§3.3 订正 C）：
`hdr_fmt 2→0`、`hdr_len 64→20`、`mtu_diff 15→0`、`ppp_ip_ver_ost 120→0x7F`、
补 `rep_ip_en=1`、`rep_ip_ver=0`。否则 6RD 路径一上机就是错的。

**Step 1：DS-Lite（只用常量 Control + 两个地址）**
- Content：按 §2.2 精确写 4 个 word + 两个 16 B 地址；`hdr_len=40`。
- Control：直接回放 `0x0005FCC1/0xFC004000/0xE03F80FF/0x02801FFF`。
- 从 `FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS` 取 src/dst，缺则拒绝。
- 验证：debugfs `content-get` / `control-get` 读回逐 word 比对（这是里程碑 1 已有的能力）。

**Step 2：6RD（Content 全零 + 修正后的 Control）**
- Content：16 个 word 全 0（不需要读 tunnel 参数）。
- Control：回放修正后的 `0x0801FEC0/0xFCFFCA00/0x453F9001/0x01401FE0`。
- 从 `ENC_IPV4_ADDRS` 取外层 IPv4 src/dst。

**Step 3：MAP-T（三表联动，最后做）**
- 先只做 debugfs 手工组装（Control 基础向量 + 参数注入 + FMR word0..2），
  **上机 readback 确认** `inr_to_out_fld=0x80`、`hdr_len/hdr_fmt` 与 §3.4 一致，再进 flow 路径。
- 受 FMR=3 限制，必须做规则复用/淘汰策略。

**Step 4：VXLAN（放到最后，且先只做 debugfs）**
- Content 按 §4.2 自己拼装（我们比 OEM 更清楚 Linux vxlan netdev 的字段），
  **成对预留 idx/idx+1**；`hdr_len` = 实际外层头长度。
- Control：`hdr_fmt=1`、`hdr_len=外层头长度`、`vxlan_sp_ost`=UDP sport 偏移、其余按 §4.3。
- **不要**写 `NE+0x35E8 / 0x35EC / 0x35F0 / 0x35F4 / 0x35F8`；只置 action 侧的
  `RTL_FE_VXLAN_SPORT_UPDATE_EN` / `RTL_FE_VXLAN_SPORT_MSB`。
- 需要设备 readback 才能定稿，因为当前无任何实测 Content/Control 向量可比对。

**Step 5：EIF 仲裁（与上面并行但独立）**
- 实现 §5.4 的最小方案：双头只用 hash 16..31，逐行参数相等性判定 + refcount。
- 明确**不使用** 32..63，并在代码注释里引用 §5.2 的「OEM 未实现」证据。

**通用护栏（每步都要）**
1. Control+Content **成对**分配，任一失败则回滚。
2. 删除严格按 §7.3 时序。
3. 所有写入后 readback 校验（`aal_pe_dual_*_entry_get` 路径）。
4. 未闭合字段一律停在 sentinel（`0x7F` / 0），不得填「看起来合理」的值。

---

## 9. 对既有文档/代码的订正清单

| # | 对象 | 原值 | 实测 | 证据 |
|---|---|---|---|---|
| C1 | phase0 §3.3 `aal_l3pe_vxlan_hash1_sport_range_set` 寄存器 | `NE+0x35EC`，20 bit | **`NE+0x35E8`，两个 16 bit 半字（min/max）** | ca-ne+0x69000 |
| C2 | phase0 §3.3「VXLAN 走独立入口，config 由以下函数完成」 | 暗示 fc_mgr 会配置 | **fc_mgr 只调 `aal_l3pp_vxlan_dport_set`，从不调 hash1/hash2** | `nm -u`；唯一调用点 fc_mgr+0xc05c4 |
| C3 | phase0 §3.2 6RD 列 | `hdr_fmt=2, hdr_len=64, mtu_diff=15, ppp_ip_ver_ost=120, rep_ip_en=0` | **`hdr_fmt=0, hdr_len=20, mtu_diff=0, ppp_ip_ver_ost=0x7F, rep_ip_en=1, rep_ip_ver=0`** | fc_mgr+0x9e330 字面量 + 位域解码 |
| C4 | phase0 §3.2 MAP-T 列 | `inr_to_out_fld=0x10` | **参数分支实测 0x80** | fc_mgr+0x995c0 |
| C5 | `fe/fe_tunnel.c` `rtl_fe_dual_control_preset_6rd()` | 照抄 C3 | 需按 C3 修正 | 同上 |
| C6 | `fe/fe_tunnel.h` 注释「hash 32..63 用于双头」 | 暗示 OEM 在用 | **本语料无实现证据，表未被引用** | §5.2 |

C1/C2/C5 是**会影响上机正确性**的缺陷，建议 W8b 开始前先修。

---

## 10. UNKNOWN 清单（禁止猜测）

1. **PPTP / L2TP / MAP-T 的 Content word0..15 精确值** —— 缓冲区在 `flow_setup*` 前段构建，未展开到字面量。
2. **MAP-T Control 的完整字段推导** —— 参数化 + 多分支（`0x99728` 等分支未展开）。
3. **VXLAN Content 的完整字节模板** —— 依赖 `priv+0x60/0x68/0x70/0x78/0x80/0x88/0x90/0x1b0` 的私有结构布局。
4. **VXLAN Control 的 `rep_len_ost1` / `inr_to_out_fld` 的完整位来源** —— 由 `priv[456]` 三位组合决定，未穷举。
5. **`NE+0x35EC/0x35F0/0x35F4/0x35F8` 的 20/24 bit 语义** —— 只知宽度，不知比对什么。
6. **`RTL_FE_VXLAN_SPORT_MSB` 的位宽/取值、`..._UPDATE_EN` 与 hash1/hash2 的选择关系**。
7. **hash 值何时被选到 32..63** —— `rtk_fc_dualHashKey` 只算 16 bit 哈希，无 32..63 的判定点。
8. **物理行 16..31 共享冲突时的优先策略** —— OEM 无实现。
9. **`hdr_fmt` 的完整枚举语义** —— 实测 DS-Lite=0、6RD=0、MAP-T=2、VXLAN=1，但 0 同时用于 DS-Lite 与 6RD，
   说明 `hdr_fmt` 不单独决定外层 IP 版本（可能由 `ip4_ost`/`ip6_oft` 哪个非 0x7F 决定）。
10. **`6rd_dip_pre_len`/`mapt_pre_len` 的编码值语义**（phase0 称 7 表示某前缀长，未验证）。
11. **GRE_ETH_BR / IPSEC / XLAT464 / SRV6 的全部模板**。

---

## 11. 可复现命令

```sh
# 语料完整性
sha256sum /mnt/c/rea/fc_mgr.ko /mnt/c/rea/ca-ne.ko

# DS-Lite Content 字面量
aarch64-linux-gnu-objdump -dr --start-address=0x9a4a0 --stop-address=0x9a5a0 /mnt/c/rea/fc_mgr.ko

# DS-Lite / 6RD / MAP-T Control 字面量
aarch64-linux-gnu-objdump -dr --start-address=0x9a2f0 --stop-address=0x9a438 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -dr --start-address=0x9e330 --stop-address=0x9e438 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -dr --start-address=0x995c0 --stop-address=0x99750 /mnt/c/rea/fc_mgr.ko

# 6RD Content 全零
aarch64-linux-gnu-objdump -dr --start-address=0x9e2f0 --stop-address=0x9e330 /mnt/c/rea/fc_mgr.ko

# VXLAN
aarch64-linux-gnu-objdump -dr --start-address=0xbf540 --stop-address=0xbf700 /mnt/c/rea/fc_mgr.ko   # get_outer_content
aarch64-linux-gnu-objdump -dr --start-address=0x9f340 --stop-address=0x9f5a0 /mnt/c/rea/fc_mgr.ko   # content 1/2 槽
aarch64-linux-gnu-objdump -dr --start-address=0x9ea90 --stop-address=0x9ed20 /mnt/c/rea/fc_mgr.ko   # control

# VXLAN 寄存器（ca-ne）
aarch64-linux-gnu-objdump -dr --start-address=0x69000 --stop-address=0x690c0 /mnt/c/rea/ca-ne.ko
aarch64-linux-gnu-objdump -dr --start-address=0x690c0 --stop-address=0x691e0 /mnt/c/rea/ca-ne.ko

# clear 路径
aarch64-linux-gnu-objdump -dr --start-address=0x6a270 --stop-address=0x6a390 /mnt/c/rea/ca-ne.ko

# 删除顺序
aarch64-linux-gnu-objdump -dr --start-address=0x9d770 --stop-address=0x9d8f0 /mnt/c/rea/fc_mgr.ko | grep -E "bl\s|CALL26"

# EIF 别名表
aarch64-linux-gnu-objdump -s -j .rodata --start-address=0x5640 --stop-address=0x5680 /mnt/c/rea/fc_mgr.ko
aarch64-linux-gnu-objdump -dr /mnt/c/rea/fc_mgr.ko | grep -c "rodata+"          # 4672 条，均无 0x5640
nm -u /mnt/c/rea/fc_mgr.ko | grep -i vxlan                                      # 仅 dport_set
nm -u /mnt/c/rea/fc_mgr.ko | grep -iE "l3e_if|eif"                              # 无
```