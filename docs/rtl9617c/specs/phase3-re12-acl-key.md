# Phase 3 / RE-12：ACL 0x14 key/FIB 格式与 DS-Lite/6RD 常量（只读逆向）

- 语料 `fc_8277c.ko` SHA-256 `a287e7930b4930f552ae6b2b799a0b35050ae166d1dab8da40717aae11653571`（2 091 056 B）
- 语料 `ca-ne.ko`    SHA-256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e`（4 381 304 B）
- 两个哈希实测一致；两个构建仓库只读，未写入任何仓库文件。
- 前置：`phase3-re11-extratag-napt6.md` §3、`phase3-re8-extratag.md` §4/§5、`phase3-re7-dualhdr-content.md`。
- 状态：**纯静态逆向，未上机验证**。`observed` = objdump/REA 反汇编逐条读出；`derived` = 由 observed 字面量按代码算术推出的值（不是设备读数）；`UNKNOWN` = 本语料无法确认，**禁止在 W8c 中猜测填充**。

---

## 0. 地址约定（本任务实测核对，与 RE-11 不同）

| 记号 | 含义 |
|---|---|
| `fc+0xNNNN` | `nm -n fc_8277c.ko` 的 `.text` 节内偏移（`.text` VMA=0，等于 objdump 地址） |
| `ne+0xNNNN` | `nm -n ca-ne.ko` 的 `.text` 节内偏移 |
| `REA(fc)` | `fc+n` **+ 0x100000** —— 本任务实测：`_rtk_fc_g3_caAalClsRuleAdd` nm `0x9D710` → REA `0x19D710` |
| `REA(ne)` | `ne+n` **+ 0x100040** —— 实测：`aal_l3_cls_add` nm `0x87060` → REA `0x1870A0` |

> **对 RE-11 的订正**：`fc_8277c` 的 REA 基址是 `+0x100000`，不是 `+0x100040`（`+0x100040` 是 `fc_mgr` 与 `ca-ne` 的基址）。凡引用 RE-11 的 fc 地址都要减去 0x40 才能对上 nm。

`fc_db` 为驱动 `.bss` 数据库（主机内存）；`netifHwTbl(n)` = `fc_db+0x806000+n*0x228`（stride 0x228，RE-11 已证）。

---

## 1. 结论速览（对应任务 5 项）

1. **ACL 0x14 的 key 是两层结构**：前 **0x89 B** 是"匹配头"（`+0x00` key space nibble = **0x0E**、`+0x04` = **0x03**、`+0x08..0x88` 是 `aal_l3_cls_key_clean()` 产出的 don't-care 模板 + 各 subtype 覆写），**`+0x89` 起是 FIB 动作块**（本语料至少 `0x57 B`，总长 **0xE0 B**）。
   `aal_l3_cls_add()` 的 `rule` 4 B 是**输出**，公式实测为
   `rule = {key_type[31:28], fib_mode[26:24], dev[23:20], key_tbl_idx[19:4], key_idx[3:0]}` —— **确认任务假设完全正确**。
2. **DS-Lite / 6RD 的常量已逐条取出**（§4）：DS-Lite `key+0x16 = 0x407F`、`key+0x81 = 0x00090000`、`fib+0x3B |= 0x10`；6RD `key+0x16` 保持 `0x007F`、前缀写 `key+0x28/0x2B/0x3B/0x3D`、`key+0x81 = 0x000A0000`。两者 **fib_mode 都由公共代码算成 1**（不是 0）。
3. **"双头 DS check"不是由 key 的某一位选择的**：它由 `_rtk_rg_aclAndCfReservedRuleAddSpecial` 的**保留规则类型 0x14** 决定（desc[0] 子类型 4/5/6），key 命名空间固定 `key[0]=0x0E/key[1]=0x03`。DS-Lite 与 MAPE 的**唯一** key 差异是 `key+0x16` bit6（0x40）；6RD 则改用 `key+0x28..0x4C` 前缀区。desc 中**没有** Content/Control 表号或索引字段。
4. **`aal_l3_cls_get` 在 ca-ne/fc_8277c/ca-rtk/cli-drv 中均不存在**（`nm` 全查）。readback 只能用 `aal_l3_cls_full_key_get / fib_N_get / flow_key_get / key_clean_get / fib_clean_get` 与 `l3fe_debug_dump_cls_fib`。任务里点名的函数名需要按此更正。
5. **W8c 可行性**：见 §7。结论是**不能让 DS-Lite/6RD flow 真正生效**——key/FIB 编码可以 1:1 复刻并做自测，但真正命中依赖闭源 `ca-ne.ko` 的 `aal_l3_cls_add`（mainline 无对应实现）与 ACL 0x14 保留规则，且 FIB 动作块逐位语义仍 UNKNOWN。需要设备证据（§8）。

---

## 2. ACL 0x14 安装链与 desc（0x30 B）

### 2.1 调用链（`observed`）

```
rtk_fc_ingress_outerHdrPathUpdate            fc+0x90A80
  ├─ dualType==1 → _rtk_fc_flow_updateDSLITE_by_igrPktHdr      fc+0x8D990
  ├─ dualType==2 → _rtk_fc_flow_updatePPTP_by_igrPktHdr        fc+0x8D060
  ├─ dualType==3 → _rtk_fc_flow_updateL2TP_by_igrPktHdr        fc+0x8D4F0
  ├─ dualType==7 → _rtk_fc_flow_update6RD_by_igrPktHdr         fc+0x8E3A0
  └─ 其他        → flow key[0] bits[29:28] = 2（普通双头路径）
```
`dualType` 字段 = `dword[netif+0xB8]`，由 `_rtk_fc_pktHdr_inspect`（fc+0x487B0）在报文解析时写入（实测写入值 1/2/3/4/5/6/7/8，见 fc+0x48CC8=6、0x48DD0=4、0x48F78=7、0x4942C=5、0x49780=2、0x497F0=1、0x49A94=3）。
`rtk_fc_ingress_outerHdrPathUpdate` 的调用点在 `_rtk_fc_flow_hashIndex_get`（fc+0x3A420）的 fc+0x3B01C。

### 2.2 `_rtk_rg_aclAndCfReservedRuleAddSpecial(type, desc, ?, ?)`（fc+0xA1F00）

- `type` 上限 `cmp w26,#0x14` → **0x14 合法**；0x14 分支入口 **fc+0xA21A0**。
- 只读 desc 前 **0x30 B**（6 个 u64），子类型分派在 **fc+0xA4004**（`cmp w0,#8`，0..8）。
- 成功后把 **分配到的 4 B rule** 写回 **desc+0x28**（fc+0xA4684: `ldr w0,[sp,#144]; str w0,[x27,#40]`，x27=desc）。

desc 布局（`observed`）：

| 偏移 | 宽 | 含义 | 证据 |
|---|---|---|---|
| +0x00 | u32 | 子类型：0=L2TP、3=PPTP、4=MAPE、5=DS-Lite、6=6RD、7/8=MAP-T | 各 builder 写入值 |
| +0x04 | u32 | 0（保留）；AddSpecial 会取 `(desc[4]&0xF)<<4` 写 key+0xDC | fc+0xA40D8 |
| +0x08 | u8 | `aal_l3_cls_add` 的 aal type（0/1），本语料所有 0x14 builder 写 **0** | fc+0xA4170 `ldrb w0,[sp,#176]` → RuleAdd 第 1 参 |
| +0x09 | u8 | **intf mapping 索引**（6 bit），来自 `_rtk_fc_flow_intf_mapping_idx_get()` | fc+0xA4150/0xA4168 |
| +0x0C..+0x1B | 16 B | 4 × u32，每个都 `rev`（bswap32）后写入 | 两个 builder |
| +0x1C | u32 | 标志位（仅 DS-Lite/MAPE 使用；6RD 保持 0） | §2.3 |
| +0x20..+0x27 | — | 0 | builder 清零 |
| +0x28 | u32 | **输出**：ACL rule（4 B 编码，见 §5） | fc+0xA4684 |

### 2.3 DS-Lite desc 组装（`_rtk_fc_flow_updateDSLITE_by_igrPktHdr` fc+0x8D990）

`observed`（栈偏移已换算为 desc 偏移，desc base = `sp+0x5C`）：

```
desc[0x00] = 5（DS-Lite） 或 4（MAPE 分支，由 netif_rec+0x0E 的 extratag 配置选择）
desc[0x04] = 0
desc[0x08] = 0
desc[0x09] = _rtk_fc_flow_intf_mapping_idx_get(netif->l3_if_idx)
desc[0x0C..0x1B] = bswap32(priv[0x08/0x0C/0x10/0x14])      // sub=5
                   或 bswap32(priv[0x18/0x1C/0x20/0x24])   // sub=4 (MAPE)
desc[0x1C] = flags
desc[0x20..0x27] = 0
desc[0x28] = 0（输出）
_rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc)
netifHwTbl[l3_if_idx].dualHdr_ds_clsIdx (= netifHwTbl+0x214) = desc[0x28]
_rtk_fc_g3IgrExtraInfo_init(desc)                      // ★ desc 同时当 flow extra-info
flow_key[0] |= 0x80001 ; flow_key[6] |= 0x10000000
RTK_RG_ASIC_FLOWPATH_SET(pt, flow_key, desc, flags)
```

`desc[0x1C]` 逐位（fc+0x8DA50..0x8DAF8，`netif` = 第 1 参）：
```
bit0      = 1                                   // 恒置
bit1      = (netif+0x08 != 0)
bit14     = (netif+0x10 != 0)
bits[13:2]  = (netif+0x128 >> 0) & 0xFFF
bits[26:15] = (netif+0x128 >> 17) & 0xFFF       // 仅当 netif+0x10 != 0，否则 0
```
`priv` = `*(void**)(netif+0x28)`；`netif+0x128` 为 u64。

### 2.4 6RD desc 组装（`rtk_fc_8277C_v6rd_downStream_reservedACL_add` fc+0x8E190）

```
desc = sp+0x3C（先清到 0x5C）
desc[0x00] = 6
desc[0x09] = param_1                          // intf idx
desc[0x0C..0x13] = *(u64*)(param_2 + 0x24)    // 只填 8 B
desc[0x1C] = 0（未写）；desc[0x28] = 0（输出）
_rtk_rg_aclAndCfReservedRuleAddSpecial(0x14, desc) → *param_3 = desc[0x28]
```
调用者 `_rtk_fc_flow_update6RD_by_igrPktHdr`（fc+0x8E3A0）在调用前先 `RTK_RG_ASIC_FLOWPATH_SET`（fc+0x8E508），再：
`rtk_fc_8277C_v6rd_downStream_reservedACL_add(intf_idx, &ctx, &out_u32)`（fc+0x8E558）。
> **observed**：该 `out_u32`（`sp+0x5C`）在 `_rtk_fc_flow_update6RD_by_igrPktHdr` 函数体内**没有被再次读取**；6RD 的 ACL 索引保存位置 **UNKNOWN**（DS-Lite 明确存 netifHwTbl+0x214）。

---

## 3. key 结构布局（0x89 B 头 + 0x57 B FIB = 0xE0 B）

### 3.1 头部前 8 字节（`observed`）

| 偏移 | 值 | 说明 |
|---|---|---|
| +0x00 | u32 = **0x0E** | 4-bit key space / AAL key type nibble（`aal_l3_cls_add` 只接受 ≤0xF；HW 放到 entry dword0 bits[21:18]）。**MAP-T 子类型 7 会改成 0x0F**（fc+0xA42D8 `str w4(0xf),[sp,#216]`） |
| +0x04 | u32 = **0x03** | 子模式（`aal_l3_cls_add` 只接受 ≤3；HW entry dword0 bits[23:22]） |

### 3.2 `aal_l3_cls_key_clean(key+8)` 模板（ne+0x82430，`observed`）

调用点在 AddSpecial fc+0xA4044：`x0 = sp+0xE0` = key+8。它把 **0x89 B 头**清成"全 don't-care（0xFF）+ 固定的 0/常量槽"：

```
key[0x00..0x07] 由 AddSpecial 单独写（0x0E / 0x03），clean 不碰
key[0x08..0x15] = FF
key[0x16..0x17] = 0x007F          // (u16 &= 0x7F)
key[0x18..0x27] = 00
key[0x28]       = FF
key[0x29..0x2A] = 0xFC01
key[0x2B..0x3A] = 00
key[0x3B..0x3C] = 0xC01F
key[0x3D..0x4C] = 00
key[0x4D..0x6A] = FF
key[0x6B..0x7A] = 00
key[0x7B..0x88] = FF
```
> 0xFF = don't-care（不参与匹配），0x00 = 匹配 0；这是 `aal_l3_cls_key_clean` 与 `__l3_cls_key_type` 掩码分类共同体现的编码方式（`observed`+`derived`）。**各字节的字段名本语料未给，UNKNOWN。**

### 3.3 0x14 公共写（所有子类型都执行，fc+0xA40D8..0xA4198）

```
key[0x13] &= ~0x60
key[0xC4..0xC7] = (old & 0xFFE00001) | ((old | 0x00040010) & 0x001FFFFE)
                  // 即 fib+0x3B |= 0x10、fib+0x3D |= 0x04
key[0xDA..0xDB] = (old & 0xF01F) | 0x0020 | ((desc[9] & 0x3F) << 6)
key[0xDC]       = (old & 0x07) | 0x08 | ((desc[4] & 0x0F) << 4)
```
再按 `desc[0x1C]` 的 bit1/bit14（只有 DS-Lite/MAPE 非 0；6RD 为 0 → 走第 4 条）：

| 条件 | 动作（`observed`） |
|---|---|
| bit0=1 | `key[0x59] &= ~0x02` |
| bit1=1 且 bit14=1 | 打包到 `key[0x53..0x5A`：bits[17:6]=aux[26:15]、bits[44:33]=aux[13:2]、常量位 0x0008000000080000/0x8000_0000_0000 | 
| bit1=1, bit14=0 | `key[0x56..0x59] = (old & 0xF200013F) | 0x04800000 | (((aux>>2)&0xFFF)<<9)` |
| bit1=0, bit14=1 | `key[0x56..0x59] = (old & 0xF200013F) | 0x04400000 | (((aux>>15)&0xFFF)<<9)` |
| bit1=0, bit14=0 | `key[0x59] &= ~0x0C` |

（`aux` = AddSpecial 内部 `sp+0x94` 的 4 B：DS-Lite/MAPE 填 `desc[0x1C]`，6RD 填 `desc[0x14]`(=0)，L2TP 填 `desc[0x0C]`。）

### 3.4 子类型专属写（本任务只要 4/5/6，`observed`）

| key 偏移 | sub=4 MAPE | sub=5 DS-Lite | sub=6 6RD |
|---|---|---|---|
| +0x16 (u16) | `0x403F` | **`0x407F`** | 保持 `0x007F` |
| +0x18..0x1B | desc[0x18] | desc[0x18] | 0 |
| +0x1C..0x1F | desc[0x14] | desc[0x14] | 0 |
| +0x20..0x23 | desc[0x10] | desc[0x10] | 0 |
| +0x24..0x27 | desc[0x0C] | desc[0x0C] | 0 |
| +0x28 (u16) | — | — | bits[15:9] = 0x20 |
| +0x2B..0x2E | — | — | desc[0x10]（64-bit 值的高 32 位） |
| +0x2F..0x36 | — | — | 0 |
| +0x37..0x3A | — | — | 0 |
| +0x3B (u16) | — | — | bits[11:5] = 0x20 |
| +0x3D..0x40 | — | — | desc[0x0C]（低 32 位） |
| +0x41..0x4C | — | — | 0 |
| +0x7B | 0xFF（不变） | 0xFF（不变） | 0xFF（不变） |
| +0x7C | **0xEF** | **0xEF** | **0xEF** |
| +0x81..0x84 (u32) | `0x00090000` | **`0x00090000`** | **`0x000A0000`** |

> **最重要的一条（`observed`）**：sub=4 与 sub=5 的 key **只差 `key+0x16` bit6（0x40）**。因此 `key+0x16 bit6 = DS-Lite(1) / MAPE(0)`，其余布局完全相同。
> 6RD 不是靠单个 bit，而是改用 `key+0x28/0x2B/0x3B/0x3D` 的 64-bit 前缀区，并把 `key+0x81` 换成 0x000A0000。

### 3.5 FIB 动作块（key+0x89，至少 0x57 B）

- `__l3_cls_fib_mode(key+0x89, &mode)`（ne+0x81730）读取 `fib+0x00/0x02/0x04/0x08/0x14/0x18/0x24/0x27/0x28/0x29/0x2E/0x35/0x3B/0x40/0x54`。
- `__l3_cls_fib_entry_update(key+0x89, fib_mode, out)`（ne+0x7F280）读取到 `fib+0x56`，按 fib_mode 分成 3 套打包器：`==3`、`==4`、`else(0/1/2)`。
- **0x14 公共写把 `fib+0x3B` bit4 置 1** → 对 DS-Lite/6RD 计算得 **fib_mode = 1**（`derived`，§6 给出复算脚本结果）。因此 **rule 的 `fib_mode[26:24]` 恒为 `001`**（所有 0x14 规则）。
- 语义命名（permit / trap / redirect / dpid / qos 等）本语料只在 ca-ne 的调试打印字符串里出现（`6| permit(0:drop;1:permit) = 0x%x`、`6| cls_std_fib_0..4 = %d`、`(trap by RSV_ACL[%d])`、`(hit RSV_ACL[%d])`），**没有把位映射到 0x14 实际写值上 → 逐位语义 UNKNOWN**。

---

## 4. DS-Lite / 6RD 关键常量总表（`observed`）

| 项 | DS-Lite | 6RD |
|---|---|---|
| builder | `_rtk_fc_flow_updateDSLITE_by_igrPktHdr` fc+0x8D990 | `rtk_fc_8277C_v6rd_downStream_reservedACL_add` fc+0x8E190 |
| desc[0] subtype | 5（MAPE=4） | 6 |
| desc[9] intf | `_rtk_fc_flow_intf_mapping_idx_get(l3_if)` | 调用者传入 |
| desc[0x0C..] | 16 B（priv+8..0x14 或 +0x18..0x24，bswap32） | 8 B（param_2+0x24） |
| desc[0x1C] | flags（§2.3） | 0 |
| key[0]/key[4] | 0x0E / 0x03 | 0x0E / 0x03 |
| key[0x16] | 0x407F | 0x007F |
| key[0x81] | 0x00090000 | 0x000A0000 |
| key[0x7C] | 0xEF | 0xEF |
| key[0x18..0x27] | 4 个地址字（倒序：0x18=desc[0x18] … 0x24=desc[0x0C]） | 0 |
| key[0x28..0x4C] | clean 模板原值 | 前缀：0x28 bits[15:9]=0x20、0x3B bits[11:5]=0x20、0x2B=hi32、0x3D=lo32，其余 0 |
| fib 公共 | fib[0x3B]\|=0x10、fib[0x3D]\|=0x04、fib[0x51..0x53]=intf 打包 | 同左（公共代码） |
| fib_mode（derived） | **1** | **1** |
| rule[26:24] | 001 | 001 |
| 索引落地 | netifHwTbl+0x214 (`dualHdr_ds_clsIdx`) | caller 的 out（函数内未再用，UNKNOWN） |

---

## 5. `_rtk_fc_g3_caAalClsRuleAdd` 与 `aal_l3_cls_add`（rule 4 B 公式的实测依据）

### 5.1 `_rtk_fc_g3_caAalClsRuleAdd(type, key, rule, ref_hint)`（fc+0x9D710）

```
_rtk_fc_g3_caAalClsAssignRuleRefIdx(key, hint, name[16], 16)
if (fc_db.debug & 2) _rtk_fc_g3_caAalClsRulePortVlanTransform(key, scratch)
ret = aal_l3_cls_add(0, type, key, rule)        // dev=0
失败时按 -EOPNOTSUPP/参数错误/表满分别打 "add CA AAL CLS (RSV_ACL[%s]) ..."
成功/失败都会把 {vld,hint,key[0],rule,type,掩码} 记入 SW 影子表 DAT_00b56590（0x200 × 0x28）
```
影子表记录（`observed`，绝对地址 `0xb56590`，每 0x28 B）：`+0x00 vld`、`+0x04 hint`、`+0x08 key[0]`、`+0x0C rule`、`+0x10 type(u8)`、`+0x14 掩码`、`+0x18 (key+0x58>>16&0xF)`、`+0x1C (key[2]>>1&0xFF)`、`+0x20 u16 (key[8..15]>>0x2E)`、`+0x22 u16 (>>0x1E)`、`+0x24 ((key+0x58>>0x17)&0x3F)-1`、`+0x25 ((key+0x50>>2)&0xF)-1`。

### 5.2 `aal_l3_cls_add(dev, type, key, rule)`（ca-ne ne+0x87060）

`observed` 前置校验与主体：
```
if (type > 1) return -9;                  // desc+0x08，本语料恒 0
if (!key || !rule) return -8;
if (key[0] > 0x0F) return -9;
if (key[1] > 0x03) return -9;
fib_mode = __l3_cls_fib_mode(key+0x89, &c8);           // 0..7；7=非法
key_type = __l3_cls_key_type(key+2, fib_mode, &cc);    // 0..7
... 在 l3_cls_key_table 里找槽（按 key[0]/key[1]/key_type 匹配已有 HW entry）
__l3_cls_key_entry_update(key, key_type, key_idx, &hw_key)
__l3_cls_fib_entry_update(key+0x89, fib_mode, &hw_fib)
__l3_cls_fib_idx_get(key_type, key_tbl_idx, key_idx, &fib_idx)
*rule = (c8 << 24) | (cc << 28) | key_idx | (key_tbl_idx << 4) | (dev << 20)   // ★
```
- **rule 4 B = `{key_type[31:28], fib_mode[26:24], dev[23:20], key_tbl_idx[19:4], key_idx[3:0]}`，实测确认。**
- key_type 6/7 占 **2 个** HW key entry；其余 1 个。key_type==0 用 1 个 FIB entry，其余用 2 个。
- type=0/1 通过 `(DAT_002b0478>>1 & 0xffff) * type` 选择 key 表 bank（本语料恒 bank 0）。
- **HW entry 字段位置（`derived`，从槽搜索比较指令反推，未逐位确认）**：dword0 bits[18:21]=key[0]、bits[22:23]=key[1]、bits[24:26]=key_type、bits[27:30]=子 entry 有效位图；fib entry bits[23:25]=fib_mode。
- **key 头字节确实被 HW 打包器消费（`observed`）**：__l3_cls_key_entry_update 以 x4=key+8 为基址读 key+0x14..0x24（ne+0x83B64/0x83BCC/0x83BE0/0x83C28/0x83C34：[x4,#12/#13/#14/#15/#16/#20/#24/#28]，其中 [x4,#14] = key+0x16、[x4,#16] = key+0x18 …）。即 §3.4 里 DS-Lite/MAPE 的 bit6 差异是 HW 可见字段，不是纯驱动标记。

### 5.3 `__l3_cls_key_type(key+2, fib_mode, &key_type)`（ne+0x81A00）

用"don't-care 掩码"对 8 类 key 模板做分类，打印的掩码常量（`observed`，可直接用于自测）：
```
CL_IF_ID_KEY_MSK              = 0x607c8d8160064000
CL_IPV4_SA_SHORT_KEY_MSK      = 0x60000de01c8640f8
CL_IPV4_DA_SHORT_KEY_MSK      = 0x60000de01c1640f8
CL_SPCL_PKT_KEY_MSK           = 0x60fe8de00400ff03
CL_IPV4_TUNNEL_ID_KEY_MSK     = 0x607c8d9964de4098
CL_IPV6_SA_SHORT_KEY_MSK      = 0x60000de01d0740d8
CL_IPV6_DA_SHORT_KEY_MSK      = 0x60000de01c2740d8
CL_MCST_MAC_DA_KEY_MSK        = 0x709c0df960060000
CL_MCST_IP_DA_KEY_MSK         = 0x701c0df960360000
CL_FLOW_MAC_IP_SA_KEY_MSK     = 0x68fffffffd87ffff
CL_FLOW_MAC_IP_DA_KEY_MSK     = 0x68fffffffc37ffff
CL_FLOW_MAC_RANGE_IP_SA_KEY_MSK = 0x697efffffd87ffff
CL_FLOW_MAC_RANGE_IP_DA_KEY_MSK = 0x697efffffc37ffff
CL_FULL_KEY_MSK               = 0x787fffffffb6c0fc
```
0x14 保留规则最终命中哪一类（rule[31:28]）**需要设备 readback**；本报告不猜。`aal_l3_cls_key_clean_set`（ne+0x83240）会按 key_type 0..7 生成模板，其中标签 u16 在模板 **+0x2A** = `0x8001 | (key_type << 8)`（`observed`，例：type6 → 0x8601）。

---

## 6. 复算（`derived`，不是设备读数）

以 clean 模板 + §3.3/§3.4 写值构造 key 后，按 `__l3_cls_fib_mode` 的三段掩码复算：

```
DS-Lite: key[0x0E]=0x407F  key[0x18..0x27]=addr  key[0x7C]=0xEF  key[0x81]=00090000
         fib[0x3B]=0x10 fib[0x3D]=0x04 fib[0x51..0x53]=intf
         → uVar2 = 0x200 → (0x200 & 0xffffffffffffecc2)==0 → fib_mode = 1
6RD    : key[0x0E]=0x007F  key[0x28..0x4C]=prefix  key[0x81]=000A0000
         fib 写值相同（公共代码）→ fib_mode = 1
```

DS-Lite 派生 key 头（`00 0e 00 00 00 03 00 00 ...`，测试向量，地址取 2001:db8::1 示例）：
```
00: 0e 00 00 00 03 00 00 00 ff ff ff ff ff ff ff ff
10: ff ff ff 9f ff ff 7f 40 00 00 00 01 00 00 00 00
20: 00 00 00 00 b8 0d 01 20 ff 01 fc 00 00 00 00 00
30: 00 00 00 00 00 00 00 00 00 00 00 1f c0 00 00 00
40: 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff ff
50: ff ff ff ff ff ff ff ff ff fd ff ff ff ff ff ff
60: ff ff ff ff ff ff ff ff ff ff ff 00 00 00 00 00
70: 00 00 00 00 00 00 00 00 00 00 00 ff ef ff ff ff
80: ff 00 00 09 00 ff ff ff ff
fib(00..56): 全 0，除
  3b: 10 00 04 00            （fib[0x3B]=0x10, fib[0x3D]=0x04）
  51: 60 04 08               （intf=0x11 时；intf<<6 | 0x20）
```
> 仅用于自测差分；`desc` 地址与 intf 是示例值，不代表设备配置。

---

## 7. ACL 0x14 触发条件 与 Content/Control 关联

1. **触发选择**：不是 key 的某一位，而是 `_rtk_rg_aclAndCfReservedRuleAddSpecial` 的 **type=0x14**（枚举名 `RTK_8277C_CLS_TYPE_DUAL_HEADER_DS_CHECK`，字符串 `fc+0xF3CF8`/`fc+0xF2808`）。desc[0] 子类型 4/5/6 只决定 key/FIB 常量和封装语义。
2. **key 命名空间固定**：`key[0]=0x0E`、`key[1]=0x03`（全部 0x14 子类型；MAP-T 子类型 7 例外 `key[0]=0x0F`）。因此"双头 DS check"不能靠改 key_type 位切换，只能靠安装 0x14 规则。
3. **DS-Lite vs MAPE**：唯一 key 差异 `key+0x16` bit6（DS-Lite=1）。**6RD**：`key+0x16` 保持 0x007F（bit6=1、bit14=0），并写 `key+0x28/0x2B/0x3B/0x3D` 前缀区。
4. **与 Content/Control 的关联**：desc 与 AddSpecial 的输入/输出中**没有** Content(31)/Control(32)/FMR(33) 的表号或索引字段（`observed`，desc 全 0x30 B 已逐字段解出）。三者是**并列独立表**，由同一 flow 的安装函数分别下发：
   - DS-Lite：`_rtk_fc_flow_updateDSLITE_by_igrPktHdr` 只做 ACL + FLOWPATH；Content/Control 在同链路的双头安装函数里（RE-7/RE-8 已闭合）。
   - `desc` 同时被 `_rtk_fc_g3IgrExtraInfo_init(desc)` 当作 flow extra-info，再传给 `RTK_RG_ASIC_FLOWPATH_SET`（fc+0x8DBE0..0x8DC28）。
   - 硬件层 ACL 与 Content/Control 如何互相寻址 → **UNKNOWN**（需寄存器手册或设备探测）。
5. **readback 字段**：ca-ne 无 `aal_l3_cls_get`。可用（`observed` 符号表）：
   `aal_l3_cls_full_key_get`（ne+0x82510）、`aal_l3_cls_flow_key_get`、`aal_l3_cls_key_clean_get`、`aal_l3_cls_fib_0_get`..`fib_4_get`、`aal_l3_cls_fib_clean_get`、`l3fe_debug_dump_cls_fib`（ne+0xBE28）。
   调试打印会给出 `key_type = %d`、`fib_mode = %d`、`device_id/key_tbl_idx/key_idx`、`cls_std_fib_0..4`、`permit/mc/mcgid/deepq/dpid_pri`。

---

## 8. W8c 可实现的 API/字段表

```c
/* 0xE0 B: 0x89 头 + 0x57 FIB */
struct rtl_fe_acl_key {
    u32 key_space;          /* +0x00  0x0E; MAP-T=0x0F              VERIFIED */
    u32 sub_mode;           /* +0x04  0x03                          VERIFIED */
    u8  match[0x81];        /* +0x08..0x88  clean 模板+subtype 覆写  VERIFIED(字节)/UNKNOWN(语义) */
    u8  fib[0x57];          /* +0x89..0xDF                          VERIFIED(写值)/UNKNOWN(位义) */
};

void rtl_fe_acl_key_clean(struct rtl_fe_acl_key *k);                 /* 复刻 ne+0x82430 */
void rtl_fe_acl_key_build(u32 subtype, const struct rtl_fe_acl_params *p,
                          struct rtl_fe_acl_key *k);                 /* §3.3/§3.4 */
int  rtl_fe_acl_rsv14_add(u32 subtype, const struct rtl_fe_acl_desc *d, u32 *rule);
int  rtl_fe_acl_rsv14_del(u32 rule);                                 /* 仅 shadow/软件表 */
u32  rtl_fe_acl_rule_encode(u32 key_type, u32 fib_mode, u32 dev,
                            u32 key_tbl_idx, u32 key_idx);           /* VERIFIED 公式 */
```

`struct rtl_fe_acl_desc`（0x30 B，VERIFIED）：
```c
struct rtl_fe_acl_desc {
    u32 subtype;            /* +0x00  4/5/6                   VERIFIED */
    u32 rsv;                /* +0x04  0                       VERIFIED */
    u8  aal_type;           /* +0x08  0                       VERIFIED */
    u8  intf_idx;           /* +0x09  6-bit                   VERIFIED */
    u8  addr[16];           /* +0x0C..0x1B 已 bswap32 的 4 字  VERIFIED(位置)/UNKNOWN(每字语义) */
    u32 flags;              /* +0x1C                         VERIFIED(DS-Lite) */
    u8  pad[8];             /* +0x20..0x27 = 0                VERIFIED */
    u32 rule_out;           /* +0x28                         VERIFIED */
};
```

已验证 vs UNKNOWN：

| 项 | 状态 |
|---|---|
| key 长度 0x89 + FIB ≥0x57；key[0]=0x0E/key[1]=0x03；clean 模板字节图 | **VERIFIED**（源码级 `observed`） |
| desc 0x30 B 布局、+0x28 输出 rule、subtype 4/5/6 常量 | **VERIFIED** |
| rule 4 B 位域公式 | **VERIFIED**（fc+0x1875A4 汇编 + 反编译） |
| fib_mode=1（0x14 全体） | **DERIVED**（按 `__l3_cls_fib_mode` 掩码复算；需设备 readback 确认） |
| key+0x16 bit6 = DS-Lite/MAPE 选择 | **VERIFIED**（sub=4/5 唯一差异） |
| key_type（rule[31:28]）具体值 | **UNKNOWN** — 由 `__l3_cls_key_type` 在运行时按实际 key 计算；未静态定值 |
| key 各字节的字段名（tclass/proto/port/…） | **UNKNOWN** — 本语料无符号/无手册 |
| FIB 块 permit/trap/redirect/qos 的逐位编码 | **UNKNOWN** — 只有打印字符串暗示存在这些字段 |
| 0x14 与 Content/Control 的硬件互寻址 | **UNKNOWN** |
| 6RD ACL 索引持久化位置 | **UNKNOWN**（函数内未用 out） |

---

## 9. W8c 能否让 DS-Lite/6RD flow 真正生效

**结论：不能安全生效，只能做到"编码器 + 软件路径 + 自测"。**

理由（逐条，均可引用上面的 observed）：
1. **安装入口缺失**：ACL 0x14 规则靠 `aal_l3_cls_add`（ca-ne 闭源导出），mainline/自研驱动没有该 AAL 层。fc_8277c 直接 `bl aal_l3_cls_add`，没有 ioctl/公开 API 旁路。
2. **动作语义未闭合**：rule 只是"索引编码"，真正的 permit/trap/redirect 在 key+0x89 的 FIB 块里；本语料没有把 FIB 位映射到动作（§3.5）。即使照抄字节，也无法证明动作正确。
3. **触发依赖 0x14 保留规则**：`dualType`（netif+0xB8）只决定"装哪条 0x14 规则"；没有这条规则，硬件不会把外层头报文送进双头/DS 检查（RE-8：Content/Control 与 ACL 是两条独立链，ACL 是触发侧）。
4. **索引不可见**：DS-Lite 索引存 `netifHwTbl+0x214`，但 mainline 无同构 netif 记录；6RD 连保存点都 UNKNOWN。
5. **本任务没有上机**：以上全部是静态结论，任何"已生效"的说法都不成立。

**W8c 可以做（不阻塞）**：
- 把 §8 的 key/desc/rule 编码器写成纯函数 + 单测（用 §6 的派生字节做黄金向量）；
- 在软件封装路径（RE-11 §2 的 `rtk_fc_outerHdr_insert/remove` 复刻）里复刻 DS-Lite/6RD 的封装/解封装行为；
- 把 ACL 0x14 的安装留成 `-EOPNOTSUPP` 的显式 TODO，并在设备上按 §10 采集证据后再决定是否实现。

---

## 10. 仍需的设备证据（最小集）

1. OEM 设备上读 `fc_db.netifHwTbl[i]+0x214`（`dualHdr_ds_clsIdx`）：DS-Lite flow 建立后应非 0；记录 rule[31:28]/[26:24]/[19:4]/[3:0] 的实测值。
2. 打开 ca-ne 的 `ca_aal_debug` bit3，抓 `__l3_cls_key_type`/`__l3_cls_fib_mode` 打印：确认 key_type（本报告 UNKNOWN）、fib_mode（本报告 derived=1）、key_tbl_idx/key_idx。
3. 抓 `add special ACL DUAL_HEADER_DS_CHECK success, idx: %d, intf_idx=%d`（fc+0xF1E48）与 `(trap by RSV_ACL[%d])`/`(hit RSV_ACL[%d])` 调试串，确认命中路径与 AC 动作。
4. 用 `l3fe_debug_dump_cls_fib` + `aal_l3_cls_full_key_get`/`fib_N_get` dump 已安装 entry，与本报告 §6 的 key 字节逐字节 diff（这是唯一能确认 key 布局与 FIB 位义的方法）。
5. 报文级：DS-Lite 下挂终端 ping 通（v4-in-v6 封装/解封装真实生效）+ 抓包确认 outer/inner 头。

---

## 11. 复现命令（只读）

```sh
# 地址核对
readelf -S /mnt/c/rea/fc_8277c.ko | grep -A1 ' \.text '
nm -n /mnt/c/rea/fc_8277c.ko | grep -E '_rtk_fc_g3_caAalClsRuleAdd|AddSpecial|updateDSLITE|v6rd_downStream|update6RD|outerHdrPathUpdate'
nm -n /mnt/c/rea/ca-ne.ko    | grep -E 'aal_l3_cls_(add|key_clean|full_key|fib)|__l3_cls_(key_type|fib_mode|fib_entry|key_entry)'

# ACL 0x14 主体
aarch64-linux-gnu-objdump -dr --start-address=0xa21a0 --stop-address=0xa2400 /mnt/c/rea/fc_8277c.ko
aarch64-linux-gnu-objdump -dr --start-address=0xa4004 --stop-address=0xa4450 /mnt/c/rea/fc_8277c.ko
aarch64-linux-gnu-objdump -dr --start-address=0xa4b40 --stop-address=0xa4d40 /mnt/c/rea/fc_8277c.ko
aarch64-linux-gnu-objdump -dr --start-address=0x8d990 --stop-address=0x8dd30 /mnt/c/rea/fc_8277c.ko   # DS-Lite
aarch64-linux-gnu-objdump -dr --start-address=0x8e190 --stop-address=0x8e2c0 /mnt/c/rea/fc_8277c.ko   # 6RD
aarch64-linux-gnu-objdump -dr --start-address=0x90a80 --stop-address=0x90b28 /mnt/c/rea/fc_8277c.ko   # dualType 分派

# ca-ne key/FIB
aarch64-linux-gnu-objdump -dr --start-address=0x83240 --stop-address=0x83450 /mnt/c/rea/ca-ne.ko       # key_clean_set 模板
REA: open_binary /mnt/c/rea/fc_8277c.ko   (REA 地址 = nm + 0x100000)
     open_binary /mnt/c/rea/ca-ne.ko       (REA 地址 = nm + 0x100040)
     aal_l3_cls_add              0x1870A0
     __l3_cls_key_type           0x181A40
     __l3_cls_fib_mode           0x181770
     __l3_cls_fib_entry_update   0x17F2C0
     aal_l3_cls_key_clean        0x182470
     aal_l3_cls_key_clean_set    0x183280
```

---

## 12. 本次新增/订正的 UNKNOWN 列表

| 编号 | 内容 |
|---|---|
| U12-1 | key+0x08..0x88 的**字段名**（本语料只有字节与掩码，无字段符号） |
| U12-2 | FIB 块 permit/trap/redirect/dpid/qos 等动作的**逐位编码** |
| U12-3 | 0x14 规则最终 `key_type`（rule[31:28]）静态值；需 readback |
| U12-4 | hash/ACL 触发后与 Content(31)/Control(32) 的硬件互寻址方式 |
| U12-5 | 6RD ACL 索引保存点（`out_u32` 在函数内未再读） |
| U12-6 | `key+0x53..0x5A` / `key+0x56` 两个 12-bit 字段（来自 netif+0x128 的 [11:0]/[28:17]）的语义（疑似 DS-Lite 前缀长度/PSID） |
| U12-7 | 4 vs 5 的 `key+0x16` bit6 在硬件侧的正式字段名（只证"选择 DS-Lite 而非 MAPE"） |