# Phase 2 RE-9 — cli-drv.ko：L3 DoS 16 类型最终位表（只读逆向，U10-a/U10-b 闭合）

状态：**只读**。未修改 `pt1500-refactor-build` / `pt1500-immortalwrt-build`，未接触 `/opt/rea-snap`。
本文**取代** `phase2-re5-dos-attack.md` §3.3 / §14.2 / §15 / §16 / §17 中所有关于
「type→bit 未知」「14 组 vs 16 类型」「dos_type_en 是 32 bit」的结论。

## 0. 语料、方法、地址约定

| 项 | 值 |
|---|---|
| 主证据 A | `/mnt/c/rea/cli-drv.ko`，aarch64 relocatable，not stripped，sha256 `e6d1ba46197d0ef4dee8d9ec6260201d311cb983c217b6a986a5ee10500f76ac`（6 024 648 B） |
| 主证据 B（决定件） | `/mnt/c/rea/ca-rtk.ko`，aarch64，not stripped，sha256 见 `sha256sum`（本轮只读，未改动） |
| 交叉对证 C | `/mnt/c/rea/ca-ne.ko`（RE-5 语料，同 SHA 未变） |
| 工具 | `aarch64-linux-gnu-{nm,objdump -dr,readelf}`；python3 只读解 `.rodata` 跳表 |
| 地址约定 | 全文一律 **节内地址（nm/objdump 原值）**。REA = 节内 + `0x100040`（.text 文件偏移 `0x40`，image base `0x100000`，已用 `readelf -S` 核对） |
| 不写盘 | 全程 `objdump | grep` 管道，未生成任何中间文件 |

标注：**[观测]** = 汇编/跳表直接可见；**[推导]** = 多处观测合并；**[UNKNOWN]** = 未确认。

### 0.1 为什么这次能闭死

RE-5 的硬阻塞是「实现 `aat_dos_atk_*` 的内核模块不在包内」（RE-5 U15）。本轮语料补上了这个模块：
**`cli-drv.ko` 就是创建 `/dev/cortina-cli-dev`、解析命令字符串、实现全部 `__cli_aal_dos_atk_*` 的内核模块**
（`nm` 里 62 个 `__cli_aal_*dos_atk*` 符号 + `U aal_dos_atk_set` 等导入）。
另外 `ca-rtk.ko` 里的 Realtek DAL 层 `dal_rtl8277c_sec_attackPrevent_set/_get` 是**第二个独立调用方**，
它用一张 16 项跳表把「攻击类型枚举」直接翻成位号 —— 这是 type→bit 的决定性证据。

---

## 1. 结论摘要（先给答案）

1. **`dos_type_en` = `0x3304[31:16]`，16 bit，一位一个攻击类型。** **[观测]**
   `__cli_aal_dos_atk_fib_dos_type_en_set` 用 **`strh`** 写 `img[6]` 高半字（`0xe8350`），
   不是 32 bit；CLI 的 `<0-0xffffffff>` 只是解析量程提示，高位被 `strh` 静默丢弃。
2. **type→bit 已确定：`dos_type_en` 的 bit k = 下表 S 序第 k 个类型（k=0..15）。** **[观测]**（证明见 §4）
3. **每个类型的配置字段 = `{pol_id(9 bit), [th(16 bit)], en(1 bit)}`**；
   3 个 flood 有 `th`，其余 13 个只有 `{pol_id(9), en(1)}`。
   ⇒ 16 类型的 208 bit 恰好铺满 `0x32ec..0x3304[15]`，与 RE-5「14 组 vs 16 类型差 2」的矛盾**不存在**。
4. **`pol_id` 是 9 bit（不是阈值），`th` 是 16 bit（不是端口掩码）。**
   端口掩码是独立的 **64 bit**：`0x3308`（低 32）+ `0x330c`（高 32）。**RE-5 §3.3 把二者搞反了。**
5. CLI 的 16 个类型名顺序 = **S 序**（= 位号序）；Realtek DAL 的 `attack_type` 枚举 = **R 序（S 的逆序）**。
   RE-5 §15 的两个候选序**都是对的，但属于不同层**。
6. trap/drop 的 6 个 timer 字段全部落实：`t0_ctrl = [11]`（1 bit）、`t1..t5 = [15:12]/[19:16]/[23:20]/[27:24]/[31:28]`（各 4 bit）；
   `reserved = [10]`（1 bit）。**RE-5 §5 把 reserved 记成 [11]、t0 记成 [15:12]，偏移一格，本轮回正。**

---

## 2. CLI setter 的统一形状（决定了怎么读这些函数）

以 `__cli_aal_dos_atk_fib_icmp_flood_pol_id_set` @ **`0xe62b8`** 为例（16 个类型的三个变体逐一比对，
除 bfi 立即数外指令序列完全同构）**[观测]**：

```
unit      = cli_atoi(argv[0]) & 0xffff          ; 0xe62ec
val       = cli_atoi(argv[1])                   ; 0xe6310   (dos_port_mask 用 cli_str2ll → 64 bit)
mask      = 0xffffffffffffffff  (stur x0,[sp,#60])       ; 0xe62f8   ← 恒等于 ~0ULL !
img[0..8] = aal_dos_atk_get(unit, &img)         ; 0xe6320   ; img 基址 = sp+0x44 = sp+68
img[k]    = bfi/bfxil(img[k], val, lsb, width)  ; 0xe6368   本例: bfxil #0,#9
aal_dos_atk_set(unit, mask, &img)               ; 0xe6374
失败 → cli_print("aal_dos_atk_set failed, return = %d")，返回 1；成功返回 0
```

三条可直接照抄的事实：
- **`field_mask` 永远是 `~0ULL`** ⇒ OEM 的 CLI 是「整块 9 寄存器读 → 改一个字段 → 整块写回」，
  不是单字段写。所以**位号只能从 `bfi/bfxil` 的立即数读，mask 位不含信息**。
- `img[k]` 与寄存器 1:1 对应：`img[k] = NE(0x32ec + 4·k)`。
  依据：`ca-ne.ko` `aal_dos_atk_get` @ `0x91f50` 按 `0x32ec,0x32f0,0x32f4,0x32f8,0x32fc,0x3300,0x3304,0x3308,0x330c`
  顺序 dump 到 `cfg[0..8]`（`0x91f74`–`0x92090` 九个 `mov x?, #0x33xx` 逐条可见）**[观测]**。
- `trap/drop/flood_cnt` 的 setter 用另一个模板：`mask = 0xffffffff`（`stp w0,wzr,[sp,#48]`，w0=-1），
  cfg 是**单个 u32**（不是 9 字镜像），走 `aal_dos_atk_event_{trap,drop}_set` / `aal_dos_atk_flood_cnt_set`。

---

## 3. L3 DoS 块位流布局（288 bit 完整图）**[观测]**

9 个寄存器按地址升序拼成一条 288 bit 位流（`img[0]` 的 bit0 在最前）。本轮把 37 个 mask 位
（`ca-ne.ko` `aal_dos_atk_set`）与 CLI 的 `bfi` 立即数逐一对齐，**每个 CLI 字段恰好等于一个 mask 位**：

| mask bit | 归属（S 序类型） | 字段 | 寄存器切片 | 宽 | CLI 函数 |
|---|---|---|---|---|---|
| 0 | t0 icmp_flood | pol_id | `0x32ec[8:0]` | 9 | `_pol_id_set` |
| 1 | t0 icmp_flood | th | `0x32ec[24:9]` | 16 | `_th_set` |
| 2 | t0 icmp_flood | en | `0x32ec[25]` | 1 | `_set` |
| 3 | t1 fin_flood | pol_id | `0x32ec[31:26]`+`0x32f0[2:0]` | 6+3 | `_pol_id_set` |
| 4 | t1 fin_flood | th | `0x32f0[18:3]` | 16 | `_th_set` |
| 5 | t1 fin_flood | en | `0x32f0[19]` | 1 | `_set` |
| 6 | t2 syn_flood | pol_id | `0x32f0[28:20]` | 9 | `_pol_id_set` |
| 7 | t2 syn_flood | th | `0x32f0[31:29]`+`0x32f4[12:0]` | 3+13 | `_th_set` |
| 8 | t2 syn_flood | en | `0x32f4[13]` | 1 | `_set` |
| 9 | t3 syn_with_data | pol_id | `0x32f4[22:14]` | 9 | `_pol_id_set` |
| 10 | t3 syn_with_data | en | `0x32f4[23]` | 1 | `_set` |
| 11 | t4 udp_bomb | pol_id | `0x32f4[31:24]`+`0x32f8[0]` | 8+1 | `_pol_id_set` |
| 12 | t4 udp_bomb | en | `0x32f8[1]` | 1 | `_set` |
| 13 | t5 ping_of_death | pol_id | `0x32f8[10:2]` | 9 | `_pol_id_set` |
| 14 | t5 ping_of_death | en | `0x32f8[11]` | 1 | `_set` |
| 15 | t6 icmp_fragment | pol_id | `0x32f8[20:12]` | 9 | `_pol_id_set` |
| 16 | t6 icmp_fragment | en | `0x32f8[21]` | 1 | `_set` |
| 17 | t7 tcp_frag_error | pol_id | `0x32f8[30:22]` | 9 | `_pol_id_set` |
| 18 | t7 tcp_frag_error | en | `0x32f8[31]` | 1 | `_set` |
| 19 | t8 tcp_short_hdr | pol_id | `0x32fc[8:0]` | 9 | `_pol_id_set` |
| 20 | t8 tcp_short_hdr | en | `0x32fc[9]` | 1 | `_set` |
| 21 | t9 syn1024 | pol_id | `0x32fc[18:10]` | 9 | `_pol_id_set` |
| 22 | t9 syn1024 | en | `0x32fc[19]` | 1 | `_set` |
| 23 | t10 null_scan | pol_id | `0x32fc[28:20]` | 9 | `_pol_id_set` |
| 24 | t10 null_scan | en | `0x32fc[29]` | 1 | `_set` |
| 25 | t11 xma_scan | pol_id | `0x32fc[31:30]`+`0x3300[6:0]` | 2+7 | `_pol_id_set` |
| 26 | t11 xma_scan | en | `0x3300[7]` | 1 | `_set` |
| 27 | t12 syn_fin_scan | pol_id | `0x3300[16:8]` | 9 | `_pol_id_set` |
| 28 | t12 syn_fin_scan | en | `0x3300[17]` | 1 | `_set` |
| 29 | t13 blat_attacks | pol_id | `0x3300[26:18]` | 9 | `_pol_id_set` |
| 30 | t13 blat_attacks | en | `0x3300[27]` | 1 | `_set` |
| 31 | t14 land_attacks | pol_id | `0x3300[31:28]`+`0x3304[4:0]` | 4+5 | `_pol_id_set`（`0xe7f98`–`0xe7fb4`） |
| 32 | t14 land_attacks | en | `0x3304[5]` | 1 | `_set` |
| 33 | t15 smac_eq_dmac | pol_id | `0x3304[14:6]` | 9 | `_pol_id_set` |
| 34 | t15 smac_eq_dmac | en | `0x3304[15]` | 1 | `_set` |
| 35 | — | **`dos_type_en`** | `0x3304[31:16]` | **16** | `dos_type_en_set` |
| 36 | — | **`dos_port_mask`** | `0x3308[31:0]`+`0x330c[31:0]` | **64** | `dos_port_mask_set` |

合计 = 3×(9+16+1) + 13×(9+1) + 16 + 64 = 78 + 130 + 16 + 64 = **288** = 9×32，无洞无重叠 **[观测]**。

**掩码位规律（可直接生成宏）**：设 S 序类型号 t∈[0,15]
```
pol_bit(t) = (t <= 2) ? 3*t      : 2*t + 3
th_bit(t)  = pol_bit(t) + 1                 /* 仅 t<=2 存在 */
en_bit(t)  = pol_bit(t) + ((t <= 2) ? 2 : 1)
type_en    = 35
port_mask  = 36
```

---

## 4. 0x3304[31:16] `dos_type_en` 的 type→bit 最终表（**已证明**）

### 4.1 直接观测（cli-drv.ko）

`__cli_aal_dos_atk_fib_dos_type_en_set` @ **`0xe82a0`**：
`strh w22, [sp, #94]`（**`0xe8350`**）。img 基址 = sp+68 ⇒ sp+94 = `img[6]` 的 byte2 ⇒
**`0x3304[31:16]`，写 16 bit**，随后 `aal_dos_atk_set(unit, ~0ULL, &img)`。
`__cli_aal_dos_atk_get` @ `0xe5e00` 打印时用 `ldrh w3, [sp,#78]`（`0xe6268`，img 基址 sp+52 ⇒ `0x3304[31:16]`）
配格式 `"%-30s:  0x%08x"`，字段名串 `dos_type_en`（`.rodata.str1.1+0x16dc7`）——**同样是 16 bit**。
⇒ RE-5 §14.2「`dos_type_en` 应落 `0x3304[31:0]`」**错误**：`0x3304[15:0]` 已被
land_attacks 的 pol_id(`[4:0]`)+en(`[5]`) 与 smac_eq_dmac 的 pol_id(`[14:6]`)+en(`[15]`) 占满。

### 4.2 决定性证据：ca-rtk.ko DAL 跳表（type→bit 的直接换算）

`dal_rtl8277c_sec_attackPrevent_set` @ **`0xc7a8`**（`ca-rtk.ko`）：

```
c810: cmp  w22, #0xf      ; 参数2 = attack_type，0..15，越界报错
c818: cmp  w20, #0xa      ; 参数3 = enable，0..10
c8d8: adrp x0, .rodata+0x1020
c8e0: ldrh w0, [x0, w22, uxtw #1]     ; 16 项 int16 跳表
c8e4: adr  x1, 0xc8f0
c8e8: add  x0, x1, w0, sxth #2        ; target = 0xc8f0 + entry*4
c8ec: br   x0
...
; 每个 case 末尾把「位号」放进 w19，然后统一汇合到 0xcb18：
cb18: mov  w0, #0x1
cb1c: ldrsh w3, [sp, #126]            ; img[6] 高半字 = 0x3304[31:16] = dos_type_en
cb20: lsl  w19, w0, w19               ; w19 = 1 << 位号
cb28: sxth w19, w19
cb30/34: bic/ orr  → 按 enable 清/置该位
cb50: strh w3, [sp, #126]             ; 写回 16 bit
cb54: orr  x1, x1, #0x800000000       ; mask bit 35 = 0x3304[31:16]
cb5c: bl   aal_dos_atk_set
```

`.rodata+0x1020` 跳表（文件偏移 `0x1e700+0x1020=0x1f720`，16×int16）与各 case 的 `mov w19,#N`：

| attack_type（DAL 枚举） | 跳表目标 | 类内 L3 mask 位 → 字段 | w19（= `dos_type_en` 位号） | 实际类型 |
|---|---|---|---|---|
| 0 | `0xc8f0` | bit34 → `0x3304[15]` | 15 | smac_eq_dmac |
| 1 | `0xc918` | bit32 → `0x3304[5]` | 14 | land_attacks |
| 2 | `0xc940` | bit30 → `0x3300[27]` | 13 | blat_attacks |
| 3 | `0xc968` | bit28 → `0x3300[17]` | 12 | syn_fin_scan |
| 4 | `0xc990` | bit26 → `0x3300[7]` | 11 | xma_scan |
| 5 | `0xc9b8` | bit24 → `0x32fc[29]` | 10 | null_scan |
| 6 | `0xc9e0` | bit22 → `0x32fc[19]` | 9 | syn1024 |
| 7 | `0xca08` | bit20 → `0x32fc[9]` | 8 | tcp_short_hdr |
| 8 | `0xca30` | bit18 → `0x32f8[31]` | 7 | tcp_frag_error |
| 9 | `0xca58` | bit16 → `0x32f8[21]` | 6 | icmp_fragment |
| 10 | `0xca80` | bit14 → `0x32f8[11]` | 5 | ping_of_death |
| **11** | `0xc830` | **无（`mov w0,#0xd` 直接返回 13）** | — | **udp_bomb（DAL 不支持）** |
| 12 | `0xcaa8` | bit10 → `0x32f4[23]` | 3 | syn_with_data |
| 13 | `0xcad0` | bit8 → `0x32f4[13]` | 2 | syn_flood |
| 14 | `0xcaf8` | bit5 → `0x32f0[19]` | 1（编译器把 `mov w19,#1` 折叠掉：进入 switch 前 w19 恒为 1） | fin_flood |
| 15 | `0xcb74` | bit2 → `0x32ec[25]` | 0 | icmp_flood |

每个 case 同时置 L2 侧对应 mask 位（`sp+68`，u32），并同样用 `w19` 置位——见 §10。
**L3 mask 位与 §3 表逐项吻合（bit2/5/8/10/14/16/18/20/22/24/26/28/30/32/34）**，
唯一缺口是 bit12（udp_bomb），正好对应 attack_type 11 报错 ⇒ 三方自洽。**[观测]**

> 说明：`0xcaf8`（attack_type 14）没有显式 `mov w19`，但该路径前置条件是 `w19==1`
> （`0xc804` 从 `.bss+0x5454` 载入后 `cmp #1; b.ne` 已排除其它值），所以位号确定为 1；
> 与 L3 bit5=`fin_flood en` 一致，可交叉确认。

### 4.3 最终 type→bit 表（W6c 直接用）

`dos_type_en` = `0x3304[31:16]`，`BIT(k)` 指该 16 bit 字段内的第 k 位（= 寄存器 bit 16+k）：

| k | 类型名（CLI 顺序 = S 序） | `dos_type_en` 位 | 寄存器位 |
|---|---|---|---|
| 0 | `icmp_flood` | bit0 | `0x3304[16]` |
| 1 | `fin_flood` | bit1 | `0x3304[17]` |
| 2 | `syn_flood` | bit2 | `0x3304[18]` |
| 3 | `syn_with_data` | bit3 | `0x3304[19]` |
| 4 | `udp_bomb` | bit4 | `0x3304[20]` |
| 5 | `ping_of_death` | bit5 | `0x3304[21]` |
| 6 | `icmp_fragment` | bit6 | `0x3304[22]` |
| 7 | `tcp_frag_error` | bit7 | `0x3304[23]` |
| 8 | `tcp_short_hdr` | bit8 | `0x3304[24]` |
| 9 | `syn1024` | bit9 | `0x3304[25]` |
| 10 | `null_scan` | bit10 | `0x3304[26]` |
| 11 | `xma_scan` | bit11 | `0x3304[27]` |
| 12 | `syn_fin_scan` | bit12 | `0x3304[28]` |
| 13 | `blat_attacks` | bit13 | `0x3304[29]` |
| 14 | `land_attacks` | bit14 | `0x3304[30]` |
| 15 | `smac_eq_dmac` | bit15 | `0x3304[31]` |

**残留风险（低）**：`udp_bomb`（k=4）这一位在 `ca-rtk.ko` 里**没有任何代码置位**
（attack_type 11 直接返回 13）。它的位号由「S 序 15-0 连续、缺口恰在 4」推出，
且 `0x32f8[1]` 这个 per-slot en 位确实存在（cli-drv `0xe6e60`）。若设备实测要 100% 确认，
只需 `dos_type_en 0 0xffff` 后逐类型开关做 16 次差集（1 次上机即可）。

---

## 5. 每类型字段表（含函数名 + 地址，全部 [观测]）

`img` 基址 sp+68；`bfi` 指令地址一并给出。所有 `_set`（使能）宽度均为 **1 bit**，
`_pol_id_set` 宽度均为 **9 bit**，`_th_set` 宽度均为 **16 bit**。

| 类型 | `_pol_id_set` @ / bfi @ | pol_id 字段 | `_th_set` @ / bfi @ | th 字段 | `_set` @ / bfi @ | en 字段 |
|---|---|---|---|---|---|---|
| icmp_flood | `0xe62b8` / `0xe6368` `bfxil #0,#9` | `0x32ec[8:0]` | `0xe63a0` / `0xe6450` `bfi #9,#16` | `0x32ec[24:9]` | `0xe6488` / `0xe6538` `bfi #25,#1` | `0x32ec[25]` |
| fin_flood | `0xe6570` / `0xe6620` `bfi x #26,#9` | `0x32ec[31:26]`+`0x32f0[2:0]` | `0xe6658` / `0xe6708` `bfi #3,#16` | `0x32f0[18:3]` | `0xe6740` / `0xe67f0` `bfi #19,#1` | `0x32f0[19]` |
| syn_flood | `0xe6828` / `0xe68d8` `bfi #20,#9` | `0x32f0[28:20]` | `0xe6910` / `0xe69c4` `orr lsl#29` + `0xe69d0` `ubfx #3,#13` | `0x32f0[31:29]`+`0x32f4[12:0]` | `0xe6a10` / `0xe6ac0` `bfi #13,#1` | `0x32f4[13]` |
| syn_with_data | `0xe6af8` / `0xe6ba8` `bfi #14,#9` | `0x32f4[22:14]` | — | — | `0xe6be0` / `0xe6c90` `bfi #23,#1` | `0x32f4[23]` |
| udp_bomb | `0xe6cc8` / `0xe6d78` `bfi x #24,#9` | `0x32f4[31:24]`+`0x32f8[0]` | — | — | `0xe6db0` / `0xe6e60` `bfi #1,#1` | `0x32f8[1]` |
| ping_of_death | `0xe6e98` / `0xe6f48` `bfi #2,#9` | `0x32f8[10:2]` | — | — | `0xe6f80` / `0xe7030` `bfi #11,#1` | `0x32f8[11]` |
| icmp_fragment | `0xe7068` / `0xe7118` `bfi #12,#9` | `0x32f8[20:12]` | — | — | `0xe7150` / `0xe7200` `bfi #21,#1` | `0x32f8[21]` |
| tcp_frag_error | `0xe7238` / `0xe72e8` `bfi #22,#9` | `0x32f8[30:22]` | — | — | `0xe7320` / `0xe73d0` `bfi #31,#1` | `0x32f8[31]` |
| tcp_short_hdr | `0xe7408` / `0xe74b8` `bfxil #0,#9` | `0x32fc[8:0]` | — | — | `0xe74f0` / `0xe75a0` `bfi #9,#1` | `0x32fc[9]` |
| syn1024 | `0xe75d8` / `0xe7688` `bfi #10,#9` | `0x32fc[18:10]` | — | — | `0xe76c0` / `0xe7770` `bfi #19,#1` | `0x32fc[19]` |
| null_scan | `0xe77a8` / `0xe7858` `bfi #20,#9` | `0x32fc[28:20]` | — | — | `0xe7890` / `0xe7940` `bfi #29,#1` | `0x32fc[29]` |
| xma_scan | `0xe7978` / `0xe7a28` `bfi x #30,#9` | `0x32fc[31:30]`+`0x3300[6:0]` | — | — | `0xe7a60` / `0xe7b10` `bfi #7,#1` | `0x3300[7]` |
| syn_fin_scan | `0xe7b48` / `0xe7bf8` `bfi #8,#9` | `0x3300[16:8]` | — | — | `0xe7c30` / `0xe7ce0` `bfi #17,#1` | `0x3300[17]` |
| blat_attacks | `0xe7d18` / `0xe7dc8` `bfi #18,#9` | `0x3300[26:18]` | — | — | `0xe7e00` / `0xe7eb0` `bfi #27,#1` | `0x3300[27]` |
| land_attacks | `0xe7ee8` / `0xe7f98`–`0xe7fb4` | `0x3300[31:28]`+`0x3304[4:0]` | — | — | `0xe7fe8` / `0xe8098` `bfi #5,#1` | `0x3304[5]` |
| smac_eq_dmac | `0xe80d0` / `0xe8180` `bfi #6,#9` | `0x3304[14:6]` | — | — | `0xe81b8` / `0xe8268` `bfi #15,#1` | `0x3304[15]` |

**跨寄存器字段的确切指令（照抄用）**：
- `fin_flood pol_id`（`0xe6620`）：`ldur x0,[sp,#68]; bfi x0, w22, #26, #9; stur x0,[sp,#68]`
  → 低 3 位进 `0x32f0[2:0]`，高 6 位进 `0x32ec[31:26]`。
- `syn_flood th`（`0xe69c0`–`0xe69e0`）：
  `img[1] = (img[1] & 0x1fffffff) | (val << 29)`；`img[2] = (img[2] & 0xffffe000) | (val >> 3 & 0x1fff)`
- `udp_bomb pol_id`（`0xe6d78`）：`bfi x0, w22, #24, #9` on `img[2..3]` ⇒ `0x32f8[0]` 拿最高位。
- `xma_scan pol_id`（`0xe7a28`）：`bfi x0, w22, #30, #9` on `img[4..5]` ⇒ `0x3300[6:0]` 拿高 7 位。
- `land_attacks pol_id`（`0xe7f98`–`0xe7fb4`）：
  `img[5] = (img[5] & 0x0fffffff) | (val << 28)`；`img[6] = (img[6] & 0xffffffe0) | ((val >> 4) & 0x1f)`
  → **注意这条字段物理上不连续**（`0x3300[31:28]` 后接 `0x3304[4:0]`），
  与 `ca-ne.ko` mask bit31 同时覆盖两个字完全一致。

---

## 6. `dos_port_mask` = 64 bit @ `0x3308` + `0x330c` **[观测]**

`__cli_aal_dos_atk_fib_dos_port_mask_set` @ **`0xe8380`**：
`cli_str2ll(argv[1])`（`0xe83d8`，**64 bit 解析**）→
```
str  w19,       [sp, #96]    ; 0xe8430  img[7] = 0x3308 = 低 32 bit
lsr  x19, x19, #32           ; 0xe8434
str  w19,       [sp, #100]   ; 0xe8438  img[8] = 0x330c = 高 32 bit
```
`show` 侧用 `ldr x3, [sp,#80]`（`0xe6280`，16 进制 `%016llx`）读回 64 bit ⇒ 双边一致。
语义（哪些端口/位）**[UNKNOWN]**：位与端口的对应未在本包任何模块内出现（无 per-bit 操作）。

---

## 7. flood 计数 `0x3310`（含一处 **OEM 自相矛盾**，必须记录）

| 侧 | 函数 @ | 行为 | 位域 |
|---|---|---|---|
| CLI `_cnt_cnt_set` | `0xe853c`，`bfxil #0,#10` @ `0xe85d4` | get→改→set，mask=0xffffffff | **`[9:0]` 10 bit** |
| CLI `_cnt_reserved_set` | `0xe860c`，`bfi #10,#22` @ `0xe86a4` | 同上 | `[31:10]` 22 bit |
| CLI `flood_cnt_get` | `0xe8468` | `aal_dos_atk_flood_cnt_get` 整字 | — |
| 驱动 `aal_dos_atk_flood_cnt_set` | ca-ne `0x920d0`，`bfxil #0,#11` @ `0x92128` | `ldrh w2,[x2]; reg = (reg&~0x7ff)|(w2&0x7ff)` | **`[10:0]` 11 bit** |
| 驱动 L2 `aal_l2_dos_atk_flood_cnt_set` | ca-ne `0x92aa0`，`bfxil #0,#10` @ `0x92afc` | — | `[9:0]` 10 bit |

⇒ **OEM 的 CLI 把 L3 计数器当 10 bit，OEM 的驱动当 11 bit（L2 两边都是 10 bit）。**
这是 OEM 内部不一致，不是我们的读错（两侧立即数都已逐条核对）。
**W6c 建议**：驱动层按 **11 bit `[10:0]`** 实现（与 ca-ne 一致，硬件宽度以驱动为准），
并在注释里记录 CLI 侧只写 10 bit 的差异；`reserved` 用 `[31:11]`。

---

## 8. `event_trap` / `event_drop` 字段表（6 个 timer 全部落实）

寄存器（ca-ne 直接可见）：`aal_dos_atk_event_trap_set` 用 **`0x3314`**（`0x921fc`/`0x922f8`），
`aal_dos_atk_event_drop_set` 用 **`0x3318`**（`0x923bc`/`0x924b8`）。两者字段布局**完全相同**。

CLI 侧（`*_set` 全部 mask=0xffffffff、cfg 单 u32、先 `get` 再改一位再 `set`）**[观测]**：

| 字段 | trap 函数 @ / bfi @ | drop 函数 @ / bfi @ | 寄存器位 | 宽 | ca-ne mask 位 |
|---|---|---|---|---|---|
| `rdir_ldpid` | `0xe9264` / `0xe92fc` `bfxil #0,#6` | `0xe8890` / `0xe8928` | `[5:0]` | 6 | 0 |
| `rdir_cos` | `0xe9334` / `0xe93cc` `bfi #6,#3` | `0xe8960` / `0xe89f8` | `[8:6]` | 3 | 1 |
| `keep_orig_pkt` | `0xe9404` / `0xe949c` `bfi #9,#1` | `0xe8a30` / `0xe8ac8` | `[9]` | 1 | 2 |
| **`reserved`** | `0xe94d4` / `0xe956c` `bfi #10,#1` | `0xe8b00` / `0xe8b98` | **`[10]`** | 1 | **无（不可写）** |
| **`t0_ctrl`** | `0xe95a4` / `0xe963c` `bfi #11,#1` | `0xe8bd0` / `0xe8c68` | **`[11]`** | **1** | 4 |
| `t1_ctrl` | `0xe9674` / `0xe970c` `bfi #12,#4` | `0xe8ca0` / `0xe8d38` | `[15:12]` | 4 | 5 |
| `t2_ctrl` | `0xe9744` / `0xe97dc` `bfi #16,#4` | `0xe8d70` / `0xe8e08` | `[19:16]` | 4 | 6 |
| `t3_ctrl` | `0xe9814` / `0xe98ac` `bfi #20,#4` | `0xe8e40` / `0xe8ed8` | `[23:20]` | 4 | 7 |
| `t4_ctrl` | `0xe98e4` / `0xe997c` `bfi #24,#4` | `0xe8f10` / `0xe8fa8` | `[27:24]` | 4 | 8 |
| `t5_ctrl` | `0xe99b4` / `0xe9a4c` `bfi #28,#4` | `0xe8fe0` / `0xe9078` | `[31:28]` | 4 | 9 |

**对上位表的更正**（RE-5 §5 原表 `[11]=reserved / [15:12]=t0 / … / [31:28]=t4`）：
CLI 的 6 个 timer 字段 + reserved 现在全部有确切槽位 ——
`reserved=[10]`、`t0=[11]`（**1 bit**）、`t1..t5=[15:12],[19:16],[23:20],[27:24],[31:28]`。
`ca-ne.ko` `aal_dos_atk_event_trap_set` 的 `tbz` 序列（`0x92220`–`0x922e8`）只处理 mask 位
`0,1,2,4,5,6,7,8,9`（**bit3 未用**，`[10]` 无人能写）——这与 CLI 把 `reserved` 放在 `[10]` 完全自洽：
**OEM 自己暴露的 `reserved` 旋钮是空操作**（mask 无对应位，写不进硬件）。**[观测+推导]**

`t0_ctrl` 只有 1 bit 是反直觉的，但两侧一致（cli-drv `bfi #11,#1`；ca-ne mask bit4 → `[11]` 1 bit），
按观测记录，不做语义猜测。

---

## 9. L2 DoS 块（同法闭合，作交叉验证）**[观测]**

L2 镜像 5 字：`img[k] = NE(0x1220+4k)`，CLI 基址 sp+52（`__cli_aal_l2_dos_atk_fib_*`）。

| 字段 | 函数 @ / bfi @ | 寄存器 | 宽 |
|---|---|---|---|
| icmp_flood th | `0x180870` / `0x180918` `strh [sp,#52]` | `0x1220[15:0]` | 16 |
| icmp_flood en | `0x180948` / `0x1809ec` `bfi #16,#1` | `0x1220[16]` | 1 |
| fin_flood th | `0x180a24` / `0x180acc` `bfi x #17,#16` | `0x1220[31:17]`+`0x1224[0]` | 15+1 |
| fin_flood en | `0x180b04` / `0x180bac` `bfi #1,#1` | `0x1224[1]` | 1 |
| syn_flood th | `0x180be4` / `0x180c8c` `bfi #2,#16` | `0x1224[17:2]` | 16 |
| syn_flood en | `0x180cc4` / `0x180d6c` `bfi #18,#1` | `0x1224[18]` | 1 |
| syn_with_data en | `0x180da4` / `0x180e4c` `bfi #19,#1` | `0x1224[19]` | 1 |
| udp_bomb en | `0x180e84` / `0x180f2c` `bfi #20,#1` | `0x1224[20]` | 1 |
| ping_of_death en | `0x180f64` / `0x18100c` `bfi #21,#1` | `0x1224[21]` | 1 |
| icmp_fragment en | `0x181044` / `0x1810ec` `bfi #22,#1` | `0x1224[22]` | 1 |
| tcp_frag_error en | `0x181124` / `0x1811cc` `bfi #23,#1` | `0x1224[23]` | 1 |
| tcp_short_hdr en | `0x181204` / `0x1812ac` `bfi #24,#1` | `0x1224[24]` | 1 |
| syn1024 en | `0x1812e4` / `0x18138c` `bfi #25,#1` | `0x1224[25]` | 1 |
| null_scan en | `0x1813c4` / `0x18146c` `bfi #26,#1` | `0x1224[26]` | 1 |
| xma_scan en | `0x1814a4` / `0x18154c` `bfi #27,#1` | `0x1224[27]` | 1 |
| syn_fin_scan en | `0x181584` / `0x18162c` `bfi #28,#1` | `0x1224[28]` | 1 |
| blat_attacks en | `0x181664` / `0x18170c` `bfi #29,#1` | `0x1224[29]` | 1 |
| land_attacks en | `0x181744` / `0x1817ec` `bfi #30,#1` | `0x1224[30]` | 1 |
| smac_eq_dmac en | `0x181824` / `0x1818cc` `bfi #31,#1` | `0x1224[31]` | 1 |
| **`dos_type_en`** | `0x181904` / `0x1819ac` `strh [sp,#60]` | **`0x1228[15:0]`** | **16** |
| **`dos_port_mask`** | `0x181ab4` / `0x181b5c` `strh [sp,#62]`、`0x181b64` `str [sp,#64]`、`0x181b6c` `strh [sp,#68]` | `0x1228[31:16]` + `0x122c[31:0]` + `0x1230[15:0]` | 16+32+16 = 64 |

⇒ **L2 补正**：`dos_type_en` 是 **`0x1228[15:0]`**（不是 RE-5 §14.2 猜的 `0x1220[31:0]`）；
`dos_port_mask` 是 `0x1228[31:16]`+`0x122c`+`0x1230[15:0]`（与 RE-5 §14.1 一致）。
L2 无 `pol_id`（CLI 无对应命令），16 类型 = 3×(th16+en1) + 13×en1 = 64 bit，正好铺满 `0x1220..0x1224`。
**类型顺序与 L3 完全相同（S 序）**，`dos_type_en` 位号也与 L3 相同（`ca-rtk` 用同一个 `w19` 置位 L2，
`0xcb9c`–`0xcbcc`，mask bit19 = `0x1228[15:0]`）。

---

## 10. 与现有 W6c 候选表的差异（`phase2-re5-dos-attack.md` §16 / 实现草案）

| # | RE-5 原结论 | 本轮结论 | 影响 |
|---|---|---|---|
| 1 | `dos_type_en` 落 `0x3304[31:0]`（32 bit），1 bit/类型未证 | **`0x3304[31:16]`，16 bit，bit k = S[k]**，已证 | **必须改**：写 32 bit 会覆盖 land/smac 的字段 |
| 2 | `0x3304[31:16]` 单独装不下 32 bit ⇒ 否掉 | 恰好就是 16 bit，CLI 的 32 bit 只是解析量程 | 同上 |
| 3 | 9 bit 字段疑为「阈值」、16 bit 疑为「端口掩码」 | **9 bit = pol_id，16 bit = th**；端口掩码是 64 bit `0x3308/0x330c` | **改命名，语义反了** |
| 4 | type→bit 两个候选序 S / R，未定案 | **CLI（S 序）= 位号序；DAL `attack_type` = R 序** | 两个序都对，但用在不同层；W6c 用 S |
| 5 | 16 类型 vs 14 组「值+使能」差 2，成因不明 | 3 个 flood 有 th(16)+en(1)，其余 13 个只有 pol_id(9)+en(1)；208 bit 精确铺满 | 矛盾消解 |
| 6 | trap：`reserved=[11]`、`t0=[15:12]`…`t4=[31:28]`、`t5` 无槽 | `reserved=[10]`、`t0=[11]`(1 bit)、`t1..t5=[15:12]..[31:28]` | **偏移一格，全部改** |
| 7 | L3 flood_cnt `[10:0]` 11 bit（ca-ne） | ca-ne 11 bit / CLI 10 bit，**OEM 内部不一致** | 驱动按 11 bit，注释记录 |
| 8 | L2 `dos_type_en` = `0x1220[31:0]` | **`0x1228[15:0]`** | 若 W6c 也做 L2，必须改 |
| 9 | `0x3304[15]` 独立 1 bit（正确） | 确认是 smac_eq_dmac en | 不变 |
| 10 | `0x3348` dual_dos_en 无人访问 | 在 `cli-drv.ko`/`ca-rtk.ko`/`ca-ne.ko` 中均 **0 命中** | 仍 UNKNOWN（三方都不碰） |

---

## 11. W6c 可直接替换的 `enum` / 宏 / 字段表

```c
/* ===== 寄存器块 ===== */
#define NE_DOS_L3_ATK(n)     (0x32ecu + 4u * (n))   /* n=0..8 : L3FE_PP_DOS_ATK_0..8 */
#define NE_DOS_L3_FLOOD_CNT  0x3310u
#define NE_DOS_L3_EVT_TRAP   0x3314u
#define NE_DOS_L3_EVT_DROP   0x3318u
#define NE_DOS_L2_ATK(n)     (0x1220u + 4u * (n))   /* n=0..4 : L2FE_PP_DOS_ATK_0..4 */
#define NE_DOS_L2_FLOOD_CNT  0x1234u
#define NE_DOS_L2_EVT_TRAP   0x1238u

/* ===== 类型号 = 位号 = CLI 顺序（S 序）。ca-rtk.ko DAL 的 attack_type 是它的逆序 ===== */
enum rtl_dos_type {
    RTL_DOS_TYPE_ICMP_FLOOD = 0,   /* type_en bit0  */
    RTL_DOS_TYPE_FIN_FLOOD,        /* bit1  */
    RTL_DOS_TYPE_SYN_FLOOD,        /* bit2  */
    RTL_DOS_TYPE_SYN_WITH_DATA,    /* bit3  */
    RTL_DOS_TYPE_UDP_BOMB,         /* bit4  */
    RTL_DOS_TYPE_PING_OF_DEATH,    /* bit5  */
    RTL_DOS_TYPE_ICMP_FRAGMENT,    /* bit6  */
    RTL_DOS_TYPE_TCP_FRAG_ERROR,   /* bit7  */
    RTL_DOS_TYPE_TCP_SHORT_HDR,    /* bit8  */
    RTL_DOS_TYPE_SYN1024,          /* bit9  */
    RTL_DOS_TYPE_NULL_SCAN,        /* bit10 */
    RTL_DOS_TYPE_XMA_SCAN,         /* bit11 */
    RTL_DOS_TYPE_SYN_FIN_SCAN,     /* bit12 */
    RTL_DOS_TYPE_BLAT_ATTACKS,     /* bit13 */
    RTL_DOS_TYPE_LAND_ATTACKS,     /* bit14 */
    RTL_DOS_TYPE_SMAC_EQ_DMAC,     /* bit15 */
    RTL_DOS_TYPE_MAX = 16,
};

/* dos_type_en = 0x3304[31:16]，一位一类型 */
#define L3_DOS_TYPE_EN_REG      0x3304u
#define L3_DOS_TYPE_EN_SHIFT    16
#define L3_DOS_TYPE_EN_BIT(t)   BIT(t)                    /* 只允许 t<16 */
#define L3_DOS_TYPE_EN_ALL      0xffffu
#define L2_DOS_TYPE_EN_REG      0x1228u                   /* [15:0] */
#define L2_DOS_TYPE_EN_SHIFT    0

/* 端口掩码 = 64 bit */
#define L3_DOS_PORT_MASK_LO     0x3308u
#define L3_DOS_PORT_MASK_HI     0x330cu
#define L2_DOS_PORT_MASK_W0     0x1228u   /* [31:16] = bits[15:0] */
#define L2_DOS_PORT_MASK_W1     0x122cu   /* bits[47:16] */
#define L2_DOS_PORT_MASK_W2     0x1230u   /* [15:0]  = bits[63:48] */

/* 只有 3 个 flood 有 th；pol_id 只有 L3 有 */
#define RTL_DOS_HAS_TH(t)       ((t) <= RTL_DOS_TYPE_SYN_FLOOD)
#define RTL_DOS_IS_L3_POL(t)    (1)

/* ===== 字段位置表（reg = NE 偏移；wide=1 表示跨寄存器，按 64 bit 位流处理） ===== */
struct rtl_dos_field { u16 reg; u8 lsb; u8 width; u8 wide; };
struct rtl_dos_type_desc {
    struct rtl_dos_field pol;      /* width=0 → 无此字段 */
    struct rtl_dos_field th;
    struct rtl_dos_field en;
};
/* 展开后的 16 行（pol/ th/ en），可直接 static const 初始化： */
static const struct rtl_dos_type_desc rtl_dos_types[RTL_DOS_TYPE_MAX] = {
 /* icmp_flood    */ { {0x32ec, 0, 9,0}, {0x32ec, 9,16,0}, {0x32ec,25,1,0} },
 /* fin_flood     */ { {0x32ec,26, 9,1}, {0x32f0, 3,16,0}, {0x32f0,19,1,0} },
 /* syn_flood     */ { {0x32f0,20, 9,0}, {0x32f0,29,16,1}, {0x32f4,13,1,0} },
 /* syn_with_data */ { {0x32f4,14, 9,0}, {0,0,0,0},          {0x32f4,23,1,0} },
 /* udp_bomb      */ { {0x32f4,24, 9,1}, {0,0,0,0},          {0x32f8, 1,1,0} },
 /* ping_of_death */ { {0x32f8, 2, 9,0}, {0,0,0,0},          {0x32f8,11,1,0} },
 /* icmp_fragment */ { {0x32f8,12, 9,0}, {0,0,0,0},          {0x32f8,21,1,0} },
 /* tcp_frag_error*/ { {0x32f8,22, 9,0}, {0,0,0,0},          {0x32f8,31,1,0} },
 /* tcp_short_hdr */ { {0x32fc, 0, 9,0}, {0,0,0,0},          {0x32fc, 9,1,0} },
 /* syn1024       */ { {0x32fc,10, 9,0}, {0,0,0,0},          {0x32fc,19,1,0} },
 /* null_scan     */ { {0x32fc,20, 9,0}, {0,0,0,0},          {0x32fc,29,1,0} },
 /* xma_scan      */ { {0x32fc,30, 9,1}, {0,0,0,0},          {0x3300, 7,1,0} },
 /* syn_fin_scan  */ { {0x3300, 8, 9,0}, {0,0,0,0},          {0x3300,17,1,0} },
 /* blat_attacks  */ { {0x3300,18, 9,0}, {0,0,0,0},          {0x3300,27,1,0} },
 /* land_attacks  */ { {0x3300,28, 9,1}, {0,0,0,0},          {0x3304, 5,1,0} },
 /* smac_eq_dmac  */ { {0x3304, 6, 9,0}, {0,0,0,0},          {0x3304,15,1,0} },
};
/* wide=1 的 pol_id 按 64 bit 位流取：base=reg 起的 (reg,reg+4) 两字拼成 u64，
   bit[lsb..lsb+8]；th 同理（syn_flood 的 th、fin_flood th 用 32/64 bit 组合）。*/

/* ===== trap / drop（0x3314 / 0x3318 同构） ===== */
#define DOS_EVT_RDIR_LDPID(v)    (((u32)(v) & 0x3fu) << 0)   /* [5:0]  */
#define DOS_EVT_RDIR_COS(v)      (((u32)(v) & 0x07u) << 6)   /* [8:6]  */
#define DOS_EVT_KEEP_ORIG(v)     (((u32)(v) & 0x01u) << 9)   /* [9]    */
#define DOS_EVT_RESERVED(v)      (((u32)(v) & 0x01u) << 10)  /* [10] 无 mask 位→写不进硬件 */
#define DOS_EVT_T0(v)            (((u32)(v) & 0x01u) << 11)  /* [11] 1 bit! */
#define DOS_EVT_TN(i, v)         (((u32)(v) & 0x0fu) << (12 + 4*((i)-1)))  /* i=1..5 */
#define DOS_EVT_MASK_LDPID  BIT(0)
#define DOS_EVT_MASK_COS    BIT(1)
#define DOS_EVT_MASK_KEEP   BIT(2)
#define DOS_EVT_MASK_T0     BIT(4)
#define DOS_EVT_MASK_TN(i)  BIT(5 + ((i)-1))                 /* i=1..5 */

/* ===== flood 计数 / 使能 ===== */
#define DOS_FLOOD_CNT_L3_MASK   GENMASK(10, 0)   /* ca-ne 驱动口径 11 bit（CLI 只写 10） */
#define DOS_FLOOD_CNT_L2_MASK   GENMASK(9, 0)
```

**实现要点（全部由本轮观测强制）**
1. **使能一个类型要写两处**：`en` 位（§5 表）**和** `dos_type_en` 的 `BIT(k)`。
   OEM 的 DAL（`ca-rtk` `0xcb20`/`0xcb50`）就是同时置两处；CLI 的 `dos_atk <unit> <type> 1` 只置前者。
2. `dos_type_en` **只能写 16 bit**（`strh`）；写 32 bit 会踩坏 land/smac 的 pol_id/en。
3. `land_attacks` 的 pol_id 和 3 个 flood 的 th 跨寄存器，**必须按位流读改写**，
   不能用单寄存器 RMW 宏。
4. `aal_dos_atk_set` 是 masked-blit（RE-5 §1 已证），CLI 用 `~0ULL` 整块回写；
   我们实现建议**按字段位给最小 mask**（更安全），但必须保留其它字段。
5. `reserved`（`0x3314[10]` / `0x3318[10]`）**无 mask 位可写**，不要把它当可配项暴露。
6. 上电默认值仍 **[UNKNOWN]**（RE-5 §6：init 只初始化锁）。

---

## 12. 残留 UNKNOWN（本轮之后）

| # | 项 | 状态 |
|---|---|---|
| U-a | `udp_bomb` 的 `dos_type_en` 位 = bit4 | **推导（高置信）**：DAL 的 attack_type 11 报错，位号 4 空缺，与 S 序连续编号吻合；需 1 次设备差集实测 |
| U-b | `dos_port_mask` 的 64 位与端口号的对应 | UNKNOWN（本包无 per-bit 操作；`ca-rtk`/`cli-drv`/`ca-ne` 都整块读写） |
| U-c | `t0_ctrl` 为何仅 1 bit（而 t1..t5 各 4 bit） | UNKNOWN（两侧一致，非读错；语义待设备/文档） |
| U-d | `pol_id` 9 bit 指向哪张策略表 | UNKNOWN（本包内无消费者） |
| U-e | `0x3348`（`L3FE_PP_dual_dos_en`） | UNKNOWN，`cli-drv.ko` / `ca-rtk.ko` / `ca-ne.ko` **三方 0 命中** |
| U-f | L3 flood_cnt 10 vs 11 bit | OEM 内部矛盾（§7），W6c 取 11 bit 并注释 |
| U-g | DoS 块上电默认值 / 是否需要显式关闭 | UNKNOWN（三方都没有 default 下发） |

---

## 13. 证据索引

| 内容 | 证据 |
|---|---|
| `cli-drv.ko` 全部 DoS 符号（62 个 `__cli_aal_*dos_atk*` + 7 个 `U aal_dos_atk_*`） | `aarch64-linux-gnu-nm cli-drv.ko \| grep -i dos_atk` |
| setter 模板 + `field_mask = ~0ULL` + `img` 基址 sp+68 | `objdump -dr --start=0xe62b8 --stop=0xe6570`（`0xe62f8` `stur x0,[sp,#60]`；`0xe635c` `ldr w0,[sp,#68]`） |
| `img[k] = NE(0x32ec+4k)` 的顺序依据 | ca-ne `aal_dos_atk_get` @ `0x91f50`，`0x91f74`–`0x92090` 九个 `mov x?,#0x33xx` |
| `show dos_atk` 字段名与顺序（S 序） | `.rodata.str1.1+0x16b7c..0x16de1`（`icmp_flood_pol_id` … `smac_eq_dmac`, `dos_type_en`, `dos_port_mask`）；打印点 `0xe5e58`–`0xe6298` |
| `dos_type_en` = 16 bit | `0xe8350` `strh w22,[sp,#94]`；回读 `0xe6268` `ldrh w3,[sp,#78]` |
| `dos_port_mask` = 64 bit | `0xe8430`/`0xe8434`/`0xe8438`；回读 `0xe6280` `ldr x3,[sp,#80]` |
| 16 类型 × 3 变体的 bfi 立即数 | `objdump -dr --start=0xe62b8 --stop=0xe82a0`（逐条列于 §5） |
| 跨寄存器字段的位运算 | `0xe69c0`–`0xe69e0`（syn th）、`0xe7f98`–`0xe7fb4`（land pol_id） |
| trap/drop 字段 | `0xe9264`–`0xe9a84`（trap）、`0xe8890`–`0xe90b0`（drop） |
| ca-ne trap mask 位 → 寄存器位 | `aal_dos_atk_event_trap_set` @ `0x921d0`，`tbz` 序列 `0x92220`–`0x922e8`；寄存器 `0x3314`（`0x921fc`） |
| ca-ne drop 寄存器 `0x3318` | `0x923bc` / `0x924b8` |
| ca-ne flood_cnt 11 bit | `0x92128` `bfxil #0,#11`；L2 `0x92afc` `bfxil #0,#10` |
| **DAL 跳表（type→bit 决定件）** | ca-rtk `dal_rtl8277c_sec_attackPrevent_set` @ `0xc7a8`；跳表 `.rodata+0x1020`（文件偏移 `0x1f720`，16×int16 = 0,10,20,…,161,-48）；`0xcb20` `lsl w19,w0,w19`；`0xcb50` `strh w3,[sp,#126]`；`0xcb54` mask bit35 |
| DAL 的 L2 同源置位 | `0xcb9c`–`0xcbcc`（mask bit19 = `0x1228[15:0]`） |
| DAL `attackFloodThresh_set` 复核 3 个 th 位置 | ca-rtk `0xcd54`：`0xce10` `bfi #9,#16`、`0xce60`/`0xce70`（29/3 跨字）、`0xcea0` `bfi #3,#16`；L2 `0xce84` `bfi #2,#16`、`0xceb0` `bfi x #17,#16` |
| L2 块逐字段 | `objdump -dr --start=0x180870 --stop=0x181b70` |

---

## 14. 给 lead 的三句话

1. **type→bit 不再是 UNKNOWN**：`0x3304[31:16]` 的 bit k = S 序第 k 个类型，已被 `ca-rtk.ko` 的
   `1 << w19` + `strh` 直接证明（不是猜的枚举序）。
2. **W6c 的候选表有 6 处必须改**：`dos_type_en` 宽度/位置、pol_id 与 th 语义互换、
   trap 的 reserved/t0 偏移、L2 `dos_type_en` 位置、flood_cnt 位宽矛盾。
3. **使能要写两处**（per-type en + `dos_type_en` bit），且 `land_attacks` pol_id 与 3 个 flood `th`
   跨寄存器，必须按位流实现。