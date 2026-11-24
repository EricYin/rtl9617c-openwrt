# Phase 2 RE-4 — Host Policing / Rate-Meter / MIB / MAC-LUT 绑定 规格书

状态：**Phase 2 只读逆向**。语料仅 `fc_mgr.ko` + `ca-ne.ko`（+ 开源 `rtl9617c` 对照树 / `default_scfg.txt` 仅作旁证），
本轮**未修改** `pt1500-refactor-build`、`pt1500-immortalwrt-build` 中任何文件。

## 0. 语料、工具与标注约定

| 项 | 值 |
|---|---|
| `fc_mgr.ko` | `/mnt/c/rea/fc_mgr.ko`，aarch64，not stripped，sha256 `10c4f7f0dc22762de96768e80cb90e7d4203c2b406fccf1197f4fdc2daace479`（与 `scratch/stock-probe/.../FleetConntrackDriver/fc_mgr.ko` 同文件） |
| `ca-ne.ko` | `/mnt/c/rea/ca-ne.ko`，sha256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e` |
| 反汇编 | `aarch64-linux-gnu-objdump -dr --no-show-raw-insn`（保留重定位，确认 `g_ne_reg_iobase` / `fc_db` 基址） |
| 语义 | REA（Ghidra 12.1.4）`procedure_pseudo_code` / `trace_feature` / `procedure_callers`；REA 证据 ID 见附录 A |
| 地址 | 本文一律给 **nm 节内地址**（即 objdump 显示的符号地址）。REA 地址 = 节内地址 + `0x100040`（已验证：`0xbe640 → 0x1be680`；`0x391b0 → 0x1391f0`）。`ca-ne` 同一换算。 |
| `fc_db` | `fc_mgr` 的全局驱动数据库指针（`.bss` 符号 `fc_db`，`adrp/ldr` 两处重定位可直接确认）。下文 `fc_db+0xNNNN` 均为该结构的字节偏移，不是 NE 寄存器。 |

标注级别：**[观测]** = 反汇编/伪代码直接可见；**[推导]** = 由多处观测合并；**[UNKNOWN]** = 语料内无法确认。

---

## 1. Host Policing 数据模型（96 索引空间的真实含义）

### 1.1 三个并行数组（全部在 `fc_db` 内） **[观测]**

| 结构 | 基址 | 步长 | 项数 | 含义 |
|---|---|---|---|---|
| 控制表（SW 副本） | `fc_db + 0xC200B0` | `0x28`(40 B) | **96** | 每个 hostIndex 一条，内容 = 用户下发的 36 B 控制结构 + `u16 id` |
| 每-id 运行结构 | `fc_db + 0xC20FB0` | `0x50`(80 B) | ≥96（优化模式 96） | 一条 host police 条目的 HW 句柄：meter 索引 / pol1 索引 / MIB 累计 / 链表节点 |
| LUT 入口指针数组 | `fc_db + 0xBF0090`（= `(lutIdx+0x17E012)*8`） | 8 B | lutIdx ≤ **0x1027**(4135) | 每个 MAC LUT 表项一个指针，表项 `+0x1E` = hostPolice 索引 |

证据：
- 96 上限：`rtk_fc_hostPoliceControl_set` @ `0xbe640`，`cmp w20,#0x5f; b.hi`（0..95）；
  `rtk_fc_hostPoliceMib_get/clear` @ `0xb7380`/`0xb7290` 同样 `cmp #0x5f`。
- 控制表步长 0x28、96 项：`set` 内重复 MAC 扫描 `piVar7 = &DAT_00e38c38; … piVar7 += 10; while (uVar14 != 0x60)`（`0xbe704..0xbe720`）。
- 每-id 结构步长 0x50：`_rtk_fc_hwHostPolingMib_get` @ `0x544e0` 的 `mov x0,#0x50; madd x0,x19,x0,x20; add x0,x0,#0xc20,lsl#12; ldur x0,[x0,#-24]`
  ⇒ `fc_db + id*0x50 + 0xC20FE8`（= 基址 `0xC20FB0` + `0x38`）。
- LUT 指针数组：`_rtk_fc_lutHostPolicingIdxUpdate` @ `0x391b0`：
  `mov x2,#0xe012; movk x2,#0x17,lsl#16; add x5,x2,w5,sxtw; ldr x0,[fc_db,x5,lsl#3]; strh w1,[x0,#30]`。

### 1.2 控制结构（36 B，用户 ABI） **[观测]**

`rtk_fc_proc_host_policing_config_set` @ `0x890e0` 逐字段解析 procfs 行，随后把结构体拷到栈上调用 `set`；
usage 字符串（`.rodata.str1.8`，`strings fc_mgr.ko | grep host_policing_config`）：

```
echo hostIndex MAC mibCountCtrl ingressLimitCtrl ingressLimitMeterIdx egressLimitCtrl egressLimitMeterIdx [ingressLimitRate egressLimitRate] > /proc/fc/ctrl/host_policing_config
```

字段落位（`set` 的 `param_2` 为 `u32[]`）：

| 偏移 | 类型 | 名称 | 取值/语义 |
|---|---|---|---|
| `+0x00` | `u8[6]` | `mac` | 目的/源 MAC（同一 MAC 同时承担 ingress-SA 与 egress-DA 两个角色） |
| `+0x06` | `u16` | pad | — |
| `+0x08` | `u32` | `ingressLimitCtrl` | 0..2（0=关，非 0=开） |
| `+0x0c` | `u32` | `egressLimitCtrl` | 0..2 |
| `+0x10` | `u32` | `mibCountCtrl` | 0..2（0=不计；非 0=计，见 §4/§8） |
| `+0x14` | `u32` | `ingressLimitMeterIdx` | **虚拟 meter 索引**（不是速率！） |
| `+0x18` | `u32` | `egressLimitMeterIdx` | 虚拟 meter 索引 |
| `+0x1c` | `u32` | `ingressLimitRate` | kbps；`0xFFFFFFFF` = 不变；上限 `0x1F3FFFF`(32 767 999) |
| `+0x20` | `u32` | `egressLimitRate` | 同上 |

- 速率上限与「不限速哨兵」：`rtk_fc_proc_host_policing_config_set` 对第 8/9 个参数做
  `cmn w0,#1`（允许 −1）/ `cmp w0,#0x1f3ffff`（`0x8929c..0x892e0`）；
  `_rtk_fc_g3L3Policer_set` @ `0x52960` 以 `param_2 == 0x1f3ffff` 作为**关闭**分支。
- `MAC = 00:00:00:00:00:00` 表示**删除该索引**：`set` 在 `clear` 之后比较新 MAC 的 6 字节是否为 0
  （`local_14==0 && local_10==0` ⇒ 解锁返回 0，`0xbe6f4..0xbe700`、`0xbe970`）。
- MAC 不能重复：同一 `(mac[0:3], mac[4:5])` 在其余 95 项中出现即返回 `-1`（`0xbe704..0xbe760`，
  日志 `"Set host policing entry failed! The MAC %pM has been set in entry [%d]."`）。

### 1.3 96 个索引怎么分？——**按「终端(MAC)」分，不分方向/端口** **[观测]**

- 96 项的唯一键是 **MAC**（重复检查只比较 MAC；控制结构里没有任何 port/方向字段）。
- 每条目内部再分 **ingress(SA)** 与 **egress(DA)** 两套独立配置（meter / rate / MIB）。
- 方向语义有字符串硬证（`fc_mgr.ko` 字符串表）：
  `L2_INGRESS_SA_HOSTPOLICING`、`L2_EGRESS_DA_HOSTPOLICING`、
  `"SA %pM is set in hostPolice[%d]… update its rx count"`、`"DA %pM is set in hostPolice[%d]… update its tx count"`。
- ⇒ **96 = 可做 MAC 级限速/计数的终端数**；不是「端口×方向×终端」的笛卡尔积。
  端口维度只出现在共享的 SW 限速器 `rtk_fc_sw_rate_limit_set(port≤3, …)` @ `0xb4a70`，与 host 表无关。

### 1.4 每-id 运行结构（0x50 B） **[观测]**

`fc_db + 0xC20FB0 + id*0x50`：

| 偏移 | 类型 | 含义 | 证据 |
|---|---|---|---|
| `+0x00` | `u64` | SW Rx 计数 A | `_rtk_fc_sw_hostMib_all_cpu_get` @ `0x3f640` 读 `+0xFB0`(4016) 与 `+0xFC0`(4032) 相加 |
| `+0x08` | `u64` | SW Tx 计数 A | 同上（dir=1 时读 `+0xFB8`/`+0xFC8`） |
| `+0x10` | `u64` | SW Rx 计数 B | 同上 |
| `+0x18` | `u64` | SW Tx 计数 B | 同上 |
| `+0x20` | `u32` | **hw_ctl**（见 §1.5） | `set` `str w0,[x5,#4048]`；`clear` `and #0xffc00000; orr #0xfffff` |
| `+0x24` | `u16`+pad | **hostPolConfList id**（0..95，`0xFFFF`=空闲） | `set` `strh w7,[x1,#212]`（`0xbea38`）；`clear` `strh w0,[x23,#212]`（`0xbe408`） |
| `+0x28` | `u64` | **HW Rx 累计** | `_rtk_fc_hwHostPolingMib_get` `ldr x0,[x19,#4056]` |
| `+0x30` | `u64` | **HW Tx 累计** | `ldr x0,[x19,#4064]` |
| `+0x38` | `u32` | **pol1 索引字**：`[9:0]` ingress pol1、`[19:10]` egress pol1、`0x3FF`=无 | `(&DAT_00e39b70)[id*0x14]`；`clear` `orr #0xfffff` |
| `+0x40` | `void*` | 空闲链表 next | `clear` `str x1,[x0,#4080]` |
| `+0x48` | `void*` | 空闲链表 prev | `str x27,[x5,#4088]` |

### 1.5 `hw_ctl` 位域 **[观测]**

`set` 在 `0xbe9d0..0xbea78` 组装并写 `per-id + 0x20`：

```c
hw_ctl = (ingress_hw_meter_idx & 0x3FF)
       | (egress_hw_meter_idx  & 0x3FF) << 10
       | (ingress_is_sw_type ? 1u : 0u) << 20
       | (egress_is_sw_type  ? 1u : 0u) << 21
       | (hw_ctl & 0xFFC00000);          /* [31:22] 保留 */
```

- `[9:0]` / `[19:10]` = 映射函数返回的**硬件 meter 索引**（不是用户给的虚拟索引）。
- `bit20/bit21` = `rt_rate_shareMeterMappingHw_get` 返回 `type==4(SW)` 时为 1；`type==1(HOST)` 时为 0。
  `rtk_fc_hostPoliceControl_get` @ `0xb4620` 正是用这两位决定回读走 `_rtk_fc_l3Meter_get()` 还是 SW 表。
- `0xFFC00000` 保留位：OEM 用读改写保留，我们实现时应显式写 0。

### 1.6 `pol1` 索引字（`per-id +0x38`） **[观测]**

- `[9:0]` ingress 计数/限速 policer（POL1）索引，`0x3FF` = 无；
- `[19:10]` egress 同类索引；
- `clear` 写 `(old & 0xFFC00000) | 0xFFFFF`（两个方向都置 0x3FF）。
- 读回方式：`bits[9:0] = (V << 0x36) >> 0x36`；`bits[19:10] = (V << 0x2C) >> 0x36`（见 §4）。

---

## 2. `rtk_fc_hostPoliceControl_set` / `_clear` 完整序列

### 2.1 `_rtk_hostPoliceControl_clear(idx)` @ `0xbe1f0` **[观测]**

```
 1. 取 SW 条目 S = fc_db+0xC200B0+idx*0x28；
    if (S.mac != 0) {
        if (_rtk_fc_lut_find(S.mac, &lutIdx, 0) == 0)          // fc_mgr 0x380b0
            rtk_fc_flow_delete_by_l2Idx(lutIdx);               // 0x5a9d0：删加速流，解除旧绑定
    }
 2. id = S.hostPolConfList_idx (S+0x24, s16)；
    if (id != -1) {
        _rtk_fc_hwHostPolingMib_clear(id);                     // 0x54680：读空 HW 计数 + 清 SW 累计
        memset(fc_db+0xC20FB0+id*0x50, 0, 0x20);               // +0x00..0x1F 四个 u64
        hw_ctl = (hw_ctl & 0xFFC00000) | 0xFFFFF;              // 关两个方向的 meter
        if (S.mibCountCtrl == 1) {                             // 仅 ==1 才释放 pol1
            release_pol1(pol1_word[9:0]);                      // 见 §2.3
            release_pol1(pol1_word[19:10]);
        }
        *(u64*)(per-id+0x28) = 0; *(u64*)(per-id+0x30) = 0;    // 清 HW 累计
        pol1_word |= 0xFFFFF;
        if (id < 0x60) { list_add_tail(&per-id->node, &fc_db[0xC22DC0]); }
        else { warn "hostPolConfList_idx should < RTK_FC_HOSTPOLICING_TABLE_HW_SIZE(96)" }
        S.hostPolConfList_idx = 0xFFFF;
    }
 3. memset(S, 0, 0x24);                                        // 只清 36 B 控制结构；+0x24 的 id 已在第 2 步置 0xFFFF
 4. _rtk_fc_lutHostPolicingIdxUpdate(S.mac);                   // 把 LUT 表项 +0x1E 置 0xFFFF
```

### 2.2 `rtk_fc_hostPoliceControl_set(idx, ctrl)` @ `0xbe640` **[观测]**

```
 0. if (idx > 95) return 0x10005;
 1. 逐方向解析虚拟 meter → 硬件 meter（函数 rtk_fc_rt_rate_shareMeter_mapping_hw_get @ 0xD800，
    实际是外部 rt_rate_shareMeterMappingHw_get 的尾调用 thunk）：
      ingress: mapping(ctrl.ingressLimitMeterIdx) → {type, hwIdx}
               type==1: 要求 hwIdx < 0xC0 (192)            [0xbe7f4..0xbe820]
               type==4: 要求 hwIdx < 0x80 (128)            [0xbe85c..0xbe878]
      egress : 同上，上限相同（type1 0xC0 / type4 0x80）   [0xbe810..0xbe878 / 0xbeb5c..0xbeb68]
      其它 type 或映射失败 → 返回 0x10000
 2. 取全局锁 rtk_fc_mgr_global_spin_lock_bh_irq_protect()；
 3. 保存新 MAC；_rtk_hostPoliceControl_clear(idx)；            // 先全清
 4. 若新 MAC 为全 0 → 解锁返回 0（删除语义）；
 5. 96 项重复 MAC 扫描（跳过自身）→ 重复返回 -1；
 6. 分配 hostPolConfList id：
      if (两个方向都不是 SW 类型) 只从 free list @ fc_db+0xC22DC0 取；
      else 先取 free list @ fc_db+0xC22DB0，空了再取 @ 0xC22DC0；
      两表皆空 → 日志 "No free hostPoliceConf entry!"，返回 -1；
 7. 拷贝 36 B 控制结构到 S，S.id = id；
 8. 组装并写 per-id hw_ctl（§1.5）；
 9. 组装 pol1 字（§2.4）：mibCountCtrl==0 → 0xFFFFF；否则按方向分配/复用；
10. 对每个 enable 且 rate != -1 的方向：
      type==1 → _rtk_fc_g3L3Policer_set(hwIdx, rate, 1)      // 0x52960
      type==4 → 只写 SW meter 表（§3.4），不碰硬件
11. if (_rtk_fc_lut_find(newMac, &lutIdx) == 0) rtk_fc_flow_delete_by_l2Idx(lutIdx);
12. _rtk_fc_lutHostPolicingIdxUpdate(newMac);                  // LUT 表项 +0x1E = idx
13. 解锁，返回 0。
```

**要点**：`set` 是「整条目重建」而不是增量写；`clear` 是它的第一步，因此任何一次 `set` 都会先删流、
释放 meter/pol1、把 LUT 索引置 −1，再重新分配。上层必须把它当原子操作（全局锁覆盖全程）。

### 2.3 pol1 索引分配/释放（192 项） **[观测]**

- 位图：`fc_db + 0xBE2028 + idx*4`（u32/项，idx 0..191）。
  `bit0` = 已占用；`bit1` = 由 host policing 的 MIB 计数占用（"host-owned"）。
- 分配（`set`，`0xbea80` 附近）：线性扫描 0..191 找 `bit0==0`，命中后 `|= 3`。
  仅当**该方向没有 HW 限速**（`ingressLimitCtrl==0` 或 type==4）时才分配；
  若该方向有 HW 限速（type==1 且 enable），则 `pol1 = 该方向的 hw meter 索引`，**不再单独分配**。
- 释放（`clear`，`0xbe4a4..0xbe5e8`）：先警告检查 `bit0`，仅当 `bit1==1` 时清 `bit0`（不误放别人的 meter）。
- `0x3FF`(0x3ff) = 无 pol1（该方向不计）。

### 2.4 pol1 字组装（`set`，`0xbea80..0xbeacc`） **[观测]**

```
if (mibCountCtrl == 0)      pol1 = (pol1 & 0xFFF00000) | 0xFFFFF;   // 低 20 位置 1，两方向都不计
else {
  ingress:
    if (ingressIsSw)        pol1[9:0]   = 0x3FF;
    else if (!ingressLimitCtrl) pol1[9:0] = alloc_free_pol1();
    else                    pol1[9:0]   = ingressHwMeterIdx & 0x3FF;
  egress:
    if (egressIsSw)         pol1[19:10] = 0x3FF;
    else if (!egressLimitCtrl) pol1[19:10] = alloc_free_pol1();
    else                    pol1[19:10] = egressHwMeterIdx & 0x3FF;
}
```

⇒ **「HW 限速」与「纯计数」共用同一批 192 个 POL1 槽位**；限速方向直接复用 meter 索引，
计数方向从位图另取。MIB 读数就是读这个 pol1 索引的 POL1 计数器（§4）。

---

## 3. Rate Meter 子系统（虚拟 meter → 硬件 meter）

### 3.1 映射函数 **[观测]**

`rtk_fc_rt_rate_shareMeter_mapping_hw_get` @ `0xD800`（fc_mgr）**只有一条尾调用**：

```c
void rtk_fc_rt_rate_shareMeter_mapping_hw_get(void) { rt_rate_shareMeterMappingHw_get(); }
```

- `rt_rate_shareMeterMappingHw_get` 在 `fc_mgr.ko` 里是 **U（未定义）**，由其它模块提供；
  本语料（`ca-ne.ko` / `fc_8277c.ko` / `ca-plat-kernel.ko` / `hostSpeedUp.ko` / `rtk_igmp_hook.ko`）均**未定义**它，
   `rtk_rate_shareMeter_set/get/Bucket_get/Mode_get` 同样全部是 U。
  ⇒ **share-meter 的物理寄存器块不在语料内**（见 U-2）。
- 输出结构（由调用方栈布局反推）**[观测]**：
  `{ u16 meter_type; u16 pad; u32 reserved; u32 hw_index; }`。
- 输入是**虚拟 meter 索引**（用户 `ingressLimitMeterIdx`/`egressLimitMeterIdx`），不是速率。
  速率是 `+0x1C/+0x20` 单独给出，用于编程 POL1 profile。

### 3.2 meter 类型与后端（字符串 + `dump_rtMeter_table` 双重证据） **[观测]**

`fc_mgr.ko` 字符串表（`.rodata.str1.8`）：

```
RT_METER_TYPE_STORM      → l2_policer
RT_METER_TYPE_HOST       → l3_policer1        (缺省) / sw "share meter" (bit26 模式)
RT_METER_TYPE_FLOW       → l3_policer2
RT_METER_TYPE_ACL        → l3_policer1
RT_METER_TYPE_SW         → sw_meter
```

`dump_rtMeter_table` @ `0x30EA0` 对虚拟索引 `0..0x196` 逐个调用映射函数并 `switch(type)`：
type1 → `_rtk_fc_l3Meter_get(1,…)` 或 `rtk_rate_shareMeter_get()`（受 `fc_db[1460].bit26` 控制）；
type2 → `_rtk_fc_l3Meter_get(2,…)`；type3 → `_rtk_fc_l3Meter_get(3,…)`；type4 → SW 表。

### 3.3 索引池划分（`dump_rtMeter_debugging_table` @ `0x31710` 的常量） **[观测]**

该函数按 `fc_db[1460].bit25` 打开后打印「Meter Usage」，格式与立即数一一对应：

| 池 | 大小 | 区间 | 用途（原文字符串） |
|---|---|---|---|
| L2 policer | `0`（本机型未启用；参数为 0） | — | `storm control. (with L2 packet type policer)` |
| **L3 policer1 (POL1)** | **256** | `0..191` | `for RT host use. (host policing rate limiting (HW policing) or host logging)` |
| | | `192..192` | `Hash default action drop.` |
| | | `193..193` | `Hash default action umc trap with rate limit.` |
| | | `194..225` | `mc netif rx mib.` |
| | | `226..255` | `ACL rate limiting` |
| L3 policer2 (POL2) | 64 | `0..31` / `32..63` | 两级 flow/组 policer（受 bit9/bit10 控制细分） |
| SW meter | **128** | `0..127` | `sw_meter`（纯软件，位图在 `fc_db+0xBE2010`，128 bit） |

⇒ **96 条 host 条目 × 2 方向 = 192 = POL1 的 host 池恰好用完**。这是 96 这个数字的根本来源。
PL1 的 192/193 两个特殊槽（hash default drop / UMC trap 限速）在 `dump_rtMeter_table`
`0x311B4..0x312BC` 被单独 dump，也解释了为什么 host 池止步于 191。

### 3.4 速率编码（落到 POL1 profile） **[观测，与 phase0 §2.3 一致]**

`rtk_8277c_l3_flow_policer_rate_set` @ `0xC6940`：

```
w5 = 0x10624DD3; umull; >>37         → rate/500
profile[1] = cir/500 (u16)  → DATA0[25:10]
profile[4] = pir/500 (u16)  → DATA1[31:16]
profile[0] = cir%500 (u10)  → DATA0[9:0]
profile[3] = pir%500 (u10)  → DATA1[15:6]
flags = 0x1B
⇒ rate_kbps = 500*hi + lo；上限 0xFFFF*500+499 = 32 767 999 (0x1F3FFFF)
```

- `_rtk_fc_g3L3Policer_set(idx, rate, ifg=1)` @ `0x52960`：
  `rate == 0x1F3FFFF` → `rtk_8277c_l3_flow_policer_mode_set(idx,0)`（关闭）；
  否则 `mode_set(idx,1)` + `rate_set(idx,rate,rate)`（**CIR=PIR**）+ `rtk_8277c_l3_policer_ifg_config_set(1)`。
  索引守卫：`idx ≤ 0xFE` 或 `idx == 0xFF`；`rate < 0x1F40000`。
- burst（CBS/PBS）由 `rtk_8277c_l3_flow_policer_burstSize_set` @ `0xC6CE0` 写 12 bit 原值；
  **host policing 路径不设 burst**（`profile[2]/[5]` 保持上次值或 0）——需要 burst 时必须另行调用（见 U-3）。
- NE 落点（`ca-ne.ko`）：
  `aal_l3_te_policer_flow_profile_set` @ `0x740B0` → ACCESS `0x9128`、DATA2 `0x912C`、DATA1 `0x9130`、DATA0 `0x9134`（8-bit 索引）；
  `aal_l3_te_policer_flow_cfg_set` @ `0x6F6C0` → `0x9108 + (idx>>5)*4`（32 流共享 1 个 cfg 寄存器）。

### 3.5 type==4（SW meter）在 host policing 路径的落点 **[观测]**

`set` 的 `0xbeaa4..0xbeabc`（ingress）/`0xbead8..0xbeaf0`（egress）：

```
entry = fc_db + 0x972340 + hwIdx*0x38;
entry->enable (+0x00) = 1;
entry->rate   (+0x04) = ctrl.ingressLimitRate;   // kbps，原值
```

- 表边界：`0x972340 + 128*0x38 = 0x973F40`，恰好接上 `rtk_fc_sw_rate_limit_set` 的每端口表
  （`rtk_fc_sw_rate_limit_set` @ `0xB4A70` 用 `fc_db+0x973F40`，port 0..3，步长 0x34）。
  **⇒ 该 SW meter 表 = 128 项 × 0x38，与 type4 的 0x80 上限完全吻合。**
- 纯软件实现：实际限速在包路径 `_rtk_fc_sw_rate_limit` @ `0x10EC0` / `_rtk_fc_sw_rate_limit_drop` @ `0x10C00`。
  ⇒ 这条路径**没有任何 NE 寄存器**。

### 3.6 关于任务书里的「128 × 7 bit share-meter 物理寄存器块」 **[UNKNOWN]**

- 语料里能确认的 128 项表只有 §3.5 的 SW meter（fc_db 内存，非硬件）和 `sw_meter` 位图。
- 若产品走 `fc_db[1460].bit26 = 1` 的「share meter」模式（`dump_rtMeter_table` type1 分支调用
  `rtk_rate_shareMeter_get/Bucket_get/Mode_get`），真正的硬件表在**提供这些符号的模块**里，
  本语料没有该模块 ⇒ 寄存器块/7-bit bucket 编码 **[UNKNOWN]**。
- 但可确认「7 bit bucket」这一设计线索：`dump_rtMeter_table` 对每个 meter 分别读
  `rate`（`rtk_rate_shareMeter_get`）、`bucket`（`rtk_rate_shareMeterBucket_get`）、`mode`
  ⇒ 条目 = {mode, bucket/rate}，bucket 是独立字段；`rtk_rate_shareMeter_set` 的 bucket 参数
  在 Realtek 同族 SDK 里是 7 bit（0..127），与「128 × 7 bit」一致 **[推导]**。

---

## 4. Host Policing MIB（读出 / 清零）

### 4.1 软件接口 **[观测]**

```
rtk_fc_hostPoliceMib_get(idx, u64 out[2])      @ 0xB7380
    if (!out) return 0x10001;  if (idx > 95) return 0x10005;
    lock;
    out[0] = out[1] = 0;
    id = S.hostPolConfList_idx; if (id != -1) {
        _rtk_fc_hwHostPolingMib_get(id, &out[0], &out[1]);     // HW 累计
        out[0] += _rtk_fc_sw_hostMib_all_cpu_get(id, 0);       // SW 累计
        out[1] += _rtk_fc_sw_hostMib_all_cpu_get(id, 1);
    }
    unlock; return 0;

rtk_fc_hostPoliceMib_clear(idx)                @ 0xB7290
    if (idx > 95) return 0x10005; lock;
    id = S.hostPolConfList_idx; if (id != -1) {
        _rtk_fc_hwHostPolingMib_clear(id);                     // 读空 + 清 SW 累计
        *(u64*)(per-id+0x28) = 0; *(u64*)(per-id+0x30) = 0;
    }
    unlock; return 0;
```

- `out[0]` / `out[1]` 的语义由 `dump_hw_host_policing_mib` @ `0x30C00` 的格式串钉死：
  `"[%2d]%pM"` + `"%20llu"` ×2，表头为 `[Rx]` / `[Tx]`
  ⇒ **out[0] = ingress(Rx)、out[1] = egress(Tx)**，各 64 bit 软件累计。
- 「每索引的 MIB 槽数」= **2**（每方向 1 个 POL1 计数器 + 1 个 SW 累计器）。
  没有独立的「host policing MIB 寄存器块」——MIB 复用 POL1 计数器（见下）。

### 4.2 硬件计数器：`aal_l3_te_pm_policer_flow_get` @ ca-ne `0x753B0` **[观测]**

```
aal_l3_te_pm_policer_flow_get(unit=0, idx, out[48B])
  → __l3_te_pm_counter_access.constprop.0 @ 0x71FE0
```

`__l3_te_pm_counter_access` 的寄存器（全部 NE 偏移，`g_ne_reg_iobase` 重定位已确认）：

| NE 偏移 | 作用 |
|---|---|
| **`0x973C`** | ACCESS：bit31 = BUSY/START，bit30 = 1 写 / 0 读，`[10:0]` = flow 索引（`bfxil #0,#11`） |
| `0x9740` | data0 |
| `0x9744` | data1 |
| `0x9748` | data2 |
| `0x974C` | data3 |
| `0x9750` | data4 |
| `0x9754` | data5 |
| `0x9758` | data6 |
| `0x975C` | data7 |
| `0x9760` | data8 |

忙等上限 4096 次（`mov w8,#0x1000`），超时返回 5；每读一字前后 `dmb oshld`。

`aal_l3_te_pm_policer_flow_get` 把 9 个字拼成 8 个计数器（**位宽是关键**）：

| 输出 | 组装方式 | 位宽 |
|---|---|---|
| `out[0..3]` | `0x9760 / 0x975C / 0x9758 / 0x9754` 原样 | **4 × 32 bit** |
| `out[4]` | `(0x974C[3:0] << 32) \| 0x9750` | **36 bit** |
| `out[5]` | `(0x9748[7:0] << 28) \| (0x974C[31:4])` | **36 bit** |
| `out[6]` | `(0x9744[11:0] << 24) \| (0x9748[15:8])` | **36 bit** |
| `out[7]` | `(0x9740[15:0] << 20) \| (0x9744[31:12])` | **36 bit** |

### 4.3 fc_mgr 用哪两个计数器 **[观测]**

`_rtk_fc_hwHostPolingMib_get` @ `0x544E0`：

```c
idx = pol1_word[9:0] (ingress) 或 [19:10] (egress);
if (idx != 0x3FF) {
    aal_l3_te_pm_policer_flow_get(0, idx, buf);
    per-id->hw_rx += (buf[4] - buf[5]);      // 0x545B8..0x545D4
}
```

- 用的是 **`out[4]`（36 bit）减 `out[5]`（36 bit）**，差值累加到 `per-id+0x28`（Rx）/`+0x30`（Tx）。
- `_rtk_fc_hwHostPolingMib_clear` @ `0x54680` 做同样的 get（把待读值读走）然后把 `+0x28/+0x30` 清零，
  **不写 0x9138 计数器清零寄存器**。
- 另一个清计数器入口在 `ca-ne`：`_aal_l3_te_policer_flow_counter_clear` @ `0x70AE0`：
  `0x9138` 轮询 → 写 `0x9140 = 0` → 写 `0x913C = 0` → 写 `0x9138 = 0xC0000000 | idx` → 轮询。
  **host policing 路径不调用它**。

### 4.4 位宽/单位结论

- 硬件计数：**36 bit**（fc_mgr 实际使用的那一对），另有 4 个 32 bit 字段 fc_mgr 未使用。
  36 bit 计数器按字节计：1 Gbps 线速下约 550 s 回绕，10 Gbps 下约 55 s ⇒ 必须像 OEM 一样周期性读并软件累加成 64 bit。
- 软件累计：`u64`（per-id `+0x28/+0x30`），SW meter 路径另有 4 × `u64`（`+0x00..0x1F`）。
- **`out[4]-out[5]` 的确切语义（passed vs total−dropped、字节 vs 包）[UNKNOWN]**：
  fc_mgr 只把它当「本次增量」累加，不保存上次绝对值，说明该计数器块大概率是**读后清零/增量型**；
  但语料内无法证明。这是 W6c 设备验证的第一优先项（U-4）。

---

## 5. MAC LUT / SMAC / DMAC 与 host police 索引的绑定

### 5.1 绑定发生在 L2 LUT 表项 `+0x1E` **[观测]**

`_rtk_fc_lutHostPolicingIdxUpdate(int *mac)` @ `0x391B0`：

```c
if (_rtk_fc_lut_find(mac, &lutIdx, 0) != 0) return 0;       // 没有 MAC 表项 → 什么都不做
if (lutIdx > 0x1027) { printk("0 <= lutIdx && lutIdx < RTK_FC_TABLESIZE_LUT"); dump_stack(); }
for (i = 0; i < 96; i++)
    if (memcmp(sw_entry[i].mac, mac, 6) == 0) {
        lut_entry = *(u64 *)(fc_db + (lutIdx + 0x17E012)*8);   // 指针数组基址 fc_db+0xBF0090
        *(u16 *)(lut_entry + 0x1E) = i;                        // ← 绑定点
        return 0;
    }
*(u16 *)(lut_entry + 0x1E) = 0xFFFF;                            // 未配置 → −1
```

- **每个 MAC LUT 表项只有 1 个 host-police 索引**（`+0x1E`，s16，−1 = 无）。
- 同一条目同时服务两个方向：作为**源 MAC** 命中时走 ingress，作为**目的 MAC** 命中时走 egress。

### 5.2 从 LUT 到流：两个消费者 **[观测]**

| 消费者 | 地址 | 行为 |
|---|---|---|
| `_rtk_fc_extraInfo_setting` | `0x18C90` | 用 flow 的 SMAC LUT idx (`+4`) 和 DMAC LUT idx (`+8`) 查 LUT 表项，把 `[+0x1E]` 分别写到 flow `+0x4C` / `+0x4E`（`0x18E54..0x18E98`） |
| `_rtk_fc_abstrSwFlow_DmacLearning` | `0x16300`（关键指令 `0x16370..0x163A0`） | 读 flow `+0x2A4` 的 LUT idx → LUT 表项 `+0x1E` → flow `+0x2A8` |
| `dump_sw_flow_fields` | `0x2B820` | 打印 `"SMAC hostPolicing Idx: %d, DMAC hostPolicing Idx: %d"`，来源正是 flow `+0x10/+0x12`（另一处 flow 结构） |

### 5.3 从流到 L3TE policer：`_rtk_fc_g3FlowIdDecision` @ `0x53320` **[观测]**

`RTK_RG_G3_FLOW_SET.constprop.0` @ `0x8B240` 内：

```c
_rtk_fc_g3FlowIdDecision(param_1, param_3 /*flow信息*/, &local_dd, &local_dc);
if (local_dd != 0) {
    uStack_4e |= 0x200;          // [推导] G3 flow 条目 +0x36 的 bit9 = policer enable
    local_4c  = (u8)local_dc;    // [推导] G3 flow 条目 +0x38 = policer id（8 bit）
}
```

`_rtk_fc_g3FlowIdDecision` 逻辑：

```
ingressIdx = flow[+0x4C] (s16), egressIdx = flow[+0x4E] (s16)
对每个 != -1 的方向：
  S = host 表项[ingressIdx/egressIdx]
  if (S.id == -1)                     → 报错 "hostPolConfList_idx is invalid"
  if (S.id >= 96)                     → 报错 "no need HW policer assignment"
  sw = hw_ctl bit20 (ingress) / bit21 (egress)
  if (!sw) {                          // HW 限速
      *do_meter = (S.mibCountCtrl != 0);
      *policerId = hw_ctl[9:0] (ingress) / [19:10] (egress);   // = POL1 槽号
      再校验 pol1_word 对应位与 policerId 一致（"loggingRx_policerIdx"）
  } else {                            // SW 限速
      *do_meter = 0; *policerId = 0;  // 不设 flow id
  }
```

⇒ **最终绑定到 L3TE 的是 G3 flow 条目的 `pol_id`（8 bit，POL1 槽号）+ `pol_en`**，
不是 `header_a.pol_grp_id`（那是 POL2/组级），也不是 ACL 规则字段。

### 5.4 ACL 路径：**不携带 host police 索引** **[观测]**

`rtk_fc_aclFilterAndQos_add` @ `0xB5070` → `_rtk_fc_aclFilterAndQos_add` @ `0xB0C90`：

- ACL 的 METER 动作走**独立的虚拟 meter 池**：

```c
iVar = rtk_fc_rt_rate_shareMeter_mapping_hw_get(*(u32*)(aclEntry+0xD0), &m);
if (iVar == 0 && (u16)m.type == 3) {          // 必须是 ACL 类型
    if (m.hwIdx - 0xE2 < 0x1E) ok;            // hwIdx ∈ [0xE2, 0xFF] → 226..255
    else return 0x10007 "Invalid hw meter index ... ACL rate limiting";
} else return 0x10007;
```

- ACL 规则里**没有** host-police 索引字段，也不读 LUT 的 `+0x1E`。
- ⇒ Host Policing 与 ACL 限速是**两条独立路径**，只在「共享同一张 L3TE POL1 256 槽表」这一点上相交
  （host 0..191 / ACL 226..255）。

### 5.5 结论（回答任务书问题 4）

| 问题 | 结论 |
|---|---|
| MAC LUT / SMAC / DMAC 的绑定点 | L2 MAC LUT 表项 `+0x1E`（u16），由 `_rtk_fc_lutHostPolicingIdxUpdate` @ `0x391B0` 写；LUT 指针数组基址 `fc_db+0xBF0090` |
| ACL 规则是否携带 host police 索引 | **否**。ACL 用 type3 专用 meter 池（226..255），与 host 无关 |
| `header_a.pol_grp_id` 是否指向它 | **否**。指向 host meter 的是 L3TE/G3 flow 的 **`pol_id`（8 bit）+ `pol_en`**，由 `_rtk_fc_g3FlowIdDecision` 在 `RTK_RG_G3_FLOW_SET` 里写入（flow 条目 `+0x36` bit9 / `+0x38`） |
| 完整链路 | 用户下发 (idx, MAC, 2×meter, 2×rate) → 96 表 → LUT 表项 `+0x1E` → flow `+0x4C/+0x4E` → G3 flow `pol_id` → NE `0x9128/0x9134` POL1 profile（速率） |

---

## 6. 双向限速：结论

1. **每条 host 条目占 2 个 meter**：ingress 一个、egress 一个，各自独立映射、独立编程
   （`ctrl+0x14/+0x18` 两个虚拟索引、`hw_ctl[9:0]/[19:10]` 两个硬件索引）。 **[观测]**
2. **96 条 × 2 方向 = 192 = POL1 host 池大小**，与 `dump_rtMeter_debugging_table` 的
   `[000]-[191]: for RT host use` 完全吻合。 **[观测+推导]**
3. **方向语义固定**：ingress 匹配 **SMAC(SA)**，egress 匹配 **DMAC(DA)**（`L2_INGRESS_SA_HOSTPOLICING` /
   `L2_EGRESS_DA_HOSTPOLICING` 字符串 + `extraInfo` 的 SMAC/DMAC LUT idx 两路）。 **[观测]**
4. **不是「每终端一条、双向两条硬件条目」的另一种可能**——就是：一条 host 表项（MAC），内部两条
   相互独立的限速/计数配置；硬件侧各占 1 个 POL1 槽。 **[观测]**
5. 若某方向使用 SW meter（type4），则该方向不占 POL1 槽，只在 `fc_db+0x972340` 的 128 项 SW 表占 1 项，
   并由软件包路径限速。 **[观测]**
6. 因此满配 96 主机双向 HW 限速时，POL1 的 host 池 **刚好用尽**；此时 ACL（226..255 共 30 个）仍可独立使用，
   互不冲突。POL1 的 192/193（hash 默认动作）与 194..225（mc netif rx mib）也不会被 host 占用。 **[观测]**

---

## 7. 可直接落地的 API 草案

> 标注：**[V]** = 本语料已验证（函数/寄存器/位域可直接照抄）；**[D]** = 由已验证事实推导，需要设备确认；
> **[U]** = 语料缺失，落地前必须先补证据。

```c
/* ---------- 常量 ---------- */
#define FC_HOSTPOL_MAX          96          /* [V] set/get/mib 均 cmp #0x5f */
#define FC_POL1_HOST_BASE       0           /* [V] dump_rtMeter_debugging_table */
#define FC_POL1_HOST_END        191         /* [V] */
#define FC_POL1_HASH_DROP       192         /* [V] 保留，勿分配 */
#define FC_POL1_HASH_UMC        193         /* [V] 保留，勿分配 */
#define FC_POL1_MC_NETIF_MIB    194         /* [V] 194..225 */
#define FC_POL1_MC_NETIF_END    225
#define FC_POL1_ACL_BASE        226         /* [V] 226..255 */
#define FC_POL1_ACL_END         255
#define FC_POL1_NUM             256
#define FC_SW_METER_NUM         128         /* [V] type4 上限 0x80；SW 表 128×0x38 */
#define FC_HOST_RATE_MAX        0x1F3FFFFu  /* [V] = 不限速 */
#define FC_HOST_RATE_UNCHANGED  0xFFFFFFFFu /* [V] */

/* ---------- 数据结构（与 OEM 36B 控制结构一一对应） ---------- */
struct fc_host_pol_cfg {           /* [V] procfs ABI */
    u8  mac[6];
    u16 pad;
    u32 ingress_ctrl;              /* 0=off, 非0=on */
    u32 egress_ctrl;
    u32 mib_ctrl;                  /* 0=off, 非0=on（1/2 差别见 U-5） */
    u32 ingress_vmeter;            /* 虚拟 meter 索引 */
    u32 egress_vmeter;
    s32 ingress_rate_kbps;         /* -1 = 不变；<= 0x1F3FFFF */
    s32 egress_rate_kbps;
};

/* ---------- 内部句柄 ---------- */
struct fc_host_pol_hw {            /* [V] per-id 0x50B 结构 */
    u64 sw_rx_a, sw_tx_a, sw_rx_b, sw_tx_b;   /* +0x00..0x1F */
    u32 hw_ctl;                               /* +0x20  [9:0]=i_idx [19:10]=e_idx [20]=i_sw [21]=e_sw */
    u16 id;                                   /* +0x24  hostPolConfList id, 0xFFFF=空闲 */
    u16 rsv0;
    u64 hw_rx_acc, hw_tx_acc;                 /* +0x28 / +0x30 */
    u32 pol1_word;                            /* +0x38  [9:0]=i_pol1 [19:10]=e_pol1 0x3FF=none */
    u32 rsv1;                                 /* +0x3C */
    struct list_head node;                    /* +0x40 / +0x48 */
};

/* ---------- API ---------- */
/* 1) 分配 host 索引（用户态语义：hostIndex 由调用方给 0..95；驱动侧只校验） */
int  fc_hostpol_program(u32 host_idx, const struct fc_host_pol_cfg *cfg);
     /* [V] 等价 rtk_fc_hostPoliceControl_set @ 0xbe640（整条重建：clear→重编程） */

int  fc_hostpol_clear(u32 host_idx);
     /* [V] 等价 _rtk_hostPoliceControl_clear @ 0xbe1f0；mac 全 0 也可删除 */

int  fc_hostpol_read(u32 host_idx, struct fc_host_pol_cfg *out);
     /* [V] 等价 rtk_fc_hostPoliceControl_get @ 0xb4620（速率从 HW/SW 回读） */

/* 2) 绑定（MAC → host police 索引在 LUT 的落点） */
int  fc_hostpol_bind_mac(const u8 mac[6], s16 host_idx);
     /* [V] 写 L2 LUT entry+0x1E；−1 解绑；由 program() 内部最后一步自动完成，
        单独暴露仅用于 LUT 老化/重建后修复（对应 _rtk_fc_lutHostPolicingIdxUpdate @ 0x391b0） */

/* 3) MIB */
int  fc_hostpol_mib_get(u32 host_idx, u64 *rx, u64 *tx);
     /* [V] 等价 rtk_fc_hostPoliceMib_get @ 0xb7380；rx=out[0], tx=out[1] */
int  fc_hostpol_mib_clear(u32 host_idx);
     /* [V] 等价 rtk_fc_hostPoliceMib_clear @ 0xb7290（读空 HW + 清 SW 累计） */

/* 4) 虚拟 meter（由 rate-meter 模块提供，fc_mgr 只做映射） */
int  fc_hostpol_meter_create(u32 rate_kbps, u32 *vmeter);       /* [U] rt_rate_shareMeter_* 不在语料 */
int  fc_hostpol_meter_destroy(u32 vmeter);                      /* [U] */
int  fc_hostpol_meter_map(u32 vmeter, u16 *type, u32 *hw_idx);  /* [V] 语义（type 1/4，上限 0xC0/0x80），
                                                                   [U] 实现（rt_rate_shareMeterMappingHw_get 是 U 符号） */
/* 5) 底层 POL1 速率编程（可直接用 ca-ne 的导出 API） */
int  fc_pol1_rate_set(u32 pol1_idx, u32 rate_kbps, bool ifg_include);
     /* [V] _rtk_fc_g3L3Policer_set @ 0x52960 → aal_l3_te_policer_flow_profile_set @ ca-ne 0x740b0
        pol1_idx ∈ [0,0xFE] ∪ {0xFF}；rate == 0x1F3FFFF ⇒ disable */
```

**已验证可直接照抄的调用序列（HW 限速方向）**

```c
/* program(host_idx, cfg) 内部，方向 d： */
map = rt_rate_shareMeterMappingHw_get(cfg.vmeter[d]);          /* [V] 调用点 0xbe7f4/0xbe850 */
if (map.type == 1) {
    assert(map.hw_idx < 192);
    g3L3Policer_set(map.hw_idx, cfg.rate[d], /*ifg=*/1);       /* [V] 0x52960 */
} else { /* type 4 */
    assert(map.hw_idx < 128);
    fc_db->sw_meter[map.hw_idx].enable = 1;                     /* [V] fc_db+0x972340+idx*0x38 */
    fc_db->sw_meter[map.hw_idx].rate   = cfg.rate[d];
}
/* 然后： */
lutIdx = lut_find(cfg.mac);
if (found) flow_delete_by_l2Idx(lutIdx);                        /* [V] 0x5a9d0 */
lut_entry[lutIdx].hostpol_idx = host_idx;                       /* [V] +0x1E */
```

---

## 8. UNKNOWN 清单

| # | 项 | 影响 | 下一步 |
|---|---|---|---|
| U-1 | `rtk_fc_rt_rate_shareMeter_mapping_hw_get` 的**实现**（虚拟→硬件索引分配/复用规则、释放时机、虚拟索引空间 0..0x196 的布局） | 无法独立实现 meter 池；只能依赖 OEM 模块 | 需要 `rt_rate_shareMeterMappingHw_get` / `rtk_rate_shareMeter_*` 所在模块（Realtek SDK `rtk.ko`/内置） |
| U-2 | **128×7-bit share-meter 物理寄存器块**（`RT_METER_TYPE_HOST` 走 bit26 模式的硬件表） | 无法直接编程 share-meter 变体 | 同上；或用设备读寄存器对比 `rtk_rate_shareMeter_set` 前后的 NE 空间 |
| U-3 | host policing 不写 CBS/PBS（burst）；OEM 是否另调 burstSize_set | 限速精度/突发行为 | 反 `rtk_8277c_l3_flow_policer_burstSize_set` @ 0xC6CE0 的调用方；或设备实测 |
| U-4 | `aal_l3_te_pm_policer_flow_get` 的 `out[4]`/`out[5]` 语义与**是否读后清零**（决定 `out[4]-out[5]` 累加是否正确） | MIB 数值正确性 | 设备上连续两次 get 同一 POL1 索引，比较返回值；同时打流 |
| U-5 | `mibCountCtrl` 取值 1 vs 2 的差异（`clear` 只在 `==1` 时释放 pol1，`!=0` 时都分配 ⇒ 值 2 可能泄漏 pol1） | 资源泄漏风险 | 设备复现：置 2 → clear → 观察随后 alloc 是否耗尽 |
| U-6 | pol1 位图（`fc_db+0xBE2028`）与 HW 限速复用的 meter 索引是否会别名（限速方向不置位图） | 可能重复分配 | 设备复现：两条目同 rate、不同 meter，观察 pol1 冲突 |
| U-7 | `hw_ctl` bit22..31 的真实用途（OEM 只保留） | 低 | 设备读回 |
| U-8 | `fc_db[1460]` 的 bit9/bit25/bit26 对应的配置项名（SW POL2 镜像 / 扩展 dump / share-meter 模式） | 模式选择 | 反 `rtk_fc_proc_*` 配置 setter |
| U-9 | `_rtk_fc_sw_hostPolicingMibCounting` 的 per-CPU SW 计数分片布局（`fc_db+0xC200FB0 + (5*id+cpu)*16`）与聚合路径 | 仅 SW meter 的 MIB | 反 `_rtk_fc_sw_hostMib_all_cpu_get` 的写入方 |
| U-10 | `mibCountCtrl` 与 `host logging`（字符串 `HOST_MIB`、"host logging"）的关系 | 功能语义 | 反 procfs 另一入口 / 设备 CLI |
| U-11 | 96 项之外（`id >= 0x60`）的 SW-only 链表（`fc_db+0xC22DB0`）容量 | 仅影响非优化模式 | 反 `_rtk_fc_lutEntry_pool_init` @ 0x36A70 的初始化 |

---

## 9. 对 W6c 的结论

**可以开工的部分（寄存器/数据模型级）**

- 96×双向数据模型、`hw_ctl`/`pol1` 位域、set/clear 全序列（§1/§2）——已闭合。
- L3TE POL1 速率编程（kbps、`/500` 编码、`0x1F3FFFF` 哨兵、IFG 参数）——已闭合，可直接调 ca-ne 导出 API。
- POL1 256 槽的分区（host 0..191 / hash 192,193 / mc-netif 194..225 / ACL 226..255）——已闭合。
- MAC LUT `+0x1E` → flow `+0x4C/+0x4E` → G3 flow `pol_id/pol_en` 的绑定链——已闭合。
- MIB 读出/清零的**软件流程**与**寄存器块**（NE `0x973C` + `0x9740..0x9760`）——已闭合。

**仍阻塞的部分**

- 虚拟 meter 管理器（`rt_rate_shareMeterMappingHw_get` / `rtk_rate_shareMeter_*`）**不在语料**，
  host policing 的「按 rate 共享 meter」能力无法独立复刻；W6c 只能先做「调用 OEM 映射函数」或
  「固定 1:1 分配」的降级实现。
- share-meter 物理寄存器块（U-2）与计数器读后语义（U-4）需要设备证据。

**还缺的设备证据（按优先级）**

1. 连续两次 `aal_l3_te_pm_policer_flow_get` 同一 POL1 索引（打流中），确认读后是否清零、`out[4]-out[5]` 是否单调。
2. `rtk_rate_shareMeter_set(vmeter, rate, burst)` 前后对比 NE/NI 相关寄存器空间（找 share-meter/bucket 表基址）。
3. 满配 96 条 host 规则（双向）后 `dump_rtMeter_debugging_table` / `host_policing_mib` 的输出，验证 192 槽恰好用尽。
4. `mibCountCtrl=2` 的 clear 行为（U-5）与 pol1 位图别名（U-6）。

---

## 附录 A：关键 REA 证据

| 函数 | fc_mgr 地址 | REA 证据 ID |
|---|---|---|
| `rtk_fc_hostPoliceControl_set` | `0xBE640` | `ev_edd64a73cd616787b55e7ab58c85da6fd3b537ee898b23c8b76cc21da9494d13` |
| `_rtk_hostPoliceControl_clear` / `rtk_fc_rt_rate_shareMeter_mapping_hw_get` / `rtk_fc_hostPoliceMib_get` / `_clear` / `_rtk_fc_lutHostPolicingIdxUpdate` / `_rtk_fc_g3L3Policer_set` | `0xBE1F0` / `0xD800` / `0xB7380` / `0xB7290` / `0x391B0` / `0x52960` | `ev_9413d6cf117e5e44013aea92981e279bafbba51aef6fd3022e7d90940e8a0c47` |
| `_rtk_fc_hwHostPolingMib_get` / `_clear` / `rtk_fc_hostPoliceControl_get` / `rtk_fc_aclFilterAndQos_add` / `_rtk_fc_aclFilterAndQos_add` | `0x544E0` / `0x54680` / `0xB4620` / `0xB5070` / `0xB0C90` | `ev_e5331539616bb49d42344886025405c3fe0d74a0bb7e43bf4f1f8c64adab888e` |
| `_rtk_fc_g3FlowIdDecision` + 10 条 "flow id decision" 字符串 | `0x53320` | `ev_d32924d6a7bd773a08d8ad671dc1c01a5d900e30cd1b130a93aa9dae2e9e54c1` / `ev_d13479152e5f96f821ea87e1130f2608ee3eb1da3dd2e3cde5fd17f1462db52d` |
| `RTK_RG_G3_FLOW_SET.constprop.0` | `0x8B240` | `ev_c703f7dd68910493c99f5baa37e3cc7fa3345a0aaa03d0dfeb332b1da417a4f2` |

`ca-ne.ko` 侧（objdump 直读，无 REA 证据 ID）：
`aal_l3_te_pm_policer_flow_get` @ `0x753B0`、`__l3_te_pm_counter_access.constprop.0` @ `0x71FE0`、
`_aal_l3_te_policer_flow_counter_clear` @ `0x70AE0`、`aal_l3_te_policer_flow_profile_set` @ `0x740B0`、
`aal_l3_te_policer_flow_cfg_set` @ `0x6F6C0`。