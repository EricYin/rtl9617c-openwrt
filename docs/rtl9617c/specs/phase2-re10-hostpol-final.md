# Phase 2 RE-10 — share-meter 物理层 + Host Policing 最终规格（ca-rtk.ko / fc_8277c.ko）

状态：**Phase 2 只读逆向**。语料仅 `ca-rtk.ko` + `ca-ne.ko`（寄存器 AAL 参照）+ `fc_8277c.ko`；
本轮**未修改**任何构建仓库与 .ko 文件。本文对 `phase2-re4-hostpolicing.md`（基于 `fc_mgr.ko`/`ca-ne.ko`）做**差异订正**，
并在 §3 给出 ca-rtk.ko 里 share-meter DAL 的完整物理落点。

## 0. 语料、工具与地址约定

| 项 | 值 |
|---|---|
| `ca-rtk.ko` | `/mnt/c/rea/ca-rtk.ko`，aarch64，not stripped，sha256 `99f923ac92dc22187d75920f70e15f11f056753129f3cb74c658cc130afa7425` |
| `fc_8277c.ko` | `/mnt/c/rea/fc_8277c.ko`，aarch64，not stripped，sha256 `a287e7930b4930f552ae6b2b799a0b35050ae166d1dab8da40717aae11653571` |
| `ca-ne.ko` | `/mnt/c/rea/ca-ne.ko`（寄存器 AAL；本轮物理偏移全部由它直接反汇编取得） |
| 反汇编 | `aarch64-linux-gnu-objdump -dr --no-show-raw-insn`（保留重定位确认 `fc_db`、`g_ne_reg_iobase`、`ca_rtk_debug` 基址） |
| 语义 | REA（Ghidra 12.1.4）`analyze_function` / `inspect_analysis_view`（分页读伪代码） |
| 地址 | 一律 **nm 节内地址**（objdump 显示的符号地址）。**REA 地址 = 节内地址 + 0x100000**（实测：`0xb924→0x10b924`、`0xb05e0→0x1b05e0`；任务书写的 `+0x100040` 只适用于 `fc_mgr.ko`，对这两个 .ko 不成立）。 |
| NE 寄存器 | `ca-ne.ko` 内 `g_ne_reg_iobase` + 字节偏移；本文的 `0x25xx / 0x16xx / 0x97xx` 均为该偏移。 |

标注级别：**[观测]** = 反汇编/伪代码直接可见；**[推导]** = 多处观测合并；**[UNKNOWN]** = 语料内无法确认。

---

## 1. 结论摘要（TL;DR）

1. **ca-rtk.ko 的 share-meter 不是一张“128×7 bit 硬件表”**。它的软件表只有 **22 项 × 28 B**（`0x16` 由 dump 循环常量钉死，`_dal_rtl8277c_rate_glb_db_dump @0x9798`），速率单位 kbps、**12 bit bucket**，物理落点是 **L2 TE policer 的 16/16/8 个 slot**（pkt_type / port / agr_flow），不是 L3 POL1。**[观测]**
2. 任务书中的「128×7 bit」在这两个 .ko 里**找不到对应结构**——最近的 128 只有 fc_db 里的 SW meter 表（128×0x38，仅 enable+rate），bucket 仍为 12 bit。**若 9617C 的 `rtk.ko` 另有 128 项 share-meter 表，该模块不在本语料 ⇒ [UNKNOWN]**（§3.9）。
3. fc_8277c 的 Host Policing 表是 **32 项 × 0x88 B**（不是 96），控制结构仍是 36 B；`set` 的入口守卫是 `idx > 0x1F → 0x10005`。**[观测]**
4. Host Policing 有三种计量模式，由 `fc_db+156` 的 bit0/bit1 选择：**L3 POL1 直配** / **share-meter（`rtk_rate_shareMeter_set`，index = 0x80+vmeter）** / **虚拟 meter 映射（`rt_rate_shareMeterMappingHw_get`）**。**[观测]**
5. `_rtk_fc_g3_l2cls_for_hostPoliceControl_add/del` 在 fc_8277c 里是 **20 字节空桩**（`mov w0,#0; ret`）——**没有任何 ACL/class 调用序列**；绑定完全靠 **L2 LUT 表项 +0x1E**。**[观测]**
6. G3 flow 的绑定字段：**`pol_en` = 64-bit header bit25，`pol_id` = header bits[39:32]（8 bit）**；由 `_rtk_fc_g3FlowIdDecision` 计算，`RTK_RG_G3_FLOW_SET` 写入。**[观测]**
7. MIB：per-id 结构里 **`+0x70` = rx 累计 u64、`+0x78` = tx 累计 u64、`+0x80` = pol1 索引字 u32**（`[9:0]` ingress、`[19:10]` egress、bit20/21 = SW 标志）；HW 计数来自 `aal_l3_te_pm_policer_flow_get` 的 **out[2]/out[3]**（32 bit 字段，**不是** re4 写的 out[4]/out[5]）。`clear` 只做“读走 + 清软件累计”，**不写硬件清零寄存器**。**[观测]**

---

## 2. 与 phase2-re4 的差异订正

| 项 | phase2-re4（fc_mgr.ko / 9617C） | 本文（fc_8277c.ko） | 说明 |
|---|---|---|---|
| Host 表项数 | 96（`cmp #0x5f`） | **32**（`cmp w21,#0x1f` @0xB0624；重复 MAC 扫描 `cmp w3,#0x20` @0xB06D4；MIB `cmp w20,#0x1f` @0xB1F18） | 8277C 是 32 条 |
| 每-id 结构 | 步长 0x50，基址 `fc_db+0xC20FB0` | **步长 0x88，控制表基址 `fc_db+0x95EC08`**；MIB/计数器在 `fc_db+0x95EC78/+0x95EC80/+0x95EC88` | 完全不同的布局 |
| sw 控制表 | `fc_db+0xC200B0`，0x28/项 | `fc_db+0x95EC08`，0x88/项（表内前 36 B = 控制结构） | 同上 |
| lutIdx 上限 | 0x1027 | **0x101F**（`cmp #0x101f` @0x2BFD4） | 表尺寸不同 |
| LUT 指针数组 | `fc_db+0xBF0090`（`(lutIdx+0x17E012)*8`） | **`fc_db + (0x126514 + lutIdx)*8`**（常量 `0x126514` @0x2C024/0x2C064） | 数组基址不同 |
| 速率编程 | 映射函数 → `_rtk_fc_g3L3Policer_set` | 三模式：POL1 直配(0xA0+v) / **`rtk_rate_shareMeter_set`(0x80+v)** / 虚拟 meter 映射 | §4.4 |
| POL1 分区 | host 0..191 / hash 192,193 / mc-netif 194..225 / ACL 226..255 | **L3 模式：rate 0xA0..0xBF、ingress MIB 0xC0..0xDF、egress MIB 0xE0..0xFF**；share-meter 模式：MIB 0xA0..0xBF / 0xC0..0xDF | §4.5 |
| MIB 计数器 | `out[4]-out[5]`（36 bit） | **`out[2]-out[3]`（32 bit 段）** | §4.7，见 U-3 |
| flow 字段 | flow `+0x4C/+0x4E` | **flow `+0x40`(SMAC hostPol idx) / `+0x42`(DMAC hostPol idx)** | `_rtk_fc_extraInfo_setting` @0xCE10 |
| g3 l2cls 绑定 | 未见（UNKNOWN） | **add/del = 空桩**，确认无 ACL/class 路径 | §4.9 |

> 结论：**不能把 re4 的 96/0x50/0xC20FB0 常量照搬到 8277C**。两套 fc_db 布局互不兼容，落地时以本表为准。

---

## 3. share-meter 子系统（ca-rtk.ko）

> 重要前提：ca-rtk.ko 是 **RTL8277C PON 侧**的 `dal_rtl8277c_*` 速率 DAL。它实现的 share-meter 服务于
> **每端口 storm-control（uuc/umc/bc/mc/dhcp/arp/igmp_mld）**，与 fc_8277c 里 host policing 调用的
> `rtk_rate_shareMeter_*`（§4.4，索引 0x80..0x9F）**不是同一张表**——见 §3.9 与 U-1。

### 3.1 软件表：22 项 × 28 B **[观测]**

- 基址：`ca_rtk` 的 `.bss+0x4768`，条目数组在 `+0xA80`。
- **条目数 = 22**：`_dal_rtl8277c_rate_glb_db_dump @0x9798` 的循环 `cmp w20,#0x16; b.ne`（`0x98A8`），
  且 `dal_rtl8277c_rate_init @0xA904` 用 `memset(base+0xA80, 0, 0x268)`（0x268/0x1C = 22）。
- 条目字段（dump 字符串 `meterEntry[%u].<field>=%u` 逐字段钉死）：

| 偏移 | 字段 | 语义 | 证据 |
|---|---|---|---|
| `+0x00` | `mode` | policer 模式/使能；0 = 关闭（`get` 把 mode==0 翻成 rate=0x1F3FFFF） | `str w2,[x6,x1]` @0xB098 |
| `+0x04` | `pps` | 速率模式：0 = 字节/kbps 口径，1 = 包/秒 | `shareMeterMode_set` `str w20,[x1,#2692]` |
| `+0x08` | `cir` | 承诺速率（kbps） | `str w25,[x0,#8]` |
| `+0x0C` | `cbs` | 承诺突发（12 bit，0..0xFFF） | `str w20,[x2,#12]` |
| `+0x10` | `pir` | 峰值速率（kbps，本路径恒 = cir） | `str w25,[x0,#16]` |
| `+0x14` | `pbs` | 峰值突发（12 bit） | `str w20,[x2,#20]` |
| `+0x18` | `ipg` | IFG 补偿：0 = 不含，0x14(20) = 含 20 B 开销 | `csel w23,w23,#0x14,eq` |

### 3.2 索引空间 **[观测]**

- **0..21（22 项）**。入口守卫：`idx < *(u32*)(*(u64*)(hal_ctrl+0x18)+0x18)`（caps 字段），
  dump 循环固定 22 ⇒ 本 build 的实际上限 = 22。
- 速率上限：`0x1F3FFFF = 32,767,999`（kbps）；`0xFFFFFFFF` = “不变”哨兵，**DAL 本身不接受**
  （`cmp w25,#0x1F3FFFF; b.hi → return 1`；host policing 层在调用前就把 -1 过滤掉了）。
- 非法参数返回：`1`（越界）、`0xF`（`rate_init != 1`）、`7`（空指针）、`0`（成功）。

### 3.3 单位与编码 **[观测]**

`_dal_rtl8277c_use_ca_agr_flow_set @0x9A38` / `_dal_rtl8277c_use_ca_l2_flood_set @0x9D08`：

```
hi = rate / 1000          ; udiv
lo = rate - hi*1000       ; msub，10 bit
profile[1] = hi           ; 16 bit → DATA0[25:10]
profile[0] = lo           ; 10 bit → DATA0[9:0]
profile[4] = hi           ; 16 bit → DATA1[31:16]  (PIR = CIR)
profile[3] = lo           ; 10 bit → DATA1[15:6]
profile[2] = cbs ? cbs : 1 ; 12 bit，拆分 → DATA0[31:26] + DATA1[5:0]
profile[5] = pbs ? pbs : 1 ; 12 bit → DATA2[11:0]
flags = 0x3F              ; 6 个字段全写
```

⇒ **rate 单位 = kbps，硬件值 = 1000×hi + lo = 原值**（基数 1000，不是 L3 的 500）。
⇒ **bucket 单位 = 字节，12 bit 原值，0 被夹成 1**（`csel w0,w0,#1,ne`）。
⇒ 若 `pps=1`，同一 26 bit 数值按“包/秒”解释（cfg bit4 切换，见 §3.5）。

### 3.4 物理落点：L2 TE policer 三张子表 **[观测，寄存器来自 ca-ne.ko]**

| 子表 | cfg 寄存器（NE 偏移） | profile ACCESS | DATA2 | DATA1 | DATA0 | 索引位宽 |
|---|---|---|---|---|---|---|
| `pkt_type` | `0x2500 + 4*i`（i=0..15） | `0x2540` | `0x2544` | `0x2548` | `0x254C` | 4 bit |
| `port` | `0x255C + 4*i`（i=0..15） | `0x259C` | `0x25A0` | `0x25A4` | `0x25A8` | 4 bit |
| `agr_flow` | `0x25B8 + 4*i`（i=0..7） | `0x25D8` | `0x25DC` | `0x25E0` | `0x25E4` | 3 bit |

- cfg 常量证据：`0x3d0c0940/0x3d0c0957/0x3d0c096e`，经 `ubfiz x1,x1,#2,#14` 得
  `(0x940/0x957/0x96E)<<2 = 0x2500/0x255C/0x25B8`（`aal_l2_te_policer_pkt_type_cfg_set @0x42D70`、
  `port_cfg_set @0x42EA0`、`agr_flow_cfg_set @0x43000`）。
- profile ACCESS 证据：`__l2_te_policer_pkt_type_profile_access @0x45760`、
  `__l2_te_policer_port_profile_access @0x453D0`、`__l2_te_policer_agr_flow_profile_access @0x45040`。
- **(block, type) → slot 的仲裁器**：`aal_arb_non_known_pol_map_get @0x3F050`
  - 写 `NE 0x1624`：`(block<<2)|type | 0x80000000`（bit31 = start）；
  - 轮询 bit31（上限 10000 次），读 `NE 0x1628`，取 `[3:0]` = policer index（0..15）；
  - 即 **L2 TE policer 槽号不是软件线性分配的，而是硬件仲裁表查出来的**。

### 3.5 cfg 字位域 **[观测，flag 映射来自 access 函数]**

`aal_l2_te_policer_pkt_type_cfg_set` 的 `flags` 位 → cfg 位：

| flag | cfg 位 | 含义（本路径用到的） |
|---|---|---|
| bit0 | `[2:0]` | meter 模式/使能（0=disable，1=enable，2=保留） |
| bit1 | bit3 | — |
| **bit2** | **bit4** | **rate mode（0=字节/kbps，1=包/秒；对应软件 `pps` 字段）** |
| bit3 | bit5 | — |
| **bit4** | **`[10:6]`** | **IFG 补偿字节数（0 或 20）** |
| bit5..8 | bit11/12/13/`[15:14]` | — |

`_use_ca_*` 只写 flags = `0x15`（bit0/2/4）⇒ 只改 mode、rate-mode、IFG，其余位读改写保留。

### 3.6 profile 96 bit 打包（pkt_type，已验证） **[观测]**

| profile 偏移 | 位宽 | 去向 |
|---|---|---|
| `+0` | 10 | DATA0[9:0]（CIR lo） |
| `+2` | 16 | DATA0[25:10]（CIR hi） |
| `+4` | 12 | DATA0[31:26]（低 6）+ DATA1[5:0]（高 6）← **CBS** |
| `+6` | 10 | DATA1[15:6]（PIR lo） |
| `+8` | 16 | DATA1[31:16]（PIR hi） |
| `+10` | 12 | DATA2[11:0] ← **PBS** |

证据：`aal_l2_te_policer_pkt_type_profile_set @0x45980`（`bfxil/bfi` 序列）。
`agr_flow` 的打包**同构**（`_use_ca_agr_flow_set` 用完全相同的 profile 偏移与 flags 0x3F）**[推导]**；
`port` 的打包未验证 **[UNKNOWN]**。

### 3.7 读写顺序 **[观测]**

**profile 访问原语**（`__l2_te_policer_*_profile_access`）：
- 写：`DATA2 → DATA1 → DATA0 → ACCESS`；`ACCESS = idx | (1<<30) | (1<<31)`。
- 读：`ACCESS = idx | (0<<30) | (1<<31)` → 忙等 bit31（上限 0x1000）→ 读 `DATA0 → DATA1 → DATA2`。
- 每次写前/读后 `dmb oshst/oshld`；索引位宽 4/4/3 bit。

**一次 shareMeter_set 的完整顺序**（`dal_rtl8277c_rate_shareMeter_set @0xB924`）：
1. 参数校验（idx/rate/mode）。
2. rate == 0x1F3FFFF（关闭）：写软件表 `mode=0,pps=0,cir=0,cbs=0xFFF,pir=0,pbs=0xFFF`，跳 6。
3. 否则**先扫一遍消费者**（32 block × 7 slot，见 §3.8），把现有 cfg 的 `mode/pps/IFG` 与 profile 的 `CBS/PBS` 抄进软件表；
4. 写 `cir=pir=rate`；
5. 写 `ipg = mode ? 0x14 : 0`；
6. 调 `_dal_rtl8277c_check_meter_change_set(idx) @0x9EB8`：
   - 再扫一遍消费者；
   - 命中 → `cfg_set`（先写 cfg：mode/rate-mode/IFG）；
   - 再 `profile_get` → 改 6 个字段 → `profile_set`（DATA2→DATA1→DATA0→ACCESS）；
   - 类型 4/5/6 还会顺带 `aal_l2_specpkt_ctrl_set`。

> 即：**软件表先写、硬件后写**；硬件是“读改写”，且**只改 6 个 profile 字段**（CIR/PIR/CBS/PBS），
> 不动 profile 里其余保留位。

### 3.8 消费者发现（32 block × 7 slot） **[观测]**

- block 表：`ca_rtk .bss+0x4768`（32 项 × 0x54），每项 7 个 u16 “flow_id/meter 槽”：
  `+0x1C`(uuc)、`+0x1E`(umc)、`+0x20`(bc)、`+0x22`(mc)、`+0x24`(dhcp)、`+0x26`(arp)、`+0x28`(igmp_mld)。
  证据：`dal_rtl8277c_rate_init @0xA904`（32 次 memset -1）、`dal_rtl8277c_rate_stormControlMeterIdx_set @0xAEE0`。
- `_check_meter_change_set` 命中槽位后分派：
  - `+0x1C` → `_use_ca_l2_flood_set(block, 0, …)`（pkt_type 子表）；
  - `+0x20` → `_use_ca_l2_flood_set(block, 3, …)`；
  - `+0x24` → `aal_l2_te_policer_agr_flow_cfg_set/profile_set(idx=5)` + `aal_l2_specpkt_ctrl_set(type=5)`；
  - `+0x26` → agr_flow idx=6（type=4 路径）；
  - `+0x28` → agr_flow idx=7（type=4 路径）；
  - 其余槽位在该函数内未见（**[UNKNOWN]**：umc/mc 两槽的更新路径未在本函数出现）。
- `aal_l2_specpkt_ctrl_*` 侧：写 `[+0x54]=1`、`[+0x58]=rate`、`[+0x64]=0x11`、`[+0x66]=((block)<<9)|type`（`_use_ca_specpkt_ctrl_set @0x9BF0`）。

### 3.9 关于「128 × 7 bit」 **[UNKNOWN — 明确否定]**

- ca-rtk.ko 的 share-meter 表 = **22 项**，bucket = **12 bit**（`cmp w20,#0xFFF` @0xBFC24）。
- L2 TE policer profile 的 bucket 字段 12 bit（§3.6）；L3 TE POL1/POL2/POL3 的 burst 也是 12 bit
  （`_rtk_fc_l3MeterBucket_set @0x4D280` 守卫 0..0xFFF）。
- 语料内唯一的 128 项结构是 fc_db 的 **SW meter 表**（128 × 0x38，`fc_db+0x858000`，仅 enable/rate），
  与 bucket 无关。
- ⇒ **「128 项 × 7 bit」在 ca-rtk.ko / fc_8277c.ko / ca-ne.ko 中均无对应物。**
  若量产的 `rtk.ko`（提供 `rtk_rate_shareMeter_*` 的模块）内部是 128×7 bit，则该模块**不在本语料**，
  必须以设备/该模块补齐（U-1）。**不要**用 ca-rtk 的 22 项表去实现 host policing 的 0x80..0x9F 索引。

---

## 4. Host Policing（fc_8277c.ko）最终规格

### 4.1 数据模型 **[观测]**

**32 条 host 条目，键 = MAC，不分方向/端口**（与 re4 的 96 条同构，只是数量与布局不同）。

| 结构 | 基址 | 步长 | 项数 |
|---|---|---|---|
| 控制表（SW 副本，前 36 B = 用户 ABI） | `fc_db + 0x95EC08` | `0x88` | **32** |
| LUT 指针数组 | `fc_db + (0x126514 + lutIdx)*8` | 8 B | lutIdx ≤ **0x101F** |

每 id 结构（`E = fc_db + 0x95EC08 + id*0x88`）：

| 偏移 | 类型 | 含义 | 证据 |
|---|---|---|---|
| `+0x00` | `u8[6]` | MAC（= 控制结构起点） | `stp x0,x1,[x2]` @0xB9E4 |
| `+0x08` | u32 | `ingressLimitCtrl`（0/1/2） | `[x20,#8]` |
| `+0x0C` | u32 | `egressLimitCtrl` | `[x20,#12]` |
| `+0x10` | u32 | `mibCountCtrl` | `[x20,#16]`、`ldr [x4,#11288]` |
| `+0x14` | u32 | `ingressLimitMeterIdx`（虚拟，0..31） | `[x20,#20]` |
| `+0x18` | u32 | `egressLimitMeterIdx`（虚拟，0..31） | `[x20,#24]` |
| `+0x1C` | u32 | `ingressLimitRate`（kbps，0xFFFFFFFF=不变） | `[x20,#28]` |
| `+0x20` | u32 | `egressLimitRate` | `[x20,#32]` |
| `+0x28+16*cpu` | u64 | SW rx 计数（cpu 0..3） | `_rtk_fc_sw_hostMib_all_cpu_get @0x34B20` |
| `+0x30+16*cpu` | u64 | SW tx 计数 | 同上 |
| `+0x68` | u32 | ingress 硬件 meter 索引（实际使用） | `str w26,[x4,#11376]` @0xB9F4 |
| `+0x6C` | u32 | egress 硬件 meter 索引 | `str w27,[x4,#11380]` |
| `+0x70` | u64 | HW rx 累计 | `_rtk_fc_hwHostPolingMib_get` |
| `+0x78` | u64 | HW tx 累计 | 同上 |
| `+0x80` | u32 | **pol1 索引字**：`[9:0]` ingress、`[19:10]` egress、bit20/21 = SW 类型标志（0=HW，1=SW） | `ldr w1,[x5,#8]` / `bfxil` |

> 注意：`+0x80` 的 SW 标志在 **pol1 字里**（bit20/21），不像 re4 那样单独有 `hw_ctl`。

### 4.2 `rtk_fc_hostPoliceControl_set(idx, ctrl)` @0xB05E0 全序列 **[观测]**

```
 0. 若 fc_db+20 bit13（与 fc_db+24 相关）→ 特殊分支；否则 idx > 0x1F → 返回 0x10005。
 1. 读旧 MAC（E+0x00..0x05）保存到栈；锁 rtk_fc_mgr_global_spin_lock_bh_irq_protect()。
 2. 若新 MAC != 0：32 项重复 MAC 扫描（跳过自身），重复 → 日志
    "Set host policing entry failed! The MAC %pM has been set in entry [%d]." + 返回 -1。
 3. 拷贝 36 B 控制结构 → E；写 E+0x68 = ingress 硬件 meter、E+0x6C = egress 硬件 meter
    （由模式决定，见 §4.4）。
 4. pol1 字：清 bit20/21，按模式置位；若 mibCountCtrl == 0 → bits[19:0] 全置 1（0xFFFFF，两方向 0x3FF）。
 5. 逐方向编程速率（见 §4.4）；rate == 0xFFFFFFFF 时跳过。
 6. `_rtk_fc_hwHostPolingMib_clear(idx)`；清 64 B（E+0x28..E+0x67 的 4 组 SW 计数）。
 7. 若 MAC 变化：`_rtk_fc_lut_find(oldMac)` → `rtk_fc_flow_delete_by_l2Idx(lutIdx)` → 日志
    "Clear flow by hostPolControl[%d] original MAC %pM"；
    然后 `_rtk_fc_lutHostPolicingIdxUpdate(newMac)`，旧 MAC 再调一次（把 +0x1E 置 -1）。
 8. 解锁，返回 0。
```

- **删除语义**：MAC = 00:00:00:00:00:00 + 全 0 控制结构 ⇒ 第 3 步写入全 0 ⇒ 第 6 步清零 ⇒ 第 7 步把旧 MAC 的 LUT +0x1E 置 -1。
- `_rtk_fc_g3_l2cls_for_hostPoliceControl_add/del` 在第 7 步的 MAC 变化路径被调用，但**是空桩**（§4.9）。

### 4.3 模式位 `fc_db+156`（u16） **[观测]**

| 位 | 语义 | 证据 |
|---|---|---|
| bit0 | **虚拟 meter 映射模式**：走 `rt_rate_shareMeterMappingHw_get`（`[fc_db+0x50]+8` 函数指针），type1(host) 要求 hw ≤ 0x9F，type4(sw) 要求 hw ≤ 0x1F | `tbnz w0,#0,0xB0748`；`cmp w26,#0x9f` @0xB1088；`cmp w26,#0x1f` @0xB0784 |
| bit1 | **share-meter + SW MIB 模式**：速率为 `vmeter+0x80` 走 `rtk_rate_shareMeter_set`；MIB 只读 SW 计数 | `tbnz w0,#1,0xB08EC`；MIB `tbz w0,#1` @0x4CE34 |

字符串侧证：`"[HOST] SW shaper and mib update mode:"`、`"[Drop] the packet belongs to shareMeter[%d], and over its rate limit. (type=%d)"`。

### 4.4 速率编程（每方向） **[观测]**

| bit1 | bit0 | 硬件 meter 索引 | 编程调用 |
|---|---|---|---|
| 0 | 0 | `vmeter + 0xA0`（160..191） | `_rtk_fc_g3L3Policer_set(idx, rate_kbps, 1)` @0x4ABE0 |
| 1 | 0 | `vmeter + 0x80`（128..159） | `rtk_rate_shareMeter_set(idx, rate_kbps, 1)`（U 符号） |
| × | 1 | 映射返回值 `hw_idx`（type1 ≤0x9F / type4 ≤0x1F） | type1 → `_rtk_fc_g3L3Policer_set`；type4 → SW meter 表 |

- `_rtk_fc_g3L3Policer_set(idx, rate, ifg)`：`rate == 0x1F3FFFF` → `rtk_8277c_l3_flow_policer_mode_set(idx,0)`（关）；
  否则 `mode_set(idx,1)` + `rtk_8277c_l3_flow_policer_rate_set(idx, rate, rate)`（**CIR=PIR**）+ `rtk_8277c_l3_policer_ifg_config_set(ifg&1)`。
- `rtk_8277c_l3_flow_policer_rate_set @0xC6600`：`/500` 编码（magic `0x10624DD3`，`>>37`，`msub #500`），
  26 bit ⇒ `rate_kbps = 500*hi + lo`，上限 `0x1F3FFFF`；profile flags = **0x1B**（只写 CIR/PIR，不动 burst）。
- type4 SW meter 表：`fc_db + 0x858000 + hwIdx*0x30`，`+0x3618 = enable`、`+0x361C = rate`（`str w2,[x0,#13848]; str w1,[x0,#13852]` @0xB0FF8）。
- 方向：**ingress 用 SA 命中、egress 用 DA 命中**（字符串 `L2_INGRESS_SA_HOSTPOLICING` / `L2_EGRESS_DA_HOSTPOLICING`，
  `"SA %pM … rx count"` / `"DA %pM … tx count"`）。

### 4.5 POL1 槽位映射 **[观测]**

| 模式 | 速率受限方向 | 仅计数的 ingress | 仅计数的 egress |
|---|---|---|---|
| L3（bit1=0） | `vmeter + 0xA0`（160..191） | `idx + 0xC0`（192..223） | `idx + 0xE0`（224..255） |
| share-meter（bit1=1） | share-meter `vmeter + 0x80` | `idx + 0xA0`（160..191） | `idx + 0xC0`（192..223） |

证据：`add w26,w26,#0xa0` @0xB065C、`#0x80` @0xB08EC、`add w0,w0,#0xc0` @0xB1650、`#0xe0` @0xB1664、
`#0xa0` @0xB0F10、`#0xc0`（share-meter 计数 egress，见 0x4C670 日志构造）。

### 4.6 get @0xB1C40 **[观测]**

- 校验 idx ≤ 0x1F、指针非空；读 pol1 字 bit20/21 判定方向是否 SW 类型：
  - SW → 从 SW meter 表 `fc_db+0x858000+hwIdx*0x30+0x361C` 取 rate；
  - 否则 bit1=1 → `rtk_rate_shareMeter_get(hwIdx, &rate, &mode)`；bit1=0 → `_rtk_fc_l3Meter_get(1, hwIdx, &rate, &mode)`。
- 回填控制结构 `+0x1C/+0x20`；mode 的回填偏移 **[UNKNOWN]**（见 U-8）。

### 4.7 MIB **[观测]**

- `rtk_fc_hostPoliceMib_get(idx, u64 out[2]) @0xB1EE0`：
  `out[0]=out[1]=0` → `_rtk_fc_hwHostPolingMib_get(idx,&out[0],&out[1])` →
  `out[0] += _rtk_fc_sw_hostMib_all_cpu_get(idx,0)`；`out[1] += …(idx,1)`。
  `out[0] = Rx(ingress)、out[1] = Tx(egress)`。
- `_rtk_fc_hwHostPolingMib_get(id, *rx, *tx) @0x4CDD0`：
  - ingress pol1 = `E+0x80` 的 `[9:0]`；egress = `[19:10]`；`0x3FF` → 无。
  - 若 `fc_db+156 bit1 == 0` 且对应 pol1 != 0x3FF：
    `aal_l3_te_pm_policer_flow_get(0, pol1, buf)`；
    **`buf[2] - buf[3]`**（栈 `+0x58`/`+0x60`，u64 下标 2/3）累加进 `E+0x70`/`E+0x78`。
  - 若 `bit1 == 1`：跳过硬件读，只返回 `E+0x70/+0x78` 的已有累计（由 SW 计数填充）。
- `_rtk_fc_hwHostPolingMib_clear(id) @0x4CF70`：对两方向各做一次 `get`（把增量读走），
  再把 `E+0x70/E+0x78` 清零；**不写 0x9138 之类的硬件 counter-clear 寄存器**。
- `rtk_fc_hostPoliceMib_clear(idx) @0xB0490`：`_hwHostPolingMib_clear(idx)` + 清 `E+0x28..E+0x67` 的 64 B SW 计数。
- SW 计数：`_rtk_fc_sw_hostPolicingMibCounting @0x34FF0` 按 CPU 累加字节；
  每 CPU 槽 = `E+0x28+16*cpu`（rx）/`E+0x30+16*cpu`（tx），4 CPU。
- **位宽订正**：fc_mgr 用 `out[4]-out[5]`（36 bit），fc_8277c 用 **`out[2]-out[3]`（32 bit）**。
  两者都按“读后差值累加”工作，说明计数块大概率为**读后清零/增量型**（U-3）。

### 4.8 LUT 绑定 `_rtk_fc_lutHostPolicingIdxUpdate @0x2BFA0` **[观测]**

```
lut_find(mac,&lutIdx,0) 失败 → 返回 0（什么都不做）
lutIdx > 0x101F → 打印 "0 <= lutIdx && lutIdx < RTK_FC_TABLESIZE_LUT" + dump_stack
扫 32 项（fc_db+0x95EC08，步长 0x88）：比较 [0..3] 与 [4..5] 的 MAC
  命中 → lut_entry[+0x1E] = 该项索引 (u16)
  未命中 → lut_entry[+0x1E] = 0xFFFF
lut_entry = *(u64*)(fc_db + (0x126514 + lutIdx)*8)
```

- 每个 MAC LUT 表项只有 **1 个** host-police 索引（`+0x1E`，s16，-1 = 无）。
- 消费者：`_rtk_fc_extraInfo_setting @0xCE10` 把 SMAC LUT idx / DMAC LUT idx 的 `+0x1E`
  分别写到 **flow `+0x40`（SMAC）/ `+0x42`（DMAC）**（`ldrsh w0,[x0,#30]; strh w0,[x19,#64]/[x19,#66]`）。
- `dump_sw_flow_fields @0x20400` 打印 `"SMAC hostPolicing Idx: %d, DMAC hostPolicing Idx: %d"`（字符串 @0xDDF60）。

### 4.9 `_rtk_fc_g3_l2cls_for_hostPoliceControl_add/del` = 空桩 **[观测]**

```asm
_rtk_fc_g3_l2cls_for_hostPoliceControl_add:   ; 0x4ABA0, 20 bytes
   bti c ; mov w0,#0 ; paciasp ; autiasp ; ret
_rtk_fc_g3_l2cls_for_hostPoliceControl_del:   ; 0x4ABC0, 20 bytes
   bti c ; mov w0,#0 ; paciasp ; autiasp ; ret
```

⇒ **不存在“pol_id/pol_en 写入 + LUT +0x1E + ACL/class 调用序列”的第三条路径**。
`rtk_fc_hostPoliceControl_set` 在 MAC 变化时确实 `bl` 了 add（0xB0D30）、clear 时 `bl` 了 del（0xB1244），
但两者**不写任何寄存器、不查任何表**。Host policing 的绑定链只有：

```
用户 36B 控制结构（MAC + 2×(meter,rate) + 2×ctrl + mib ctrl）
  → 32 项 host 表（fc_db+0x95EC08）
  → L2 LUT 表项 +0x1E
  → flow +0x40 / +0x42（SMAC/DMAC）
  → _rtk_fc_g3FlowIdDecision
  → G3 flow header: pol_en(bit25) + pol_id(bits39:32)
  → POL1 profile（速率）/ POL1 计数器（MIB）
```

### 4.10 G3 flow 绑定 `_rtk_fc_g3FlowIdDecision @0x4BEE0` + `RTK_RG_G3_FLOW_SET @0x830A0` **[观测]**

`_rtk_fc_g3FlowIdDecision(flow, ?, u8 *pol_en, u16 *pol_id)`：
- 读 `flow+0x40`（SMAC host idx，s16）与 `flow+0x42`（DMAC host idx，s16）；-1 跳过。
- `fc_db+156 bit1` 决定走 share-meter 分支（0x4C058）还是 L3 分支。
- 优先级：**ingress 限速 > egress 限速 > 仅计数**：
  - ingress 限速：`*pol_en = 1`；`*pol_id = E+0x68`；日志
    `"flow id decision: hostPolicing[%d] (MAC: %pM) ingress rate limit (meter: %d, policer id: %d)."`；
    再校验 `pol1[9:0] == pol_id`，不一致打印 `"Please check! decided flow ID is %d, but hostPolicing[%d]'s loggingRx_policerIdx is %d"`；
  - egress 限速：`*pol_id = E+0x6C`；同构日志（loggingTx_policerIdx）；
  - 仅计数：`*pol_en = (mibCountCtrl != 0)`；L3 模式 `*pol_id = egressHostIdx + 0xE0`，share-meter 模式 `+0xC0`；
    日志 `"flow id decision: hostPolicing[%d] (MAC: %pM) ingress mib (policer id: %d)."` / `…egress mib…`。
- `RTK_RG_G3_FLOW_SET` 写 header：
  - `orr x0,x0,#0x2000000` → **bit25 = pol_en**（`0x834A4`）；
  - `strb w1,[sp,#244]` → **bits[39:32] = pol_id**（`0x834AC`）；
  - 另有 `bfi w4,w5,#19,#6`（bits[24:19]）一个 6 bit 字段，疑似 policer group id **[UNKNOWN]**。

---

## 5. 更新后的 HostPolicing API 与可落地范围（W6f）

```c
/* ---------- 常量（fc_8277c.ko 实测） ---------- */
#define FC_HOSTPOL_MAX            32          /* [V] cmp #0x1f */
#define FC_HOSTPOL_ENTRY_STRIDE   0x88        /* [V] */
#define FC_HOSTPOL_CTRL_BASE      0x95EC08    /* [V] fc_db + id*0x88 */
#define FC_HOSTPOL_RATE_MAX       0x1F3FFFFu  /* [V] 32,767,999 kbps */
#define FC_HOSTPOL_RATE_UNCHANGED 0xFFFFFFFFu /* [V] 调用前过滤 */
#define FC_POL1_RATE_BASE_L3      0xA0        /* [V] 160..191 (vmeter 0..31) */
#define FC_POL1_MIB_IN_L3         0xC0        /* [V] 192..223 (hostIdx) */
#define FC_POL1_MIB_EG_L3         0xE0        /* [V] 224..255 (hostIdx) */
#define FC_SHAREMETER_HOST_BASE   0x80        /* [V] rtk_rate_shareMeter_* 的 host 区 */
#define FC_POL1_MIB_IN_SW         0xA0        /* [V] share-meter 模式 */
#define FC_POL1_MIB_EG_SW         0xC0
#define FC_LUT_HOSTPOL_OFF        0x1E        /* [V] LUT entry +0x1E, 0xFFFF = none */

/* ---------- 1) 配置一条 host 条目（等价 rtk_fc_hostPoliceControl_set @0xB05E0） ---------- */
int fc_hostpol_program(u32 idx, const struct fc_host_pol_cfg *cfg);   /* [V] 整条重建 */
int fc_hostpol_clear(u32 idx);                                        /* [V] MAC=0 + 全 0 控制结构 */
int fc_hostpol_read(u32 idx, struct fc_host_pol_cfg *out);            /* [V] get @0xB1C40 */

/* ---------- 2) 速率 ---------- */
/* L3 模式（bit1=0）：POL1 slot = vmeter+0xA0；调用 ca-ne 导出： */
int fc_pol1_rate_set(u32 pol1_idx, u32 kbps, bool ifg);   /* [V] _rtk_fc_g3L3Policer_set @0x4ABE0
                                                              → rtk_8277c_l3_flow_policer_{mode,rate}_set
                                                              → aal_l3_te_policer_flow_profile_set @0x740B0 */
/* share-meter 模式（bit1=1）：index = vmeter+0x80；调用 rtk_rate_shareMeter_set() —— 该实现不在语料 [U] */

/* ---------- 3) MAC 绑定 ---------- */
int fc_hostpol_bind_mac(const u8 mac[6], s16 host_idx);   /* [V] write LUT entry+0x1E; -1 = unbind
                                                              (_rtk_fc_lutHostPolicingIdxUpdate @0x2BFA0) */

/* ---------- 4) MIB ---------- */
int fc_hostpol_mib_get(u32 idx, u64 *rx, u64 *tx);        /* [V] @0xB1EE0, rx=out[0], tx=out[1] */
int fc_hostpol_mib_clear(u32 idx);                        /* [V] @0xB0490：读走 + 清 SW 累计 */
```

### 5.1 可以立即实现（不依赖设备）

| 能力 | 依据 |
|---|---|
| 32 条 host 表 + 36 B 控制结构 + 重复 MAC 检查 + 整条重建 | §4.1/§4.2 |
| POL1 速率编程（kbps、`/500`、`0x1F3FFFF` 哨兵、IFG） | §4.4 + ca-ne `aal_l3_te_policer_flow_profile_set @0x740B0` |
| POL1 槽位映射（0xA0/0xC0/0xE0） | §4.5 |
| LUT `+0x1E` 绑定 + flow `+0x40/+0x42` + G3 `pol_en(bit25)/pol_id([39:32])` | §4.8/§4.10 |
| MIB 读清（`out[2]-out[3]` 累加、clear 只清软件累计） | §4.7 |
| 方向语义（ingress=SA / egress=DA） | 字符串 + `extraInfo` 两路 |

### 5.2 仍需设备/缺失模块

1. **`rtk_rate_shareMeter_*` 的真实实现**（share-meter 模式 0x80..0x9F）——U 符号，不在语料；其索引空间/桶宽/读回语义必须补（U-1）。
2. **`out[2]-out[3]` 的语义与是否读后清零**（U-3）——决定 MIB 累计是否正确，需打流连续读两次。
3. `mibCountCtrl = 2` 与 `1` 的差异（U-5）。
4. `fc_db+156` bit0/bit1 由哪个 procfs/配置项设置（U-2）。
5. `RTK_RG_G3_FLOW_SET` 里 bits[24:19] 的 6 bit 字段含义（U-6）。
6. L2 TE `port` profile 的打包字段（§3.6 只验证了 pkt_type/agr 同构）（U-7）。

---

## 6. UNKNOWN 清单

| # | 项 | 影响 | 下一步 |
|---|---|---|---|
| U-1 | `rtk_rate_shareMeter_set/get/Bucket/Mode` 的实现（提供者模块不在语料；索引 0x80..0x9F 说明其池 ≥160） | share-meter 模式无法独立实现 | 找 `rtk.ko`（或 9617C 对应模块）反汇编；或设备读寄存器对比 |
| U-2 | `fc_db+156` bit0/bit1 的配置入口 | 三种模式无法运行时切换 | 反 procfs/参数 setter |
| U-3 | `aal_l3_te_pm_policer_flow_get` 的 out[2]/out[3] 语义与读后清零 | MIB 数值正确性 | 设备连续两次 get 同一 POL1 索引 + 打流 |
| U-4 | 「128×7 bit」share-meter 表是否存在（本语料无） | 若存在则需另一套寄存器 | 设备/模块补证；**不要**用 ca-rtk 22 项表代替 |
| U-5 | `mibCountCtrl` 1 vs 2 的差异 | 资源/行为差异 | 设备复现 |
| U-6 | G3 header bits[24:19] 6 bit 字段 | 可能影响 group policer | 反 `RTK_RG_G3_FLOW_SET` 其余分支 |
| U-7 | L2 TE `port` profile 打包 | 仅影响 port policer 路径 | 反 `aal_l2_te_policer_port_profile_set @0x455F0` |
| U-8 | `hostPoliceControl_get` 的 mode 回填偏移 | 回读语义 | 反 0xB1C40 全函数 |
| U-9 | ca-rtk share-meter 的 umc/mc 两槽更新路径 | 仅 storm-control 完整性 | 反 `_check_meter_change_set` 未覆盖分支 |

---

## 附录 A：函数 / 地址索引

### ca-rtk.ko（nm 地址；REA = +0x100000）

| 函数 | 地址 |
|---|---|
| `dal_rtl8277c_rate_shareMeter_set` | `0xB924` |
| `dal_rtl8277c_rate_shareMeter_get` | `0xBD84` |
| `dal_rtl8277c_rate_shareMeterMode_set` / `_get` | `0xBE68` / `0xBF0C` |
| `dal_rtl8277c_rate_shareMeterBucket_set` / `_get` | `0xBFB8` / `0xC064` |
| `_dal_rtl8277c_check_meter_change_set` | `0x9EB8` |
| `_dal_rtl8277c_use_ca_l2_flood_set` / `_agr_flow_set` / `_specpkt_ctrl_set` | `0x9D08` / `0x9A38` / `0x9BF0` |
| `dal_rtl8277c_rate_init` | `0xA904` |
| `_dal_rtl8277c_rate_glb_db_dump`（22 项循环） | `0x9798`（`cmp #0x16` @ `0x98A8`） |
| `dal_rtl8277c_rate_stormControlMeterIdx_set` | `0xAEE0` |

### ca-ne.ko（寄存器 AAL）

| 函数 | 地址 | 寄存器 |
|---|---|---|
| `aal_l2_te_policer_pkt_type_cfg_set` | `0x42D70` | `0x2500+4i` |
| `aal_l2_te_policer_port_cfg_set` | `0x42EA0` | `0x255C+4i` |
| `aal_l2_te_policer_agr_flow_cfg_set` | `0x43000` | `0x25B8+4i` |
| `__l2_te_policer_pkt_type_profile_access` | `0x45760` | `0x2540/44/48/4C` |
| `__l2_te_policer_port_profile_access` | `0x453D0` | `0x259C/A0/A4/A8` |
| `__l2_te_policer_agr_flow_profile_access` | `0x45040` | `0x25D8/DC/E0/E4` |
| `aal_l2_te_policer_pkt_type_profile_set` | `0x45980` | 96 bit 打包 |
| `aal_arb_non_known_pol_map_get` | `0x3F050` | `0x1624` cmd / `0x1628` result |
| `aal_l3_te_pm_policer_flow_get` | `0x753B0` | `0x973C` + `0x9740..0x9760` |
| `aal_l3_te_policer_flow_profile_set` | `0x740B0` | `0x9128/2C/30/34` |

### fc_8277c.ko（nm 地址；REA = +0x100000）

| 函数 | 地址 |
|---|---|
| `rtk_fc_hostPoliceControl_set` | `0xB05E0` |
| `rtk_fc_hostPoliceControl_get` | `0xB1C40` |
| `rtk_fc_hostPoliceMib_get` | `0xB1EE0` |
| `rtk_fc_hostPoliceMib_clear` | `0xB0490` |
| `_rtk_fc_hwHostPolingMib_get` / `_clear` | `0x4CDD0` / `0x4CF70` |
| `_rtk_fc_sw_hostMib_all_cpu_get` | `0x34B20` |
| `_rtk_fc_sw_hostPolicingMibCounting` | `0x34FF0` |
| `_rtk_fc_lutHostPolicingIdxUpdate` | `0x2BFA0` |
| `_rtk_fc_g3_l2cls_for_hostPoliceControl_add` / `_del` | `0x4ABA0` / `0x4ABC0`（空桩） |
| `_rtk_fc_g3FlowIdDecision` | `0x4BEE0` |
| `RTK_RG_G3_FLOW_SET.constprop.0` | `0x830A0` |
| `_rtk_fc_extraInfo_setting` | `0xCE10` |
| `_rtk_fc_g3L3Policer_set` | `0x4ABE0` |
| `_rtk_fc_l3Meter_set` / `_get` / `Bucket_set` / `RateMode_set` | `0x4D0C0` / `0x4D180` / `0x4D280` / `0x4D420` |
| `rtk_8277c_l3_flow_policer_rate_set` | `0xC6600`（`/500`） |

### REA 证据 ID

| 用途 | evidence_id |
|---|---|
| ca-rtk `dal_rtl8277c_rate_shareMeter_set` | `ev_2ef79dd4eff14867145195cc9002e54cb66ed7d9f4afb3ef0756a36ec82b76a4` |
| ca-rtk `_dal_rtl8277c_rate_glb_db_dump`（22 项） | `ev_bf4520f36029a12c01d289c6323ed91cfd6484607b4ffeeed4c62a01b35350d9` |
| fc_8277c `rtk_fc_hostPoliceControl_set` | `ev_bc959bae93c75e6f283a80bb62b79ecfbc530212a43354bf65e8f25777dc334b` |
| fc_8277c `hostPoliceControl_set` callees（含 `rtk_rate_shareMeter_set` 调用） | `ev_66b25c95e9b35e100845921918053bfa8c0dad9f1198041b563e28e1d46adb41` |
| fc_8277c `hostPoliceControl_set` strings | `ev_01c699c4ab7a5000775c2636f7721b153a441c88a578460a8c8156f9ab4792f3` / `ev_e3675756828230aab59994317b8ca2934776a8f2e5faa1050b86fc1f6ee0b1bc` |
