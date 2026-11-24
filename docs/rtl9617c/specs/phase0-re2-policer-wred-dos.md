# Phase 0 RE-2 — L3TE Policer / Host Policing / WRED / L2-L3 DoS / 流镜像 全局寄存器规格书

状态：**Phase 0 只读测绘**。本文只读 `ca-ne.ko` / `fc_mgr.ko` / `default_scfg.txt` / 开源 `rtl9617c` 对照树，
未修改 `pt1500-refactor-build`、`pt1500-immortalwrt-build` 中任何文件。

## 0. 语料、工具与标注约定

| 项 | 值 |
|---|---|
| `ca-ne.ko` | `scratch/stock-probe/lib/modules/5.10.70/extra/ca-ne.ko`，aarch64，**not stripped**，BuildID `89eddd74…`，sha256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e` |
| `fc_mgr.ko` | `…/rtl86900/FleetConntrackDriver/fc_mgr.ko`，aarch64，not stripped，BuildID `7e3dd80a…` |
| `default_scfg.txt` | `/opt/ubiwork/cfg/default_scfg.txt`，Cortina **TAURUS**（=CA-8277C）默认启动配置，823 行 |
| 开源对照 | `pt1500-refactor-build/target/linux/rtl9617c/files-6.18/.../rtl9617c_regs.h`、`fe/fe_hw.c`、`fe/fe_hw.h`、`ni/ni_qos.c` |

取证方式：
- 符号/节内地址：`aarch64-linux-gnu-nm -n`；反汇编：`aarch64-linux-gnu-objdump -dr`（保留重定位，用于确认基址符号与调用目标）。
- 语义确认：REA（Ghidra 12.1.4，`/mnt/c/rea/ca-ne.ko`，image_base `0x100000`）`procedure_pseudo_code` / `xrefs`。
- **地址换算**：本文 `ca-ne.ko` 内一律给出 **nm/objdump 节内地址**；REA 地址 = 节内地址 + `0x100040`
  （例：`aal_l3pe_mirror_set` 节内 `0x6b010` → REA `0x16b050`）。
- `fc_mgr.ko` 内函数地址为 fc_mgr 节内地址（模块不同，不可与 ca-ne 混算）。

标注级别：**[观测]** = 反汇编/伪代码直接可见；**[推导]** = 由多处观测逻辑合并；**[UNKNOWN]** = 未能确认。

---

## 1. 公共前提：NE 寄存器空间与间接表访问协议

所有 `ca-ne.ko` 的 `aal_l3te_*` / `aal_l3pe_*` / `aal_dos_*` 寄存器访问都基于**同一个全局指针**：

```
extern void __iomem *g_ne_reg_iobase;      // ca-ne.ko .bss
```

证据：`__l3_te_policer_flow_profile_access.constprop.0` @ `0x73e90`，
`adrp x12, …` + `ldr x5,[x12]` 两条指令的重定位均为
`R_AARCH64_ADR_PREL_PG_HI21 g_ne_reg_iobase` / `R_AARCH64_LDST64_ABS_LO12_NC g_ne_reg_iobase`。
即下文所有 `0x9xxx` / `0x3xxx` **都是 NE 寄存器空间内的字节偏移**，不是独立 IP 块基址。

### 1.1 间接表访问协议（L3TE 全族一致） **[观测]**

以 `__l3_te_policer_flow_profile_access.constprop.0` @ `0x73e90` 为范式（4 个寄存器一组）：

```
ACCESS (最低地址)  : bit31 = START/BUSY（写 1 启动；读回轮询到 0 表示完成）
                     bit30 = 1 写 / 0 读
                     bit[idx_w-1:0] = 表项索引
DATA2              : ACCESS + 0x04
DATA1              : ACCESS + 0x08
DATA0              : ACCESS + 0x0c   ← 最高地址
```

- 忙等上限：`mov w1, #0x1000` → **4096 次**，超时返回 `5`（`aal_l3_te_policer_flow_profile_access` 内 `mov w0,#0x5`）。
- 每个数据字前后都有 `dmb oshst` / `dmb oshld`。
- 写序列（`w11==1`）：先写 DATA0 → DATA1 → DATA2，最后写 ACCESS = `BIT31|BIT30<<30|idx`。
- 读序列：先写 ACCESS = `BIT31|idx`，轮询，再依次读 DATA0/DATA1/DATA2。

该「DATA0 在最高地址、往下递减」的排布与开源驱动注释一致：
`rtl9617c_regs.h` 第 18 行 `/* ILPB words sit in descending addresses: DATA0 at 0x11f8 .. DATA4 at 0x11e8 */`；
访问位定义同文件第 11–14 行 `RTL_NI_INDIRECT_BUSY BIT(31)` / `RTL_NI_INDIRECT_WRITE BIT(30)` / `RTL_NI_INDIRECT_TIMEOUT_US 100000`。

### 1.2 L3TE 寄存器块布局（本文涉及部分） **[推导]**

| 偏移 | 用途 | 证据 |
|---|---|---|
| `0x9004` | `TE_GLB_CTRL`（开源名 `RTL_TE_GLB_CTRL`）；**bit25** = L3TE 组级 policer 表深度选择 | 见 §2.3 |
| `0x9080 + 4*n` (n=0..3) | `L3TE PIE/WRED 每端口使能` | §4.3 |
| `0x9090 + 4*i` | policer `pkt_type` cfg（15 项） | `aal_l3_te_policer_pkt_type_cfg_set` @ `0x6f460` |
| `0x90cc + 4*i` | policer `port` cfg | `aal_l3_te_policer_port_cfg_set` @ `0x6f590` |
| `0x9108 + 4*(flow>>5)` | policer **flow** cfg（8 个 32-flow bank 寄存器） | `aal_l3_te_policer_flow_cfg_set` @ `0x6f6c0` |
| `0x9128/2c/30/34` | **POL flow 256 槽 profile** 间接访问 | §2.1 |
| `0x9144 + …` | policer `agr_flow`(POL2/组) cfg | `aal_l3_te_policer_agr_flow_cfg_set` @ `0x6f920` |
| `0x9164/68/6c/70` | **POL2/组 64 槽 profile** 间接访问 | §2.1 |
| `0x918c/90/94/98` | **POL3 (flow3) 64 槽 profile** 间接访问 | §2.1 |
| `0x938c` … `0x93ac` | **WRED profile**（32 槽 × 8 word） | §4.1 |
| `0x93b0` … `0x93b8` | **WRED profile select**（64 队列 × 2 word） | §4.2 |
| `0x9408` | `L3TE flow control` | `aal_l3_te_flow_control_set` @ `0x6f000` |
| `0x32ec … 0x330c` | **L3 DoS attack 全局配置**（9 个连续寄存器） | §5.1 |
| `0x3310` | L3 DoS flood 计数 | §5.2 |
| `0x3540` / `0x3544` | **L3FE 流镜像控制 / 镜像长度** | §6 |

---

## 2. L3TE Policer（流级 256 槽 + 组级 64 槽）

### 2.1 三张 profile 表的间接访问寄存器 **[观测]**

三个 access 函数的立即数直接给出基址与索引宽度（`ca-ne.ko`，均为 `.constprop.0` 内部函数）：

| 表 | 索引宽 | ACCESS | DATA2 | DATA1 | DATA0 | access 函数 |
|---|---|---|---|---|---|---|
| **POL flow（流级 256）** | **8 bit**（`bfxil w0,w1,#0,#8`） | `0x9128` | `0x912c` | `0x9130` | `0x9134` | `__l3_te_policer_flow_profile_access.constprop.0` @ **`0x73e90`** |
| **POL2 / 组级（64）** | **6 bit**（`bfxil w0,w1,#0,#6`） | `0x9164` | `0x9168` | `0x916c` | `0x9170` | `__l3_te_policer_flow_grp_profile_access.constprop.0` @ **`0x73600`** |
| **POL3 / flow3（64）** | **6 bit** | `0x918c` | `0x9190` | `0x9194` | `0x9198` | `__l3_te_policer_flow3_profile_access.constprop.0` @ **`0x73af0`** |

对上层的公开 API（`ca-ne.ko`，全部经 `__ksymtab` 导出，供 `fc_mgr.ko` 使用）：

```
0x740b0  aal_l3_te_policer_flow_profile_set(u32 unit, u32 idx, u32 flags, void *prof)   // 0..255
0x75de0  aal_l3_te_policer_flow_profile_get
0x73940  aal_l3_te_policer_agr_flow_profile_set(u32 unit, u32 idx, u32 flags, void*)   // 0..63
0x73820  aal_l3_te_policer_agr_flow_profile_get
0x73d10  aal_l3_te_policer_flow3_profile_set(u32 unit, u32 idx, u32 flags, void*)      // 0..63
0x75b50  aal_l3_te_policer_flow3_profile_get
0x6f6c0  aal_l3_te_policer_flow_cfg_set(u32 unit, u32 idx, u32 flags, void *cfg)
0x710a0  aal_l3_te_policer_flow_cfg_get
0x6f920  aal_l3_te_policer_agr_flow_cfg_set / 0x6fb00 get
0x6f7f0  aal_l3_te_policer_flow3_cfg_set  / 0x71160 get
0x753b0  aal_l3_te_pm_policer_flow_get        (性能计数读出)
0x70ae0  _aal_l3_te_policer_flow_counter_clear (计数器清零，导出名带前导下划线)
```

`aal_l3_te_policer_flow_profile_set` 的入口守卫为
`cmp w1,#0xff; ccmp x3,#0x0,#0x4,ls; b.eq → return 2`，即 **idx 0..255 且 prof 非 NULL**（`0x740b4..0x740d4`）[观测]。

### 2.2 profile 12 字节结构 → 3 个 data word 的位域 **[观测]**

`aal_l3_te_policer_flow_profile_set` @ `0x740b0` 的打包逻辑（`flags` 每位使能一个 u16 字段）：

| 结构体字段 | 宽度 | 落点 | 打包指令 |
|---|---|---|---|
| `u16 [0]` | 10 bit | `DATA0[9:0]` | `bfxil w1,w0,#0,#10` |
| `u16 [2]` | 16 bit | `DATA0[25:10]` | `bfi w0,w1,#10,#16` |
| `u16 [4]` | 12 bit | `DATA0[31:26]`（低 6）+ `DATA1[5:0]`（高 6） | `bfi w0,w1,#26,#6` + `bfxil w0,w2,#0,#6` |
| `u16 [6]` | 10 bit | `DATA1[15:6]` | `bfi w1,w0,#6,#10` |
| `u16 [8]` | 16 bit | `DATA1[31:16]` | `bfi w0,w1,#16,#16` |
| `u16 [10]` | 12 bit | `DATA2[11:0]` | `bfxil w0,w1,#0,#12` |

`flags` 位 → 字段：bit0→`[0]`、bit1→`[2]`、bit2→`[4]`、bit3→`[6]`、bit4→`[8]`、bit5→`[10]`。
反向解包见 `aal_l3_te_policer_agr_flow_profile_get` @ `0x73820`（`ubfx #0,#10` / `#10,#16` /
`ubfiz #6,#6 | lsr #26` / `#6,#10` / `lsr #16` / `#0,#12`）——三张表**共用同一 12 字节 profile 结构** [观测]。

字段合法值检查：`[0]`、`[6]` 上限 `0x3ff`；`[4]`、`[10]` 必须落在 `1..0xfff`（`sub #1; cmp #0xffe; b.ls`），
即 **0 是非法的 CBS/PBS**（`0x74174..0x7418c`、`0x741b4..0x741c4`）[观测]。

### 2.3 CIR / PIR / CBS / PBS 编码（决定单位与时基） **[观测]**

调用方在 `fc_mgr.ko`：`rtk_8277c_l3_flow_policer_rate_set` @ **`0xc6940`**（3 参数 `flow_id, cir_kbps, pir_kbps`）：

```
w5 = 0x10624dd3 ; umull x6,w1,w5 ; x6 >>= 37      →  x6 = cir_kbps / 500
umull x5,w2,w5 ; x5 >>= 37                        →  x5 = pir_kbps / 500
strh w6,[sp,#62]   ; profile[1] = CIR/500   (→ DATA0[25:10], 16 bit)
strh w5,[sp,#68]   ; profile[4] = PIR/500   (→ DATA1[31:16], 16 bit)
msub w6, w6, w8(=500), w7(=cir)  → cir % 500  → profile[0] = CIR%500 (→ DATA0[9:0], 10 bit)
msub w5, w5, w8(=500), w2(=pir)  → pir % 500  → profile[3] = PIR%500 (→ DATA1[15:6], 10 bit)
flags = 0x1b (bit0,1,3,4)  → 只写这四个字段
```

**结论（可直接落地）**：
- 硬件速率字段 = **kbps**，物理上拆成 `{hi(16b), lo(10b)}`，重组关系为
  **`rate_kbps = 500 * hi + lo`**（`hi = rate/500`，`lo = rate%500`）。
- 有效范围：`hi ≤ 0xffff` → 上限约 **32 767 999 kbps**；`lo` 只需 0..499，10 bit 足够。
- **时基/单位 = 千比特每秒（kbps），与 `CFG_ID_PON_SHAPER_DEFAULT_VALUE = 8410000 ##Unit kbps` 同族口径**（`default_scfg.txt:125`）。
- **CBS / PBS 编码**：`rtk_8277c_l3_flow_policer_burstSize_set` @ **`0xc6ce0`**
  （3 参数 `flow_id, cbs, pbs`）写 `flags = 0x24`（bit2、bit5）：
  `profile[2] = cbs`（`strh w1,[sp,#64]`）、`profile[5] = pbs`（`strh w2,[sp,#70]`），
  两者均为 **12 bit、取值 1..0xfff**。寄存器不存储单位换算，即 **burst 单位由软件直接给出**；
  `rtk_8277c_l3_flow_policer_burstSize_get` @ `0xc6e30` 原样回读 → 单位 = 调用方传入量（OEM 传字节，**[推导]**）。
- **rate mode**：`rtk_8277c_l3_flow_policer_rateMode_set` @ `0xc7020`，`flags = 4`（bit2）→ **cfg 寄存器 bit4**，
  `mode==1` 时置 1，否则保持 0 → 单一 1 bit「计量模式」开关（0/1，语义 [UNKNOWN]，见 §8）。

**禁用/无限制哨兵值**（`rtk_8277c_l3_flow_policer_mode_set` @ `0xc646c..0xc6494`，disable 分支）：
`profile[0]=0x3ff, profile[1]=0xffff, profile[3]=0x3ff, profile[4]=0xffff`，`flags=0x1b`。
即 **CIR=PIR=最大速率 ⇒ 不限速**；`profile[2]/[5]` 不动 [观测]。

### 2.4 POL flow cfg 寄存器（每 32 个 flow 共享 1 个寄存器） **[观测]**

`aal_l3_te_policer_flow_cfg_set` @ `0x6f6c0` 的地址计算：

```
w5 = 0x3d0c2442 ; w1 = w5 + (idx >> 5) ; x1 = (w1 & 0x3fff) << 2 ; 访问 base + x1
⇒ 偏移 = 0x9108 + (idx >> 5) * 4     （idx = 0..255 → 8 个寄存器 0x9108/0c/10/14/18/1c/20/24）
```

16 bit 载荷位域（`bfxil`/`bfi` 立即数）：

| 位 | 宽 | flags 位 | 说明 |
|---|---|---|---|
| `[2:0]` | 3 | bit0 | **type / 使能**：`0` = 关，`2` = 开（§2.5） |
| `[3]` | 1 | bit1 | [UNKNOWN] |
| `[4]` | 1 | bit2 | **rate mode**（`rtk_8277c_l3_flow_policer_rateMode_set`） |
| `[5]` | 1 | bit3 | [UNKNOWN] |
| `[10:6]` | 5 | bit4 | [UNKNOWN]（5 bit，疑似颜色/优先级或 group id 低位） |
| `[11]` | 1 | bit5 | [UNKNOWN] |
| `[12]` | 1 | bit6 | [UNKNOWN] |
| `[13]` | 1 | bit7 | [UNKNOWN] |
| `[15:14]` | 2 | bit8 | [UNKNOWN] |

**注意（重要）**：`aal_l3_te_policer_flow3_cfg_set` @ `0x6f7f0` 使用**完全相同的基常量 `0x3d0c2442` 与 `(idx>>5)`**，
`aal_l3_te_policer_agr_flow_cfg_set` @ `0x6f920` 用 `0x3d0c2451`（= `0x9144 + idx*4`，64 项），
`pkt_type_cfg_set` 用 `0x3d0c2424`（= `0x9090 + idx*4`）、`port_cfg_set` 用 `0x3d0c2433`（= `0x90cc + idx*4`）。
⇒ **POL 与 POL3 的 cfg 共用 0x9108 bank 寄存器，只有 profile 表不同**；bank 语义 [推导]。

### 2.5 `POL_EN` vs `POL_VLD` —— L2TE 与 L3TE 的区分 **[观测/推导]**

- **L2TE（L2 流）**：`POL_VLD/POL_EN/POL_ID` 是 L2 flow **action word 的位域**，不是独立寄存器。
  定义在开源对照 `fe/fe_hw.c` 的 `rtl_fe_action_fields[]`（第 65–67 行）：

  | 字段 | bit 起点 | 宽 |
  |---|---|---|
  | `RTL_FE_MRR_VLD` | 0 | 1 |
  | `RTL_FE_MRR_EN` | 1 | 1 |
  | `RTL_FE_POL_VLD` | **165** | 1 |
  | `RTL_FE_POL_EN` | **166** | 1 |
  | `RTL_FE_POL_ID` | **167** | **8**（→ 256 槽） |
  | `RTL_FE_POL2_ID_EN` | 175 | 1 |
  | `RTL_FE_POL2_ID` | 176 | 6（→ 64 组） |
  | `RTL_FE_POL3_ID_EN` | 182 | 1 |
  | `RTL_FE_POL3_ID` | 183 | 6（→ 64 组） |

  ⇒ **`_VLD` = 该 action 是否携带 policer 配置（有效位）；`_EN` = 是否真正执行计量/着色（执行位）**。
  两者分离是有意的：`VLD=1, EN=0` 表示「已下发但不生效」。
- **L3TE（L3 流）**：同样的三元组出现在 **header_a（内部包头）** 而非 action 表。
  `ca-ne.ko` 字符串证据（`strings ca-ne.ko`）：

  ```
  header_a: mcgid=%d drop_code=%d rx_pkt_type=%d no_drop=%d mirror=%d mark=%d
            pol_en=%d pol_id=%d pol_grp_id=%d deep_q=%d cpu_flg=%d cos=%d
            ldpid=%d lspid=%d pkt_size=%d fe_bypass=%d pol_grp_id=%d
  ```
  ⇒ L3TE 链路携带 **`pol_en`(1) + `pol_id`(8, 256 槽) + `pol_grp_id`(组级)**，
  与 POL / POL2 / POL3 三张表一一对应；`pol_en` 对应 L2 的 `POL_EN`（执行位）。
  `POL_VLD` 在 L3 侧无独立字段 —— **L3 的「有效」由 profile 哨兵值（§2.3 全 1 = 不限速）隐式表达** [推导]。
- `rtk_8277c_l3_flow_policer_mode_set` @ `0xc6380` 的 enable/disable 只动 **cfg `[2:0]`**
  （enable 写 `2`、disable 写 `0`），并配合 §2.3 的 profile 哨兵值 —— 即
  **「开关」在 cfg，「限速值」在 profile**，两部分必须成对下发 [观测]。

### 2.6 组级 64 槽的深度选择（bit25） **[观测]**

`aal_l3_te_policer_agr_flow_profile_get` @ `0x73820` 读 `base+0x9004` 后：

```
if (idx > 7  && (reg & BIT25) == 0) return 2;   // 非法
if (idx > 63 && (reg & BIT25) != 0) return 2;   // 非法
⇒ 0x9004(BIT25)=0 → 组表仅 8 项；=1 → 64 项
```

`0x9004` 的开源名即 `RTL_TE_GLB_CTRL`（`rtl9617c_regs.h:263`），但该位在开源头里**未定义**
（开源只定义 `RTL_TE_GLB_TAILDROP_EN BIT(2)`）⇒ 这是本次新增的规格。

### 2.7 `rtk_8277c_l3_flow_policer*` 调用序列 **[观测]**

`fc_mgr.ko` 中导出 API 与地址（节内）：

```
0xc6380 mode_set(flow_id, enable)        0xc66f0 mode_get
0xc6940 rate_set(flow_id, cir_kbps, pir_kbps)   0xc6ab0 rate_get
0xc6ce0 burstSize_set(flow_id, cbs, pbs) 0xc6e30 burstSize_get
0xc7020 rateMode_set(flow_id, mode)      0xc7170 rateMode_get
0xc7300/0xc7670  policer2_mode_set/get
0xc78c0/0xc7a30  policer2_rate_set/get          ← POL2（组级，环回/聚合）
0xc7c50/0xc7da0  policer2_burstSize_set/get
0xc7f90/0xc80e0  policer2_rateMode_set/get
0xc8270/0xc85e0  policer3_mode_set/get          ← POL3
0xc8830/0xc89a0  policer3_rate_set/get
0xc8ba0/0xc8cf0  policer3_burstSize_set/get
0xc8ee0/0xc9030  policer3_rateMode_set/get
0xc5f00/0xc6240  rtk_8277c_l3_policer_ifg_config_set/get   ← IFG 补偿
0xcbb50          rtk_8277c_policer_init
```

**使能一个流的推荐序列**（由 `mode_set` 反推的 OEM 实践 [推导]）：

```
1) rate_set()      → 写 profile 的 CIR/PIR（flags 0x1b）
2) burstSize_set() → 写 profile 的 CBS/PBS（flags 0x24）
3) rateMode_set()  → 写 cfg bit4
4) mode_set(id,1)  → 先读 cfg+profile，扫描同 bank 内其它 31 个 flow 的 profile 是否为「空闲哨兵」
                     （profile[0]==0x3ff && profile[3]==0x3ff && (profile[1]&profile[4])==0xffff
                       && cfg[2]==0），确认后才写 cfg[2:0]=2
```

`mode_set` disable 分支（`0xc63b4..0xc6464`）逐一遍历 `flow_id & ~31 … +32`，
对非目标 flow 调 `flow_cfg_get`/`flow_profile_get` 做空闲检查；若同 bank 有其它在用流则**跳过 cfg 写入**，
只把 profile 置哨兵值 —— 这就是「32 流共享 cfg 寄存器」带来的**槽位分配约束** [观测]。

---

## 3. Host Policing（`rtk_fc_hostPoliceControl_set`）

### 3.1 入口与容量 **[观测]**

`fc_mgr.ko`：

```
0xbe640  rtk_fc_hostPoliceControl_set
0xb4620  rtk_fc_hostPoliceControl_get
0xbe1f0  _rtk_hostPoliceControl_clear          ← set 内部第一步就调用它
0xb7380  rtk_fc_hostPoliceMib_get
0xb7290  rtk_fc_hostPoliceMib_clear
0x0d800  rtk_fc_rt_rate_shareMeter_mapping_hw_get
```

- 入口 `cmp w20, #0x5f` → **host policer 索引 0..95（共 96 个）**；`cmp w2, #0x60` 佐证 96 上限。
- set 的第一动作：`bl _rtk_hostPoliceControl_clear`（`0xbe6f0`），随后重新下发 —— 即
  **「全清 → 重编程」语义，不是增量写**。这对上层是重要的原子性假设。

### 3.2 与共享限速表（share meter）的绑定 **[观测]**

`rtk_fc_hostPoliceControl_set` 内对控制结构的**两个速率**分别调用
`rtk_fc_rt_rate_shareMeter_mapping_hw_get`（`0xbe7f4` 用 `[x19,#24]`，`0xbe850` 用 `[x19,#20]`）：

```
cmp w1, #0x1 / cmp w1, #0x4      ; 返回的“单位”编码（1 与 4 两类）
cmp w24, #0x7f                   ; 索引上限 127 → 共享表 128 项
```

⇒ **Host Policer 不直接写 CIR/PIR，而是把速率映射到一张 7 bit（0..127）共享 rate-meter 表**。
`[x19,#20]` 与 `[x19,#24]` 两个字段 = **双向（ingress / egress）各自的速率**，
共用同一 128 项池 ⇒ **双向限速的槽位约束：每条 host policy 最多占用 2 个 share-meter 条目，
全系统可用 128 项**（[推导]：两项映射发生在同一函数、同一 7 bit 上限）。

### 3.3 硬件字节/包计数 **[观测 + UNKNOWN]**

- 读出：`rtk_fc_hostPoliceMib_get` @ `0xb7380`；清零：`rtk_fc_hostPoliceMib_clear` @ `0xb7290`
  （两者相邻，`get` 后立即 `clear` 是 OEM 惯例）。
- **具体的 MIB 寄存器偏移、字节/包两个计数器的位宽与读出-清零先后顺序：[UNKNOWN]**
  —— 本轮未反汇编 `0xb7380`/`0xb7290`（时间预算），W6 需补一次 `procedure_pseudo_code`
  （REA 地址 `0xb7380+0x100040`，注意 fc_mgr 的 image_base 需先 `binary_session` 确认）。

### 3.4 MAC LUT / SMAC / DMAC 绑定 **[UNKNOWN]**

任务书要求的「MAC LUT / SMAC / DMAC 如何与 flow policer 绑定」**未能在 `fc_mgr.ko` 中标定**：
`rtk_fc_hostPoliceControl_set` 只处理速率→share-meter 映射与 clear/重编程，
未见对 MAC 表项的写操作（该函数内无 `aal_*l2*` / `aal_ni_mac*` 调用）。
⇒ 绑定逻辑应在更上层（`rtk_fc_aclFilterAndQos_add` @ `0xb5070` 等 ACL 路径）或另一模块。
**这是本文最大的功能缺口**，见 §8。

---

## 4. WRED

### 4.1 WRED profile 表（32 槽 × 8 word） **[观测]**

`__l3_te_wred_profile_access.constprop.0` @ **`0x72d30`**：

```
ACCESS = 0x938c   bit31 = START/BUSY, bit30 = 写, bits[4:0] = 索引（0..31，共 32 个 profile）
DATA0 = 0x93ac, DATA1 = 0x93a8, DATA2 = 0x93a4, DATA3 = 0x93a0,
DATA4 = 0x939c, DATA5 = 0x9398, DATA6 = 0x9394, DATA7 = 0x9390   ← 8 个数据字，仍是降序
```

入口守卫：`cmp w9, #0xfff`（重试上限 4096）、`cmp w17, #0x1`（读写选择）、超时返回 `5`。
上层 API：`aal_l3_te_wred_profile_set` @ **`0x73070`**（REA `0x1730b0`），
`aal_l3_te_wred_profile_get` @ `0x75760`。

### 4.2 profile 载荷位域（32 × 6 bit + 2 × 4 bit） **[观测]**

`aal_l3_te_wred_profile_set(unit, idx, flags, u32 *prof)` 伪代码（REA `0x1730b0`）给出打包：

```
word0 = prof[0] | prof[1]<<6 | prof[2]<<12 | prof[3]<<18 | prof[4]<<24 | prof[5]<<30
word1 = (prof[5]>>2 & 0xf) | prof[6]<<4 | prof[7]<<10 | prof[8]<<16 | prof[9]<<22 | prof[10]<<28
word2 = (prof[10]>>4 & 3) | prof[11]<<2 | prof[12]<<8 | prof[13]<<14 | prof[14]<<20 | prof[15]<<26
word3..5 = prof[0x10..0x1f] 同构（第二组 16 个 6 bit）
word6 = (prof[0x20] & 0xf) | ((prof[0x20] >> 4 & 0xf) << 4)      ← 2 个 4 bit
word7 = 未使用（伪代码中 local_10[1] 保持 0）
flags: bit0 → word0..2；bit1 → word3..5；bit2/bit3 → word6 的低/高 nibble
```

⇒ **一个 WRED profile = 32 个 6 bit 子字段（两组各 16）+ 2 个 4 bit 子字段**。
6 bit 无法容纳 14 bit 阈值 ⇒ 这 32 个子字段是**索引/权重**（指向 §4.5 的 L3TE 阈值 profile 表），
不是阈值本身 [推导]。逐字段的物理含义（min/max/drop-prob/color）**[UNKNOWN]**。

### 4.3 队列绑定：WRED profile select（64 队列） **[观测]**

`__l3_te_wred_profile_sel_access.constprop.0` @ **`0x729e0`**：

```
ACCESS = 0x93b0   bit31 = START/BUSY, bit30 = 写, bits[5:0] = 队列索引（0..63）
DATA0 = 0x93b8, DATA1 = 0x93b4
```

上层：`aal_l3_te_wred_profile_sel_set` @ `0x72bc0`，`_get` @ `0x75680`。
⇒ **绑定方法**：先 `profile_set()` 配好 32 个 profile 之一，再
`profile_sel_set(queue_id /*0..63*/, profile_idx /*0..31*/)` 把队列指到 profile。
64 队列 = L3TE egress VOQ 数（与 `CFG_ID_L3QM_PE0_1_VOQ_PER_PORT = 8`、8 个端口一致，
`default_scfg.txt:158`）[推导]。

### 4.4 每端口 PIE/WRED 使能 **[观测]**

`aal_l3_te_glb_pie_wred_port_enable_set` @ **`0x6ef90`**：

```
port = (w1 & 0xff); if (port > 3) return 2;
addr = base + ((0xf4309080 + port*4) & 0xfffc)  →  偏移 0x9080 + 4*port  (port 0..3)
写整个 32 bit = 调用方给的 value（不是读改写、不是单 bit）
```

`_get` 在 `0x70cd0`。**注意**：这里的「port」只有 4 个（0..3），与 8 个 L3TE 端口不等，
推测是 4 个 PIE/WRED 引擎实例而非物理端口 [UNKNOWN]。

### 4.5 推荐参数区间（来自 OEM 默认配置） **[观测]**

`default_scfg.txt` `[L3TE CONFIGS]`（第 557–681 行）给出厂默认，可作为**推荐区间基准**：

| 项 | 默认值 | 备注 |
|---|---|---|
| `CFG_ID_L3TE_PROFILE_THRSH_EQn_TH0` | EQ0/EQ1 = `4096`；EQ2..EQ7 = `12` | 8 条 egress queue 的低阈值 |
| `CFG_ID_L3TE_PROFILE_THRSH_EQn_TH1` | 全 `12` | 高阈值 |
| `CFG_ID_L3TE_PORT_THRSH_PROFILE_0/1_LTH/HTH` | `12 / 120` | 「紧」档 |
| `CFG_ID_L3TE_PORT_THRSH_PROFILE_2/3_LTH/HTH` | `4096 / 8192` | 「松」档 |
| `CFG_ID_L3TE_VOQ_THRSH_PROFILE_n_THL/THH/PRVT` | 0: `300/2048/3`；1: `8/14/12`；2,3: `4096/6114/100`；4: `0x3FFF/0x3FFF/1500`；5: `0x3FFF/0x3FFF/71`；6,7 全 `0x3FFF` | 8 个 VOQ 阈值 profile |
| `CFG_ID_L3TE_WRED_MARK_IDX` / `UNMARK_IDX` | 均为 `8` | WRED 着色后的 mark/unmark 索引 |
| `CFG_ID_L3TE_CB_PORT_GRPTHRSH_PROFILE_n_LTH/HTH` | 全 `0x3FFF` | 组阈值 = 关 |

**判读**：`0x3FFF` 是 14 bit 饱和值 = **功能关闭**；`12` 是颗粒度下限（约 1 个 buffer 单元）。
⇒ 落地建议：**VOQ 阈值沿用 0/1 两档「小队列」+ 2/3 两档「大队列」+ 4..7 关闭**，
WRED 只在 `PROFILE_THRSH_EQ0/EQ1`（TH0=4096）上启用，其余保持 `12`。

---

## 5. L2 / L3 DoS

### 5.1 L3 DoS attack 全局配置块（9 个寄存器） **[观测]**

`aal_dos_atk_set` @ **`0x918c0`**（REA `0x191900`），伪代码结构：

```
ca_spin_lock(__aal_l3_dos_lock);
读 0x32ec, 0x32f4, 0x32fc, 0x3304, 0x3308, 0x330c（+ 0x32f0/0x32f8/0x3300 作为高 32 bit 拼接）
for (每个 64 bit enable mask 位) if (mask & BIT(n)) 改写对应字段
dmb oshst
按 0x32ec → 0x32f0 → 0x32f4 → 0x32f8 → 0x32fc → 0x3300 → 0x3304 → 0x3308 → 0x330c
   依次写回（每次写前 dmb oshst）
ca_spin_unlock(__aal_l3_dos_lock);
```

- **寄存器块 = NE 偏移 `0x32ec, 0x32f0, 0x32f4, 0x32f8, 0x32fc, 0x3300, 0x3304, 0x3308, 0x330c`**
  （9 个连续 32 bit，跨度 `0x32ec..0x330c`）。
- 接口语义：`aal_dos_atk_set(unit, u64 field_mask, u32 *cfg)` —— **不是按 attack type 分派，
  而是「按字段使能掩码」的 RMW**；掩码共 ~38 个有效位（`BIT(0)` 到 `param_2 >> 32 & 0x10`）。
- **写顺序固定为地址升序，且每写一个寄存器前 `dmb oshst`** —— 这是可直接照抄的序列约束。
- 每个字段宽 1/5/9/13/16 bit 不等（例：`0x32ec[8:0]` 9 bit、`[24:9]` 16 bit、`[25]` 1 bit；
  `0x32f4[12:0]` 13 bit、`[22:12]` 9 bit…），逐字段含义 **[UNKNOWN]**（见 §8）。

### 5.2 flood 计数 **[观测]**

`aal_dos_atk_flood_cnt_set` @ **`0x920d0`**：`ca_spin_lock` → 访问 **NE `0x3310`** → `ca_spin_unlock`；
`_get` @ `0x92170`。⇒ **flood 计数寄存器 = `0x3310`（单 32 bit）**，读写均在
`__aal_l3_dos_lock` 保护下。

### 5.3 trap / drop 事件控制 **[观测]**

```
0x921d0  aal_dos_atk_event_trap_set     0x92330  aal_dos_atk_event_trap_get
0x92390  aal_dos_atk_event_drop_set     0x924f0  aal_dos_atk_event_drop_get
0x92550  aal_dos_init
```

### 5.4 L2 DoS **[观测]**

```
0x925f0  aal_l2_dos_atk_set        0x929a0  aal_l2_dos_atk_get
0x92aa0  aal_l2_dos_atk_flood_cnt_set  0x92b40  ..._get
0x92bb0  aal_l2_dos_atk_event_trap_set 0x92c90  ..._get
0x92d00  aal_l2_dos_init
```

`__aal_l2_dos_lock` @ `.bss 0x7368`、`__aal_l3_dos_lock` @ `.bss 0x7360`（两把独立锁 ⇒ L2/L3 DoS 可并发）。
L2 DoS 的具体寄存器块**未标定 [UNKNOWN]**（本轮只确认函数边界）。

### 5.5 SYN / ICMP / UDP flood 触发位 **[UNKNOWN]**

任务书要求的「SYN/ICMP/UDP flood 触发寄存器位表」**本轮未完成**：
`aal_dos_atk_set` 是纯字段掩码式 RMW，**attack type 枚举不在此函数内**，
需要从 `__ksymtab` 导出的调用方（另一模块 / `aal_l2_dos_atk_set` 的分派）反推。
本节能给出的硬事实只有：**9 个寄存器地址 + 掩码宽度分布 + 写顺序 + 锁**。

---

## 6. 流镜像（W3 优先，已提前完成）

### 6.1 寄存器事实（REA 伪代码逐位确认） **[观测]**

**基址符号 = `g_ne_reg_iobase`**（REA 已确认 `readelf -r` 引用），`0x3540/0x3544` 是 NE 空间内偏移。

`aal_l3pe_mirror_set` @ `0x6b010`（REA `0x16b050`）：

```c
undefined8 aal_l3pe_mirror_set(uint param_1, uint param_2, uint param_3)
{
  undefined4 local_4;                       // ← 未初始化！
  DataMemoryBarrier(0,2);
  *(uint *)(g_ne_reg_iobase + 0x3540) =
        local_4 & 0xfe000000                // bits[31:25] = 垃圾
      | (param_1 & 0x3f) << 0x13            // bits[24:19] = param_1[5:0]
      | local_4 & 0xff00                    // bits[15:8]  = 垃圾
      | (param_2 & 7)    << 0x10            // bits[18:16] = param_2[2:0]
      | param_3 & 0xff;                     // bits[7:0]   = param_3[7:0]
  return 0;
}
```

`aal_l3pe_mirror_len_set` @ `0x6b060`（REA `0x16b0a0`）：

```c
undefined8 aal_l3pe_mirror_len_set(uint param_1)
{
  undefined4 local_4;                       // ← 未初始化！
  DataMemoryBarrier(0,2);
  *(uint *)(g_ne_reg_iobase + 0x3544) = local_4 & 0xfffff000 | param_1 & 0xfff;
  return 0;
}
```

**结论（可直接落地的 3 条硬事实）**：
1. `NE+0x3540`：`[24:19]` = arg0（6 bit）、`[18:16]` = arg1（3 bit）、`[7:0]` = arg2（8 bit）。
2. `NE+0x3544`：`[11:0]` = 镜像长度（12 bit，0..4095）。
3. **OEM 代码有未初始化变量缺陷**：`0x3540` 的 `[31:25]` 与 `[15:8]`、`0x3544` 的 `[31:12]`
   在写时取的是**栈上垃圾**。我们实现时**必须显式写 0**（并保留其它位），
   否则会随编译器/栈内容变化 —— 这是 W3 必须知道的第一条。

### 6.2 调用方：**不存在** **[观测]**

- `ca-ne.ko` 内 `aal_l3pe_mirror_set` / `aal_l3pe_mirror_len_set` **零调用者**：
  - `aarch64-linux-gnu-readelf -r ca-ne.ko` 全表 78 891 行，`grep -c mirror` = **0**
    （对比 `g_ne_reg_iobase` 出现 4030 次、`aal_l3pe_*` 引用 98 次）；
  - 不是 `__ksymtab` 导出符号（`grep ksymtab_aal_l3pe_mirror` = 0）⇒ 其它模块无法调用；
  - REA `xrefs(0x16b050)` 返回 **空列表**。
  ⇒ 这两个函数是 **OEM 遗留/未接线的孤儿 API**。**参数语义无法从调用方恢复**。
- 全 `stock-probe` 5 个 `.ko` 中只有 `ca-ne.ko` 含该字符串。

### 6.3 参数语义推导（**推断，非观测**）

可用约束：
- 6 bit 字段（`[24:19]`）：与本芯片全族的端口/LDPID 宽度一致 ——
  `RTL_L2FE_ARB_PDPID_MAP_LDPID GENMASK(5,0)`、`RTL_FE_KEY_LSPID {712,6}`、`RTL_FE_KEY_ORIG_LSPID {706,6}`，
  且 `rtk_fc_mirror_port_set` @ `0xb4ec0` 对镜像口做 `and w22, w19, #0x3f`（**6 bit 端口号**）。
  ⇒ **`[24:19]` 最可能是「镜像目的端口 / LDPID」（6 bit）**。
- 3 bit 字段（`[18:16]`）：与 `rtl_fc_mirror_port_set` 的 `w3 = 2/3`（引擎/方向选择）、
  `cmp w19,#0x10` 的分支同类 ⇒ **最可能是「镜像模式（ingress/egress/both/off）」**。
- 8 bit 字段（`[7:0]`）：`rtk_fc_mgr_mirror_config_set` @ `0x9ec0` 把 `(port & 0x3f) << 1 | (idx & 0xff)`
  存进 16 bit 全局 `fc_mgr_db + 0xa000 + 3992`；其中低 8 bit 是 `w0`（镜像实例/镜像组 id）。
  ⇒ **`[7:0]` 最可能是「镜像实例/组索引」或「镜像 VLAN 相关 ID」**（`CFG_ID_MIRROR_VLAN = 2018`，`default_scfg.txt:712`）。

**判定：语义为 [推导]，不是 [观测]。0x3540 的 `[7:0]` 与 `[18:16]` 仍有 ~30% 不确定性。**

### 6.4 L2FE 是否另有 mirror 配置 —— 是，且机制完全不同 **[观测]**

- **L2TE/L2FE 走「per-flow action 位 + ACL」**，没有 0x3540 那样的全局 mirror 寄存器：
  - `fe/fe_hw.c` 的 action 位域：`RTL_FE_MRR_VLD` = **bit 0**、`RTL_FE_MRR_EN` = **bit 1**（宽各 1）；
  - 因此每个 L2 flow 可独立选择「是否镜像 / 镜像是否生效」，与 `POL_VLD/POL_EN` 完全同构（§2.5）；
  - `fc_mgr.ko` 的 `rtk_fc_mirror_port_set` @ `0xb4ec0` 实现路径是：
    `aal_ni_hv_glb_internal_port_id_cfg_set()`（写 `RTL_NI_GLB_INTERNAL_PORT_ID_CFG 0xa1bc`，
    flag 位 `BIT3|BIT4` = 0x18，子字段 3）
    → `rtk_8277c_asic_mirrored_port_set()`（`0xc57c0`，把 6 bit 口存进全局 `l3fe_egress_mirrored_port`
      @ `fc_mgr_db+0x55b0`，再调 `rtk_8277c_asic_dmaLso_lspid_from_hdra()`）
    → `rtk_fc_mgr_mirror_config_set()`（存 16 bit 全局配置）
    → `_rtk_rg_aclAndCfReservedRuleAddSpecial(1, …)`（**加一条保留 ACL 规则**）
    → `rtk_fc_flow_flush()`；
  - 关闭时对称调用 `_rtk_rg_aclAndCfReservedRuleDelSpecial(1, NULL)`。
  ⇒ **L2 镜像 = 「ACL 保留规则 + 6 bit 目的口 + `l3fe_egress_mirrored_port` 全局」**，
    与 L3FE 的 `0x3540/0x3544` 是**两套独立机制**。

### 6.5 `RTL_FE_MRR_VLD/EN` 与全局寄存器的配合关系 **[推导]**

- `RTL_FE_MRR_VLD/EN`（L2 action bit0/bit1）是 **per-flow 选择器**；
- `NE+0x3540` 的 6 bit 目的口 + 3 bit 模式是 **全局目的地/模式**；
- 二者是「流级开关 × 全局目的地」的正交组合 —— 与 policer 的「flow cfg(bank) × profile(per-flow)」结构同构。
- `ca-ne.ko` 字符串 `"… ready signal for %12s -----%c-----> %s  (for L3FE egr mirror packet)"`
  与 `header_a` 的 `mirror=%d` 字段证明：**镜像判定在 L3FE 内由 header_a.mirror 位携带**，
  即 L3TE 侧还有一个「置 mirror 位」的动作来源（未标定，[UNKNOWN]）。
- `0x3544` 的 12 bit 长度 = **镜像报文截断长度**（copy-length），与目的口/模式解耦，
  可在不重下 `0x3540` 的情况下单独调整 [推导]。

### 6.6 关闭时的清零顺序 **[观测 + 建议]**

OEM **没有**实现关闭序列（函数只写非零值，且带垃圾位）。可用事实：
- `aat_`/`aal_l3pe_mirror_set` 与 `len_set` 之间**无顺序依赖**（两函数各自独立 `dmb oshst` 后单次 32 bit 写，无 read-modify-write 依赖）。
- 参考同族 `rtk_fc_mirror_port_set` 的关闭顺序（`0xb4f74` 附近）：
  **先摘 ACL 规则 / 清全局配置，再清目的口**，最后 `rtk_fc_flow_flush()`。

**建议给 W3 的实现顺序**（[推导]，非 OEM 观测）：

```
开启： 1. 写 NE+0x3544 = len            （先设长度，避免 0 长度窗口）
       2. 写 NE+0x3540 = (port<<19)|(mode<<16)|(idx)   （保留位显式 0）
关闭： 1. 写 NE+0x3540 = 0              （先停镜像）
       2. 写 NE+0x3544 = 0              （再清长度）
       3. 需要时再 flush 流表
```

---

## 7. 可直接落地的寄存器宏

```c
/* ---- NE 基址与间接访问协议 ---- */
#define NE_REG(off)                 (ne_base + (off))
#define L3TE_IND_BUSY               BIT(31)
#define L3TE_IND_WR                 BIT(30)
#define L3TE_IND_IDX(w)             ((u32)(w) & ((1u << (w)) - 1))

/* ---- L3TE policer：三张 profile 表（DATA0 在最高地址） ---- */
#define L3TE_POL_FLOW_ACC           0x9128u   /* idx[7:0], 256 槽 */
#define L3TE_POL_FLOW_D2            0x912cu
#define L3TE_POL_FLOW_D1            0x9130u
#define L3TE_POL_FLOW_D0            0x9134u

#define L3TE_POL_GRP_ACC            0x9164u   /* idx[5:0], 64 槽 (POL2) */
#define L3TE_POL_GRP_D2             0x9168u
#define L3TE_POL_GRP_D1             0x916cu
#define L3TE_POL_GRP_D0             0x9170u

#define L3TE_POL_FLOW3_ACC          0x918cu   /* idx[5:0], 64 槽 (POL3) */
#define L3TE_POL_FLOW3_D2           0x9190u
#define L3TE_POL_FLOW3_D1           0x9194u
#define L3TE_POL_FLOW3_D0           0x9198u

/* ---- profile 打包（12 B → 3 word） ---- */
#define POL_PROF_CIR_LO(v)          ((v) & 0x3ffu)          /* CIR%500 → D0[9:0]     */
#define POL_PROF_CIR_HI(v)          (((v)/500u) & 0xffffu)  /* CIR/500 → D0[25:10]   */
#define POL_PROF_CBS(v)             ((v) & 0xfffu)          /* CBS     → D0[31:26]|D1[5:0] */
#define POL_PROF_PIR_LO(v)          ((v) & 0x3ffu)          /* PIR%500 → D1[15:6]    */
#define POL_PROF_PIR_HI(v)          (((v)/500u) & 0xffffu)  /* PIR/500 → D1[31:16]   */
#define POL_PROF_PBS(v)             ((v) & 0xfffu)          /* PBS     → D2[11:0]    */

/* ---- L3TE policer flow cfg（每 32 流 1 个寄存器） ---- */
#define L3TE_POL_FLOW_CFG(id)       (0x9108u + (((id) >> 5) * 4u))
#define L3TE_POL_CFG_TYPE_MASK      GENMASK(2, 0)   /* 0=off, 2=on */
#define L3TE_POL_CFG_RATE_MODE      BIT(4)

/* ---- TE 全局 ---- */
#define L3TE_TE_GLB_CTRL            0x9004u
#define L3TE_TE_GLB_POL_GRP_64      BIT(25)         /* 0: 8 组, 1: 64 组 */

/* ---- WRED ---- */
#define L3TE_WRED_PROF_ACC          0x938cu         /* idx[4:0], 32 profiles */
#define L3TE_WRED_PROF_D0           0x93acu         /* .. D7 = 0x9390 */
#define L3TE_WRED_PROF_SEL_ACC      0x93b0u         /* idx[5:0], 64 queues   */
#define L3TE_WRED_PROF_SEL_D0       0x93b8u
#define L3TE_WRED_PROF_SEL_D1       0x93b4u
#define L3TE_PIE_WRED_PORT_EN(p)    (0x9080u + 4u * (p))   /* p = 0..3, 整字写 */

/* ---- L3 DoS ---- */
#define L3TE_DOS_CFG_BASE           0x32ecu
#define L3TE_DOS_CFG(n)             (0x32ecu + 4u * (n))    /* n = 0..8 */
#define L3TE_DOS_FLOOD_CNT          0x3310u

/* ---- L3FE 流镜像（W3） ---- */
#define L3FE_MIRROR_CTRL            0x3540u
#define L3FE_MIRROR_PORT(v)         (((u32)(v) & 0x3f) << 19)   /* [24:19] */
#define L3FE_MIRROR_MODE(v)         (((u32)(v) & 0x07) << 16)   /* [18:16] */
#define L3FE_MIRROR_ID(v)           ((u32)(v) & 0xff)           /* [7:0]   */
#define L3FE_MIRROR_LEN             0x3544u
#define L3FE_MIRROR_LEN_VAL(v)      ((u32)(v) & 0xfff)          /* [11:0]  */
#define L3FE_MIRROR_CTRL_RESERVED   0xfe00ff00u   /* MUST write 0 (OEM leaves garbage) */
```

---

## 8. UNKNOWN 清单

| # | 项 | 影响 | 下一步 |
|---|---|---|---|
| U1 | **L3FE 镜像 `0x3540` 三参数语义**（`[7:0]`、`[18:16]`、`[24:19]`） | W3 无法断言功能语义 | 零调用者；需设备实测或 Realtek SDK 头文件；本文只给位宽+位序（已足够做寄存器级实现） |
| U2 | `0x3544` 的 12 bit 长度单位（字节 / 64 B / 是否含 FCS） | 影响截断精度 | 实测或 SDK |
| U3 | policer cfg `[3] [5] [10:6] [11] [12] [13] [15:14]` 九个字段含义 | 只能用默认值 | 反 `rtk_8277c_l3_flow_policer*` 其它 setter（2/3 号）对照 |
| U4 | `rate mode`（cfg bit4）0/1 的确切计量口径（含 IFG？按字节还是按包？） | 限速误差 | `rtk_8277c_l3_policer_ifg_config_set` @ `0xc5f00` 与 `POL_CTRL0_IPG_MASK GENMASK(10,6)` 对照 |
| U5 | **Host Policing 的 MAC LUT / SMAC / DMAC 绑定** | 功能缺口 | 反 `rtk_fc_hostPoliceMib_get` @ `0xb7380` + `rtk_fc_aclFilterAndQos_add` @ `0xb5070` |
| U6 | Host Policing MIB 寄存器偏移、字节/包位宽、读出-清零顺序 | W6 阻塞 | 反 `0xb7380` / `0xb7290`（fc_mgr，REA 需先切 target） |
| U7 | Host Policing share-meter 表（128×7bit）的物理寄存器地址 | 无法直接编程 | 反 `rtk_fc_rt_rate_shareMeter_mapping_hw_get` @ `0xd800` |
| U8 | WRED profile 32×6bit 的逐字段含义（min/max/prob/color） | 只能照抄默认值 | 反 `fc_mgr` 侧 WRED setter |
| U9 | WRED 与 L3TE CB VOQ 阈值表（`0x95b0` 块）的耦合方式 | 阈值单位 | 对照 `RTL_TE_CB_VOQ_THRSH_PROFILE_*`（`rtl9617c_regs.h:284-296`） |
| U10 | **DoS 逐 attack type（SYN/ICMP/UDP flood）位表** | W6 阻塞 | 反 `aal_l2_dos_atk_set` @ `0x925f0` 与 `__ksymtab` 调用方 |
| U11 | L2 DoS 寄存器块地址 | W6 阻塞 | 同上 |
| U12 | `0x9004` bit25 之外还有哪些 L3TE 全局位被 `aal_*` 使用 | 低 | 全量扫 `mov x_, #0x9004` 的 9 处调用点 |
| U13 | `POL` 与 `POL3` 共用 `0x9108` cfg bank 是否真实（还是两套不同常量） | 影响 256+64 槽能否独立配置 | 需逐个核对 `flow3_cfg_set` 的 `mov w5` 立即数（本轮被过滤） |

---

## 9. 对下游的结论

**W3（流镜像）能否直接实现？——能，但只能是「寄存器级」实现，不能声称功能语义。**
- 已具备：寄存器偏移（`NE+0x3540/0x3544`）、位宽位序（`[24:19]`/`[18:16]`/`[7:0]`/`[11:0]`）、
  写序约束（单次 32 bit、`dmb` 后写、无 RMW 依赖）、**必须显式清零保留位的 OEM 缺陷**、
  与 L2 镜像机制的正交关系、建议的开关顺序。
- 缺：三个字段的功能命名（U1）。建议 W3 以 `mirror_set(port6, mode3, id8)` 的**纯寄存器 API** 落地，
  宏名用 `L3FE_MIRROR_PORT/MODE/ID` 并注明 `/* semantic inferred, see phase0-re2 U1 */`。

**W6 能否开工？——部分可以。**
- 可立即开工：WRED profile/sel 间接访问（§4.1/4.3 寄存器地址+位域已闭合）、
  policer profile/cfg 打包（§2.2/2.4 已闭合）、L3 DoS 的 9 寄存器块 + 写序 + 锁（§5.1）。
- 阻塞：DoS **逐 attack type 位表**（U10）、L2 DoS 块（U11）、Host Police MIB（U6）。
  建议 W6 先做「寄存器访问层 + 位域打包层」，把 attack-type 表留成数据驱动的 `TODO(U10)`。

**本次新增、开源树中不存在的规格**（可直接回填 `rtl9617c_regs.h`）：
`0x9004 BIT25`（L3TE 组表 8/64）、`0x9080+4n`（PIE/WRED 端口使能）、
`0x9090/0x90cc/0x9108/0x9144`（policer cfg 四块）、
`0x9128/0x9164/0x918c`（三张 profile 间接表）、`0x938c/0x93b0`（WRED 两表）、
`0x32ec..0x330c`（L3 DoS）、`0x3310`（DoS flood cnt）、`0x3540/0x3544`（L3FE 镜像）。