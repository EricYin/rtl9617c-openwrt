# Phase 2 RE-5 — L2/L3 DoS attack-type 位表（ca-ne.ko 只读逆向）

状态：**Phase 2 只读**。未修改 `pt1500-refactor-build` / `pt1500-immortalwrt-build`，未接触 `/opt/rea-snap`。

## 0. 语料、方法、地址约定

| 项 | 值 |
|---|---|
| 主语料 | `/mnt/c/rea/ca-ne.ko`，aarch64，not stripped，sha256 `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e` |
| 取证 | `aarch64-linux-gnu-nm/-objdump -d`（节内地址）；REA 6.5.0 / Ghidra 12.1.4 伪代码（`ca-ne.ko`，image_base `0x100000`） |
| 地址 | 本文一律给 **nm/objdump 节内地址**；REA 地址 = 节内 + `0x100040`（例：`aal_dos_atk_set` 节内 `0x918c0` → REA `0x191900`） |
| 外部对证 | OEM 5.10.70 initramfs（同一 CA-8277C 平台）：`/tmp/stock-initramfs/etc/reg.txt`（寄存器名表）、`/tmp/stock-initramfs/usr/lib/libca-cli.so`、`/tmp/stock-initramfs/usr/bin/app-cli`（字段名/命令名） |

标注：**[观测]** = 汇编/伪代码直接可见；**[推导]** = 多处观测合并；**[外部]** = 来自 OEM 其他制品（非 ca-ne.ko）；**[UNKNOWN]** = 未确认。

## 1. 关键结构结论：两个 API 都是「按位掩码回写寄存器镜像」

这是本轮最重要的发现，它决定了后面所有表的读法：

`aal_dos_atk_set(unit, u64 field_mask, u32 *cfg)` @ **`0x918c0`**（REA `0x191900`）和
`aal_l2_dos_atk_set(unit, u32 field_mask, void *cfg)` @ **`0x925f0`**（REA `0x192630`）
**不是**按 attack-type 分派、也**不是**读-改-写单个字段，而是：

```
1. ca_spin_lock(__aal_l3_dos_lock / __aal_l2_dos_lock)
2. 把整个寄存器块读入栈上镜像（每读一个字前 dmb oshld）
3. 对 field_mask 的每一个置位位 n：把 cfg 镜像中对应的 **连续位切片** 原样拷进寄存器镜像
4. dmb oshst → 按地址升序逐字写回（每写一个字前 dmb oshst）
5. ca_spin_unlock
```

证据：
- `aal_dos_atk_get` @ **`0x91f50`**（REA `0x191f90`）把 9 个寄存器**原样** dump 到 `cfg[0..8]`
  —— 与 set 的 `cfg` 是同一个 36 字节镜像结构。
- 逐位核对 set 的每个切片，**全部等于恒等拷贝**（见 §2 累计位偏移 0..287 无洞、无重叠）；
  例如 mask bit 4 = `0x32f0[18:3] ← cfg[1][18:3]`，编译器把它展开成
  `ubfx #3,#8 | lsl #5 | bfi #3,#16` 三条指令（`0x91e30` 附近的 `orr/bfi` 序列可验证同一手法）。
- 因此 `cfg` = **寄存器镜像本身**；「字段」只是 mask 的**粒度**。真正的 attack-type 语义
  （哪个 σ 切片属于哪个攻击类型）**不在 ca-ne.ko 内**——模块内 `aal_dos_atk_set` 的
  `__ksymtab` 是唯一引用（`readelf -r` 全表只有 `__ksymtab` 4 个 PREL32，无 .text 调用、
  无函数指针表），`get_call_graph(backward)` 无调用者；调用方在**外部模块**（未随包提供）。

`aal_dos_atk_set` 的返回值恒为 0；`aal_l2_dos_atk_set` 在 `cfg==NULL` 时返回 **2**（`0x192630` 入口 `cbz x2` → `mov w0,#2`）。

## 2. L3 DoS 寄存器块 `0x32ec..0x330c`（9 × 32 bit）+ 掩码位表

寄存器名来自 OEM `reg.txt`（**[外部]**，与 ca-ne.ko 偏移逐一吻合）：

| NE 偏移 | OEM 名 |
|---|---|
| `0x32ec` `0x32f0` `0x32f4` `0x32f8` `0x32fc` `0x3300` `0x3304` `0x3308` `0x330c` | `L3FE_PP_DOS_ATK_0` … `L3FE_PP_DOS_ATK_8` |

伪代码给出的读/写顺序固定为 `0x32ec → 0x32f0 → 0x32f4 → 0x32f8 → 0x32fc → 0x3300 → 0x3304 → 0x3308 → 0x330c`，
每字写前 `dmb oshst`（`0x91e50`–`0x91f24` 的 9 段 store 序列）**[观测]**。

### 2.1 37 个 mask 位 → 40 个寄存器切片（合计 288 bit，恒等覆盖 0..287）**[观测]**

`field_mask` 只用 **bit0..bit36**（低 32 位 + bit32..bit36）。位宽分布 = 1 / 4 / 5 / 9 / 16 / 32。

| mask bit | 目标寄存器切片 | 宽 | 备注 |
|---|---|---|---|
| 0 | `0x32ec[8:0]` | 9 | |
| 1 | `0x32ec[24:9]` | 16 | |
| 2 | `0x32ec[25]` | 1 | |
| 3 | `0x32ec[31:26]` + `0x32f0[2:0]` | 6+3 | **跨寄存器** |
| 4 | `0x32f0[18:3]` | 16 | |
| 5 | `0x32f0[19]` | 1 | |
| 6 | `0x32f0[28:20]` | 9 | |
| 7 | `0x32f0[31:29]` + `0x32f4[12:0]` | 3+13 | **跨寄存器** |
| 8 | `0x32f4[13]` | 1 | |
| 9 | `0x32f4[22:14]` | 9 | |
| 10 | `0x32f4[23]` | 1 | |
| 11 | `0x32f4[31:24]` + `0x32f8[0]` | 8+1 | **跨寄存器** |
| 12 | `0x32f8[1]` | 1 | |
| 13 | `0x32f8[10:2]` | 9 | |
| 14 | `0x32f8[11]` | 1 | |
| 15 | `0x32f8[20:12]` | 9 | |
| 16 | `0x32f8[21]` | 1 | |
| 17 | `0x32f8[30:22]` | 9 | |
| 18 | `0x32f8[31]` | 1 | |
| 19 | `0x32fc[8:0]` | 9 | |
| 20 | `0x32fc[9]` | 1 | |
| 21 | `0x32fc[18:10]` | 9 | |
| 22 | `0x32fc[19]` | 1 | |
| 23 | `0x32fc[28:20]` | 9 | |
| 24 | `0x32fc[29]` | 1 | |
| 25 | `0x32fc[31:30]` + `0x3300[6:0]` | 2+7 | **跨寄存器** |
| 26 | `0x3300[7]` | 1 | |
| 27 | `0x3300[16:8]` | 9 | |
| 28 | `0x3300[17]` | 1 | |
| 29 | `0x3300[26:18]` | 9 | |
| 30 | `0x3300[27]` | 1 | |
| 31 | `0x3300[31:28]` **和** `0x3304[4:0]` | 4+5 | 一个 mask 位覆盖两个寄存器（`0x91d94`–`0x91db4`） |
| 32 | `0x3304[5]` | 1 | |
| 33 | `0x3304[14:6]` | 9 | |
| 34 | `0x3304[15]` | 1 | |
| 35 | `0x3304[31:16]` | 16 | |
| 36 | `0x3308[31:0]` **和** `0x330c[31:0]` | 32+32 | 一个 mask 位覆盖两个整寄存器 |

**校验**：9+16+1+9+16+1+9+16+1+9+1+9+1+9+1+9+1+9+1+9+1+9+1+9+1+9+1+9+1+9+1+4+5+1+9+1+16+32+32 = **288** = 9 × 32，且累计起点 0、终点 287 连续无洞 **[观测]**。

> 与 Phase 0 §5.1 的差异：Phase 0 写「~38 个有效位、宽 1/5/9/13/16」是伪代码粗读的结果；
> 本轮用汇编逐条核对后修正为 **37 个 mask 位 / 40 个切片**，其中 13 bit 实际是
> `0x32f0[31:29]`(3) + `0x32f4[12:0]`(13) 的一个 16 bit 跨寄存器字段，
> `0x3304[15]` 是独立 1 bit（Phase 0 误并入 16 bit 字段），`0x3304[31:16]` 才是 16 bit。

### 2.2 字段位宽族（供生成宏）

| 宽 | 出现次数 | mask 位 |
|---|---|---|
| 16 | 4 | 1, 4, 7(13+3), 35 |
| 9 | 15 | 0,3,6,9,11,13,15,17,19,21,23,25,27,29,33 |
| 8/7/6/5/4/3 | 各 1（均为跨寄存器切片的组成） | 11,25,3,31,31,7 |
| 1 | 15 | 2,5,8,10,12,14,16,18,20,22,24,26,28,30,34 |
| 4 | 1 | 31（`0x3300[31:28]`） |
| 5 | 1 | 31（`0x3304[4:0]`） |
| 32 | 2 | 36 |

「9 bit + 1 bit 交替」的规律在第 0..187 位内极其规整（见 §3.3 的 [推导]）。

## 3. attack type 枚举

### 3.1 结论先行

- **attack-type 枚举不在 ca-ne.ko 内**：`aal_dos_atk_set` 是纯镜像回写器（§1），模块内既无 switch、
  也无 `.rodata` 类型名表、无调用方（`readelf -r` 仅 `__ksymtab`；`get_call_graph` backward 空）。
- 类型名从 **OEM 用户态 CLI 命令清单**恢复（**[外部]** `libca-cli.so` / `app-cli`），
  L2 与 L3 两族**共用同一套 16 个 attack type 名**（两族命令名逐项对应）。

### 3.2 16 个 attack type（OEM CLI 声明顺序）**[外部]**

`cli_aal_dos_atk_fib_<name>_set` / `cli_aal_l2_dos_atk_fib_<name>_set` 命令族，按字符串表中的出现顺序：

| # | name | L3 专有命令 | 说明（由名字直读） |
|---|---|---|---|
| 1 | `icmp_flood` | `_th_set`（+`_pol_id_set`） | ICMP flood，**有阈值** |
| 2 | `fin_flood` | `_th_set`（+`_pol_id_set`） | FIN flood，**有阈值** |
| 3 | `syn_flood` | `_th_set`（+`_pol_id_set`） | SYN flood，**有阈值** |
| 4 | `syn_with_data` | `_pol_id_set` | SYN 带数据 |
| 5 | `udp_bomb` | `_pol_id_set` | UDP bomb |
| 6 | `ping_of_death` | `_pol_id_set` | ping of death |
| 7 | `icmp_fragment` | `_pol_id_set` | ICMP 分片 |
| 8 | `tcp_frag_error` | `_pol_id_set` | TCP 分片错误 |
| 9 | `tcp_short_hdr` | `_pol_id_set` | TCP 短头 |
| 10 | `syn1024` | `_pol_id_set` | SYN 载荷 1024 |
| 11 | `null_scan` | `_pol_id_set` | NULL 扫描 |
| 12 | `xma_scan` | `_pol_id_set` | XMAS 扫描 |
| 13 | `syn_fin_scan` | `_pol_id_set` | SYN+FIN 扫描 |
| 14 | `blat_attacks` | `_pol_id_set` | blat 攻击（OEM 拼写） |
| 15 | `land_attacks` | `_pol_id_set` | LAND 攻击 |
| 16 | `smac_eq_dmac` | `_pol_id_set` | SMAC==DMAC |

L2 族额外有 `cli_aal_l2_dos_atk_fib_temp_set`（**[UNKNOWN]**，疑似测试/临时字段）；
L3 族无 `_pol_id_set` 之外的 L2 差异。

**注意**：以上是**名字与相对顺序**的 [观测]（字符串表顺序）；「字符串表顺序 == 枚举值顺序」
是 [推导]，未在有调用方二进制的情况下证实。

### 3.3 类型 → 位 的映射：**[UNKNOWN]**（本轮给到的最强结构证据）

可确证的只有**结构性**事实：

1. **只有 3 个 flood 类型带阈值**（`icmp_flood` / `fin_flood` / `syn_flood` 独有 `_th_set`）；
   L3 块里恰好有 **3 个 16 bit 字段**位于每个「9 bit 值」之后：`0x32ec[24:9]`、`0x32f0[18:3]`、
   `0x32f0[31:29]+0x32f4[12:0]`。
   ⇒ **[推导]** 这 3 个 16 bit 字段是 3 个 flood 类型的**端口掩码**（16 口），
   前面 9 bit 是**阈值**，后面的 1 bit 是**使能**：
   ```
   icmp_flood : th=0x32ec[8:0]      port_mask=0x32ec[24:9]                 en=0x32ec[25]
   fin_flood  : th=0x32ec[31:26]+0x32f0[2:0]  port_mask=0x32f0[18:3]       en=0x32f0[19]
   syn_flood  : th=0x32f0[28:20]    port_mask=0x32f0[31:29]+0x32f4[12:0]   en=0x32f4[13]
   ```
2. 之后位 78..187 恰好是 **11 组整齐的「9 bit 值 + 1 bit 使能」**：
   `0x32f4[22:14]/[23]`、`0x32f4[31:24]+0x32f8[0]/[1]`、`0x32f8[10:2]/[11]`、`0x32f8[20:12]/[21]`、
   `0x32f8[30:22]/[31]`、`0x32fc[8:0]/[9]`、`0x32fc[18:10]/[19]`、`0x32fc[28:20]/[29]`、
   `0x32fc[31:30]+0x3300[6:0]/[7]`、`0x3300[16:8]/[17]`、`0x3300[26:18]/[27]`。
3. 尾部 `0x3300[31:28]`(4) / `0x3304[4:0]`(5) / `0x3304[5]`(1) / `0x3304[14:6]`(9) /
   `0x3304[15]`(1) / `0x3304[31:16]`(16) / `0x3308`(32) / `0x330c`(32) 未被上述规律吸收。

⇒ **3 + 11 = 14 组「值+使能」，与 16 个类型差 2**。可能的解释（均未证实）：
(a) `0x3304[31:16]` 是 **`dos_type_en` 16 位位图**（一个 bit 一个 attack type）——
    CLI 确实有 `..._dos_type_en_set`；若成立，则 type→bit 就是该字段的 bit0..bit15（顺序见 §3.2）；
(b) 尾部 `0x3304[4:0]/[5]/[14:6]/[15]` 再构成 1..2 组；
(c) 其中一个类型（`smac_eq_dmac`，L2/L3 都有 `dos_port_mask`）走别的寄存器。
**以上 a/b/c 均列为 [UNKNOWN]，不得在实现中当作已证事实。**

### 3.4 L3 专有字段族（CLI 名，**[外部]**）

```
aal_dos_atk_fib_<type>_set              // 使能
aal_dos_atk_fib_<type>_th_set           // 仅 icmp/fin/syn_flood
aal_dos_atk_fib_<type>_pol_id_set       // 策略号（9 bit 候选）
aal_dos_atk_fib_dos_type_en_set         // 类型使能位图候选
aal_dos_atk_fib_dos_port_mask_set       // 端口掩码候选
aal_dos_atk_flood_cnt_cnt_cnt_set       // 0x3310[10:0]
aal_dos_atk_flood_cnt_cnt_reserved_set  // 保留
aal_dos_atk_event_trap_trap_cfg_{rdir_ldpid,rdir_cos,keep_orig_pkt,reserved,t0_ctrl..t5_ctrl}_set
aal_dos_atk_event_drop_drop_cfg_{rdir_ldpid,rdir_cos,keep_orig_pkt,reserved,t0_ctrl..t5_ctrl}_set
```

## 4. flood 计数寄存器

| API | 地址（节内） | 寄存器 | 位域 | 语义 |
|---|---|---|---|---|
| `aal_dos_atk_flood_cnt_set` | **`0x920d0`** | NE `0x3310` | `[10:0]` **11 bit** | mask bit0 才生效；`reg = (reg & ~0x7ff) \| (val & 0x7ff)`；单字段 RMW，**不按 attack type 分槽** |
| `aal_dos_atk_flood_cnt_get` | **`0x92170`** | NE `0x3310` | 整字返回 | 同一把 `__aal_l3_dos_lock` |
| `aal_l2_dos_atk_flood_cnt_set` | **`0x92aa0`** | NE `0x1234` | `[9:0]` **10 bit** | `bfxil #0,#10`；`cfg==NULL` → 返回 2 |
| `aal_l2_dos_atk_flood_cnt_get` | **`0x92b40`** | NE `0x1234` | 整字返回 | |

- **清零**：把 `[10:0]`（L2 `[9:0]`）写 0 即清零（`*_set(unit, 1, &zero)`）；ca-ne.ko 内**没有**独立的 clear 函数 **[观测]**。
- **不分槽**：全块只有 1 个 32 bit 计数寄存器，`[31:11]`（L2 `[31:10]`）保留 —— 与 CLI 的 `cnt_reserved` 字段一致。
- OEM `reg.txt`：`L3FE_PP_DOS_ATK_FLOOD_CNT 0xf4303310`、`L2FE_PP_DOS_ATK_FLOOD_CNT 0xf4301234` **[外部]**，与偏移一致。

## 5. trap / drop 控制（L3）

| API | 地址 | 寄存器 | 掩码位 |
|---|---|---|---|
| `aal_dos_atk_event_trap_set` | **`0x921d0`** | NE `0x3314` | bit0,1,2,4,5,6,7,8,9（**bit3 未用**） |
| `aal_dos_atk_event_trap_get` | **`0x92330`** | NE `0x3314` | 整字 |
| `aal_dos_atk_event_drop_set` | **`0x92390`** | NE `0x3318` | 同 trap（逐条汇编完全同构） |
| `aal_dos_atk_event_drop_get` | **`0x924f0`** | NE `0x3318` | 整字 |

两者位域相同（汇编 `0x921d0`–`0x92320` / `0x92390`–`0x924e0` 逐条对照，`bfi/ubfx` 立即数一一对应）**[观测]**：

| 位 | 宽 | mask bit | OEM 字段名 [外部] |
|---|---|---|---|
| `[5:0]` | 6 | 0 | `..._cfg_rdir_ldpid`（重定向目的 LDPID） |
| `[8:6]` | 3 | 1 | `..._cfg_rdir_cos`（重定向 CoS） |
| `[9]` | 1 | 2 | `..._cfg_keep_orig_pkt`（保留原包） |
| `[10]` | 1 | — | 无对应 mask 位（**不可写**） |
| `[11]` | 1 | 4 | `..._cfg_reserved`（CLI 如此命名） |
| `[15:12]` | 4 | 5 | `..._cfg_t0_ctrl`（假定按序） |
| `[19:16]` | 4 | 6 | `t1_ctrl`（假定） |
| `[23:20]` | 4 | 7 | `t2_ctrl`（假定） |
| `[27:24]` | 4 | 8 | `t3_ctrl`（假定） |
| `[31:28]` | 4 | 9 | `t4_ctrl`（假定） |

**[UNKNOWN]**：CLI 列了 `t0..t5_ctrl` 共 **6** 个 timer 字段，但寄存器只有 **5** 个 4 bit 槽
（`[15:12]`…`[31:28]`）→ 要么第 6 个在别处，要么名字与槽不是 1:1。上表 `t0..t4` 的对应关系是
按位序 [推导]，**未证实**；`t5` 无槽可放。

## 6. init 语义（重要：只初始化锁）

| 函数 | 地址 | 行为 |
|---|---|---|
| `aal_dos_init` | **`0x92550`** | `if (g_ne_reg_iobase != NULL) return 0;` 否则 `ca_spin_lock_init(&__aal_l3_dos_lock, 1)`；**不写任何寄存器** |
| `aal_l2_dos_init` | **`0x92d00`** | 同上，锁为 `__aal_l2_dos_lock`；**不写任何寄存器** |

两者由模块 init 调用（`.text` `0xac4` 处 `bl aal_dos_init`，`readelf -r` 可见）**[观测]**。
⇒ **OEM 的 DoS 寄存器块没有「默认值下发」**；上电默认值 = 硬件复位值，**[UNKNOWN]**
（`default_scfg.txt` 中无任何 DOS 配置项，已 `grep -i dos` 全表为零命中）。
L2/L3 两把锁独立（`.bss` `__aal_l3_dos_lock` / `__aal_l2_dos_lock`），故 L2/L3 可并发。

## 7. L2 DoS 块 `0x1220..0x1238`

| NE 偏移 | OEM 名 [外部] | 用途 |
|---|---|---|
| `0x1220` `0x1224` | `L2FE_PP_DOS_ATK_0` / `_1` | 攻击配置（成对，跨寄存器字段） |
| `0x1228` `0x122c` `0x1230` | `L2FE_PP_DOS_ATK_2/_3/_4` | 攻击配置 |
| `0x1234` | `L2FE_PP_DOS_ATK_FLOOD_CNT` | flood 计数 `[9:0]` |
| `0x1238` | `L2FE_PP_DOS_ATK_EVENT_TRAP` | trap 配置 |

### 7.1 `aal_l2_dos_atk_set` @ **`0x925f0`** —— 21 个 mask 位 / 144 bit **[观测]**

| mask bit | 切片 | 宽 |
|---|---|---|
| 0 | `0x1220[15:0]` | 16 |
| 1 | `0x1220[16]` | 1 |
| 2 | `0x1220[31:17]` + `0x1224[0]` | 15+1 |
| 3 | `0x1224[1]` | 1 |
| 4 | `0x1224[17:2]` | 16 |
| 5…18 | `0x1224[18]`…`[31]`（各 1 bit） | 14 × 1 |
| 19 | `0x1228[15:0]` | 16 |
| 20 | `0x1228[31:16]` + `0x122c[31:0]` + `0x1230[15:0]` | 16+32+16 |

合计 144 bit；`0x1230[31:16]` **不被任何 mask 位覆盖**。

### 7.2 `aal_l2_dos_atk_get` @ **`0x929a0`**：原样 dump 5 个寄存器（同 L3 模式）。

### 7.3 `aal_l2_dos_atk_event_trap_set` @ **`0x92bb0`** —— 与 L3 trap **不同**，只有 3 个字段 **[观测]**

| 位 | 宽 | mask bit |
|---|---|---|
| `0x1238[5:0]` | 6 | 0 |
| `0x1238[8:6]` | 3 | 1 |
| `0x1238[9]` | 1 | 2 |

`0x1238[31:10]` 保留。**L2 没有 event_drop 寄存器，也没有 `aal_l2_dos_atk_event_drop_*`** **[观测]**（`nm` 无此符号，`reg.txt` 无此名）。

### 7.4 L2 与 L3 块的异同（结论）

| 维度 | L3 | L2 |
|---|---|---|
| 配置寄存器 | 9 个（288 bit） | 5 个（160 bit，有效 144） |
| mask 位数 | 37 | 21 |
| flood 计数 | `0x3310[10:0]`（11 bit） | `0x1234[9:0]`（10 bit） |
| trap | `0x3314`，9 字段（含 4 bit timer ×5） | `0x1238`，仅 3 字段 |
| drop | `0x3318`（与 trap 同构） | **无** |
| attack type 名集 | 16 个 | 同一套 16 个（+`temp`） |
| init | 仅锁 | 仅锁 |
| 附加 | — | `L3FE_PP_dual_dos_en @0x3348`（L3 侧）；**ca-ne.ko 内未找到任何函数访问 0x3348 → [UNKNOWN]** |

## 8. 可直接生成 `RTL_DOS_*` 的宏表（只含已证切片）

```c
/* ===== 公共 ===== */
#define NE_DOS_L3_ATK(n)      (0x32ecu + 4u * (n))   /* n = 0..8  : L3FE_PP_DOS_ATK_0..8 */
#define NE_DOS_L3_FLOOD_CNT   0x3310u
#define NE_DOS_L3_EVT_TRAP    0x3314u
#define NE_DOS_L3_EVT_DROP    0x3318u
#define NE_DOS_L2_ATK(n)      (0x1220u + 4u * (n))   /* n = 0..4  : L2FE_PP_DOS_ATK_0..4 */
#define NE_DOS_L2_FLOOD_CNT   0x1234u
#define NE_DOS_L2_EVT_TRAP    0x1238u

#define DOS_FLOOD_CNT_L3_MASK GENMASK(10, 0)
#define DOS_FLOOD_CNT_L2_MASK GENMASK(9, 0)

/* ===== L3 trap/drop（两寄存器同构） ===== */
#define DOS_EVT_RDIR_LDPID(v)     (((u32)(v) & 0x3fu)  << 0)   /* [5:0]  */
#define DOS_EVT_RDIR_COS(v)       (((u32)(v) & 0x07u)  << 6)   /* [8:6]  */
#define DOS_EVT_KEEP_ORIG_PKT(v)  (((u32)(v) & 0x01u)  << 9)   /* [9]    */
#define DOS_EVT_RESERVED(v)       (((u32)(v) & 0x01u)  << 11)  /* [11]   */
#define DOS_EVT_T_CTRL(i, v)      (((u32)(v) & 0x0fu)  << (12 + 4 * (i))) /* i=0..4 -> [15:12]..[31:28] */
#define DOS_EVT_MASK_LDPID  BIT(0)
#define DOS_EVT_MASK_COS    BIT(1)
#define DOS_EVT_MASK_KEEP   BIT(2)
#define DOS_EVT_MASK_RSVD   BIT(4)
#define DOS_EVT_MASK_T(i)   BIT(5 + (i))                        /* i=0..4 */

/* ===== L2 trap（字段更少） ===== */
#define DOS_L2_EVT_RDIR_LDPID(v)  (((u32)(v) & 0x3fu) << 0)
#define DOS_L2_EVT_RDIR_COS(v)    (((u32)(v) & 0x07u) << 6)
#define DOS_L2_EVT_KEEP(v)        (((u32)(v) & 0x01u) << 9)

/* ===== L3 配置块位切片（mask bit -> 寄存器/位移）===== */
/* 用法：blit(reg, shift, width, src_bit_off) —— 源是 36 字节镜像的连续位流 */
#define L3_DOS_SLICE_0   0x32ec,  0,  9
#define L3_DOS_SLICE_1   0x32ec,  9, 16
#define L3_DOS_SLICE_2   0x32ec, 25,  1
/* ... 见 §2.1 全表；跨寄存器切片（3/7/11/25/31/36）需按位流实现，
 *     不要用单寄存器 read-modify-write 宏 */

/* ===== 推荐：不要暴露"字段名"，直接暴露 OEM 同款 masked-blit ===== */
int rtl_dos_atk_set(u32 unit, u64 field_mask, const u32 img[9]);
int rtl_l2_dos_atk_set(u32 unit, u32 field_mask, const u32 img[5]);
int rtl_dos_flood_cnt_set(u32 unit, u32 val);        /* img[..] 或直接 0x3310[10:0] */
int rtl_l2_dos_flood_cnt_set(u32 unit, u32 val);     /* 0x1234[9:0] */
```

## 9. 推荐 sysfs / debugfs API

```
/sys/kernel/debug/rtl9617c/dos/
├── l3/flood_cnt                 (ro)      读 0x3310[10:0]
├── l3/flood_cnt_clear           (wo, 任意写) 写 0 → 清零
├── l3/trap/{ldpid,cos,keep_orig_pkt,reserved,t0..t4}   (rw)
├── l3/drop/{ldpid,cos,keep_orig_pkt,reserved,t0..t4}   (rw)
├── l2/flood_cnt (ro) / flood_cnt_clear (wo)
├── l2/trap/{ldpid,cos,keep_orig_pkt}                   (rw)
├── attack/<name>/{enable,threshold,port_mask}          (rw)
└── attack/<name>/dump                                   (ro, 打印镜像 9 字)
```

设计约束（由本文观测决定，必须遵守）：
1. **一律走 masked-blit**：任何一次写都必须带 `field_mask`，否则会把镜像里未初始化的字写回寄存器
   （OEM 自己的 `get→改→set` 模式就是这么用的）。
2. **读-改-写必须在 `__aal_l3_dos_lock` 语义下串行**（OEM 用 spinlock；我们用一个 mutex 即可）。
3. **写序固定地址升序 + 每字 `wmb()`**（OEM 的 `dmb oshst`）。
4. `attack/<name>/enable` **在映射 UNKNOWN 前只能实现为「写整块镜像」**，
   不要按猜测的 bit 位置写单 bit —— 会把相邻类型的阈值/端口掩码改坏。
5. flood 计数是**全局单值**，不是 per-type；`clear` 即写 0。

## 10. UNKNOWN 清单（本轮）

| # | 项 | 影响 | 下一步 |
|---|---|---|---|
| U10-a | **attack type ↔ 位切片 的最终绑定**（16 类型 vs 14 组「值+使能」） | W6c 无法提供 per-type 开关 | 需要实现 `aat_dos_atk_*` 的**外部模块**（不在本包内）或 Realtek SDK 头文件；`/tmp/stockroot/lib/modules/5.10.70` 权限 0700 不可读 |
| U10-b | `0x3304[31:16]` 是否为 `dos_type_en` 16 位位图（若是，即 type→bit 表） | 决定 per-type enable 是否能单 bit 开关 | 同上；或用 `diag` 在设备上看该寄存器随 CLI 命令的变化 |
| U10-c | 9 bit 字段是「阈值」还是「pol_id」 | 决定 API 命名 | CLI 同时有 `_th_set`（仅 3 类）与 `_pol_id_set`（全部），倾向 pol_id；未证 |
| U10-d | `0x3304[4:0]` / `[15]` / `0x3300[31:28]`（4/5/1 bit）语义 | 只能是保留/全局 | 同上 |
| U11 | `L2FE_PP_DOS_ATK_0..4` 的逐字段语义 | 同 U10 | 同上 |
| U12 | trap 的 `t5_ctrl` 无对应槽；`[10]` 位不可写 | 6 个 timer 只落实 5 个 | 外部模块字段表 |
| U13 | `0x3348` (`L3FE_PP_dual_dos_en`) 无人访问 | 可能影响 DoS 是否生效 | 设备写测 |
| U14 | DoS 块上电默认值 | 初始化策略 | 设备 `diag` 读 |

## 11. 对 W6c 的结论

**能否直接实现？——寄存器层：能；per-attack-type 语义层：不能。**

可直接落地（本文已闭合）：
- L3 9 寄存器 / L2 5 寄存器的**精确偏移、写序、锁、masked-blit 语义**；
- **37 / 21 个 mask 位与寄存器切片的完整对应表**（288 / 144 bit，无洞）；
- flood 计数（`0x3310[10:0]` / `0x1234[9:0]`）读写与清零；
- trap / drop（`0x3314` / `0x3318`，9 字段）与 L2 trap（`0x1238`，3 字段）；
- init 只初始化锁（**不要**指望 OEM 有默认值下发）。

不能声称（必须留 TODO）：
- 「SYN flood 的使能位是 bit N」这类断言；
- `dos_type_en` 位图的存在性与布局；
- 16 个类型名到位的映射。

**建议给 W6c 的实现**：
1. 先实现 **OEM 同款的 masked-blit API + 寄存器镜像结构**（`u32 img[9]` / `u32 img[5]`），
   这是 100% 可复现的部分；
2. sysfs 只暴露**已证字段**（flood_cnt / trap / drop / 整块 dump），
   对 attack/<name> 只做「读整块 + 写整块」；
3. 把 type→bit 表做成**数据驱动**并标 `TODO(U10-a)`，待拿到外部模块或设备实测后填表；
4. 上设备后用 `diag` 对比「CLI 开某一类型前后 0x32ec..0x330c 的差异」，一次即可反解 U10-a/U10-b
   ——**这是最短路径**（每条 CLI 命令都有独立名字，可逐条差分）。

## 12. 证据索引

| 内容 | 证据 |
|---|---|
| `aal_dos_atk_set` 伪代码（9 寄存器镜像 + mask 位） | REA `ev_144debbf91fc6c544ba55ec68634ef9f58a0cd44ddaf19c5560f4bd9b7e46a48` |
| `aal_dos_atk_get` 原样 dump | REA `ev_88775a227448a72f0a2ddec01fcf05222686a7cb12f3a16b6db580449837f9fe` |
| L2 `aal_l2_dos_atk_set` 伪代码 | REA `ev_33968dfdf0e3adbf0b06a0de63810b6781c4d6b62574b32a9423fbb37a7db5f9` |
| `flood_cnt_set` (0x3310[10:0]) | REA `ev_f1cbd9ac06ac386116f85f550ab68f21c313af1b3e516707be95f00fad2ba3dc` |
| `event_trap_set` (0x3314) | REA `ev_b78a48b90265d7c6390c0ec1d8c61c519fa1c0a33ce444536d8f781f6a145766` |
| 位切片逐条复核 | `objdump -d`：`0x921d0`(trap)、`0x92390`(drop)、`0x92aa0`(L2 cnt)、`0x92bb0`(L2 trap)、`0x92550`/`0x92d00`(init)、`0x91c00`–`0x91e30`(0x3300/0x3304 打包)、`0x91e50`–`0x91f24`(写序) |
| OEM 寄存器名 | `/tmp/stock-initramfs/etc/reg.txt` 行 99–105、754–765、777 |
| OEM 类型名 / 字段名 | `/tmp/stock-initramfs/usr/lib/libca-cli.so`、`/tmp/stock-initramfs/usr/bin/app-cli`（`strings` 过滤 `_dos_atk_`） |
---

# 附：Phase 2 RE-5b — 从 OEM CLI 追 type→bit（task-17，追加，不覆盖上文）

状态：**只读**。新增语料：`/tmp/stock-initramfs/usr/lib/libca-cli.so`（**not stripped**，13 900+ 符号）、
`/tmp/stock-initramfs/usr/bin/app-cli`（stripped）、`/tmp/stock-initramfs/lib/libcms_core.so`。

> **对上文的更正**：§3.2 说「按字符串表顺序 = OEM CLI 声明顺序」不够准确。字符串池顺序是编译器按
> 源文件函数顺序发射的；而 CLI 的 help/注册表是**相反顺序**（见 §15）。两者都不能单独当作枚举序。

## 13. CLI 传输层（全部 [观测]，libca-cli.so）

### 13.1 每个 `cli_aal_dos_atk_*` 都是 20 字节转发桩

```
cli_aal_dos_atk_fib_syn_flood_set:            ; 0x1ced00, 20 B
    mov  x3, x2                                ; 第 4 参数原样透传
    mov  w2, w1                                ; 第 3 参数（nargs）
    adrp x1, 0x28b000 / add x1, x1, #0x620     ; x1 = 0x28b620 = 命令名字符串
    b    cli_cmd_ioctl                         ; 0x1a1e30
```
- 每个桩只传 **一个命令名字符串指针**（形如 `cli_aal_dos_atk_fib_syn_flood_set`），
  **不传任何类型索引 / 寄存器号 / 位号**。
- ⇒ **user space 完全没有 type→bit 信息**；位映射只可能在 `/dev/cortina-cli-dev` 背后的内核模块里。

### 13.2 ioctl 载荷结构（`cli_cmd_ioctl` @ 0x1a1e30，逐条读汇编）**[观测]**

```
buf = alloca(0x2268); memset(buf, 0, 0x2268)
strcpy(buf + 0x2004, cmd_name)              ; 命令名
*(u32 *)(buf + 0x2084) = nargs
for (i = 0; i < nargs; i++)                 ; 参数一律按 **字符串** 传
    strncpy(buf + 0x2088 + i*0x20, argv[i], 32);  buf[...+31] = 0
fd = open("/dev/cortina-cli-dev", O_RDWR);
if (ioctl(fd, 0x4301, buf) != 0) return 7;
cli_print(cmd_name, "%s", buf + 4);         ; 成功时打印 buf+4 起的结果串
return *(u32 *)(buf + 0x18);                ; 返回码
```
结论：
- **参数是 ASCII 字符串**（每槽 32 B），内核侧解析 ⇒ CLI 的 `<0-0xffffffff>` 只是**解析范围提示**，
  不等于寄存器字段宽度；
- ioctl 号 **0x4301**，设备节点 **`/dev/cortina-cli-dev`**；
- 该设备**不是 ca-ne.ko 创建的**（ca-ne.ko 内无任何 `dos_atk_fib` 符号/字符串）⇒ 实现
  `aat_dos_atk_*` 的内核模块**不在本包**。这是 U10-a 无法闭死的根因。

### 13.3 help 串给出的参数名与量程 **[观测]**（本轮决定性新证据）

```
dos_atk    <0-0xf> dos_port_mask  <0-0xffffffffffffffff>     ← 64 bit !
dos_atk    <0-0xf> dos_type_en    <0-0xffffffff>             ← 32 bit
dos_atk    <0-0xf> <type>         <0-0xffffffff>             ← 16 个类型各一条
dos_atk    <0-0xf> <type>_th      <0-0xffffffff>             ← 仅 icmp / fin / syn_flood
dos_atk    <0-0xf> <type>_pol_id  <0-0xffffffff>             ← L3 全部 16 类
show dos_atk <0-0xf>
l2_dos_atk <0-0xf> temp           <0-0xffffffff>             ← 仅 L2
l2_dos_atk <0-0xf> dos_port_mask  <0-0xffffffffffffffff>     ← L2 也有 64 bit port mask
l2_dos_atk <0-0xf> dos_type_en    <0-0xffffffff>             ← L2 也有 32 bit type en
l2_dos_atk <0-0xf> <type>[_th]    …                          ← **L2 无 pol_id**
```
- `<0-0xf>` 是 **unit**（`aal_*` 第 1 参数，ca-ne.ko 内被忽略），**不是**攻击类型索引。
- **`dos_port_mask` 是 64 bit 量** ⇒ 对上了 mask bit36「一个 mask 位同时拷 `0x3308`+`0x330c`」
  （64 bit 字段 = 两个 32 bit 寄存器）——见 §14.1。

## 14. 用新证据回填位表（[推导]，带置信度）

### 14.1 `dos_port_mask`：L3 = `0x3308`+`0x330c`，L2 = `0x1228[31:16]`+`0x122c`+`0x1230[15:0]`（各 64 bit）—— 置信度高

| | L3 | L2 |
|---|---|---|
| 64 bit 单字段 | `0x3308[31:0]` ‖ `0x330c[31:0]`，由 **mask bit36 一次拷贝两字** | `0x1228[31:16]`(16) + `0x122c[31:0]`(32) + `0x1230[15:0]`(16)，由 **mask bit20 一次拷贝** |

理由：两平台各恰好有**一个** mask 位覆盖跨 2/3 个寄存器的 64 bit 连续切片，而 CLI 里唯一的 64 bit
参数就是 `dos_port_mask` ⇒ 「唯一 64 bit 字段 ↔ 唯一 64 bit 切片」，不是位宽猜测。

### 14.2 `dos_type_en`：32 bit —— 置信度中

`dos_type_en` 量程 `<0-0xffffffff>` = 32 bit。块内 32 bit 对齐切片恰两处：

| | L3 | L2 |
|---|---|---|
| 组成 | bit31 的 `0x3304[4:0]`(5) + bit32 `[5]`(1) + bit33 `[14:6]`(9) + bit34 `[15]`(1) + bit35 `[31:16]`(16) = **32** | bit0 `0x1220[15:0]`(16) + bit1 `[16]`(1) + bit2 `0x1220[31:17]`(15) = **32** |
| 候选 | **`0x3304[31:0]`**（整寄存器） | **`0x1220[31:0]`**（整寄存器） |

⇒ **对 task-17 第 1 问的答案**：`0x3304[31:16]` 单独 16 bit **装不下** `dos_type_en`（它要 32 bit），
所以 Phase 2 §3.3 里「0x3304[31:16] = dos_type_en 位图」的猜测**应被修正为 0x3304[31:0]**。
但「32 bit = 16 类型 × 1 bit」还是「16 类型 × 2 bit」**仍 UNKNOWN**。

### 14.3 其余切片
`0x32ec..0x3300` 的 15 组「9 bit + 1 bit」与 3 个 16 bit 仍按 §3.3 理解（阈值 / 端口掩码 / 动作位），
但新增硬约束：**`pol_id` 是 L3 独有**（L2 无 `_pol_id` 命令）⇒ L2 的 per-type 阈值只能挤进
`0x1224[31:0]`（32 bit，如 16×2 bit 打包）。**未证实。**

## 15. 枚举顺序：两个候选序，仍未定案

| 序 | 来源 | 顺序（第 1 个 = 最早源函数 / `.data` 注册表最低地址） |
|---|---|---|
| **S（源/字符串池序）** | `.rodata` 按函数发射顺序 | icmp_flood → fin_flood → syn_flood → syn_with_data → udp_bomb → ping_of_death → icmp_fragment → tcp_frag_error → tcp_short_hdr → syn1024 → null_scan → xma_scan → syn_fin_scan → blat_attacks → land_attacks → smac_eq_dmac |
| **R（help/注册表序 = S 的逆序）** | `_cmd` 描述符在 `.data` 的地址升序（0x36bca0 → 0x36bef8 …） | smac_eq_dmac → land_attacks → blat_attacks → syn_fin_scan → xma_scan → null_scan → syn1024 → tcp_short_hdr → tcp_frag_error → icmp_fragment → ping_of_death → udp_bomb → syn_with_data → syn_flood → fin_flood → icmp_flood |

两者都**不是**枚举值的直接证据；`dos_type_en` 的 bit 分配只在内核模块里。
**一次可定案的实验**（需设备）：`dos_type_en 0 0xffffffff` 读回得 16 bit 并集，再逐类型
`dos_atk 0 <type> 1` 后读回做差集，每次只差 1 bit ⇒ 16 次即得完整 type→bit 表（L2 读 `0x1220`）。

## 16. 给 W6c 的 `RTL_DOS_TYPE_*` 宏/表（含 UNKNOWN 标注）

```c
/* ===== 已可断言：两个"大字段"的物理位置（[推导]，高置信） ===== */
#define L3_DOS_TYPE_EN        0x3304u   /* 32 bit 候选，见 U10-b */
#define L2_DOS_TYPE_EN        0x1220u
#define L3_DOS_PORT_MASK_LO   0x3308u   /* 64 bit = lo | (hi << 32) */
#define L3_DOS_PORT_MASK_HI   0x330cu
#define L2_DOS_PORT_MASK_W0   0x1228u   /* [31:16] = 低 16 bit */
#define L2_DOS_PORT_MASK_W1   0x122cu
#define L2_DOS_PORT_MASK_W2   0x1230u   /* [15:0]  = 高 16 bit */

/* ===== 类型编号：CANDIDATE，未证实（U10-a）。默认采用序 S；若实测为序 R 只需改这里 ===== */
enum rtl_dos_type {
    RTL_DOS_TYPE_ICMP_FLOOD = 0, RTL_DOS_TYPE_FIN_FLOOD, RTL_DOS_TYPE_SYN_FLOOD,
    RTL_DOS_TYPE_SYN_WITH_DATA,  RTL_DOS_TYPE_UDP_BOMB,  RTL_DOS_TYPE_PING_OF_DEATH,
    RTL_DOS_TYPE_ICMP_FRAGMENT,  RTL_DOS_TYPE_TCP_FRAG_ERROR, RTL_DOS_TYPE_TCP_SHORT_HDR,
    RTL_DOS_TYPE_SYN1024,        RTL_DOS_TYPE_NULL_SCAN, RTL_DOS_TYPE_XMA_SCAN,
    RTL_DOS_TYPE_SYN_FIN_SCAN,   RTL_DOS_TYPE_BLAT,      RTL_DOS_TYPE_LAND,
    RTL_DOS_TYPE_SMAC_EQ_DMAC,
    RTL_DOS_TYPE_MAX
};
#define RTL_DOS_TYPE_BIT(t)   BIT((t))          /* 仅当 1 bit/类型 成立 */
#define RTL_DOS_TYPE_ALL      GENMASK(15, 0)    /* 高 16 位用途 UNKNOWN */

/* ===== 只有 3 类有阈值；pol_id 仅 L3 ===== */
#define RTL_DOS_HAS_THRESHOLD(t) \
    ((t) == RTL_DOS_TYPE_ICMP_FLOOD || (t) == RTL_DOS_TYPE_FIN_FLOOD || \
     (t) == RTL_DOS_TYPE_SYN_FLOOD)
#define RTL_DOS_HAS_POL_ID(is_l3)  (is_l3)      /* L2 无 pol_id（CLI 命令面已证实） */
```

## 17. 本轮 UNKNOWN（更新 §10）

| # | 项 | 状态 |
|---|---|---|
| U10-a | type → bit 的**具体位号** | **仍 UNKNOWN**。两个候选序见 §15；内核模块缺失是硬阻塞 |
| U10-b | `dos_type_en` 1 bit/类型 还是 2 bit/类型；有效位是否只有 16 | **UNKNOWN**（更精确：参数面是 32 bit） |
| U10-c | 9 bit 字段 = 阈值 还是 pol_id | 仍 [推导]；新约束：L2 无 pol_id ⇒ 若 L2 有 9 bit 字段则必是阈值 |
| U10-e | 15 组「9+1」的逐类型归属 | UNKNOWN |
| U15 | `aat_dos_atk_*` 内核实现模块 | **确认不在本包**（ca-ne.ko 无 `dos_atk_fib` 符号/字符串；`/dev/cortina-cli-dev` 由其它模块创建） |

**给 lead 的结论**：寄存器层与传输层已闭死（§13/§14）；type→bit 只能给到
「候选序 + 32 bit `dos_type_en` 落 `0x3304`/`0x1220`、64 bit `dos_port_mask` 落 `0x3308+0x330c` /
`0x1228+0x122c+0x1230`」——**位号本身需要设备上 16 次 CLI+diag 差分**（§15 给了具体步骤），文字证据到此为止。