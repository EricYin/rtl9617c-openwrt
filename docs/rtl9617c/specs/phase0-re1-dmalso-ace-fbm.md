# Phase 0 RE-1 — DMA LSO / TX CSUM / SG / ACE / SRAM EQ0 / FBM 规格书

> 目标：为 mainline 6.18 `rtl9617c` 驱动改造提供可直接落地的寄存器与描述符规格。
> 只读逆向。**未修改** `pt1500-refactor-build` / `pt1500-immortalwrt-build` 任何文件。

---

## 0. 证据基线与引用约定

| 项 | 值 |
|---|---|
| 二进制 | `ca-ne.ko`，aarch64，未 strip，13170 符号 |
| SHA-256 | `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e`（WSL 原始副本与 `/mnt/c/rea/ca-ne.ko` **逐字节相同**，已核对） |
| 反编译 | REA / Ghidra 12.1.4，`image_base = 0x100000`，4762 procedures |
| 交叉核对 | `aarch64-linux-gnu-nm/-objdump/-readelf`（重定位、常量、`.data/.rodata` 初值） |
| 配置 | `/opt/ubiwork/cfg/default_scfg.txt`（只读） |
| 原厂 DTB0 | `/opt/ubiwork/images/part_ubi_device.bin/img-1593892973_vol-ubi_DTB0.ubifs`（`dtc -I dtb -O dts` 成功） |

**地址写法**：`函数名 @Ghidra地址`（与 REA 一致），括号内给 `nm` 节内偏移。
例：`aal_ni_init_tx_dma_lso @0x1047c0 (nm .text 0x4780)`。
`.text` 段换算：**Ghidra = nm + 0x100040**。`.text.unlikely` 不适用该常数，故两者并列给出。

**未确认一律写 `UNKNOWN`。** 下文凡标 `[INFERRED]` 者为推断，不可当结论使用。

复用前置结论（本报告已复核，非直接抄录）：`extra_regs_spec.txt`、`regs_audit_spec.txt` 中与本文冲突处以本文为准，并已在 §7 记差异。

---

## 1. `0xf7001000` DMA LSO 全局寄存器

### 1.1 基址确认（三重证据）

1. `aal_ni_set_tx_write_ptr @0x104dc0 (nm 0x4d80)`：`x3 = 0xffffffff8ffff000`，即 `-(0xf7001000)`，寄存器地址 = `g_dma_reg_iobase + (arg - 0xf7001000)`。故 `g_dma_reg_iobase = 0xf7001000`。
2. `aal_ni_init_tx_dma_lso @0x1047c0` 调试打印常量：`mov w2,#0x1100 ; movk w2,#0xf700,lsl#16` → `0xf7001100`（VP0 首寄存器）。
3. 原厂 DTB0 `ethernet@f4300000` 的 `reg` 第 5 项 = `<0x04 0xf7001000 0x00 0x1000>`，即 DMA 窗口 4 KiB。

**重要纠正**：`0xf7001900 / 0xf7001d80 / 0xf7001f00` 并非独立寄存器块，而是 `base + 0x900 / 0xd80 / 0xf00`。全部偏移都落在 `base+0x000..0xFFF` 之内，与 DTB 的 0x1000 窗口一致。

### 1.2 全局寄存器表（写序即 OEM 初始化顺序）

| 偏移 | OEM 符号名（来自模块内打印串） | OEM 写入值 | 位域语义 |
|---|---|---|---|
| `0x000` | `DMA_SEC_DMA_GLB_DMA_LSO_CTRL` | RMW → `0x2D`，随后 `rtk_*` 再 RMW → `0x1D` | bit0 = 全局 enable；bits[3:2] = 1,1；**bit5 先置 1 后被清**；bit4 由 `rtk_ni_init_tx_dma_lso` 置 1 |
| `0x014` | `DMA_SEC_DMA_GLB_DMA_LSO_AXI_USER_SEL0` | `0x55555555` | 12 个 VP × 2 bit，每字段 = 1（AXI user/ID 选择） |
| `0x018` | `..._AXI_USER_SEL1`（名称 UNKNOWN） | `0x02008080` | 见 §1.4 解码 |
| `0x01C` | `DMA_AXI_USER_PATTERN1`（驱动命名） | `0x02008080` | 同上 |
| `0x020` | 名称 UNKNOWN（PATTERN2） | `0x02008080` | 同上 |
| `0x024` | 名称 UNKNOWN（PATTERN3） | `0x02008080` | 同上 |
| `0x030` | 名称 UNKNOWN | 只读 | `ca_ni_tx_dump_debug_reg @0x1a6d40 (nm 0xa6d00)` 读取 |
| `0x050` | `DMA_SEC_DMA_GLB_DMA_LSO_DEBUG0` | 只读 | **bits[7:4] = 错误码；`0x5` = DMA stuck** |
| `0x0C8` | 名称 UNKNOWN（ACE 属性镜像） | `ace ? 2 : 0`（仅 bits[7:0]） | 与 per-VP `+0x08` 同值 |
| `0x900` | `DMA_SS_CTRL`（驱动命名） | RMW `|= BIT(31)` | bit31 |
| `0xD80` | `DMA_AXI_CONFIG`（驱动命名） | RMW → `0x7AFF`（已知掩码 `0x7FFF`） | bits[7:0]=`0xFF`；bits[10:8]=2；bit11/12/13/14=1；bit9=0 |
| `0xF00` | `DMA_AFT_CTRL`（驱动命名） | RMW `|= BIT(0)`；bits[17:4]=`0x40` | → `0x401` |

`0x018/0x01C/0x020/0x024` 的 `0x02008080` 解码（以 §3.2 AXI 属性字段表解释）：
`cache[7:4]=0x8, domain[15:14]=2, ace_cmd[25]=1`，其余为 0。

### 1.3 Per-VP 寄存器块（`base + 0x100 + vp*0xA0`，vp = 0..11，stride `0xA0`）

| 块内偏移 | OEM 符号名 | 写入值 | 语义 |
|---|---|---|---|
| `+0x00` | `DMA_SEC_DMA_LSO_VP_CONTROL` | `0xFF` | **bit q = 队列 q 使能**（8 队列位图）。OEM 对 12 个 VP 全部写 `0xFF` |
| `+0x04` | `DMA_SEC_DMA_LSO_VP_TXQ_BASE_DEPTH_ACCESS` | `(queue & 7) \| 0xC0000000` | bit31 = busy/trigger（**轮询至 0**）；bit30 = 写方向（读用 `0x80000000`）；bits[2:0] = 队列号 |
| `+0x08` | `..._TXQ_BASE_DEPTH_DATA1` | `dma_lso_ace_test ? 2 : 0` | AXI 属性 / ACE 标志 |
| `+0x0C` | `..._TXQ_BASE_DEPTH_DATA0` | `((phys>>4)<<4) \| 0xA` | bits[3:0] = **log2(描述符个数)**；bits[31:4] = 环基址 >>4（**16 B 粒度**） |
| `+0x18 + 8*q` | TX **write** pointer | 软件 head | 写指针 |
| `+0x1C + 8*q` | TX **read** pointer | 硬件 tail（只读） | 读指针 |
| `+0x160` | VP 中断状态 | 读；写回清除 | bit0、bit1 被检查 |
| `+0x164` | VP 中断使能（驱动 `DMA_VP_IRQ_ENABLE=0x64`） | — | — |
| `+0x168` | 每队列 misc 中断状态 | 读；写 1 清除 | **每队列 3 bit**：q0=bit0, q1=bit3, q2=bit6, q3=bit9, q4=bit12, q5=bit15, q6=bit18, q7=bit21 |
| `+0x170` | 第二状态寄存器 | 读；写回清除 | 语义 UNKNOWN |
| `+0x178` | per-VP header_a 模板 | `(old & 0xFFFFFC00) \| (old & 7) \| (ldpid&0x3F)<<3 \| (febypass&1)<<9` | bits[2:0] 保留；**bits[8:3] = ldpid**；**bit9 = fe_bypass** |

> `aal_ni_set_dma_lso_headerA @0x22123c (nm .text.unlikely 0xa70)` 现场打印
> `port_no=%d, ldpid=%d, febypass=%d`，并对 `0xf7001000 + port*0xA0 + 0x178` 做上述 RMW —— 这是**唯一**直接设置 per-VP header_a 的函数。

`+0x00 = 0xFF` 的"8 队列位图"含义由 `+0x18/+0x1C` 每组 8 字节 × 8 组、以及 `ca_ni_init_tx_dma_lso` 的 `for q in 0..7` 循环共同确定（见 §1.5）。

### 1.4 `aal_ni_init_tx_dma_lso` 完整调用序列

`aal_ni_init_tx_dma_lso @0x1047c0 (nm 0x4780)`，共 316 条指令。调用者：`aal_ni_init_ni @0x105860`、`ca_ni_dma_lso_reset @0x23c4ec`（REA `procedure_callers` 完整覆盖，无未解析边）。

严格顺序（每条 MMIO 前 `dmb oshst`、读后 `dmb oshld`）：

```
 1. for vp = 0 .. 11:                        # 12 次
        write32(base + 0x100 + vp*0xA0, 0xFF)
        read back, 若 ca_aal_debug bit0 则 printk
 2. RMW(base + 0xD80):
        v |= 0x0000000F          # bits[3:0]
        v |= 0x000000F0          # bits[7:4]
        v  = bfi(v, 2, #8, #3)   # bits[10:8]  = 2
        v |= 0x00000800          # bit11
        v |= 0x00001000          # bit12
        v |= 0x00002000          # bit13
        v |= 0x00004000          # bit14
        => 0x7AFF
 3. write32(base + 0x014, 0x55555555)        # 12 x 2bit = 1
 4. write32(base + 0x018, 0x02008080)
    write32(base + 0x01C, 0x02008080)
    write32(base + 0x020, 0x02008080)
    write32(base + 0x024, 0x02008080)
 5. RMW(base + 0x900)  |= 0x80000000          # 只置 bit31
 6. RMW(base + 0x000):  v |= 0x01; v |= 0x0C; v |= 0x20   => 0x2D
 7. for off = 0x1000, 0x1080, 0x1100, 0x1180, 0x1200:     # 5 次
        write32(g_ne_axi_reo_reg_iobase + off, 0x0F)
 8. call rtk_ni_init_tx_dma_lso()             # 见下
```

`rtk_ni_init_tx_dma_lso @0x22118c (nm .text.unlikely 0x9c0)` —— 全函数只有 2 个 MMIO 写，**必须最后调用**：

```
 1. RMW(base + 0x000):  v &= ~0x20;  v |= 0x10      # 清 bit5、置 bit4  => 0x1D
 2. RMW(base + 0xF00):  v |= 0x01;  v = bfi(v, 0x40, #4, #14)   # bits[17:4]=64 => 0x401
```

**轮询与延时**：`aal_ni_init_tx_dma_lso` / `rtk_ni_init_tx_dma_lso` 内**没有任何 delay 或轮询**，只有 `dmb oshst/oshld`。真正的轮询在寄存器级设置函数里（§1.6）。

### 1.5 `ca_ni_init_tx_dma_lso` — 每 VP × 每队列环分配

`ca_ni_init_tx_dma_lso @0x1ac100 (nm 0xac0c0)`，1892 条指令。

```
a. aal_scfg_read("CFG_ID_DMA_LSO_ACE_TEST", 1, &dma_lso_ace_test)
   # 配置值 = 1  (default_scfg.txt:789)
b. RMW(base + 0x0C8):  bits[7:0] = dma_lso_ace_test ? 2 : 0
c. for vp = 0 .. 11:                 # 外层 12 VP
     for q  = 0 .. 7:                # 内层 8 队列
         tx_buf  = alloc 0x6000 B    # 24 KiB 发送缓冲池
         tx_desc = alloc 0x2000 B    # 8 KiB = 1024 个 8 B 描述符
         if (dma_lso_ace_test):
             用 __ca_malloc + virt_to_phys（非 dma_alloc_coherent）
             if (l3qm_dmalso_sram_enable[vp] >> q) & 1:
                 tx_desc 取自 SRAM 撞针分配器:
                     sram_cur_virtual_addr / (sram_start_phy_addr + sram_cur_used_size)
                     每次 +0x2000
         else:
             两者均 dma_alloc_attrs(coherent)
         reg_rptr[vp][q] = 0xF700111C + vp*0xA0 + q*8    # 前面读、后面写
         reg_wptr[vp][q] = reg_rptr - 4 = 0xF7001118 + ...
         desc_count      = 0x400 = 1024
         清空 1024 个描述符的 ctrl 字段
         aal_ni_set_dma_lso_base_depth_addr(vp, q, desc_phys)
d. of_get_child_by_name("dma_lso_vp10_int") -> irq;  "dma_lso_vp11_int"; "dma_lso_int"
   request_threaded_irq(dma_lso_irq, ca_ni_tx_interrupt, NULL, 0, "dma lso", dev)
e. smp_dispatch_ni_tx_multi_desc_set(1, (num_online_cpus < 4) ? 0 : 3)
```

关键量：**每 VP 8 队列 × 12 VP = 96 个 TX 环，每环 1024 描述符，环形缓冲 8 KiB。**

### 1.6 `rtk_dma_lso_checksum_select` — 名称误导，实为 skb L3/L4 解析器

`rtk_dma_lso_checksum_select @0x1a6470 (nm 0xa6430)`，332 条指令。**它不写任何 DMA 寄存器**（全函数仅 2 个 `strh`，写 `skb+0xB0` / `skb+0xB2`，且都被后续分支覆盖）。真实职责：

- 入参 `struct sk_buff *skb`（`x0`）。
- `ca_ni_parse_l2()` 取 ethertype（大端转小端）。
- 按 ethertype 分派：`0x0800` = IPv4、`0x86DD` = IPv6、`0x8864` = PPPoE session。
- IPv4：`ca_ni_parse_ipv4()`；校验 IHL ≥ 5、非分片（`ip_summed` 的 `CHECKSUM_PARTIAL` 位）；TCP 时取 `doff`，UDP 时取 `udplen`，做边界检查。
- IPv6：`ipv6_skip_exthdr()` / `ipv6_ext_hdr()` 跳过扩展头。
- 副作用（供后续 `ca_ni_get_lso_para0` 复用）：
  - `skb+0xB0` = `skb->transport_header` 相对 `skb->head` 的偏移
  - `skb+0xB2` = `skb->network_header` 偏移
  - `skb+0xAE` = IPv6/UDP 时重新定位的 L4 偏移
- 返回值：`1` = 需要硬件校验和/分段处理；`0` = 不支持（走 `ca_ni_extra_stats_inc(0)` 计数）。

**对 mainline 的意义**：这段逻辑等价于 `skb_checksum_help()` 的判定部分 + `skb_transport_offset()`，不应移植为寄存器操作。

### 1.7 `aal_ni_set_tx_dma_lso_para` — 该符号不存在

全模块 13170 个符号中**没有** `aal_ni_set_tx_dma_lso_para`（`nm | grep -i lso_para` 仅命中 `ca_ni_get_lso_para0.isra.0` 与 `__kstrtab_*` 中的 `aal_ni_set_dma_lso_headerA`）。等价职责分散在：

| 职责 | 实际函数 |
|---|---|
| per-VP header_a（ldpid/fe_bypass） | `aal_ni_set_dma_lso_headerA @0x22123c` |
| per-skb lso_para0（IPv4/IPv6/TCP/UDP/segment_size） | `ca_ni_get_lso_para0.isra.0 @0x1a58f0 (nm 0xa58b0)` |
| 环基址 + 深度（= log2 描述符数） | `aal_ni_set_dma_lso_base_depth_addr @0x106260 (nm 0x6220)` |
| 写指针推进 | `aal_ni_set_tx_write_ptr @0x104dc0`（末条 `dmb oshst`） |

`aal_ni_set_dma_lso_base_depth_addr(vp, queue, phys)`（88 条指令）：

```
 1. write32(base + 0x10C + vp*0xA0, ((phys>>4)<<4) | 0x0A)
 2. write32(base + 0x108 + vp*0xA0, ace ? 2 : 0)
 3. write32(base + 0x104 + vp*0xA0, (queue & 7) | 0xC0000000)
 4. 轮询 base+0x104 直到 bit31 == 0；上限 1,000,000 次（无 delay，纯自旋）
 5. 超时则 printk "indirect access write not finished!!!"
 6. call aal_ni_get_dma_lso_base_depth_addr(vp, queue)   # 回读
```

---

## 2. TX 描述符与 buffer header 位域

### 2.1 环描述符（DMA 环元素，8 字节）

OEM 写入点：`ca_ni_start_xmit_buf.constprop.0 @0x1aabf0 (nm 0xaabb0)`

```c
*(u32 *)(desc_ring + idx*8)     = (u32)phys_addr;      // tx_desc0.wrd
*(u32 *)(desc_ring + idx*8 + 4) = ctrl;                // tx_desc1.wrd
```

`ctrl = (local_50 & 0xFF000000) | (local_50 & 0xFF) | ((buf_len & 0xFFFF) << 8)`

| 位 | 字段 | 值 |
|---|---|---|
| `[7:0]` | DMA 映射状态标志 | 见下 |
| `[23:8]` | **总长度** = `payload_len + hdr_len` | 非 SG 时 hdr_len = 0x10；SG 时 0x18 |
| `[31:24]` | 描述符类型/属性字节 | 普通 `0x61`；SG `0xE0` |

`[7:0]` 取值（`ca_ni_start_xmit_buf` 中 `local_50` 的演化）：

| 值 | 条件 |
|---|---|
| `0x01` | `dma_lso_ace_test == 0` 且 `dma_map_page_attrs()` 返回地址的物理页落在低半区 |
| `0x02` | `dma_lso_ace_test == 1`（走 `virt_to_phys` 路径）且地址有效 |
| `0x03` | 上述路径判定 `iVar30 < 0`（地址无效/需回退） |

**与现有驱动的差异（重大）**：现有 `ni_dma.c` 把 `[31:24]` 固定为 `0x61`（`DMA_DESC_CTRL`）或 `0x61`（OAM，`0x61000000`，低字节 0），
且从不设置 `[7:0]=1/2/3` 的 DMA 映射状态、也从未产生 SG 形态（`0xE0`）。
driver 的 `DMA_DESC_CTRL 0x61000002` 只对应"非 SG + 状态 2"，即 **OEM 的 ACE 路径**。

### 2.2 buffer header（紧邻 payload 之前，16 或 24 字节）

`ca_ni_start_xmit_buf` 中 `puVar28 = param_1 - 0x10`（非 SG）或 `param_1 - 0x18`（SG）。
结构（按 `puVar28` 为基）：

| 偏移 | 宽度 | 成员（OEM 打印名） |
|---|---|---|
| `0x00` | 4 | `lso_para0` |
| `0x04` | 4 | `lso_para1` |
| `0x08` | 8 | `header_a`（`tx_buf->header_a.bits64`） |
| `0x10` | 8 | **非 SG**：`header_cpu`（`tx_buf->header_cpu.bits64`）；**SG**：SG 地址表指针 |
| 合计 | `0x10` / `0x18` | 即 hdr_len |

OEM 自证打印（同函数内）：
```
"\t lso_para0.wrd=0x%x, lso_para1.wrd=0x%x (%d)\n"
"\t tx_buf->header_a.bits64=0x%llx\n"
"\t tx_buf->header_cpu.bits64=0x%llx\n"
```

### 2.3 `lso_para0`（32 bit）—— **完整字段表（打印名即权威）**

字段名与位移取自 `ca_ni_start_xmit_buf` 内的 3 组 `printk`，非推断：

| 位 | 字段 | 典型值 | 来源 |
|---|---|---|---|
| `[13:0]` | `lso_para0.segment_size`（MSS） | 由 MTU/`skb->len` 计算 | `local_14 & 0x3fff` |
| `[15:14]` | 未命名（保留/被保留） | 0 | 掩码 `0xfdffc000` 保留 |
| `[23:16]` | 未命名（保留） | 0 | 同上 |
| `[24]` | `lso_para0.unknown_tag_en` | 0 | `>> 0x18 & 1` |
| `[25]` | **`lso_para0.segment_en`**（TSO/LSO 使能） | 1 | `>> 0x19 & 1`；`ca_ni_get_lso_para0` 无条件置 1 |
| `[26]` | **`lso_para0.ipv4_en`** | 1（IPv4 路径） | `>> 0x1a & 1` |
| `[27]` | **`lso_para0.ipv6_en`** | 1（IPv6 路径） | `>> 0x1b & 1` |
| `[28]` | **`lso_para0.tcp_en`**（TCP csum 卸载） | 1 | `>> 0x1c & 1` |
| `[29]` | **`lso_para0.udp_en`**（UDP csum 卸载） | 1 | `>> 0x1d & 1` |
| `[30]` | `lso_para0.bypass_en` | 0 | `>> 0x1e & 1` |
| `[31]` | `lso_para0.lenfix_en`（长度修正 / 含 trailer） | 0 | `>> 0x1f` |

写入模板（`ca_ni_get_lso_para0` 首段）：
```c
*para0 = (mss & 0x3FFF) | BIT(25) | (*para0 & 0xFDFFC000);
```

`ca_ni_get_lso_para0` 各分支置位（`nm 0xa58b0` / `@0x1a58f0`）：

| 分支 | 置位 |
|---|---|
| IPv4 且 TCP 头合法 | `\|= 0x10000000`（tcp_en） |
| IPv4 且 UDP 且 `udp->check != 0` | `\|= 0x20000000`（udp_en），并**软件预计算 UDP 校验和**写回 `udp->check` |
| IPv4 且检测到 trailer | `\|= 0x80000000`（lenfix_en） |
| IPv4 收尾（`LAB_001a5cf8`） | `\|= 0x04000000`（ipv4_en） |
| IPv6 且 TCP | `\|= 0x08000000`（ipv6_en）；若 `local_1b==0` 再 `\|= 0x18000000`（ipv6_en\|tcp_en） |
| IPv6 且 UDP 且 check≠0 | `\|= 0x20000000`（udp_en） |
| IPv6 收尾 | `\|= 0x08000000` |
| 不支持（非 IPv4/IPv6/PPPoE-IP） | `&= 0xBFFFFFFF`（清 bypass_en） |

`keep_txCon_lsopara` 旁路：`ca_ni_start_xmit_buf` 在
`(*(u64*)(txinfo+0x20) & 0x4000400000000000) == 0x400000000000` 时
**保留调用方给定的 para0**（`local_14 = *(u32*)(txinfo+0x22)`），不重算。

### 2.4 `lso_para1`（32 bit）

只有一处语义明确：`local_10 = ((len & 0x3FFF) << 15)` 的**高 32 位**被 `puVar28[1] = len & 0xFFFF` 覆盖，
因此环内实际写入的 `lso_para1` = `buf_len & 0xFFFF`（OEM 打印 `lso_para1.wrd=0x%x (%d)`，第 3 个参数即 `param_2 & 0xffff`）。

- SG 分支额外把 `((len+8) & 0x3FFF) << 47 | BIT(31)` 合入 64 bit 字，之后仍被 `para1` 覆盖。
- `[31:16]` 语义 **UNKNOWN**（OEM 从不单独置位）。

### 2.5 `header_a`（64 bit）

两种视角，互为验证：

**(a) 发送路径模板**（`ca_ni_start_xmit_buf` 的非 PTP 分支）：

| 位 | 字段 | 写入 |
|---|---|---|
| `[2:0]` | cos / TX 队列号 | `txq_index & 7` |
| `[13]` | UNKNOWN | 当 `uVar16 != 0` 时置 1（`0x2000`） |
| `[17:16]` | `pol_en`（0=off,1=L2,2=L3,3=both） | — |
| `[26:18]` | `pol_id`（9 bit） | `txinfo->field & 0x1FF` |
| `[29:27]` | `pol_grp_id`（3 bit） | `vlan_id & 7` |
| `[31]` | `cpu_flg` | PTP 路径强制 1 |
| `[34:32]` | `cos`（同上，与 `[2:0]` 同一字段的高位视图） | — |
| `[40:35]` | **`ldpid`**（6 bit） | `txinfo->ldpid & 0x3F`；`+8` 变体用于特殊情况 |
| `[46:41]` | **`lspid`**（6 bit） | `txinfo->lspid & 0x3F` |
| `[60:47]` | **`pkt_size`**（14 bit） | `len & 0x3FFF` |
| `[61]` | **`fe_bypass`** | `bypass_fwd_engine & 1` |
| `[63:62]` | **`hdr_type`**（0=UC,1=MC,2=CPU+学习信息,3=PTP） | PTP 时 = 3 |

`header_a` 位名与位移的权威来源：`ca_ni_dump_hdr_a @0x23cc50` 的打印串
`cos(3) / ldpid-mcidx(6) / lspid(6) / pkt_size(14) / fe_bypass / hdr_type / pol_id(9) / pol_grp_id(3) / pol_en`。

**(b) PTP 命令叠加**（`ca_ni_tx_set_hdr_a_ptp_cmd @0x1a4e20 (nm 0xa4de0)`），仅当 `hdr_type == 3`：

| 位 | 字段 | 值 |
|---|---|---|
| `[1:0]` | `cmd_asel` | 0=NO_OP, 1=TS_CORRECT, 2=TS_P_OFFSET, 3=TS_N_OFFSET |
| `[3:2]` | `cmd_op` | 同上语义（打印为 `cmd_op(2)`） |
| `[5]` | `cmd_mode` | 0 = Timestamp mode，1 = Correction mode |
| `[7:6]` | `ptp_type` | 0 = PTP over Ethernet, 1 = CFM, 2 = PTP/UDP/IPv4, 3 = PTP/UDP/IPv6 |
| `[14:8]` | `cmd_offset`（7 bit） | — |
| `[22:16]` | `udp_cksum_offset`（7 bit） | — |
| `[31]` | `cpu_flg` | 强制 1 |
| `[63:62]` | `hdr_type` | 强制 3 |

两处独立反编译（`ca_ni_tx_set_hdr_a_ptp_cmd` 的 `bfi` 序列 与 `ca_ni_dump_hdr_a` 的 `>>` 解码）**逐字段一致**，可信度高。

### 2.6 SG 多段

- 触发：`txinfo->sg != NULL`（`*(u64*)(param_4 + 8) != 0`）。
- 效果：`hdr_len` 0x10 → 0x18；`header_cpu` 槽位改为 **SG 地址表指针**（`*(u64*)(puVar28+4) = *(u64*)(param_4+8)`）。
- `ctrl[31:24]` = `0xE0`；`ctrl[23:8]` = `(len+8) & 0xFFFF`。
- SG 表元素格式、段数上限：**UNKNOWN**（`param_4+8` 指向的结构在本模块内未被解引用解析）。

### 2.7 PPPoE / VLAN tag 插入 / 跳过

经全模块检索，**`lso_para0`/`lso_para1`/`header_a` 中不存在 PPPoE 或 VLAN 插入位域**。OEM 的做法是：

1. **PPPoE**：`ca_ni_get_lso_para0` 对 ethertype `0x8864` 额外偏移 `+8` 找到内层 IP 头
   （`lVar21 + *(u16*)(skb+0xAE)`，`uVar16 = ((ip) + 8) - skb->head`），并校验 `iph->version == 4` 且 `(iph->tos & 0xD0) == 0x40`。
   即 PPPoE 由**软件改偏移**解决，不在描述符里编码。
2. **VLAN / TPID / 802.1p / DEI**：由 **AFT L2FIB 表**在 DMA LSO 内部完成，寄存器入口为
   `aal_ni_set_dma_lso_aft_l2fib_top_vlan @0x222820`、`..._inner_vlan @0x222954`、
   `..._top_vlan_8021p_dei @0x222a98`、`..._inner_vlan_8021p_dei @0x222bdc`、
   `..._top_tpid @0x222d20`、`..._inner_tpid @0x222e54`、`..._pppoe @0x222f78`
   （调试入口 `ni_debug` 命令 3~9，见 §7）。
   这些函数的寄存器偏移/位域**未在本轮展开**（`UNKNOWN`，列为后续 W5 可选任务）。
3. `ca_ni_start_xmit_buf` 中确有一段 `header_a` 低字改写（bits `[29:27]`=vlan 低 3 位、bit8、bit2），
   但字段命名与语义**UNKNOWN**；只能确认它只在 `txinfo` 的某个字节 bit4 置位时执行。

---

## 3. ACE 缓存一致性

### 3.1 配置键与取值

| 键 | `default_scfg.txt` 值 | 行 | ca-ne.ko 是否读取 |
|---|---|---|---|
| `CFG_ID_DMA_LSO_ACE_TEST` | **1** | 789 | **是**：`aal_scfg_read("CFG_ID_DMA_LSO_ACE_TEST",1,&dma_lso_ace_test)`，见 `ca_ni_init_tx_dma_lso @0x1ac100` |
| `CFG_ID_L3QM_ACE_TEST` | **1** | 298 | **否**。`aal_l3qm_init_startup_config @0x159440` 里 `l3qm_ace_test = 1;` 是**硬编码**，该键字符串在模块内不存在 |
| `CFG_ID_NE_SRAM_PHY_BASE` | `0xc0000000` | 129 | 是（`ca_ne_sram_phy_base`） |
| `CFG_ID_NE_DDR_COHERENT_PHY_BASE` | `0x0bc48000` | 130 | 是（`ca_ne_ddr_coherent_phy_base`） |
| `CFG_ID_NE_DDR_NONCACHE_PHY_BASE` | `0x09000000` | 131 | 是（`ca_ne_ddr_noncache_phy_base`） |
| `CFG_ID_L3QM_ACP_ENABLE` | 0 | 293 | 否（模块内无此键；ACP=Accelerator Coherency Port，0=关闭） |

> **结论**：`CFG_ID_L3QM_ACE_TEST` 在本 SDK 的 ca-ne.ko 中**不被读取**，等价行为被硬编码为"始终 1"。
> 若 mainline 侧要保留可配置性，需自行新增参数，不能指望沿用它。
> 数值型 scfg id 观测：`"207"`→cpu_epp attrib, `"208"`→eq attrib, `"249"`→EQ cfg3, `"250"`→EQ cfg4,
> `"515"`→main_hash_bm_test, `"635"`→cpuepp_sram_enable(8 B), `"636"`→dmalso_sram_enable(12 B)。
> 这些数字与 `CFG_ID_*` 名称的对应表**不在本模块内**（UNKNOWN）。

### 3.2 AXI 属性字格式（`RTL_QM_AXI_ATTRIB_*`）

间接访问寄存器组（`g_ne_reg_iobase` 基址）：

| 偏移 | 名称 | 用法 |
|---|---|---|
| `0x66A4` | `ACCESS` | 写 `(entry & 0x3F) \| 0x80000000` = 读；写 `\| 0xC0000000` = 写；bit31 轮询至 0（上限 300 次） |
| `0x66A8` | `DATA1` | 高位扩展 |
| `0x66AC` | `DATA0` | 属性字主体 |

`DATA0` 位域（`aal_l3qm_dump_axi_attrib @0x155620 (nm 0x555e0)` 打印串逐字段给出）：

| 位 | 名称 | 备注 |
|---|---|---|
| `[3:0]` | `qos` | |
| `[7:4]` | `cache` | `RTL_QM_AXI_ATTRIB_CACHE` |
| `[11:8]` | **`snoop`** | 驱动头文件缺此定义 |
| `[13:12]` | **`bar`**（2 bit） | 驱动缺失 |
| `[15:14]` | `domain` | `RTL_QM_AXI_ATTRIB_DOMAIN` |
| `[21:16]` | **`user`**（6 bit） | 驱动缺失 |
| `[24:22]` | **`prot`**（3 bit） | 驱动缺失 |
| `[25]` | `ace_cmd` | `RTL_QM_AXI_ATTRIB_ACE_CMD` |
| `[31:26]` | `axi_top_bit` 低 6 位 | `RTL_QM_AXI_ATTRIB_TOP_BIT` |

**`axi_top_bit` 完整 8 bit** = `((DATA1 & 0x3) << 6) | (DATA0 >> 26)`。
来源：`aal_l3qm_get_cpuepp_axi_attrib @0x1559d0 (nm 0x55990)` 的
`printk("axi_top_bit=0x%x, ace_cmd=%d", (local_8 & 3) << 6 | local_c >> 0x1a, local_c >> 0x19 & 1)`。

- 每 CPU-EPP 属性入口号 = `cpu_port + 0x30`（`uVar1 = param_1 + 0x30`）。
- 每 **EQ** 的 `axi_top_bit` 另有直读寄存器：`g_ne_reg_iobase + (eqid*0x14 + 0x61F8)`，取 `& 0xFF`
  （`aal_l3qm_get_eq_pool_axi_top_8bit @0x155bb0 (nm 0x55b70)`）。
- 写属性：`aal_l3qm_set_epp_axi_attrib @0x1563b0 (nm 0x56370)` —— 先写 `DATA0`，再写 `ACCESS = 0xC0000000 | (entry&0x3F)`，轮询 bit31。

**编译期默认属性值**（`.data 0x17D8`，`l3qm_axi_attrib_cpu_epp_values[8]`，会被 scfg `"207"` 覆盖）：

| 索引 | 值 | qos | cache | snoop | bar | domain | user | prot | ace_cmd | top6 |
|---|---|---|---|---|---|---|---|---|---|---|
| 0,1 | `0x10000004` | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 |
| 2..7 | `0x12808060` | 0 | 6 | 0 | 0 | 2 | 0 | 2 | **1** | 4 |

`0x12808060` 的 `ace_cmd=1` + `domain=2` + `prot=2` + `cache=6` 与"ACE 已使能"一致；
`0x10000004` 无 `ace_cmd`，为对照组。**`l3qm_axi_attrib_eq_values[16]`（`.data 0x1798`）初值全 0，同样由 scfg `"208"` 覆盖。**

### 3.3 `dma_lso_ace_test` 决定的行为差异（实测，非推断）

| 位置 | `ace == 0` | `ace == 1` |
|---|---|---|
| `base+0x0C8` bits[7:0] | 0 | **2** |
| per-VP `+0x08` | 0 | **2** |
| TX 缓冲/描述符内存 | `dma_alloc_attrs(..., GFP 0xCC1)` = coherent | `__ca_malloc` + 手工 `virt_to_phys()` |
| 描述符环可放 SRAM | 否 | 是（受 `l3qm_dmalso_sram_enable[]` 控制） |
| 描述符 `ctrl[7:0]` | `0x01` | `0x02` |
| 启动期 `dma_map_page_attrs()` | 调用 | **不调用** |

> `ace==1` 路径完全绕过 Linux DMA API，用 `virt_to_phys()` + 显式 AXI 属性（`snoop`/`cache`/`ace_cmd`）保证一致性。
> 这正是"OEM 用 ACE 而不是 `dma-coherent`"的证据链：属性字里有 `snoop[11:8]`、`ace_cmd[25]`，而 DTS 里没有 `dma-coherent`。

### 3.4 DTS 是否需要 `dma-coherent`

**不需要，且不应添加。** 证据：

1. 原厂 DTB0 `ethernet@f4300000`（`compatible = "cortina,ni-interface"`）**无 `dma-coherent` 属性**，
   也无 `dma-ranges`；一致性完全由 §3.2 的 AXI 属性表 + 显式 `virt_to_phys()` 保证。
2. 原厂 DTB0 中**只有** `ldma@90301200` / `ldma@90301240`（`cortina,adma`）带 `dma-coherent`。
   这两个是独立 ADMA 引擎，与 NI/DMA-LSO 无关。
3. 现有 mainline `rtk-taurus.dtsi` 的 `ni` 节点同样无 `dma-coherent`——与 OEM 一致，保持原样即可。
4. OEM 改用两块**独立物理窗口**区分一致性：
   - coherent：`0x0BC48000`（`CFG_ID_NE_DDR_COHERENT_PHY_BASE`），reserved `0x1200000`
   - non-cache：`0x09000000`（`CFG_ID_NE_DDR_NONCACHE_PHY_BASE`），reserved `0x2270000`
   两者都作为普通 `reg` 项出现在 OEM DTB 里（`0x00 0xbc48000 0x10000`、`0x01 0x9000000 0x1a50000`）。

### 3.5 与 ARM CCI 的关系

- `CFG_ID_L3QM_ACP_ENABLE = 0`，说明 **ACP 口未启用**；模块内也不存在 ACP 相关代码路径。
- OEM DTB0 未声明 `cci`/`cci-control` 节点；`/soc` 只有 `realtek,taurus`。
- 因此 ACE 属性中的 `snoop`/`domain`/`ace_cmd` 是**总线属性编码**，不是 Linux `dma-coherent` 语义。
- 具体 `domain`/`bar`/`prot` 编码到 ARM ACE 协议的映射，以及 SoC 是否真的接了 CCI-400：**UNKNOWN**
  （无设备树或寄存器证据，不作推断）。

**给 mainline 的建议**：先用 `dma_alloc_coherent()` 走一致映射（当前驱动已如此），
把 `dma_lso_ace_test` 固定为 1（写 `0xC8`/`0x108` = 2），但**不启用** OEM 的 `virt_to_phys` 路径。
只有在实测发现 `dma_alloc_coherent` 与硬件 ACE 属性冲突时，才切到 OEM 路径。

---

## 4. SRAM EQ0 与 FBM 回收池

### 4.1 地址与尺寸

| 项 | 值 | 来源 |
|---|---|---|
| L3QM SRAM 物理基址 | `0xC0000000` | `CFG_ID_NE_SRAM_PHY_BASE`、`CFG_ID_L3QM_SRAM_START_ADDR`（129/137 行） |
| SRAM 保留总尺寸 | `0x40000`（256 KiB） | `CFG_ID_NE_SRAM_RESERVED_SIZE`（132 行） |
| 驱动实际请求尺寸 | **`0x44000`（272 KiB）** | `ca_ni_init_reserved_mem @0x1a1c60` → `aal_l3qm_init_reserved_mem(ca_ne_sram_base, 0x44000, …)` |
| L3QM WAN SRAM buffer | size 128 B × count 1200 = `0x25800` = 153600 | `CFG_ID_L3QM_WAN_SRAM_BUFFER_SIZE/COUNT`；`l3qm_eq_sram_wan_total_size` `.data 0x1788 = 0x00025800` |
| L3QM LAN SRAM buffer | size 512 B | `CFG_ID_L3QM_LAN_SRAM_BUFFER_SIZE` |
| `l3qm_eq0_sram_eq1_dram` | **1**（EQ0 在 SRAM，EQ1 在 DRAM） | `.data 0x178C = 1`；`CFG_ID_L3QM_EQ0_SRAM_EQ1_DRAM = 1` |
| 另一 SRAM 窗口（L2TM/LAN DQ） | `0x80000000`，size `0x3C000` | OEM DTB0 `reg` 项；`QM_LAN_DQ_SRAM_BASE = 0x80000000` |

> **注意 `0x44000` vs `0x40000` 的差**：驱动请求 272 KiB 而配置只保留 256 KiB。
> `aal_l3qm_init_reserved_mem` 内有硬性检查并在越界时 `SoftwareBreakpoint(0x800)`（即 `BUG()`）：
> `if (param_2 < uVar9) { printk(...); BUG(); }`。**mainline 移植时必须用 0x40000 或先把配置改大**，否则板级会 panic。

### 4.2 SRAM 撞针分配器（`aal_l3qm_init_reserved_mem @0x159b00`）

```
sram_start_virtual_addr = param_1              # ca_ne_sram_base (ioremap VA)
sram_dts_conf_size      = param_2              # 0x44000
sram_cur_used_size     += uVar9                # 已用
sram_cur_virtual_addr   = param_1 + uVar9
```

按顺序切分（每段前插 `l3qm_magic_marker_len/4` 个 `0xDEADBEEF` 魔术标记做越界检测）：

1. `l3fe_main_hash_overflow_hash_fib`（`param_1 + 0x80` 起）
2. `l3fe_main_hash_default_hash_fib`（若 `…_internal_reg_mode == 0`）
3. `l3fe_main_hash_action_cache_fib`（若 `…_internal_sram_mode == 0`）
4. 其后全部剩余空间交给 **DMA LSO TX 描述符环**（`ca_ni_init_tx_dma_lso` 的 `sram_cur_* += 0x2000`）

**对齐约束**：
- 每段起点只按 `0x80` 偏置 + 前序长度累加，**无额外对齐**；
- 但描述符环要求 `base` 按环大小对齐——由 `set_dma_lso_base_depth_addr` 的 `((phys>>4)<<4)` 与 `bits[3:0]=log2(N)`
  共同隐含：**环基址必须 `N*8` 字节对齐**（1024 描述符 → **8 KiB 对齐**）。
  `ca_ni_init_tx_dma_lso` 每次 `+0x2000` 正好满足。

### 4.3 FBM 池

**已确认**：

1. EQ 配置字（`g_ne_reg_iobase + 0x61EC + eqid*0x14` 段）含 **`fbm_pool_id` 字段 bits[6:4]**：
   `aal_l3qm_init_empty_buffer` 中 `local_4c & 0xf | (l3qm_eq_profile_cpu_pool0_fbm_pool_id & 7) << 4`（`aal_l3qm_init_empty_buffer @0x156b90 / nm 0x56b50`）。
2. 每 EQ 段的 **buffer count 在 bits[29:16]**：
   `ca_ni_fill_eq_buf_pool @0x1a2500 (nm 0xa24c0)` 读 `*(u16*)(… + eqid*0x14 + 0x61EC) >> 0x10 & 0x3FFF`。
3. 配置里 CPU 池的 FBM 归属：
   | 键 | 值 |
   |---|---|
   | `CFG_ID_L3QM_EQ_PROFILE_CPU_USE_FBM` | **0** |
   | `CFG_ID_L3QM_EQ_PROFILE_CPU_POOL0_FBM_POOL_ID` | 6 |
   | `CFG_ID_L3QM_EQ_PROFILE_CPU_POOL1_FBM_POOL_ID` | 7 |
   | `CFG_ID_L3QM_EQ_PROFILE_PE0_USE_FBM` | 1 |
   | `CFG_ID_L3QM_EQ_PROFILE_PE1_USE_FBM` | 0 |
   | `CFG_ID_L3QM_USE_FBM` | `0x00`（全局关） |
4. `ca_ni_init_fbm @0x1a2670 (nm 0xa2630)` 在本板上**只打印不配置**：
   因为 `ca_ni_cpu64_use_fbm == 0`，函数体整段 `if` 被跳过；实际只做
   `aal_l3qm_eq_get_cpu_pool0_info()` / `pool1_info()` 的日志（`virt/phy/entry_size/entry_count/fbm_pool_id`）。
5. `aal_l3qm_eq_get_cpu_use_fbm @0x155c60` 仅返回 `.bss` 里的 `l3qm_eq_profile_cpu_use_fbm`。

**UNKNOWN（重要）**：
- **FBM 空闲链表的描述符格式与本模块无关**——`ca-ne.ko` 内没有任何 FBM free-list 读写；
  回收/分配全部在硬件（L2TM/L3QM 的 buffer manager）。本模块只做"池号 + 数量 + 起始 BID"的静态配置。
- `l3qm_eq_profile_cpu_pool0_buf_count` 与 `…_pool0_bid_start` 的 BID 空间是全局共享还是每池独立：**UNKNOWN**。
- `CFG_ID_L3QM_USE_FBM = 0x00` 与 `PE0_USE_FBM = 1` 并存的生效语义：**UNKNOWN**（未在代码中找到仲裁逻辑）。

---

## 5. 与现有 `ni_dma.c` / `ni_qm.c` 的缺口清单

### 5.1 已正确、无需改动（本轮核对）

| 项 | 驱动值 | OEM 证据 |
|---|---|---|
| DMA 基址 | `0xf7001000` | DTB0 + `aal_ni_set_tx_write_ptr` 负常数 |
| `DMA_CTRL 0x000` 最终值 | `DMA_CTRL_RUN = BIT(0)\|(3<<2)\|BIT(4)` = **`0x1D`** | OEM 写 `0x2D` 后 `rtk_*` 清 bit5 置 bit4 → `0x1D` **完全一致** |
| `DMA_AXI_CONFIG 0xD80` | `0x7AFF`, mask `GENMASK(14,0)` | OEM `0x7AFF`，已知掩码 `0x7FFF` |
| `DMA_AFT_CTRL 0xF00` | `(64<<4)\|BIT(0)` = `0x401` | OEM 同值 |
| `DMA_VP_BASE_ACCESS 0x004` | `BIT(31)\|BIT(30)` + 轮询 bit31 | OEM `queue\|0xC0000000` + 轮询 |
| `DMA_VP_BASE_HIGH 0x008` = 2 | 2 | OEM `ace?2:0`，实测 ace=1 |
| `DMA_VP_HEADER_A 0x078` | `(CPUPORT<<3)\|BIT(9)` | `aal_ni_set_dma_lso_headerA`：`(ldpid&0x3F)<<3 \| (febypass&1)<<9` **一致** |
| VP 号 = 8 | `RTL_NI_DMA_VP 8` | `ca_ni_dmalso_vp_sel[7] = {8,1,2,3,4,10,11}`，CPU0 → **VP8** **一致** |
| 读/写指针偏移 | WRITE `0x18` / READ `0x1C` | OEM `0xF7001118` 写 / `0xF700111C` 读 **一致** |
| 描述符 8 字节 `{addr, ctrl}` | 一致 | §2.1 |
| `ctrl[31:24]=0x61`、`ctrl[23:8]=len<<8` | `DMA_DESC_CTRL 0x61000002` | 一致（仅覆盖 ace 非 SG 形态） |
| 环深度编码 | `\| RTL_NI_DMA_ORDER(6)`，64 项 | `bits[3:0] = log2(N)` **一致** |
| `ni_qm.c` EQ cfg0..cfg4 写序 | 先 1/2/3/4 后 0 | `aal_l3qm_init_empty_buffer` 同序 |

### 5.2 缺口（按风险排序）

| # | 缺口 | 现有代码 | OEM 事实 | 风险 |
|---|---|---|---|---|
| **G1** | `0x018 / 0x020 / 0x024` 未写 | 只写 `0x01C` | 四个都写 `0x02008080` | 高：`0x018/0x020/0x024` 可能是其它 AXI user pattern，缺失可能让某类事务丢属性 |
| **G2** | per-VP `+0x00`（VP_CONTROL）只置 bit0 | `writel(BIT(0), vp+DMA_VP_ENABLE)` | 12 VP 全部写 `0xFF`（8 队列全开） | 中：单队列可工作，但多队列/多 CPU 扩展会踩坑 |
| **G3** | 描述符环只有 64 项 | `RTL_NI_DMA_ORDER 6` | **1024 项**（`0x2000/8`），9.6 万描述符总量 | 中：突发下 ring full → `-ENOSPC` / 丢包 |
| **G4** | 只有 1 个 TX 环（VP8/q0） | `RTL_NI_DMA_VP 8` 硬编码 | 12 VP × 8 队列 = 96 环，按 `ca_ni_dmalso_vp_sel[cpu%7]` 选 VP | 中：单核可用，多核 TX 会全部挤在一个环 |
| **G5** | `ctrl[7:0]` DMA 映射状态位未实现 | 恒 `0x02` | `0x01`（非 ACE）/`0x02`（ACE）/`0x03`（回退） | 中：非 ACE 路径下 `0x02` 属状态错配 |
| **G6** | SG 形态未实现 | 无 | hdr_len 0x18、`header_cpu` 槽位换 SG 指针、`ctrl[31:24]=0xE0` | 低-中：当前用 `skb_copy_bits` 单段拷贝可绕开 |
| **G7** | 无 LSO/TSO 与 TX 校验和卸载 | 无（`skb_copy_bits` + 无 csum） | `lso_para0` 11 个字段 + 软件 UDP 预计算 | **高，但这是 W5 的主目标** |
| **G8** | header_a 仅写 `(ldpid<<3)\|BIT(9)` | 同 | 还需 `pkt_size[60:47]`、`lspid[46:41]`、`cos[2:0]`、`hdr_type[63:62]`、`fe_bypass[61]` | 高：缺 `pkt_size` 可能让 HW 长度判定错误 |
| **G9** | `rtk_dma_lso_checksum_select` 无对应 | 无 | skb L3/L4 偏移解析 + `skb+0xB0/0xB2` 缓存 | 高（G7 的前置） |
| **G10** | SRAM 描述符环未用 | 全 DDR | `l3qm_dmalso_sram_enable[12]` 位图按队列放 SRAM | 低：可选优化 |
| **G11** | `DMA_SS_CTRL 0x900` 多置了 `BIT(VP)` | `BIT(31)\|BIT(RTL_NI_DMA_VP)` | OEM 只置 `BIT(31)` | 低：需 A/B 验证 |
| **G12** | `0x014` AXI_USER_SEL 只设本 VP | 仅本 VP 2 bit = 1 | 全部 12 字段 = 1（`0x55555555`） | 低-中 |
| **G13** | 无 `+0x160/+0x170` 状态读取与清除 | 只清 `+0x168` bit0 | 三个状态寄存器都要读清 | 低：影响中断风暴定位 |
| **G14** | 无 `DMA_SEC_DMA_GLB_DMA_LSO_DEBUG0(0x50)` stuck 检测 | 无 | `(v>>4)&0xF == 5` ⇒ DMA stuck ⇒ `ca_ni_dma_lso_reset()` | 低：可诊断性 |
| **G15** | 无 12 VP 中断（`dma_lso_vp10_int`/`vp11_int`） | 仅 `ni` 单 IRQ | OEM 三个 IRQ + `request_threaded_irq` | 低：单队列用不到 |

### 5.3 当前驱动 TX 描述符 vs 硬件描述符格式的差异（明确结论）

现有驱动把**两种不同的硬件结构压成了一个**：

1. **环描述符**（8 B）：驱动 `struct rtl_ni_dma_desc { __le32 addr; __le32 ctrl; }` —— **格式正确**。
2. **buffer header**（16/24 B）：驱动把它折叠进"每描述符独立的 16 字节前缀"，内容为
   ```c
   put_unaligned_le32(len,       buf + 4);   // ← OEM 这里是 lso_para1 = buf_len
   put_unaligned_le32(frame->header_high, buf + 8);
   put_unaligned_le32(low,       buf + 12);
   ```
   而 OEM 的实际布局是 `[0]=lso_para0, [4]=lso_para1, [8..15]=header_a(64bit)`，**且 `[0]` 必须是 `lso_para0`**。

   ⇒ **驱动把 `len` 写到了 OEM 的 `lso_para1` 位置，`buf+0` 恒为 0（被 memset）**，
   即 OEM 的 **`lso_para0` 从未被写入**。当前之所以能发包，是因为 `lso_para0 = 0` 恰好等于
   "segment_en=0 / 所有 offload 关闭" 的合法值。

   ⇒ 一旦要实现 LSO/TSO/CSUM，**必须**把 `lso_para0` 放到 `buf+0`，
   并把 `header_a` 作为 64 bit 写到 `buf+8`（驱动目前是拆成两个 32 bit `header_high`/`header_low`，且顺序为 `high` 在前）。

3. **`header_a` 的 32/64 bit 分工**：驱动用 `header_high`/`header_low` 两个 32 bit 字段，
   而 OEM 是单个 64 bit 字，且 `ldpid` 在 `[40:35]`（跨越两个 32 bit 半字）。驱动的 `header_high`/`header_low`
   命名与 OEM 的 `lso_para0/lso_para1` **没有对应关系**，属独立发明，需重写。

---

## 6. 建议的分步开启顺序与 A/B 回退开关

原则：**每一步都能用模块参数一键回到上一步**，且失败不 panic。

| 步 | 内容 | A/B 开关（模块参数） | 默认 | 回退动作 |
|---|---|---|---|---|
| S0 | 保持现状（单环、无 offload），仅补齐 G1/G11/G12 的寄存器初值 | `regs_strict=0\|1` | 0 | `0` 时用现有 `ni_dma.c` 原值 |
| S1 | 修正 buffer header 布局：`buf+0=lso_para0(=0)`, `buf+4=lso_para1(=len)`, `buf+8=header_a(64b)` | `hdr_layout=oem\|legacy` | `legacy` | 切回 `legacy` |
| S2 | 补 `header_a` 的 `pkt_size/lspid/cos/hdr_type`（G8） | `hdr_a_full=0\|1` | 0 | `0` 只写 `ldpid\|fe_bypass` |
| S3 | 移植 `rtk_dma_lso_checksum_select` 等价逻辑（G9），仅**判定**不外理 | `tx_csum_sel=0\|1` | 0 | — |
| S4 | IPv4 + TCP/UDP 校验和卸载（`para0.tcp_en/udp_en/ipv4_en`），UDP 走软件预计算 | `tx_csum=0\|1` | 0 | 关掉后回 `skb_checksum_help()` |
| S5 | `segment_en` + `segment_size`（TSO），先只开 IPv4/TCP | `tso=0\|1`，`tso_mss_max=1460` | 0 | 关闭即回 S4 |
| S6 | IPv6 路径（`ipv6_en`，含 `ipv6_skip_exthdr`） | `tso_v6=0\|1` | 0 | — |
| S7 | 环扩到 1024 项（G3）；`RTL_NI_DMA_ORDER 6→10` | `ring_order=6\|10` | 6 | — |
| S8 | 多队列（每 VP 8 队列）+ `ca_ni_dmalso_vp_sel[]` 多核选 VP（G2/G4） | `tx_queues=1\|8` | 1 | — |
| S9 | SG 多段（G6） | `tx_sg=0\|1` | 0 | — |
| S10 | SRAM 描述符环（G10，需 DTS 增加 `0xc0000000` 窗口） | `tx_ring_sram=0\|1` | 0 | — |

**顺序理由**：
- S1 是所有 offload 的地基（`lso_para0` 必须在 `buf+0`），必须先做且零行为变化。
- S3 是 S4/S5 的前置判定器；S4 再 S5，因为 TSO 依赖 csum 字段正确。
- S7/S8 是性能项，与 offload 正交，可最后做。
- S10 需改 DTS（OEM DTB 都未映射 `0xc0000000`），风险独立，放最后。

**必须同时修的板级硬约束**：`aal_l3qm_init_reserved_mem` 要求 SRAM 尺寸 ≥ 实际用量，
而 `CFG_ID_NE_SRAM_RESERVED_SIZE = 0x40000` < 驱动传入的 `0x44000`。mainline 若照搬 `0x44000` 会在启动期 `BUG()`。

---

## 7. 附录

### 7.1 关键函数地址索引

| 函数 | Ghidra/REA | nm 节内 |
|---|---|---|
| `aal_ni_init_tx_dma_lso` | `0x1047c0` | `.text 0x4780` |
| `rtk_ni_init_tx_dma_lso` | `0x22118c` | `.text.unlikely 0x9c0` |
| `aal_ni_set_dma_lso_headerA` | `0x22123c` | `.text.unlikely 0xa70` |
| `aal_ni_dma_lso_dump_registers` | `0x221404` | `.text.unlikely 0xc38` |
| `ca_ni_init_tx_dma_lso` | `0x1ac100` | `.text 0xac0c0` |
| `aal_ni_set_dma_lso_base_depth_addr` | `0x106260` | `.text 0x6220` |
| `aal_ni_get_dma_lso_base_depth_addr` | `0x106100` | `.text 0x60c0` |
| `aal_ni_get_dma_lso_interrupt_status` | `0x105c90` | `.text 0x5c50` |
| `aal_ni_wait_dma_lso_misc_interrupts` | `0x106570` | `.text 0x6530` |
| `aal_ni_clear_dma_lso_misc_interrupts` | `0x1063c0` | `.text 0x6380` |
| `aal_ni_set_tx_write_ptr` | `0x104dc0` | `.text 0x4d80` |
| `aal_ni_get_tx_read_ptr` | `0x104140` | `.text 0x4100` |
| `ca_ni_tx_dma_lso_readwrite_ptr_reset` | `0x1a8950` | `.text 0xa8910` |
| `rtk_dma_lso_checksum_select` | `0x1a6470` | `.text 0xa6430` |
| `ca_ni_get_lso_para0.isra.0` | `0x1a58f0` | `.text 0xa58b0` |
| `ca_ni_start_xmit_buf.constprop.0` | `0x1aabf0` | `.text 0xaabb0` |
| `ca_ni_tx_set_hdr_a_ptp_cmd` | `0x1a4e20` | `.text 0xa4de0` |
| `ca_ni_dump_hdr_a`（静态） | `0x23cc50` | — |
| `ca_ni_init_fbm` | `0x1a2670` | `.text 0xa2630` |
| `ca_ni_fill_eq_buf_pool` | `0x1a2500` | `.text 0xa24c0` |
| `ca_ni_init_l3qm` | `0x1a1ca0` | `.text 0xa1c60` |
| `ca_ni_init_reserved_mem` | `0x1a1c60` | `.text 0xa1c20` |
| `aal_l3qm_init_startup_config` | `0x159440` | `.text 0x59400` |
| `aal_l3qm_init_reserved_mem` | `0x159b00` | `.text 0x59ac0` |
| `aal_l3qm_init_cpu_epp` | `0x158eb0` | `.text 0x58e70` |
| `aal_l3qm_get_ace_test` | `0x1559c0` | `.text 0x55980` |
| `aal_l3qm_get_cpuepp_axi_attrib` | `0x1559d0` | `.text 0x55990` |
| `aal_l3qm_get_eq_pool_axi_top_8bit` | `0x155bb0` | `.text 0x55b70` |
| `aal_l3qm_set_epp_axi_attrib` | `0x1563b0` | `.text 0x56370` |
| `aal_l3qm_dump_axi_attrib` | `0x155620` | `.text 0x555e0` |
| `aal_l3qm_axi_reo_rd_init` | `0x1568a0` | `.text 0x56860` |
| `aal_l3qm_axi_reo_wr_init` | `0x156970` | `.text 0x56930` |
| `aal_l3qm_eq_get_cpu_use_fbm` | `0x155c60` | `.text 0x55c20` |

### 7.2 `ni_debug` 调试命令（AFT L2FIB 相关，供后续逆向入口）

`1` 打印 DMA LSO 寄存器；`2` dump AFT L2FIB；`3` top vlan；`4` inner vlan；
`5` top dei/8021p；`6` inner dei/8021p；`7` top tpid；`8` inner tpid；`9` pppoe session id；`10` clean。
（来源：模块内 `.rodata` 帮助串。）

### 7.3 与既有 scratch 结论的差异记录

- `extra_regs_spec.txt` / `regs_audit_spec.txt` 若把 `0xf7001900` 当作独立块 → **错误**，它是 `base+0x900`（`DMA_SS_CTRL`）。
- 若把 `DMA_VP_IRE_ENABLE 0x64` 与 `+0x160` 混为同一寄存器 → **错误**，`0x160` 是状态、`0x164` 是使能。

---

## 8. 仍未确认（UNKNOWN 清单）

1. `lso_para1[31:16]` 的语义；SG 地址表元素格式与最大段数。
2. `lso_para0[23:14]`（掩码保留区）是否有隐藏字段；`unknown_tag_en(bit24)` 的实际触发条件。
3. `DMA_SEC_DMA_LSO_VP_TXQ_BASE_DEPTH_DATA1` 除 `0/2` 之外是否还有其它合法编码（ACE 属性全集）。
4. `0x018 / 0x020 / 0x024` 三个 AXI user pattern 寄存器的确切名称与作用域。
5. AXI 属性字 `domain / bar / prot / snoop` 到 ARM ACE 协议的映射，及 SoC 是否实际接 CCI-400。
6. `header_a` 中 VLAN 相关低字改写（bits `[29:27]`、bit8、bit2）的字段语义。
7. FBM 空闲链表/回收描述符格式（本模块无相关代码，全在硬件）；`CFG_ID_L3QM_USE_FBM=0` 与 `PE0_USE_FBM=1` 的仲裁语义。
8. AFT L2FIB 表（VLAN/TPID/PPPoE 插入）的寄存器位域（7 个 setter 已定位，未展开）。
9. `CFG_ID_L3QM_ACE_TEST` 与 numericscfg id（`207/208/249/250/515/635/636`）到 `CFG_ID_*` 名称的映射表。

---

*本文所有值均来自 `ca-ne.ko` 反编译/反汇编、`default_scfg.txt` 或原厂 DTB0，未做任何推断性填充；推断项已标 `[INFERRED]`，未确认项已标 `UNKNOWN`。*