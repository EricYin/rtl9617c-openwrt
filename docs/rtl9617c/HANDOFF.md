# PT1500-H10 (RTL9617C) 硬件能力项目 —— Agent 交接文档

> 交接时间：2026-11-22
> 当前状态：**静态语料可做的部分已完成并提交；剩余三项被外部条件阻塞，目标已标记 blocked。**
> 接手前请先读 §0 的“不要做什么”，再按 §8 的顺序继续。

---

## 0. 一句话现状

- Phase 0 三份规格书、Phase 1（TRNG/Baby Jumbo/QoS/GRE/DSCP/mirror/LuCI）、Phase 2 寄存器核心层、FE `FLOW_ACTION_POLICE`、Host Policing 32 条 L3 模型、DoS 最终 16-bit 类型表、NAPT6 371-bit 打包器、Dual-Header 表/模板/EIF 仲裁都已提交。
- **编译门禁全绿**：55 个对象强制重编 0 error / 0 warning；11 个 Python 宿主测试 + 2 个 ASan/UBSan C 测试全部 PASS。
- **没有任何实机验证**。所有上板行为（丢包、限速、MIB、DS-Lite 封装、NAPT6）都未测。
- 主仓与发版仓已同步，仅保留已知的 `651-netfilter-flowtable-vlan-used-keys.patch` 差异。

**不要**把“raw/debugfs 已实现”说成“功能已生效”。尤其是：
- NAPT6 只有打包器和前缀表，**没有切换全局模式、没有安装 flow**；
- Dual-Header 只有表/模板/解析/clear-on-free，**flow install 仍显式拒绝**；
- Host Policing 只有 L3 模式；share-meter 模式没有实现；
- DoS 只有 `udp_bomb` 的 type_en bit 4 是推导项。

---

## 1. 工作区、仓库与构建树

| 用途 | 路径 |
|---|---|
| 主仓（开发） | `/home/crysister/pt1500-refactor-build` |
| 发版仓（ImmortalWrt 镜像） | `/home/crysister/pt1500-immortalwrt-build` |
| 分支 | `pt1500-auth-pir-20261119` |
| 内核构建树 | `/home/crysister/pt1500-refactor-build/build_dir/target-aarch64_cortex-a53_musl/linux-rtl9617c_generic/linux-6.18.64` |
| 交叉工具链 | `/home/crysister/pt1500-refactor-build/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl/bin/aarch64-openwrt-linux-musl-` |
| 原始计划书 | `/home/crysister/.gemini/antigravity/brain/b5d386d9-2a78-471e-a963-f27aaa1785dd/implementation_plan.md` |
| 证据规格（主仓内） | `docs/rtl9617c/specs/` |
| Windows 侧 OEM 模块副本 | `C:\rea\*.ko` / `/mnt/c/rea/*.ko` |

Windows 命令统一用：
```powershell
wsl.exe -d Ubuntu-24.04 -- bash -lc '<command>'
# 需要 root 读 0700 文件时：
wsl.exe -d Ubuntu-24.04 -u root -- bash -lc '<command>'
```

**WSL 包装器的坑**：`bash -lc` 里做 `for f in ...; do ... "$f"; done` 这类变量引用有时会被吞掉（表现为只打印表头、路径为空）。可靠做法是写一个 `/tmp/*.sh` 或 `/mnt/c/rea/*.sh`，再 `bash` 它；或者全部用字面绝对路径。

---

## 2. 提交清单（从旧到新）

### Phase 1
| Commit | 内容 |
|---|---|
| `c7f162fbf7` | TRNG、Baby Jumbo 1536、`FLOW_ACTION_PRIORITY`→8-VoQ、GRE 透传、6-bit DSCP 重标、L3PE 流镜像 |
| `2a57f50e11` | LuCI：熵源、MTU/Baby Jumbo、流表 CoS/协议、资源槽位 |
| `360444a2bd` | 桥接流不再显示 `proto=0` |

### Phase 2 核心
| Commit | 内容 |
|---|---|
| `d3b760e002` | OEM TX header（`lso_para0@+0`/`lso_para1@+4`/`header_a@+8`）、L3TE 256 流+64 组 Policer/WRED/DoS 寄存器层、MCGID/MCE/ARB FIB 组播表 |
| `8d2529c403` | FE `FLOW_ACTION_POLICE` → L3TE 槽位，全生命周期归还，`pol=<slot>`/`pol=-1` |
| `4df5575ea6` | `tx_csum`/`tso`/`tso_v6` 默认关闭的 TX 校验和与 IPv4 TCP LSO；`hdr_a_full` 默认改 0；复核 `lso_para1` 是 payload 长度 |

### DoS
| Commit | 内容 |
|---|---|
| `955e1cbdc5` | L3/L2 DoS 寄存器镜像、masked blit、flood/trap/drop、候选类型表 |
| `e3a945134b` | **最终 16-bit type→bit 表**替换候选表（`cli-drv.ko` + `ca-rtk.ko` 证据） |

### Host Policing
| Commit | 内容 |
|---|---|
| `6637166d98` | 96 条 fc_mgr 模型（**已被 `9ed135c1d5` 取代，不要在这上面继续**） |
| `d0c79c9268` | Host Policing 槽位绑定到 L3 FE 流（borrowed slot 不 free） |
| `9ed135c1d5` | **修正为 fc_8277c 32 条 / 32 vmeter 模型**（当前有效） |

### NAPT6 / Dual-Header
| Commit | 内容 |
|---|---|
| `7cb1603347` | NAPTV6 371-bit action 打包 + NPT6 前缀表 16 条（raw/debugfs） |
| `94a13b8208` | Dual-Header Content/Control/FMR 表管理 |
| `481f7300d3` | DS-Lite/6RD Content 模板、6RD/MAP-T Control 修正、clear-on-free、ENC 解析（install 仍拒绝） |
| `5cca58591f` | EIF 32..63 别名仲裁/refcount（纯软件） |

### 文档
| Commit | 内容 |
|---|---|
| `93d4a49e57` | Phase 0 三份规格书落入 `docs/rtl9617c/specs/` |
| `cdace904fe` | 回归测试清单与范围 |
| `84f3b8d8fd` | Host Policing / DoS / NAPT6 / Dual-Header 证据 |
| `c4cc7924fb` | 最终 DoS / Host Policing / extra-tag+NAPT6 证据 |
| `a4b10e37cc` | ACL key/FIB 证据（RE-12） |

当前功能 HEAD 为 `5cca58591f`（EIF 仲裁）；本交接文档的提交在其之后。如果接手时 HEAD 不同，先 `git log --oneline -20` 核对（至少应包含 `5cca58591f`）。

---

## 3. 关键代码地图

```
target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/
├── fe/
│   ├── fe_main.c        FE flow 解析/install/delete、police、hostpol 绑定、mirror
│   ├── fe_hw.c/.h       FE 表/action 寄存器、RTL_FE_ACTION_*、POL 位
│   ├── fe_priv.h        struct rtl_fe / rtl_fe_flow / rtl_fe_rule
│   ├── fe_mcast.c/.h    MCGID/MCE/ARB FIB；MDB 仅软件映射（未下发硬件）
│   ├── fe_tunnel.c/.h   Content/Control/FMR、DS-Lite/6RD、clear-on-free、EIF 仲裁、tunnel debugfs
│   └── fe_napt6.c/.h    NAPTV6 371-bit 打包、NPT6 前缀表、napt6 debugfs
├── ni/
│   ├── ni_te_flow.c/.h  L3TE policer/WRED、DoS、HostPolicing、te_flow/hostpol/dos debugfs
│   ├── ni_dma.c/.h      TX DMA、OEM header、tx_csum/tso
│   ├── ni_port.c        netdev features、GSO 门禁、xmit
│   ├── ni.h             共享结构/宏（TX offload、hostpol API 等）
│   └── ni_main.c        probe/remove 接线（rtl_fe_create(&ni->te)、te_flow_init/exit）
├── Makefile             fe/fe_tunnel.o、fe/fe_napt6.o 已加入
└── dts/rtl9617c-pt1500-h10-2p5g.dts   TRNG/Baby Jumbo

package/rtl9617c/rtl9617c-pon-control/tests/
├── fe-eif-owner.py
├── puc-token-buckets.py
├── tx-dma-layout.py
├── te-policer.py
├── te-police-flow.py
├── mcast-pool.py
├── tunnel-table.py
├── dos-table.py
├── hostpol.py
├── hostpol-flow.py
├── napt6-table.py
├── oam-auth.c / oam-flags.c（ASan/UBSan 基线）
└── ...
```

### 关键模块参数（`/sys/module/rtl9617c_ni/parameters/`）

| 参数 | 默认 | 作用 |
|---|---|---|
| `hdr_layout_oem` | 1 | OEM TX header 布局；S1 与旧编码字节等价 |
| `hdr_a_full` | **0** | header_a 全字段；开 1 会改 OMCI 补齐帧 `pkt_size` |
| `tx_csum` | **0** | TX IPv4/IPv6 TCP/UDP 校验和卸载 |
| `tso` | **0** | IPv4/TCP LSO；单 buffer 上限 2032 B |
| `tso_v6` | **0** | IPv6/TCP LSO |
| `clear_on_free` | true | Dual-Header free 时清硬件条目 |
| `dual_hdr` | **false** | Dual-Header ENC 解析；install 仍拒绝 |

### debugfs 节点

- TE：`/sys/kernel/debug/rtl9617c_te/{te_flow,hostpol,dos}`
- FE：`fe->debugfs` = `debugfs_create_dir(dev_name(fe->dev), NULL)`，运行时先 `ls /sys/kernel/debug` 找到实际目录；节点包括 `flows`、`mirror`、`mcast`、`tunnel`、`napt6`。

常用：
```sh
cat /sys/kernel/debug/rtl9617c_te/hostpol
cat /sys/kernel/debug/rtl9617c_te/dos
cat <fe-debugfs>/tunnel
cat <fe-debugfs>/napt6
cat <fe-debugfs>/flows
```

---

## 4. 已验证的事实（不要重复踩坑）

### 4.1 DoS

- `dos_type_en`：L3 `0x3304[31:16]` **16 bit**；L2 `0x1228[15:0]`。
- 16 类型 = CLI 序：`icmp_flood`=0 … `smac_eq_dmac`=15。
- 每类型：9-bit `pol_id` + 1-bit enable；仅 icmp/fin/syn_flood 有 16-bit `th`。
- 使能**双写**：per-type enable + `dos_type_en` 的 `BIT(k)`。
- trap/drop：`reserved[10]`、`t0[11]` 1 bit、`t1..t5=[15:12]/[19:16]/[23:20]/[27:24]/[31:28]`。
- L3 flood count 11 bit（OEM 内部 10/11 bit 矛盾已注释）。
- **唯一推导项**：`udp_bomb` 的 type_en bit 4（DAL 不支持该类型，位号空缺）。设备校准：`type-en 0xffff` 后逐类型开关，读回差集。

### 4.2 Host Policing（当前有效模型）

- **32 条** MAC 表项，控制结构 36 B。
- **32 个 vmeter（0..31）→ POL1 `0xA0+v`（160..191）**。
- 仅计数方向：ingress `0xC0+idx`（192..223）、egress `0xE0+idx`（224..255）。
- flow policer 只能用 `0..159`；`0xA0..0xFF` 在 `te->flow_slots` 中保留。
- 速率 kbps/500、CIR=PIR、`0x1F3FFFF` 哨兵；不写 CBS/PBS。
- MIB：`aal_l3_te_pm_policer_flow_get(0, pol1, buf)` 用 **`buf[2]-buf[3]`（32-bit）**；清计数不写 `0x9138`。
- G3 决策：ingress 限速 > egress 限速 > egress MIB 槽；FE 已接 `rtl_te_hostpol_lookup()`。
- `6637166d98` 的 96 条/2 槽模型是 fc_mgr 分支，**已废弃**，不要回退。

### 4.3 NAPT6

- 371-bit 布局（ACTGRP `0x0114000a`），12 word/48 B，75 字段；`ip_addr_napt6` 在 bit 129。
- `default_scfg.txt`：
  - `CFG_ID_L3FE_MAIN_HASH_ACTION_TABLE_ENTRY_LENGTH = 48`
  - `CFG_ID_L3FE_MAIN_HASH_ACTION_TABLE_ENTRY_COUNT = 65536`
  - `CFG_ID_L3FE_MAIN_HASH_FLOW_ACTION_GRP24_SUPPORT = 0`
- `aal_hash_action_mode_set` 存在且导出，但闭源集合中**无调用者**；切换会让整张 action 表换 371-bit 布局。
- 未启用、未安装 flow、未写 `0x35E8/0x35EC..`。

### 4.4 Dual-Header

- DS-Lite Content：word0 `0x00000060`、word1 `0xFFFF0400`、src word2..5、dst word6..9。
- 6RD Content 全零；6RD Control 修正为 `0801FEC0 FCFFCA00 453F9001 01401FE0`。
- MAP-T `inr_to_out_fld=0x80`。
- clear-on-free：Content/Control 16 word 清零，FMR 16 word `0xFFFFFFFF`，先 Control 后 Content。
- EIF：`phys = hash<32 ? hash : 16+(hash&0xF)`；32..63 与 16+x/48+x 共享物理行；已实现纯软件 refcount 仲裁，未接 flow。
- **install 仍拒绝**：OEM 的 ACL 0x14/extra-tag 路径在闭源 AAL；直接放行会“正常转发但不加隧道头”。

### 4.5 TX/CSUM/LSO

- `lso_para1` = payload 长度，**不是** `len+16`；`ctrl[23:8]` 才是 `len+16`。
- `tx_csum`/`tso` 默认 0；开启时才宣告 `NETIF_F_*`。
- 单 2048 B DMA buffer ⇒ 超级包上限 2032 B，只能 1–2 段；真正大 TSO 需要更大 buffer 或 OEM SG 形态，未做。
- `hdr_a_full` 默认 0；只有 offload 帧强制 full。

---

## 5. 阻塞项（目标 blocked 的原因）

### 5.1 Host Policing share-meter 模式
- `fc_8277c.ko` 只导入 `rtk_rate_shareMeter_*`，无实现。
- stock rootfs 的 61 个 `.ko`、`librtk.so` 里只有 socket 包装（`setsockopt 0x31b8`），没有寄存器级实现。
- 提供者可能在内核内置 5.10 镜像中；该镜像不在语料。
- **需要**：`rtk.ko` 或 5.10 OEM 内核镜像（含符号），或设备寄存器对比。

### 5.2 NAPTV6 全局模式
- `aal_hash_action_mode_set` 导出但无调用者；`GRP24_SUPPORT=0`。
- 切换会改变整张 action 表宽度，不能由驱动自行打开。
- **需要**：设备上确认 `hash_action_table_entry_length` 运行值、找到合法调用路径、mode 0/1 双 dump、NPTv6 校验和实验。

### 5.3 DS-Lite/6RD 真正安装
- ACL 0x14 key 0x89 B + FIB 0x57 B 布局已挖到字节级（RE-12），但：
  - 安装入口 `aal_l3_cls_add` 在闭源 `ca-ne.ko`；
  - FIB 的 permit/trap/redirect 逐位语义 UNKNOWN；
  - `aal_l3_cls_get` 不存在；
  - mainline 无 AAL 层。
- **需要**：闭源 AAL 的头文件/源码，或设备 `full_key_get`/`fib_N_get`/`l3fe_debug_dump_cls_fib` readback。

### 5.4 实机验证
全部未做：DoS 丢包、Host Policing 限速/MIB、DS-Lite 封装、NAPT6、TRNG、PPPoE 1500、ETS、GRE、mirror、组播复制、TX CSUM/LSO。

---

## 6. 证据语料与 REA 使用

### 6.1 模块

| 文件 | SHA-256 | 用途 |
|---|---|---|
| `/mnt/c/rea/ca-ne.ko` | `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e` | NE 寄存器/AAL、DoS masked blit、NAPTV6 打包 |
| `/mnt/c/rea/fc_mgr.ko` | `10c4f7f0dc22762de96768e80cb90e7d4203c2b406fccf1197f4fdc2daace479` | 旧分支 Flow/HostPolicing 证据（96 条模型，已废弃） |
| `/mnt/c/rea/cli-drv.ko` | `e6d1ba46197d0ef4dee8d9ec6260201d311cb983c217b6a986a5ee10500f76ac` | DoS 16 类型 CLI handler，最终位表来源 |
| `/mnt/c/rea/fc_8277c.ko` | `a287e7930b4930f552ae6b2b799a0b35050ae166d1dab8da40717aae11653571` | 真实 8277C 分支：Host Policing 32 条、extra-tag、ACL |
| `/mnt/c/rea/ca-rtk.ko` | `99f923ac92dc22187d75920f70e15f11f056753129f3cb74c658cc130afa7425` | share-meter DAL、DoS attackPrevent 跳表 |
| `/mnt/c/rea/ca-plat-kernel.ko` | `0a538812574e04a6fb7a5776d30a7b4e8bd4b1494e33a4b6ba0988cf04c08c20` | 平台辅助 |
| `/mnt/c/rea/rtk_igmp_hook.ko` | `05000feaec728e25653829cb29ba56c8fff59dbbae794d3f8424697c145b4f56` | IGMP hook |

### 6.2 其他
- 完整 stock rootfs：`/tmp/stockroot`（用 `wsl -u root` 读）。
- `default_scfg.txt`：`/tmp/stockroot/etc/default_scfg.txt`，第 749/759/764 行是 NAPT6 48 B/GRP24 证据。
- `librtk.so`：`/tmp/stockroot/lib/librtk.so`，share-meter 符号是 socket 包装，不是寄存器实现。
- DTB0 / `default_scfg.txt` / OEM 打印串在 Phase 0 规格中引用。

### 6.3 REA 约定（易错）
- REA 是共享单文档 headless Ghidra：`open_binary` 会替换当前文档；不要让多个 agent 同时切模块。
- **不要 `close_binary`**（会破坏其他 agent 的会话）。
- 地址换算：
  - `ca-ne.ko`、`fc_mgr.ko`：REA = nm + **`0x100040`**；
  - `fc_8277c.ko`：REA = nm + **`0x100000`**（RE-12 实测订正）；
  - 每份 spec 开头都有自己的约定，先读再算。
- 大函数用 `procedure_pseudo_code`/`objdump -dr`，不要动辄 `analyze_function`。
- `aarch64-linux-gnu-objdump` 在 WSL 可用；`objdump` 本体不支持 aarch64。

---

## 7. 构建与回归门禁

### 7.1 只编驱动（推荐）

```bash
# 1) 同步源码到 build_dir
rsync -a --include="*/" --include="*.c" --include="*.h" --include="Makefile" --exclude="*" \
  /home/crysister/pt1500-refactor-build/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c/ \
  /home/crysister/pt1500-refactor-build/build_dir/target-aarch64_cortex-a53_musl/linux-rtl9617c_generic/linux-6.18.64/drivers/net/ethernet/realtek/rtl9617c/

# 2) 强制重编
find /home/crysister/pt1500-refactor-build/build_dir/target-aarch64_cortex-a53_musl/linux-rtl9617c_generic/linux-6.18.64/drivers/net/ethernet/realtek/rtl9617c \
  -type f \( -name "*.c" -o -name "*.h" \) -exec touch {} +

cd /home/crysister/pt1500-refactor-build/build_dir/target-aarch64_cortex-a53_musl/linux-rtl9617c_generic/linux-6.18.64
make -j4 ARCH=arm64 \
  CROSS_COMPILE=/home/crysister/pt1500-refactor-build/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl/bin/aarch64-openwrt-linux-musl- \
  drivers/net/ethernet/realtek/rtl9617c/
```

判定：`make` 退出 0；`grep -vE "STAGING_DIR"` 后 **0 warning / 0 error**。`STAGING_DIR` 警告是环境问题，可忽略。

也可从主仓根目录 `make target/linux/compile -j8`（W8 用过，0 warning）。

### 7.2 11 个 Python 测试

```bash
cd /home/crysister/pt1500-refactor-build
python3 package/rtl9617c/rtl9617c-pon-control/tests/fe-eif-owner.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/puc-token-buckets.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/tx-dma-layout.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/te-policer.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/te-police-flow.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/mcast-pool.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/tunnel-table.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/dos-table.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/hostpol.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/hostpol-flow.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/napt6-table.py
```

### 7.3 C 基线（ASan/UBSan）

```bash
src=package/rtl9617c/rtl9617c-pon-control/src
tests=package/rtl9617c/rtl9617c-pon-control/tests
out=$(mktemp -d)
cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I "$src" "$tests/oam-auth.c" "$src/pon-oam.c" -o "$out/oam-auth"
"$out/oam-auth"
cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I "$src" "$tests/oam-flags.c" "$src/pon-oam.c" -o "$out/oam-flags"
"$out/oam-flags"
```

### 7.4 双仓同步

```bash
diff -rq /home/crysister/pt1500-refactor-build/target/linux/rtl9617c \
          /home/crysister/pt1500-immortalwrt-build/target/linux/rtl9617c
# 只应出现：
# Only in .../patches-6.18: 651-netfilter-flowtable-vlan-used-keys.patch
```

该 patch 是 refactor-only、与 used_keys 重复，**不要同步过去**。测试目录也应保持 `diff -rq` 无输出。

---

## 8. 接手后的建议顺序

### 8.1 如果拿到设备（最高价值）

1. **先读、不写**：
   - `cat /sys/kernel/debug/rtl9617c_te/dos` 保存基线。
   - `cat <fe-debugfs>/tunnel`、`napt6`、`flows` 保存基线。
2. **DoS 校准**（只差 `udp_bomb` bit 4）：
   - `echo "type-en 0xffff" > /sys/kernel/debug/rtl9617c_te/dos`
   - 逐类型 `echo "type <name> off" > dos`，读回 `0x3304[31:16]` 差集，确认 bit4。
3. **Host Policing L3 模式**：
   - `echo "add <mac> <ingress_kbps> <egress_kbps>" > hostpol`
   - 打流，读 `hostpol` 的 rx/tx/delta；确认丢包/限速。
   - 不要先开 share-meter 模式。
4. **Dual-Header 表**：
   - 用 `tunnel` 的 `content-raw/control-raw/control-set/fmr-set` 做写读回；
   - 确认 clear-on-free 顺序；**不要**期待 flow 自动封装。
5. **NAPT6**：
   - 只读 `napt6 dump`、action 表长度；**不要**在活动系统上切全局 mode。
6. 所有结果写回 `docs/rtl9617c/specs/` 对应文档，标注 `observed`。

### 8.2 如果拿到 `rtk.ko` / 5.10 内核镜像

- 在镜像里找 `rtk_rate_shareMeter_set/get/Bucket/Mode` 的定义（不是 U 符号）。
- 反出物理寄存器块、128×7 bit 表、索引分配；
- 补 `ni_te_flow.c` 的 share-meter 模式，新增 `hostpol` 的 `mode` 命令；
- 默认仍关闭，先 debugfs/param 验证。

### 8.3 如果拿到闭源 AAL 头文件/源码

- 补 `aal_l3_cls_add` 的 FIB permit/trap/redirect 语义；
- 在 `fe_tunnel` 里实现 `acl-key-build` + `install`，把 `rtl_fe_install()` 的 tunnel 拒绝改成条件放行；
- 仍保持 `dual_hdr=0` 默认，先 debugfs 单条验证。

### 8.4 如果什么都没有

- 不要继续在静态语料里空转；当前交付边界就是：
  - Host Policing：L3 模式（32 条/32 vmeter）+ FE 绑定；
  - DoS：最终位表（`udp_bomb` bit4 推导）；
  - NAPT6：raw 打包/前缀表；
  - Dual-Header：表/模板/解析/clear/EIF 仲裁，flow install 拒绝。
- 把所有“未验证/未实现”原样保留在文档和代码注释里，不要升级为“已完成”。

---

## 9. 红线与纪律

1. **默认路径不能变**：所有新硬件路径必须默认关闭，或只在显式 debugfs/tc 操作时生效。
2. **不猜测寄存器**：没有 OEM 证据的字段/单位/顺序，写 `TODO(U-*)`，不要“先写一个值试试”。
3. **不声称未验证的功能**：代码注释、commit message、交接文档三处必须一致。
4. **不要回退已修正的模型**：
   - Host Policing 用 32 条 fc_8277c 模型，不要回 96 条；
   - DoS 用最终 16-bit 表，不要回候选表；
   - `hdr_a_full` 默认 0；
   - `lso_para1` 是 payload 长度，不是 `len+16`。
5. **Git**：`git add` 用显式路径；commit 前 `git diff --cached --stat`/`--check`；不要 `|| true`；不要 `reset --hard`/`clean`；不要改已发布历史。
6. **双仓**：主仓改完同步 `target/linux/rtl9617c` 与 tests；保留发版仓的已知 patch 差异。
7. **设备**：没有明确授权，不做 flash/reboot/串口/流量测试；上传用 `ssh -T`（不要 `-n`），上传后校验 hash。

---

## 10. 仍然 UNKNOWN 的清单（按优先级）

| # | 问题 | 影响 | 需要的证据 |
|---|---|---|---|
| U-1 | `rtk_rate_shareMeter_*` 物理实现 | Host Policing share-meter 模式 | `rtk.ko`/内核镜像/设备 |
| U-2 | NAPTV6 全局 mode 的合法调用者 | NAPT6 启用 | 设备/闭源配置路径 |
| U-3 | `out[2]/out[3]` 是否读后清零 | Host Policing MIB 正确性 | 设备连续读+打流 |
| U-4 | ACL 0x14 FIB permit/trap/redirect 位 | DS-Lite/6RD 安装 | 闭源 AAL/设备 readback |
| U-5 | `udp_bomb` type_en bit 4 | DoS 完整位表 | 设备差集 |
| U-6 | 64-bit `dos_port_mask` 位↔端口 | DoS 端口掩码 | 设备 |
| U-7 | `pol_id` 指向哪张策略表 | DoS/Host Policing 语义 | 设备/闭源 |
| U-8 | EIF 16..31 三路 alias 的真实硬件行为 | Dual-Header EIF | 设备 |
| U-9 | NPTv6 校验和中性 / DNAT6 方向 / PAT | NAT66 功能 | 设备报文实验 |
| U-10 | `lso_para1` 高 16 bit、TX 环深度/SG | 大 TSO | 设备 |

---

## 11. 交接检查清单（接手后 30 分钟）

- [ ] `cd /home/crysister/pt1500-refactor-build && git status --porcelain` 只看到既有 `uc.out` 等无关未跟踪文件。
- [ ] `git log --oneline -20` 包含 §2 的提交；HEAD 不早于 `5cca58591f`。
- [ ] 读 `docs/rtl9617c/specs/README.md`，再按需读对应 spec。
- [ ] 跑 §7.2 的 11 个测试，确认全 PASS。
- [ ] 跑 §7.1 的强制编译，确认 0 warning。
- [ ] `diff -rq` 双仓，确认只剩 `651-...patch`。
- [ ] 读 §0 的“不要做什么”和 §9 的红线。
- [ ] 如果拿到设备/模块，按 §8 的顺序做；否则把本文件原样交给用户，不要擅自扩 scope。

---

## 12. 相关文件索引

- 计划书：`/home/crysister/.gemini/antigravity/brain/b5d386d9-2a78-471e-a963-f27aaa1785dd/implementation_plan.md`
- 规格目录：`docs/rtl9617c/specs/`
  - `phase0-re1-dmalso-ace-fbm.md`
  - `phase0-re2-policer-wred-dos.md`
  - `phase0-re3-dualhdr-mc-napt6.md`
  - `phase2-re4-hostpolicing.md`
  - `phase2-re5-dos-attack.md`
  - `phase2-re9-dos-final.md`
  - `phase2-re10-hostpol-final.md`
  - `phase3-re6-napt6.md`
  - `phase3-re7-dualhdr-content.md`
  - `phase3-re8-extratag.md`
  - `phase3-re11-extratag-napt6.md`
  - `phase3-re12-acl-key.md`
- 回归命令与范围：`docs/rtl9617c/PT1500_AUTH_PIR.md`
- LuCI：`package/rtl9617c/luci-app-rtl9617c-pon/`（`PKG_RELEASE:=9`）
- 测试：`package/rtl9617c/rtl9617c-pon-control/tests/`

---

**最后更新：2026-11-22，由 lead 在目标 blocked 时生成。**