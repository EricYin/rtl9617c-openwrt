# RTL9617C Phase 0 hardware specifications

Evidence-backed register and table specifications for the PT1500-H10
(RTL9617C / Taurus) hardware-capability plan.  They were produced from the
shipped OEM kernel modules and configuration, not from assumptions or from
the shape of the mainline port.  Every claim cites the OEM function and its
`nm`-relative address; REA addresses are the same value plus `0x100040`
(the Ghidra image base is `0x100000` and `.text` starts at file offset
`0x40`).

## Documents

| File | Scope |
|---|---|
| `phase0-re1-dmalso-ace-fbm.md` | TX DMA/LSO (`0xf7001000`), buffer header (`lso_para0`/`lso_para1`/`header_a`), ACE attributes, SRAM EQ0/FBM |
| `phase0-re2-policer-wred-dos.md` | L3TE 256 flow + 64 group policers, Host Policing, WRED, L2/L3 DoS, L3PE mirror registers |
| `phase0-re3-dualhdr-mc-napt6.md` | L3PE Dual-Header Control/Content/FMR tables, EIF 0..63 alias map, MCGID/MCE/ARB MC FIB, NAPT6 gaps, FE MTU table |
| `phase2-re4-hostpolicing.md` | Host Policing 96-entry control model, POL1 0..191 partition, share-meter API gap, per-direction MAC LUT binding, MIB |
| `phase2-re5-dos-attack.md` | L3/L2 DoS register blocks, masked-blit semantics, 16 type names, candidate type bitmap, flood/trap/drop |
| `phase3-re6-napt6.md` | NAPTV6 371-bit action layout, ACTGRP model, NPT6 prefix table, NAT66/NPTv6/DNAT6 limits |
| `phase3-re7-dualhdr-content.md` | DS-Lite/6RD Content templates, Control corrections, VXLAN facts, EIF alias arbitration, clear-on-free |
| `phase3-re8-extratag.md` | OEM extra-tag action table (driver-side 16x40 B), DS-Lite/6RD command words, ACL 0x14, teardown order |
| `phase2-re9-dos-final.md` | cli-drv.ko DoS type handlers and ca-rtk attackPrevent jump table: final 16-bit type_en and per-type pol_id/th/en fields |
| `phase2-re10-hostpol-final.md` | fc_8277c Host Policing: 32 entries, 32 vmeters to POL1 0xa0..0xbf, fixed MIB slots, G3 binding, MIB delta |
| `phase3-re11-extratag-napt6.md` | fc_8277c extra-tag consumer (software outer-header path), ACL 0x14 key/rule, NAPTV6 mode setter and 48 B feasibility |
| `phase3-re12-acl-key.md` | ACL 0x14 0x89 B key + 0x57 B FIB layout, DS-Lite/6RD key constants, rule word, W8c blockers |

## Evidence base

| Artifact | SHA-256 |
|---|---|
| `ca-ne.ko` (vendor networking engine) | `a23b4f7ab80de8b847c5efe93153324395711b279951f08828037a67ad022b8e` |
| `fc_mgr.ko` (FleetConntrack manager) | `10c4f7f0dc22762de96768e80cb90e7d4203c2b406fccf1197f4fdc2daace479` |
| `rtk_igmp_hook.ko` | `05000feaec728e25653829cb29ba56c8fff59dbbae794d3f8424697c145b4f56` |

Other inputs: the stock DTB0 (`rng@90600200`, NE register windows),
`default_scfg.txt` and the vendor print strings.  The mainline sources used
for comparison are `target/linux/rtl9617c/files-6.18/.../rtl9617c/`.

## Reading conventions

- Addresses are `nm`-relative (section offsets).  The Ghidra/REA address is
  `nm + 0x100040`.
- `[OBSERVED]` means the instruction or data was read from the artifact;
  `[DERIVED]` means it follows from observed constants; `[UNKNOWN]` means the
  artifact does not settle it and no implementation may claim it.
- The UNKNOWN lists at the end of each document are part of the deliverable.
  In particular Host Policing MAC binding, the DoS attack-type table, NAPT6
  field semantics and the ARB MC FIB field names are not resolved.

## Implementation status

Phase 1 (TRNG, Baby Jumbo, flow priority, GRE, DSCP remark, mirror, LuCI),
the Phase 2 register core (OEM TX header, L3TE policer/WRED, FE
`FLOW_ACTION_POLICE`, multicast table manager), the final 16-bit DoS
type table, the fc_8277c 32-entry Host Policing model with L3 flow
binding, the Dual-Header table/template manager and the NAPTV6 371-bit
packer/NPT6 prefix table are in this branch.  The remaining functional
closure is blocked by the closed AAL layer and by device-only facts: the
`rtk_rate_shareMeter_*` provider is not in the rootfs (Host Policing
share-meter mode), `aal_hash_action_mode_set` has no caller in the OEM
collection (NAPTV6 global mode), and installing a DS-Lite/6RD flow needs
the closed `aal_l3_cls_add` FIB semantics plus device read-back of the
0x89 B key/0x57 B FIB block.  See
[`../PT1500_AUTH_PIR.md`](../PT1500_AUTH_PIR.md) for the regression
commands and the current scope.  Device validation of every offload path
is still outstanding.