# PT1500-H10 PON authentication and wired PIR fixes

This branch carries the production PON refactor, authentication/state corrections and native wired throughput repair developed on the PT1500-H10. It is based on the upstream `refactor` branch, including the built-in RTL8221B PHY patch commit. It does not include the separate external-AP performance experiments.

## Driver and control-plane changes

- Split the PON driver into shared lifecycle/debug code and `epon/`, `itu/`, and `data/` components. NI and FE retain ownership of forwarding resources; PON admission does not become a second FE lifecycle owner.
- Build Local Information vendor data from the configured live identity. Normal OAM discovery flags do not advertise local fault or Dying Gasp.
- Preserve OEM CTC authentication semantics: bounded SET attributes advance the implicit progress path, while selectors, GET requests and malformed attributes do not. Explicit type-5 results take precedence. Challenges indicate activity rather than a successful authentication result.
- Add authentication provenance, duration, reset/event reporting and user-space status integration. Runtime identity/status data must still be treated as private; do not publish device configuration or status dumps.
- Limit physical EIF allocation to 32 rows, with ownership and compatible sharing tracked separately from flow counters.
- Initialize native PUC PIR rate and burst fields correctly, without a hotfix module or boot-time repair service.

The WAN defaults are a PT1500 reference-line profile: VLAN, MTU and MAC-offset policy require review for another operator. They are not universal PON defaults. The script can reconfigure the protocol of an existing WAN using its matching PON device. Default offload policy remains mode/board specific; hardware acceleration must be enabled and verified for the desired deployment.

## Permanent wired throughput repair

The API maximum-rate sentinel must not be written directly as a packed hardware word. The native initializer now emits:

```c
writel(~0U, pon->mac + PIR_DATA0);
writel((2 << 6) | 0x3f, pon->mac + PIR_DATA1);
```

These encode `rate_k=1023`, `rate_m=65535`, `burst=4095`, and `enable=2`. The initializer runs through the driver's normal PUC configuration path, including later reinitialization. CIR semantics and reserved ITU queues are retained.

OEM specification references, copied as specifications rather than executable blobs:

- `ca-ne.ko` SHA-256 `71b3056af3217b08c96f5284f066614766286793141c9f69ad8ecb0f6b7275d4`: `aal_puc_init` initialization at `0x1af080`, and `aal_puc_pir_voq_tbc_mem_set` at `0x1a8f30`.
- `ca-rtk.ko`: `dal_rtl8277c_ponmac_queue_add`, section-relative encoding near `0x3c8`.
- `ca-ne.ko`: the EIF table descriptor at `0x27cec0` declares 32 physical rows; hash logical aliases are not additional physical resources.
- OEM `eponoamd` authentication handlers `FUN_00419338` and `FUN_00419c5c` supply the SET-progress/explicit-result behavior covered by the regression fixture.

A controlled same-device PIR-only comparison on the development image measured approximately 143 Mbps before correction, 2214 Mbps after correction, 162 Mbps after rollback, and 2233 Mbps after reapplying it. These are observations from the development build and do not constitute a boot test of this publication branch.

## Validation

Existing source regressions:

```sh
python3 package/rtl9617c/rtl9617c-pon-control/tests/puc-token-buckets.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/fe-eif-owner.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/tx-dma-layout.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/te-policer.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/te-police-flow.py
python3 package/rtl9617c/rtl9617c-pon-control/tests/mcast-pool.py

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

The publication worktree passed the original four regressions with ASan/UBSan, the package's strict AArch64 C syntax checks with `PON_FIRMWARE_VERSION` defined, and whitespace checks. The PIR test exercises the actual production initializer for all 256 EPON queues, ITU queue preservation, an empty range and write-timeout boundaries. The EIF test exercises the actual allocation/release functions and failure ownership.

The hardware-capability branch adds host-side tests for the OEM TX buffer header (`tx-dma-layout.py`), the L3TE policer/WRED/DoS register layer (`te-policer.py`), the FE `FLOW_ACTION_POLICE` slot lifecycle (`te-police-flow.py`) and the multicast MCGID/MCE/ARB-FIB pools (`mcast-pool.py`). They compile the actual driver logic against mocked MMIO, so they prove packing, allocation and rollback behaviour but not silicon behaviour.

This publication retains the upstream Linux 6.18.55 version and generic patch stack. The development tree's broader 6.18.60 update is deliberately outside this change. The original target PPPoE patch is retained, including its VLAN/CVLAN `used_keys` updates; the separate generic patch that duplicates those updates is not imported. No new dependency on flow priority or wireless forward-path APIs was identified.

A complete firmware rebuild and boot test of this exact publication branch have not been performed as part of publishing. The previously supplied PIR-fixed firmware was built and FIT-validated separately on Linux 6.18.60. Test its build marker, native PIR readback, authentication and throughput after flashing it. Never infer a successful flashed-image test from a hotfix measurement.

## Scope and remaining work

External-AP wireless forwarding performance is still unresolved. The branch now also carries the Phase 1/2 hardware-capability work: TRNG and Baby Jumbo MTU, `FLOW_ACTION_PRIORITY` to the 8-VoQ CoS field, GRE passthrough, 6-bit DSCP remark, L3PE egress mirror, the L3TE flow/group policer + WRED + L3 DoS register layer, FE `FLOW_ACTION_POLICE` wiring and the multicast table manager. These are gated so the pre-existing paths remain the default where the evidence is incomplete; device validation of the mirror, policer, WRED, multicast and TX checksum/LSO behaviour is still outstanding. Host Policing, the per-attack-type DoS table, NAPT6 and the L3PE Dual-Header tunnel wiring remain open. No captured packets, provisioned MAC/serial values, passwords, private keys or local deployment markers are part of this branch; synthetic test identities replace device-specific examples in source comments.
