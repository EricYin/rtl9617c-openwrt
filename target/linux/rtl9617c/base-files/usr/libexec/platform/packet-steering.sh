#!/bin/sh
set -e

/usr/libexec/network/packet-steering.uc "$@"

# Determine online CPU count and bitmask; bail gracefully on UP kernels.
ncpus=0
for c in /sys/devices/system/cpu/cpu[0-9]*; do
	[ -d "$c" ] && ncpus=$((ncpus + 1))
done
[ "$ncpus" -lt 2 ] && exit 0

all_mask=$(( (1 << ncpus) - 1 ))
all_hex=$(printf '%x' "$all_mask")

# Detect whether rtl9617c_ni has multi-queue hardware RSS IRQs (rx0..rxN) or
# legacy single-IRQ mode (rtl9617c_ni / rtl9617c_ni-rx0).
rx_irqs="$(awk '$NF ~ /^rtl9617c_ni(-rx[0-9]+)?$/ { sub(":", "", $1); print $1 }' /proc/interrupts)"
rx_irq_count=0
for irq in $rx_irqs; do
	rx_irq_count=$((rx_irq_count + 1))
done

# Single-IRQ fallback: dedicate the highest CPU core (CPU3 on quad-core
# RTL9617C) to the shared RX NAPI hard IRQ, and steer RPS across the remaining
# cores so softirqs never collide with the hard IRQ.
irq_cpu=$((ncpus - 1))
irq_mask=$((1 << irq_cpu))
irq_hex=$(printf '%x' "$irq_mask")
comp_hex=$(printf '%x' $((all_mask & ~irq_mask)))

steering_flows="$(uci -q get 'network.@globals[0].steering_flows' 2>/dev/null || true)"
case "$steering_flows" in
	''|*[!0-9]*) steering_flows=32768 ;;
esac

if [ "$rx_irq_count" -ge 2 ]; then
	# Multi-queue hardware RSS: the driver already pins rx0..rxN 1:1 across
	# CPUs and hashes flows in L3FE. Avoid software RPS in default mode so
	# packets do not bounce across CPUs via IPI, while keeping global RFS
	# enabled for other devices (e.g. Wi-Fi) unless mode 0 is selected.
	case "$1" in
		0)
			rps_hex="0"
			rfs_global=0
			rfs_queue=0
			;;
		2)
			rps_hex="$all_hex"
			rfs_global="$steering_flows"
			rfs_queue=4096
			;;
		""|1|*)
			rps_hex="0"
			rfs_global="$steering_flows"
			rfs_queue=0
			;;
	esac
else
	case "$1" in
		0)
			ni_cpus="$all_hex"
			rps_hex="0"
			rfs_global=0
			rfs_queue=0
			;;
		2)
			ni_cpus="$irq_hex"
			rps_hex="$all_hex"
			rfs_global="$steering_flows"
			rfs_queue=4096
			;;
		""|1|*)
			ni_cpus="$irq_hex"
			rps_hex="$comp_hex"
			rfs_global="$steering_flows"
			rfs_queue=4096
			;;
	esac
fi

if [ "$rfs_global" -eq 0 ]; then
	rfs_queue=0
elif [ "$rfs_queue" -gt "$rfs_global" ]; then
	rfs_queue="$rfs_global"
fi

if [ "$rx_irq_count" -le 1 ]; then
	for irq in $rx_irqs; do
		[ -w "/proc/irq/$irq/smp_affinity" ] && echo "$ni_cpus" > "/proc/irq/$irq/smp_affinity" 2>/dev/null || true
	done
fi

if [ -w /proc/sys/net/core/rps_sock_flow_entries ]; then
	echo "$rfs_global" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
fi

# Override physical NI and PON netdev RPS/RFS settings after packet-steering.uc
# (lan*/pon* expose one netdev rx-0 queue even when 4-queue hardware RSS is
# active, so packet-steering.uc alone would otherwise funnel traffic onto one
# core).
for devpath in /sys/class/net/lan* /sys/class/net/pon*; do
	[ -d "$devpath/queues" ] || continue
	is_stacked=0
	for low in "$devpath"/lower_*; do
		[ -e "$low" ] && is_stacked=1 && break
	done
	[ "$is_stacked" -eq 1 ] && continue

	dev="${devpath##*/}"
	q_rfs="$rfs_queue"
	case "$dev" in
		pon-oam*|pon-omci*) q_rfs=0 ;;
	esac

	for q in "$devpath"/queues/rx-*/rps_cpus; do
		[ -w "$q" ] && echo "$rps_hex" > "$q" 2>/dev/null || true
	done
	for q in "$devpath"/queues/rx-*/rps_flow_cnt; do
		[ -w "$q" ] && echo "$q_rfs" > "$q" 2>/dev/null || true
	done
done
