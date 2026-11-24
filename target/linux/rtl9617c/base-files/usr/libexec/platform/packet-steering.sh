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

# Dedicate the highest CPU core (CPU3 on quad-core RTL9617C) to the shared
# rtl9617c_ni RX NAPI hard IRQ, and steer RPS across the remaining cores so
# softirqs never collide with the hard IRQ (nor stall pon0 on a single core).
irq_cpu=$((ncpus - 1))
irq_mask=$((1 << irq_cpu))
irq_hex=$(printf '%x' "$irq_mask")
comp_hex=$(printf '%x' $((all_mask & ~irq_mask)))

steering_flows="$(uci -q get 'network.@globals[0].steering_flows' 2>/dev/null || true)"
case "$steering_flows" in
	''|*[!0-9]*) steering_flows=32768 ;;
esac

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

if [ "$rfs_global" -eq 0 ]; then
	rfs_queue=0
elif [ "$rfs_queue" -gt "$rfs_global" ]; then
	rfs_queue="$rfs_global"
fi

# The IRQ is registered with KBUILD_MODNAME, so /proc/interrupts shows the
# module name of rtl9617c-ni.ko with '_' instead of '-'.
for irq in $(awk '$NF == "rtl9617c_ni" { sub(":", "", $1); print $1 }' /proc/interrupts); do
	[ -w "/proc/irq/$irq/smp_affinity" ] && echo "$ni_cpus" > "/proc/irq/$irq/smp_affinity" 2>/dev/null || true
done

if [ -w /proc/sys/net/core/rps_sock_flow_entries ]; then
	echo "$rfs_global" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
fi

# Apply uniform multi-core RPS + RFS to all physical NI and PON netdevs
# (pon0 shares rtl9617c_ni's RX NAPI IRQ, so packet-steering.uc alone cannot
# infer its GIC IRQ and mistakenly pins pon0 to a single core).
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
