set -e

/usr/libexec/network/packet-steering.uc "$@"

case "$1" in
	1|2)
		# Packet steering enabled: pin RX0 hard IRQ to CPU2 (0x4)
		# to keep it off CPU0 while RPS spreads softirqs.
		ni_cpus=4
		;;
	""|0|*)
		# Default / disabled: reset to all CPUs mask
		ni_cpus=f
		;;
esac

for irq in $(awk '$NF == "rtl9617c-rx0" { sub(":", "", $1); print $1 }' /proc/interrupts); do
	[ -w "/proc/irq/$irq/smp_affinity" ] && echo "$ni_cpus" > "/proc/irq/$irq/smp_affinity" 2>/dev/null || true
done
