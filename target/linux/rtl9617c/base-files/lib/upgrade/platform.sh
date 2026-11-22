RAMFS_COPY_BIN='fitblk fit_check_sign'

REQUIRE_IMAGE_METADATA=1

platform_check_image() {
	local board=$(board_name)

	[ "$#" -gt 1 ] && return 1

	case "$board" in
	youhua,pt1500-h10-2p5g|\
	tianyi,tyfza1-2p5g)
		fit_check_image "$1"
		return $?
		;;
	*)
		echo "Unsupported board: $board" >&2
		return 1
		;;
	esac
}

platform_do_upgrade() {
	local board=$(board_name)

	case "$board" in
	youhua,pt1500-h10-2p5g|\
	tianyi,tyfza1-2p5g)
		fit_do_upgrade "$1"
		;;
	*)
		echo "Unsupported board: $board" >&2
		return 1
		;;
	esac
}
