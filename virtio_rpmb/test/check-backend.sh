#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Build the vhost-user-rpmb daemon against the libvhost-user of the QEMU
# that OP-TEE 4.11.0 uses (qemu_v8.xml), then check its request handling
# against the virtio-rpmb device requirements and against the frames
# OP-TEE sends through the virtio_rpmb frontend (backend_spec_check.c).
#
# The end-to-end run in QEMU needs a backend that passes this check.
#
# Usage: check-backend.sh [work directory, default $HOME/rpmb-e2e]
# Needs: git, gcc, meson, ninja, pkg-config, glib-2.0 and gio-2.0
# development files.

set -euo pipefail

DAEMON_URL=https://github.com/stsquad/qemu.git
DAEMON_REV=07332729bb7ffdaa3d11cf986784b214b8be987e	# virtio/vhost-user-rpmb-v2
QEMU_URL=https://github.com/qemu/qemu.git
QEMU_REV=refs/tags/v10.0.0

TEST_DIR=$(cd "$(dirname "$0")" && pwd)
WORK=$(realpath -m "${1:-$HOME/rpmb-e2e}")
SRC=$WORK/src
OUT=$WORK/backend

# fetch <url> <rev> <dir> <path>...: check out the given paths of <rev>
fetch() {
	local url=$1 rev=$2 dir=$3

	shift 3
	if [ ! -d "$dir/.git" ]; then
		git init -q "$dir"
		git -C "$dir" remote add origin "$url"
	fi
	git -C "$dir" sparse-checkout set "$@"
	git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$rev"
	git -C "$dir" checkout -q --force FETCH_HEAD
}

echo "== Fetching the daemon at $DAEMON_REV and libvhost-user at ${QEMU_REV#refs/tags/}"
fetch "$DAEMON_URL" "$DAEMON_REV" "$SRC/vhost-user-rpmb" tools/vhost-user-rpmb
fetch "$QEMU_URL" "$QEMU_REV" "$SRC/qemu" subprojects/libvhost-user \
	include/qemu include/standard-headers

DAEMON_SRC=$SRC/vhost-user-rpmb/tools/vhost-user-rpmb
LVU_SRC=$SRC/qemu/subprojects/libvhost-user
LVU=$OUT/libvhost-user

echo "== Patching the daemon"
for p in "$TEST_DIR"/patches/vhost-user-rpmb-*.patch; do
	basename "$p"
	git -C "$SRC/vhost-user-rpmb" apply "$p"
done

echo "== Building libvhost-user"
rm -rf "$LVU"
mkdir -p "$OUT"
meson setup "$LVU" "$LVU_SRC" > "$OUT/meson.log"
ninja -C "$LVU" > /dev/null

# The daemon's meson.build only works inside a QEMU tree; main.c and
# hmac_sha256.c need nothing but glib, gio and libvhost-user.
GLIB_FLAGS=$(pkg-config --cflags --libs glib-2.0 gio-2.0 gio-unix-2.0)

echo "== Building vhost-user-rpmb"
# shellcheck disable=SC2086
gcc -O2 -g -Wall -I"$LVU_SRC" -o "$OUT/vhost-user-rpmb" \
	"$DAEMON_SRC/main.c" "$DAEMON_SRC/hmac_sha256.c" \
	"$LVU/libvhost-user-glib.a" "$LVU/libvhost-user.a" \
	$GLIB_FLAGS -lpthread
"$OUT/vhost-user-rpmb" --print-capabilities > /dev/null

echo "== Building backend_spec_check"
# main() of the daemon is renamed and built in, see backend_spec_check.c.
# shellcheck disable=SC2086
gcc -O2 -g -Wall -Wno-return-type -Wno-deprecated-declarations \
	-I"$DAEMON_SRC" -I"$LVU_SRC" -o "$OUT/backend_spec_check" \
	"$TEST_DIR/backend_spec_check.c" "$DAEMON_SRC/hmac_sha256.c" \
	$GLIB_FLAGS

echo "== Checking the daemon (its own messages go to $OUT/check/daemon.log)"
rm -rf "$OUT/check"
mkdir -p "$OUT/check"
status=0
"$OUT/backend_spec_check" "$OUT/check" 2> "$OUT/check/daemon.log" ||
	status=$?

if [ "$status" -ne 0 ]; then
	echo "FAIL in part A: the daemon differs from virtio-rpmb (section 5.12)."
	echo "FAIL in part B: an OP-TEE request through virtio_rpmb fails."
	exit "$status"
fi
echo "vhost-user-rpmb passes the check."
