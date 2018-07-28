#!/bin/bash

set -ex

nproc=$(/usr/bin/getconf _NPROCESSORS_ONLN)

function install_kernel()
{
	VER="$1"
	URL="https://www.kernel.org/pub/linux/kernel/v4.x/linux-$VER.tar.xz"
	wget "$URL"
	tar xf "linux-$VER.tar.xz"

	pushd "linux-$VER"
	make allmodconfig
	make -j $nproc modules_prepare
	make -j $nproc headers_install
	KERNEL_HEADERS=$(pwd)/usr/include
	popd
}

function build_lksctp()
{
	./bootstrap

	#CFLAGS="-Werror"
	if [ -n "$KERNEL_HEADERS" ]; then
		CFLAGS="$CFLAGS -I$KERNEL_HEADERS"
	fi
	export CFLAGS
	./configure

	make -j $nproc

	#make -j $nproc distcheck
}

if [ -n "$KERNEL" ]; then
	install_kernel "$KERNEL"
fi

build_lksctp

