# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

MY_VER="${PV%%.*}"
MY_TARBALL="wasi-sdk-${PV}-x86_64-linux.tar.gz"

DESCRIPTION="WASI SDK toolchain: clang, lld and wasi-libc for wasm32-wasip1 (prebuilt)"
HOMEPAGE="https://github.com/WebAssembly/wasi-sdk"
SRC_URI="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${MY_VER}/${MY_TARBALL}"
S="${WORKDIR}/wasi-sdk-${PV}-x86_64-linux"

LICENSE="Apache-2.0-with-LLVM-exceptions MIT"
SLOT="0"
KEYWORDS="amd64"
RESTRICT="strip"

QA_PREBUILT="opt/wasi-sdk-${MY_VER}/*"

src_install() {
	local dest="/opt/wasi-sdk-${MY_VER}"

	dodir "${dest}"
	cp -a "${S}/." "${ED}${dest}/" || die

	insinto "/usr/$(get_libdir)/pkgconfig"
	cat > "${T}/wasi-sdk.pc" <<-PC || die
		prefix=${EPREFIX}${dest}
		exec_prefix=\${prefix}
		sysroot=\${prefix}/share/wasi-sysroot
		clang=\${prefix}/bin/clang
		clangxx=\${prefix}/bin/clang++
		target=wasm32-wasip1

		Name: wasi-sdk
		Description: WASI SDK toolchain for WebAssembly (wasm32-wasip1)
		Version: ${PV}
	PC
	doins "${T}/wasi-sdk.pc"
}

pkg_postinst() {
	elog "WASI SDK ${PV} installed to /opt/wasi-sdk-${MY_VER}."
	elog "pkg-config --variable=clang wasi-sdk, and --variable=sysroot."
}
