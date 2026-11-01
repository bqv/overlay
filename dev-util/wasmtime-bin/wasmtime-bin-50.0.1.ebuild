# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="Wasmtime WebAssembly runtime: C API and CLI (prebuilt)"
HOMEPAGE="https://wasmtime.dev/"
SRC_URI="
	https://github.com/bytecodealliance/wasmtime/releases/download/v${PV}/wasmtime-v${PV}-x86_64-linux-c-api.tar.xz -> wasmtime-v${PV}-c-api.tar.xz
	https://github.com/bytecodealliance/wasmtime/releases/download/v${PV}/wasmtime-v${PV}-x86_64-linux.tar.xz -> wasmtime-v${PV}-cli.tar.xz
"
S="${WORKDIR}"

LICENSE="Apache-2.0-with-LLVM-exceptions"
SLOT="0"
KEYWORDS="amd64"
RESTRICT="strip"

QA_PREBUILT="opt/wasmtime-${PV}/*"

src_install() {
	local dest="/opt/wasmtime-${PV}"
	local unpacked="wasmtime-v${PV}-x86_64-linux-c-api"

	dodir "${dest}"
	cp -a "${unpacked}/include" "${ED}${dest}/" || die
	cp -a "${unpacked}/lib" "${ED}${dest}/" || die
	exeinto "${dest}/bin"
	doexe "wasmtime-v${PV}-x86_64-linux/wasmtime"
	dosym "/opt/wasmtime-${PV}/bin/wasmtime" /usr/bin/wasmtime
	dodoc "wasmtime-v${PV}-x86_64-linux/LICENSE"

	insinto "/usr/$(get_libdir)/pkgconfig"
	cat > "${T}/wasmtime.pc" <<-PC || die
		prefix=${EPREFIX}/opt/wasmtime-${PV}
		exec_prefix=\${prefix}
		libdir=\${exec_prefix}/lib
		includedir=\${prefix}/include

		Name: wasmtime
		Description: Wasmtime WebAssembly runtime C API
		Version: ${PV}
		Libs: -L\${libdir} -Wl,-rpath,\${libdir} -lwasmtime
		Cflags: -I\${includedir}
	PC
	doins "${T}/wasmtime.pc"
}

pkg_postinst() {
	elog "Wasmtime ${PV} installed to /opt/wasmtime-${PV}."
	elog "Meson: dependency('wasmtime') now resolves."
}
