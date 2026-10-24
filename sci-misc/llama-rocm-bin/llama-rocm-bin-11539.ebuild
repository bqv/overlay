# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

# Upstream's prebuilt ROCm build of llama.cpp, installed beside
# sci-misc/llama-cpp (which owns /usr/bin/llama-server) under /opt, so the two
# can coexist and either one can be pointed at a model directory.
#
# The HIP runtime is deliberately NOT bundled: it comes from dev-util/therock-bin,
# which ships the same sonames this binary links against (libamdhip64.so.7,
# librocblas.so.5, libhipblas.so.3, libroctx64.so.4) plus the gfx1100 kernels.
# Consumers must therefore run it with LD_LIBRARY_PATH=/opt/therock-bin/lib.

DESCRIPTION="llama.cpp inference engine, prebuilt upstream ROCm build"
HOMEPAGE="https://github.com/ggml-org/llama.cpp"

MY_PN="llama"
MY_BIN="${MY_PN}-b${PV}-bin-ubuntu-rocm-10.0-x64"
SRC_URI="https://github.com/ggml-org/llama.cpp/releases/download/b${PV}/${MY_BIN}.tar.gz"
S="${WORKDIR}/${MY_PN}-b${PV}"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64"

# The ROCm userland this binary was built against.
RDEPEND="dev-util/therock-bin"

QA_PREBUILT="opt/llama-rocm/*"

src_install() {
	local dest="/opt/llama-rocm"

	dodir "${dest}"
	# The tarball is flat: every binary and shared library sits in one dir and
	# finds its siblings through $ORIGIN rpaths.
	cp -a "${S}/." "${ED}${dest}/" || die "install to ${dest} failed"
	fperms 0755 "${dest}"
}

pkg_postinst() {
	elog "llama.cpp (ROCm build ${PV}) installed to /opt/llama-rocm/."
	elog ""
	elog "It coexists with sci-misc/llama-cpp; nothing was placed in /usr/bin."
	elog "The HIP runtime comes from dev-util/therock-bin, so run it as:"
	elog ""
	elog "  LD_LIBRARY_PATH=/opt/therock-bin/lib /opt/llama-rocm/llama-server ..."
	elog ""
	elog "The llama OpenRC user service already exports that LD_LIBRARY_PATH."
}
