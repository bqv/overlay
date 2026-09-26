# Copyright 2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

DESCRIPTION="A native Linux client for Stremio"
HOMEPAGE="https://github.com/Stremio/stremio-linux-shell"
SRC_URI=""

EGIT_REPO_URI="https://github.com/Stremio/stremio-linux-shell.git"
EGIT_CHECKOUT_DIR="${WORKDIR}/${PN}"
S="${EGIT_CHECKOUT_DIR}"

LICENSE="GPL-3+"
SLOT="0"
KEYWORDS=""
IUSE=""

DEPEND="
	media-video/mpv
	x11-libs/gtk+:3
	dev-libs/nss
	dev-libs/openssl
	sys-libs/glibc
	net-libs/nodejs
	media-libs/alsa-lib
	app-accessibility/at-spi2-core
	x11-libs/cairo
	sys-apps/dbus
	dev-libs/expat
	x11-libs/gdk-pixbuf
	dev-libs/glib:2
	x11-themes/hicolor-icon-theme
	x11-libs/libX11
	x11-libs/libxcb
	x11-libs/libXcomposite
	x11-libs/libXdamage
	x11-libs/libXext
	x11-libs/libXfixes
	x11-libs/libxkbcommon
	x11-libs/libXrandr
	media-libs/mesa
	dev-libs/nspr
	x11-libs/pango
	net-print/cups
"
RDEPEND="${DEPEND}"

BDEPEND="
	llvm-core/clang
	sys-devel/binutils
	dev-build/cmake
	dev-util/pkgconf
	dev-util/patchelf
	dev-vcs/git
"

inherit git-r3 cargo

src_unpack() {
	git-r3_src_unpack
}

src_prepare() {
	default
	git submodule update --init --recursive || die
	cargo fetch --locked || die
}

src_compile() {
	export CC=clang
	export CXX=clang++
	export CEF_PATH="${S}/vendor/cef"
	export RUSTFLAGS="-L native=${CEF_PATH}"

	cargo build --release --locked || die
}

src_install() {
	local dest=/usr/share/stremio

	exeinto "${dest}"
	doexe target/release/stremio-linux-shell
	dosym "${dest}/stremio-linux-shell" /usr/bin/stremio

	insinto "${dest}"
	doins -r vendor/cef/*

	patchelf --set-rpath '$ORIGIN' "${ED}${dest}/stremio-linux-shell" || die

	insinto /usr/share/applications
	doins data/com.stremio.Stremio.desktop
	insinto /usr/share/icons/hicolor/scalable/apps
	newins data/icons/com.stremio.Stremio.svg com.stremio.Stremio.svg
	insinto /usr/share/metainfo
	doins data/com.stremio.Stremio.metainfo.xml

	dodoc README.md
}
