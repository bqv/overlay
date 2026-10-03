# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

# Nuvio Desktop is a jpackage / Compose-Multiplatform app.  Upstream publishes
# .deb, .rpm, .AppImage and .flatpak for Linux; the .deb is the friendliest
# artifact for a -bin package, because it is a complete tree under /opt plus a
# .desktop file, and unpacker.eclass unwraps it with plain ar/tar (it pulls in
# app-arch/zstd as a build dep for the data.tar.zst payload).  No dpkg-deb.
#
# Bumping is deliberately version-agnostic, so nothing but PV changes:
#
#   cp nuvio-bin-0.1.27_alpha.ebuild nuvio-bin-0.1.28_alpha.ebuild
#   ebuild nuvio-bin-0.1.28_alpha.ebuild manifest
#   emerge -1 media-video/nuvio-bin
#
# MY_PV maps Portage's 0.1.28_alpha back to the upstream tag 0.1.28-alpha,
# which is also the asset filename.
inherit unpacker xdg

DESCRIPTION="Nuvio Desktop media player (upstream prebuilt binaries)"
HOMEPAGE="https://github.com/NuvioMedia/NuvioDesktop"

MY_PV=${PV/_/-}

SRC_URI="
	https://github.com/NuvioMedia/NuvioDesktop/releases/download/${MY_PV}/Nuvio-Linux-x86_64-${MY_PV}.deb -> ${P}.deb
"

S="${WORKDIR}"

# Upstream's repo is GPL-3.0.  The bundled JRE and the third-party jars keep
# their own licences; upstream ships their notices in share/doc/copyright.
LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64"

# Prebuilt upstream tree: never strip the bundled JRE, and Gentoo's mirrors do
# not carry GitHub release assets.
RESTRICT="mirror strip"

QA_PREBUILT="opt/nuvio/.*"

RDEPEND="
	app-arch/brotli
	app-arch/bzip2
	app-crypt/libmd
	dev-libs/expat
	dev-libs/libbsd
	media-libs/alsa-lib
	media-libs/fontconfig
	media-libs/freetype
	media-libs/libglvnd
	media-libs/libpng
	media-video/mpv[libmpv]
	sys-libs/zlib
	x11-libs/libX11
	x11-libs/libXau
	x11-libs/libXdmcp
	x11-libs/libXext
	x11-libs/libXi
	x11-libs/libXrender
	x11-libs/libXtst
	x11-libs/libxcb
	x11-misc/xdg-utils
"
# This is deliberately narrower than the upstream Depends list.  The .deb also
# names libwebkit2gtk-4.1, the gstreamer plugins and glib-networking, but
# nothing in the payload references them (checked with strings over
# lib/app/*.jar) and the app runs on a box without them.  What is listed above
# is what the bundled JRE's libawt_xawt.so, libfontmanager.so and libjsound.so
# actually link against, plus libmpv.so.2, which the player dlopens (hence
# mpv[libmpv]: media-video/mpv can be built with -libmpv +cli, without the
# library) and xdg-utils for opening links.

src_install() {
	# Keep upstream's /opt layout and file modes: the bundled runtime is
	# thousands of files plus a few symlinks, so cp -a rather than doins.
	dodir /opt
	cp -a "${WORKDIR}"/opt/nuvio "${ED}"/opt/ || die

	insinto /usr/share/applications
	doins "${WORKDIR}"/usr/share/applications/nuvio.desktop

	# Upstream's .deb installs no CLI entry point; add one.
	dosym ../../opt/nuvio/bin/Nuvio /usr/bin/nuvio

	dodoc "${WORKDIR}"/opt/nuvio/share/doc/copyright
}
