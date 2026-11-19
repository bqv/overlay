# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit desktop

COMMIT="ea309ca6142db7856540bc227a7a4d2249f7d143"

DESCRIPTION="Compact GTK3/XEmbed PipeWire volume tray applet"
HOMEPAGE="https://github.com/sbnwl/pw-volume-tray"
SRC_URI="https://github.com/sbnwl/pw-volume-tray/archive/${COMMIT}.tar.gz -> ${P}.tar.gz"
S="${WORKDIR}/pw-volume-tray-${COMMIT}"

LICENSE="GPL-3.0-or-later"
SLOT="0"
KEYWORDS="~amd64"

DEPEND="x11-libs/gtk+:3"
RDEPEND="${DEPEND}
	media-video/wireplumber"
BDEPEND="virtual/pkgconfig"

src_install() {
	dobin pw-tray
	domenu data/pw-tray.desktop
}
