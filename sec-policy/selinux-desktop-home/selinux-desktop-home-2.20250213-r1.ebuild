# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

IUSE=""
MODS="desktop.home desktop.home.pipewire desktop.home.shortwave desktop.home.firefox desktop.home.stremio desktop.home.gajim desktop.home.crow desktop.home.openrc"
BASEPOL="2.20250213-r1"
POLICY_FILES="
	desktop.home.fc desktop.home.if desktop.home.te
	desktop.home.pipewire.fc desktop.home.pipewire.if desktop.home.pipewire.te
	desktop.home.shortwave.fc desktop.home.shortwave.if desktop.home.shortwave.te
	desktop.home.firefox.fc desktop.home.firefox.if desktop.home.firefox.te
	desktop.home.stremio.fc desktop.home.stremio.if desktop.home.stremio.te
	desktop.home.gajim.fc desktop.home.gajim.if desktop.home.gajim.te
	desktop.home.crow.fc desktop.home.crow.if desktop.home.crow.te
	desktop.home.openrc.fc desktop.home.openrc.if desktop.home.openrc.te
"
POLICY_TYPES="mcs"

inherit selinux-policy-2

DESCRIPTION="Local SELinux policy for home"

if [[ ${PV} != 9999* ]] ; then
    KEYWORDS="amd64 ~arm ~arm64 ~mips x86"
fi

DEPEND="${DEPEND}
	sec-policy/selinux-desktop-system
"
RDEPEND="${DEPEND}
"

pkg_postinst() {
	selinux-policy-2_pkg_postinst
}
