# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

IUSE=""
MODS="desktop.home desktop.home.pipewire desktop.home.shortwave desktop.home.firefox desktop.home.stremio desktop.home.gajim desktop.home.crow desktop.home.openrc desktop.home.gpg
	desktop.home.java desktop.home.mpv desktop.home.dsh_native desktop.home.adb"
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
	desktop.home.gpg.fc desktop.home.gpg.if desktop.home.gpg.te
	desktop.home.java.fc desktop.home.java.if desktop.home.java.te
	desktop.home.mpv.fc desktop.home.mpv.if desktop.home.mpv.te
	desktop.home.adb.fc desktop.home.adb.if desktop.home.adb.te
	desktop.home.dsh_native.fc desktop.home.dsh_native.if desktop.home.dsh_native.te
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
	# 5037 is the adb server's port. refpolicy labels it adb_port_t, which is a member of
	# unreserved_port_type, so the base policy lets every session process bind it - and any
	# of them could therefore start a rival adb server. Relabel it to the local type the adb
	# module declares, which is not in that attribute, so only android_tools_t may bind it
	# (desktop.home.adb). A local port mapping outranks the base portcon, and applying it
	# here means `make merge` reproduces it on every merge.
	semanage port -m -t adb_server_port_t -p tcp 5037
	# the pass keychain needs gpg to write generic home content - see booleans.local
	setsebool -P gpg_manage_generic_user_content on
	setsebool -P gpg_agent_env_file on
}
