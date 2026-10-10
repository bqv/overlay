# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

IUSE=""
MODS="desktop.system.staff desktop.system.sysadm desktop.system.session desktop.system.nginx desktop.system.remote desktop.system.portage desktop.system.selinux desktop.system.tools desktop.system.boot desktop.system.greet desktop.system.mosh desktop.system.network desktop.system.netbird"
BASEPOL="2.20250213-r1"
POLICY_FILES="
	desktop.system.staff.te
	desktop.system.sysadm.te
	desktop.system.session.te
	desktop.system.nginx.te
	desktop.system.remote.te
	desktop.system.portage.te
	desktop.system.selinux.te
	desktop.system.tools.te
	desktop.system.boot.te
	desktop.system.greet.te desktop.system.greet.fc
	desktop.system.mosh.if desktop.system.mosh.te desktop.system.mosh.fc
	desktop.system.network.fc desktop.system.network.te
	desktop.system.netbird.fc desktop.system.netbird.te
"
POLICY_TYPES="mcs"

inherit selinux-policy-2

DESCRIPTION="Local SELinux policy for system"

if [[ ${PV} != 9999* ]] ; then
    KEYWORDS="amd64 ~arm ~arm64 ~mips x86"
fi

DEPEND="${DEPEND}
	sec-policy/selinux-base-policy
	sec-policy/selinux-base
"
RDEPEND="${DEPEND}
"

# The secmark ruleset is part of this policy, not a runtime artefact: the
# packet types the modules grant only mean anything if something labels the
# packets, and vice versa. It used to be applied by hand with `nft -f`, with
# the boot loading a *separately* hand-saved /var/lib/nftables/rules-save -
# two copies and nothing keeping them in step, which is exactly how they
# drifted (the savefile silently lagged the source by three fixes). Installing
# it here makes the repository the single source: the boot service loads this
# file directly, and /etc/conf.d/nftables no longer saves over anything.
src_install() {
	selinux-policy-2_src_install
	insinto /usr/share/selinux/mcs
	newins "${FILESDIR}/ruleset.nftables" ruleset.nftables
}

pkg_postinst() {
	selinux-policy-2_pkg_postinst
	setsebool -P xserver_allow_dri true
	setsebool -P sysadm_allow_rw_inherited_fifo true
	setsebool -P xdm_sysadm_login true
	setsebool -P systemd_tmpfiles_manage_all true
	setsebool -P authlogin_pam true
	setsebool -P authlogin_nsswitch_use_ldap true
	# nginx binds :80 on the LAN addresses; without this the master cannot
	# bind at all and the LAN door is gone (see booleans.local).
	setsebool -P nginx_enable_http_server true
}
