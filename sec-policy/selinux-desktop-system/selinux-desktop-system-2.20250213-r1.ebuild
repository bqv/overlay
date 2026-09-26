# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

IUSE=""
MODS="desktop.system.base desktop.system.mosh desktop.system desktop.system.users"
BASEPOL="2.20250213-r1"
POLICY_FILES="
	desktop.system.base.if desktop.system.base.te desktop.system.base.fc
	desktop.system.mosh.if desktop.system.mosh.te desktop.system.mosh.fc
	desktop.system.cil desktop.system.users.cil
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

pkg_postinst() {
	selinux-policy-2_pkg_postinst
	setsebool -P xserver_allow_dri true
	setsebool -P sysadm_allow_rw_inherited_fifo true
	setsebool -P xdm_sysadm_login true
	setsebool -P systemd_tmpfiles_manage_all true
	setsebool -P authlogin_pam true
	setsebool -P authlogin_nsswitch_use_ldap true
}
