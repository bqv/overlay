# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

# SimpleX Chat's CLI is a single dynamically linked Haskell binary.  Upstream
# publishes it both as a bare asset (simplex-chat-ubuntu-<release>-<arch>, which
# is what install.sh downloads) and as a .deb holding exactly
# usr/bin/simplex-chat.  The .deb is used here because unpacker.eclass unwraps it
# with plain ar/tar and the install path is unambiguous; no dpkg-deb is needed.
#
# Bumping is deliberately version-agnostic.  The tag is v${PV} and the asset
# name carries no version at all, so nothing but PV changes:
#
#   cp simplex-chat-bin-7.0.3.ebuild simplex-chat-bin-7.0.4.ebuild
#   ebuild simplex-chat-bin-7.0.4.ebuild manifest
#   emerge -1 net-im/simplex-chat-bin
#
# The ubuntu-22_04 build is deliberate: it is the one upstream's install.sh
# installs, and its older glibc/libcrypto expectations run on anything newer.
# Upstream also tags beta releases (v7.1.0-beta.6 and friends); this package
# tracks the stable series only.
inherit unpacker

DESCRIPTION="SimpleX Chat CLI - private messenger with no user identifiers (prebuilt)"
HOMEPAGE="https://github.com/simplex-chat/simplex-chat"
SRC_URI="
	https://github.com/simplex-chat/simplex-chat/releases/download/v${PV}/simplex-chat-ubuntu-22_04-x86_64.deb -> ${P}.deb
"

S="${WORKDIR}"

# Upstream's repository is AGPL-3.0.
LICENSE="AGPL-3"
SLOT="0"
KEYWORDS="~amd64"

# Prebuilt binary: do not strip it, and Gentoo mirrors do not carry GitHub
# release assets.
RESTRICT="mirror strip"

QA_PREBUILT="usr/bin/simplex-chat"

# Read off ldd on the released binary; upstream's .deb declares no Depends at
# all, so there is nothing to map.  libc and libm come from glibc.
RDEPEND="
	dev-libs/gmp
	dev-libs/openssl:0
	sys-libs/zlib
"

src_install() {
	dobin "${WORKDIR}"/usr/bin/simplex-chat
}
