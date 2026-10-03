# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

# go-env gives us GOFLAGS (-modcacherw -buildvcs=false -buildmode=pie),
# GOMAXPROCS and tc-export.  go-module is deliberately NOT inherited: it wants a
# vendored dependency set or EGO_SUM and would then run `ego mod verify` against
# an empty module cache.
#
# The upstream Makefile is NOT used either.  Its ${EXE_NAME} target depends on
# cmd/Desktop-Bridge/deploy/linux/bridge, which runs build.sh and tries to
# initialise the extern/vcpkg git submodule -- impossible from a release tarball
# and pointless on Linux, where CGO links the system dev-libs/libfido2.  Building
# ./cmd/Desktop-Bridge directly does the same compile without that detour.
#
# Resolving modules needs network in src_compile, so this atom is mapped to
# no-network.conf in /etc/portage/package.env (FEATURES="-network-sandbox").
inherit go-env

DESCRIPTION="IMAP/SMTP bridge to a Proton Mail account (GUI-less CLI build)"
HOMEPAGE="https://github.com/ProtonMail/proton-bridge"

SRC_URI="
	https://github.com/ProtonMail/proton-bridge/archive/refs/tags/v${PV}.tar.gz -> ${P}.tar.gz
"

# Forward patch switches the keychain to a pass-only build (the default), reverse
# restores upstream's secret-service probes for USE=dbus.
PATCHES=( "${FILESDIR}/${PN}-keychain-dbus-flag.patch" )

S="${WORKDIR}/proton-bridge-${PV}"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64"
# dbus is OFF by default on purpose: upstream probes secret-service-dbus before
# pass, and on a host with no session bus libsecret/godbus autolaunch a bus and
# block forever, hanging bridge just after "Creating keychain list".
IUSE="dbus"

# CGO links the system libfido2, which in turn pulls libcbor/openssl.  The old
# hand-built binary in ~/bin was linked against libcbor.so.0.13 and died with
# exit 127 once the box moved to libcbor-0.14.0; building from source here makes
# Portage own the linkage, so preserve-libs covers us on the next bump.
CDEPEND="
	dev-libs/libfido2
"
RDEPEND="
	${CDEPEND}
	app-admin/pass
	dbus? ( app-crypt/libsecret )
"
BDEPEND="
	${CDEPEND}
	dev-lang/go
	dbus? ( app-crypt/libsecret )
"

src_prepare() {
	if use dbus; then
		# Restore upstream's secret-service probing (the forward patch is
		# unconditional because it is the package default).
		eapply "${FILESDIR}/${PN}-keychain-dbus-flag.reverse.patch"
	fi

	default
}

# -X github.com/ProtonMail/proton-bridge/v3/internal/constants.Version=${PV} etc.
PROTONMAIL_LDFLAGS=(
	-X "github.com/ProtonMail/proton-bridge/v3/internal/constants.Version=${PV}"
	-X "github.com/ProtonMail/proton-bridge/v3/internal/constants.Revision=gentoo"
	-X "github.com/ProtonMail/proton-bridge/v3/internal/constants.Tag=v${PV}"
	-X "github.com/ProtonMail/proton-bridge/v3/internal/constants.FullAppName=ProtonMailBridge"
	-X "github.com/ProtonMail/proton-bridge/v3/internal/constants.BuildEnv=gentoo"
)

src_compile() {
	export CGO_ENABLED=1
	export GOPROXY="https://proxy.golang.org,direct"
	export GOMODCACHE="${WORKDIR}/go-mod"
	export CGO_LDFLAGS="-lfido2 -lcbor -lssl -lcrypto"

	# internal/frontend/cli/system.go refers to bridge.Credits, which lives in a
	# generated file that upstream's `gofiles` target would have produced.  The
	# script only reads go.mod, so it needs no network.
	(
		cd utils || die
		bash ./credits.sh bridge || die "credits.sh failed"
	)

	# USE=-dbus compiles the pass-only keychain instead of upstream's
	# secret-service probes.
	local my_tags=""
	use dbus || my_tags="passdbus"

	# -o names the artefact the service will execute; dobin takes the installed
	# name from this filename, so it must already be ${PN}.
	go build \
		-tags="${my_tags}" \
		-ldflags "${PROTONMAIL_LDFLAGS[*]}" \
		-o "${PN}" \
		./cmd/Desktop-Bridge/ || die "go build failed"
}

src_install() {
	dobin "${PN}"
	dodoc README.md
	dodoc release-notes/bridge_stable.md
}
