# Copyright 1999-2006 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=2

inherit eutils linux-mod cmake-utils

DESCRIPTION="PPtP/L2TP/PPPoE server for Linux"
SRC_URI="http://sourceforge.net/projects/accel-ppp/files/accel-ppp/${P}.tar.bz2"
HOMEPAGE="http://accel-ppp.sourceforge.net/"

SLOT="0"
LICENSE="GPL"
KEYWORDS="~amd64 ~x86"
IUSE="postgres debug shaper pptp_driver"

DEPEND=">=sys-libs/glibc-2.8
	dev-libs/openssl
	dev-libs/libaio
	shaper? ( =dev-libs/libnl-2 )
	postgres? ( >=dev-db/postgresql-base-8.1 )"

RDEPEND="$DEPEND
         pptp_driver? ( virtual/modutils )"

BUILD_TARGETS="default"
BUILD_PARAMS="KDIR=${KERNEL_DIR}"
CONFIG_CHECK="PPP PPPOE"
MODULESD_PPTP_ALIASES=("net-pf-24 pptp")
PREFIX="/"
MODULE_NAMES="pptp(extra:${S}/driver/)"

src_prepare() {
	sed -i -e "/mkdir/d" "${S}/accel-pppd/CMakeLists.txt"
	sed -i -e "/INSTALL/d" "${S}/driver/CMakeLists.txt"
}

src_configure() {
	if use debug; then
		mycmakeargs+=( "-DCMAKE_BUILD_TYPE=Debug" )
	fi

	if  use postgres; then
		mycmakeargs+=( "-DLOG_PGSQL=TRUE" )
	fi

	if use shaper; then
		mycmakeargs+=( "-DSHAPER=TRUE" )
	fi

	cmake-utils_src_configure
}

src_compile() {
	cmake-utils_src_compile

	if use pptp_driver; then
		cd ${S}/driver
		linux-mod_src_compile || die "failed to build driver"
	fi
}

src_install() {
	cmake-utils_src_install

	if use pptp_driver; then
		cd ${S}/driver
		linux-mod_src_install
	fi

	exeinto /etc/init.d
	newexe "${S}/contrib/gentoo/net-dialup/accel-ppp/files/accel-pppd-init" accel-pppd

	insinto /etc/conf.d
	newins "${S}/contrib/gentoo/net-dialup/accel-ppp/files/pppd-confd" accel-pppd

	dodir /var/log/accel-ppp
	dodir /var/run/accel-ppp
	dodir /var/run/radattr
}
