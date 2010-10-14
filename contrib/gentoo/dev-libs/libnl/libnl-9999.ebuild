# Copyright 1999-2008 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/dev-libs/polylib/polylib-9999.ebuild,v 1.1 2008/09/21 08:46:58 vapier Exp $

EGIT_REPO_URI="git://git.kernel.org/pub/scm/libs/netlink/libnl.git"
EGIT_BOOTSTRAP="eautoreconf"
inherit git autotools eutils

DESCRIPTION="Netlink library"
HOMEPAGE="http://infradead.org/~tgr/libnl"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

src_install() {
	emake DESTDIR=${D} install || die
}
