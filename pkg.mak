#
# $Id$
#

VERSION=10282011-alpha

SOURCE=capture-daemon/configure \
       capture-daemon/Makefile.in \
       capture-daemon/*.[hc] \
       capture-daemon/configure.ac \
       capture-daemon/config.h.in \
       capture-daemon/aconf/config.guess \
       capture-daemon/aconf/config.sub \
       capture-daemon/aconf/install-sh \
       capd_proxy.py capd_storage.py fake-capture-daemon \
       runproxy.sh cleanup.sh

DOC=README FIXME

EXTRAS=depend/libfixbuf-0.8.0.tar.gz \
       depend/yaf-1.0.0.2.tar.gz

ALLCODE=${SOURCE} ${DOC} ${EXTRAS}

PKGNAME=capd-${VERSION}

all:
	mkdir ${PKGNAME}
	tar cvf - ${ALLCODE} | tar xpf - -C ${PKGNAME}
	tar cvf ${PKGNAME}.tar ${PKGNAME}
	gzip -9 ${PKGNAME}.tar
	rm -rf ${PKGNAME}

clean:
	rm -rf ${PKGNAME}
	rm -f ${PKGNAME}.tar
	rm -f ${PKGNAME}.tar.gz

