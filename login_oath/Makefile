.PATH:		${.CURDIR}/..

PROG=		login_oath
SRCS=		login_oath.c login_passwd.c

LDADD=		-lutil
DPADD=		${LIBUTIL}

BINDIR=		/usr/libexec/auth

LINKS=		${BINDIR}/${PROG} ${BINDIR}/login_totp \
		${BINDIR}/${PROG} ${BINDIR}/login_hotp

.include <bsd.prog.mk>
