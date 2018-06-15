.PATH:		${.CURDIR}/..

PROG=		login_otp
SRCS=		login_otp.c login_passwd.c

LDADD=		-lutil
DPADD=		${LIBUTIL}

BINDIR=		/usr/libexec/auth

LINKS=		${BINDIR}/${PROG} ${BINDIR}/login_totp \
		${BINDIR}/${PROG} ${BINDIR}/login_hotp

.include <bsd.prog.mk>
