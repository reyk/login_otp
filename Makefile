SRCS=		main.c oath.c oathdb.c base32.c
PROG=		oath
CFLAGS=		-Wall

LINKS=		${BINDIR}/${PROG} ${BINDIR}/login_oath

LDADD=		-lcrypto -lm
DPADD=		${LIBCRYPTO} ${LIBM}

NOMAN=		yes

BINMODE=	2555
BINGRP=		_token

.include <bsd.prog.mk>
