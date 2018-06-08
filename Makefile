SRCS=	login_oath.c oath.c base32.c
PROG=	login_oath
CFLAGS=	-Wall


NOMAN=	genau

LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}	

.include <bsd.prog.mk>
