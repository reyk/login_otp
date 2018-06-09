SRCS+=		oath.c oathdb.c base32.c util.c
CFLAGS+=	-Wall

LDADD+=		-lcrypto -lm
DPADD+=		${LIBCRYPTO} ${LIBM}

NOMAN=		yes

BINOWN=		root
BINGRP=		_token
BINMODE=	2555
