SRCS+=		otp.c otpdb.c base32.c util.c
CFLAGS+=	-Wall

LDADD+=		-lcrypto
DPADD+=		${LIBCRYPTO}

NOMAN=		yes

BINOWN=		root
BINGRP=		_token
BINMODE=	2555
