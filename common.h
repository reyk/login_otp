/*
 * Copyright (c) 2018 Reyk Floeter <contact@reykfloeter.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/resource.h>

#include <limits.h>
#include <signal.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <login_cap.h>
#include <bsd_auth.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <err.h>
#include <util.h>
#include <limits.h>
#include <readpassphrase.h>

#ifndef _OATH_COMMON_H
#define _OATH_COMMON_H

#define OATH_DB_PATH		"/etc/oath"
#define OATH_GROUP		"_token"
#define OATH_KEYLEN		16

/* Some more defaults */
#define OATH_HOTP_COUNTER	0
#define OATH_TOTP_MARGIN	30
#define OATH_HASH		OATH_HASH_SHA1
#define OATH_DIGITS		6
#define OATH_DIGITS_MAX		9

struct oathdb {
	FILE			*db_fp;
	FILE			*db_tmpfp;
	char			 db_tmp[PATH_MAX];
	int			 db_read_only;
};

enum oath_type {
	OATH_TYPE_TOTP		= 0,
	OATH_TYPE_HOTP		= 1,
};
#define	OATH_TYPE_MAX		OATH_TYPE_HOTP

enum oath_hash {
	OATH_HASH_DEFAULT	= 0,
	OATH_HASH_SHA1		= 160,
	OATH_HASH_SHA256	= 256,
	OATH_HASH_SHA512	= 512
};
#define	OATH_HASH_MAX		OATH_HASH_SHA512

struct oath_key {
	char			*oak_name;
	time_t			 oak_created;
	enum oath_type		 oak_type;
	enum oath_hash		 oak_hash;
	uint8_t			 oak_digits;
	uint64_t		 oak_counter;
	time_t			 oak_margin;
	char			*oak_key;
};

enum login_mode {
	MODE_LOGIN	= 0,
	MODE_CHALLENGE	= 1,
	MODE_RESPONSE	= 2
};

enum auth_ok {
	AUTH_OK		= 0,
	AUTH_FAILED	= -1
};

extern FILE *back;
extern char *__progname;

/* util.c */
char	*url_encode(const char *);
const char
	*url_decode(char *);

/* oath.c */
int	 oath(struct oath_key *);
int	 oath_decode_key(char *, unsigned char *, size_t);
int	 oath_generate_key(size_t, char *, size_t);
int	 oath_printkey(struct oath_key *, char *, size_t);
int	 oath_printkeyurl(struct oath_key *, char **);
struct oath_key
	*oath_parsekeyurl(const char *);
void	 oath_freekey(struct oath_key *);

/* oathdb.c */
struct oathdb
	*oathdb_open(int);
int	 oathdb_close(struct oathdb *);
struct oath_key *
	 oathdb_getkey(struct oathdb *, const char *);
int	 oathdb_setkey(struct oathdb *, struct oath_key *);
int	 oathdb_putkey(struct oathdb *, char *);
int	 oathdb_delkey(struct oathdb *, char *);

/* login_passwd.c */
int pwd_login(char *, char *, char *, int, char *, struct passwd *);

#endif /* _OATH_COMMON_H */
