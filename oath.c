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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <err.h>

#include <openssl/hmac.h>

#include "oath.h"
#include "base32.h"

int
oath_hotp(unsigned char *key, size_t keylen, uint64_t c, uint8_t digits)
{
	/* HOTP(K, C) = Truncate(HMAC-SHA-1(K, C)) */
	return (oath(key, keylen, c, digits, 160));
}

int
oath_totp(unsigned char *key, size_t keylen,
    time_t t0, time_t x, uint8_t digits, uint16_t shabits)
{
	uint64_t	 t;

	/* TOTP(K, T) = HOTP(K, (time - T0) / X) */
	t = ((uint64_t)time(NULL) - t0) / x;

	return (oath(key, keylen, t, digits, shabits));
}

int
oath(unsigned char *key, size_t keylen, uint64_t c, uint8_t digits,
    uint16_t shabits)
{
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen;
	int		 offset, bin_code;
	const EVP_MD	*evp_md;
	int		 otp;

	switch (shabits) {
	case 160:
		evp_md = EVP_sha1();
		break;
	case 256:
		evp_md = EVP_sha256();
		break;
	case 512:
		evp_md = EVP_sha512();
		break;
	default:
		warnx("invalid sha%u does not exist", shabits);
		return (-1);
	}

	if (digits > 9) {
		warnx("invalid number of digits");
		return (-1);
	}

	c = htobe64(c);
	mdlen = sizeof(md);
	HMAC(evp_md, key, (int)keylen, (void *)&c, (int)sizeof(c), md, &mdlen);

	offset = md[mdlen - 1] & 0xf;
	bin_code =
	    (md[offset + 0] & 0x7f) << 24 |
	    (md[offset + 1] & 0xff) << 16 |
	    (md[offset + 2] & 0xff) << 8 |
	    (md[offset + 3] & 0xff);

	otp = (int)(bin_code % 1000000);

	return (otp);
}

int
oath_generate_key(size_t length)
{
	char		 key[1024];
	char		 b32[2048];
	size_t		 i;

	if (length > sizeof(key)) {
		warnx("key too long");
		return (-1);
	}

	arc4random_buf(key, length);
	if (base32_encode(key, length, b32, sizeof(b32)) == -1) {
		warnx("base32_encode");
		return (-1);
	}
	for (i = 0; i < strlen(b32); i++) {
		if (i && (i % 4) == 0)
			putchar(' ');
		putchar(tolower((int)b32[i]));
	}
	putchar('\n');

	return (0);
}

size_t
oath_decode_key(char *b32, unsigned char *key, size_t keylen)
{
	size_t		 i, j;
	size_t		 b32len;

	for (i = j = 0; i < strlen(b32); i++) {
		if (b32[i] == '-' || b32[i] == ' ')
			continue;
		b32[j++] = toupper((int)b32[i]);
	}
	b32[j] = '\0';
	if ((b32len = base32_decode(b32, key, keylen)) == -1)
		return (-1);
	return (b32len);
}
