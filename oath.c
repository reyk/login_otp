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
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <getopt.h>
#include <err.h>

#include <openssl/hmac.h>

#include "common.h"
#include "base32.h"

int
oath(struct oath_key *oak, time_t *remain)
{
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen;
	unsigned char	 key[BUFSIZ];
	int		 keylen;
	int		 offset, bin_code;
	const EVP_MD	*evp_md;
	int		 otp;
	uint64_t	 c;
	time_t		 now, r;

	switch (oak->oak_hash) {
	case OATH_HASH_DEFAULT:
	case OATH_HASH_SHA1:
		evp_md = EVP_sha1();
		break;
	case OATH_HASH_SHA256:
		evp_md = EVP_sha256();
		break;
	case OATH_HASH_SHA512:
		evp_md = EVP_sha512();
		break;
	default:
		warnx("invalid hash %u does not exist", oak->oak_hash);
		return (-1);
	}

	if (oak->oak_digits > OATH_DIGITS_MAX) {
		warnx("invalid number of digits");
		return (-1);
	}

	if ((keylen = oath_decode_key(oak->oak_key, key, sizeof(key))) == -1) {
		warnx("invalid key encoding");
		return (-1);
	}

	now = time(NULL);

	if (oak->oak_type == OATH_TYPE_HOTP) {
		/* HOTP(K, C) = Truncate(HMAC-SHA-1(K, C)) */
		c = oak->oak_counter;
		r = -1;
	} else {
		/* TOTP(K, T) = HOTP(K, (time - T0) / X) */
		c = ((uint64_t)now - oak->oak_counter) / oak->oak_margin;
		r = oak->oak_margin -
		    (((uint64_t)now - oak->oak_counter) % oak->oak_margin);
	}

	if (remain != NULL)
		*remain = r;

	c = htobe64(c);
	mdlen = sizeof(md);
	HMAC(evp_md, key, keylen, (void *)&c, (int)sizeof(c), md, &mdlen);

	offset = md[mdlen - 1] & 0xf;
	bin_code =
	    (md[offset + 0] & 0x7f) << 24 |
	    (md[offset + 1] & 0xff) << 16 |
	    (md[offset + 2] & 0xff) << 8 |
	    (md[offset + 3] & 0xff);

	otp = (int)(bin_code % (int)pow(10, oak->oak_digits));

	explicit_bzero(key, sizeof(key));

	return (otp);
}

int
oath_generate_key(size_t length, char *buf, size_t buflen)
{
	char		 key[1024];

	if (length > sizeof(key)) {
		warnx("key too long");
		return (-1);
	}

	arc4random_buf(key, length);
	if (base32_encode(key, length, buf, buflen) == -1) {
		warnx("base32_encode");
		return (-1);
	}

	return (0);
}

int
oath_decode_key(char *b32, unsigned char *key, size_t keylen)
{
	size_t		 i, j;
	size_t		 len;

	for (i = j = 0; i < strlen(b32); i++) {
		if (b32[i] == '-' || b32[i] == ' ')
			continue;
		b32[j++] = toupper((int)b32[i]);
	}
	b32[j] = '\0';
	if ((len = base32_decode(b32, key, keylen)) == -1)
		return (-1);
	return ((int)len);
}

int
oath_printkey(struct oath_key *oak, char *buf, size_t len)
{
	size_t		 i, j;

	memset(buf, 0, len);
	for (i = j = 0; i < strlen(oak->oak_key); i++) {
		if (j >= len - 1)
			return (-1);
		if (i != 0 && (i % 4) == 0)
			buf[j++] = ' ';
		if (j >= len - 1)
			return (-1);
		buf[j++] = tolower((int)oak->oak_key[i]);
	}

	return (0);
}

int
oath_printkeyurl(struct oath_key *oak, char **url)
{
	char		 issuer[BUFSIZ];
	char		*alg, *opt, *uename = NULL, *ueissuer = NULL;
	uint64_t	 val;
	int		 ret;

	/* Use domainname and fallback to hostname */
	if (getdomainname(issuer, sizeof(issuer)) == -1 &&
	    gethostname(issuer, sizeof(issuer)) == -1)
		return (-1);

	if ((uename = url_encode(oak->oak_name)) == NULL ||
	    (ueissuer = url_encode(issuer)) == NULL) {
		free(uename);
		free(ueissuer);
		return (-1);
	}

	switch (oak->oak_hash) {
	case OATH_HASH_DEFAULT:
	case OATH_HASH_SHA1:
		alg = "SHA1";
		break;
	case OATH_HASH_SHA256:
		alg = "SHA256";
		break;
	case OATH_HASH_SHA512:
		alg = "SHA512";
		break;
	}

	if (oak->oak_type == OATH_TYPE_HOTP) {
		opt = "counter";
		val = oak->oak_counter;
	} else {
		opt = "period";
		val = oak->oak_margin;
	}

	ret = asprintf(url, "otpauth://"
	    "%s/%s?secret=%s&issuer=%s&algorithm=%s&digits=%u&%s=%llu",
	    oak->oak_type == OATH_TYPE_HOTP ? "hotp" : "totp",
	    uename,
	    oak->oak_key,
	    ueissuer,
	    alg,
	    oak->oak_digits,
	    opt, val);

	free(uename);
	free(ueissuer);

	return (ret);
}

struct oath_key *
oath_parsekeyurl(const char *url)
{
	struct oath_key		*oak;
	char			*v, *p, *s = NULL, *key, *val;
	size_t			 len;
	const char		*errstr = NULL;
	char			 buf[BUFSIZ];

	if ((oak = calloc(1, sizeof(*oak))) == NULL)
		return (NULL);

	if ((p = s = strdup(url)) == NULL)
		goto fail;

	len = strlen("otpauth://");
	if (strncmp("otpauth://", p, len) != 0) {
		errstr = "invalid url";
		goto fail;
	}
	p += len;
	v = p;

	/* type */
	if ((p = strchr(p, '/')) == NULL)
		goto fail;
	*p++ = '\0';

	if (strcasecmp("totp", v) == 0)
		oak->oak_type = OATH_TYPE_TOTP;
	else if (strcasecmp("hotp", v) == 0)
		oak->oak_type = OATH_TYPE_HOTP;
	else {
		errstr = "invalid oath type";
		goto fail;
	}
	v = p;

	/* name */
	if ((p = strchr(p, '?')) == NULL)
		goto fail;
	*p++ = '\0';
	if ((oak->oak_name = strdup(v)) == NULL ||
	    url_decode(oak->oak_name) == NULL)
		goto fail;
	v = p;

	/* parameters */
	for (v = p; p != NULL; v = p) {
		if ((p = strchr(p, '=')) == NULL)
			goto fail;
		*p++ = '\0';

		key = v;
		val = p;

		if ((p = strchr(p, '&')) != NULL)
			*p++ = '\0';

		if (strcasecmp("secret", key) == 0) {
			if ((oak->oak_key = strdup(val)) == NULL)
				goto fail;
			if (oath_decode_key(oak->oak_key,
			    buf, sizeof(buf)) == -1) {
				errstr = "base32 key decoding failed";
				goto fail;
			}
		} else if (strcasecmp("issuer", key) == 0) {
			/* not used */
		} else if (strcasecmp("algorithm", key) == 0) {
			if (strcasecmp("sha1", val) == 0)
				oak->oak_hash = OATH_HASH_SHA1;
			else if (strcasecmp("sha256", val) == 0)
				oak->oak_hash = OATH_HASH_SHA256;
			else if (strcasecmp("sha512", val) == 0)
				oak->oak_hash = OATH_HASH_SHA512;
			else {
				errstr = "invalid hash algorithm";
				goto fail;
			}
		} else if (strcasecmp("digits", key) == 0) {
			oak->oak_digits = strtonum(val,
			    1, OATH_DIGITS_MAX, &errstr);
			if (errstr != NULL)
				goto fail;
		} else if (strcasecmp("counter", key) == 0) {
			if (oak->oak_type != OATH_TYPE_HOTP)
				goto fail;
			/* XXX strtonum's maximum is signed long long */
			oak->oak_counter = strtonum(val,
			    -1, LLONG_MAX, &errstr);
			if (errstr != NULL)
				goto fail;
		} else if (strcasecmp("period", key) == 0) {
			if (oak->oak_type != OATH_TYPE_TOTP)
				goto fail;
			oak->oak_margin = strtonum(val,
			    0, INT64_MAX, &errstr);
			if (errstr != NULL)
				goto fail;
		}
	}

	explicit_bzero(s, strlen(s));
	free(s);

	return (oak);

 fail:
	if (errstr == NULL)
		errstr = "failed to parse url";
	warnx("%s", errstr);

	if (s != NULL)
		explicit_bzero(s, strlen(s));
	free(s);
	oath_freekey(oak);

	return (NULL);
}

void
oath_freekey(struct oath_key *oak)
{
	if (oak == NULL)
		return;
	if (oak->oak_key != NULL)
		explicit_bzero(oak->oak_key, strlen(oak->oak_key));
	free(oak->oak_name);
	free(oak->oak_key);
	free(oak);
}
