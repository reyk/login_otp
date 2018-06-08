/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <stdint.h>
#include <string.h>
#include "base32.h"

static const char _base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char _xbase32_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
static const char _zbase32_chars[] = "ybndrfg8ejkmcpqxot1uwisza345h769";

static int _base32_decode(const char *, const uint8_t *, uint8_t *, size_t);
static int _base32_encode(const char *, const uint8_t *, size_t,
	    uint8_t *, size_t);

int
base32_encode(const uint8_t *data, size_t datalen, uint8_t *buf, size_t buflen)
{
	return (_base32_encode(_base32_chars, data, datalen, buf, buflen));
}

int
base32_decode(const uint8_t *data, uint8_t *buf, size_t buflen)
{
	return (_base32_decode(_base32_chars, data, buf, buflen));
}

int
xbase32_encode(const uint8_t *data, size_t datalen, uint8_t *buf, size_t buflen)
{
	return (_base32_encode(_xbase32_chars, data, datalen, buf, buflen));
}

int
xbase32_decode(const uint8_t *data, uint8_t *buf, size_t buflen)
{
	return (_base32_decode(_xbase32_chars, data, buf, buflen));
}

int
zbase32_encode(const uint8_t *data, size_t datalen, uint8_t *buf, size_t buflen)
{
	return (_base32_encode(_zbase32_chars, data, datalen, buf, buflen));
}

int
zbase32_decode(const uint8_t *data, uint8_t *buf, size_t buflen)
{
	return (_base32_decode(_zbase32_chars, data, buf, buflen));
}

static int
_base32_encode(const char *alphabet,
    const uint8_t *data, size_t datalen, uint8_t *buf, size_t buflen)
{
	size_t	 c = 0, ch, idx, pad, next = 1, nbits = 8;

	memset(buf, 0, buflen);

	if (datalen > (1 << 28))
		return (-1);
	else if (datalen == 0)
		return (0);

	for (c = 0, ch = data[0];
	    (c < buflen) && (nbits > 0 || next < datalen); c++) {
		if (nbits < 5) {
			if (next < datalen) {
				ch <<= 8;
				ch |= data[next++] & 0xff;
				nbits += 8;
			} else {
				pad = 5 - nbits;
				ch <<= pad;
				nbits += pad;
			}
		}
		nbits -= 5;
		idx = 0x1f & (ch >> nbits);
		buf[c] = alphabet[idx];
	}

	return (c);
}

static int
_base32_decode(const char *alphabet,
    const uint8_t *data, uint8_t *buf, size_t buflen)
{
	int		 idx;
	size_t		 ch = 0;
	size_t		 nbits = 0;
	size_t		 c = 0;
	const uint8_t	*ptr;

	memset(buf, 0, buflen);

	for (ptr = data; c < buflen && *ptr; ++ptr) {
		ch <<= 5;
		nbits += 5;

		for (idx = strlen(alphabet); idx >= 0; idx--)
			if (alphabet[idx] == *ptr)
				break;
		if (idx < 0)
			return (-1);

		ch |= (size_t)idx;
		if (nbits >= 8) {
			buf[c++] = ch >> (nbits - 8);
			nbits -= 8;
		}
	}

	return (c);
}
