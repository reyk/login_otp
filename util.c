/*
 * Copyright (c) 2014, 2018 Reyk Floeter <contact@reykfloeter.com>
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "common.h"

char *
url_encode(const char *src)
{
	static char	 hex[] = "0123456789ABCDEF";
	char		*dp, *dst;
	unsigned char	 c;

	/* We need 3 times the memory if every letter is encoded. */
	if ((dst = calloc(3, strlen(src) + 1)) == NULL)
		return (NULL);

	for (dp = dst; *src != 0; src++) {
		c = (unsigned char) *src;
		if (c == ' ' || c == '#' || c == '%' || c == '?' || c == '"' ||
		    c == '&' || c == '<' || c <= 0x1f || c >= 0x7f) {
			*dp++ = '%';
			*dp++ = hex[c >> 4];
			*dp++ = hex[c & 0x0f];
		} else
			*dp++ = *src;
	}
	return (dst);
}

const char *
url_decode(char *url)
{
	char		*p, *q;
	char		 hex[3];
	unsigned long	 x;

	hex[2] = '\0';
	p = q = url;

	while (*p != '\0') {
		switch (*p) {
		case '%':
			/* Encoding character is followed by two hex chars */
			if (!(isxdigit((unsigned char)p[1]) &&
			    isxdigit((unsigned char)p[2])))
				return (NULL);

			hex[0] = p[1];
			hex[1] = p[2];

			/*
			 * We don't have to validate "hex" because it is
			 * guaranteed to include two hex chars followed by nul.
			 */
			x = strtoul(hex, NULL, 16);
			*q = (char)x;
			p += 2;
			break;
		default:
			*q = *p;
			break;
		}
		p++;
		q++;
	}
	*q = '\0';

	return (url);
}
