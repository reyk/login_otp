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
#include <stdlib.h>
#include <getopt.h>
#include <err.h>

#include "oath.h"

__dead void	 usage(void);

__dead void
usage(void)
{
	extern const char *__progname;
	fprintf(stderr, "usage: %s [-g] -k key\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		 ch;
	char		 key[1024];
	int		 keylen = -1;
	int		 totp;
	int		 digits = 6;
	int		 shabits = 160;
	time_t		 t0 = 0;
	time_t		 x = 30;

	while ((ch = getopt(argc, argv, "gk:")) != -1) {
		switch (ch) {
		case 'g':
			if (oath_generate_key(12) == -1)
				return (1);
			return (0);
		case 'k':
			if ((keylen = oath_decode_key(optarg,
			    key, sizeof(key))) == -1)
				errx(1, "decode_key");
			break;
		default:
			usage();
		}
	}

	if (keylen == -1)
		usage();

	if ((totp = oath_totp(key, keylen, t0, x, digits, shabits)) == -1)
		return (-1);

	printf("%0*d\n", digits, totp);

	return (0);
}
