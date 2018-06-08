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
