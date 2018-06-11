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

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <grp.h>
#include <err.h>

#include "common.h"

__dead static void	 usage(void);

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-agiprt] [-c check] [-d digits]"
	    " [-u url] [user]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char		 buf[BUFSIZ];
	struct oathdb	*db;
	struct oath_key	*oak = NULL, oakey;
	int		 ch;
	int		 digits = OATH_DIGITS;
	int		 gflag = 0, iflag = 0, pflag = 0;
	int		 aflag = 0, cflag = 0, rflag = 0, tflag = 0;
	char		*name = NULL, *url = NULL, *otpauth = NULL;
	int		 fd, flags;
	mode_t		 mode, omask;
	struct group	*gr;
	gid_t		 gid;
	int		 otp1, otp, ret = -1;
	const char	*errstr;
	uint64_t	 counter;
	time_t		 remain;

	if (geteuid()) {
		if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio rpath wpath cpath flock"
		    " getpw fattr", NULL) == -1)
			err(1, "pledge");
	}

	while ((ch = getopt(argc, argv, "ac:d:giprtu:")) != -1) {
		switch (ch) {
		case 'a':
			aflag = 1;
			break;
		case 'c':
			cflag = 1;

			otp1 = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				err(1, "otp %s", errstr);
			break;
		case 'd':
			digits = strtonum(optarg, 1, OATH_DIGITS_MAX, &errstr);
			if (errstr != NULL)
				err(1, "digits %s", errstr);
			break;
		case 'g':
			gflag = 1;
			break;
		case 'i':
			iflag++;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			rflag = 1;
			break;
		case 't':
			tflag = 1;
			break;
		case 'u':
			otpauth = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (geteuid() && argc)
		errx(1, "user option requires root privileges");
	if (argc)
		name = argv[0];
	else
		name = getlogin();

	/* check or print OTP from key */
	if (cflag || tflag) {
		if ((db = oathdb_open(1)) == NULL)
			errx(1, "open db");

		if ((oak = oathdb_getkey(db, name)) == NULL) {
			warnx("key not found");
			goto fail;
		}

		if (oathdb_close(db) != 0) {
			warnx("close db");
			goto fail;
		}
		db = NULL;

		if ((otp = oath(oak, &remain)) == -1) {
			warnx("failed to get otp");
			goto fail;
		}

		if (cflag) {
			if (otp1 != otp)
				ret = EXIT_FAILURE;
		} else if (tflag) {
			printf("%0*u", oak->oak_digits, otp);
			if (remain >= 0)
				printf("\t\t%02lld seconds left", remain);
			printf("\n");
		}

		oath_freekey(oak);
		oak = NULL;
	}

	if (pflag && geteuid())
		errx(1, "-p requires root privileges");

	/* initialize database */
	if (iflag) {
		if (geteuid())
			errx(1, "-i requires root privileges");

		/* Get group */
		if ((gr = getgrnam(OATH_GROUP)) != NULL)
			gid = gr->gr_gid;
		endgrent();
		if (gr == NULL)
			errx(1, "group not found: %s", OATH_GROUP);

		/* Create empty database file */
		mode = 0660;
		flags = O_WRONLY|O_CREAT;
		flags |= iflag > 1 ? O_TRUNC : O_EXCL;
		omask = umask(~mode);
		if ((fd = open(OATH_DB_PATH, flags, mode)) == -1) {
			umask(omask);
			err(1, "open %s", OATH_DB_PATH);
		}
		umask(omask);
		if (fchown(fd, 0, gid) == -1) {
			close(fd);
			unlink(OATH_DB_PATH);
			err(1, "mode %s", OATH_DB_PATH);
		}
		close(fd);
	}

	/* remove key */
	if (rflag) {
		if ((db = oathdb_open(0)) == NULL)
			errx(1, "open db");

		memset(&oakey, 0, sizeof(oakey));
		oakey.oak_name = name;
		oakey.oak_key = NULL;

		if (oathdb_setkey(db, &oakey) != 0) {
			warnx("set key");
			goto fail;
		}

		if (oathdb_close(db) != 0)
			errx(1, "close db");
		db = NULL;
	}

	/* generate key */
	if (gflag) {
		if (oath_generate_key(OATH_KEYLEN, buf, sizeof(buf)) == -1)
			errx(1, "failed to generate key");

		if ((db = oathdb_open(0)) == NULL) {
			warnx("open db");
			goto fail;
		}

		if (otpauth == NULL) {
			memset(&oakey, 0, sizeof(oakey));
			oakey.oak_name = name;
			oakey.oak_digits = digits;
			oakey.oak_key = buf;
			oak = &oakey;
		} else {
			if ((oak = oath_parsekeyurl(otpauth)) == NULL) {
				warnx("invalid url");
				goto fail;
			}
			if (geteuid() &&
			    strcmp(oak->oak_name, name) != 0) {
				warnx("key name does not match user");
				goto fail;
			}
		}

		if (oathdb_setkey(db, oak) != 0) {
			warnx("set key");
			goto fail;
		}

		if (otpauth != NULL) {
			explicit_bzero(otpauth, strlen(otpauth));
			otpauth = NULL;
			oath_freekey(oak);
			oak = NULL;
		}
		explicit_bzero(buf, sizeof(buf));

		if (oathdb_close(db) != 0)
			errx(1, "close db");
		db = NULL;

		/* A user can print own key once at initialization */
		pflag = 1;
	}

	/* print key */
	if (pflag) {
		if ((db = oathdb_open(1)) == NULL)
			errx(1, "open db");

		if ((oak = oathdb_getkey(db, name)) == NULL) {
			warnx("key not found");
			goto fail;
		}

		if (oathdb_close(db) != 0) {
			warnx("close db");
			goto fail;
		}
		db = NULL;

		if (oath_printkey(oak, buf, sizeof(buf)) == -1 ||
		    oath_printkeyurl(oak, &url) == -1) {
			warnx("print key");
			goto fail;
		}
		oath_freekey(oak);
		oak = NULL;

		if (geteuid()) {
			printf("!!! WARNING: "
			    "PLEASE KEEP THE FOLLOWING KEY SECRET !!!\n\n");
			printf("Load the following key or URL "
			    "in the authenticator:\n\n");
		}
		printf("Name:\t%s\n", name);
		printf("Key:\t%s\n", buf);
		printf("URL:\t%s\n", url);

		explicit_bzero(buf, sizeof(buf));
		explicit_bzero(url, strlen(url));
		free(url);
	}

	/* advance counter */
	if (aflag) {
		if ((db = oathdb_open(0)) == NULL)
			errx(1, "open db");

		if ((oak = oathdb_getkey(db, name)) == NULL) {
			warnx("key not found");
			goto fail;
		}

		if (oak->oak_type == OATH_TYPE_HOTP) {
			counter = oak->oak_counter + 1;
			if (counter > INT64_MAX ||
			    counter < oak->oak_counter) {
				warnx("counter wrapped, invalidating key");
				free(oak->oak_key);
				oak->oak_key = NULL;
			} else
				oak->oak_counter = counter;
			if (oathdb_setkey(db, oak) == -1) {
				warnx("key update failed");
				goto fail;
			}
		} else
			warnx("entry is not counter-based");

		if (oathdb_close(db) != 0)
			errx(1, "close db");
		db = NULL;
	}

	if (ret == -1)
		ret = EXIT_SUCCESS;
 fail:
	explicit_bzero(buf, sizeof(buf));
	if (otpauth != NULL)
		explicit_bzero(otpauth, strlen(otpauth));
	if (oak != NULL && oak != &oakey)
		oath_freekey(oak);
	if (db != NULL &&
	    oathdb_close(db) != 0)
		errx(1, "close db");
	return (ret);
}
