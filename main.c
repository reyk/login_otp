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

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <grp.h>
#include <err.h>

#include "oath.h"

__dead void	 usage(void);

__dead void
usage(void)
{
	extern const char *__progname;
	fprintf(stderr, "usage: %s [-cdgilpt] [user]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char		 buf[BUFSIZ];
	struct oathdb	*db;
	struct oath_key	*oak, oakey;
	int		 ch;
	int		 dflag = 0, gflag = 0, iflag = 0, lflag = 0, pflag = 0;
	int		 cflag = 0, tflag = 0;
	char		*name = NULL, *url = NULL;
	int		 fd, flags;
	mode_t		 mode, omask;
	struct group	*gr;
	gid_t		 gid;

	if (geteuid()) {
		if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio rpath wpath cpath flock getpw fattr", NULL) == -1)
			err(1, "pledge");
	}

	while ((ch = getopt(argc, argv, "cdgilpt")) != -1) {
		switch (ch) {
		case 'c':
			cflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'g':
			gflag = 1;
			break;
		case 'i':
			iflag++;
			break;
		case 'l':
			lflag = 0;
			break;
		case 'p':
			pflag = 1;
			break;
		case 't':
			tflag = 1;
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

	if (pflag && geteuid())
		errx(1, "-p requires root privileges");

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

	if (dflag) {
		if ((db = oathdb_open(0)) == NULL)
			errx(1, "open db");

		memset(&oakey, 0, sizeof(oakey));
		oakey.oak_name = name;
		oakey.oak_key = NULL;

		if (oathdb_setkey(db, &oakey) != 0)
			errx(1, "set key");

		if (oathdb_close(db) != 0)
			errx(1, "close db");
	}

	if (gflag) {
		if (oath_generate_key(OATH_KEYLEN, buf, sizeof(buf)) == -1)
			errx(1, "failed to generate key");

		if ((db = oathdb_open(0)) == NULL)
			errx(1, "open db");

		memset(&oakey, 0, sizeof(oakey));
		oakey.oak_name = name;
		oakey.oak_key = buf;

		if (oathdb_setkey(db, &oakey) != 0)
			errx(1, "set key");

		if (oathdb_close(db) != 0)
			errx(1, "close db");

		/* A user can print own key once at initialization */
		pflag = 1;
	}

	if (pflag) {
		if ((db = oathdb_open(1)) == NULL)
			errx(1, "open db");

		if ((oak = oathdb_getkey(db, name)) == NULL)
			errx(1, "key not found");

		if (oathdb_close(db) != 0)
			errx(1, "close db");

		if (oath_printkey(oak, buf, sizeof(buf)) == -1)
			errx(1, "key");
		if (oath_printkeyurl(oak, &url) == -1)
			errx(1, "key url");
		oath_freekey(oak);

		if (geteuid()) {
			printf("!!! WARNING: "
			    "PLEASE KEEP THE FOLLOWING KEY SECRET !!!\n\n");
			printf("Load the following key or URL "
			    "in the authenticator:\n\n");
		}
		printf("Name:\t%s\n", name);
		printf("Key:\t%s\n", buf);
		printf("URL:\t%s\n", url);
		free(url);
	}

	return (0);
}
