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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <err.h>

#include "oath.h"
#include "base32.h"

static int	 oathdb_sync(struct oathdb *);

struct oathdb *
oathdb_open(int read_only)
{
	FILE		*fp;
	struct oathdb	*db = NULL;
	int		 fd;
	char		*line = NULL;
	size_t		 linesz = 0;
	ssize_t		 linelen;

	if (read_only) {
		if ((fp = fopen(OATH_DB_PATH, "r")) == NULL) {
			/* DB does not exist, oath is disabled */
			warn("%s", OATH_DB_PATH);
			return (NULL);
		}
	} else {
		if ((fp = fopen(OATH_DB_PATH, "r+")) == NULL) {
			/* DB does not exist, oath is disabled */
			warn("%s", OATH_DB_PATH);
			return (NULL);
		}

		if (flock(fileno(fp), LOCK_EX|LOCK_NB) == -1) {
			warn("flock %s", OATH_DB_PATH);
			fclose(fp);
			return (NULL);
		}
	}

	if ((db = calloc(1, sizeof(*db))) == NULL) {
		warn("calloc");
		return (NULL);
	}

	db->db_read_only = read_only;
	db->db_fp = fp;

	if (!read_only) {
		strlcpy(db->db_tmp, "/tmp/oath-XXXXXXXXXX",
		    sizeof(db->db_tmp));
		if ((fd = mkstemp(db->db_tmp)) == -1) {
			warn("mkstemp");
			return (NULL);
		}

		if ((db->db_tmpfp = fdopen(fd, "r+")) == NULL) {
			warn("fdopen");
			return (NULL);
		}

		while ((linelen = getline(&line, &linesz, fp)) != -1) {
			/* normalize and validate line */
			line[strcspn(line, "\r\n")] = '\0';

			/* write it to the temporary file */
			fprintf(db->db_tmpfp, "%s\n", line);
		}
		free(line);
	}

	return (db);
}

int
oathdb_sync(struct oathdb *db)
{
	char		*line = NULL;
	size_t		 linesz = 0;
	ssize_t		 linelen;

	if (db->db_read_only) {
		warn("file opened read-only %s", OATH_DB_PATH);
		return (-1);
	}

	if (fseek(db->db_fp, 0, SEEK_SET) == -1) {
		warn("could not rewind %s", OATH_DB_PATH);
		return (-1);
	}
	if (fseek(db->db_tmpfp, 0, SEEK_SET) == -1) {
		warn("could not rewind %s", db->db_tmp);
		return (-1);
	}
	if (ftruncate(fileno(db->db_fp), 0) == -1) {
		warn("could not truncate %s", OATH_DB_PATH);
	}
	while ((linelen = getline(&line, &linesz, db->db_tmpfp))!= -1) {
		if (fputs(line, db->db_fp) == EOF) {
			warn("could not write to %s", OATH_DB_PATH);
			free(line);
			return (-1);
		}
	}

	return (0);
}

int
oathdb_close(struct oathdb *db)
{
	int		 ret = 0;

	if (db == NULL)
		return (0);

	if (!db->db_read_only)
		ret = oathdb_sync(db);

	if (db->db_fp != NULL)
		fclose(db->db_fp);
	if (db->db_tmpfp != NULL)
		fclose(db->db_tmpfp);

	if (strncmp("/tmp/oath", db->db_tmp, strlen("/tmp/oath")) == 0)
		unlink(db->db_tmp);

	free(db);

	return (ret);
}

char *
oathdb_nextval(char **line)
{
	char	*p, *val;

	if ((p = strchr(*line, ':')) == NULL)
		return (NULL);

	*p++ = '\0';
	val = *line;
	*line = p;

	return (val);
}

struct oath_key *
oathdb_parsekey(const char *name, char *line)
{
	struct oath_key	*oak = NULL;
	const char	*errstr;
	char		*val = line;
	time_t		 created;
	unsigned int	 type;
	unsigned int	 hash;
	uint64_t	 counter;
	uint8_t		 digits;
	time_t		 margin;
	char		*key;

	/*
	 * The format is (name: is already split out):
	 *   name:created:type:hash:digits:counter:margin:key
	 * or for TOTP defaults
	 *   name:::::::key
	 */
	/* created */
	if ((val = oathdb_nextval(&line)) == NULL)
		return (NULL);

	if (*val == ':' || *val == '0')
		created = 0;
	else {
		created = strtonum(val, 0, INT64_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
	}

	/* type */
	if ((val = oathdb_nextval(&line)) == NULL)
		return (NULL);

	if (*val == ':' || *val == '0')
		type = 0;
	else {
		type = strtonum(val, 0, OATH_TYPE_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
	}

	/* hash */
	if ((val = oathdb_nextval(&line)) == NULL)
		return (NULL);

	if (*val == ':' || *val == '0')
		hash = OATH_HASH;
	else {
		hash = strtonum(val, 0, OATH_HASH_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
	}

	/* digits */
	if ((val = oathdb_nextval(&line)) == NULL)
		return (NULL);

	if (*val == ':' || *val == '0')
		digits = OATH_DIGITS;
	else {
		digits = strtonum(val, 1, OATH_DIGITS_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
	}

	/* counter (or t0 in TOTP mode) */
	if ((val = oathdb_nextval(&line)) == NULL)
		return (NULL);

	if (*val == ':' || *val == '0')
		counter = OATH_HOTP_COUNTER;
	else {
		/* XXX strtonum's maximum is signed long long */
		counter = strtonum(val, 0, LLONG_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
	}

	/* margin */
	if ((val = oathdb_nextval(&line)) == NULL)
		return (NULL);

	if (*val == ':' || *val == '0')
		margin = OATH_TOTP_MARGIN;
	else {
		margin = strtonum(val, 0, INT64_MAX, &errstr);
		if (errstr != NULL)
			return (NULL);
	}

	/* base32 key */
	key = line;

	if ((oak = calloc(1, sizeof(*oak))) == NULL ||
	    (oak->oak_name = strdup(name)) == NULL ||
	    (oak->oak_key = strdup(key)) == NULL) {
		oath_freekey(oak);
		return (NULL);
	}

	oak->oak_created = created;
	oak->oak_type = type;
	oak->oak_hash = hash;
	oak->oak_digits = digits;
	oak->oak_counter = counter;
	oak->oak_margin = margin;

	return (oak);
}

struct oath_key *
oathdb_getkey(struct oathdb *db, const char *name)
{
	struct oath_key	*oak = NULL;
	char		*line = NULL, *entry, *val;
	size_t		 linesz = 0;
	ssize_t		 linelen;
	FILE		*fp;

	/* either read from the writeable copy or from the file directly */
	fp = db->db_read_only ? db->db_fp : db->db_tmpfp;

	/* start from the beginning */
	if (fseek(fp, 0, SEEK_SET) == -1) {
		warn("could not rewind %s", OATH_DB_PATH);
		return (NULL);
	}

	while ((linelen = getline(&line, &linesz, fp))!= -1) {
		line[strcspn(line, "\r\n")] = '\0';
		entry = line;

		/* find key */
		if ((val = oathdb_nextval(&entry)) == NULL) {
			warnx("invalid line in %s", OATH_DB_PATH);
			continue;
		}
		if (strcmp(name, val) != 0)
			continue;

		if ((oak = oathdb_parsekey(name, entry)) == NULL) {
			warnx("failed to parse line in %s", OATH_DB_PATH);
			break;
		}
	}

	free(line);
	return (oak);
}

int
oathdb_setkey(struct oathdb *db, struct oath_key *oak)
{
	char		*keyline = NULL;
	char		*line = NULL, *entry, *val, *line2 = NULL;
	size_t		 linesz = 0;
	ssize_t		 linelen;
	int		 ret = -1, found = 0;

	if (db->db_read_only) {
		warn("file opened read-only %s", OATH_DB_PATH);
		return (-1);
	}

	if (oathdb_sync(db) != 0)
		return (-1);

	/* start from the beginning */
	if (fseek(db->db_fp, 0, SEEK_SET) == -1) {
		warn("could not rewind %s", OATH_DB_PATH);
		goto done;
	}
	if (fseek(db->db_tmpfp, 0, SEEK_SET) == -1) {
		warn("could not rewind %s", db->db_tmp);
		return (-1);
	}
	if (ftruncate(fileno(db->db_tmpfp), 0) == -1) {
		warn("could not truncate %s", OATH_DB_PATH);
	}

	if (oak->oak_key != NULL) {
		/* Fill in default values */
		if (oak->oak_hash == OATH_HASH_DEFAULT)
			oak->oak_hash = OATH_HASH;
		if (oak->oak_type == OATH_TYPE_TOTP &&
		    oak->oak_margin == 0)
			oak->oak_margin = OATH_TOTP_MARGIN;
		if (oak->oak_created == 0)
			oak->oak_created = time(NULL);
		if (oak->oak_digits == 0)
			oak->oak_digits = OATH_DIGITS;

		/* create new line */
		if (asprintf(&keyline,
		    "%s:%lld:%u:%u:%u:%lld:%lld:%s",
		    oak->oak_name,
		    oak->oak_created,
		    oak->oak_type,
		    oak->oak_hash,
		    oak->oak_digits,
		    oak->oak_counter,
		    oak->oak_margin,
		    oak->oak_key) == -1)
			goto done;
	}

	while ((linelen = getline(&line, &linesz, db->db_fp))!= -1) {
		line[strcspn(line, "\r\n")] = '\0';

		if ((entry = line2 = strdup(line)) == NULL) {
			warn("strdup");
			continue;
		}

		/* find key */
		if ((val = oathdb_nextval(&entry)) == NULL) {
			warnx("invalid line in %s", OATH_DB_PATH);
			free(line2);
			continue;
		}

		if (strcmp(oak->oak_name, val) != 0) {
			free(line2);
			if (fprintf(db->db_tmpfp, "%s\n", line) == EOF) {
				warn("could not write to %s", OATH_DB_PATH);
				goto done;
			}
			continue;
		}
		free(line2);

		/* remove duplicate or line if no new key was given */
		if (found++ || keyline == NULL) {
			continue;
		}

		if (fprintf(db->db_tmpfp, "%s\n", keyline) == EOF) {
			warn("could not write update to %s", OATH_DB_PATH);
			goto done;
		}
	}

	/* add line if it is a new entry */
	if (keyline != NULL && !found &&
	    fprintf(db->db_tmpfp, "%s\n", keyline) == EOF) {
		warn("could not write update to %s", OATH_DB_PATH);
		goto done;
	}

	ret = 0;
 done:
	free(line);
	free(keyline);

	return (ret);
}

int
oathdb_delkey(struct oathdb *db, char *name)
{
	struct oath_key	 oak;

	/* An empty key will cause setkey to delete the entry */
	oak.oak_name = name;
	oak.oak_key = NULL;

	return (oathdb_setkey(db, &oak));
}

int
oathdb_putkey(struct oathdb *db, char *line)
{
	struct oath_key	*oak = NULL;
	char		*name;
	int		 ret;

	if ((name = oathdb_nextval(&line)) == NULL) {
		warnx("invalid name");
		return (-1);
	}

	if ((oak = oathdb_parsekey(name, line)) == NULL) {
		warnx("invalid line");
		return (-1);
	}

	ret = oathdb_setkey(db, oak);
	oath_freekey(oak);

	return (ret);
}
