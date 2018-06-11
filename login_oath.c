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
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <grp.h>

#include "common.h"

FILE		*back = NULL;
struct oathdb	*oathdb = NULL;

__dead void	 fatal( const char *, ...);
char		*login_oath_challenge(const char *, struct oath_key **);
int		 login_oath_otp(const char *, struct oath_key **);
int		 login_oath_advance(const char *, struct oath_key **);

__dead void
fatal( const char *fmt, ...)
{
	va_list ap;

	if (oathdb != NULL)
		(void)oathdb_close(oathdb);

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	exit(1);
}

char *
login_oath_challenge(const char *user, struct oath_key **oakp)
{
	char			*challenge = NULL;
	struct oath_key		*oak;

	if (*oakp == NULL && (oak = *oakp = oathdb_getkey(oathdb, user)) == NULL)
		return (NULL);
	else
		oak = *oakp;

	if (asprintf(&challenge, "OTP + password for \"%s\":",
	    oak->oak_name) == -1)
		challenge = NULL;

	return (challenge);
}

int
login_oath_otp(const char *user, struct oath_key **oakp)
{
	struct oath_key		*oak;

	if (*oakp == NULL && (oak = *oakp = oathdb_getkey(oathdb, user)) == NULL)
		return (-1);
	else
		oak = *oakp;

	return (oath(oak, NULL));
}

int
login_oath_advance(const char *user, struct oath_key **oakp)
{
	struct oath_key		*oak;

	if (*oakp == NULL && (oak = *oakp = oathdb_getkey(oathdb, user)) == NULL)
		return (-1);
	else
		oak = *oakp;

	if (oak->oak_type != OATH_TYPE_HOTP)
		return (0);

	if (oath_advance_counter(oak) == -1)
		syslog(LOG_ERR, "HOTP counter wrapped: %s", oak->oak_name);
	if (oathdb_setkey(oathdb, oak) == -1)
		fatal("failed to update HOTP counter");

	return (0);
}

int
main(int argc, char *argv[])
{
	enum login_mode	 mode;
	int		 ch, ret, lastchance = 0, count;
	int		 dflag = 0, otp, otp1, digits, enforce_type;
	char		*user = NULL, *pass = NULL, *autherr = NULL;
	char		*wheel = NULL, *class = NULL, *auth = NULL;
	char		*challenge = NULL;
	char		 buf[BUFSIZ];
	char		 response[BUFSIZ];
	char		 otpbuf[BUFSIZ];
	struct rlimit	 rlim;
	sigset_t	 blockset;
	const char	*errstr;
	struct passwd	*pwd;
	struct oath_key	*oak = NULL;

	setpriority(PRIO_PROCESS, 0, 0);
	openlog(NULL, LOG_ODELAY, LOG_AUTH);

	sigemptyset(&blockset);
	sigaddset(&blockset, SIGINT);
	sigaddset(&blockset, SIGQUIT);
	sigaddset(&blockset, SIGTSTP);

	rlim.rlim_cur = rlim.rlim_max = 0;
#ifndef DEBUG
	if (setrlimit(RLIMIT_CORE, &rlim) == -1)
		syslog(LOG_ERR, "couldn't set core dump size to 0: %m");
#endif

	if (strcmp(__progname, "totp") == 0)
		enforce_type = OATH_TYPE_TOTP;
	else if (strcmp(__progname, "hotp") == 0)
		enforce_type = OATH_TYPE_HOTP;
	else {
		/* login_oath: allow any type as configured in the database */
		enforce_type = -1;
	}

	while ((ch = getopt(argc, argv, "ds:v:")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 's':
			if (strcmp(optarg, "login") == 0)
				mode = MODE_LOGIN;
			else if (strcmp(optarg, "challenge") == 0)
				mode = MODE_CHALLENGE;
			else if (strcmp(optarg, "response") == 0)
				mode = MODE_RESPONSE;
			else
				fatal("%s: invalid service", optarg);
			break;
		case 'v':
			if (strncmp(optarg, "wheel=", 6) == 0)
				wheel = optarg + 6;
			else if (strncmp(optarg, "lastchance=", 11) == 0)
				lastchance = (strcmp(optarg + 11, "yes") == 0);
			break;
		default:
			fatal("usage error1");
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 2)
		fatal("usage error2");
	if (argc >= 1)
		user = argv[0];
	if (argc == 2)
		class = argv[1];
	if (user == NULL)
		fatal("user not specified");

	pwd = getpwnam_shadow(user);

	if (pledge("stdio rpath wpath cpath flock tty id", NULL) == -1)
		fatal("pledge");

	if (dflag)
		back = stdout;
	else if ((back = fdopen(3, "r+")) == NULL)
		fatal("reopening back channel: %m");

	/*
	 * Open the database.  It can be opened in read-only mode if the TOTP
	 * type is enforced and we don't have to update the counter.
	 */
	if ((oathdb = oathdb_open(enforce_type == OATH_TYPE_TOTP ? 1 : 0)) == NULL)
		fatal("%s", OATH_DB_PATH);

	/* This is sligthly based on login_passwd/login.c. */
	switch (mode) {
	case MODE_RESPONSE:
		mode = MODE_LOGIN;
		count = -1;
		while (++count < sizeof(response) &&
		    read(3, &response[count], 1) == 1) {
			if (response[count] == '\0' && ++mode == MODE_RESPONSE)
				break;
			if (response[count] == '\0' && mode == MODE_CHALLENGE) {
				pass = response + count + 1;
			}
		}
		if (mode < MODE_RESPONSE)
			fatal("protocol error on back channel");
		break;
	case MODE_LOGIN:
		if ((challenge = login_oath_challenge(user, &oak)) == NULL)
			fatal("could not get challenge");

		pass = readpassphrase(challenge,
		    buf, sizeof(buf), RPP_ECHO_OFF);
		break;
	case MODE_CHALLENGE:
		if ((challenge = login_oath_challenge(user, &oak)) == NULL)
			fatal("could not get challenge");

		if ((auth = auth_mkvalue(challenge)) == NULL)
			fatal("challenge auth value");
		fprintf(back, "%s challenge %s\n", BI_VALUE, auth);
		fprintf(back, "%s\n", BI_CHALLENGE);

		ret = 0;
		goto done;
	}

	if ((otp = login_oath_otp(user, &oak)) == -1) {
		oath_freekey(oak);
		fatal("could not get otp");
	}
	ret = AUTH_FAILED;

	digits = oak->oak_digits;
	if (pass == NULL || strlen(pass) < digits || digits >= sizeof(buf) ||
	    strlcpy(otpbuf, pass, sizeof(otpbuf)) >= sizeof(otpbuf)) {
		autherr = "Invalid format";
		goto done;
	}

	/*
	 * Don't expose any details about the error, we just differentiate
	 * between input format, OTP and password.
	 */
	autherr = "OTP failed";

	/* compare OATH type (HOTP or TOTP), if enforced */
	if (enforce_type != -1 && oak->oak_type != enforce_type)
		goto done;

	otpbuf[digits] = '\0';
	otp1 = strtonum(otpbuf, 0, INT_MAX, &errstr);
	if (errstr)
		goto done;

	/* compare OTP */
	if (otp != otp1)
		goto done;

	/* advance counter on success (HOTP only) */
	if ((otp = login_oath_advance(user, &oak)) == -1)
		goto done;

	(void)oathdb_close(oathdb);
	oathdb = NULL;

	/* compare password */
	ret = pwd_login(user, pass + digits, wheel, lastchance, class, pwd);
	if (ret != AUTH_OK)
		autherr = "Password failed";

 done:
	if (ret != AUTH_OK) {
		fprintf(back, BI_VALUE " errormsg %s\n",
		    auth_mkvalue(autherr));
		fprintf(back, "%s\n", BI_REJECT);
	}

	/* clear passwords and keys from memeory */
	explicit_bzero(buf, sizeof(buf));
	explicit_bzero(response, sizeof(response));
	explicit_bzero(otpbuf, sizeof(otpbuf));
	oath_freekey(oak);

	(void)oathdb_close(oathdb);
	free(auth);
	free(challenge);

	closelog();

	return (0);
}
