LOGIN\_OTP(8) - System Manager's Manual

# NAME

**login\_otp**,
**login\_hotp**,
**login\_totp**,
**login\_otp\_only**,
**login\_hotp\_only**,
**login\_totp\_only** - provide OATH-compatible one-time password authentication types

# SYNOPSIS

**login\_otp**
\[**-s**&nbsp;*service*]
\[**-v**&nbsp;**wheel**=**yes**|**no**]
\[**-v**&nbsp;**lastchance**=**yes**|**no**]
*user*
\[*class*]

# DESCRIPTION

The
**login\_otp**
utility is called by
login(1),
su(1),
ftpd(8),
and others to authenticate the
*user*
with a combined one-time password (OTP) and passwd-style authentication.

The OTP is compatible to the standards that have been specified by the
Initiative for Open Authentication (OATH):
either the HMAC-Based One-Time Password Algorithm (HOTP, RFC 4226) or
the Time-Based One-Time Password Algorithm (TOTP, RFC 6238).

The OTP can be configured with the
otp(1)
utility.
The
**login\_otp**
utility can be called as
**login\_otp**,
**login\_hotp**,
or
**login\_totp**
to either allow HOTP or TOTP passwords,
or to enforce HTOP or TOTP passwords accordingly,
or as
**login\_otp\_only**,
**login\_hotp\_only**,
or
**login\_totp**
to only require the HOTP or TOTP password without being combined with
the user's system password.

The
*user*
argument is the login name of the user to be authenticated.

The
*service*
argument specifies which protocol to use with the
invoking program.
The allowed protocols are
*login*,
*challenge*,
and
*response*.
(The
*challenge*
protocol is silently ignored but will report success as passwd-style
authentication is not challenge-response based).

If the
**wheel**
argument is specified and is not set to
**yes**,
then the user will be rejected as not being in group
"wheel".
This is used by
su(1).

If the
**lastchance**
argument is specified and is equal to
**yes**,
then if the user's password has expired, and it has not been
expired longer than
"password-dead"
seconds (see
login.conf(5)),
the user will be able to log in one last time to change the password.

**login\_otp**
will prompt the user for a password and report back to the invoking
program whether or not the authentication was successful.
The format of the password is a concatenated string including a valid OTP
and the system user password, for example OTP
'*123456*'
and password
'*test-123*':

	login: user
	OTP + password for "user":123456test-123

When invoked as
**login\_otp\_only**,
**login\_hotp\_only**,
or
**login\_totp\_only**,
only the OTP password is required:

	login: user
	OTP for "user":123456

The user obtains a valid OTP from an OATH-compatible external authenticator,
typically a token, hardware dongle, or authenticator mobile app,
such as the
"Google Authenticator".

# SEE ALSO

login(1),
otp(1),
passwd(1),
su(1),
login.conf(5),
ftpd(8)

# STANDARDS

D. M'Raihi,
M. Bellare, and
F. Hoornaert, and
D. Naccache, and
O. Ranen,
*HOTP: An HMAC-Based One-Time Password Algorithm*,
RFC 4226,
December 2005.

D. M'Raihi,
S. Machani, and
M. Pei, and
J. Rydell,
*TOTP: Time-Based One-Time Password Algorithm*,
RFC 6238,
May 2011.

# AUTHORS

The
**login\_otp**
program was written by
Reyk Floeter &lt;[contact@reykfloeter.com](mailto:contact@reykfloeter.com)&gt;.

OpenBSD 6.5 - November 24, 2018
