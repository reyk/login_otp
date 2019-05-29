OTP(1) - General Commands Manual

# NAME

**otp** - manage OATH-compatible one-time password authentication

# SYNOPSIS

**otp**
\[**-agiprt**]
\[**-c**&nbsp;*otp*]
\[**-d**&nbsp;*digits*]
\[**-u**&nbsp;*url*]
\[*user*]

# DESCRIPTION

The
**otp**
utility configures the user's one-time password (OTP) authentication.
If no
*user*
is specified,
the user's login name is used.

The
**otp**
is compatible to the standards that have been specified by the
Initiative for Open Authentication (OATH):
either the HMAC-Based One-Time Password Algorithm (HOTP, RFC 4226) or
the Time-Based One-Time Password Algorithm (TOTP, RFC 6238).

This utility is typically used in combination with an OATH-compatible
external authenticator, like a token, hardware dongle, or
authenticator mobile app, such as the
"Google Authenticator".

The options are as follows:

**-a**

> Advance the HOTP counter.

**-c** *otp*

> Check the specified
> *otp*
> value.

**-d** *digits*

> Specify the number of digits that are used for generated OTPs.
> Used in combination with the
> **-g**
> option.

**-g**

> Generate and print a new OTP secret key for the user.
> The default mode is TOTP but can be overridden with the settings of the
> **-u** *url*
> option.

**-i**

> Initialize the OTP database
> */etc/otp*.
> This command requires root privileges.

**-p**

> Print a users OTP secret key.
> This command requires root privileges;
> a user will only see the secret key once when generating it.

**-r**

> Remove the OTP secret key from the database.

**-t**

> Print a valid OTP token.
> If the OTP type is HOTP, the counter is not incremented automatically;
> use the
> **-a**
> option to do so.

**-u** *url*

> Specify an OTP URL when generating or importing a new OTP secret key.
> The OTP URL has the following format:

> otpauth://\[hotp|totp]/*user*\[?\[secret=*BASE32-ENCODED-KEY*]\[&issuer=*name*]\[&algorithm=SHA1|SHA256|SHA512]\[&digits=*6*]\[&period=*30*]]

# FILES

*/etc/login.conf*

> login configuration options

*/etc/otp*

> OTP secret key database

# EXIT STATUS

The
**otp**
utility returns 0 on success, and 1 if an error occurs.

If the
**-c**
option is specified, the
**otp**
utility returns 1 if the checked OTP is not valid.

# EXAMPLES

Create the OTP database:

	$ doas otp -i

Generate new user key and install it in an authenticator app:

	$ otp -g
	!!! WARNING: PLEASE KEEP THE FOLLOWING KEY SECRET !!!
	
	Load the following key or URL in the authenticator:
	
	Name:   reyk
	Key:    qqs7 eyca yxax l5nq i3rv xzgn e4
	URL:    otpauth://totp/reyk?secret=QQS7EYCAYXAXL5NQI3RVXZGNE4&issuer=example.com&algorithm=SHA1&digits=6&period=30

The otp key can also be retrieved on the local machine:

	$ otp -t
	103200          04 seconds left

Configure
*/etc/login.conf*
and add
'otp'
to the auth option (run
'cap\_mkdb /etc/login.conf'
afterwards, use
'totp'
or
'hotp'
to enforce
an OATH type).
It makes sense to replace
'passwd'
with
'otp':

	auth-defaults:auth=otp,skey:

Login using the concatenated OTP code and password, for example:

	login: reyk:otp
	OTP + password for "reyk":123456password

Or via SSH:

	$ ssh reyk:otp@myhost.example.com

Note that the
'reyk:otp'
is only needed if
'otp'
is not the default, otherwise just the username is sufficient, eg.
'reyk'.

The default mode is TOTP (time-based OTP), HOTP (counter-based OTP) is
also supported and can be configured using a custom URL when
generating the key:

	$ otp -g -u 'otpauth://hotp/reyk?secret=QQS7EYCAYXAXL5NQI3RVXZGNE4&issuer=example.com&algorithm=SHA1&digits=8&counter=0'

The HOTP counter is only incremented after successful logins or when
specifying the \`-a\` advance flag on the command line.

# SEE ALSO

doas(1),
login.conf(5),
login\_otp(8)

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
**otp**
program was written by
Reyk Floeter &lt;[contact@reykfloeter.com](mailto:contact@reykfloeter.com)&gt;.

OpenBSD 6.5 - May 29, 2019
