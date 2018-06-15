login_oath
==========

OTP authentication type for OpenBSD to login with an authenticator app
such as _Google Authenticator_.  This tool implements RFC 6238 (TOTP)
and RFC 4226 (HOTP).

Installation
------------

This program only depends on libc, libutil, and libcrypto in OpenBSD's
base system.  No external library is needed.

	$ make obj
	$ make all
	$ doas make install

This installs the following binaries:

* `/usr/bin/oath`: to generate keys, control the oath database, etc.
* `/usr/libexec/auth/login_oath`: the main login program for TOTP or HOTP.
* `/usr/libexec/auth/login_totp`: hardlink that only accepts TOTP.
* `/usr/libexec/auth/login_hotp`: hardlink that only accepts HOTP.

Usage
-----

See the [otp(1)](otp/README.md) and [login_otp(8)](login_otp/README.md)
manual pages for instructions.

TODO
----

* Authentication chaining?
* LDAP?
