login_otp
=========

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

* `/usr/bin/otp`: to generate keys, control the oath database, etc.
* `/usr/libexec/auth/login_otp`: the main login program for TOTP or HOTP.
* `/usr/libexec/auth/login_totp`: hardlink that only accepts TOTP.
* `/usr/libexec/auth/login_hotp`: hardlink that only accepts HOTP.
* `/usr/libexec/auth/login_otp_only`: hardlink that only requires TOTP or HOTP without the user's system password.
* `/usr/libexec/auth/login_totp_only`: hardlink that only requires TOTP without the user's system password.
* `/usr/libexec/auth/login_hotp_only`: hardlink that only requires HOTP without the user's system password.

Usage
-----

See the [otp(1)](otp/README.md) and [login_otp(8)](login_otp/README.md)
manual pages for instructions.

TODO
----

* Authentication chaining?
* LDAP?
