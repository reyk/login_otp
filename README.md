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

Create the OTP database:

	$ doas oath -i

Generate new user key and install it in an authenticator app:

	$ oath -g
	!!! WARNING: PLEASE KEEP THE FOLLOWING KEY SECRET !!!
	
	Load the following key or URL in the authenticator:
	
	Name:   reyk
	Key:    qqs7 eyca yxax l5nq i3rv xzgn e4
	URL:    otpauth://totp/reyk?secret=QQS7EYCAYXAXL5NQI3RVXZGNE4&issuer=example.com&algorithm=SHA1&digits=6&period=30

> Note that this tool does not provide a QR code, but the key can be
> installed manually or via the `otpauth://` URL (clicking it on iOS will
> open the authenticator).  Try the following URL:
> [otpauth://totp/example?secret=67FGQKYRC7LE56G3XMLYWPTSW4&issuer=example.com&algorithm=SHA1&digits=8&period=30](otpauth://totp/example?secret=67FGQKYRC7LE56G3XMLYWPTSW4&issuer=example.com&algorithm=SHA1&digits=6&period=30)

The oath key can also be retrieved on the local machine:

	$ oath -t
	103200          04 seconds left

Configure `/etc/login.conf` and add `oath` to the auth option (run
`cap_mkdb /etc/login.conf` afterwards, use `totp` or `hotp` to enforce
an OATH type).  It makes sense to replace `passwd` with `oath`.

	auth-defaults:auth=oath,skey:

Login using the concatenated OTP code and password, for example:

	login: reyk:oath
	OTP + password for "reyk": 123456password
	
Or via SSH:

	$ ssh reyk:oath@myhost.example.com

> Note that `reyk:oath` is only needed if `oath` is not the default,
> otherwise just the username is sufficient, eg. `reyk`.

The default mode is TOTP (time-based OTP), HOTP (counter-based OTP) is
also supported and can be configured using a custom URL when
generating the key:

	$ oath -g -u 'otpauth://hotp/reyk?secret=QQS7EYCAYXAXL5NQI3RVXZGNE4&issuer=example.com&algorithm=SHA1&digits=8&counter=0'

The HOTP counter is only incremented after successful logins or when
specifying the `-a` advance flag on the command line.

TODO
----

* Write manpages oath(1) and login_oath(8).
* Authentication chaining?
* LDAP?
