python-vipaccess
================


[![Build Status](https://api.travis-ci.org/tprasadtp/python-vipaccess.png)](https://travis-ci.org/tprasadtp/python-vipaccess)
[![Coverage
 Status](https://coveralls.io/repos/github/tprasadtp/python-vipaccess/badge.svg?branch=master)](https://coveralls.io/github/tprasadtp/python-vipaccess?branch=master)
 [![Docker Build Status](https://img.shields.io/docker/build/tprasadtp/py-vipaccess.svg)](https://hub.docker.com/r/tprasadtp/py-vipaccess/)

This is a fork of [@cyrozap](https://github.com/cyrozap)'s [`python-vipaccess`](https://github.com/dlenski/python-vipaccess).


## Branches
| Branch | About |
| ------ | ----- |
| upstream-hotp | Ustream branch with added hotp support (No QR code stuff) |
| upstream | Upstream master Branch |
| master | Fork with HOTP support, different docker file, QR code generation |


Main differences:

- Option to generate either the desktop (`VSST`) or mobile (`VSMT`)
  version on the VIP Access tokens; as far as I can tell there is no
  real difference between them, but some clients require one or the
  other specifically.
- Provision HOTP Tokens (`VSMB`)
- Command-line utility is expanded to support *both* token
  provisioning (creating a new token) and emitting codes for an
  existing token (inspired by the command-line interface of
  [`stoken`](https://github.com/cernekee/stoken), which handles the same functions for [RSA SecurID](https://en.wikipedia.org/wiki/RSA_SecurID) tokens


Intro
-----

python-vipaccess is a free and open source software (FOSS)
implementation of Symantec's VIP Access client.

If you need to access a network which uses VIP Access for [two-factor
authentication](https://en.wikipedia.org/wiki/Two-factor_authentication),
but can't or don't want to use Symantec's proprietary
applications—which are only available for Windows, MacOS, Android,
iOS—then this is for you.

As [@cyrozap](https://github.com/cyrozap) discovered in reverse-engineering the VIP Access protocol
([original blog
post](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol)),
Symantec VIP Access actually uses a **completely open standard**
called [Time-based One-time Password
Algorithm](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
for generating the 6-digit codes that it outputs. The only
non-standard part is the **provisioning** protocol used to create a
new token.

Dependencies
------------

-  Python 2.7, 3.3, 3.4, 3.5
-  [`lxml`](https://pypi.python.org/pypi/lxml/3.4.0)
-  [`oath`](https://pypi.python.org/pypi/oath/1.2)
-  [`pycryptodome`](https://pypi.python.org/pypi/pycryptodome/3.4.7)
-  [`requests`](https://pypi.python.org/pypi/requests/)
-  qrcode

If you have `pip` installed on your system, you can install them with
`pip install lxml oath pycryptodome requests qrcode image`.

Manual
------

If you have Docker installed, you can simply use the
[Docker image](https://hub.docker.com/r/kayvan/vipaccess/) to run
the `vipaccess` tool:

```
docker run --rm kayvan/vipaccess provision -p -t VSST
Credential created successfully:
	otpauth://totp/VIP%20Access:VSST1113377?secret=YOURSECRET&issuer=Symantec
This credential expires on this date: 2020-06-05T15:26:26.585Z

You will need the ID to register this credential: VSST1113377
```

And with your generated secret, use the `show` command like this:

```
docker run --rm kayvan/vipaccess show -s YOURSECRET
935163
```

Alternatively, you can build it:

1. Check out this repository by running
   ``git clone https://github.com/dlenski/python-vipaccess.git``
2. Switch to the ``python-vipaccess`` directory by running
   ``cd python-vipaccess``
3. Install the ``vipaccess`` module

   -  With [pip](https://en.wikipedia.org/wiki/Pip_(package_manager)): ``pip install .``
   -  Without pip: ``python setup.py install``

Usage
-----

(This section covers the expanded CLI options of this fork, rather than [@cyrozap](https://github.com/cyrozap)'s original version.)

### Provisioning a new VIP Access credential

This is used to create a new VIP Access token: by default, it stores
the new credential in the file `.vipaccess` in your home directory (in a
format similar to `stoken`), but it can store to another file instead,
or instead just print out the "token secret" string with instructions
about how to use it.

```
usage: vipaccess provision [-h] [-p | -o DOTFILE] [-t TOKEN_MODEL]

optional arguments:
  -h, --help            show this help message and exit
  -p, --print           Print the new credential, but don't save it to a file
  -o DOTFILE, --dotfile DOTFILE
                        File in which to store the new credential (default
                        ~/.vipaccess
  -t TOKEN_MODEL, --token-model TOKEN_MODEL
                        VIP Access token model. Should be VSST (desktop token,
                        default) or VSMT (mobile token), VSMB for HOTP token. Some clients only
                        accept one or the other.
```

Here is an example of the output from `vipaccess provision -p`:

```
Credential created successfully:
	otpauth://totp/VIP%20Access:VSST12345678?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=Symantec
This credential expires on this date: 2019-01-15T12:00:00.000Z

You will need the ID to register this credential: VSST12345678

You can use oathtool to generate the same OTP codes
as would be produced by the official VIP Access apps:

    oathtool -d6 -b --totp    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  # 6-digit code
    oathtool -d6 -b --totp -v AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  # ... with extra information
```

Here is the format of the `.vipaccess` token file output from
`vipaccess provision [-o ~/.vipaccess]`. (This file is created with
read/write permissions *only* for the current user.)

```
version 1
secret AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
id VSST12345678
expiry 2019-01-15T12:00:00.000Z
```

### Using qrencode to register your credential with TOTP apps (e.g. Authy)

Once you generate a token with `vipaccess provision -p`, use the `otpauth` URL
to generate the QR code:

```
qrencode -t ANSI256 'otpauth://totp/VIP%20Access:VSSTXXXX?secret=YYYY&issuer=Symantec'
```

Scan the code into your TOTP generating app, like Authy.


### Using HOTP

Use VSMB as token type `vipaccess provision -p -t VSMB`
Known Limitations:
* No way to re-synchronize if token ever gets out of sync with VIP Server.
* You should use HEX code with Yubikeys
* Tokens have an expiry date similar TOTP tokens unlike Yubikey VIP Tokens.
* First try may not work as we used that token to validate it.


### Generating access codes using an existing credential

The `vipaccess [show]` option will also do this for you: by default it
generates codes based on the credential in `~/.vipaccess`, but you can
specify an alternative credential file or specify the OATH "token
secret" on the command line.

Cannot be used with hotp tokens as of now.
```
usage: vipaccess show [-h] [-s SECRET | -f DOTFILE]

optional arguments:
  -h, --help            show this help message and exit
  -s SECRET, --secret SECRET
                        Specify the token secret on the command line (base32
                        encoded)
  -f DOTFILE, --dotfile DOTFILE
                        File in which the credential is stored (default
                        ~/.vipaccess
```

As alluded to above, you can use other standard
[OATH](https://en.wikipedia.org/wiki/Initiative_For_Open_Authentication)-based
tools to generate the 6-digit codes identical to what Symantec's official
apps produce.
