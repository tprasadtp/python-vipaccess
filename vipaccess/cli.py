from __future__ import print_function

import os, sys
import argparse
import oath
import base64
from vipaccess.patharg import PathType
from vipaccess import provision as vp

EXCL_WRITE = 'x' if sys.version_info>=(3,3) else 'wx'

# http://stackoverflow.com/a/26379693/20789

def set_default_subparser(self, name, args=None):
    """default subparser selection. Call after setup, just before parse_args()
    name: is the name of the subparser to call by default
    args: if set is the argument list handed to parse_args()

    , tested with 2.7, 3.2, 3.3, 3.4
    it works with 2.6 assuming argparse is installed
    """
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:  # global help if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)

argparse.ArgumentParser.set_default_subparser = set_default_subparser

########################################

def provision(p, args):
    request = vp.generate_request(token_model=args.token_model)
    response = vp.get_provisioning_response(request)
    otp_token = vp.get_token_from_response(response.content)
    otp_secret = vp.decrypt_key(otp_token['iv'], otp_token['cipher'])
    otp_secret_b32 = base64.b32encode(otp_secret).upper().decode('ascii')
    if not vp.check_token(otp_token['id'], otp_secret):
        sys.stderr.write("Something went wrong--the token is invalid.\n")
        sys.exit(1)

    if args.print:
        otp_uri = vp.generate_otp_uri(otp_token['id'], otp_secret)
        print('Credential created successfully:\n\t' + otp_uri)
        print("This credential expires on this date: " + otp_token['expiry'])
        print('\nYou will need the ID to register this credential: ' + otp_token['id'])
        print('\nYou can use oathtool to generate the same OTP codes')
        print('as would be produced by the official VIP Access apps:\n')
        print('    oathtool -d6 -b --totp    {}  # 6-digit code'''.format(otp_secret_b32))
        print('    oathtool -d6 -b --totp -v {}  # ... with extra information'''.format(otp_secret_b32))
    else:
        os.umask(0o077) # stoken does this too (security)
        with open(os.path.expanduser(args.dotfile), EXCL_WRITE) as dotfile:
            dotfile.write('version 1\n')
            dotfile.write('secret %s\n' % otp_secret_b32)
            dotfile.write('id %s\n' % otp_token['id'])
            dotfile.write('expiry %s\n' % otp_token['expiry'])
        print('Credential created and saved successfully: ' + dotfile.name)
        print('You will need the ID to register this credential: ' + otp_token['id'])

def show(p, args):
    if args.secret:
        key = oath._utils.tohex( oath.google_authenticator.lenient_b32decode(args.secret) )
    else:
        with open(args.dotfile, "r") as dotfile:
            d = dict( l.strip().split(None, 1) for l in dotfile )
        assert d.get('version')=='1'
        key = oath._utils.tohex( oath.google_authenticator.lenient_b32decode(d.get('secret')) )

    print(oath.totp(key))

def main():
    p = argparse.ArgumentParser()

    class PrintAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, 'print', True)
            setattr(namespace, 'dotfile', None)

    sp = p.add_subparsers(dest='cmd')
    pprov = sp.add_parser('provision', help='Provision a new VIP Access credential')
    pprov.set_defaults(func=provision)
    m = pprov.add_mutually_exclusive_group()
    m.add_argument('-p', '--print', action=PrintAction, nargs=0,
                   help="Print the new credential, but don't save it to a file")
    m.add_argument('-o', '--dotfile', type=PathType(type='file', exists=False), default=os.path.expanduser('~/.vipaccess'),
                   help="File in which to store the new credential (default ~/.vipaccess")
    pprov.add_argument('-t', '--token-model', default='VSST',
                      help="VIP Access token model. Should be VSST (desktop token, default) or VSMT (mobile token). Some clients only accept one or the other.")

    pshow = sp.add_parser('show', help="Show the current 6-digit token")
    m = pshow.add_mutually_exclusive_group()
    m.add_argument('-s', '--secret',
                   help="Specify the token secret on the command line (base32 encoded)")
    m.add_argument('-f', '--dotfile', type=PathType(exists=True), default=os.path.expanduser('~/.vipaccess'),
                   help="File in which the credential is stored (default ~/.vipaccess")
    pshow.set_defaults(func=show)

    p.set_default_subparser('show')
    args = p.parse_args()
    return args.func(p, args)

if __name__=='__main__':
    main()
