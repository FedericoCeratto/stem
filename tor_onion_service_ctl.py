#!/usr/bin/env python

"""
A simple CLI interface to Tor based on Stem.
It supports creation, deletion and listing of hidden services.

It must be run by an user that has read access to Tor's data directory.

Released under LGPLv3.
Author: Federico Ceratto <federico.ceratto@gmail.com>
"""

from argparse import ArgumentParser
from stem.control import Controller
import errno
import os
import re
import shutil
import sys


class UsageError(Exception):
    pass


def print_conf(d):
    for k,v in d.items():
        if not isinstance(v, dict):
            print "%s %s" % (k, v)
        else:
            for nk in sorted(v):
                nv = v[nk]
                print "%s    %s %s" % (k, nk, nv)


def connect():
    controller = Controller.from_port()
    controller.authenticate()
    data_dir = controller.get_conf('DataDirectory', '/tmp')
    return controller, data_dir


def check_read_permissions(data_dir):
    try:
        os.listdir(data_dir)
    except OSError as e:
        print("Unable to read %s" % data_dir)
        if e.errno is not errno.EACCES:
            print("Error %d: %s" % (e.errno, e.strerror))

        sys.exit(1)


def create_service(args):
    """Create hidden service.
    """
    auth_type = client_names = None
    if args.auth:
        auth_type = args.auth_type
        if not args.auth_type:
            raise UsageError("'auth' enabled: an auth type must be provided")

        if not args.client_names:
            raise UsageError("Comma-separated client names are required")

        client_names = args.client_names.split(',')

        for cn in client_names:
            if not re.match(r'[A-Za-z0-9+-_]{1,16}$', cn):
                raise UsageError("Invalid client name: %r" % cn)

    controller, data_dir = connect()
    # Check if the data directory is readable: better fail now than
    # creating the Hidden service and failing to print the hostname
    check_read_permissions(data_dir)
    hidden_service_dir = os.path.join(data_dir, args.name)
    result = controller.create_hidden_service(
        hidden_service_dir,
        args.external_port,
        target_port=args.internal_port,
        auth_type=auth_type,
        client_names=client_names,
    )
    controller.save_conf()
    controller.close()
    if result is None:
        print("Hidden service creation failed.")
        sys.exit(1)

    print(result.hostname)


def delete_service(args):
    """Delete hidden service.
    """
    controller, data_dir = connect()
    hidden_service_dir = os.path.join(data_dir, args.name)
    if os.path.isdir(hidden_service_dir):
        controller.remove_hidden_service(hidden_service_dir)
        controller.save_conf()
        controller.close()
        shutil.rmtree(hidden_service_dir)

    else:
        print("Hidden service not found")
        sys.exit(1)


def list_services(args):
    """List hidden services.
    """
    controller, data_dir = connect()
    hs_conf = controller.get_hidden_service_conf()
    hs_conf = {k.rstrip(os.sep).rsplit(os.sep, 1)[-1]: v
               for k,v in hs_conf.items()}

    check_read_permissions(data_dir)
    dir_names = sorted(os.listdir(data_dir))
    for dname in dir_names:
        hostname_fn = os.path.join(data_dir, dname, 'hostname')
        if not os.path.isfile(hostname_fn):
            continue

        with open(hostname_fn) as f:
            lines = [l.strip() for l in f]

        print dname
        conf = hs_conf[dname]
        for p in conf['HiddenServicePort']:
            print "    port:", p

        try:
            print "    auth: %s" % conf['HiddenServiceAuthorizeClient']
            for l in lines:
                l = l.split()
                print "    host: %s %s" % (l[0], l[-1])
        except KeyError:
            for l in lines:
                print "    host: %s" % l

        print


def list_services(args):
    """List hidden services.
    """
    controller, data_dir = connect()
    hs_conf = controller.get_hidden_service_conf()
    hs_conf = {k.rstrip(os.sep).rsplit(os.sep, 1)[-1]: v
               for k,v in hs_conf.items()}

    check_read_permissions(data_dir)
    dir_names = sorted(os.listdir(data_dir))
    for dname in dir_names:
        hostname_fn = os.path.join(data_dir, dname, 'hostname')
        if not os.path.isfile(hostname_fn):
            continue

        with open(hostname_fn) as f:
            lines = [l.strip() for l in f]

        print dname
        conf = hs_conf[dname]
        for p in conf['HiddenServicePort']:
            print "    port:", p

        try:
            print "    auth: %s" % conf['HiddenServiceAuthorizeClient']
            for l in lines:
                l = l.split()
                print "    host: %s %s" % (l[0], l[-1])
        except KeyError:
            for l in lines:
                print "    host: %s" % l

        print


def show_auth_cookies(args):
    """Show hidden service auth cookie[s]
    """
    controller, data_dir = connect()
    hidden_service_dir = os.path.join(data_dir, args.name)
    try:
        keys = controller.get_hidden_service_auth_cookies(hidden_service_dir)
    except ValueError as e:
        print e.message
        sys.exit(1)

    if args.client:
        if args.client not in keys:
            print "Client key not found"
            sys.exit(1)

        print keys[args.client]
        return

    for client_name in sorted(keys):
        print client_name, keys[client_name]





def main():
    ap = ArgumentParser()
    subparsers = ap.add_subparsers()

    # Create new service
    new_p = subparsers.add_parser(
        'new',
        help='Create hidden service: new <name> <external port>'
    )
    new_p.add_argument('name', help="Service name")
    new_p.add_argument('external_port', type=int, help="External port")
    new_p.add_argument('--internal-port', type=int, help="Internal port")
    new_p.set_defaults(func=create_service)

    # Optional client authentication
    # Not implemented as a subparser due to http://bugs.python.org/issue9253
    new_p.add_argument('auth', choices=['auth'], nargs='?',
                       help="Enable client authentication")
    new_p.add_argument('auth_type',
                       choices=['basic', 'stealth'], nargs='?',
                       help="authentication type")
    new_p.add_argument('client_names', nargs='?',
                       help="Comma-separated client names")

    # Delete service
    del_p = subparsers.add_parser(
        'del',
        help='Delete hidden service: del <name>'
    )
    del_p.add_argument('name')
    del_p.set_defaults(func=delete_service)

    # List services
    list_p = subparsers.add_parser(
        'list',
        help='List hidden services: list'
    )
    list_p.set_defaults(func=list_services)

    # Print private key[s]
    auth_cookie_p = subparsers.add_parser(
        'auth-cookie',
        help='Show client private keys: auth-cookie <name> [<client_name>]'
    )
    auth_cookie_p.add_argument('name', help='Service name')
    auth_cookie_p.add_argument('client', help='Client name',
                           nargs='?', default=None)
    auth_cookie_p.set_defaults(func=show_auth_cookies)

    # Parse args, call  function
    args = ap.parse_args()
    try:
        args.func(args)

    except UsageError as e:
        ap.error(e)


if __name__ == "__main__":
    main()
