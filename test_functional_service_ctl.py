
"""
Very basic functional testing for tor_onion_service_ctl.py
WARNING: the tests require a working Tor daemon and sudo permissions os
"TOR_USER" and will create and destroy hidden services.

Released under LGPLv3.
Author: Federico Ceratto <federico.ceratto@gmail.com>
"""

import pytest
from subprocess import Popen, PIPE

TOR_USER = 'debian-tor'


def run(cmd, mustfail=False):
    """Run CLI tool"""
    cmd = "sudo -u %s ./tor_onion_service_ctl.py %s" % (TOR_USER, cmd)
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out = p.communicate()[0]
    if mustfail ^ bool(p.returncode):
        raise RuntimeError("Return code: %r" % p.returncode)

    return out


def test_functional():
    assert 'testservice' not in run('list')
    run('new testservice 1234')
    assert 'testservice' in run('list')
    run('new testservice 1234', mustfail=True)

    r = run('auth-cookie testservice', mustfail=True)
    assert 'Client auth not enabled' in r

    run('del testservice')
    assert 'testservice' not in run('list')
    run('del testservice', mustfail=True)

    r = run('auth-cookie testservice', mustfail=True)
    assert 'Hidden service directory not found' in r


def test_auth_basic():
    assert 'testservice' not in run('list')
    run('new testservice 1234 auth basic client1,client2')
    l = run('list')
    assert 'testservice' in l
    assert '.onion client1' in l
    assert '.onion client2' in l
    assert 'auth: basic client1,client2' in l
    cookies = run('auth-cookie testservice').splitlines()
    assert len(cookies) == 2
    assert cookies[0].startswith('client1 ')
    assert cookies[0].endswith('=')
    assert cookies[1].startswith('client2 ')
    assert cookies[1].endswith('=')
    cookies = run('auth-cookie testservice client1').splitlines()
    print repr(cookies)
    assert len(cookies) == 1
    assert 'client' not in cookies[0]  # name is not printed
    run('auth-cookie testservice bogus_client', mustfail=True)
    run('del testservice')
    assert 'testservice' not in run('list')
    r = run('auth-cookie testservice', mustfail=True)
    assert 'Hidden service directory not found' in r


def test_auth_stealth():
    assert 'testservice' not in run('list')
    run('new testservice 1234 auth stealth client1,client2')
    l = run('list')
    assert 'testservice' in l
    assert '.onion client1' in l
    assert '.onion client2' in l
    assert 'auth: stealth client1,client2' in l
    run('del testservice')
    assert 'testservice' not in run('list')


def test_invalid_cmds():
    run('boo', mustfail=True)
    run('del', mustfail=True)
    run('new', mustfail=True)
    run('auth-cookie', mustfail=True)
    run('new foo', mustfail=True)
    run('new foo 123 auth', mustfail=True)
    run('new foo 123 auth bogusauth', mustfail=True)
    run('new foo 123 auth basic', mustfail=True)
    run('new foo 123 auth basic bad^name', mustfail=True)
    run('new foo 123 auth basic stringwithmorethan16chars', mustfail=True)


