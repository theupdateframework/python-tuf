#! /usr/bin/env python

from distutils.core import setup

setup(
    name        = 'TUF',
    version     = '0.1',
    description = 'A secure updater framework for Python',
    author      = 'lots of people',
    url         = 'https://updateframework.com',
    packages    = [
        'evpy',
        'tuf',
        'tuf.repo',
        'tuf.client',
        'tuf.pushtools',
        'tuf.pushtools.transfer',
        'simplejson'
    ],
    scripts=[
        'quickstart.py',
        'tuf/pushtools/push.py',
        'tuf/pushtools/receivetools/receive.py',
        'tuf/repo/signercli.py'
    ]
)
