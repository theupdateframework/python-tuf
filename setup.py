#! /usr/bin/env python

from distutils.core import setup

setup(
  name='tuf',
  version='0.1',
  description='A secure updater framework for Python',
  author='https://www.updateframework.com',
  author_email='info@updateframework.com',
  url='https://www.updateframework.com',
  packages=[
    'evpy',
    'simplejson',
    'tuf',
    'tuf.client',
    'tuf.compatibility',
    'tuf.interposition',
    'tuf.pushtools',
    'tuf.pushtools.transfer',
    'tuf.repo'
  ],
  scripts=[
    'quickstart.py',
    'tuf/pushtools/push.py',
    'tuf/pushtools/receivetools/receive.py',
    'tuf/repo/signercli.py'
  ]
)
