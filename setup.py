#! /usr/bin/env python

from distutils.core import setup

setup(name='tuf',
  version='0.0.0',
  description='A secure updater framework for Python',
  author='numerous',
  author_email='info@updateframework.com',
  url='https://www.updateframework.com',
  packages=['tuf',
    'tuf.client',
    'tuf.pushtools',
    'tuf.pushtools.transfer',
    'tuf.repo',
    'tuf.interposition',
    'evpy',
    'simplejson'],
  scripts=['quickstart.py',
    'basic_client.py',
    'tuf/pushtools/push.py',
    'tuf/pushtools/receivetools/receive.py',
    'tuf/repo/signercli.py'])
