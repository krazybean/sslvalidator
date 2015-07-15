#!/usr/bin/env python

from distutils.core import setup

setup(name='sslvalidator',
      version='1.0',
      description='Python utility for validating certificates',
      author='juan castro',
      author_email='juan.castro@rackspace.com',
      packages=['pyOpenSSL', 'M2Crypto'],
      )
