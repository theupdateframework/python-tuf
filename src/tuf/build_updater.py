"""

build_updater.py

Written by Geremy Condra
Licensed under MIT
Released 12 October 2010

Implements the Distutils 'build_updater' command.
"""

from distutils.core import Command

import os
import shutil
import subprocess
import time
import datetime


import tuf
import tuf.conf
import tuf.client.updater

def do_update(url):
	tuf.conf.settings.repo_meta_dir = "."
	repo_data = {'repo': {'urlbase': url, 'metapath': "meta", 'targetspath': "targets", 'metacontent': ['**'], 'targetscontent': ['**']}}

	repo = tuf.client.updater.Repository("", repo_data)

	repo.refresh()
	targets = repo.get_all_targets()
	
	# JAC: add file removal support for nmap folks...
	repo.remove_missing_files()

	files_to_update = repo.get_files_to_update(targets)
	for target in targets:
		if target in files_to_update:
			try:os.makedirs(os.path.dirname(target.path))
			except: pass
			target.download(target.path)


def retry(f, *args, **kwargs):
	# if an exception is raised, retry the operation
	f(*args, **kwargs)
	f(*args, **kwargs)

def copy_metadata(client, server):
	try: shutil.copytree(os.getcwd(), client)
	except: pass
        try: shutil.rmtree(client + '/' + 'cur')
	except: pass
	shutil.copytree(server + '/' + 'meta', client + '/' + 'cur')
        try: shutil.rmtree(client + '/' + 'prev')
	except: pass
	shutil.copytree(server + '/' + 'meta', client + '/' + 'prev')
	try: os.remove('build_updater.pyc')
	except: pass

class build_updater(Command):

    # Brief (40-50 characters) description of the command
    description = "Builds all the necessary values for a basic TUF update system for the given project"

    # List of option tuples: long name, short name (None if no short
    # name), and help string.
    user_options = [    ('expiration', None, "Determines when signatures expire"),
                        ('keystore', None, "The path to look for the keystore at"),
                        ('server', None, "The directory to place the generated meta and targets folders")
                   ]

    def initialize_options(self):
        self.keysize = None
	self.expiration = None
        self.keystore = None
	self.server = None
	self.client = None

    def finalize_options(self):
	if self.keysize is None:
	        self.keysize = 1024
	if self.expiration is None:
		# today's date + 30 days
		t = time.time()
		t += 30 * 24 * 60 * 60
		dt = datetime.date.fromtimestamp(t)
		self.expiration = dt.strftime('%d/%m/%Y')
	if self.keystore is None:
		self.keystore = '../keystore'
        if self.server is None:
                self.server = os.getcwd()
	if self.client is None:
		self.client = os.getcwd()

    def run(self):
	args = ["quickstart.py",
		"-k",
		self.keystore,
		"-t",
		"1",
		"-l",
		self.server,
		"-r",
		os.getcwd(),
		"-e",
		self.expiration]
	subprocess.call(args)
	retry(copy_metadata, self.client, self.server)

class update_updater(Command):

    # Brief (40-50 characters) description of the command
    description = "Pushes new updates to a preexisting update server"

    # List of option tuples: long name, short name (None if no short
    # name), and help string.
    user_options = [    ('keystore', None, "The path to look for the keystore at"),
                        ('server', None, "The directory to place the generated meta and targets folders"),
                        ('client', None, "The directory to place the generate client package"),
			('step', None, "The step in the process to perform")
                   ]

    def initialize_options(self):
        self.keystore = None
	self.server = None
        self.password = None
	self.client = None
	self.step = None

    def finalize_options(self):
	if self.keystore is None:
		self.keystore = '../keystore'
        if self.server is None:
                self.server = os.getcwd()
	if self.password is None:
		self.password = ''
	if self.client is None:
		self.client = '.'
	if self.step is None:
		self.step = 1

    def run(self):
	args = ["quickstart.py",
		"-k",
		self.keystore,
		"-l",
		self.server,
		"-r",
		os.getcwd(),
                "-c",
		self.server + '/' + 'root.cfg',
		"--step",
		str(self.step),
		"-u"]
	subprocess.call(args)
	retry(copy_metadata, self.client, self.server)

class update(Command):

    # Brief (40-50 characters) description of the command
    description = "Performs an update in the current directory"

    # List of option tuples: long name, short name (None if no short
    # name), and help string.
    user_options = [('url', None, "The url of the remote update server")]

    def initialize_options(self):
        self.url = None

    def finalize_options(self):
	if self.url is None:
		raise Exception("No software update URL specified")

    def run(self):
	do_update(self.url)
