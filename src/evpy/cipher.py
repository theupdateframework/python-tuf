#! /usr/bin/env python

"""
cipher.py

Written by Geremy Condra
Released on 18 March 2010
Licensed under MIT License

This module provides a basic interface to OpenSSL's EVP
cipher functions.

All the functions in this module raise CipherError on
malfunction.

From an end-user perspective, this module should be used
in situations where you want to have a single generally
human-readable or human-generated key used for both
encryption and decryption. 

This means that as a general rule, if your application 
involves transmitting this key over an insecure channel
you should not be using this module, but rather 
evpy.envelope.

Usage:

	>>> from evpy import cipher
	>>> message = b"this is data"
	>>> pw = b"mypassword"
	>>> salt, iv, enc = cipher.encrypt(message, pw)
	>>> cipher.decrypt(salt, iv, enc, pw)
	'this is data'
"""

import ctypes
import time

import evp


class CipherError(evp.SSLError):
	pass

def _strengthen_password(pw, iv, salt=None):
	# add the hash
	evp.OpenSSL_add_all_digests()
	# build the key buffer
	key = ctypes.create_string_buffer(24)
	# either take the existing salt or build a new one
	if not salt:
		salt = ctypes.create_string_buffer(8)
		# get the needed entropy, bailing if it doesn't work in
		# the first thousand tries
		for i in range(1000):
			if evp.RAND_bytes(salt, 8): break
		else:
			raise CipherError("Could not generate enough entropy")
		# extract the salt
		salt = salt.raw
	# get the hash
	evp_hash = evp.EVP_get_digestbyname("sha512")
	if not evp_hash:
		raise CipherError("Could not create hash object")
	# fill the key
	if not evp.EVP_BytesToKey(evp.EVP_aes_192_cbc(), evp_hash, salt, pw, len(pw), 1000, key, iv):
		raise CipherError("Could not strengthen key")
	# go home
	return salt, key.raw
	

def encrypt(data, password):
	"""Encrypts the given data, raising CipherError on failure.

	This uses AES192 to encrypt and strengthens the given
	passphrase using SHA512.

	Usage:
		>>> from evpy import cipher
		>>> f = open("test/short.txt", "rb")
		>>> data = f.read()
		>>> pw = b"mypassword"
		>>> salt, iv, enc = cipher.encrypt(data, pw)
		>>> cipher.decrypt(salt, iv, enc, pw) == data
		True
	"""
	# ensure data exists
	if not len(data):
		raise CipherError("Data must actually exist")
	if not len(password):
		raise CipherError("Password must actually exist")

	# build and initialize the context
	ctx = evp.EVP_CIPHER_CTX_new()
	if not ctx:
		raise CipherError("Could not create context")
	evp.EVP_CIPHER_CTX_init(ctx)

	# get the cipher object
	cipher_object = evp.EVP_aes_192_cbc()
	if not cipher_object:
		raise CipherError("Could not create cipher object")

	# finish the context and cipher object
	if not evp.EVP_EncryptInit_ex(ctx, cipher_object, None, None, None):
		raise CipherError("Could not finish context")

	# build the randomized iv
	iv_length = evp.EVP_CIPHER_CTX_iv_length(ctx)
	iv = ctypes.create_string_buffer(iv_length)
	# get the needed entropy, bailing if it doesn't work in
	# the first thousand tries
	for i in range(1000):
		if evp.RAND_bytes(iv, iv_length): break
	else:
		raise CipherError("Not enough entropy for IV")
	output_iv = iv.raw

	# strengthen the password into an honest-to-goodness key
	salt, aes_key = _strengthen_password(password, iv)

	# initialize the encryption operation
	if not evp.EVP_EncryptInit_ex(ctx, None, None, aes_key, iv):
		raise CipherError("Could not start encryption operation")

	# build the output buffer
	buf = ctypes.create_string_buffer(len(data) + 16)
	written = ctypes.c_int(0)
	final = ctypes.c_int(0)

	# update
	if not evp.EVP_EncryptUpdate(ctx, buf, ctypes.byref(written), data, len(data)):
		raise CipherError("Could not update ciphertext")
	output = buf.raw[:written.value]

	# finalize
	if not evp.EVP_EncryptFinal_ex(ctx, buf, ctypes.byref(final)):
		raise CipherError("Could not finalize ciphertext")
	output += buf.raw[:final.value]

	# ...and go home
	return salt, output_iv, output


def decrypt(salt, iv, data, password):
	"""Decrypts the given data, raising CipherError on failure.
	
	Usage:
		>>> from evpy import cipher
		>>> f = open("test/short.txt", "rb")
		>>> data = f.read()
		>>> pw = b"mypassword"
		>>> salt, iv, enc = cipher.encrypt(data, pw)
		>>> cipher.decrypt(salt, iv, enc, pw) == data
		True
	"""
	# ensure inputs are the correct size
	if not len(data):
		raise CipherError("Data must actually exist")
	if not len(password):
		raise CipherError("Password must actually exist")
	if len(salt) != 8:
		raise CipherError("Incorrect salt size")
	if len(iv) != 16:
		raise CipherError("Incorrect iv size")

	# build and initialize the context
	ctx = evp.EVP_CIPHER_CTX_new()
	if not ctx:
		raise CipherError("Could not create context")
	evp.EVP_CIPHER_CTX_init(ctx)

	# get the cipher object
	cipher_object = evp.EVP_aes_192_cbc()
	if not cipher_object:
		raise CipherError("Could not create cipher object")

	# build the key
	salt, key = _strengthen_password(password, iv, salt)

	# start decrypting the ciphertext
	if not evp.EVP_DecryptInit_ex(ctx, cipher_object, None, key, iv):
		raise CipherError("Could not open envelope")

	# build the output buffers
	buf = ctypes.create_string_buffer(len(data) + 16)
	written = ctypes.c_int(0)
	final = ctypes.c_int(0)

	# update
	if not evp.EVP_DecryptUpdate(ctx, buf, ctypes.byref(written), data, len(data)):
		raise CipherError("Could not update plaintext")
	output = buf.raw[:written.value]

	# finalize
	if not evp.EVP_DecryptFinal_ex(ctx, buf, ctypes.byref(final)):
		raise CipherError("Could not finalize decryption")
	output += buf.raw[:final.value]

	return output
