#! /usr/bin/env python

"""
signature.py

Written by Geremy Condra
Released on 18 March 2010
Licensed under MIT License

This module provides a basic interface to OpenSSL's EVP
signature functions.

All functions in this module will raise a SignatureError
in the event of a malfunction.

The goal of cryptographic signatures is to provide some
degree of assurance that the data you are processing is
both coming from the person you think is sending it and
is what they sent.

Note that this does not encrypt data in the sense that
it does not provide secrecy for it, while evpy.cipher
and evpy.envelope provide secrecy but no other security
properties.

Usage:
	>>> from evpy import signature
	>>> data = b"abcdefg"
	>>> public_key = "test/keys/public1.pem"
	>>> private_key = "test/keys/private1.pem"
	>>> s = signature.sign(data, private_key)
	>>> signature.verify(data, s, public_key)
	True
"""

import ctypes

import evp


class SignatureError(evp.SSLError):
	pass


def sign(data, keyfile=None, key=None):
	"""Signs the given data, raising SignatureError on failure.

	Exactly one of keyfile, key should be given; if key is not
	defined, then the key will be read from the given file.

	Usage:
		>>> from evpy import signature
		>>> f = open("test/short.txt", "rb")
		>>> data = f.read()
		>>> public_key = "test/keys/public1.pem"
		>>> private_key = "test/keys/private1.pem"
		>>> s = signature.sign(data, private_key)
		>>> signature.verify(data, s, public_key)
		True
	"""
	# add the digests
	evp.OpenSSL_add_all_digests()

	# build the context
	ctx = evp.EVP_MD_CTX_create()
	if not ctx:
		raise SignatureError("Could not create context")

	# get the signing key
	if key and not keyfile:
		skey = _build_skey_from_string(key)
	elif keyfile and not key:
		skey = _build_skey_from_file(keyfile)
	else:
		raise SignatureError("Exactly one of key, keyfile must be specified")

	# build the hash object
	evp_hash = _build_hash()
	if not evp.EVP_DigestInit(ctx, evp_hash):
		_cleanup(skey, ctx)
		raise SignatureError("Could not initialize signature")

	# update
	if not evp.EVP_DigestUpdate(ctx, data, len(data)):
		_cleanup(skey, ctx)
		raise SignatureError("Could not update signature")

	# finalize
	output_buflen = ctypes.c_int(evp.EVP_PKEY_size(skey))
	output = ctypes.create_string_buffer(output_buflen.value)
	if not evp.EVP_SignFinal(ctx, output, ctypes.byref(output_buflen), skey):
		_cleanup(skey, ctx)
		raise SignatureError("Could not finalize signature")

	# cleanup
	_cleanup(skey, ctx)

	# and go home
	return ctypes.string_at(output, output_buflen)


def verify(data, sig, keyfile=None, key=None):
	"""Verifies the given signature, returning a boolean.

	Exactly one of keyfile, key should be specified.

	This function raises SignatureError on error.

	Usage:
		>>> from evpy import signature
		>>> f = open("test/short.txt", "rb")
		>>> data = f.read()
		>>> public_key = "test/keys/public1.pem"
		>>> private_key = "test/keys/private1.pem"
		>>> s = signature.sign(data, private_key)
		>>> signature.verify(data, s, public_key)
		True
	"""
	# add the digests
	evp.OpenSSL_add_all_digests()
	
	# build the context
	ctx = evp.EVP_MD_CTX_create()
	if not ctx:
		raise SignatureError("Could not create context")

	# get the vkey
	if key and not keyfile:
		vkey = _build_vkey_from_string(key)
	elif keyfile and not key:
		vkey = _build_vkey_from_file(keyfile)
	else:
		raise SignatureError("Exactly one of key, keyfile must be specified")

	# build the hash object
	evp_hash = _build_hash()
	if not evp.EVP_DigestInit(ctx, evp_hash):
		_cleanup(vkey, ctx)
		raise SignatureError("Could not initialize verifier")

	# update
	if not evp.EVP_DigestUpdate(ctx, data, len(data)):
		_cleanup(vkey, ctx)
		raise SignatureError("Could not update verifier")

	# finalize
	retcode = evp.EVP_VerifyFinal(ctx, sig, len(sig), vkey)

	# cleanup
	_cleanup(vkey, ctx)

	# and go home
	if retcode == 1:
		return True
	elif retcode == 0:
		return False
	else:
		raise SignatureError("Error verifying signature")

def _cleanup(key, ctx):
	evp.EVP_PKEY_free(key)
	evp.EVP_MD_CTX_cleanup(ctx)
	evp.EVP_MD_CTX_destroy(ctx)

def _string_to_bio(s):
	return evp.BIO_new_mem_buf(s, len(s))

def _build_skey_from_file(keyfile):
	fp = evp.fopen(keyfile, "r")
	if not fp:
		raise SignatureError("Could not open keyfile")
	# get the signing key
	skey = evp.PEM_read_PrivateKey(fp, None, None, None)
	if not skey:
		evp.fclose(fp)
		raise SignatureError("Could not read signing key")
	# close the file
	evp.fclose(fp)
	return skey

def _build_skey_from_string(key):
	buf = ctypes.create_string_buffer(key)
	bio = evp.BIO_new_mem_buf(buf, len(buf.value))
	skey = evp.PEM_read_bio_PrivateKey(bio, None, None, None, None)
	if not skey:
		raise SignatureError("Could not construct signing key from the given string")
	evp.BIO_free(bio)
	return skey

def _build_vkey_from_file(keyfile):
	fp = evp.fopen(keyfile, "r")
	if not fp:
		raise SignatureError("Could not open keyfile")
	# get the verification key
	vkey = evp.PEM_read_PUBKEY(fp, None, None, None)
	if not vkey:
		evp.fclose(fp)
		raise SignatureError("Could not read verification key")
	# close the file
	evp.fclose(fp)
	return vkey

def _build_vkey_from_string(key):
	buf = ctypes.create_string_buffer(key)
	bio = evp.BIO_new_mem_buf(buf, len(buf.value))
	vkey = evp.PEM_read_bio_PUBKEY(bio, None, None, None)
	if not vkey:
		raise SignatureError("Could not construct verification key from the given string")
	return vkey

def _build_hash():
	evp_hash = evp.EVP_get_digestbyname("sha512")
	if not evp_hash:
		raise SignatureError("Could not create hash object")
	return evp_hash
