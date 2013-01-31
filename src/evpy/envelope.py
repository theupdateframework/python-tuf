#! /usr/bin/env python

"""
envelope.py

Written by Geremy Condra
Released on 18 March 2010
Licensed under MIT License

This module provides a basic interface to OpenSSL's EVP
envelope functions.

In a nutshell, these functions are designed to provide
the primary benefit of public key cryptography (the
ability to provide secrecy without first sharing a
secret) without its primary downside (small message
length). It does this by generating a random AES key 
with which to encrypt the data, then encrypting that
key against the provided RSA key.

This means that if you have an application in which
you wish to share sensitive data but do not wish to
share a common secret, this is your module. Be aware
that compromising your private key is effectively
game over with this scheme.

If you require a shared secret and want the key to 
be human readable, then you will probably want to 
use the cipher module instead.

All the functions in this module raise EnvelopeError on
malfunction.

Usage:

	>>> from evpy import envelope
	>>> f = open("test/short.txt", "rb")
	>>> data = f.read()
	>>> public_key = "test/keys/public1.pem"
	>>> private_key = "test/keys/private1.pem"
	>>> iv, key, ciphertext = envelope.encrypt(data, public_key)
	>>> envelope.decrypt(iv, key, ciphertext, private_key) == data
	True
"""

import ctypes

import evp
from signature import _string_to_bio

class EnvelopeError(evp.SSLError):
	pass

def _build_dkey_from_file(keyfile):
	fp = evp.fopen(keyfile, "r")
	if not fp:
		raise EnvelopeError("Could not open keyfile")
	# get the decryption key
	skey = evp.PEM_read_PrivateKey(fp, None, None, None)
	if not skey:
		evp.fclose(fp)
		raise EnvelopeError("Could not read decryption key")
	# close the file
	evp.fclose(fp)
	return skey

def _build_dkey_from_string(key):
	bio = _string_to_bio(key)
	dkey = evp.PEM_read_bio_PrivateKey(bio, None, None, None)
	if not dkey:
		raise EnvelopeError("Could not build decryption key from string")
	evp.BIO_free(bio)
	return dkey

def _build_ekey_from_file(keyfile):
	fp = evp.fopen(keyfile, "r")
	if not fp:
		raise EnvelopeError("Could not open keyfile")
	# get the encryption key
	ekey = evp.PEM_read_PUBKEY(fp, None, None, None)
	if not ekey:
		evp.fclose(fp)
		raise EnvelopeError("Could not read encryption key")
	# close the file
	evp.fclose(fp)
	return ekey

def _build_ekey_from_string(key):
	bio = _string_to_bio(key)
	ekey = evp.PEM_read_bio_PUBKEY(bio, None, None, None)
	if not ekey:
		raise EnvelopeError("Could not create encryption key from string")
	evp.BIO_free(bio)
	return ekey

def _build_bio():
	method = evp.BIO_s_mem()
	return evp.BIO_new(method);

def _asn1_hex_to_int(value):
	print(value)
	return int(''.join(value.split(':')), 16)

def _parse_printed_key(k):
	attrs = {}
	current = ""
	current_attr = ""
	for line in k.splitlines()[1:]:
		# its a continuation of the current block
		if line.startswith(' '):
			current += line.strip()
		else:
			# special case the public exponent
			if "publicExponent" in current_attr:
				attrs['publicExponent'] = int(current_attr.split()[1])
			elif current_attr:
				attrs[current_attr] = _asn1_hex_to_int(current)
			current_attr = line.strip(':')
			current = ""
	translator = {'publicExponent': 'e', 'privateExponent': 'd', 'modulus': 'n', 'prime1': 'p', 'prime2': 'q'}
	translated_attrs = {}
	for key, value in attrs.items():
		try:
			translated_attrs[translator[key]] = value
		except: pass
	return translated_attrs
				

def keygen(bitlength=1024, e=65537, pem=True):
	key = evp.RSA_generate_key(bitlength, e, None, None)
	if not key:
		raise EnvelopeError("Could not generate key")
	if pem:
		private_bio = evp.BIO_new(evp.BIO_s_mem())
		if not private_bio:
			raise KeygenError("Could not create temporary storage")
		public_bio = evp.BIO_new(evp.BIO_s_mem())
		if not public_bio:
			raise KeygenError("Could not create temporary storage")
		private_buf = ctypes.create_string_buffer('', 65537)
		if not private_buf:
			raise MemoryError("Could not allocate key storage")
		public_buf = ctypes.create_string_buffer('', 65537)
		if not public_buf:
			raise MemoryError("Could not allocate key storage")
		if not evp.PEM_write_bio_RSAPrivateKey(private_bio, key, None, None, 0, 0, None):
			raise KeygenError("Could not write private key")
		if not evp.PEM_write_bio_RSA_PUBKEY(public_bio, key):
			raise KeygenError("Could not write public key")
		public_len = evp.BIO_read(public_bio, public_buf, 65537)
		private_len = evp.BIO_read(private_bio, private_buf, 65537)
		evp.BIO_free(public_bio)
		evp.BIO_free(private_bio)
		return public_buf.value, private_buf.value
	else:
		# we go through this rigamarole because if there's an engine
		# in place it won't populate the RSA key's values properly.
		key_bio = evp.BIO_new(evp.BIO_s_mem())
		if not key_bio:
			raise KeygenError("Could not create temporary storage")
		if not evp.RSA_print(key_bio, key, 0):
			raise KeygenError("Could not stringify key")
		key_buf = ctypes.create_string_buffer('', 65537)
		if not key_buf:
			raise MemoryError("Could not allocate key storage")
		evp.BIO_read(key_bio, key_buf, 65537)
		evp.BIO_free(key_bio)
		key_string = key_buf.value
		return key, _parse_printed_key(key_string)
		
	
	

def encrypt(data, keyfile=None, key=None):
	"""Encrypts the given data, raising EnvelopeError on failure.

	This uses AES192 to do bulk encryption and RSA to encrypt
	the given public key.

	Usage:
		>>> from evpy import envelope
		>>> f = open("test/short.txt", "rb")
		>>> data = f.read()
		>>> public_key = "test/keys/public1.pem"
		>>> private_key = "test/keys/private1.pem"
		>>> iv, key, ciphertext = envelope.encrypt(data, public_key)
		>>> envelope.decrypt(iv, key, ciphertext, private_key) == data
		True
	"""
	# validate the incoming data
	if not data:
		raise EnvelopeError("Incoming data must be bytes")
	if not len(data):
		raise EnvelopeError("Data must actually exist")

	# build and initialize the context
	ctx = evp.EVP_CIPHER_CTX_new()
	if not ctx:
		raise EnvelopeError("Could not create context")
	evp.EVP_CIPHER_CTX_init(ctx)

	# get the key from the keyfile
	if key and not keyfile:
		ekey = _build_ekey_from_string(key)
	elif keyfile and not key:
		ekey = _build_ekey_from_file(keyfile)
	else:
		raise EnvelopeError("Must specify exactly one key or keyfile")

	# get the cipher object
	cipher_object = evp.EVP_aes_192_cbc()
	if not cipher_object:
		raise EnvelopeError("Could not create cipher object")

	# finish the context and cipher object
	if not evp.EVP_EncryptInit_ex(ctx, cipher_object, None, None, None):
		raise EnvelopeError("Could not finish context")

	# build the randomized iv
	iv_length = evp.EVP_CIPHER_CTX_iv_length(ctx)
	iv = ctypes.create_string_buffer(iv_length)
	for i in range(1000):
		if evp.RAND_bytes(iv, iv_length): break
	else:
		raise EnvelopeError("Could not generate enough entropy for IV")
	output_iv = iv.raw

	# build the randomized AES key
	keysize = evp.EVP_CIPHER_key_length(cipher_object)
	aes_key = ctypes.create_string_buffer(keysize)
	for i in range(1000):
		if evp.RAND_bytes(aes_key, keysize): break
	else:
		raise EnvelopeError("Could not generate enough entropy for AES key")

	# extract the RSA key
	rsa_key = evp.EVP_PKEY_get1_RSA(ekey)
	if not rsa_key:
		raise EnvelopeError("Could not get RSA key")

	# encrypt it
	buf_size = evp.RSA_size(rsa_key)
	if not buf_size:
		raise EnvelopeError("Invalid RSA keysize")
	encrypted_aes_key = ctypes.create_string_buffer(buf_size)
	# RSA_PKCS1_PADDING is defined as 1
	written = evp.RSA_public_encrypt(keysize, aes_key, encrypted_aes_key, rsa_key, 1)
	if not written:
		raise EnvelopeError("Could not encrypt AES key")
	output_key = encrypted_aes_key.raw[:written]

	# initialize the encryption operation
	if not evp.EVP_EncryptInit_ex(ctx, None, None, aes_key, iv):
		raise EnvelopeError("Could not start encryption operation")

	# build the output buffer
	buf = ctypes.create_string_buffer(len(data) + 16)
	written = ctypes.c_int(0)
	final = ctypes.c_int(0)

	# update
	if not evp.EVP_EncryptUpdate(ctx, buf, ctypes.byref(written), data, len(data)):
		raise EnvelopeError("Could not update ciphertext")
	output = buf.raw[:written.value]

	# finalize
	if not evp.EVP_EncryptFinal_ex(ctx, buf, ctypes.byref(final)):
		raise EnvelopeError("Could not finalize ciphertext")
	output += buf.raw[:final.value]

	# ...and go home
	return output_iv, output_key, output


def decrypt(iv, encrypted_aes_key, data, keyfile=None, key=None):
	"""Decrypts the given ciphertext, raising EnvelopeError on failure.

	Usage:
		>>> from evpy import envelope
		>>> f = open("test/short.txt", "rb")
		>>> data = f.read()
		>>> public_key = "test/keys/public1.pem"
		>>> private_key = "test/keys/private1.pem"
		>>> iv, key, ciphertext = envelope.encrypt(data, public_key)
		>>> envelope.decrypt(iv, key, ciphertext, private_key) == data
		True
	"""
	# build and initialize the context
	ctx = evp.EVP_CIPHER_CTX_new()
	if not ctx:
		raise EnvelopeError("Could not create context")
	evp.EVP_CIPHER_CTX_init(ctx)

	# get the cipher object
	cipher_object = evp.EVP_aes_192_cbc()
	if not cipher_object:
		raise EnvelopeError("Could not create cipher object")

	# get the key from the keyfile
	if key and not keyfile:
		dkey = _build_dkey_from_string(key)
	elif keyfile and not key:
		dkey = _build_dkey_from_file(keyfile)
	else:
		raise EnvelopeError("Must specify exactly one key or keyfile")

	# open the envelope
	if not evp.EVP_OpenInit(ctx, cipher_object, encrypted_aes_key, len(encrypted_aes_key), iv, dkey):
		raise EnvelopeError("Could not open envelope")

	# build the output buffer
	buf = ctypes.create_string_buffer(len(data) + 16)
	written = ctypes.c_int(0)
	final = ctypes.c_int(0)

	# update
	if not evp.EVP_DecryptUpdate(ctx, buf, ctypes.byref(written), data, len(data)):
		raise EnvelopeError("Could not update envelope")
	output = buf.raw[:written.value]

	# finalize
	if not evp.EVP_DecryptFinal_ex(ctx, buf, ctypes.byref(final)):
		raise EnvelopeError("Could not finalize envelope")
	output += buf.raw[:final.value]

	return output
