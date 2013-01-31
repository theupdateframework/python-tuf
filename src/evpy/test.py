#! /usr/bin/env python

"""
test.py

Written by Geremy Condra
Licensed under MIT License
Released 21 March 2010

Simple unit tests for evpy
"""

import unittest

from evpy import evp
from evpy import cipher
from evpy import signature
from evpy import envelope

# locations for test data
TEST_DATA_DIR = "test/"
TEST_KEYS = TEST_DATA_DIR + "keys/"

# test text
STRING = open(TEST_DATA_DIR + "long.txt").read()
LONG = open(TEST_DATA_DIR + "long.txt", 'rb').read()
SHORT = open(TEST_DATA_DIR + "short.txt", 'rb').read()
UNICODE = open(TEST_DATA_DIR + "unicode.txt", 'rb').read()
NULL = open(TEST_DATA_DIR + "null.txt", 'rb').read()
TEST_TEXTS = {  "long": LONG, 
		"short": SHORT, 
		"unicode": UNICODE, 
		"null": NULL}

# test keys
SHORT_SYMMETRIC = open(TEST_KEYS + "short_symmetric.txt", 'rb').read()
LONG_SYMMETRIC = open(TEST_KEYS + "long_symmetric.txt", 'rb').read()
SYMMETRIC_KEYS = [LONG_SYMMETRIC, SHORT_SYMMETRIC]
SYMMETRIC_STRING = open(TEST_KEYS + "short_symmetric.txt").read()

KEY_1 = TEST_KEYS + "private1.pem", TEST_KEYS + "public1.pem"
KEY_2 = TEST_KEYS + "private2.pem", TEST_KEYS + "public2.pem"
MISMATCH_1 = KEY_1[0], KEY_2[1]
MISMATCH_2 = KEY_2[0], KEY_1[1]
MISSING_PRIVATE_KEY = "notakey.pem", KEY_1[1]
MISSING_PUBLIC_KEY = KEY_1[0], "notakey.pem"
BLANK_PRIVATE_KEY = KEY_1[0], TEST_KEYS + "blank.pem"
BLANK_PUBLIC_KEY = TEST_KEYS + "blank.pem", KEY_1[1]

def run_n_times(f, g, n):
	def err(*args, **kwargs):
		if err.n > 0:
			err.n -= 1
			return f(*args, **kwargs)
		else: 
			return g(*args, **kwargs)
	err.n = n
	return err

class TestCipher(unittest.TestCase):

	def round_trip(self, key, text):
		salt, iv, enc = cipher.encrypt(text, key)
		output = cipher.decrypt(salt, iv, enc, key)
		self.assertEqual(output, text, "Failed to round trip")

	def test_round_trip_short_zero(self):
		self.assertRaises(cipher.CipherError, self.round_trip, SHORT_SYMMETRIC, '')

	def test_round_trip_short_long(self):
		self.round_trip(SHORT_SYMMETRIC, LONG)

	def test_round_trip_short_short(self):
		self.round_trip(SHORT_SYMMETRIC, SHORT)

	def test_round_trip_short_unicode(self):
		self.round_trip(SHORT_SYMMETRIC, UNICODE)

	def test_round_trip_short_null(self):
		self.round_trip(SHORT_SYMMETRIC, NULL)

	def test_round_trip_long_zero(self):
		self.assertRaises(cipher.CipherError, self.round_trip, LONG_SYMMETRIC, '')

	def test_round_trip_long_long(self):
		self.round_trip(LONG_SYMMETRIC, LONG)

	def test_round_trip_long_short(self):
		self.round_trip(LONG_SYMMETRIC, SHORT)

	def test_round_trip_long_unicode(self):
		self.round_trip(LONG_SYMMETRIC, UNICODE)

	def test_round_trip_long_null(self):
		self.round_trip(LONG_SYMMETRIC, NULL)

	def test_no_data(self):
		iv, salt, enc = cipher.encrypt(UNICODE, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, '', SHORT_SYMMETRIC)

	def test_short_salt(self):
		salt, iv, enc = cipher.encrypt(UNICODE, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, salt[:-1], iv, enc, SHORT_SYMMETRIC)

	def test_long_salt(self):
		salt, iv, enc = cipher.encrypt(UNICODE, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, salt+salt[:-1], iv, enc, SHORT_SYMMETRIC)

	def test_short_iv(self):
		salt, iv, enc = cipher.encrypt(UNICODE, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, salt, iv[:-1], enc, SHORT_SYMMETRIC)

	def test_long_iv(self):
		salt, iv, enc = cipher.encrypt(UNICODE, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, salt, iv+iv[:-1], enc, SHORT_SYMMETRIC)

	def test_round_trip_no_password(self):
		iv, salt, enc = cipher.encrypt(UNICODE, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.encrypt, UNICODE, '')
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, '')

	def test_round_trip_failure(self):
		salt, iv, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, salt, iv, enc, LONG_SYMMETRIC)
		salt, iv, enc = cipher.encrypt(NULL, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, salt, iv, enc, LONG_SYMMETRIC)

	def test_bad_rand_bytes(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		rand_bytes = cipher.evp.RAND_bytes
		cipher.evp.RAND_bytes = lambda a,b: 0
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.RAND_bytes = rand_bytes

	def test_bad_rand_bytes_1(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		rand_bytes = cipher.evp.RAND_bytes
		cipher.evp.RAND_bytes = lambda a,b: 0
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.RAND_bytes = rand_bytes

	def test_bad_rand_bytes_2(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		rand_bytes = cipher.evp.RAND_bytes
		cipher.evp.RAND_bytes = run_n_times(cipher.evp.RAND_bytes, lambda a,b:0, 1)
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.RAND_bytes = rand_bytes

	def test_bad_hash_by_name(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		hash_by_name = cipher.evp.EVP_get_digestbyname
		cipher.evp.EVP_get_digestbyname = lambda a: None
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.EVP_get_digestbyname = hash_by_name

	def test_bad_bytes_to_key(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		bytes_to_key = cipher.evp.EVP_BytesToKey
		cipher.evp.EVP_BytesToKey = lambda a,b,c,d,e,f,g,h: 0
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, SHORT_SYMMETRIC)
		cipher.evp.EVP_BytesToKey = bytes_to_key

	def test_bad_ctx_new(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		new_ctx = cipher.evp.EVP_CIPHER_CTX_new
		cipher.evp.EVP_CIPHER_CTX_new = lambda: None
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, SHORT_SYMMETRIC)
		cipher.evp.EVP_CIPHER_CTX_new = new_ctx

	def test_bad_cipher_object(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		cipher_getter = cipher.evp.EVP_aes_192_cbc
		cipher.evp.EVP_aes_192_cbc= lambda: None
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, SHORT_SYMMETRIC)
		cipher.evp.EVP_aes_192_cbc = cipher_getter

	def test_bad_encrypt_init_1(self):
		encrypt_init = cipher.evp.EVP_EncryptInit_ex
		cipher.evp.EVP_EncryptInit_ex = lambda a,b,c,d,e: None
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.EVP_EncryptInit_ex = encrypt_init

	def test_bad_encrypt_init_2(self):
		encrypt_init = cipher.evp.EVP_EncryptInit_ex
		cipher.evp.EVP_EncryptInit_ex = run_n_times(cipher.evp.EVP_EncryptInit_ex, lambda a,b,c,d,e: None, 1)
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.EVP_EncryptInit_ex = encrypt_init

	def test_bad_encrypt_update(self):
		encrypt_update = cipher.evp.EVP_EncryptUpdate
		cipher.evp.EVP_EncryptUpdate = lambda a,b,c,d,e: None
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.EVP_EncryptUpdate = encrypt_update

	def test_bad_encrypt_final(self):
		encrypt_final = cipher.evp.EVP_EncryptFinal_ex
		cipher.evp.EVP_EncryptFinal_ex = lambda a,b,c: None
		self.assertRaises(cipher.CipherError, cipher.encrypt, SHORT, SHORT_SYMMETRIC)
		cipher.evp.EVP_EncryptFinal_ex = encrypt_final

	def test_bad_decrypt_init(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		decrypt_init = cipher.evp.EVP_DecryptInit_ex
		cipher.evp.EVP_DecryptInit_ex = lambda a,b,c,d,e: None
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, SHORT_SYMMETRIC)
		cipher.evp.EVP_DecryptInit_ex = decrypt_init

	def test_bad_decrypt_update(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		decrypt_update = cipher.evp.EVP_DecryptUpdate
		cipher.evp.EVP_DecryptUpdate = lambda a,b,c,d,e: None
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, SHORT_SYMMETRIC)
		cipher.evp.EVP_DecryptUpdate = decrypt_update

	def test_bad_decrypt_final(self):
		iv, salt, enc = cipher.encrypt(SHORT, SHORT_SYMMETRIC)
		decrypt_final = cipher.evp.EVP_DecryptFinal_ex
		cipher.evp.EVP_DecryptFinal_ex = lambda a,b,c: None
		self.assertRaises(cipher.CipherError, cipher.decrypt, iv, salt, enc, SHORT_SYMMETRIC)
		cipher.evp.EVP_DecryptFinal_ex = decrypt_final


class TestSignature(unittest.TestCase):
	
	def round_trip(self, keys, text):
		s = signature.sign(text, keys[0])
		return signature.verify(text, s, keys[1])

	def round_trip_strings(self, keys, text):
		s = signature.sign(text, key=open(keys[0], 'rb').read())
		v = signature.verify(text, s, key=open(keys[1], 'rb').read())
		return v

	def round_trip_all_keys(self, text):
		self.assertTrue(self.round_trip(KEY_1, text))
		self.assertTrue(self.round_trip(KEY_2, text))
		self.assertFalse(self.round_trip(MISMATCH_1, text))
		self.assertFalse(self.round_trip(MISMATCH_2, text))
		self.assertTrue(self.round_trip_strings(KEY_1, text))
		self.assertTrue(self.round_trip_strings(KEY_2, text))
		self.assertFalse(self.round_trip_strings(MISMATCH_1, text))
		self.assertFalse(self.round_trip_strings(MISMATCH_2, text))

	def test_round_trip_long(self):
		self.round_trip_all_keys(LONG)

	def test_round_trip_short(self):
		self.round_trip_all_keys(SHORT)

	def test_round_trip_unicode(self):
		self.round_trip_all_keys(UNICODE)

	def test_round_trip_null(self):
		self.round_trip_all_keys(NULL)

	def test_round_trip_zero(self):
		self.round_trip_all_keys('')

	def test_arguments(self):
		text = SHORT
		keys = KEY_1
		self.failUnlessRaises(signature.SignatureError, signature.sign, text, key=open(keys[0], 'rb').read(), keyfile=keys[0])
		self.failUnlessRaises(signature.SignatureError, signature.sign, text)
		s = signature.sign(text, keyfile=keys[0])
		self.failUnlessRaises(signature.SignatureError, signature.verify, text, s, key=open(keys[1], 'rb').read(), keyfile=keys[1])
		self.failUnlessRaises(signature.SignatureError, signature.verify, text, s)

	def test_bad_ctx(self):
		s = signature.sign(SHORT, KEY_1[0])
		new_ctx = signature.evp.EVP_MD_CTX_create
		signature.evp.EVP_MD_CTX_create = lambda: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[0])
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[1])
		signature.evp.EVP_MD_CTX_create = new_ctx

	def test_bad_hash(self):
		s = signature.sign(SHORT, KEY_1[0])
		new_hash = signature.evp.EVP_get_digestbyname
		signature.evp.EVP_get_digestbyname = lambda a: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[0])
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[1])
		signature.evp.EVP_get_digestbyname = new_hash

	def test_bad_digest_init(self):
		s = signature.sign(SHORT, KEY_1[0])
		init = signature.evp.EVP_DigestInit
		signature.evp.EVP_DigestInit = lambda a,b: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[0])
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[1])
		signature.evp.EVP_DigestInit = init

	def test_bad_digest_update(self):
		s = signature.sign(SHORT, KEY_1[0])
		update = signature.evp.EVP_DigestUpdate
		signature.evp.EVP_DigestUpdate = lambda a,b,c: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[0])
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[1])
		signature.evp.EVP_DigestUpdate = update

	def test_bad_sign_final(self):
		final = signature.evp.EVP_SignFinal
		signature.evp.EVP_SignFinal = lambda a,b,c,d: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[0])
		signature.evp.EVP_SignFinal = final

	def test_bad_verify_final(self):
		s = signature.sign(SHORT, KEY_1[0])
		final = signature.evp.EVP_VerifyFinal
		signature.evp.EVP_VerifyFinal = lambda a,b,c,d: None
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[1])
		signature.evp.EVP_VerifyFinal = final

	def test_bad_read_privatekey(self):
		read_private_key = signature.evp.PEM_read_PrivateKey
		signature.evp.PEM_read_PrivateKey = lambda a,b,c,d: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[0])
		signature.evp.PEM_read_PrivateKey = read_private_key

	def test_bad_read_publickey(self):
		s = signature.sign(SHORT, KEY_1[0])
		read_public_key = signature.evp.PEM_read_PUBKEY
		signature.evp.PEM_read_PUBKEY = lambda a,b,c,d: None
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[1])
		signature.evp.PEM_read_PUBKEY = read_public_key

	def test_bad_read_bio_privatekey(self):
		read_private_key = signature.evp.PEM_read_bio_PrivateKey
		signature.evp.PEM_read_bio_PrivateKey = lambda a,b,c,d,e: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, key=open(KEY_1[0], 'rb').read())
		signature.evp.PEM_read_bio_PrivateKey = read_private_key

	def test_bad_read_bio_publickey(self):
		s = signature.sign(SHORT, KEY_1[0])
		read_public_key = signature.evp.PEM_read_bio_PUBKEY
		signature.evp.PEM_read_bio_PUBKEY = lambda a,b,c,d: None
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, key=open(KEY_1[1], 'rb').read())
		signature.evp.PEM_read_bio_PUBKEY = read_public_key

	def test_bad_fopen(self):
		s = signature.sign(SHORT, KEY_1[0])
		file_open = signature.evp.fopen
		signature.evp.fopen = lambda a,b: None
		self.assertRaises(signature.SignatureError, signature.sign, SHORT, KEY_1[1])
		self.assertRaises(signature.SignatureError, signature.verify, SHORT, s, KEY_1[0])
		signature.evp.fopen = file_open


class TestEnvelope(unittest.TestCase):

	def round_trip(self, keys, text):
		iv, sym_key, enc = envelope.encrypt(text, keys[1])
		return envelope.decrypt(iv, sym_key, enc, keys[0])

	def round_trip_strings(self, keys, text):
		iv, sym_key, enc = envelope.encrypt(text, key=open(keys[1], 'rb').read())
		return envelope.decrypt(iv, sym_key, enc, key=open(keys[0], 'rb').read())

	def test_round_trip_zero(self):
		self.assertRaises(envelope.EnvelopeError, self.round_trip, KEY_1, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip, KEY_2, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_1, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_2, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, KEY_1, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, KEY_2, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_1, '')
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_2, '')

	def test_round_trip_long(self):
		self.assertEqual(self.round_trip_strings(KEY_1, LONG), LONG, "Failed to round trip")
		self.assertEqual(self.round_trip_strings(KEY_2, LONG), LONG, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_1, LONG)
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_2, LONG)
		self.assertEqual(self.round_trip(KEY_1, LONG), LONG, "Failed to round trip")
		self.assertEqual(self.round_trip(KEY_2, LONG), LONG, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_1, LONG)
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_2, LONG)

	def test_round_trip_short(self):
		self.assertEqual(self.round_trip(KEY_1, SHORT), SHORT, "Failed to round trip")
		self.assertEqual(self.round_trip(KEY_2, SHORT), SHORT, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_1, SHORT)
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_2, SHORT)
		self.assertEqual(self.round_trip_strings(KEY_1, SHORT), SHORT, "Failed to round trip")
		self.assertEqual(self.round_trip_strings(KEY_2, SHORT), SHORT, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_1, SHORT)
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_2, SHORT)

	def test_round_trip_unicode(self):
		self.assertEqual(self.round_trip(KEY_1, UNICODE), UNICODE, "Failed to round trip")
		self.assertEqual(self.round_trip(KEY_2, UNICODE), UNICODE, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_1, UNICODE)
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_2, UNICODE)
		self.assertEqual(self.round_trip_strings(KEY_1, UNICODE), UNICODE, "Failed to round trip")
		self.assertEqual(self.round_trip_strings(KEY_2, UNICODE), UNICODE, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_1, UNICODE)
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_2, UNICODE)

	def test_round_trip_null(self):
		self.assertEqual(self.round_trip(KEY_1, NULL), NULL, "Failed to round trip")
		self.assertEqual(self.round_trip(KEY_2, NULL), NULL, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_1, NULL)
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISMATCH_2, NULL)
		self.assertEqual(self.round_trip_strings(KEY_1, NULL), NULL, "Failed to round trip")
		self.assertEqual(self.round_trip_strings(KEY_2, NULL), NULL, "Failed to round trip")
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_1, NULL)
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, MISMATCH_2, NULL)

	def test_bad_keys(self):
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISSING_PUBLIC_KEY, SHORT)
		self.assertRaises(envelope.EnvelopeError, self.round_trip, MISSING_PRIVATE_KEY, SHORT)
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, BLANK_PUBLIC_KEY, SHORT)
		self.assertRaises(envelope.EnvelopeError, self.round_trip_strings, BLANK_PRIVATE_KEY, SHORT)

	def test_bad_call(self):
		# neither key nor keyfile
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT)
		# both
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[0], open(KEY_1[0], 'rb').read())
		# string key instead of bytes
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, key=open(KEY_1[0], 'r').read())
		# string data instead of bytes
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, str(SHORT), KEY_1[0], open(KEY_1[0], 'rb').read())
		# get valid encryption data		
		iv, aes_key, enc = envelope.encrypt(SHORT, KEY_1[1])
		# neither key nor keyfile
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc)
		# both
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc, KEY_1[1], key=open(KEY_1[1], 'rb').read())
		# string key instead of bytes
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc, key=open(KEY_1[1], 'r').read())
		# string data instead of bytes
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, str(enc), KEY_1[1], key=open(KEY_1[1], 'rb').read())
		# string iv instead of bytes
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, str(iv), aes_key, enc, KEY_1[1], key=open(KEY_1[1], 'rb').read())
		# string key instead of bytes
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, str(aes_key), enc, KEY_1[1], key=open(KEY_1[1], 'rb').read())

	def test_bad_rand_bytes_1(self):
		rand_bytes = envelope.evp.RAND_bytes
		envelope.evp.RAND_bytes = lambda a,b:0
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.RAND_bytes = rand_bytes

	def test_bad_rand_bytes_2(self):
		rand_bytes = envelope.evp.RAND_bytes
		envelope.evp.RAND_bytes = run_n_times(evp.RAND_bytes, lambda a,b:0, 1)
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.RAND_bytes = rand_bytes

	def test_bad_rsa_size(self):
		rsa_size = envelope.evp.RSA_size
		envelope.evp.RSA_size = lambda a:0
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.RSA_size = rsa_size

	def test_bad_read_privatekey(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		read_private_key = envelope.evp.PEM_read_PrivateKey
		envelope.evp.PEM_read_PrivateKey = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.PEM_read_PrivateKey = read_private_key

	def test_bad_read_publickey(self):
		read_public_key = envelope.evp.PEM_read_PUBKEY
		envelope.evp.PEM_read_PUBKEY = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.PEM_read_PUBKEY = read_public_key

	def test_bad_read_bio_privatekey(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		read_private_key = envelope.evp.PEM_read_bio_PrivateKey
		envelope.evp.PEM_read_bio_PrivateKey = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, key=open(KEY_1[0], 'rb').read())
		envelope.evp.PEM_read_bio_PrivateKey = read_private_key

	def test_bad_read_bio_publickey(self):
		read_public_key = envelope.evp.PEM_read_bio_PUBKEY
		envelope.evp.PEM_read_bio_PUBKEY = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, key=open(KEY_1[0], 'rb').read())
		envelope.evp.PEM_read_bio_PUBKEY = read_public_key

	def test_bad_fopen(self):
		iv, aes_key, enc = envelope.encrypt(SHORT, KEY_1[1])
		file_open = envelope.evp.fopen
		envelope.evp.fopen = lambda a,b: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc, KEY_1[0])
		envelope.evp.fopen = file_open

	def test_bad_ctx_new(self):
		iv, aes_key, enc = envelope.encrypt(SHORT, KEY_1[1])
		new_ctx = envelope.evp.EVP_CIPHER_CTX_new
		envelope.evp.EVP_CIPHER_CTX_new = lambda: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc, KEY_1[0])
		envelope.evp.EVP_CIPHER_CTX_new = new_ctx

	def test_bad_cipher_object(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		cipher_getter = envelope.evp.EVP_aes_192_cbc
		envelope.evp.EVP_aes_192_cbc= lambda: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.EVP_aes_192_cbc = cipher_getter

	def test_bad_encrypt_init_1(self):
		encrypt_init = envelope.evp.EVP_EncryptInit_ex
		envelope.evp.EVP_EncryptInit_ex = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptInit_ex = encrypt_init

	def test_bad_encrypt_init_2(self):
		encrypt_init = envelope.evp.EVP_EncryptInit_ex
		envelope.evp.EVP_EncryptInit_ex = run_n_times(envelope.evp.EVP_EncryptInit_ex, lambda a,b,c,d,e: None, 1)
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptInit_ex = encrypt_init

	def test_bad_encrypt_update(self):
		encrypt_update = envelope.evp.EVP_EncryptUpdate
		envelope.evp.EVP_EncryptUpdate = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptUpdate = encrypt_update

	def test_bad_encrypt_final(self):
		encrypt_final = envelope.evp.EVP_EncryptFinal_ex
		envelope.evp.EVP_EncryptFinal_ex = lambda a,b,c: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptFinal_ex = encrypt_final

	def test_bad_open_init(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		decrypt_init = envelope.evp.EVP_OpenInit
		envelope.evp.EVP_OpenInit = lambda a,b,c,d,e,f: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.EVP_OpenInit = decrypt_init

	def test_bad_decrypt_update(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		decrypt_update = envelope.evp.EVP_DecryptUpdate
		envelope.evp.EVP_DecryptUpdate = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.EVP_DecryptUpdate = decrypt_update

	def test_bad_decrypt_final(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		decrypt_final = envelope.evp.EVP_DecryptFinal_ex
		envelope.evp.EVP_DecryptFinal_ex = lambda a,b,c: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		cipher.evp.EVP_DecryptFinal_ex = decrypt_final

	def test_bad_rsa_get(self):
		get_rsa = envelope.evp.EVP_PKEY_get1_RSA
		envelope.evp.EVP_PKEY_get1_RSA = lambda a: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_PKEY_get1_RSA = get_rsa

	def test_bad_rsa_encrypt(self):
		encrypt_rsa = envelope.evp.RSA_public_encrypt
		envelope.evp.RSA_public_encrypt = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.RSA_public_encrypt = encrypt_rsa

	def test_bad_read_privatekey(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		read_private_key = envelope.evp.PEM_read_PrivateKey
		envelope.evp.PEM_read_PrivateKey = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.PEM_read_PrivateKey = read_private_key

	def test_bad_read_publickey(self):
		read_public_key = envelope.evp.PEM_read_PUBKEY
		envelope.evp.PEM_read_PUBKEY = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.PEM_read_PUBKEY = read_public_key

	def test_bad_read_bio_privatekey(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		read_private_key = envelope.evp.PEM_read_bio_PrivateKey
		envelope.evp.PEM_read_bio_PrivateKey = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, key=open(KEY_1[0], 'rb').read())
		envelope.evp.PEM_read_bio_PrivateKey = read_private_key

	def test_bad_read_bio_publickey(self):
		read_public_key = envelope.evp.PEM_read_bio_PUBKEY
		envelope.evp.PEM_read_bio_PUBKEY = lambda a,b,c,d: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, key=open(KEY_1[0], 'rb').read())
		envelope.evp.PEM_read_bio_PUBKEY = read_public_key

	def test_bad_fopen(self):
		iv, aes_key, enc = envelope.encrypt(SHORT, KEY_1[1])
		file_open = envelope.evp.fopen
		envelope.evp.fopen = lambda a,b: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc, KEY_1[0])
		envelope.evp.fopen = file_open

	def test_bad_ctx_new(self):
		iv, aes_key, enc = envelope.encrypt(SHORT, KEY_1[1])
		new_ctx = envelope.evp.EVP_CIPHER_CTX_new
		envelope.evp.EVP_CIPHER_CTX_new = lambda: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, aes_key, enc, KEY_1[0])
		envelope.evp.EVP_CIPHER_CTX_new = new_ctx

	def test_bad_cipher_object(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		cipher_getter = envelope.evp.EVP_aes_192_cbc
		envelope.evp.EVP_aes_192_cbc= lambda: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.EVP_aes_192_cbc = cipher_getter

	def test_bad_encrypt_init(self):
		encrypt_init = envelope.evp.EVP_EncryptInit_ex
		envelope.evp.EVP_EncryptInit_ex = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptInit_ex = encrypt_init

	def test_bad_encrypt_update(self):
		encrypt_update = envelope.evp.EVP_EncryptUpdate
		envelope.evp.EVP_EncryptUpdate = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptUpdate = encrypt_update

	def test_bad_encrypt_final(self):
		encrypt_final = envelope.evp.EVP_EncryptFinal_ex
		envelope.evp.EVP_EncryptFinal_ex = lambda a,b,c: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_EncryptFinal_ex = encrypt_final

	def test_bad_open_init(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		decrypt_init = envelope.evp.EVP_OpenInit
		envelope.evp.EVP_OpenInit = lambda a,b,c,d,e,f: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.EVP_OpenInit = decrypt_init

	def test_bad_decrypt_update(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		decrypt_update = envelope.evp.EVP_DecryptUpdate
		envelope.evp.EVP_DecryptUpdate = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		envelope.evp.EVP_DecryptUpdate = decrypt_update

	def test_bad_decrypt_final(self):
		iv, key, enc = envelope.encrypt(SHORT, KEY_1[1])
		decrypt_final = envelope.evp.EVP_DecryptFinal_ex
		envelope.evp.EVP_DecryptFinal_ex = lambda a,b,c: None
		self.assertRaises(envelope.EnvelopeError, envelope.decrypt, iv, key, enc, KEY_1[0])
		cipher.evp.EVP_DecryptFinal_ex = decrypt_final

	def test_bad_rsa_get(self):
		get_rsa = envelope.evp.EVP_PKEY_get1_RSA
		envelope.evp.EVP_PKEY_get1_RSA = lambda a: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.EVP_PKEY_get1_RSA = get_rsa

	def test_bad_rsa_encrypt(self):
		encrypt_rsa = envelope.evp.RSA_public_encrypt
		envelope.evp.RSA_public_encrypt = lambda a,b,c,d,e: None
		self.assertRaises(envelope.EnvelopeError, envelope.encrypt, SHORT, KEY_1[1])
		envelope.evp.RSA_public_encrypt = encrypt_rsa

if __name__ == "__main__":
	unittest.main()
