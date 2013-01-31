#! /usr/bin/env python

import ctypes
import ctypes.util
import platform
from os import linesep

def handle_errors():
	ERR_load_crypto_strings()
	errno = ERR_get_error()
	errbuf = ctypes.create_string_buffer(1024)
	ERR_error_string_n(errno, errbuf, 1024)
	return errbuf.value.decode("ascii")

class SSLError(Exception):
	def __init__(self, msg):
		sslerr = handle_errors()
		Exception.__init__(self, msg + linesep + sslerr)

libraries = {}

libraries["c"] = ctypes.CDLL(ctypes.util.find_library("c"))

if platform.system() != "Windows":
	libraries["ssl"] = ctypes.CDLL(ctypes.util.find_library("ssl"))
else:
	libraries["ssl"] = ctypes.CDLL(ctypes.util.find_library("libeay32"))


class RSA(ctypes.Structure):
	_fields_ = [	("n", ctypes.c_void_p),
			("e", ctypes.c_void_p),
			("d", ctypes.c_void_p),
			("p", ctypes.c_void_p),
			("q", ctypes.c_void_p),
			("dmp1", ctypes.c_void_p),
			("iqmp", ctypes.c_void_p)]

def handle_errors():
	ERR_load_crypto_strings()
	errno = ERR_get_error()
	errbuf = ctypes.create_string_buffer(1024)
	ERR_error_string_n(errno, errbuf, 1024)
	return errbuf.value.decode("ascii")


fopen = libraries['c'].fopen
fopen.restype = ctypes.c_void_p
fopen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]


fclose = libraries['c'].fclose
fclose.restype = ctypes.c_int
fclose.argtypes = [ctypes.c_void_p]


ERR_load_crypto_strings = libraries['ssl'].ERR_load_crypto_strings
ERR_load_crypto_strings.restype = ctypes.c_int
ERR_load_crypto_strings.argtypes = []


ERR_print_errors_fp = libraries['ssl'].ERR_print_errors_fp
ERR_print_errors_fp.restype = ctypes.c_int
ERR_print_errors_fp.argtypes = [ctypes.c_void_p]


OpenSSL_add_all_digests = libraries['ssl'].OpenSSL_add_all_digests
OpenSSL_add_all_digests.restype = ctypes.c_int
OpenSSL_add_all_digests.argtypes = []


EVP_MD_CTX_create = libraries['ssl'].EVP_MD_CTX_create
EVP_MD_CTX_create.restype = ctypes.c_void_p
EVP_MD_CTX_create.argtypes = []


PEM_read_PrivateKey = libraries['ssl'].PEM_read_PrivateKey
PEM_read_PrivateKey.restype = ctypes.c_void_p
PEM_read_PrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


PEM_read_X509 = libraries['ssl'].PEM_read_X509
PEM_read_X509.restype = ctypes.c_void_p
PEM_read_X509.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


PEM_read_PUBKEY = libraries['ssl'].PEM_read_PUBKEY
PEM_read_PUBKEY.restype = ctypes.c_void_p
PEM_read_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


PEM_read_bio_PUBKEY = libraries['ssl'].PEM_read_bio_PUBKEY
PEM_read_bio_PUBKEY.restype = ctypes.c_void_p
PEM_read_bio_PUBKEY.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


BIO_free = libraries['ssl'].BIO_free
BIO_free.restype = ctypes.c_int
BIO_free.argtypes = [ctypes.c_void_p]


PEM_read_bio_PrivateKey = libraries['ssl'].PEM_read_bio_PrivateKey
PEM_read_bio_PrivateKey.restype = ctypes.c_void_p
PEM_read_bio_PrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


EVP_get_digestbyname = libraries['ssl'].EVP_get_digestbyname
EVP_get_digestbyname.restype = ctypes.c_void_p
EVP_get_digestbyname.argtypes = [ctypes.c_char_p]


EVP_DigestInit = libraries['ssl'].EVP_DigestInit
EVP_DigestInit.restype = ctypes.c_int
EVP_DigestInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


EVP_DigestUpdate = libraries['ssl'].EVP_DigestUpdate
EVP_DigestUpdate.restype = ctypes.c_int
EVP_DigestUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]


EVP_SignFinal = libraries['ssl'].EVP_SignFinal
EVP_SignFinal.restype = ctypes.c_int
EVP_SignFinal.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p]


EVP_VerifyFinal = libraries['ssl'].EVP_VerifyFinal
EVP_VerifyFinal.restype = ctypes.c_int
EVP_VerifyFinal.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]


EVP_PKEY_free = libraries['ssl'].EVP_PKEY_free
EVP_PKEY_free.restype = ctypes.c_int
EVP_PKEY_free.argtypes = [ctypes.c_void_p]


EVP_MD_CTX_cleanup = libraries['ssl'].EVP_MD_CTX_cleanup
EVP_MD_CTX_cleanup.restype = ctypes.c_int
EVP_MD_CTX_cleanup.argtypes = [ctypes.c_void_p]


EVP_MD_CTX_destroy = libraries['ssl'].EVP_MD_CTX_destroy
EVP_MD_CTX_destroy.restype = ctypes.c_int
EVP_MD_CTX_destroy.argtypes = [ctypes.c_void_p]


EVP_CIPHER_CTX_new = libraries['ssl'].EVP_CIPHER_CTX_new
EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
EVP_CIPHER_CTX_new.argtypes = []


EVP_CIPHER_CTX_init = libraries['ssl'].EVP_CIPHER_CTX_init
EVP_CIPHER_CTX_init.restype = ctypes.c_int
EVP_CIPHER_CTX_init.argtypes = [ctypes.c_void_p]

try:
	EVP_CIPHER_CTX_iv_length = libraries['ssl'].EVP_CIPHER_CTX_iv_length
	EVP_CIPHER_CTX_iv_length.restype = ctypes.c_int
	EVP_CIPHER_CTX_iv_length.argtypes = [ctypes.c_void_p]
except:
	EVP_CIPHER_CTX_iv_length = lambda(x): 16


EVP_aes_192_cbc = libraries['ssl'].EVP_aes_192_cbc
EVP_aes_192_cbc.restype = ctypes.c_void_p
EVP_aes_192_cbc.argtypes = []


EVP_PKEY_size = libraries['ssl'].EVP_PKEY_size
EVP_PKEY_size.restype = ctypes.c_int
EVP_PKEY_size.argtypes = [ctypes.c_void_p]


EVP_SealInit = libraries['ssl'].EVP_SealInit
EVP_SealInit.restype = ctypes.c_int
EVP_SealInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]


EVP_EncryptInit_ex = libraries['ssl'].EVP_EncryptInit_ex
EVP_EncryptInit_ex.restype = ctypes.c_int
EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]


EVP_EncryptUpdate = libraries['ssl'].EVP_EncryptUpdate
EVP_EncryptUpdate.restype = ctypes.c_int
EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]


EVP_DecryptUpdate = libraries['ssl'].EVP_DecryptUpdate
EVP_DecryptUpdate.restype = ctypes.c_int
EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]


EVP_EncryptFinal_ex = libraries['ssl'].EVP_EncryptFinal_ex
EVP_EncryptFinal_ex.restype = ctypes.c_int
EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]


EVP_SealFinal = libraries['ssl'].EVP_SealFinal
EVP_SealFinal.restype = ctypes.c_int
EVP_SealFinal.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]


EVP_DecryptFinal_ex = libraries['ssl'].EVP_DecryptFinal_ex
EVP_DecryptFinal_ex.restype = ctypes.c_int
EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]


RAND_bytes = libraries['ssl'].RAND_bytes
RAND_bytes.restype = ctypes.c_int
RAND_bytes.argtypes = [ctypes.c_char_p, ctypes.c_int]


BIO_new_mem_buf = libraries['ssl'].BIO_new_mem_buf
BIO_new_mem_buf.restype = ctypes.c_void_p
BIO_new_mem_buf.argtypes = [ctypes.c_char_p, ctypes.c_int]


EVP_CIPHER_CTX_rand_key = libraries['ssl'].EVP_CIPHER_CTX_rand_key
EVP_CIPHER_CTX_rand_key.restype = ctypes.c_int
EVP_CIPHER_CTX_rand_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p]


try:
	EVP_CIPHER_key_length = libraries['ssl'].EVP_CIPHER_key_length
	EVP_CIPHER_key_length.restype = ctypes.c_int
	EVP_CIPHER_key_length.argtypes = [ctypes.c_void_p]
except:
	EVP_CIPHER_key_length = lambda(x): 24


EVP_PKEY_encrypt = libraries['ssl'].EVP_PKEY_encrypt
EVP_PKEY_encrypt.restype = ctypes.c_int
EVP_PKEY_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]


EVP_OpenInit = libraries['ssl'].EVP_OpenInit
EVP_OpenInit.restype = ctypes.c_int
EVP_OpenInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p]


EVP_PKEY_size = libraries['ssl'].EVP_PKEY_size
EVP_PKEY_size.restype = ctypes.c_int
EVP_PKEY_size.argtypes = [ctypes.c_void_p]


RSA_public_encrypt = libraries['ssl'].RSA_public_encrypt
RSA_public_encrypt.restype = ctypes.c_int
RSA_public_encrypt.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]


EVP_PKEY_get1_RSA = libraries['ssl'].EVP_PKEY_get1_RSA
EVP_PKEY_get1_RSA.restype = ctypes.c_void_p
EVP_PKEY_get1_RSA.argtypes = [ctypes.c_void_p]


EVP_DecryptInit_ex = libraries['ssl'].EVP_DecryptInit_ex
EVP_DecryptInit_ex.restype = ctypes.c_int
EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]


EVP_CIPHER_CTX_set_key_length = libraries['ssl'].EVP_CIPHER_CTX_set_key_length
EVP_CIPHER_CTX_set_key_length.restype = ctypes.c_int
EVP_CIPHER_CTX_set_key_length.argtypes = [ctypes.c_void_p, ctypes.c_int]


EVP_BytesToKey = libraries['ssl'].EVP_BytesToKey
EVP_BytesToKey.restype = ctypes.c_int
EVP_BytesToKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]


ERR_get_error = libraries['ssl'].ERR_get_error
ERR_get_error.restype = ctypes.c_long
ERR_get_error.argtypes = []


ERR_error_string_n = libraries['ssl'].ERR_error_string_n
ERR_error_string_n.restype = ctypes.c_void_p
ERR_error_string_n.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_int]

RSA_size = libraries['ssl'].RSA_size
RSA_size.restype = ctypes.c_int
RSA_size.argtypes = [ctypes.c_void_p]

RSA_new = libraries['ssl'].RSA_new
RSA_new.restype = ctypes.POINTER(RSA)

RSA_generate_key = libraries['ssl'].RSA_generate_key
RSA_generate_key.restype = ctypes.POINTER(RSA)
RSA_generate_key.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]

RSA_print = libraries['ssl'].RSA_print
RSA_print.restype = ctypes.c_int
RSA_print.argtypes = [ctypes.c_void_p, ctypes.POINTER(RSA), ctypes.c_int]

PEM_write_bio_RSA_PUBKEY = libraries['ssl'].PEM_write_bio_RSA_PUBKEY

PEM_write_bio_RSAPrivateKey = libraries['ssl'].PEM_write_bio_RSAPrivateKey
PEM_write_bio_RSAPrivateKey.restype = ctypes.c_int
PEM_write_bio_RSAPrivateKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(RSA), ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

PEM_write_RSAPrivateKey = libraries['ssl'].PEM_write_RSAPrivateKey
PEM_write_RSAPrivateKey.restype = ctypes.c_int
PEM_write_RSAPrivateKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(RSA), ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

i2d_RSAPrivateKey = libraries['ssl'].i2d_RSAPrivateKey

BIO_read = libraries['ssl'].BIO_read

BIO_s_mem = libraries['ssl'].BIO_s_mem
BIO_s_mem.restype = ctypes.c_void_p

BIO_new = libraries['ssl'].BIO_new
BIO_new.restype = ctypes.c_void_p
BIO_new.argtypes = [ctypes.c_void_p]

RAND_seed = libraries['ssl'].RAND_seed
RAND_seed.argtypes = [ctypes.c_void_p, ctypes.c_int]
