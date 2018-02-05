/*
 * ISC License
 *
 * Copyright (c) 2018
 * Juuso Alasuutari <juuso dot alasuutari at gmail dot com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sodium.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "sodium_bcrypt_pbkdf.h"
#include "explicit_bzero_compat.h"

#define SSHKEY_CIPHER_TYPE_INVALID   (-1)
#define SSHKEY_CIPHER_TYPE_NONE      ( 0)
#define SSHKEY_CIPHER_TYPE_AES256CBC ( 1)
#define SSHKEY_CIPHER_TYPE_AES256CTR ( 2)

#define SSHKEY_KDF_TYPE_INVALID      (-1)
#define SSHKEY_KDF_TYPE_NONE         ( 0)
#define SSHKEY_KDF_TYPE_BCRYPT       ( 1)

__attribute__((always_inline))
static inline uint32_t sshkey_read_u32be( uint8_t *p )
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

__attribute((always_inline))
static inline bool skip_key_magic( uint8_t **data,
                                   size_t   *data_len );

__attribute__((always_inline))
static inline int sshkey_get_cipher( uint8_t **data,
                                     size_t   *data_len );

__attribute__((always_inline))
static inline int sshkey_get_kdf( uint8_t **data,
                                  size_t   *data_len,
                                  int       cipher,
                                  uint8_t **salt,
                                  size_t   *salt_len,
                                  size_t   *rounds );

static uint8_t *sshkey_decrypt( int      cipher,
                                uint8_t *enc,
                                size_t   enc_len,
                                uint8_t *key,
                                uint8_t *iv,
                                uint8_t *dec,
                                size_t  *dec_len );

static bool sshkey_get_u32be( uint8_t  **data,
                              size_t    *data_len,
                              uint32_t  *result );

static uint8_t *sshkey_get_public( uint8_t **data,
                                   size_t   *data_len,
                                   bool      nested );

static uint8_t *sshkey_get_data( uint8_t  **data,
                                 size_t    *data_len,
                                 uint32_t  *result_len );

bool sshkey_parse( const uint8_t *buf,
                   size_t         len,
                   const char    *pass,
                   uint8_t       *public,
                   uint8_t       *secret,
                   char          *comment,
                   size_t         comment_len )
{
	const char head[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
	const char foot[] = "-----END OPENSSH PRIVATE KEY-----";
	const size_t head_len = sizeof(head) - 1u;
	const size_t foot_len = sizeof(foot) - 1u;

	while (len > 0u) {
		switch (buf[0]) {
		case (uint8_t)'\t':
		case (uint8_t)'\n':
		case (uint8_t)'\r':
		case (uint8_t)' ':
			++buf;
			--len;
			continue;
		}
		break;
	}

	while (len > 0u) {
		size_t i = len - 1u;
		switch (buf[i]) {
		case (uint8_t)'\t':
		case (uint8_t)'\n':
		case (uint8_t)'\r':
		case (uint8_t)' ':
			len = i;
			continue;
		}
		break;
	}

	if (len < (head_len + foot_len)
	    || memcmp(buf, head, head_len) != 0
	    || memcmp(&buf[len - foot_len], foot, foot_len) != 0) {
		return false;
	}

	uint8_t _bin[BUFSIZ];
	uint8_t *bin = &_bin[0];

	memset(bin, 0, sizeof(_bin));

	bool ret = false;

	do {
		const char *b64 = (const char *)&buf[head_len];
		size_t b64_len = len - (head_len + foot_len);

		if (sodium_base642bin(bin, sizeof(_bin), b64,
		                      b64_len, "\t\n\r ", &len,
		                      NULL, sodium_base64_VARIANT_ORIGINAL)) {
			break;
		}

		if (!skip_key_magic(&bin, &len)) {
			break;
		}

		int cipher = sshkey_get_cipher(&bin, &len);
		if (cipher == SSHKEY_CIPHER_TYPE_INVALID) {
			break;
		}

		uint8_t *salt = NULL;
		size_t salt_len = 0, rounds = 0;
		int kdf = sshkey_get_kdf(&bin, &len, cipher,
		                         &salt, &salt_len,
		                         &rounds);
		if (kdf == SSHKEY_KDF_TYPE_INVALID) {
			break;
		}

		if ((kdf == SSHKEY_KDF_TYPE_BCRYPT)
		    && (salt_len < 1u || rounds < 1u)) {
			break;
		}

		uint32_t u32 = 0;

		// Key count must be exactly 1
		if (!sshkey_get_u32be(&bin, &len, &u32) || u32 != 1u) {
			break;
		}

		uint8_t *pub[2] = { NULL, NULL };

		// Get pointer to public key data
		if (!(pub[0] = sshkey_get_public(&bin, &len, true))) {
			break;
		}

		// Read secret key data, can be encrypted or not
		uint8_t *data = NULL;
		if (!(data = sshkey_get_data(&bin, &len, &u32))) {
			break;
		}
		len = (size_t)u32;

		if (kdf) {
			(void)sodium_bcrypt_pbkdf(pass, strlen(pass), salt,
			                          salt_len, bin, 48, rounds);

			uint8_t *key = bin;
			uint8_t *iv = key + 32;
			uint8_t *out = iv + 16;

			if (!(data = sshkey_decrypt(cipher, data, len,
			                            key, iv, out, &len))) {
				break;
			}
		}

		if (len < 8u ||
		    sshkey_read_u32be(data) != sshkey_read_u32be(&data[4])) {
			break;
		}

		data += 8;
		len -= 8u;

		if (!(pub[1] = sshkey_get_public(&data, &len, false))) {
			break;
		}

		if (memcmp(pub[0], pub[1], 32u) != 0) {
			break;
		}

		uint8_t *sec = sshkey_get_data(&data, &len, &u32);
		if (sec == NULL || u32 != 64u) {
			break;
		}
		memcpy(secret, sec, 64u);

		if (public) {
			memcpy(public, pub[0], 32u);
		}

		if (comment != NULL && comment_len > 0u) {
			uint8_t *com = sshkey_get_data(&data, &len, &u32);

			if (com == NULL || u32 < 1u) {
				len = 0;

			} else {
				len = (u32 < comment_len)
				      ? (size_t)u32
				      : (comment_len - 1u);
				memcpy(comment, com, len);
			}

			memset(&comment[len], 0, comment_len - len);
		}

		ret = true;
	} while (0);

	explicit_bzero(&_bin[0], sizeof(_bin));

	return ret;
}

__attribute((always_inline))
static inline bool skip_key_magic( uint8_t **data,
                                   size_t   *data_len )
{
	const char magic[] = "openssh-key-v1";
	uint8_t *ptr = *data;
	size_t len = *data_len;

	if (len < sizeof(magic) || memcmp(ptr, magic, sizeof(magic)) != 0) {
		return false;
	}

	*data = ptr + sizeof(magic);
	*data_len = len - sizeof(magic);

	return true;
}

static bool sshkey_get_u32be( uint8_t  **data,
                              size_t    *data_len,
                              uint32_t  *result )
{
	size_t len = *data_len;

	if (len < 4) {
		return false;
	}

	uint8_t *ptr = *data;

	*result = sshkey_read_u32be(ptr);
	*data_len = len - 4;
	*data = ptr + 4;

	return true;
}

static uint8_t *sshkey_get_data( uint8_t  **data,
                                 size_t    *data_len,
                                 uint32_t  *result_len )
{
	size_t len = *data_len;

	if (len < 4u) {
		return NULL;
	}

	uint8_t *ptr = *data;
	uint32_t u32 = sshkey_read_u32be(ptr);

	len -= 4u;

	if (len < (size_t)u32) {
		ptr = NULL;

	} else {
		ptr += 4;

		*result_len = u32;
		*data_len = len - (size_t)u32;
		*data = ptr + u32;
	}

	u32 = 0u;

	return ptr;
}

__attribute__((always_inline))
static inline int sshkey_get_cipher_type( uint8_t *name,
                                          size_t   name_len )
{
	switch (name_len) {
	case 4:
		return (memcmp(name, "none", 4) == 0)
		       ? SSHKEY_CIPHER_TYPE_NONE
		       : SSHKEY_CIPHER_TYPE_INVALID;
	case 10:
		if (memcmp(name, "aes256-c", 8) == 0) {
			switch (name[8]) {
			case (uint8_t)'b':
				return (name[9] == (uint8_t)'c')
				       ? SSHKEY_CIPHER_TYPE_AES256CBC
				       : SSHKEY_CIPHER_TYPE_INVALID;
			case (uint8_t)'t':
				if (name[9] == (uint8_t)'r') {
					return SSHKEY_CIPHER_TYPE_AES256CTR;
				}
			}
		}
#if __GNUC__ >= 7
		__attribute__((fallthrough));
#endif
	default:
		return SSHKEY_CIPHER_TYPE_INVALID;
	}
}

__attribute__((always_inline))
static inline int sshkey_get_cipher( uint8_t **data,
                                     size_t   *data_len )
{
	uint8_t *name;
	uint32_t name_len;

	if (!(name = sshkey_get_data(data, data_len, &name_len))) {
		return SSHKEY_CIPHER_TYPE_INVALID;
	}

	return sshkey_get_cipher_type(name, name_len);
}

__attribute__((always_inline))
static inline int sshkey_get_kdf_type( uint8_t *name,
                                       size_t   name_len )
{
	switch (name_len) {
	case 4:
		return (memcmp(name, "none", 4) == 0)
		       ? SSHKEY_KDF_TYPE_NONE
		       : SSHKEY_KDF_TYPE_INVALID;
	case 6:
		return (memcmp(name, "bcrypt", 6) == 0)
		       ? SSHKEY_KDF_TYPE_BCRYPT
		       : SSHKEY_KDF_TYPE_INVALID;
	default:
		return SSHKEY_KDF_TYPE_INVALID;
	}
}

__attribute__((always_inline))
static inline int sshkey_get_kdf( uint8_t **data,
                                  size_t   *data_len,
                                  int       cipher,
                                  uint8_t **salt,
                                  size_t   *salt_len,
                                  size_t   *rounds )
{
	uint8_t *ptr;
	uint32_t len;
	int kdf;

	if (!(ptr = sshkey_get_data(data, data_len, &len))) {
		return SSHKEY_KDF_TYPE_INVALID;
	}

	if ((kdf = sshkey_get_kdf_type(ptr, len)) != SSHKEY_KDF_TYPE_INVALID) {
		// KDF params length
		if (!sshkey_get_u32be(data, data_len, &len)) {
			return SSHKEY_KDF_TYPE_INVALID;
		}

		if (kdf == SSHKEY_KDF_TYPE_NONE) {
			// If KDF is none forbid params and cipher
			if (len > 0u || cipher != SSHKEY_CIPHER_TYPE_NONE) {
				kdf = SSHKEY_KDF_TYPE_INVALID;
			}
			return kdf;
		}

		// If KDF is not none require params and cipher. Because the
		// layout of KDF params is [salt length + salt + rounds] the
		// minimum params length is 2*4 bytes (if salt length is 0).
		if (len < 8u || cipher == SSHKEY_CIPHER_TYPE_NONE) {
			return SSHKEY_KDF_TYPE_INVALID;
		}

		// Salt
		if (!(ptr = sshkey_get_data(data, data_len, &len))) {
			return SSHKEY_KDF_TYPE_INVALID;
		}
		*salt = ptr;
		*salt_len = (size_t)len;

		// Rounds
		if (!sshkey_get_u32be(data, data_len, &len)) {
			return SSHKEY_KDF_TYPE_INVALID;
		}
		*rounds = (size_t)len;
	}

	return kdf;
}

static uint8_t *sshkey_decrypt( int      cipher,
                                uint8_t *enc,
                                size_t   enc_len,
                                uint8_t *key,
                                uint8_t *iv,
                                uint8_t *dec,
                                size_t  *dec_len )
{
	if (cipher == SSHKEY_CIPHER_TYPE_NONE) {
		*dec_len = enc_len;
		return enc;
	}

	uint8_t *ret = NULL;
	EVP_CIPHER_CTX ctx;

	EVP_CIPHER_CTX_init(&ctx);

	do {
		int _len1 = 0, _len2 = 0;

		if (EVP_DecryptInit_ex(&ctx,
		                       (cipher == SSHKEY_CIPHER_TYPE_AES256CBC)
		                       ? EVP_aes_256_cbc()
		                       : EVP_aes_256_ctr(),
		                       NULL, key, iv) != 1) {
			break;
		}

		if (!(enc_len & 15u)) {
			(void)EVP_CIPHER_CTX_set_padding(&ctx, 0);
		}

		if (EVP_DecryptUpdate(&ctx, dec, &_len1,
		                      enc, (int)enc_len) != 1) {
			break;
		}

		if (EVP_DecryptFinal_ex(&ctx, dec + _len1, &_len2) != 1) {
			break;
		}

		*dec_len = (size_t)(_len1 + _len2);
		ret = dec;
	} while(0);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return ret;
}

static uint8_t *sshkey_get_public( uint8_t **data,
                                   size_t   *data_len,
                                   bool      nested )
{
	const char magic[] = "ssh-ed25519";
	uint32_t len = 0;
	uint8_t *ptr = NULL;

	if (nested) {
		if (!sshkey_get_u32be(data, data_len, &len)
		    || (len != (4u + (sizeof(magic) - 1u) + 4u + 32u))) {
			return NULL;
		}
	}

	if (!(ptr = sshkey_get_data(data, data_len, &len))
	    || (len != (sizeof(magic) - 1u))
	    || (memcmp(ptr, magic, sizeof(magic) - 1u) != 0)) {
		return NULL;
	}

	if (!(ptr = sshkey_get_data(data, data_len, &len)) || (len != 32u)) {
		return NULL;
	}

	return ptr;
}

#ifdef __cplusplus
}
#endif
