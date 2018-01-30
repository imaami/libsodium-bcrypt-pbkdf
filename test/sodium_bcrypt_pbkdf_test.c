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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sodium.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "sodium_bcrypt_pbkdf.h"
#include "hexdump.h"

__attribute__((always_inline))
static inline int decrypt( uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *key, uint8_t *iv, uint8_t *plaintext );

int main( int    argc,
          char **argv )
{
	if (argc < 2 || argv[1] == NULL || sodium_init() == -1) {
		return EXIT_FAILURE;
	}

	uint8_t salt[16];
	uint8_t hash[48];

	memset(&salt[0], 0, sizeof(salt)); // Obviously not a decent salt
	memset(&hash[0], 0, sizeof(hash));


	int r = sodium_bcrypt_pbkdf(argv[1], strlen(argv[1]),
	                            salt, sizeof(salt),
	                            hash, sizeof(hash), 16);

	uint8_t *key = &hash[0], *iv = &hash[32];

	// Obviously not actual ciphertext (but who knows, right?)
	uint8_t ciphertext[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	uint8_t plaintext[BUFSIZ] = { '\0' };

	puts("+------+----------------------------------------------------+----------------+");
	hexdump((const uint8_t *)salt, sizeof(salt), "salt", 4);
	puts("+------+----------------------------------------------------+----------------+");
	hexdump((const uint8_t *)key, 32, "key ", 4);
	puts("+------+----------------------------------------------------+----------------+");
	hexdump((const uint8_t *)iv, 16, "iv  ", 4);
	puts("+------+----------------------------------------------------+----------------+");
	hexdump((const uint8_t *)ciphertext, sizeof(ciphertext), "enc ", 4);

	r = decrypt(ciphertext, sizeof(ciphertext), key, iv, plaintext);
	if (r > 0) {
		puts("+------+----------------------------------------------------+----------------+");
		hexdump((const uint8_t *)plaintext, (size_t)r, "dec ", 4);
	}

	puts("+------+----------------------------------------------------+----------------+");

	return (r == -1) ? EXIT_FAILURE : EXIT_SUCCESS;
}

__attribute__((always_inline))
static inline int decrypt( uint8_t *ciphertext, size_t ciphertext_len,
                           uint8_t *key, uint8_t *iv, uint8_t *plaintext )
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, plaintext_len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (EVP_DecryptUpdate(ctx, plaintext, &len,
	                      ciphertext, (int)ciphertext_len) != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

#ifdef __cplusplus
}
#endif
