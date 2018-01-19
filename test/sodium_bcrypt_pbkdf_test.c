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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "sodium_bcrypt_pbkdf.h"

int main( int    argc,
          char **argv )
{
	if (argc < 2 || argv[1] == NULL || sodium_init() == -1) {
		return EXIT_FAILURE;
	}

	uint8_t salt[16];
	uint8_t key[48];

	randombytes_buf(salt, sizeof(salt));

	fputs("salt: ", stdout);
	for (size_t i = 0; i < sizeof(salt); ++i) {
		printf("%02x", salt[i]);
	}
	puts("");

	int r = sodium_bcrypt_pbkdf(argv[1], strlen(argv[1]),
	                            salt, sizeof(salt),
	                            key, sizeof(key), 16);

	fputs("key:  ", stdout);
	if (r == 0) {
		for (size_t i = 0; i < sizeof(key); ++i) {
			printf("%02x", key[i]);
		}
	}
	puts("");

	return r;
}
