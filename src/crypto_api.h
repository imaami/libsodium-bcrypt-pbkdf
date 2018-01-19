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

#ifndef _CRYPTO_API_H_
#define _CRYPTO_API_H_

#include <sodium.h>

/* This inline function is a workaround for the following compiler warning:
 *
 *   bcrypt_pbkdf.c: In function ‘bcrypt_pbkdf’:
 *   bcrypt_pbkdf.c:137:31: warning: pointer targets in passing argument 2
 *   of ‘crypto_hash_sha512’ differ in signedness [-Wpointer-sign]
 *     crypto_hash_sha512(sha2pass, pass, passlen);
 *                                  ^~~~
 */
__attribute__((always_inline))
static inline int really_crypto_hash_sha512( unsigned char       *out,
                                             const unsigned char *in,
                                             unsigned long long   inlen )
{
	return crypto_hash_sha512(out, in, inlen);
#	define crypto_hash_sha512(out, in, inlen)\
	really_crypto_hash_sha512(out, (const unsigned char *)(in), inlen)
}

#endif // _CRYPTO_API_H_
