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

#ifndef _SODIUM_BCRYPT_PBKDF_H_
#define _SODIUM_BCRYPT_PBKDF_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Remember to link your program against libsodium,
 * and call sodium_init() before this function.
 */
extern int sodium_bcrypt_pbkdf( const char    *pass,
                                size_t         passlen,
                                const uint8_t *salt,
                                size_t         saltlen,
                                uint8_t       *key,
                                size_t         keylen,
                                unsigned int   rounds );

#endif // _SODIUM_BCRYPT_PBKDF_H_
