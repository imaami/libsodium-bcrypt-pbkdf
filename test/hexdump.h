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

#ifndef _HEXDUMP_H_
#define _HEXDUMP_H_

#include <stdint.h>
#include <stddef.h>

extern void hexdump( const uint8_t *src,
                     size_t         src_len,
                     const char    *pfx,
                     size_t         pfx_len );

#endif // _HEXDUMP_H_

#ifdef __cplusplus
}
#endif
