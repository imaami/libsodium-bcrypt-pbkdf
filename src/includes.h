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

#ifndef _INCLUDES_H_
#define _INCLUDES_H_

#include <stdint.h>

#define u_int32_t uint32_t
#define u_int16_t uint16_t
#define u_int8_t  uint8_t

#ifndef HAVE_STDLIB_H
# define HAVE_STDLIB_H
#endif

#include "openbsd-compat/blf.h"

#endif // _INCLUDES_H_
