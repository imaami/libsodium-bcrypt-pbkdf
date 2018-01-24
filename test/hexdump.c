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

__attribute__((always_inline))
static inline size_t hexdump_hex_byte( char    *dst,
                                       uint8_t  src )
{
	uint8_t tmp;

	dst[0] = ' ';

	// high nibble
	tmp = (src >> 4) & UINT8_C(0x0f);
	tmp += (tmp < UINT8_C(0x0a)) ? UINT8_C(0x30) : UINT8_C(0x57);
	dst[1] = (char)tmp;

	// low nibble
	tmp = src & UINT8_C(0x0f);
	tmp += (tmp < UINT8_C(0x0a)) ? UINT8_C(0x30) : UINT8_C(0x57);
	dst[2] = (char)tmp;

	return 3;
}

__attribute__((always_inline))
static inline size_t hexdump_ascii_byte( char    *dst,
                                         uint8_t  src,
                                         bool    *prt )
{
	size_t i = 0;

	if (src > UINT8_C(0x1f) && src < UINT8_C(0x7f)) {
		// This byte is a printable character
		if (!*prt) {
			// Previous byte was a non-printable character
			dst[i++] = '\x1b';
			dst[i++] = '[';
			dst[i++] = '0';
			dst[i++] = 'm';
			*prt = true;
		}
		dst[i++] = (char)src;

	} else {
		// This byte is a non-printable character
		if (*prt) {
			// Previous byte was a printable character
			dst[i++] = '\x1b';
			dst[i++] = '[';
			dst[i++] = '3';
			dst[i++] = '3';
			dst[i++] = 'm';
			*prt = false;
		}
		dst[i++] = '.';
	}

	return i;
}

static size_t hexdump_line( char          *dst,
                            const uint8_t *src,
                            size_t         len )
{
		size_t pos = 0, i = 0;
		bool tmp = (len < 9u);

		dst[pos++] = ' ';

		if (!tmp) {
			do {
				pos += hexdump_hex_byte(&dst[pos], src[i]);
			} while (++i < 8u);

			dst[pos++] = ' ';
		}

		for (; i < len; ++i) {
			pos += hexdump_hex_byte(&dst[pos], src[i]);
		}

		i = 16u - len;
		i += i << 1;
		i += 2 + (size_t)tmp;

		memset(&dst[pos], 0x20, i);
		pos += i;
		dst[pos++] = '|';

		tmp = true;

		for (i = 0; i < len; ++i) {
			pos += hexdump_ascii_byte(&dst[pos], src[i], &tmp);
		}

		if (!tmp) {
			dst[pos++] = '\x1b';
			dst[pos++] = '[';
			dst[pos++] = '0';
			dst[pos++] = 'm';
		}

		dst[pos++] = '|';
		dst[pos++] = '\0';

		return pos;
}

void hexdump( const uint8_t *src,
              size_t         src_len,
              const char    *pfx,
              size_t         pfx_len )
{
	if (src_len < 1u) {
		return;
	}

	char line[256] = { '|', ' ', '\x1b', '[', '3', '6', 'm', '\0' };
	size_t cols, pos;

	memcpy(&line[7], pfx, pfx_len);
	pos = 7u + pfx_len;
	line[pos++] = '\x1b';
	line[pos++] = '[';
	line[pos++] = '0';
	line[pos++] = 'm';
	line[pos++] = ' ';
	line[pos++] = '|';

	// First row
	cols = (src_len > 15u) ? 16u : (src_len & 15u);
	hexdump_line(&line[pos], src, cols);
	src_len -= cols;
	puts(line);

	// The rest of the rows
	if (src_len) {
		++pfx_len;
		memset(&line[2], 0x20, pfx_len);
		pos = 2u + pfx_len;
		line[pos++] = '|';

		do {
			src += cols;
			cols = (src_len > 15u) ? 16u : (src_len & 15u);
			hexdump_line(&line[pos], src, cols);
			src_len -= cols;
			puts(line);
		} while (src_len);
	}
}

#ifdef __cplusplus
}
#endif
