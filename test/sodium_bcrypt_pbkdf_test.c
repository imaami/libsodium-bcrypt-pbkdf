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
#include <sodium.h>

#include "sshkey.h"
#include "hexdump.h"

static const char EXAMPLE_ED25519_KEY[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBQiEncSN\n"
    "XufpFQBYcZgzG0AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJSDa2FIQAqjANN8\n"
    "DapA8hP7MqzblNqMTq0TR4mIpYduAAAAoBNPDJDkoq8qvPQrzASUnJsKZfhqnkeT8xw44v\n"
    "CENLCNBp2+++/NbJBbUoqTr99nvO+nwYlceTUc9nSF8HpHAH35HxyTfxOocutZoz/mdqHJ\n"
    "zlqeVodBa8T94NQiYG/AhMd7rwpalh27mpGf5Dxv4Bty/9Zb3HZvNZ5+wYObnYJQTIyw7o\n"
    "YVyTQVfW1TTw5HBnTsMzVnTprhJmsQTgKVESI=\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

int main( int    argc,
          char **argv )
{
	(void)argc;
	(void)argv;

	if (sodium_init() == -1) {
		return EXIT_FAILURE;
	}

	uint8_t buf[256];
	uint8_t *public = &buf[0];
	uint8_t *secret = public + 32;
	char *comment = (char *)(secret + 64);
	size_t comment_len = sizeof(buf) - (32u + 64u);

	memset(&buf[0], 0, sizeof(buf));

	puts("+------+----------------------------------------------------+----------------+");
	hexdump((const uint8_t *)&EXAMPLE_ED25519_KEY[0],
	        sizeof(EXAMPLE_ED25519_KEY) - 1u, "file", 4);
	puts("+------+----------------------------------------------------+----------------+");

	if (!sshkey_parse((const uint8_t *)&EXAMPLE_ED25519_KEY[0],
	                  sizeof(EXAMPLE_ED25519_KEY) - 1, "example",
	                  public, secret, comment, comment_len)) {
		return EXIT_FAILURE;
	}

	hexdump((const uint8_t *)public, 32u, "pub ", 4);
	puts("+------+----------------------------------------------------+----------------+");
	hexdump((const uint8_t *)secret, 64u, "sec ", 4);
	puts("+------+----------------------------------------------------+----------------+");

	if ((comment_len = strlen(comment)) > 0u) {
		hexdump((const uint8_t *)comment, comment_len, "com ", 4);
		puts("+------+----------------------------------------------------+----------------+");
	}

	return EXIT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
