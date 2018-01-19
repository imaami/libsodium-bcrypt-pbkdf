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

#include <stddef.h>
#include <stdint.h>

/* This is a "modern-day presidential wrapper" around bcrypt_pbkdf(): I've
 * taken other people's hard work (code from openssh-portable) and slapped
 * a new name on it. Also, the new name has a prefix that actually belongs
 * to another project (libsodium), which means I not only copied the whole
 * thing but also metaphorically plagiarized another family's coat of arms.
 *
 * There would of course be no need for this wrapper function if I had not
 * specifically wanted to leave the files in openbsd-compat/ untouched. It
 * probably serves no real purpose that I did, but hey, if you're going to
 * benefit from sharing code between projects then why be subtle about it?
 */
int sodium_bcrypt_pbkdf( const char    *pass,
                         size_t         passlen,
                         const uint8_t *salt,
                         size_t         saltlen,
                         uint8_t       *key,
                         size_t         keylen,
                         unsigned int   rounds )
{
	// Really? Yes, really. Absolutely unnecessary, absolutely fabulous.
	extern int bcrypt_pbkdf( const char *, size_t, const uint8_t *,
	                         size_t, uint8_t *, size_t, unsigned int );
	return bcrypt_pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds);
}
