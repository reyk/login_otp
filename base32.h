/*
 * Copyright (c) 2015 Reyk Floeter <contact@reykfloeter.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#ifndef _BASE32_H
#define _BASE32_H

int	 base32_decode(const uint8_t *, uint8_t *, size_t);
int	 base32_encode(const uint8_t *, size_t, uint8_t *, size_t);
int	 xbase32_decode(const uint8_t *, uint8_t *, size_t);
int	 xbase32_encode(const uint8_t *, size_t, uint8_t *, size_t);
int	 zbase32_decode(const uint8_t *, uint8_t *, size_t);
int	 zbase32_encode(const uint8_t *, size_t, uint8_t *, size_t);

#endif /* _BASE32_H */
