/*
 * Copyright (c) 2016 Mike Belopuhov
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

#ifndef _AES_H_
#define _AES_H_

#define AES_MAXKEYBITS	(256)
#define AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)

typedef struct aes_ctx {
#ifndef __LP64__
	uint32_t ek[60];
	uint32_t dk[60];
	uint32_t ek_exp[120];
	uint32_t dk_exp[120];
#else
	uint64_t ek[30];
	uint64_t dk[30];
	uint64_t ek_exp[120];
	uint64_t dk_exp[120];
#endif
	unsigned num_rounds;
	int enc_only;
} AES_CTX;

int	AES_Setkey(AES_CTX *, const uint8_t *, int, int);
void	AES_Encrypt(AES_CTX *, const uint8_t *, uint8_t *);
void	AES_Decrypt(AES_CTX *, const uint8_t *, uint8_t *);

#endif	/* _AES_H_ */
