/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Modifications for OpenBSD are copyright (c) 2016 Mike Belopuhov.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/stdint.h>

#include "aes.h"

#ifdef _KERNEL
#define enc32le(dst, v)		htolem32(dst, v)
#define dec32le(src)		lemtoh32(src)
#else
#define enc32le(dst, v)		*(uint32_t *)(dst) = htole32(v)
#define dec32le(src)		letoh32(*(uint32_t *)(src))
#endif

#ifndef __LP64__

#include "aes_ct.c"

int
AES_Setkey(AES_CTX *ctx, const uint8_t *key, int len, int enconly)
{
	ctx->num_rounds = aes_ct_keysched(ctx->ek, key, len);
	if (ctx->num_rounds == 0)
		return -1;
	aes_ct_skey_expand(ctx->ek_exp, ctx->num_rounds, ctx->ek);
	ctx->enc_only = enconly;
	if (!enconly) {
		if (aes_ct_keysched(ctx->dk, key, len) != ctx->num_rounds)
			return -1;
		aes_ct_skey_expand(ctx->dk_exp, ctx->num_rounds, ctx->dk);
	}
	return 0;
}

void
AES_Encrypt(AES_CTX *ctx, const uint8_t *src, uint8_t *dst)
{
	uint32_t q[8];

	q[1] = 0;
	q[3] = 0;
	q[5] = 0;
	q[7] = 0;
	q[0] = dec32le(src);
	q[2] = dec32le(src + 4);
	q[4] = dec32le(src + 8);
	q[6] = dec32le(src + 12);
	aes_ct_ortho(q);
	aes_ct_bitslice_encrypt(ctx->num_rounds, ctx->ek_exp, q);
	aes_ct_ortho(q);
	enc32le(dst, q[0]);
	enc32le(dst + 4, q[2]);
	enc32le(dst + 8, q[4]);
	enc32le(dst + 12, q[6]);
}

void
AES_Decrypt(AES_CTX *ctx, const uint8_t *src, uint8_t *dst)
{
	uint32_t q[8];

	q[0] = dec32le(src);
	q[2] = dec32le(src + 4);
	q[4] = dec32le(src + 8);
	q[6] = dec32le(src + 12);
	q[1] = 0;
	q[3] = 0;
	q[5] = 0;
	q[7] = 0;
	aes_ct_ortho(q);
	aes_ct_bitslice_decrypt(ctx->num_rounds, ctx->dk_exp, q);
	aes_ct_ortho(q);
	enc32le(dst, q[0]);
	enc32le(dst + 4, q[2]);
	enc32le(dst + 8, q[4]);
	enc32le(dst + 12, q[6]);
}

#else  /* __LP64__ */

#include "aes_ct64.c"

int
AES_Setkey(AES_CTX *ctx, const uint8_t *key, int len, int enconly)
{
	ctx->num_rounds = aes_ct64_keysched(ctx->ek, key, len);
	if (ctx->num_rounds == 0)
		return -1;
	aes_ct64_skey_expand(ctx->ek_exp, ctx->num_rounds, ctx->ek);
	ctx->enc_only = enconly;
	if (!enconly) {
		if (aes_ct64_keysched(ctx->dk, key, len) != ctx->num_rounds)
			return -1;
		aes_ct64_skey_expand(ctx->dk_exp, ctx->num_rounds, ctx->dk);
	}
	return 0;
}

void
AES_Encrypt(AES_CTX *ctx, const uint8_t *src, uint8_t *dst)
{
	uint64_t q[8];
	uint32_t w[4];

	w[0] = dec32le(src);
	w[1] = dec32le(src + 4);
	w[2] = dec32le(src + 8);
	w[3] = dec32le(src + 12);
	aes_ct64_interleave_in(&q[0], &q[4], w);
	aes_ct64_ortho(q);
	aes_ct64_bitslice_encrypt(ctx->num_rounds, ctx->ek_exp, q);
	aes_ct64_ortho(q);
	aes_ct64_interleave_out(w, q[0], q[4]);
	enc32le(dst, w[0]);
	enc32le(dst + 4, w[1]);
	enc32le(dst + 8, w[2]);
	enc32le(dst + 12, w[3]);
}

void
AES_Decrypt(AES_CTX *ctx, const uint8_t *src, uint8_t *dst)
{
	uint64_t q[8];
	uint32_t w[16];
	int i;

	memset(w, 0, sizeof(w));
	w[0] = dec32le(src);
	w[1] = dec32le(src + 4);
	w[2] = dec32le(src + 8);
	w[3] = dec32le(src + 12);
	for (i = 0; i < 4; i ++) {
		aes_ct64_interleave_in(
		    &q[i], &q[i + 4], w + (i << 2));
	}
	aes_ct64_ortho(q);
	aes_ct64_bitslice_decrypt(ctx->num_rounds, ctx->dk_exp, q);
	aes_ct64_ortho(q);
	for (i = 0; i < 4; i ++) {
		aes_ct64_interleave_out(
		    w + (i << 2), q[i], q[i + 4]);
	}
	enc32le(dst, w[0]);
	enc32le(dst + 4, w[1]);
	enc32le(dst + 8, w[2]);
	enc32le(dst + 12, w[3]);
}

#endif
