/* ====================================================================
 * Copyright (c) 2001-2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CHACHA_POLY
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/chacha20poly1305.h>
#include "evp_locl.h"
#include <openssl/rand.h>

#define FILL_BUFFER ((size_t)128)

typedef struct {
    uint8_t        iv[12];
    uint8_t        nonce[48];
    size_t         aad_l;
    size_t         ct_l;
    unsigned       valid:1;
    unsigned       draft:1;
    uint8_t        poly_buffer[FILL_BUFFER];
    uint8_t        chacha_buffer[FILL_BUFFER];
    uint16_t       poly_buffer_used;
    uint16_t       chacha_used;
#ifdef CHAPOLY_x86_64_ASM
    void (*poly1305_init_ptr)(poly1305_state *, const uint8_t *);
    void (*poly1305_update_ptr)(poly1305_state *, const uint8_t *, size_t);
    void (*poly1305_finish_ptr)(poly1305_state *, uint8_t *);
    poly1305_state poly_state;
    #define poly_init aead_ctx->poly1305_init_ptr
    #define poly_update poly1305_update_wrapper
    #define poly_finish poly1305_finish_wrapper
#else
    #define poly_init CRYPTO_poly1305_init
    #define poly_update(c,i,l) CRYPTO_poly1305_update(&c->poly_state,i,l)
    #define poly_finish(c,m) CRYPTO_poly1305_finish(&c->poly_state,m)
#endif
} EVP_CHACHA20_POLY1305_CTX;


#ifdef CHAPOLY_x86_64_ASM
#include <immintrin.h>

static void poly1305_update_wrapper(EVP_CHACHA20_POLY1305_CTX *ctx,
                                    const uint8_t *in,
                                    size_t in_len)
{
    int todo;
    /* Attempt to fill as many bytes as possible before calling the update
       function */
    if (in_len < FILL_BUFFER || ctx->poly_buffer_used) {
        todo = FILL_BUFFER - ctx->poly_buffer_used;
        todo = in_len < todo? in_len : todo;
        memcpy(ctx->poly_buffer + ctx->poly_buffer_used, in, todo);
        ctx->poly_buffer_used += todo;
        in += todo;
        in_len -= todo;

        if (ctx->poly_buffer_used == FILL_BUFFER) {
            ctx->poly1305_update_ptr(&ctx->poly_state,
                                     ctx->poly_buffer,
                                     FILL_BUFFER);
            ctx->poly_buffer_used = 0;
        }
    }

    if (in_len >= FILL_BUFFER) {
        ctx->poly1305_update_ptr(&ctx->poly_state, in, in_len & (-FILL_BUFFER));
        in += in_len & (-FILL_BUFFER);
        in_len &= (FILL_BUFFER - 1);
    }

    if (in_len) {
        memcpy(ctx->poly_buffer, in, in_len);
        ctx->poly_buffer_used = in_len;
    }
}


static void poly1305_finish_wrapper(EVP_CHACHA20_POLY1305_CTX *ctx,
                                    uint8_t mac[POLY1305_MAC_LEN])
{
    if (ctx->poly_buffer_used) {

        if (ctx->poly_buffer_used % POLY1305_PAD_LEN) {
            memset(ctx->poly_buffer + ctx->poly_buffer_used, 0,
            POLY1305_PAD_LEN - (ctx->poly_buffer_used % POLY1305_PAD_LEN));
        }

        ctx->poly1305_update_ptr(&ctx->poly_state,
                                 ctx->poly_buffer,
                                 ctx->poly_buffer_used);
    }

    ctx->poly1305_finish_ptr(&ctx->poly_state, mac);
    memset(ctx->poly_buffer, 0, FILL_BUFFER);
}
#endif


#ifdef CHAPOLY_x86_64_ASM
static void EVP_chacha20_poly1305_cpuid(EVP_CHACHA20_POLY1305_CTX *ctx)
{
    if ((OPENSSL_ia32cap_loc()[1] >> 5) & 1) {          /* AVX2 */
        ctx->poly1305_init_ptr = poly1305_init_x64;     /* Lazy init */
        ctx->poly1305_update_ptr = poly1305_update_avx2;
        ctx->poly1305_finish_ptr = poly1305_finish_avx2;
/*
    } else if (0 && (OPENSSL_ia32cap_loc()[0] >> 60) & 1) {  // AVX -disabled
        ctx->poly1305_init_ptr = poly1305_init_avx;
        ctx->poly1305_update_ptr = poly1305_update_avx;
        ctx->poly1305_finish_ptr = poly1305_finish_avx;
*/
    } else {                                            /* x64 code */
        ctx->poly1305_init_ptr = poly1305_init_x64;
        ctx->poly1305_update_ptr = poly1305_update_x64;
        ctx->poly1305_finish_ptr = poly1305_finish_x64;
    }
}
#endif


static int EVP_chacha20_poly1305_init_draft(EVP_CIPHER_CTX *ctx,
                                            const unsigned char *key,
                                            const unsigned char *iv,
                                            int enc)
{
    EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
    memcpy(aead_ctx->nonce, key, 32);
    aead_ctx->valid = 0;
    aead_ctx->draft = 1;

#ifdef CHAPOLY_x86_64_ASM
    EVP_chacha20_poly1305_cpuid(aead_ctx);
#endif

    return 1;
}


static int EVP_chacha20_poly1305_init(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *key,
                                      const unsigned char *iv,
                                      int enc)
{
    EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
    memcpy(aead_ctx->nonce, key, 32);
    memcpy(aead_ctx->iv, iv, 12);
    aead_ctx->valid = 0;
    aead_ctx->draft = 0;

#ifdef CHAPOLY_x86_64_ASM
    EVP_chacha20_poly1305_cpuid(aead_ctx);
#endif

    return 1;
}


static int EVP_chacha20_poly1305_cipher(EVP_CIPHER_CTX *ctx,
                                        unsigned char *out,
                                        const unsigned char *in,
                                        size_t inl)
{
    EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
    uint8_t  poly_mac[POLY1305_MAC_LEN];
    uint8_t  zero[POLY1305_PAD_LEN] = {0};
    uint64_t cmp;
    int      i, todo;

    if (!aead_ctx->valid)
        return 0;

    if (inl < POLY1305_MAC_LEN)
        return -1;

    /* Fix for MAC */
    inl -= POLY1305_MAC_LEN;

    if (!ctx->encrypt) {
        poly_update(aead_ctx, in, inl);
    }

    i = 0;
    if (inl < 256) {
        /* Consume the buffer we computed during poly initialization */
        todo = inl > (FILL_BUFFER - aead_ctx->chacha_used) ?
               FILL_BUFFER - aead_ctx->chacha_used :
               inl;

#ifdef CHAPOLY_x86_64_ASM
        for (; i <= todo - 16; i+=16) {
            _mm_storeu_si128((__m128i*)&out[i],
                  _mm_xor_si128(_mm_loadu_si128((__m128i *)&in[i]),
                     _mm_loadu_si128((__m128i *)&aead_ctx->chacha_buffer[i + 64])));
        }
#endif
        for (; i < todo; i++) {
            out[i] = in[i] ^ aead_ctx->chacha_buffer[i + 64 /*aead_ctx->chacha_used*/];
        }

    } else {
        /* For long messages don't use precomputed buffer */
        ((uint64_t *)(aead_ctx->nonce))[4]--;
    }

    todo = inl - i;

    if (todo) {
        CRYPTO_chacha_20(&out[i], &in[i], todo, aead_ctx->nonce);
    }

    if (ctx->encrypt) {
        poly_update(aead_ctx, out, inl);
    }

    aead_ctx->ct_l += inl;

    if (!aead_ctx->draft) {
        /* For RFC padd ciphertext with zeroes, then mac len(aad)||len(ct) */
        todo = aead_ctx->ct_l % POLY1305_PAD_LEN ?
               POLY1305_PAD_LEN - (aead_ctx->ct_l % POLY1305_PAD_LEN) :
               0;

        if (todo) {
            poly_update(aead_ctx, zero, todo);
        }

        poly_update(aead_ctx, (uint8_t*)&aead_ctx->aad_l, sizeof(uint64_t));
        poly_update(aead_ctx, (uint8_t*)&aead_ctx->ct_l, sizeof(uint64_t));

    } else {
        /* For the draft don't pad, mac len(ct) */
        poly_update(aead_ctx, (uint8_t*)&aead_ctx->ct_l, sizeof(uint64_t));
    }
    aead_ctx->valid = 0;

    if (ctx->encrypt) {
        poly_finish(aead_ctx, &out[inl]);
        return inl + POLY1305_MAC_LEN;

    } else { /* Decryption */
        poly_finish(aead_ctx, poly_mac);
        /* Constant time comparison */
        cmp = (*(uint64_t *)(poly_mac)) ^ (*(uint64_t *)(in + inl));
        cmp |= (*(uint64_t *)(poly_mac + 8)) ^ (*(uint64_t *)(in + inl + 8));

        if (cmp) {
            OPENSSL_cleanse(out, inl);
            return -1;
        }

        return inl;
    }
}


static int EVP_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx)
{
    return 1;
}


static int EVP_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *ctx,
                                      int type,
                                      int arg,
                                      void *ptr)
{
    EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
    uint8_t        aad[EVP_AEAD_TLS1_AAD_LEN + 8];
    uint64_t       thirteen = EVP_AEAD_TLS1_AAD_LEN;

    switch (type) {
        case EVP_CTRL_AEAD_TLS1_AAD:

            if (arg != EVP_AEAD_TLS1_AAD_LEN)
                return 0;

            /* Initialize poly keys */
            memset(aead_ctx->chacha_buffer, 0, FILL_BUFFER);

            if (!aead_ctx->draft) {
                /* RFC IV = (0 || iv) ^ seq_num */
                memset(aead_ctx->nonce + 32, 0, 4);
                memcpy(aead_ctx->nonce + 36, aead_ctx->iv, 12);
                *(uint64_t *)(aead_ctx->nonce + 40) ^= *(uint64_t *)(ptr);

            } else {
                /* draft IV = 0 || seq_num */
                memset(aead_ctx->nonce + 32, 0, 8);
                memcpy(aead_ctx->nonce + 40, ptr, 8);
            }
            /* Poly keys = ENC(0) */
            CRYPTO_chacha_20(aead_ctx->chacha_buffer,
                             aead_ctx->chacha_buffer,
                             FILL_BUFFER,
                             aead_ctx->nonce);

            poly_init(&aead_ctx->poly_state, aead_ctx->chacha_buffer);

            aead_ctx->chacha_used = 64;
            aead_ctx->poly_buffer_used = 0;
            aead_ctx->aad_l = arg;
            aead_ctx->ct_l = 0;

            /* Absorb AAD */
            memcpy(aad, ptr, arg);
            memset(aad + arg, 0, sizeof(aad) - arg);

            /* If decrypting fix length for tag */
            if (!ctx->encrypt) {
                unsigned int len = (aad[arg-2] << 8) | aad[arg-1];
                len -= POLY1305_MAC_LEN;
                aad[arg-2] = len>>8;
                aad[arg-1] = len & 0xff;
            }

            if (!aead_ctx->draft) {
                /* In the RFC, AAD is padded with zeroes */
                poly_update(aead_ctx, aad, POLY1305_PAD_LEN);

            } else {
                /* In the draft AAD is followed by len(AAD) */
                memcpy(&aad[arg], &thirteen, sizeof(thirteen));
                poly_update(aead_ctx, aad, arg + sizeof(thirteen));
            }

            aead_ctx->valid = 1;
            return POLY1305_MAC_LEN;

            break;

        default:
            return 0;
            break;
    }

    return 0;
}


#define CUSTOM_FLAGS    (\
          EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
        | EVP_CIPH_ALWAYS_CALL_INIT  \
        | EVP_CIPH_CUSTOM_COPY)


static const EVP_CIPHER chacha20_poly1305_d = {
    0,    /* nid ??? */
    1,    /* block size, sorta */
    32,   /* key len */
    0,    /* iv len */
    CUSTOM_FLAGS|EVP_CIPH_FLAG_AEAD_CIPHER,    /* flags */
    EVP_chacha20_poly1305_init_draft,
    EVP_chacha20_poly1305_cipher,
    EVP_chacha20_poly1305_cleanup,
    sizeof(EVP_CHACHA20_POLY1305_CTX),         /* ctx size */
    NULL,
    NULL,
    EVP_chacha20_poly1305_ctrl,
    NULL
    };


static const EVP_CIPHER chacha20_poly1305 = {
    0,    /* nid ??? */
    1,    /* block size, sorta */
    32,   /* key len */
    12,   /* iv len */
    CUSTOM_FLAGS|EVP_CIPH_FLAG_AEAD_CIPHER,    /* flags */
    EVP_chacha20_poly1305_init,
    EVP_chacha20_poly1305_cipher,
    EVP_chacha20_poly1305_cleanup,
    sizeof(EVP_CHACHA20_POLY1305_CTX),         /* ctx size */
    NULL,
    NULL,
    EVP_chacha20_poly1305_ctrl,
    NULL
    };


const EVP_CIPHER *EVP_chacha20_poly1305_draft(void)
{ return &chacha20_poly1305_d; }


const EVP_CIPHER *EVP_chacha20_poly1305(void)
{ return &chacha20_poly1305; }
#endif
