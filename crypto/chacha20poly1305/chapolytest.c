/* ====================================================================
 * Copyright (c) 2011-2013 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/chacha20poly1305.h>

struct chacha_test {
    const char *noncehex;
    const char *outhex;
};

struct poly1305_test {
    const char *inputhex;
    const char *keyhex;
    const char *outhex;
};

static const struct chacha_test chacha_tests[] = {
    {
        "00000000000000000000000000000000""00000000000000000000000000000000"
        "00000000000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28""bdd219b8a08ded1aa836efcc8b770dc7"
        "da41597c5157488d7724e03fb8d84a37""6a43b8f41518a11cc387b669b2ee6586",
    },
    {
        "00000000000000000000000000000000""00000000000000000000000000000001"
        "00000000000000000000000000000000",
        "4540f05a9f1fb296d7736e7b208e3c96""eb4fe1834688d2604f450952ed432d41"
        "bbe2a0b6ea7566d2a5d1e7e20d42af2c""53d792b1c43fea817e9ad275ae546963",
    },
    {
        "00000000000000000000000000000000""00000000000000000000000000000000"
        "00000000000000000000000000000001",
        "de9cba7bf3d69ef5e786dc63973f653a""0b49e015adbff7134fcb7df137821031"
        "e85a050278a7084527214f73efc7fa5b""5277062eb7a0433e445f41e31afab757",
    },
    {
        "00000000000000000000000000000000""00000000000000000000000000000000"
        "00000000000000000100000000000000",
        "ef3fdfd6c61578fbf5cf35bd3dd33b80""09631634d21e42ac33960bd138e50d32"
        "111e4caf237ee53ca8ad6426194a8854""5ddc497a0b466e7d6bbdb0041b2f586b",
    },
    {
        "000102030405060708090a0b0c0d0e0f""101112131415161718191a1b1c1d1e1f"
        "00000000000000000001020304050607",
        "f798a189f195e66982105ffb640bb775""7f579da31602fc93ec01ac56f85ac3c1"
        "34a4547b733b46413042c94400491769""05d3be59ea1c53f15916155c2be8241a"
        "38008b9a26bc35941e2444177c8ade66""89de95264986d95889fb60e84629c9bd"
        "9a5acb1cc118be563eb9b3a4a472f82e""09a7e778492b562ef7130e88dfe031c7"
        "9db9d4f7c7a899151b9a475032b63fc3""85245fe054e3dd5a97a5f576fe064025"
        "d3ce042c566ab2c507b138db853e3d69""59660996546cc9c4a6eafdc777c040d7"
        "0eaf46f76dad3979e5c5360c3317166a""1c894c94a371876a94df7628fe4eaaf2"
        "ccb27d5aaae0ad7ad0f9d4b6ad3b5409""8746d4524d38407a6deb",
    },
};

static const struct poly1305_test poly1305_tests[] = {
    {
        "",
        "c8afaac331ee372cd6082de134943b17""4710130e9f6fea8d72293850a667d86c",
        "4710130e9f6fea8d72293850a667d86c",
    },
    {
        "48656c6c6f20776f726c6421",
        "746869732069732033322d6279746520""6b657920666f7220506f6c7931333035",
        "a6f745008f81c916a20dcc74eef2b2f0",
    },
    {
        "00000000000000000000000000000000""00000000000000000000000000000000",
        "746869732069732033322d6279746520""6b657920666f7220506f6c7931333035",
        "49ec78090e481ec6c26b33b91ccc0307",
    },
    {
        "43727970746f6772617068696320466f""72756d2052657365617263682047726f"
        "7570",
        "85d6be7857556d337f4452fe42d506a8""0103808afb0db2fd4abff6af4149f51b",
        "a8061dc1305136c6c22b8baf0c0127a9"
    },
    {
        "f3f6",
        "851fc40c3467ac0be05cc20404f3f700""580b3b0f9447bb1e69d095b5928b6dbc",
        "f4c633c3044fc145f84f335cb81953de"
    },
    {
        "",
        "a0f3080000f46400d0c7e9076c834403""dd3fab2251f11ac759f0887129cc2ee7",
        "dd3fab2251f11ac759f0887129cc2ee7"
    },
    {
        "663cea190ffb83d89593f3f476b6bc24""d7e679107ea26adb8caf6652d0656136",
        "48443d0bb0d21109c89a100b5ce2c208""83149c69b561dd88298a1798b10716ef",
        "0ee1c16bb73f0f4fd19881753c01cdbe"
    },
    {
        "ab0812724a7f1e342742cbed374d94d1""36c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67""fa83e158c994d961c4cb21095c1bf9",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "5154ad0d2cb26e01274fc51148491f1b"
    },
    /*
     * self-generated
     */
    {
        "ab0812724a7f1e342742cbed374d94d1""36c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67""fa83e158c994d961c4cb21095c1bf9af",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "812059a5da198637cac7c4a631bee466"
    },
    {
        "ab0812724a7f1e342742cbed374d94d1""36c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "5b88d7f6228b11e2e28579a5c0c1f761"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "bbb613b2b6d753ba07395b916aaece15"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "c794d7057d1778c4bbee0a39b3d97342"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "ffbcb9b371423152d7fca5ad042fbaa9"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
        "812059a5da198637cac7c4a631bee466",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "069ed6b8ef0f207b3e243bb1019fe632"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
        "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "cca339d9a45fa2368c2c68b3a4179133"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
        "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761"
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "53f6e828a2f0fe0ee815bf0bd5841a34"
    },
    {
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
        "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761"
        "ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0"
        "990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af"
        "48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef"
        "663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136"
        "812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761",
        "12976a08c4426d0ce8a82407c4f48207""80f8c20aa71202d1e29179cbcb555a57",
        "b846d44e9bbd53cedffbfbb6b7fa4933"
    },
    {
    /*
        * poly1305_ieee754.c failed this in final stage
        */
        "842364e156336c0998b933a6237726180d9e3fdcbde4cd5d17080fc3beb49614"
        "d7122c037463ff104d73f19c12704628d417c4c54a3fe30d3c3d7714382d43b0"
        "382a50a5dee54be844b076e8df88201a1cd43b90eb21643fa96f39b518aa8340"
        "c942ff3c31baf7c9bdbf0f31ae3fa096bf8c63030609829fe72e179824890bc8"
        "e08c315c1cce2a83144dbbff09f74e3efc770b54d0984a8f19b14719e6363564"
        "1d6b1eedf63efbf080e1783d32445412114c20de0b837a0dfa33d6b82825fff4"
        "4c9a70ea54ce47f07df698e6b03323b53079364a5fc3e9dd034392bdde86dccd"
        "da94321c5e44060489336cb65bf3989c36f7282c2f5d2b882c171e74",
        "95d5c005503e510d8cd0aa072c4a4d06""6eabc52d11653df47fbf63ab198bcc26",
        "f248312e578d9d58f8b7bb4d19105431"
    },
    /*
        * test vectors from Google
        */
    {
        "",
        "c8afaac331ee372cd6082de134943b17""4710130e9f6fea8d72293850a667d86c",
        "4710130e9f6fea8d72293850a667d86c",
    },
    {
        "48656c6c6f20776f726c6421",
        "746869732069732033322d6279746520""6b657920666f7220506f6c7931333035",
        "a6f745008f81c916a20dcc74eef2b2f0"
    },
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "746869732069732033322d6279746520""6b657920666f7220506f6c7931333035",
        "49ec78090e481ec6c26b33b91ccc0307"
    },
    /*
        * test vectors from Andrew Moon
        */
    {   /* nacl */
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        "e355a5",
        "eea6a7251c1e72916d11c2cb214d3c25""2539121d8e234e652d651fa4c8cff880",
        "f3ffc7703f9400e52a7dfb4b3d3305d9"
    },
    {   /* wrap 2^130-5 */
        "ffffffffffffffffffffffffffffffff",
        "02000000000000000000000000000000""00000000000000000000000000000000",
        "03000000000000000000000000000000"
    },
    {   /* wrap 2^128 */
        "02000000000000000000000000000000",
        "02000000000000000000000000000000""ffffffffffffffffffffffffffffffff",
        "03000000000000000000000000000000"
    },
    {   /* limb carry */
        "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff"
        "11000000000000000000000000000000",
        "01000000000000000000000000000000""00000000000000000000000000000000",
        "05000000000000000000000000000000"
    },
    {   /* 2^130-5 */
        "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe"
        "01010101010101010101010101010101",
        "01000000000000000000000000000000""00000000000000000000000000000000",
        "00000000000000000000000000000000"
    },
    {   /* 2^130-6 */
        "fdffffffffffffffffffffffffffffff",
        "02000000000000000000000000000000""00000000000000000000000000000000",
        "faffffffffffffffffffffffffffffff"
    },
    {   /* 5*H+L reduction intermediate */
        "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
        "0000000000000000000000000000000001000000000000000000000000000000",
        "01000000000000000400000000000000""00000000000000000000000000000000",
        "14000000000000005500000000000000"
    },
    {   /* 5*H+L reduction final */
        "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
        "00000000000000000000000000000000",
        "01000000000000000400000000000000""00000000000000000000000000000000",
        "13000000000000000000000000000000"
    }
};

static unsigned char hex_digit(char h)
{
    if (h >= '0' && h <= '9')
        return h - '0';
    else if (h >= 'a' && h <= 'f')
        return h - 'a' + 10;
    else if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;
    else
        abort();
}

static void hex_decode(unsigned char *out, const char* hex)
{
    size_t j = 0;

    while (*hex != 0) {
        unsigned char v = hex_digit(*hex++);
        v <<= 4;
        v |= hex_digit(*hex++);
        out[j++] = v;
    }
}

static void hexdump(unsigned char *a, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        printf("%02x", a[i]);
    }
}

/* misalign returns a pointer that points 0 to 15 bytes into |in| such that the
 * returned pointer has alignment 1 mod 16. */
static void* misalign(void* in)
{
    intptr_t x = (intptr_t) in;
    x += (17 - (x % 16)) % 16;
    return (void*) x;
}

int main()
{

    unsigned num_tests =
        sizeof(chacha_tests) / sizeof(struct chacha_test);
    unsigned i;
    unsigned char nonce_bytes[48 + 16] = {0};

    for (i = 0; i < num_tests; i++) {
        unsigned char *nonce = misalign(nonce_bytes);

        printf("ChaCha20 test #%d\n", i);
        const struct chacha_test *test = &chacha_tests[i];
        unsigned char *expected, *out_bytes, *zero_bytes, *out, *zeros;
        size_t len = strlen(test->outhex);

        if (strlen(test->noncehex) != 48*2 || (len & 1) == 1)
            return 1;

        len /= 2;

        hex_decode(nonce, test->noncehex);

        expected = malloc(len);
        out_bytes = malloc(len+16);
        zero_bytes = malloc(len+16);
        /* Attempt to test unaligned inputs. */
        out = misalign(out_bytes);
        zeros = misalign(zero_bytes);
        memset(zeros, 0, len);

        hex_decode(expected, test->outhex);
        CRYPTO_chacha_20(out, zeros, len, nonce);

        if (memcmp(out, expected, len) != 0) {
            printf("ChaCha20 test #%d failed.\n", i);
            printf("got:      ");
            hexdump(out, len);
            printf("\nexpected: ");
            hexdump(expected, len);
            printf("\n");
            return 1;
        }


        free(expected);
        free(zero_bytes);
        free(out_bytes);
    }

    num_tests =
        sizeof(poly1305_tests) / sizeof(struct poly1305_test);
    unsigned char key[32], out[16], expected[16];
    poly1305_state poly1305;

    for (i = 0; i < num_tests; i++) {
        printf("Poly1305 test #%d\n", i);
        const struct poly1305_test *test = &poly1305_tests[i];
        unsigned char *in;
        size_t inlen = strlen(test->inputhex);

        if (strlen(test->keyhex) != sizeof(key)*2 ||
            strlen(test->outhex) != sizeof(out)*2 ||
            (inlen & 1) == 1)
            return 1;

        inlen /= 2;

        hex_decode(key, test->keyhex);
        hex_decode(expected, test->outhex);

        in = malloc(inlen);

        hex_decode(in, test->inputhex);

#ifdef CHAPOLY_x86_64_ASM
        if((OPENSSL_ia32cap_loc()[1] >> 5) & 1) {
            poly1305_init_x64(&poly1305, key);
            poly1305_update_avx2(&poly1305, in, inlen);
            poly1305_finish_avx2(&poly1305, out);
        } else {
            poly1305_init_x64(&poly1305, key);
            poly1305_update_x64(&poly1305, in, inlen);
            poly1305_finish_x64(&poly1305, out);
        } 
#else
        {
            CRYPTO_poly1305_init(&poly1305, key);
            CRYPTO_poly1305_update(&poly1305, in, inlen);
            CRYPTO_poly1305_finish(&poly1305, out);
        }
#endif
        if (memcmp(out, expected, sizeof(expected)) != 0) {
            printf("Poly1305 test #%d failed.\n", i);
            printf("got:      ");
            hexdump(out, sizeof(out));
            printf("\nexpected: ");
            hexdump(expected, sizeof(expected));
            printf("\n");
            return 1;
        }

        free(in);
    }

    printf("PASS\n");
    return 0;
}

