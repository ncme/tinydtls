/*
 * Copyright (c) 2009 Chris K Cockrum <ckc@cockrum.net>
 *
 * Copyright (c) 2013 Jens Trillmann <jtrillma@tzi.de>
 * Copyright (c) 2013 Marc Müller-Weinhardt <muewei@tzi.de>
 * Copyright (c) 2013 Lars Schmertmann <lars@tzi.de>
 * Copyright (c) 2013 Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright (c) 2018 Nikolas Rösener <nroesener@uni-bremen.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *
 * This implementation is based in part on the paper Implementation of an
 * Elliptic Curve Cryptosystem on an 8-bit Microcontroller [0] by
 * Chris K Cockrum <ckc@cockrum.net>.
 *
 * [0]: http://cockrum.net/Implementation_of_ECC_on_an_8-bit_microcontroller.pdf
 *
 * This is a efficient ECC implementation on the secp256r1 curve for 32 Bit CPU
 * architectures, modified to also support other short Weierstrass curves like Wei25519.
 * It provides basic operations on short Weierstrass curves and support
 * for ECDH and ECDSA.
 */
#include <inttypes.h>

#define keyLengthInBytes 32
#define arrayLength 8

typedef enum {
  SECP256R1,
  WEI25519,
  WEI25519_2
} ec_curve_t;

extern const uint32_t* ecc_param_a;		// domain parameter a
extern const uint32_t* ecc_prime_m;		// the prime modulus p
extern const uint32_t* ecc_prime_p;		// the prime modulus p with space for 2p
extern const uint32_t* ecc_prime_r;		// value for fast reduction < 2p
extern const uint32_t* ecc_order_m;		// the curve order
extern const uint32_t* ecc_order_r;		// value for fast reduction < 2n
extern const uint32_t* ecc_order_mu;	// static values mu for Barret Modular Reduction:
extern const uint32_t* ecc_prime_mu; 	// floor(base^(2*n) / modulus) with base = 2^32, words = 8
extern const uint32_t* ecc_g_point_x;	// x coordinate of the base point
extern const uint32_t* ecc_g_point_y;	// y coordinate of the base point

int ecc_ec_init(const ec_curve_t curve);

//ec Functions
void ecc_ec_mult(const uint32_t *px, const uint32_t *py, const uint32_t *secret, uint32_t *resultx, uint32_t *resulty);

static inline void ecc_ecdh(const uint32_t *px, const uint32_t *py, const uint32_t *secret, uint32_t *resultx, uint32_t *resulty) {
	ecc_ec_mult(px, py, secret, resultx, resulty);
}
int ecc_ecdsa_validate(const uint32_t *x, const uint32_t *y, const uint32_t *e, const uint32_t *r, const uint32_t *s);
int ecc_ecdsa_sign(const uint32_t *d, const uint32_t *e, const uint32_t *k, uint32_t *r, uint32_t *s);

int ecc_is_valid_key(const uint32_t * priv_key);
static inline void ecc_gen_pub_key(const uint32_t *priv_key, uint32_t *pub_x, uint32_t *pub_y)
{
	ecc_ec_mult(ecc_g_point_x, ecc_g_point_y, priv_key, pub_x, pub_y);
}

#ifdef TEST_INCLUDE
//ec Functions
void ecc_ec_add(const uint32_t *px, const uint32_t *py, const uint32_t *qx, const uint32_t *qy, uint32_t *Sx, uint32_t *Sy);
void ecc_ec_double(const uint32_t *px, const uint32_t *py, uint32_t *Dx, uint32_t *Dy);

//simple Functions for addition and substraction of big numbers
uint32_t ecc_add( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);
uint32_t ecc_sub( const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);

//field functions for big numbers
int ecc_fieldAdd(const uint32_t *x, const uint32_t *y, const uint32_t *reducer, uint32_t *result);
int ecc_fieldSub(const uint32_t *x, const uint32_t *y, const uint32_t *modulus, uint32_t *result);
int ecc_fieldMult(const uint32_t *x, const uint32_t *y, uint32_t *result, uint8_t length);
void ecc_fieldModP(uint32_t *A, const uint32_t *B);
void ecc_fieldModO(const uint32_t *A, uint32_t *result, uint8_t length);
void ecc_fieldInv(const uint32_t *A, const uint32_t *modulus, const uint32_t *reducer, uint32_t *B);

//simple functions to work with the big numbers
void ecc_copy(const uint32_t *from, uint32_t *to, uint8_t length);
int ecc_isSame(const uint32_t *A, const uint32_t *B, uint8_t length);
void ecc_setZero(uint32_t *A, const int length);
int ecc_isOne(const uint32_t* A);
void ecc_rshift(uint32_t* A);
int ecc_isGreater(const uint32_t *A, const uint32_t *B, uint8_t length);

#endif /* TEST_INCLUDE */
