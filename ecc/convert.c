/*
 * ecc_copyright (c) 2018 Nikolas Rösener <nroesener@uni-bremen.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a ecc_copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, ecc_copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above ecc_copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR ecc_copyRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This is a efficient ECC implementation on the secp256r1 curve for 32 Bit CPU
 * architectures, modified to also support other short Weierstrass curves like Wei25519.
 * It provides basic operations on short Weierstrass curves and support
 * for ECDH and ECDSA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "ecc.h"

#ifndef TEST_INCLUDE
    #define TEST_INCLUDE 1
#endif

static int ecc_isZero(const uint32_t* A){
	uint8_t n, r=0;
	for(n=0;n<8;n++){
		if (A[n] == 0) r++;
	}
	return r==8;
}

/* Constants */

static const uint32_t A[8] = {0x00076d06, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
static const uint32_t A_3[8] = {0x000279ac, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
static const uint32_t delta[8] = {0xaaad2451, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0x2aaaaaaa};
static const uint32_t c[8] = {0x00ba81e7, 0x3391fb55, 0xb482e57d, 0x3a5e2c2e, 0xfc03b081, 0x2d84f723, 0x9f5ff944, 0x70d9120b};
static const uint32_t minus_one[8] = {0xffffffec, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff};

/* Conversions */

void twisted_edwards_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    if(ecc_isZero(px))  {
        if(ecc_isZero(py)) {
            printf("ED->WEI: Special Case: 0");
            ecc_setZero(rx, arrayLength);
            ecc_setZero(ry, arrayLength);
            return;
        }
        if(ecc_isSame(py, minus_one, arrayLength)) {
            printf("ED->WEI: Special Case: (0,-1)");
            ecc_copy(A_3, rx, arrayLength);
            ecc_setZero(ry, arrayLength);
            return;
        }
    }

    /*
        The following code calculates:
        rx = (1 + py) / ((1 - py) + delta)   (mod p)
        ry = (c * (1 + py)) / (1 - py) * px  (mod p)
    */

    uint32_t nom[8];    // nominator
    uint32_t den[8];    // denominator
    uint32_t tmp[8];    // temporary
    uint32_t tmp2[8];
    uint32_t mul[16];   // multiplication result

    ecc_setZero(tmp, arrayLength);
    tmp[0] = 0x00000001;                            // tmp = 1

    ecc_fieldAdd(tmp, py, ecc_prime_r, nom);            // nom = 1 + py
    ecc_fieldSub(tmp, py, ecc_prime_m, tmp2);           // tmp2 = 1 - py
    ecc_fieldInv(tmp2, ecc_prime_m, ecc_prime_r, den);  // den = (1 - py)^-1
    ecc_fieldMult(nom, den, mul, arrayLength);          // mul = (1 + py) * (1 - py)^-1
    ecc_fieldModP(tmp, mul);                            // tmp = (1 + py) * (1 - py)^-1  (mod p)
    ecc_setZero(mul, 16);
    ecc_fieldAdd(tmp, delta, ecc_prime_r, mul);         // mul = ((1 + py) * (1 - py)^-1) + delta
    ecc_fieldModP(rx,mul);                              // rx  = ((1 + py) * (1 - py)^-1) + delta (mod p)

    ecc_fieldMult(tmp2, px, mul, arrayLength);          // mul = (1 - py) * px
    ecc_fieldModP(tmp, mul);                            // tmp = (1 - py) * px (mod p)
    ecc_fieldMult(c, nom, mul, arrayLength);            // mul =  c * (1 + py)
    ecc_fieldModP(nom, mul);                            // nom = (c * (1 + py)) (mod p)
    ecc_fieldInv(tmp, ecc_prime_m, ecc_prime_r, den);   // den = ((1 - py) * px)^-1 (mod p)
    ecc_fieldMult(nom, den, mul, arrayLength);          // mul = (c * (1 + py)) * ((1 - py) * px)^-1
    ecc_fieldModP(ry, mul);                             // ry  = (c * (1 + py)) * ((1 - py) * px)^-1  (mod p)
}

void short_weierstrass_to_twisted_edwards(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    if(ecc_isZero(py))  {
        if(ecc_isZero(px)) {
            printf("WEI->ED: Special Case: 0");
            ecc_setZero(rx, arrayLength);
            ecc_setZero(ry, arrayLength);
            return;
        }
        if(ecc_isSame(px, A_3, arrayLength)) {
            printf("WEI->ED: Special Case: (0,delta)");
            ecc_setZero(rx, arrayLength);
            ecc_copy(minus_one, ry, arrayLength);
            return;
        }
    }

    /*
        The following code calculates:
        pa = 3 * p.x - A
        rx = (c * pa) / (3 * py)
        ry = (pa - 3) / (pa + 3)
    */

   static const uint32_t three[8] = {0x00000003, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};

    uint32_t pa[8];  // intermediate result
    uint32_t nom[8]; // nominator
    uint32_t den[8]; // denominator
    uint32_t tmp[8]; // temporary
    uint32_t mul[16];// multiplication result

    ecc_fieldMult(three, py, mul, arrayLength);         // mul = 3 * py
    ecc_fieldModP(tmp, mul);                            // tmp = 3 * py (mod p)
    ecc_fieldInv(tmp, ecc_prime_m, ecc_prime_r, den);   //den = (3 * py)^-1

    ecc_fieldMult(three, px, mul, arrayLength);         // mul = 3 * p.x
    ecc_fieldModP(tmp, mul);                            // tmp = 3 * px (mod p)
    ecc_fieldSub(tmp, A, ecc_prime_m, pa);              // pa  = 3 * px - A

    ecc_fieldMult(c, pa, mul, arrayLength);             // mul = c * pa
    ecc_fieldModP(nom, mul);                            // nom = c * pa (mod p)

    ecc_fieldMult(nom, den, mul, arrayLength);          // mul = (c * pa) * (3 * py)^-1
    ecc_fieldModP(rx, mul);                             // rx  = (c * pa) * (3 * py)^-1 (mod p)

    ecc_fieldSub(pa, three, ecc_prime_m, nom);          // nom = pa - 3
    ecc_fieldAdd(pa, three, ecc_prime_r, den);          // den = pa + 3
    ecc_fieldInv(den, ecc_prime_m, ecc_prime_r, tmp);   //tmp = (pa + 3)^-1
    ecc_fieldMult(nom, tmp, mul, arrayLength);          // mul = (pa - 3) * (pa + 3)^-1
    ecc_fieldModP(ry, mul);                             // ry  = (pa - 3) * (pa + 3)^-1 (mod p)
}

void short_weierstrass_to_montgomery(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    ecc_copy(py, ry, arrayLength);
    if(ecc_isZero(px) && ecc_isZero(py)) {
        ecc_copy(px, rx, arrayLength);
        return;
    }

    /*
        The following code calculates:
        (px,py) == ((px - A/3),py)
    */
    uint32_t tmp[arrayLength];
    ecc_fieldSub(px, delta, ecc_prime_m, tmp);
    ecc_fieldModP(rx, tmp);
}

void montgomery_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    ecc_copy(py, ry, arrayLength);
    if(ecc_isZero(px) && ecc_isZero(py)) {
        ecc_copy(px, rx, arrayLength);
        return;
    }

    /*
        The following code calculates:
        (px,py) == ((px + A/3),py)
    */
    uint32_t tmp[arrayLength];
    ecc_fieldAdd(px, delta, ecc_prime_r, tmp);
    ecc_fieldModP(rx, tmp);
}