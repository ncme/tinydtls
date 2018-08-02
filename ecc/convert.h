/*
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
 * This is a efficient ECC implementation on the secp256r1 curve for 32 Bit CPU
 * architectures, modified to also support other short Weierstrass curves like Wei25519.
 * It provides basic operations on short Weierstrass curves and support
 * for ECDH and ECDSA.
 */
#include <stdint.h>

void twisted_edwards_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);
void short_weierstrass_to_twisted_edwards(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);
void short_weierstrass_to_montgomery(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);
void montgomery_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);