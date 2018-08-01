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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ecc.h"
#include "test_helper.h"

#ifdef CONTIKI
#include "contiki.h"
#else
#include <time.h>
#endif /* CONTIKI */

static const uint32_t *BasePointx, *BasePointy, *Sx, *Sy, *Tx, *Ty, *secret;
static const uint32_t *resultAddx, *resultAddy, *resultMultx, *resultMulty;
static const uint32_t *resultDoublex, *resultDoubley;
static const uint32_t *ecdsaTestRand1, *ecdsaTestRand2;

static const uint32_t *ecdsaTestMessage, *ecdsaTestSecret;
static const uint32_t *ecdsaTestresultR1, *ecdsaTestresultS1;
static const uint32_t *ecdsaTestresultR2, *ecdsaTestresultS2;

void addTest(){
	uint32_t tempx[8];
	uint32_t tempy[8];

	ecc_ec_add(Tx, Ty, Sx, Sy, tempx, tempy);
	assert(ecc_isSame(tempx, resultAddx, arrayLength));
	assert(ecc_isSame(tempy, resultAddy, arrayLength));
}

void doubleTest(){
	uint32_t tempx[8];
	uint32_t tempy[8];

	ecc_ec_double(Sx, Sy, tempx, tempy);
	assert(ecc_isSame(tempx, resultDoublex, arrayLength));
	assert(ecc_isSame(tempy, resultDoubley, arrayLength));
}

void multTest(){
	uint32_t tempx[8];
	uint32_t tempy[8];

	ecc_ec_mult(Sx, Sy, secret, tempx, tempy);
	assert(ecc_isSame(tempx, resultMultx, arrayLength));
	assert(ecc_isSame(tempy, resultMulty, arrayLength));
}

void eccdhTest(){
	uint32_t tempx[8];
	uint32_t tempy[8];
	uint32_t tempAx2[8];
	uint32_t tempAy2[8];
	uint32_t tempBx1[8];
	uint32_t tempBy1[8];
	uint32_t tempBx2[8];
	uint32_t tempBy2[8];
	uint32_t secretA[8];
	uint32_t secretB[8];
	ecc_setRandom(secretA);
	ecc_printNumber(secretA, 8);
	ecc_setRandom(secretB);
	ecc_printNumber(secretB, 8);
	ecc_ec_mult(BasePointx, BasePointy, secretA, tempx, tempy);
	ecc_ec_mult(BasePointx, BasePointy, secretB, tempBx1, tempBy1);
	//public key exchange
	ecc_ec_mult(tempBx1, tempBy1, secretA, tempAx2, tempAy2);
	ecc_ec_mult(tempx, tempy, secretB, tempBx2, tempBy2);
	assert(ecc_isSame(tempAx2, tempBx2, arrayLength));
	assert(ecc_isSame(tempAy2, tempBy2, arrayLength));

}

void ecdsaTest() {
	int ret __attribute__((unused));
	uint32_t tempx[9];
	uint32_t tempy[9];
	uint32_t pub_x[8];
	uint32_t pub_y[8];

	ecc_ec_mult(BasePointx, BasePointy, ecdsaTestSecret, pub_x, pub_y);

	ret = ecc_ecdsa_sign(ecdsaTestSecret, ecdsaTestMessage, ecdsaTestRand1, tempx, tempy);
	assert(ecc_isSame(tempx, ecdsaTestresultR1, arrayLength));
	assert(ecc_isSame(tempy, ecdsaTestresultS1, arrayLength));
	assert(ret == 0);

	ret = ecc_ecdsa_validate(pub_x, pub_y, ecdsaTestMessage, tempx, tempy);
	assert(!ret);


	ret = ecc_ecdsa_sign(ecdsaTestSecret, ecdsaTestMessage, ecdsaTestRand2, tempx, tempy);
	assert(ecc_isSame(tempx, ecdsaTestresultR2, arrayLength));
	assert(ecc_isSame(tempy, ecdsaTestresultS2, arrayLength));
	assert(ret == 0);

	ret = ecc_ecdsa_validate(pub_x, pub_y, ecdsaTestMessage, tempx, tempy);
	assert(!ret);
}

static void setup_p256() {
	//These are testvalues taken from the NIST P-256 definition
	//6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
	static const uint32_t P256_BasePointx[8] = {	0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
								0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2};

	//4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
	static const uint32_t P256_BasePointy[8] = {	0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
								0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2};

	//de2444be bc8d36e6 82edd27e 0f271508 617519b3 221a8fa0 b77cab39 89da97c9
	static const uint32_t P256_Sx[8] = {	0x89da97c9, 0xb77cab39, 0x221a8fa0, 0x617519b3,
						0x0f271508, 0x82edd27e, 0xbc8d36e6, 0xde2444be};

	//c093ae7f f36e5380 fc01a5aa d1e66659 702de80f 53cec576 b6350b24 3042a256
	static const uint32_t P256_Sy[8] = {	0x3042a256, 0xb6350b24, 0x53cec576, 0x702de80f,
						0xd1e66659, 0xfc01a5aa, 0xf36e5380, 0xc093ae7f};

	//55a8b00f 8da1d44e 62f6b3b2 5316212e 39540dc8 61c89575 bb8cf92e 35e0986b
	static const uint32_t P256_Tx[8] = {	0x35e0986b, 0xbb8cf92e, 0x61c89575, 0x39540dc8,
						0x5316212e, 0x62f6b3b2, 0x8da1d44e, 0x55a8b00f};

	//5421c320 9c2d6c70 4835d82a c4c3dd90 f61a8a52 598b9e7a b656e9d8 c8b24316
	static const uint32_t P256_Ty[8] = {	0xc8b24316, 0xb656e9d8, 0x598b9e7a, 0xf61a8a52,
						0xc4c3dd90, 0x4835d82a, 0x9c2d6c70, 0x5421c320};

	//c51e4753 afdec1e6 b6c6a5b9 92f43f8d d0c7a893 3072708b 6522468b 2ffb06fd
	static const uint32_t P256_secret[8] = {	0x2ffb06fd, 0x6522468b, 0x3072708b, 0xd0c7a893,
							0x92f43f8d, 0xb6c6a5b9, 0xafdec1e6, 0xc51e4753};

	//72b13dd4 354b6b81 745195e9 8cc5ba69 70349191 ac476bd4 553cf35a 545a067e
	static const uint32_t P256_resultAddx[8] = {	0x545a067e, 0x553cf35a, 0xac476bd4, 0x70349191,
								0x8cc5ba69, 0x745195e9, 0x354b6b81, 0x72b13dd4};

	//8d585cbb 2e1327d7 5241a8a1 22d7620d c33b1331 5aa5c9d4 6d013011 744ac264
	static const uint32_t P256_resultAddy[8] = {	0x744ac264, 0x6d013011, 0x5aa5c9d4, 0xc33b1331,
								0x22d7620d, 0x5241a8a1, 0x2e1327d7, 0x8d585cbb};

	//7669e690 1606ee3b a1a8eef1 e0024c33 df6c22f3 b17481b8 2a860ffc db6127b0
	//7669e690 1606ee3b a1a8eef1 e0024c33 df6c22f3 b17481b8 2a860ffc db6127b0
	static const uint32_t P256_resultDoublex[8] = {	0xdb6127b0, 0x2a860ffc, 0xb17481b8, 0xdf6c22f3,
									0xe0024c33, 0xa1a8eef1, 0x1606ee3b, 0x7669e690};

	//fa878162 187a54f6 c39f6ee0 072f33de 389ef3ee cd03023d e10ca2c1 db61d0c7
	//fa878162 187a54f6 c39f6ee0 072f33de 389ef3ee cd03023d e10ca2c1 db61d0c7
	static const uint32_t P256_resultDoubley[8] = {	0xdb61d0c7, 0xe10ca2c1, 0xcd03023d, 0x389ef3ee,
									0x072f33de, 0xc39f6ee0, 0x187a54f6, 0xfa878162};

	//51d08d5f 2d427888 2946d88d 83c97d11 e62becc3 cfc18bed acc89ba3 4eeca03f
	static const uint32_t P256_resultMultx[8] = {	0x4eeca03f, 0xacc89ba3, 0xcfc18bed, 0xe62becc3,
								0x83c97d11, 0x2946d88d, 0x2d427888, 0x51d08d5f};

	//75ee68eb 8bf626aa 5b673ab5 1f6e744e 06f8fcf8 a6c0cf30 35beca95 6a7b41d5
	static const uint32_t P256_resultMulty[8] = {	0x6a7b41d5, 0x35beca95, 0xa6c0cf30, 0x06f8fcf8,
								0x1f6e744e, 0x5b673ab5, 0x8bf626aa, 0x75ee68eb};

	static const uint32_t P256_ecdsaTestRand1[8] = { 0x1D1E1F20, 0x191A1B1C, 0x15161718, 0x11121314, 0x0D0E0F10, 0x090A0B0C, 0x05060708, 0x01020304};
	static const uint32_t P256_ecdsaTestRand2[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x01FFFFFF};
	static const uint32_t P256_ecdsaTestMessage[8] = { 0x65637572, 0x20612073, 0x68206F66, 0x20686173, 0x69732061, 0x68697320, 0x6F2C2054, 0x48616C6C};
	static const uint32_t P256_ecdsaTestSecret[8] = {0x94A949FA, 0x401455A1, 0xAD7294CA, 0x896A33BB, 0x7A80E714, 0x4321435B, 0x51247A14, 0x41C1CB6B};
	static const uint32_t P256_ecdsaTestresultR1[8] = { 0xC3B4035F, 0x515AD0A6, 0xBF375DCA, 0x0CC1E997, 0x7F54FDCD, 0x04D3FECA, 0xB9E396B9, 0x515C3D6E};
	static const uint32_t P256_ecdsaTestresultS1[8] = { 0x5366B1AB, 0x0F1DBF46, 0xB0C8D3C4, 0xDB755B6F, 0xB9BF9243, 0xE644A8BE, 0x55159A59, 0x6F9E52A6};
	static const uint32_t P256_ecdsaTestresultR2[8] = { 0x14146C91, 0xE878724D, 0xCD4FF928, 0xCC24BC04, 0xAC403390, 0x650C0060, 0x4A30B3F1, 0x9C69B726};
	static const uint32_t P256_ecdsaTestresultS2[8] = { 0x433AAB6F, 0x808250B1, 0xE46F90F4, 0xB342E972, 0x18B2F7E4, 0x2DB981A2, 0x6A288FA4, 0x41CF59DB};

	BasePointx = P256_BasePointx;
	BasePointy = P256_BasePointy;
	Sx = P256_Sx;
	Sy = P256_Sy;
	Tx = P256_Tx;
	Ty = P256_Ty;
	secret = P256_secret;
	resultAddx = P256_resultAddx;
	resultAddy = P256_resultAddy;
	resultMultx = P256_resultMultx;
	resultMulty = P256_resultMulty;
	resultDoublex = P256_resultDoublex;
	resultDoubley = P256_resultDoubley;
	ecdsaTestRand1 = P256_ecdsaTestRand1;
	ecdsaTestRand2 = P256_ecdsaTestRand2;
	ecdsaTestMessage = P256_ecdsaTestMessage;
	ecdsaTestSecret = P256_ecdsaTestSecret;
	ecdsaTestresultR1 = P256_ecdsaTestresultR1;
	ecdsaTestresultS1 = P256_ecdsaTestresultS1;
	ecdsaTestresultR2 = P256_ecdsaTestresultR2;
	ecdsaTestresultS2 = P256_ecdsaTestresultS2;

	ecc_ec_init(SECP256R1);
}

static void setup_wei25519() {
	static const uint32_t Wei_BasePointx[8] = {0xaaad245a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0x2aaaaaaa};
	static const uint32_t Wei_BasePointy[8] = {0x7eced3d9, 0x29e9c5a2, 0x6d7c61b2, 0x923d4d7e, 0x7748d14c, 0xe01edd2c, 0xb8a086b4, 0x20ae19a1};
	static const uint32_t Wei_Sx[8] = {0x89da97dc, 0xb77cab39, 0x221a8fa0, 0x617519b3, 0x0f271508, 0x82edd27e, 0xbc8d36e6, 0x6e2444be};
	static const uint32_t Wei_Sy[8] = {0xee46ee6c, 0x149a2fb7, 0x01023d03, 0x81614326, 0x3cdf4ed6, 0x74f2d107, 0xdb6e9765, 0x69febb92};
	static const uint32_t Wei_Tx[8] =  {0x35e0986b, 0xbb8cf92e, 0x61c89575, 0x39540dc8, 0x5316212e, 0x62f6b3b2, 0x8da1d44e, 0x45a8b00f};
	static const uint32_t Wei_Ty[8] =  {0xec3b96c4, 0x3c59e90d, 0x385b08e8, 0x9d714155, 0xe2d3aa8f, 0xeefe7ff4, 0x31d95c66, 0x0077fdd8};
	static const uint32_t Wei_secret[8] =  {0x2ffb06fd, 0x6522468b, 0x3072708b, 0xd0c7a893, 0x92f43f8d, 0xb6c6a5b9, 0xafdec1e6, 0xc51e4753};
	static const uint32_t Wei_resultAddx[8] =  {0x394990b7, 0xc2dba4af, 0x2e6c30af, 0x85991364, 0x77c4d54b, 0xf495531e, 0xcf66c20d, 0x5ef27008};
	static const uint32_t Wei_resultAddy[8] = {0x52659c1f, 0x16ba1933, 0xb8da2f89, 0x1e041ddd, 0xe88934d3, 0xdd305b90, 0xfd7337b4, 0x74d0e887};
	static const uint32_t Wei_resultMultx[8] =  {0x9b481f7c, 0x43c0fa6c, 0xf89ee066, 0x5ce92a71, 0x78f25b5a, 0xd55f3f84, 0xb4383ed2, 0x15a7472d};
	static const uint32_t Wei_resultMulty[8] =  {0x40174add, 0x315d8d15, 0x768e7f5e, 0x4d79de79, 0xd8b44b06, 0x75b652e5, 0x85c18350, 0x61b9776f};
	static const uint32_t Wei_resultDoublex[8] =  {0x914fb348, 0x073080ce, 0xae533d31, 0x79711b0d, 0x46f79276, 0xe1918857, 0x669da8b8, 0x2c52b6d3};
	static const uint32_t Wei_resultDoubley[8] = {0x66f53f61, 0x97901cb3, 0x9a710c6a, 0x5b1ac319, 0xa6e5623b, 0xe5810e05, 0x1fd2f18f, 0x03b6a30b};
	static const uint32_t Wei_ecdsaTestRand1[8] = { 0x1D1E1F20, 0x191A1B1C, 0x15161718, 0x11121314, 0x0D0E0F10, 0x090A0B0C, 0x05060708, 0x01020304};
	static const uint32_t Wei_ecdsaTestRand2[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x01FFFFFF};
	static const uint32_t Wei_ecdsaTestMessage[8] = {0x65637572, 0x20612073, 0x68206f66, 0x20686173, 0x69732061, 0x68697320, 0x6f2c2054, 0x08616c6c};
	static const uint32_t Wei_ecdsaTestSecret[8]  = {0x94a949fa, 0x401455a1, 0xad7294ca, 0x896a33bb, 0x7a80e714, 0x4321435b, 0x51247a14, 0x01c1cb6b};
	static const uint32_t Wei_ecdsaTestresultR1[] = {0x553ff581, 0x814b1dc9, 0xfa788368, 0xd5293cf5, 0x1b86154b, 0xd95ff3fc, 0x653d5588, 0x0c39aadf};
	static const uint32_t Wei_ecdsaTestresultS1[] = {0x9dd4075a, 0xa2989f56, 0x04b40155, 0xc3ff9248, 0xcf4d9228, 0x9801c1f0, 0xbfc7355c, 0x015677f4};
	static const uint32_t Wei_ecdsaTestresultR2[] = {0xf08f36bb, 0x3258841d, 0xa5c1cd42, 0x621c6d28, 0x881961eb, 0x7def309b, 0x34146a0f, 0x0380850d};
	static const uint32_t Wei_ecdsaTestresultS2[] = {0xf18ccc7e, 0x9ecb6380, 0x9d1a54fe, 0x09981c42, 0xabfde313, 0x438f57a1, 0x1ed286ed, 0x09faafd1};

	BasePointx = Wei_BasePointx;
	BasePointy = Wei_BasePointy;
	Sx = Wei_Sx;
	Sy = Wei_Sy;
	Tx = Wei_Tx;
	Ty = Wei_Ty;
	secret = Wei_secret;
	resultAddx = Wei_resultAddx;
	resultAddy = Wei_resultAddy;
	resultMultx = Wei_resultMultx;
	resultMulty = Wei_resultMulty;
	resultDoublex = Wei_resultDoublex;
	resultDoubley = Wei_resultDoubley;
	ecdsaTestRand1 = Wei_ecdsaTestRand1;
	ecdsaTestRand2 = Wei_ecdsaTestRand2;
	ecdsaTestMessage = Wei_ecdsaTestMessage;
	ecdsaTestSecret = Wei_ecdsaTestSecret;
	ecdsaTestresultR1 = Wei_ecdsaTestresultR1;
	ecdsaTestresultS1 = Wei_ecdsaTestresultS1;
	ecdsaTestresultR2 = Wei_ecdsaTestresultR2;
	ecdsaTestresultS2 = Wei_ecdsaTestresultS2;

	ecc_ec_init(WEI25519);
}

static void run_tests() {
	addTest();
	doubleTest();
	multTest();
	eccdhTest();
	ecdsaTest();
}

#ifdef CONTIKI
PROCESS(ecc_test, "ECC test");
AUTOSTART_PROCESSES(&ecc_test);
PROCESS_THREAD(ecc_test, ev, d)
{
	PROCESS_BEGIN();

	srand(1234);
	setup_p256();
	run_tests();
	printf("%s\n", "All P256 Tests successful.");

	setup_wei25519();
	run_tests();
	printf("%s\n", "All Wei2519 Tests successful.");

	PROCESS_END();
}
#else /* CONTIKI */
int main(int argc, char const *argv[])
{
	srand(time(NULL));
	setup_p256();
	run_tests();
	printf("%s\n", "All P256 Tests successful.");

	setup_wei25519();
	run_tests();
	printf("%s\n", "All Wei2519 Tests successful.");
	return 0;
}
#endif /* CONTIKI */
