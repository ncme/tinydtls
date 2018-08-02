#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ecc.h"
#include "convert.h"
#include "test_helper.h"

#ifdef WITH_C25519
#include "c25519.h"
#include "f25519.h"
#include "morph25519.h"
#include "ed25519.h"
#endif

#ifdef CONTIKI
#include "contiki.h"
#else
#include <time.h>
#endif /* CONTIKI */

/* Config */

#define TESTCYCLES 64

/* Constans */

static const uint32_t ed25519_Gx[8] = {0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760, 0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3};
static const uint32_t ed25519_Gy[8] = {0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666};

/* Functions */

static void eccdhTest(const uint32_t* secretA, const uint32_t* secretB, uint32_t* pub){
	uint32_t tempx[8];
	uint32_t tempy[8];
	uint32_t tempAx2[8];
	uint32_t tempAy2[8];
	uint32_t tempBx1[8];
	uint32_t tempBy1[8];
	uint32_t tempBx2[8];
	uint32_t tempBy2[8];
	uint32_t BasePointx[8];
	uint32_t BasePointy[8];
	uint32_t ed25519_QAx[8];
	uint32_t ed25519_QAy[8];
	uint32_t ed25519_QBx[8];
	uint32_t ed25519_QBy[8];
	uint32_t ed25519_Axk[8];
	uint32_t ed25519_Ayk[8];
	uint32_t ed25519_Bxk[8];
	uint32_t ed25519_Byk[8];

	twisted_edwards_to_short_weierstrass(ed25519_Gx, ed25519_Gy, BasePointx, BasePointy);
	const uint32_t wei25519_Gx[8] = {0xaaad245a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0x2aaaaaaa};
	const uint32_t wei25519_Gy[8] = {0x7eced3d9, 0x29e9c5a2, 0x6d7c61b2, 0x923d4d7e, 0x7748d14c, 0xe01edd2c, 0xb8a086b4, 0x20ae19a1};

	assert(ecc_isSame(BasePointx, wei25519_Gx, arrayLength));
	assert(ecc_isSame(BasePointy, wei25519_Gy, arrayLength));

	ecc_ec_mult(BasePointx, BasePointy, secretA, tempx, tempy); 	// Alice: Q_A
	ecc_ec_mult(BasePointx, BasePointy, secretB, tempBx1, tempBy1); // Bob: Q_B

	short_weierstrass_to_twisted_edwards(tempx, tempy, ed25519_QAx, ed25519_QAy);
	short_weierstrass_to_twisted_edwards(tempBx1, tempBy1, ed25519_QBx, ed25519_QBy);

	//public key exchange: Q_A to Bob, Q_B to Alice

	twisted_edwards_to_short_weierstrass(ed25519_QAx, ed25519_QAy, tempx, tempy);
	twisted_edwards_to_short_weierstrass(ed25519_QBx, ed25519_QBy, tempBx1, tempBy1);

	ecc_ec_mult(tempBx1, tempBy1, secretA, tempAx2, tempAy2); // Alice: (x_k,y_k) = d_A * Q_B
	ecc_ec_mult(tempx, tempy, secretB, tempBx2, tempBy2); // Bob: (x_k, y_k) = d_B * Q_A

	assert(ecc_isSame(tempAx2, tempBx2, arrayLength));
	assert(ecc_isSame(tempAy2, tempBy2, arrayLength));

	short_weierstrass_to_twisted_edwards(tempAx2, tempAy2, ed25519_Axk, ed25519_Ayk);
	short_weierstrass_to_twisted_edwards(tempBx2, tempBy2, ed25519_Bxk, ed25519_Byk);
	assert(ecc_isSame(ed25519_Axk, ed25519_Bxk, arrayLength));
	assert(ecc_isSame(ed25519_Ayk, ed25519_Byk, arrayLength));
	ecc_copy(tempAx2, pub, arrayLength);
}

#ifdef WITH_C25519
#define NUM_WORDS 8
#define NUM_BYTES 32
#define NUM_DIGITS 256

void print8(const uint8_t *x){ //here the values are turned to MSB!
	int n;

	for(n = NUM_BYTES - 1; n >= 0; n--){
		printf("%02x", x[n]);
	}
	printf("\n");
}


void words_to_bytes(uint8_t *r, const uint32_t *x) {
	int i;
	for(i = NUM_WORDS - 1; i >= 0; i--) {
		r[(4*i)+0] = (uint8_t) (x[i] >> 0)  & 0xFF;
		r[(4*i)+1] = (uint8_t) (x[i] >> 8)  & 0xFF;
		r[(4*i)+2] = (uint8_t) (x[i] >> 16) & 0xFF;
		r[(4*i)+3] = (uint8_t) (x[i] >> 24) & 0xFF;
	}
}

void bytes_to_words(uint32_t *r, const uint8_t *x) {
	int i;
	for(i = NUM_WORDS - 1; i >= 0; i--) {
		r[i]  = (x[(4*i)+0] << 0)  & 0x000000FF;
		r[i] += (x[(4*i)+1] << 8)  & 0x0000FF00;
		r[i] += (x[(4*i)+2] << 16) & 0x00FF0000;
		r[i] += (x[(4*i)+3] << 24) & 0xFF000000;
	}
}

void test_c25519(const uint32_t* secretA, const uint32_t* secretB, uint32_t* res) {


	uint8_t e1[C25519_EXPONENT_SIZE];
	uint8_t e2[C25519_EXPONENT_SIZE];
	struct ed25519_pt q1;
	struct ed25519_pt q2;
	struct ed25519_pt r1;
	struct ed25519_pt r2;
	uint8_t x1[32], x2[32], y1[32], y2[32];
	uint8_t weiAx2[NUM_BYTES];
	uint8_t weiAy2[NUM_BYTES];
	uint8_t weiBx2[NUM_BYTES];
	uint8_t weiBy2[NUM_BYTES];
	uint32_t tempAx2[8];
	uint32_t tempAy2[8];
	uint32_t tempBx2[8];
	uint32_t tempBy2[8];


	words_to_bytes(e1, secretA);
	words_to_bytes(e2, secretB);

	/* Create private keys */
	c25519_prepare(e1);
	c25519_prepare(e2);

	// START OF BENCHMARK
	long long cycles = cpucycles();

	/* Create public keys */
	ed25519_smult(&q1, &ed25519_base, e1);
	ed25519_smult(&q2, &ed25519_base, e2);

	/* Diffie-Hellman exchange */
	ed25519_smult(&r1, &q2, e1);
	ed25519_smult(&r2, &q1, e2);

	ed25519_unproject(x1, y1, &r1);
	ed25519_unproject(x2, y2, &r2);


	morph25519_e2w(weiAx2, weiAy2, x1, y1);
	morph25519_e2w(weiBx2, weiBy2, x2, y2);


	bytes_to_words(tempAx2, weiAx2);
	bytes_to_words(tempBx2, weiBx2);

	print_array(tempAx2,8);
	print_array(tempBx2,8);

	assert(ecc_isSame(tempAx2, tempBx2, arrayLength));
	ecc_copy(tempAx2, res, arrayLength);
}
#endif /* WITH_C25519 */

static void run_tests() {
	uint32_t secretA[arrayLength];
	uint32_t secretB[arrayLength];
	uint32_t res1[arrayLength];
	eccdhTest(secretA, secretB, res1);

	#ifdef WITH_C25519
	uint32_t res2[arrayLength];
	uint32_t ssA[NUM_WORDS], secretA[NUM_WORDS];
	uint32_t ssB[NUM_WORDS], secretB[NUM_WORDS];
	uint8_t tmp1[NUM_BYTES], tmp2[NUM_BYTES];
	ecc_setRandom(ssA); // Alice: d_A
	ecc_setRandom(ssB); // Bob: d_B

	words_to_bytes(tmp1, ssA);
	words_to_bytes(tmp2, ssB);
	c25519_prepare(tmp1);
	c25519_prepare(tmp2);
	bytes_to_words(secretA, tmp1);
	bytes_to_words(secretB, tmp2);

	test_c25519(secretA, secretB, res2);

	assert(ecc_isSame(res1, res2, arrayLength));
	#endif
}

#ifdef CONTIKI
PROCESS(ecc_test, "ECC test");
AUTOSTART_PROCESSES(&ecc_test);
PROCESS_THREAD(ecc_test, ev, d)
{
	PROCESS_BEGIN();

	srand(1234);
	ecc_ec_init(WEI25519);
	int i;
	for(i = 0; i < TESTCYCLES; i++) {
		run_tests();
	}
	printf("%s\n", "All Tests successful.");

	PROCESS_END();
}
#else /* CONTIKI */

int main(int argc, char const *argv[])
{
	ecc_ec_init(WEI25519);
	srand(time(NULL));
	int i;
	for(i = 0; i < TESTCYCLES; i++) {
		run_tests();
	}

	printf("%s\n", "All Tests successful.");
	return 0;
}
#endif /* CONTIKI */
