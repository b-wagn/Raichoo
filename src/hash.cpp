#include "hash.hpp"
#include "parameters.hpp"
#include <openssl/sha.h>

void hash_mu(const unsigned char *messagedigest, const unsigned char *varphi,
		unsigned char *mu) {

	//concat a tag, messagedigest, and varphi
	size_t hashinput_len = 4 + SECPAR + SECPAR;
	unsigned char hashinput[hashinput_len] = "MU.H";
	memcpy(&hashinput[4], messagedigest, SECPAR);
	memcpy(&hashinput[4 + SECPAR], varphi, SECPAR);

	//hash using Sha256
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, hashinput, hashinput_len);
	SHA256_Final(mu, &sha256);
}

void hash_r(const unsigned char *rand, uint32_t L, unsigned char *com) {
	//concat a tag and rand (size of rand is (L+1)*secpar
	size_t hashinput_len = 4 + SECPAR + L * SECPAR;
	unsigned char hashinput[hashinput_len] = "RANH";
	memcpy(&hashinput[4], rand, SECPAR + L * SECPAR);

	//hash using Sha256
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, hashinput, hashinput_len);
	SHA256_Final(com, &sha256);
}

void hash_alpha(const unsigned char *gamma, uint32_t l, Fr &alpha) {
	//concat a tag, gamma, and l
	size_t hashinput_len = 4 + SECPAR + 4;
	unsigned char hashinput[hashinput_len] = "ALPH";
	memcpy(&hashinput[4], gamma, SECPAR);
	memcpy(&hashinput[4 + SECPAR], &l, 4);

	//hash using MCL
	alpha.setHashOf(hashinput, hashinput_len);
}

void hash_cc(const unsigned char *com, G1 *c, uint32_t L, uint32_t *J) {
	//concat a tag, com and c
	size_t size_G1 = 33;
	size_t hashinput_len = 4 + PAR_K * PAR_N * SECPAR + PAR_N * PAR_K * L * size_G1;
	unsigned char hashinput[hashinput_len] = "CC.H";
	memcpy(&hashinput[4], com, PAR_K * PAR_N * SECPAR);
	for (size_t i = 0; i < PAR_N * PAR_K * L; ++i) {
		int pos = 4 + PAR_K * PAR_N * SECPAR + i * size_G1;
		c[i].serialize(&hashinput[pos], size_G1);
	}

	//hash enough times using Sha256
	//It holds that SECPAR * CC_HASH_RUNS >= K
	unsigned char hash[SECPAR * CC_HASH_RUNS];
	for (char r = 0; r < CC_HASH_RUNS; ++r) {
		hashinput[2] = r;
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, hashinput, hashinput_len);
		SHA256_Final(&hash[r * SECPAR], &sha256);
	}
	//translate hash into J
	for (int i = 0; i < PAR_K; ++i) {
		hash[i] &= LOG_N_MASK; //map byte to the range 0...N-1
	}
	for (int i = 0; i < PAR_K; ++i) {
		J[i] = hash[i];
	}
}

void hash_bls(const unsigned char *mu, const unsigned char *info, G1 &hash) {

	//concat a tag, mu and info
	size_t hashinput_len = 4 + SECPAR + SECPAR;
	unsigned char hashinput[hashinput_len] = "BLSH";
	memcpy(&hashinput[4], mu, SECPAR);
	memcpy(&hashinput[4 + SECPAR], info, SECPAR);

	//hash using MCL
	hashAndMapToG1(hash, hashinput, hashinput_len);
}
