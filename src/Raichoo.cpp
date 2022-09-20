//============================================================================
// Name        : Raichoo.cpp
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Main file
//============================================================================

#include <iostream>
#include <chrono>

#include "parameters.hpp"
#include "context.hpp"
#include "hash.hpp"
#include "random.hpp"
#include "user.hpp"
#include "signer.hpp"
#include "gen.hpp"
#include "ver.hpp"

#define RUNS 100.0

void test_correctness() {

	context *ctx = create_context();

	unsigned char messagedigest[SECPAR];
	unsigned char info[SECPAR];
	memset(info, 0x01, SECPAR);

	// Key Generation
	secretkey sk;
	publickey pk;
	gen(ctx, &sk, &pk);

	user_state state;
	challenge chall;
	response resp;
	signature sig;

	//run RUNS signing interactions
	for (int run = 0; run < RUNS; ++run) {
		random_bytes(messagedigest, SECPAR);

		// Signing Protocol: User
		user_challenge(ctx, &pk, info, messagedigest, &state, &chall);

		// Signing Protocol: Signer
		assert(signer(ctx, &pk, &sk, info, &chall, &resp));

		// Signing Protocol: User
		assert(user_finalize(&state, &chall, &resp, sig));

		// Verification
		assert(ver(ctx, &pk, info, messagedigest, sig));
	}

	destroy_context(ctx);

}

void test_time() {

	std::cout << "N = " << PAR_N << ", K = " << PAR_K << std::endl;

	context *ctx = create_context();

	unsigned char messagedigest[SECPAR];
	unsigned char info[SECPAR];
	memset(info, 0x01, SECPAR);

	// Key Generation
	secretkey sk;
	publickey pk;
	gen(ctx, &sk, &pk);

	user_state state;
	challenge chall;
	response resp;
	signature sig;

	int duration_signing = 0;
	int duration_verification = 0;

	//run RUNS signing interactions
	for (int run = 0; run < RUNS; ++run) {
		random_bytes(messagedigest, SECPAR);

		auto start_sign = std::chrono::high_resolution_clock::now();
		// Signing Protocol: User
		user_challenge(ctx, &pk, info, messagedigest, &state, &chall);

		// Signing Protocol: Signer
		signer(ctx, &pk, &sk, info, &chall, &resp);

		// Signing Protocol: User
		user_finalize(&state, &chall, &resp, sig);

		auto stop_sign = std::chrono::high_resolution_clock::now();
		duration_signing +=
				std::chrono::duration_cast<std::chrono::milliseconds>(
						stop_sign - start_sign).count();

		// Verification
		auto start_ver = std::chrono::high_resolution_clock::now();
		ver(ctx, &pk, info, messagedigest, sig);
		auto stop_ver = std::chrono::high_resolution_clock::now();
		duration_verification += std::chrono::duration_cast<
				std::chrono::milliseconds>(stop_ver - start_ver).count();
	}
	duration_signing /= RUNS;
	std::cout << "Av. Time Signing [ms]: " << duration_signing << std::endl;
	duration_verification /= RUNS;
	std::cout << "Av. Time Verification [ms]: " << duration_verification
			<< std::endl;

	destroy_context(ctx);
}

int main() {
	//test_correctness();
	test_time();
}
