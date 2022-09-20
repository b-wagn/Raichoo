#include "user.hpp"
#include "hash.hpp"
#include "random.hpp"

/**
 * pk_sharing: K-1 elements
 */
void inline key_rerandomization(const context *ctx, publickey *pk_sharing,
		G1 *h, G1 agg_sig, publickey *pk_sharing_new, G1 &agg_sig_new) {

	//sample a random sharing of zero
	Fr sharing_offsets[PAR_K];
	sharing_offsets[0].setRand();
	sharing_offsets[PAR_K - 1] = sharing_offsets[0];
	for (int i = 1; i < PAR_K - 1; ++i) {
		sharing_offsets[i].setRand();
		Fr::add(sharing_offsets[PAR_K - 1], sharing_offsets[PAR_K - 1],
				sharing_offsets[i]);

	}
	Fr::neg(sharing_offsets[PAR_K - 1], sharing_offsets[PAR_K - 1]);

	//shift the public key shares
	G1 tmp1;
	G2 tmp2;
	for (int i = 0; i < PAR_K - 1; ++i) {
		G1::mul(tmp1, ctx->g1, sharing_offsets[i]);
		G1::add(pk_sharing_new[i].pk1, pk_sharing[i].pk1, tmp1);
		G2::mul(tmp2, ctx->g2, sharing_offsets[i]);
		G2::add(pk_sharing_new[i].pk2, pk_sharing[i].pk2, tmp2);
	}

	//shift agg sig
	G1 shift;
	G1::mulVec(shift, h, sharing_offsets, PAR_K);
	G1::add(agg_sig_new, agg_sig, shift);

}

void user_challenge(const context *ctx, const publickey *pk,
		const unsigned char *info, const unsigned char *messagedigest,
		user_state *state, challenge *chall) {

	// save pk and ctx for later
	state->pk = pk;
	state->ctx = ctx;

	// some tmp element for computation
	G1 g1alpha;

	unsigned char rand[PAR_K * PAR_N * 2 * SECPAR];
	unsigned char com[PAR_K * PAR_N * SECPAR];

	// prepare mu's, alpha's, com's, c's
	// for every instance and every session
	for (int i = 0; i < PAR_K; ++i) {
		for (int j = 0; j < PAR_N; ++j) {
			int idx = i * PAR_N + j;
			// sample varphi_{i,j}
			random_bytes(&state->varphis[idx * SECPAR], SECPAR);

			// compute mu_{i,j}
			hash_mu(messagedigest, &state->varphis[idx * SECPAR],
					&rand[idx * 2 * SECPAR]);
			//sample gamma_{i,j} next to it
			random_bytes(&rand[idx * 2 * SECPAR + SECPAR], SECPAR);

			// compute com_{i,j}
			hash_r(&rand[idx * 2 * SECPAR], 1, &com[idx * SECPAR]);

			// compute alpha_{i,j}
			hash_alpha(&rand[idx * 2 * SECPAR + SECPAR], 0, state->alphas[idx]);

			// compute c_{i,j}
			hash_bls(&rand[idx * 2 * SECPAR], info, state->mu_hashes[idx]);
			G1::mul(g1alpha, ctx->g1, state->alphas[idx]);
			G1::add(state->c[idx], state->mu_hashes[idx], g1alpha);
		}
	}

	// hash to get the CC vector J
	hash_cc(com, state->c, 1, chall->J);

	// construct the challenge/opening and the user state
	for (int i = 0; i < PAR_K; ++i) {
		int Ji = chall->J[i];
		int idx = i * PAR_N + Ji;
		//include c_{i,J_i} and com_{i,J_i}
		chall->c[i] = state->c[idx];
		memcpy(&chall->com[i * SECPAR], &com[idx * SECPAR], SECPAR);

		//include all rands except the J_i-th one
		memcpy(&chall->rand[i * (PAR_N - 1) * 2 * SECPAR],
				&rand[i * PAR_N * 2 * SECPAR], Ji * 2 * SECPAR);
		memcpy(&chall->rand[i * (PAR_N - 1) * 2 * SECPAR + Ji * 2 * SECPAR],
				&rand[(i * PAR_N + Ji + 1) * 2 * SECPAR],
				(PAR_N - 1 - Ji) * 2 * SECPAR);
	}

}

bool user_finalize(user_state *state, challenge *chall, response *resp,
		signature &sig) {

// Step 1: Recompute final component pk_K of the sharing
	G1 pk_sharing_G1[PAR_K];
	G2 pk_sharing_G2[PAR_K + 1]; //one more element to make Step 3 efficient
	G1 sum_G1;
	G2 sum_G2;
	pk_sharing_G1[0] = resp->pk_sharing[0].pk1;
	pk_sharing_G2[0] = resp->pk_sharing[0].pk2;
	sum_G1 = pk_sharing_G1[0];
	sum_G2 = pk_sharing_G2[0];
	for (int i = 1; i < PAR_K - 1; ++i) {
		pk_sharing_G1[i] = resp->pk_sharing[i].pk1;
		pk_sharing_G2[i] = resp->pk_sharing[i].pk2;
		G1::add(sum_G1, sum_G1, pk_sharing_G1[i]);
		G2::add(sum_G2, sum_G2, pk_sharing_G2[i]);
	}
	G1::neg(sum_G1, sum_G1);
	G1::add(pk_sharing_G1[PAR_K - 1], state->pk->pk1, sum_G1);
	G2::neg(sum_G2, sum_G2);
	G2::add(pk_sharing_G2[PAR_K - 1], state->pk->pk2, sum_G2);

// Step 2: Check validity of the sharing
	bool consistent = true;
	GT tmp;
	G1 left[2];
	G2 right[2];
	G1::neg(left[1], state->ctx->g1);
	right[0] = state->ctx->g2;
	for (int i = 0; i < PAR_K; ++i) {
		//check that e(pk_i,1,g_2) = e(g_1,pk_i,2)
		left[0] = pk_sharing_G1[i];
		right[1] = pk_sharing_G2[i];
		millerLoopVec(tmp, left, right, 2);
		finalExp(tmp, tmp);
		consistent &= tmp.isOne();
	}
	if (!consistent) {
		return false;
	}

// Step 3: Check correctness of the aggregated response
	G1 cs_and_add_resp[PAR_K + 1];
	G1::neg(cs_and_add_resp[PAR_K], resp->agg_resp);
	pk_sharing_G2[PAR_K] = state->ctx->g2;
	for (int i = 0; i < PAR_K; ++i) {
		cs_and_add_resp[i] = chall->c[i];
	}
	millerLoopVec(tmp, cs_and_add_resp, pk_sharing_G2, PAR_K + 1);
	finalExp(tmp, tmp);
	if (!tmp.isOne()) {
		return false;
	}

// Step 4: Unblind the aggregated response
	G1 agg_sig;
	G1 shift;
	Fr neg_alphas[PAR_K];
	for (int i = 0; i < PAR_K; ++i) {
		int Ji = chall->J[i];
		int idx = i * PAR_N + Ji;
		Fr::neg(neg_alphas[i], state->alphas[idx]);
	}
	G1::mulVec(shift, pk_sharing_G1, neg_alphas, PAR_K);
	G1::add(agg_sig, resp->agg_resp, shift);
// Rerandomize the key sharing
	G1 selected_mu_hashes[PAR_K];
	for (int i = 0; i < PAR_K; ++i) {
		int Ji = chall->J[i];
		int idx = i * PAR_N + Ji;
		selected_mu_hashes[i] = state->mu_hashes[idx];
	}
	key_rerandomization(state->ctx, resp->pk_sharing, selected_mu_hashes,
			agg_sig, sig.pk_sharing, sig.agg_sig);

// Step 5: add the commitment randomness the signature
	for (int i = 0; i < PAR_K; ++i) {
		int Ji = chall->J[i];
		int idx = i * PAR_N + Ji;
		memcpy(&sig.com_rands[i * SECPAR], &state->varphis[idx * SECPAR],
		SECPAR);
	}
	return true;
}
