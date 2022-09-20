#include "signer.hpp"
#include "hash.hpp"

bool inline sanity_check(const context *ctx, const unsigned char *info,
		const challenge *chall) {
	//recompute the set of challenges, and all commitments
	G1 c[PAR_K * PAR_N];
	unsigned char com[PAR_K * PAR_N * SECPAR];

	Fr alpha;
	G1 g1alpha;
	G1 hash_mu;
	for (int i = 0; i < PAR_K; ++i) {
		int Ji = chall->J[i];
		//the values left of Ji
		for (int j = 0; j < Ji; ++j) {
			int idx_dst = i * PAR_N + j;
			int idx_src = i * (PAR_N - 1) + j;
			//hash rand to get com
			hash_r(&chall->rand[idx_src * 2 * SECPAR], 1,
					&com[idx_dst * SECPAR]);
			//hash gamma (second part of rand) to get alpha
			hash_alpha(&chall->rand[idx_src * 2 * SECPAR + SECPAR], 0, alpha);
			//compute c_i,j by hashing mu (first part of rand) and info
			//and shifting by g_1alpha
			hash_bls(&chall->rand[idx_src * 2 * SECPAR], info, hash_mu);
			G1::mul(g1alpha, ctx->g1, alpha);
			G1::add(c[idx_dst], hash_mu, g1alpha);

		}
		//copy the Ji-th commitment and challenge
		memcpy(&com[(i * PAR_N + Ji) * SECPAR], &chall->com[i * SECPAR],
		SECPAR);
		c[i * PAR_N + Ji] = chall->c[i];
		//the values right of Ji
		for (int j = Ji + 1; j < PAR_N; ++j) {
			int idx_dst = i * PAR_N + j;
			int idx_src = i * (PAR_N - 1) + j - 1;
			//hash rand to get com
			hash_r(&chall->rand[idx_src * 2 * SECPAR], 1,
					&com[idx_dst * SECPAR]);
			//hash gamma (second part of rand) to get alpha
			hash_alpha(&chall->rand[idx_src * 2 * SECPAR + SECPAR], 0, alpha);
			//compute c_i,j by hashing mu (first part of rand) and info
			//and shifting by g_1alpha
			hash_bls(&chall->rand[idx_src * 2 * SECPAR], info, hash_mu);
			G1::mul(g1alpha, ctx->g1, alpha);
			G1::add(c[idx_dst], hash_mu, g1alpha);
		}
	}

//re-hash to get J
	uint32_t J[PAR_K];
	hash_cc(com, c, 1, J);

//check if J is equal to the J that the user sent
	for (int i = 0; i < PAR_K; ++i) {
		if (J[i] != chall->J[i]) {
			return false;
		}
	}
	return true;
}

bool signer(const context *ctx, const publickey *pk, const secretkey *sk,
		const unsigned char *info, const challenge *chall, response *resp) {
// Verify the challenge
	if (!sanity_check(ctx, info, chall)) {
		return false;
	}

// Sample a random key sharing
	Fr sk_sharing[PAR_K];
	Fr sum;
	sk_sharing[0].setRand();
	sum = sk_sharing[0];
	G1::mul(resp->pk_sharing[0].pk1, ctx->g1, sk_sharing[0]);
	G2::mul(resp->pk_sharing[0].pk2, ctx->g2, sk_sharing[0]);
	for (int i = 1; i < PAR_K - 1; ++i) {
		sk_sharing[i].setRand();
		Fr::add(sum, sum, sk_sharing[i]);
		G1::mul(resp->pk_sharing[i].pk1, ctx->g1, sk_sharing[i]);
		G2::mul(resp->pk_sharing[i].pk2, ctx->g2, sk_sharing[i]);
	}
	Fr::neg(sum, sum);
	Fr::add(sk_sharing[PAR_K - 1], sk->sk, sum);

// Compute the aggregated response
	G1::mulVec(resp->agg_resp, chall->c, sk_sharing, PAR_K);
	return true;
}
