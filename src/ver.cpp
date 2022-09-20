#include "ver.hpp"
#include "hash.hpp"

bool ver(const context *ctx, const publickey *pk, unsigned char *info,
		unsigned char *messagedigest, const signature &sig) {

	// Arrays for final verification equation, and a tmp element
	G1 hashes_and_agg_sig[PAR_K + 1];
	G2 pks_and_g2[PAR_K + 1];
	GT tmp;

	// Step 1: Recompute the final share of the public key
	G2 pk_prod;
	pk_prod = sig.pk_sharing[0].pk2;
	for (int i = 1; i < PAR_K - 1; ++i) {
		G2::add(pk_prod, pk_prod, sig.pk_sharing[i].pk2);
	}
	G2::neg(pk_prod, pk_prod);
	G2::add(pks_and_g2[PAR_K - 1], pk->pk2, pk_prod);

	for (int i = 0; i < PAR_K - 1; ++i) {
		pks_and_g2[i] = sig.pk_sharing[i].pk2;
	}
	pks_and_g2[PAR_K] = ctx->g2;

	// Step 2: Verify that the public keys are valid
	bool consistent = true;
	G1 left[2];
	G2 right[2];
	G1::neg(left[1], ctx->g1);
	right[0] = ctx->g2;
	for (int i = 0; i < PAR_K - 1; ++i) {
		//check that e(pk_i,1,g_2) = e(g_1,pk_i,2)
		left[0] = sig.pk_sharing[i].pk1;
		right[1] = sig.pk_sharing[i].pk2;
		millerLoopVec(tmp, left, right, 2);
		finalExp(tmp, tmp);
		consistent &= tmp.isOne();
	}
	// check consistency for pk
	// this is equivalent to checking it for pk_K
	// but does not require to compute pk_K,1
	left[0] = pk->pk1;
	right[1] = pk->pk2;
	millerLoopVec(tmp, left, right, 2);
	finalExp(tmp, tmp);
	consistent &= tmp.isOne();
	if (!consistent) {
		return false;
	}

	// Step 3: recompute mus and their hashes
	for (int i = 0; i < PAR_K; ++i) {
		unsigned char mu[SECPAR];
		hash_mu(messagedigest, &(sig.com_rands[i * SECPAR]), mu);
		hash_bls(mu, info, hashes_and_agg_sig[i]);
	}
	G1::neg(hashes_and_agg_sig[PAR_K], sig.agg_sig);

	// Step 4: Verification equation
	millerLoopVec(tmp, hashes_and_agg_sig, pks_and_g2, PAR_K + 1);
	finalExp(tmp, tmp);
	return tmp.isOne();
}
