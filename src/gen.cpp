#include "gen.hpp"

void gen(const context* ctx, secretkey* sk, publickey* pk) {
	sk->sk.setRand();
	G1::mul(pk->pk1, ctx->g1, sk->sk); // pk1 = sk*g1
	G2::mul(pk->pk2, ctx->g2, sk->sk); // pk2 = sk*g2
}