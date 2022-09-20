//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines the hash functions that are used in the scheme
//============================================================================

#ifndef HASH_H_
#define HASH_H_

#include "parameters.hpp"


/**
 * Hash message to mu; uses Sha256 with prefix "MU.H"
 *
 * Parameters In:
 * 	messagedigest: a SECPAR bytes long string containing the (hash of the) message
 * 	varphi: a SECPAR bytes long (random) string
 *
 * Parameters Out:
 *  mu: a SECPAR bytes long string containing the hash
 *
 */
void hash_mu(const unsigned char *messagedigest, const unsigned char *varphi,
		unsigned char *mu);

/**
 * Hash the randomness; uses Sha256 with prefix "RANH"
 *
 * Parameters In:
 * 	rand: a (L+1)*SECPAR bytes long string containing L mu's and 1 randomness
 * 	L: an integer, determining the length of rand (batch size)
 *
 * Parameters Out:
 *  com: a SECPAR bytes long string containing the hash
 *
 */
void hash_r(const unsigned char *rand, uint32_t L, unsigned char *com);

/**
 * Hash randomness to alpha; uses MCL::setHashOf with prefix "ALPH"
 *
 * Parameters In:
 * 	gamma: a SECPAR bytes long string
 * 	l: an integer that allows deriving multiple alphas, gamma and l is hashed
 *
 * Parameters Out:
 *  alpha: a field element derived from hashing gamma and l
 *
 */
void hash_alpha(const unsigned char *gamma, uint32_t l, Fr &alpha);

/**
 * Hash to cut-and-choose index; uses Sha256 with prefix "CC.H"
 * Depending on PAR_K and PAR_N, Sha256 is used multiple times with
 * changing prefixes
 *
 * Parameters In:
 * 	com: a byte array of length PAR_K * PAR_N * SECPAR, containing PAR_K*PAR_N commitments
 * 	c: an array containing PAR_K * PAR_N* L many group elements that allows deriving multiple alphas, gamma and l is hashed
 *	L: an integer, determining the length of c (batch size)
 *
 * Parameters Out:
 *  J: the hash of com and c, representing a vector in [N]^K
 *
 */
void hash_cc(const unsigned char *com, G1 *c, uint32_t L, uint32_t *J);

/**
 * Hash to group element as in plain BLS; uses MCL::hashAndMapToG1 with prefix "BLSH"
 *
 * Parameters In:
 * 	mu: a byte array of length SECPAR
 * 	info: a SECPAR bytes long string containing the (hash of the) public information
 *
 * Parameters Out:
 *  hash: the hash of mu and info in G1
 *
 */
void hash_bls(const unsigned char *mu, const unsigned char *info, G1 &hash);

#endif
