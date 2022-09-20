//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines structs for public keys, secret keys, signatures,
//               and others
//============================================================================

#ifndef TYPES_H_
#define TYPES_H_

#include "parameters.hpp"

//#include <mcl/bn256.hpp>
//using namespace mcl::bn256;
#include <mcl/bls12_381.hpp>
using namespace mcl::bn;

/**
 * a struct defining a public key for the scheme
 */
typedef struct publickey {
	G1 pk1;
	G2 pk2;
} publickey;

/**
 * a struct defining a secret key for the scheme
 */
typedef struct secretkey {
	Fr sk;
} secretkey;

/**
 * a struct defining a signature for the scheme
 */
typedef struct signature {
	publickey pk_sharing[PAR_K - 1];
	unsigned char com_rands[PAR_K * SECPAR];
	G1 agg_sig;
} signature;

/**
 * a struct defining the first message of the signing interaction
 * sent by the user to the signer
 */
typedef struct challenge {
	uint32_t J[PAR_K];
	G1 c[PAR_K];
	unsigned char rand[PAR_K * (PAR_N - 1) * 2 * SECPAR];
	unsigned char com[PAR_K * SECPAR];
} challenge;

/**
 * a struct defining the second message of the signing interaction
 * sent by the signer to the user
 */
typedef struct response {
	publickey pk_sharing[PAR_K - 1];
	G1 agg_resp;
} response;

#endif
