//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines the user algorithms
//============================================================================

#ifndef USER_H_
#define USER_H_

#include "parameters.hpp"
#include "types.hpp"
#include "context.hpp"

/**
 * A struct that is holding the users state
 * in an execution of the signing protocol
 */
typedef struct user_state {
	G1 mu_hashes[PAR_N * PAR_K];
	G1 c[PAR_N * PAR_K];
	Fr alphas[PAR_N * PAR_K];

	unsigned char varphis[PAR_K * PAR_N * SECPAR];
	const context *ctx;
	const publickey *pk;
} user_state;

/**
 * First part of the user algorithm
 *
 * Parameters In:
 * 	ctx: context, containing generators for the groups
 * 	pk: the public key
 * 	info: a SECPAR bytes long string containing the (hash of the) public information
 * 	messagedigest: a SECPAR bytes long string containing the (hash of the) message
 *
 * Parameters Out:
 *  state: the state that the user has to keep, in order to run
 *  	   user finalize after receiving the response from the signer
 * 	chall: the first message sent by the user to the signer
 *
 */
void user_challenge(const context *ctx, const publickey *pk,
		const unsigned char *info, const unsigned char *messagedigest,
		user_state *state, challenge *chall);

/**
 * Second part of the user algorithm
 *
 * Parameters In:
 *  state: the state that the user has to keep, output by user_challenge
 *  challenge: the first message sent by the user to the signer, output by user_challenge
 *  resp: the response message sent by the signer to the user
 *
 * Parameters Out:
 * 	sig: the final signature
 *
 * Returns if the computation of the signature succeeded (true) or if it failed (false)
 */
bool user_finalize(user_state *state, challenge *chall, response *resp,
		signature &sig);

#endif
