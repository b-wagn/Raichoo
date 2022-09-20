//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines the signer algorithm
//============================================================================

#ifndef SIGNER_H_
#define SIGNER_H_

#include "parameters.hpp"
#include "context.hpp"
#include "types.hpp"

/**
 * signer algorithm
 *
 * Parameters In:
 * 	ctx: context, containing generators for the groups
 * 	pk: the public key
 * 	sk: the secret key
 * 	info: a SECPAR bytes long string containing the (hash of the) public information
 * 	chall: the first message sent by the user to the signer
 *
 * Parameters Out:
 * 	resp: the second message sent by the signer to the user
 *
 * Returns if the interaction should be continued (true) or aborted (false)
 */
bool signer(const context *ctx, const publickey *pk, const secretkey *sk,
		const unsigned char *info, const challenge *chall, response *resp);

#endif
