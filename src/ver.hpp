//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines the verification algorithm
//============================================================================

#ifndef VER_H_
#define VER_H_

#include "types.hpp"
#include "context.hpp"

/**
 * signature verification algorithm
 *
 * Parameters In:
 * 	ctx: context, containing generators for the groups
 * 	pk: public key
 * 	info: a SECPAR bytes long string containing the (hash of the) public information
 * 	messagedigest: a SECPAR bytes long string containing the (hash of the) message
 *
 * Returns if the signature is valid (true) or not (false)
 */
bool ver(const context *ctx, const publickey *pk, unsigned char *info,
		unsigned char *messagedigest, const signature &sig);

#endif
