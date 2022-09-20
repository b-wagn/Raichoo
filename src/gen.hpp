//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines the key generation algorithm
//============================================================================

#ifndef GEN_H_
#define GEN_H_

#include "parameters.hpp"
#include "context.hpp"
#include "types.hpp"

/**
 * key generation algorithm
 * 
 * Parameters In:
 * 	ctx: context, containing generators for the groups
 * 	
 * Parameters Out:
 * 	sk: the generated secret key
 * 	pk: the generated public key
 */
void gen(const context *ctx, secretkey *sk, publickey *pk);

#endif
