//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines the context, that each algorithm gets, containing
//               generators of the source groups G1 and G2
//============================================================================

#ifndef CONTEXT_H_
#define CONTEXT_H_

#include "parameters.hpp"

typedef struct context {
	G1 g1;
	G2 g2;
} context;

context* create_context();
void destroy_context(context *ctx);

#endif
