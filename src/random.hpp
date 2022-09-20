//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines a function to fill bytes randomly
//============================================================================

#ifndef RANDOM_HPP_
#define RANDOM_HPP_

/**
 * sampling of random bytes
 *
 * Parameters In:
 * 	len: the number of bytes that should be sampled,
 * 		 dst is assumed to have at enough space for len many bytes
 *
 * Parameters Out:
 * 	dst: contains the randomly sampled bytes
 */
void random_bytes(unsigned char *dst, int len);

#endif
