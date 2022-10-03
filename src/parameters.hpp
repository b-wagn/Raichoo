//============================================================================
// Author      : Benedikt Wagner
// Copyright   : https://opensource.org/licenses/BSD-3-Clause
// Description : Defines global parameters, such as the number of instances
//============================================================================

#ifndef PARAMETERS_H_
#define PARAMETERS_H_

#define SECPAR 32 //security parameter in bytes

/************SELECTION*OF*CURVE**************/

/**
 #include <mcl/bn256.hpp>
 using namespace mcl::bn256;
 **/

#include <mcl/bls12_381.hpp>
using namespace mcl::bn;

#define NUMBYTESG1ELEMENT 48

#define MEDIUM_N_PARS

/*************SYSTEM*PARAMETERS**************/
// PAR_N: number of sessions per instance
// LOG_N_MASK: a bit mask for computing modulo PAR_N
// PAR_K: number of instances
// CC_HASH_RUNS: number of times we need to use Sha256 to hash to [N]^K
#ifdef LOW_N_PARS
#define PAR_N 4
#define LOG_N_MASK  0x03
#define PAR_K 80
#define CC_HASH_RUNS 3//>=ceil(K/32)
#endif

#ifdef MEDIUM_N_PARS
#define PAR_N 8
#define LOG_N_MASK  0x07
#define PAR_K 54
#define CC_HASH_RUNS 2//>=ceil(K/32)
#endif

#ifdef  HIGH_N_PARS
#define PAR_N 32
#define LOG_N_MASK  0x1f
#define PAR_K 33
#define CC_HASH_RUNS 2//>=ceil(K/32)
#endif

#endif
