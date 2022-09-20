#include "random.hpp"
#include <openssl/rand.h>

void random_bytes(unsigned char *dst, int len) {
	RAND_poll();
	RAND_bytes(dst, len);
}

