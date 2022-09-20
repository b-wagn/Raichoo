#include "context.hpp"

context* create_context() {
	initPairing();
	context *ctx = new context;
	mapToG1(ctx->g1, 1);
	mapToG2(ctx->g2, 1);
	return ctx;
}

void destroy_context(context *ctx) {
	delete ctx;
}
