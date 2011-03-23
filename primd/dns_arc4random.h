/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

/* modified by Satoshi Ebisawa <ebisawa@gmail.com> */

#ifndef __ARC4RANDOM_H__
#define __ARC4RANDOM_H__

struct arc4_stream {
    u_int8_t i;
    u_int8_t j;
    u_int8_t s[256];
};

typedef struct {
    struct arc4_stream rs;
    int rs_initialized;
    int rs_stired;
} arc4_ctx_t;

u_int32_t xarc4random(arc4_ctx_t *ctx);

#endif
