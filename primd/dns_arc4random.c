/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project (for instance by leaving this copyright notice
 * intact).
 */

/*
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

/* modified by Satoshi Ebisawa <ebisawa@gmail.com> */

#include <sys/cdefs.h>
/* __FBSDID("$FreeBSD: src/lib/libc/gen/arc4random.c,v 1.10 2004/03/24 14:44:57 green Exp $"); */

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "dns_arc4random.h"

#define	RANDOMDEV	"/dev/urandom"

static inline u_int8_t arc4_getbyte(struct arc4_stream *);
static void arc4_stir(struct arc4_stream *);

static inline void
arc4_init(struct arc4_stream *as)
{
	int     n;

	for (n = 0; n < 256; n++)
		as->s[n] = n;
	as->i = 0;
	as->j = 0;
}

static inline void
arc4_addrandom(struct arc4_stream *as, u_char *dat, int datlen)
{
	int n;
	u_int8_t si;

	as->i--;
	for (n = 0; n < 256; n++) {
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
}

static void
arc4_stir(struct arc4_stream *as)
{
	int fd, n, len;
	struct {
		struct timeval tv;
		pid_t pid;
		u_int8_t rnd[128 - sizeof(struct timeval) - sizeof(pid_t)];
	} rdat;

	gettimeofday(&rdat.tv, NULL);
	rdat.pid = getpid();
	fd = open(RANDOMDEV, O_RDONLY, 0);
	if (fd >= 0) {
		len = sizeof(rdat.rnd);
		if (read(fd, rdat.rnd, len) != len)
			;  /* ignore */
		close(fd);
	} 
	/* fd < 0?  Ah, what the heck. We'll just take whatever was on the
	 * stack... */

	arc4_addrandom(as, (void *) &rdat, sizeof(rdat));

	/*
	 * Throw away the first N bytes of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.  N=1024 is based on
	 * suggestions in the paper "(Not So) Random Shuffles of RC4"
	 * by Ilya Mironov.
	 */
	for (n = 0; n < 1024; n++)
		arc4_getbyte(as);
}

static inline u_int8_t
arc4_getbyte(struct arc4_stream *as)
{
	u_int8_t si, sj;

	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;

	return (as->s[(si + sj) & 0xff]);
}

static inline u_int32_t
arc4_getword(struct arc4_stream *as)
{
	u_int32_t val;

	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);

	return (val);
}

static void
arc4_check_init(arc4_ctx_t *ctx)
{
	if (!ctx->rs_initialized) {
		arc4_init(&ctx->rs);
		ctx->rs_initialized = 1;
	}
}

static void
arc4_check_stir(arc4_ctx_t *ctx)
{
	if (!ctx->rs_stired) {
		arc4_stir(&ctx->rs);
		ctx->rs_stired = 1;
	}
}

u_int32_t
xarc4random(arc4_ctx_t *ctx)
{
	u_int32_t rnd;

	arc4_check_init(ctx);
	arc4_check_stir(ctx);
	rnd = arc4_getword(&ctx->rs);

	return (rnd);
}
