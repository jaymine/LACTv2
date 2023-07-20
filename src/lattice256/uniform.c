/******
 *  Based on the public domain implementation in
 *  https://github.com/pq-crystals/dilithium
 *  We acknowledge the authors of Dilithium.
 *******/

#include "polyvec.h"

static unsigned int rej_uniform(int64_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
    unsigned int ctr, pos;
    uint64_t t;

    ctr = pos = 0;
    while(ctr < len && pos + D <= buflen) {
        t  = buf[pos++];
        t |= (uint64_t)buf[pos++] << 8;
        t |= (uint64_t)buf[pos++] << 16;
        t &= 0x7FFFFF;

        if(t < LACTX_Q)
            a[ctr++] = t;
    }
    return ctr;
}

void poly_uniform(poly *a,
                  const uint8_t seed[SEED_BYTES],
                  uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int buflen = UNIFORM_BLOCK*SHAKE128_RATE;
    uint8_t buf[UNIFORM_BLOCK*SHAKE128_RATE + 2];
    keccak_state state;

    shake128_stream_init(&state, seed, nonce);
    shake128_squeezeblocks(buf, UNIFORM_BLOCK, &state);

    ctr = rej_uniform(a->coef, LACTX_N, buf, buflen);

    while(ctr < LACTX_N) {
        off = buflen % 3;
        for(i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        shake128_squeezeblocks(buf + off, 1, &state);
        buflen = SHAKE128_RATE + off;
        ctr += rej_uniform(a->coef + ctr, LACTX_N - ctr, buf, buflen);
    }
}
