/******
 *  Based on the public domain implementation in
 *  https://github.com/pq-crystals/dilithium
 *  We acknowledge the authors of Dilithium.
 *******/


#ifndef LACTx_NTT_IMPL_H
#define LACTx_NTT_IMPL_H

#include "ntt.h"
#include <stdint.h>


/**
 * montgomery_reduce
 * @param a
 * @return  t \equiv a*2^{-64} (mod Q) such that -Q < t < Q
 */
int64_t montgomery_reduce(__int128 a) {
    int64_t t;

    t = (__int128)((int64_t)(a*QINV) & FILTER);
    t = ((a - (__int128)t*Q) >> KMONT);
    return t;
}


void ntt(int64_t a[N]) {
    unsigned int len, start, j, k;
    int64_t zeta, t;

    k = 0;
    for(len = 128; len > 0; len >>= 1) {
        for(start = 0; start < N; start = j + len) {
            zeta = zetas[++k];
            for(j = start; j < start + len; ++j) {
                t = montgomery_reduce((__int128)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}


void invntt_tomont(int64_t a[N]) {
    unsigned int start, len, j, k;
    int64_t t, zeta;

    k = 256;
    for(len = 1; len < N; len <<= 1) {
        for(start = 0; start < N; start = j + len) {
            zeta = -zetas[--k];
            for(j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce((__int128) zeta * a[j + len]);
            }
        }
    }

    for(j = 0; j < N; j++) {
        a[j] = montgomery_reduce((__int128) F1 * a[j]);
    }
}


void invntt(int64_t a[N]) {
    unsigned int start, len, j, k;
    int64_t t, zeta;
    k = 256;
    for(len = 1; len < N; len <<= 1) {
        for(start = 0; start < N; start = j + len) {
            zeta = -zetas[--k];
            for(j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce((__int128) zeta * a[j + len]);
            }
        }
    }

    for(j = 0; j < N; ++j) {
        a[j] = montgomery_reduce((__int128) F2 * a[j]);
    }
}




#endif //LACTx_NTT_IMPL_H
