/****************************************************************************
*    LACT+ - Post-Quantum Lattice-based Aggregable Transactions (Version 2) *
*    Copyright (C) 2022  Jayamine Alupotha                                  *
*                                                                           *
*    This program is free software: you can redistribute it and/or modify   *
*    it under the terms of the GNU General Public License as published by   *
*    the Free Software Foundation, either version 3 of the License, or      *
*    (at your option) any later version.                                    *
*                                                                           *
*    This program is distributed in the hope that it will be useful,        *
*    but WITHOUT ANY WARRANTY; without even the implied warranty of         *
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
*    GNU General Public License for more details.                           *
*                                                                           *
*    You should have received a copy of the GNU General Public License      *
*    along with this program.  If not, see <https://www.gnu.org/licenses/>. *
*****************************************************************************/


#ifndef LACTx_POLY_IMPL_H
#define LACTx_POLY_IMPL_H

#include <stdio.h>
#include "poly.h"
#include "fips202.h"
#include "shake.h"
#include "openssl/rand.h"

/**
 * Reduce 64bit number to the range [-2^K1, 2^K1]
 *
 * @param a - the number
 * @return a number in [-2^K1, 2^K1]
 */
int64_t reduce64(const int64_t a) {
    int64_t t;
    t = (a + ((int64_t)1 << K11)) >> K1;
    t = a - t*Q; // bring t to [-2^50, 2^50]

    return t;
}

/**
 * Reduce 64bit number to the range [-(Q-1)/2, (Q-1)/2]
 *
 * @param a - the number
 * @return a number in [-(Q-1)/2, (Q-1)/2]
 */
int64_t reduce64_exact(int64_t a) {
    int64_t t;
    t = (a + ((int64_t)1 << K11)) >> K1;
    t = a - t*Q; // bring t to [-2^50, 2^50]

    if (t > Q2) t = -Q + t;
    if (t < -Q2) t = Q + t;

    return t;
}

/**
 * Get a1 such that a = a1 * 2^p + a2 and |a2| < 2^p
 * @param a - input
 * @param p - the number of lower bits
 * @return
 */


int64_t highbits(int64_t a, unsigned int p) {
    //int64_t t =  ((((int64_t)(a & (((int64_t)1) << (p - 1)) - 1)) << (64 - K11))>> (p + 64 - K11));
    if (a == (Q - 1) >> 1) a = 0;
    int64_t t =  (a & ((((int64_t) 1 << (K1 - p)) - 1) << (p - 1))) >> p;
    return t;
}

/**
 * Get a1 * 2^p
 * @param a - input
 * @param p - the number of lower bits
 * @return
 */
int64_t roundup(int64_t a, unsigned int p) {
    return reduce64(a << p);
}

/**
 * Initiate a polynomial from a vector
 * @param vec - input
 * @return a polynomial
 */
poly poly_from_vec(const int64_t vec[N]) {
    int i;
    poly a;
    for (i = 0; i < N; i++) {
        a.coef[i] = vec[i];
    }
    return a;
}

/**
 * Set b = a
 * @param b - output polynomial
 * @param a - input polynomial
 */
void poly_set(poly *b, poly *a) {
    unsigned int j;
    for (j = 0; j < N; j++)
        b->coef[j] = a->coef[j];
}

/**
 * Compare two polynomials
 * @param s1 - input polynomial
 * @param s2 - input polynomial
 * @return 0 - equal and -1 - otherwise
 */
int poly_compare(const poly *s1, const poly *s2) {
    for (int i = 0; i < N; i++) {
        if (s1->coef[i] != s2->coef[i]){
#if defined(ENABLE_DEBUG_MODE)
            printf("%d %ld %ld\n", i, s1->coef[i], s2->coef[i]);
#endif
            return -1;
        }
    }
    return 0;
}

/**
 * Compare (K1 - p) number of high bits of each element
 * @param s1 - input polynomial
 * @param s2 - input polynomial
 * @param p - the number of lower bits
 */
int poly_highbits_compare(const poly *s1, const poly *s2, unsigned int p) {
    for (int i = 0; i < N; i++) {
        if (highbits(s1->coef[i], p) != highbits(s2->coef[i], p)){
#if defined(ENABLE_DEBUG_MODE)
            printf("%d %ld %ld\n", i, (s1->coef[i] & filter), (s2->coef[i] & filter));
#endif
            return -1;
        }
    }
    return 0;
}

/**
 * Set [start:end] to zero (except "end")
 * @param a - input polynomial
 * @param start - starting index
 * @param end - ending index
 * @return
 */
void poly_set_zero(poly *a, unsigned int start, unsigned int end) {
    unsigned int i;
    for (i = start; i < end; i++) {
        a->coef[i] = 0;
    }
}

/**
 * Change range to [0, Q-1]
 * @param a
 * @return
 */
static int64_t addq(int64_t a) {
    a += (a >> 31) & Q;
    return a;
}

/**
 * Reduce all coefficients of a polynomial to [-2^K1, 2^K1]
 * @param a - the polynomial
 */
void poly_reduce(poly *a) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        a->coef[i] = reduce64(a->coef[i]);
    }
}

/**
 * Reduce all coefficients of a polynomial to [-Q, Q]
 * @param a - the polynomial
 */
void poly_reduce_exact(poly *a) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        a->coef[i] = reduce64_exact(a->coef[i]);
    }
}

/**
 * Get high bits of each coefficient
 * @param a - out polynomial
 * @param b - input polynomial
 * @param p - the number of lower bits
 */
void poly_highbits(poly *a, poly *b, unsigned int p) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        a->coef[i] = highbits(b->coef[i], p);
    }
}

/**
 * Get the roundup of each coefficient such that a*2^p
 * @param a - out polynomial
 * @param b - input polynomial
 * @param p - the number of lower bits
 */
void poly_roundup(poly *a, poly *b, unsigned int p) {
    unsigned int i;
    for (i = 0; i < N; i++) {
        a->coef[i] = roundup(b->coef[i], p);
    }
}

/**
 * Change coefficient range of a polynomial to [0, Q-1]
 * @param a
 */
void poly_addq(poly *a) {
    unsigned int i;
    for (i = 0; i < N; ++i)
        a->coef[i] = addq(a->coef[i]);
}

/**
 * Add two polynomials without any modular reductions
 * @param c - input polynomial
 * @param a - input polynomial
 * @param b - a + b
 */
void poly_add(poly *c, poly *a, poly *b) {
    unsigned int i;
    for (i = 0; i < N; ++i)
        c->coef[i] = a->coef[i] + b->coef[i];
}

/**
 * Subtract two polynomials without any modular reductions
 * @param c - input polynomial
 * @param a - input polynomial
 * @param b - a - b
 */
void poly_sub(poly *c, poly *a, poly *b) {
    unsigned int i;
    for (i = 0; i < N; ++i)
        c->coef[i] = a->coef[i] - b->coef[i];
}

/**
 * Multiply by 2^l
 * @param a
 */
void poly_shift_l(poly *a, unsigned int l) {
    unsigned int i;
    for (i = 0; i < N; ++i)
        a->coef[i] <<= l;
}

/**
 * Apply NTT forward transformation to a polynomial
 * @param a - polynomial
 */
void poly_ntt(poly *a) {
    ntt(a->coef);
}

/**
 * Apply NTT inverse transformation to a polynomial
 * and outputs a polynomial multiplied by the Montgomery factor.
 * @param a - polynomial
 */
void poly_inv_ntt_to_mont(poly *a) {
    invntt_tomont(a->coef);
}

/**
 * Apply NTT inverse transformation to a polynomial
 * @param a - polynomial
 */
void poly_inv_ntt(poly *a) {
    invntt(a->coef);
}

/**
 * Point-wise multiplication of polynomials in NTT domain
 * @param a - input
 * @param b - input
 * @param c - a*b (elementwise)
 */
void poly_pointwise_montgomery(poly *c, poly *a, poly *b) {
    unsigned int i;

    for(i = 0; i < N; i++)
        c->coef[i] = montgomery_reduce((__int128)a->coef[i] * b->coef[i]);

}

/**
 * c = a * b in Z[X]/[X^N + 1] where b.coef[i] = value and all other coefficients are zero.
 * @param c - output
 * @param a - input
 * @param i - index
 * @param value - ith coefficient
 */
void poly_easy_mul(poly *c, poly *a, unsigned int i, int value) {
    unsigned int j;
    poly tmp; // Should not directly set c because a can be the same pointer as c.
    for (j = 0; j < (N - i); j++) {
        tmp.coef[j + i] = value * a->coef[j];
    }
    for (j = (N - i); j < N; j++) {
        tmp.coef[j - N + i] = -(value * a->coef[j]);
    }
    poly_set(c, &tmp);
}

/**
 * Check infinity norm
 * @param a - polynomial
 * @param B - norm
 * @return 0 if B <= GAMMA2 and |a|_infinity < B; -1 otherwise
 */
int poly_chknorm(const poly *a, int64_t B) {
    unsigned int i;
    int64_t t;

    if (B > GAMMA2)
        return -1;

    for (i = 0; i < N; ++i) {
        // Absolute value
        t = a->coef[i] >> 63;
        t = a->coef[i] - (t & 2 * a->coef[i]);

        if (t >= B) {
            //printf("%ld\n", a->coef[i]);
            return -1;
        }
    }

    return 0;
}


/**
 * Check infinity norm for a customized range
 * @param a  - polynomial
 * @param B  - norm
 * @param start - start point
 * @param end - end point
 * @return 0 if B <= GAMMA2 and |a[start:end]|_infinity < B; -1 otherwise
 */
int poly_chknorm_custom(const poly *a, int64_t B, int start, int end) {
    unsigned int i;
    int64_t t;

    if (B > GAMMA2 || start < 0 || end > N)
        return -1;

    for (i = start; i < end; ++i) {
        // Absolute value
        t = a->coef[i] >> 63;
        t = a->coef[i] - (t & 2 * a->coef[i]);

        if (t >= B) {
            return -1;
        }
    }

    return 0;
}

/**
 * Generate challenge polynomial with CH number of +1/-1
 * @param x  - output polynomial
 * @param seed - input hash bytes
 */
void poly_challenge(poly *x, const uint8_t seed[SEED_BYTES]) {
    unsigned int i, b, pos;
    int64_t signs;
    uint8_t buf[SHAKE256_RATE];
    keccak_state state;

    shake256_init(&state);
    shake256_absorb(&state, seed, SEED_BYTES);
    shake256_finalize(&state);
    shake256_squeezeblocks(buf, 1, &state);

    signs = 0;
    for(i = 0; i < 8; ++i)
        signs |= (int64_t)buf[i] << 8*i;
    pos = 8;

    for(i = 0; i < N; ++i)
        x->coef[i] = 0;
    for(i = N - BETA; i < N; ++i) {
        do {
            if(pos >= SHAKE256_RATE) {
                shake256_squeezeblocks(buf, 1, &state);
                pos = 0;
            }

            b = buf[pos++];
        } while(b > i);

        x->coef[i] = x->coef[b];
        x->coef[b] = (int64_t)1 - 2*(signs & 1);
        signs >>= 1;
    }
}


#endif //LACTx_POLY_IMPL_H
