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

#ifndef LCTx_COMMITMENT_IMPL_H
#define LCTx_COMMITMENT_IMPL_H

#include <stdio.h>
#include "openssl/rand.h"
#include "lactx_store.h"
#include "util.h"


/**
 * Set binary vector of a full integer v
 * @param b - out binary
 * @param v - in
 */
void binary_set(poly *b, uint64_t v) {
    uint16_t j;
    for (j = 0; j < LACTX_L; j++)
        b->coef[j] = (int64_t) (v >> j) & (int64_t) 1;
    for (j = LACTX_L; j < LACTX_N; j++) {
        b->coef[j] = 0;
    }
}

/**
 * Copy a coin to another coin
 * @param a - out
 * @param b - in
 */
void lactx_coin_copy(coin_t *a, coin_t *b) {
    unsigned int i;
    // Minting coins
    a->s = b->s;
    if (b->s != 0) {
        poly_n_set(&a->u, &b->u);
        return;
    }
    // Normal coins
    memcpy(a->x2, b->x2, SEED_BYTES);
    poly_n_set(&a->u, &b->u);
    poly_n_set(&a->t1, &b->t1);
    poly_n_set(&a->t2_hints, &b->t2_hints);
    for (i = 0; i < LACTX_L; i++) poly_set(&a->z[i], &b->z[i]);
    for (i = 0; i < LACTX_m - D; i++) poly_set(&a->R[i], &b->R[i]);
}

/**
 * Formatted printing of a coin
 * @param a - coin
 */
void lactx_coin_print(coin_t *a) {
    unsigned int l;
    // Minting coins
    printf("s: %ld\n", a->s);
    if (a->s != 0) {
        printf("u: ");
        for (l = 0; l < 5; l++)
            printf("%ld ", a->u.vec[0].coef[l]);
        printf("\n");
        return;
    }
    // Normal coins
    printf("x2: ");
    for (l = 0; l < 5; l++)
        printf("%d ", a->x2[l]);
    printf("\n");
    printf("u: \n");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->u.vec[0].coef[l]);
    printf("\n");
    printf("t1: ");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->t1.vec[0].coef[l]);
    printf("\n");
    printf("t2 hints: ");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->t2_hints.vec[0].coef[l]);
    printf("\n");
    printf("z: ");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->z[0].coef[l]);
    printf("\n");
    printf("R: ");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->R[0].coef[l]);
    printf("\n");
}


/**
 * Create a coin object to receive coins from the coinbase account.
 * @param ctx - context object
 * @param coin - output confidential coin object with u.
 * @param s - supplied coin
 */
void lactx_mint_coin_create(context_t *ctx, coin_t *coin, uint64_t s) {
    poly_m s_u;
    poly b;

    coin->s = s;

    binary_set(&b, s);
    // u = H[b, 0^LACTX_N, .., 0^LACTX_N]
    poly_m_set_zero(&s_u, 0, LACTX_N);
    poly_set(&s_u.vec[0], &b);
    poly_ntt(&s_u.vec[0]);
    poly_matrix_mul(&coin->u, ctx->H, &s_u);
    poly_n_inv_ntt_to_mont(&coin->u);
    poly_n_reduce(&coin->u);
    poly_n_highbits(&coin->u, &coin->u, u_ERROR);
}


/**
 * Creates a confidential coin bundle and assign a random mask
 * @param ctx  - context object (cannot be null)
 * @param coin - coin object (cannot be null)
 * @param mask - bytes of the random mask (cannot be null)
 * @param v - coin amount
 * @return -1 if v is negative; 0 otherwise
 */
int lactx_coin_create(context_t *ctx, coin_t *coin, uint8_t mask[LACTX_m - D][r_BYTES], uint64_t v) {

    uint8_t a_seed[LACTX_L][a_BYTES];
    uint8_t r1_seed[LACTX_m - D][r1_BYTES];
    uint8_t r2_seed[LACTX_m - D][r2_BYTES];
    int i, j;
    keccak_state state;
    uint8_t u_bytes[u_HIGHBITS];
    uint8_t t1_bytes[t1_HIGHBITS];
    uint8_t t2_bytes[t2_HIGHBITS];
    uint8_t x1_bytes[SEED_BYTES];

    poly x1;
    poly x1_ntt;
    poly x2;
    poly x2_ntt;
    poly z;
    poly z_1;
    poly a[LACTX_L];
    poly a_ntt[LACTX_L];
    poly b;
    poly b_ntt;
    poly_m s_u;
    poly_m s_t1;
    poly_m s_t2;
    poly_n coin_t2;

    binary_set(&b, v); // binary polynomial of v
    binary_set(&b_ntt, v);
    poly_ntt(&b_ntt);

    coin->s = 0;  // Set supply coin value

    rejection_point:
    get_value_masks(a, a_seed, &b); // Get a[LACTX_L] where each a_i is in [-ALPHA, ALPHA]
    for (i = 0; i < LACTX_L; i++) {
        poly_set(&a_ntt[i], &a[i]);
        poly_ntt(&a_ntt[i]);
    }

    // u = H[b, 0^LACTX_N, 0^LACTX_N, r_0, ..., r_(LACTX_m-3)]
    poly_set(&s_u.vec[0], &b);
    poly_set_zero(&s_u.vec[1], 0, LACTX_N);
    poly_set_zero(&s_u.vec[2], 0, LACTX_N);
    get_masks_tau(&s_u, mask);  // ||r|| < TAU
    poly_m_ntt(&s_u);
    poly_matrix_mul(&coin->u, ctx->H, &s_u);
    poly_n_inv_ntt_to_mont(&coin->u);
    poly_n_reduce(&coin->u);
    poly_n_highbits(&coin->u, &coin->u, u_ERROR);

    // t1 = H[0^LACTX_N, sum_{i=0}^LACTX_L a[i]rot(2(b_i - 1), i), 0^LACTX_N, r_(2,0),.., r_(2, LACTX_m-3)]
    poly_m_set_zero(&s_t1, 0, LACTX_N);
    for (i = 0; i < LACTX_L; i++) {
        poly_easy_mul(&z, &a[i], i, (int)(2 * b.coef[i] - 1));
        poly_add(&s_t1.vec[1], &s_t1.vec[1], &z);
    }
    poly_reduce(&s_t1.vec[1]);
    get_masks_tau1(&s_t1, r1_seed);  // ||r_1|| < TAU1
    poly_m_ntt(&s_t1);
    poly_matrix_mul(&coin->t1, ctx->H, &s_t1);
    poly_n_inv_ntt_to_mont(&coin->t1);
    poly_n_reduce(&coin->t1);
    poly_n_highbits(&coin->t1, &coin->t1, t1_ERROR);

    // packing
    pack_poly_ring_custom(u_bytes, &coin->u, K1 - u_ERROR);
    pack_poly_ring_custom(t1_bytes, &coin->t1, K1 - t1_ERROR);

    // challenge 1: x1 = hash(u, t1)
    shake256_init(&state);
    shake256_absorb(&state, u_bytes, u_HIGHBITS);
    shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(x1_bytes, SEED_BYTES, &state);
    poly_challenge(&x1, x1_bytes);
    poly_set(&x1_ntt, &x1);
    poly_ntt(&x1_ntt);

    // t2 = H[x1sum_{i=0}^LACTX_L a[i], sum_{i=0}^LACTX_L a[i]a[i], 0^LACTX_N, r_(2,0),.., r_(2, LACTX_m-3)]
    poly_m_set_zero(&s_t2, 0, LACTX_N);
    for (i = 0; i < LACTX_L; i++) {
        poly_add(&s_t2.vec[0], &s_t2.vec[0], &a[i]);

        poly_pointwise_montgomery(&z, &a_ntt[i], &a_ntt[i]);
        poly_add(&s_t2.vec[1], &s_t2.vec[1], &z); // a[i]a[i]
    }
    poly_inv_ntt_to_mont(&s_t2.vec[1]);
    poly_ntt(&s_t2.vec[0]);
    poly_pointwise_montgomery(&s_t2.vec[0], &s_t2.vec[0], &x1_ntt);
    poly_inv_ntt_to_mont(&s_t2.vec[0]);
    poly_reduce(&s_t2.vec[0]);
    poly_reduce(&s_t2.vec[1]);
    get_masks_tau2(&s_t2, r2_seed);
    poly_m_ntt(&s_t2);
    poly_matrix_mul(&coin_t2, ctx->H, &s_t2);
    poly_n_inv_ntt_to_mont(&coin_t2);
    poly_n_reduce(&coin_t2);

    poly_n_highbits(&coin_t2, &coin_t2, t2_ERROR);
    pack_poly_ring_custom(t2_bytes, &coin_t2, K1 - t2_ERROR);

    // challenge 2: x2 = hash(u, t1, t2)
    shake256_init(&state);
    shake256_absorb(&state, u_bytes, u_HIGHBITS);
    shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
    shake256_absorb(&state, t2_bytes, t2_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(coin->x2, SEED_BYTES, &state);
    poly_challenge(&x2, coin->x2);
    poly_set(&x2_ntt, &x2);
    poly_ntt(&x2_ntt);

    // z_i = x2rot(b_i, i) + a_i
    for (i = 0; i < LACTX_L; i++) {
        if (b.coef[i] == 0) {
            poly_set(&coin->z[i], &a[i]);
        } else {
            poly_easy_mul(&z, &x2, i, 1);
            poly_add(&coin->z[i], &z, &a[i]);
        }
        // Even though the valid range is [-(ALPHA - 1), ALPHA - 1],
        // the secure range is [-(ALPHA - 2), ALPHA - 2] to prevent data leakage
        if (poly_chknorm(&coin->z[i], ALPHA - 1) != 0) {
            DEBUG_PRINT(("Rejected z_%d %d\n", i, poly_chknorm(&coin->z[i], ALPHA - 1)));
            goto rejection_point;
        }
    }

    // R_i = x2(x1*r + r1) + r2
    for (j = 0; j < LACTX_m - D; j++) {
        poly_pointwise_montgomery(&coin->R[j], &s_u.vec[j + D], &x1_ntt);
        poly_inv_ntt_to_mont(&coin->R[j]);
        poly_reduce_exact(&coin->R[j]);
        poly_inv_ntt(&s_t1.vec[j + D]);
        poly_reduce_exact(&s_t1.vec[j + D]);
        poly_add(&coin->R[j], &coin->R[j], &s_t1.vec[j + D]);
        poly_ntt(&coin->R[j]);
        poly_pointwise_montgomery(&coin->R[j], &coin->R[j], &x2_ntt);
        poly_inv_ntt_to_mont(&coin->R[j]);
        poly_inv_ntt(&s_t2.vec[j + D]);
        poly_reduce_exact(&s_t2.vec[j + D]);
        poly_add(&coin->R[j], &coin->R[j], &s_t2.vec[j + D]);
        poly_reduce(&coin->R[j]);

        // TAU2 - CHI*CHI*TAU - CHI*TAU1
        if (poly_chknorm(&coin->R[j], ((int64_t) TAU2 - BETA * BETA * TAU - BETA * TAU1)) != 0) {
            DEBUG_PRINT(("Rejected R_%d %d\n", j, poly_chknorm(&coin->R[j], ((int64_t) TAU2 - 2 * TAU1 * CHI))));
            goto rejection_point;
        }
    }

    // check norm of the aggregated vector and make hints
    poly_m s;
    poly_n tmp;
    poly_n tmp1;
    poly_n coin_t22;

    poly_m_set_zero(&s, 0, LACTX_N);
    for (i = 0; i < LACTX_L; i++) {
        poly_add(&s.vec[0], &s.vec[0], &coin->z[i]); // sum_{i=0}^{LACTX_L-1} z_i sum z_i

        poly_easy_mul(&z, &x2, i, 1);
        poly_sub(&z, &coin->z[i],  &z); // (z_i - x2rot(1, i))
        poly_ntt(&z);
        poly_set(&z_1, &coin->z[i]);
        poly_ntt(&z_1);
        poly_pointwise_montgomery(&z, &z, &z_1); // z_i(z_i - x2rot(1, i))
        poly_add(&s.vec[1], &s.vec[1], &z); // sum_{i=0}^{LACTX_L-1} z_i(z_i - x2rot(1, i))
    }
    poly_inv_ntt_to_mont(&s.vec[1]);
    poly_reduce_exact(&s.vec[1]);

    poly_ntt(&s.vec[0]);
    poly_pointwise_montgomery(&s.vec[0], &s.vec[0], &x1_ntt);
    poly_inv_ntt_to_mont(&s.vec[0]);
    poly_reduce_exact(&s.vec[0]);

    if (poly_chknorm(&s.vec[0], GAMMA1) != 0) {
        DEBUG_PRINT(("Rejected aggregated z\n"));
        goto rejection_point;
    }

    if (poly_chknorm(&s.vec[1], GAMMA1) != 0) {
        DEBUG_PRINT(("Rejected aggregated z\n"));
        goto rejection_point;
    }

    for (j = 0; j < LACTX_m - D; j++) {
        poly_set(&s.vec[j + D], &coin->R[j]);
    }

    // t2 = Hs - x2(x1u + t1)
    poly_m_ntt(&s);
    poly_matrix_mul(&coin_t22, ctx->H, &s);
    poly_n_inv_ntt_to_mont(&coin_t22);
    poly_n_reduce(&coin_t22); // Hs

    poly_n_set(&tmp, &coin->u);
    poly_n_roundup(&tmp, &tmp, u_ERROR);
    poly_n_ntt(&tmp);
    poly_n_pointwise_montgomery(&tmp, &tmp, &x1_ntt); // x1u
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_reduce(&tmp);
    poly_n_set(&tmp1, &coin->t1);
    poly_n_roundup(&tmp1, &tmp1, t1_ERROR);
    poly_n_add(&tmp, &tmp, &tmp1); // x1u + t1
    poly_n_reduce(&tmp);
    poly_n_ntt(&tmp);
    poly_n_pointwise_montgomery(&tmp, &tmp, &x2_ntt); // x2(x1u + t1)
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_reduce(&tmp);

    poly_n_sub(&coin_t22, &coin_t22, &tmp);
    poly_n_reduce(&coin_t22);

    poly_n_highbits(&coin_t22, &coin_t22, t2_ERROR);

    int res = poly_n_hints(&coin->t2_hints, &coin_t22, &coin_t2);
    if (res == -1) {
        DEBUG_PRINT(("rejected t2_hints\n"));
        goto rejection_point;
    }

    poly_n_makeup(&coin_t22, &coin->t2_hints);
    if (poly_n_compare(&coin_t22, &coin_t2) != 0) {
        DEBUG_PRINT(("not equal\n"));
    }

    return 0;
}


/**
 * Open a commitment and checks the committed value
 * @param ctx  - context object
 * @param coin - coin object
 * @param mask - the secret mask used to blind the coin amount (can be null for minted coins)
 * @param v - coin amount
 * @return 1 if the v is the committed value, otherwise returns 0.
 */
int lactx_coin_open(context_t *ctx, coin_t *coin, uint8_t mask[LACTX_m - D][r_BYTES], uint64_t v) {
    poly_m s_u;
    poly_n u;

    // Minting Transactions
    if (coin->s != 0) {
        poly_m_set_zero(&s_u, 0, LACTX_N);
        binary_set(&s_u.vec[0], coin->s);
    }
    // Normal Transaction
    else {
        binary_set(&s_u.vec[0], v);
        poly_set_zero(&s_u.vec[1], 0, LACTX_N);
        poly_set_zero(&s_u.vec[2], 0, LACTX_N);
        set_masks_tau(&s_u, mask);  // ||r|| < TAU
        if (poly_m_chknorm(&s_u, GAMMA1)) return 0;
    }

    poly_m_ntt(&s_u);
    poly_matrix_mul(&u, ctx->H, &s_u);
    poly_n_inv_ntt_to_mont(&u);
    poly_n_reduce(&u);

    poly_n_highbits(&u, &u, u_ERROR);
    return !poly_n_compare(&coin->u, &u);
}


/**
 * Verify a confidential coin bundle
 * @param ctx - the context object
 * @param coin - coin object
 * @return returns 1 if the coin bundle is valid, otherwise returns 0.
 */
int lactx_coin_verify(context_t *ctx, coin_t *coin) {

    int i, j;
    keccak_state state;
    uint8_t u_bytes[u_HIGHBITS];
    uint8_t t1_bytes[t1_HIGHBITS];
    uint8_t t2_bytes[t2_HIGHBITS];
    uint8_t x1_bytes[SEED_BYTES];
    uint8_t x2_bytes[SEED_BYTES];

    poly x1_ntt;
    poly x2;
    poly x2_ntt;
    poly z;
    poly z_1;
    poly_m s;
    poly_n coin_t2;
    poly_n tmp;
    poly_n tmp1;

    for (i = 0; i < LACTX_L; i++) {
        if (poly_chknorm(&coin->z[i], ALPHA)) {
            DEBUG_PRINT(("failed z_(%d)\n", i));
            return 0;
        }
    }
    for (j = 0; j < LACTX_m - D; j++) {
        if (poly_chknorm(&coin->R[j], TAU2)) {
            DEBUG_PRINT(("failed R_(%d)\n", j));
            return 0;
        }
    }

    // packing
    pack_poly_ring_custom(u_bytes, &coin->u, K1 - u_ERROR);
    pack_poly_ring_custom(t1_bytes, &coin->t1, K1 - t1_ERROR);

    // challenge 1: x1 = hash(u, t1)
    shake256_init(&state);
    shake256_absorb(&state, u_bytes, u_HIGHBITS);
    shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(x1_bytes, SEED_BYTES, &state);
    poly_challenge(&x1_ntt, x1_bytes);
    poly_ntt(&x1_ntt);

    // challenge 2
    poly_challenge(&x2, coin->x2);
    poly_set(&x2_ntt, &x2);
    poly_ntt(&x2_ntt);

    // s = [x1 sum_{i=0}^{LACTX_L-1} z_i, sum_{i=0}^{LACTX_L-1} z_i(z_i - x2rot(1, i)), 0^LACTX_N, R_0, .., R_(LACTX_m-3)]
    poly_m_set_zero(&s, 0, LACTX_N);
    for (i = 0; i < LACTX_L; i++) {
        poly_add(&s.vec[0], &s.vec[0], &coin->z[i]); // sum_{i=0}^{LACTX_L-1} z_i sum z_i

        poly_easy_mul(&z, &x2, i, 1);
        poly_sub(&z, &coin->z[i],  &z); // (z_i - x2rot(1, i))
        poly_ntt(&z);
        poly_set(&z_1, &coin->z[i]);
        poly_ntt(&z_1);
        poly_pointwise_montgomery(&z, &z, &z_1); // z_i(z_i - x2rot(1, i))
        poly_add(&s.vec[1], &s.vec[1], &z); // sum_{i=0}^{LACTX_L-1} z_i(z_i - x2rot(1, i))
    }
    poly_inv_ntt_to_mont(&s.vec[1]);
    poly_reduce_exact(&s.vec[1]);

    poly_ntt(&s.vec[0]);
    poly_pointwise_montgomery(&s.vec[0], &s.vec[0], &x1_ntt);
    poly_inv_ntt_to_mont(&s.vec[0]);
    poly_reduce_exact(&s.vec[0]);

    if (poly_chknorm(&s.vec[1], GAMMA1) != 0)
        return 0;

    for (j = 0; j < LACTX_m - D; j++) {
        poly_set(&s.vec[j + D], &coin->R[j]);
    }

    // t2 = Hs - x2(x1u + t1)
    poly_m_ntt(&s);
    poly_matrix_mul(&coin_t2, ctx->H, &s);
    poly_n_inv_ntt_to_mont(&coin_t2);
    poly_n_reduce(&coin_t2); // Hs

    poly_n_set(&tmp, &coin->u);
    poly_n_roundup(&tmp, &tmp, u_ERROR);
    poly_n_ntt(&tmp);
    poly_n_pointwise_montgomery(&tmp, &tmp, &x1_ntt); // x1u
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_reduce(&tmp);
    poly_n_set(&tmp1, &coin->t1);
    poly_n_roundup(&tmp1, &tmp1, t1_ERROR);
    poly_n_add(&tmp, &tmp, &tmp1); // x1u + t1
    poly_n_reduce(&tmp);
    poly_n_ntt(&tmp);
    poly_n_pointwise_montgomery(&tmp, &tmp, &x2_ntt); // x2(x1u + t1)
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_reduce(&tmp);

    poly_n_sub(&coin_t2, &coin_t2, &tmp);
    poly_n_reduce(&coin_t2);

    poly_n_highbits(&coin_t2, &coin_t2, t2_ERROR);
    poly_n_makeup(&coin_t2, &coin->t2_hints);
    pack_poly_ring_custom(t2_bytes, &coin_t2, K1 - t2_ERROR);

    // challenge 2: x2 = hash(u, t1, t2)
    shake256_init(&state);
    shake256_absorb(&state, u_bytes, u_HIGHBITS);
    shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
    shake256_absorb(&state, t2_bytes, t2_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(x2_bytes, SEED_BYTES, &state);

    return memcmp(x2_bytes, coin->x2, SEED_BYTES) == 0;
}

#endif /* LCTx_COMMITMENT_IMPL_H */
