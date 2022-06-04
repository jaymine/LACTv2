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

#ifndef LACTX_LACTX_HEADER_IMPL_H
#define LACTX_LACTX_HEADER_IMPL_H

#include <stdio.h>
#include "openssl/rand.h"
#include "lactx_store.h"
#include "util.h"
#include <math.h>

void lactx_header_print(header_t *a) {
    unsigned int i, l;
    // Normal coins
    printf("===================\nx0: ");
    printf("%d %d\n", a->in_len, a->out_len);
    for (l = 0; l < 5; l++)
        printf("%d ", a->x0[l]);
    printf("\n");
    printf("pk: \n");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->pk.vec[0].coef[l]);
    printf("\n");
    printf("sigma: \n");
    for (l = 0; l < 5; l++)
        printf("%ld ", a->sigma[0].coef[l]);
    printf("\n");
    if (a->v_in == 0 && a->v_out == 0) {
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
        printf("z0: ");
        if (a->in_len >= 2) {
            for (l = 0; l < 5; l++)
                printf("%ld ", a->z0[0].coef[l]);
            printf("\n");
        }
        if (a->out_len >= 2) {
            printf("z1: ");
            for (l = 0; l < 5; l++)
                printf("%ld ", a->z1[0].coef[l]);
            printf("\n");
        }
        printf("R: ");
        for (l = 0; l < 5; l++)
            printf("%ld ", a->R[0].coef[l]);
        printf("\n");
    }
    printf("=================\n");
}

unsigned int get_carry_range(unsigned int additions) {
    return (unsigned int)ceil(log2(additions == 0 ? 0: additions));
}

int lactx_header_init(
        header_t *header,
        unsigned int out_len,
        unsigned int int_len
) {
    header->z0 = (poly *) malloc(L * get_carry_range(int_len) * sizeof(poly));
    header->z1 = (poly *) malloc(L * get_carry_range(out_len) * sizeof(poly));
    return 1;
}

int lactx_header_free(header_t *header) {
    free(header->z0);
    free(header->z1);
    return 1;
}

/**
 * Set headers such that c = [0, [sum_{i=1}^{len} b_{i,j} + c_{j-1}]_{j=0}^{l-1}, 0]
 * @param c - header polynomial
 * @param v - value vector
 * @param len - number of values in v which can be [0, 2].
 */
void set_carries(poly *c, const uint64_t *v, unsigned int len) {
    unsigned int i, j;
    poly_set_zero(c, 0, N);
    int64_t tmp;
    c->coef[0] = 0;
    for (j = 0; j < L; j++) {
        tmp = 0;
        for (i = 0; i < len; i++) {
            tmp += ((int64_t) (v[i] >> j) & (int64_t) 1);
        }
        c->coef[j + 1] = (tmp + c->coef[j])/2;
    }
}

/**
 * Set c_hat = sum_{i=0}^{L-1} sum_0^{carry_range}(d_i^l * rot(2c_i^l - 1, j)) such that c_i = sum(2^lc_i^l)
 * @param c_hat - output polynomial (not in NTT domain)
 * @param c - header polynomial (not in NTT domain)
 * @param d - blinding polynomial (not in NTT domain)
 */
void set_carries_hat(poly *c_hat, const poly *c, poly d[][L + 1], unsigned int carry_range) {
    unsigned int j, l;
    poly_set_zero(c_hat, 0, N);
    poly z;
    for (j = 1; j < L; j++) {
        for (l = 0; l < carry_range; l++) {
            poly_easy_mul(&z, &d[l][j], j*carry_range + l,
                          (int) (2 * ((c->coef[j] >> l) & 1) - 1));
            poly_add(c_hat, c_hat, &z);
        }
    }
    poly_reduce(c_hat);
}

/**
 * Set d0_hat = sum_(j=0)^(L-1) (d0_j)^(d0_j)
 * @param d_hat - output (not in NTT)
 * @param d_ntt - input in NTT
 * @param carry_range
 */
void set_d_hat(poly *d_hat, poly d_ntt[][L + 1], unsigned int carry_range) {
    unsigned int j, l;
    poly_set_zero(d_hat, 0, N);
    poly z;
    for (j = 1; j < L; j++) {
        for (l = 0; l < carry_range; l++) {
            poly_pointwise_montgomery(&z, &d_ntt[l][j], &d_ntt[l][j]);
            poly_add(d_hat, d_hat, &z);
        }
    }
    poly_inv_ntt_to_mont(d_hat);
    poly_reduce(d_hat);
}

/**
 * Creates z_hat = ∑_(i=0)^(L−1) z0_i(z0_i−x2rot(1,i))
 * @param z_hat - output
 * @param z -  z[L] (not in NTT domain)
 * @param z_ntt - z[L] (in NTT domain)
 * @param x2 - challenge (not in NTT domain)
 */
void set_z_hat(poly *z_hat, poly z[], poly z_ntt[][L + 1], poly *x2, unsigned int carry_range) {
    unsigned int i, l;
    poly_set_zero(z_hat, 0, N);
    poly tmp;
    for (i = 1; i < L; i++) {
        for (l = 0; l < carry_range; l++) {
            poly_easy_mul(&tmp, x2, i*carry_range + l, 1);
            poly_sub(&tmp, &z[i*carry_range + l], &tmp); // (z_j - x2rot(1, j))
            poly_ntt(&tmp);
            poly_pointwise_montgomery(&tmp, &tmp, &z_ntt[l][i]); // z_j(z_j - x2rot(1, j))
            poly_add(z_hat, z_hat, &tmp); // sum_{i=0}^{L-1} z_i(z_i - x2rot(1, i))
        }
    }
    poly_inv_ntt_to_mont(z_hat);
    poly_reduce_exact(z_hat);
}

void set_s_hat(poly *s_hat, poly z[], unsigned int carry_range) {
    unsigned int i, l;
    poly_set_zero(s_hat, 0, N);
    poly tmp;
    for (i = 1; i < L; i++) {
        for (l = 0; l < carry_range; l++) {
            poly_easy_mul(&tmp, &z[i*carry_range + l], i*carry_range + l, 1);
            poly_add(s_hat, s_hat, &tmp); // sum_{i=0}^{L-1} z_i(z_i - x2rot(1, i))
        }
    }
    poly_reduce_exact(s_hat);
}

void set_s_hat_pp(poly *z_hat_pp, poly z_ntt[][L + 1], unsigned int carry_range) {
    unsigned int i, l;
    poly_set_zero(z_hat_pp, 0, N);
    poly tmp;
    for (i = 1; i < L; i++) {
        for (l = 0; l < carry_range; l++) {
            poly_pointwise_montgomery(&tmp, &z_ntt[l][i], &z_ntt[l][i]); // z_j(z_j - x2rot(1, j))
            poly_add(z_hat_pp, z_hat_pp, &tmp); // sum_{i=0}^{L-1} z_i(z_i - x2rot(1, i))
        }
    }
    poly_inv_ntt_to_mont(z_hat_pp);
    poly_reduce_exact(z_hat_pp);
}

/**
 * Set d_hat_p = sum_{j=0}^{L-1} d_j - 2(d_{j+1}) * rot(N - 1, -1)
 * @param d_hat_p - output polynomial (not in NTT domain)
 * @param d - blinding polynomial (not in NTT domain) [L + 1][carry_range]
 */
void set_d_hat_p(poly *d_hat_p, poly d[][L + 1], unsigned int carry_range) {
    unsigned int j, l;
    poly_set_zero(d_hat_p, 0, N);
    poly tmp, d_ntt;
    for (j = 0; j < L; j++) {
        for (l = 0; l < carry_range; l++) {
            if (j + 1 < L) {
                poly_easy_mul(&tmp, &d[l][j + 1], N - ((j + 1) * carry_range + l) + (j + 1) - 1, -(1 << l));
                poly_sub(d_hat_p, d_hat_p, &tmp);
                poly_sub(d_hat_p, d_hat_p, &tmp);
            }
            poly_easy_mul(&tmp, &d[l][j], N - (j*carry_range + l) + j, -(1 << l));
            poly_add(d_hat_p, d_hat_p, &tmp);
        }
    }
}

/**
 * Set z_hat_p = sum_{j=0}^{L-1} z_j - 2(z_{j+1}) * rot(N - 1, -1)
 * @param z_hat_p - output polynomial (not in NTT domain)
 * @param z - blinding polynomial (in NTT domain) [L + 1][carry_range]
 */
void set_z_hat_p(poly *z_hat_p, poly z[], unsigned int carry_range) {
    unsigned int j, l;
    poly_set_zero(z_hat_p, 0, N);
    poly tmp;
    poly_set_zero(&tmp, 0, N);
    for (j = 0; j < L; j++) {
        for (l = 0; l < carry_range; l++) {
            if (j + 1 < L) {
                poly_easy_mul(&tmp, &z[(j + 1) * carry_range + l], N - ((j + 1) * carry_range + l) + (j + 1) - 1,
                              -(1 << l));
                poly_sub(z_hat_p, z_hat_p, &tmp);
                poly_sub(z_hat_p, z_hat_p, &tmp);
            }
            poly_easy_mul(&tmp, &z[j*carry_range + l], N - (j*carry_range + l) + j, -(1 << l));
            poly_add(z_hat_p, z_hat_p, &tmp);
        }
    }
    poly_reduce_exact(z_hat_p);
}

/**
 * Create a carry proof and return its secret mask
 * @param ctx - context object
 * @param s_u - carry proof's mask (output)
 * @param header - header object (will be generated here)
 * @param out_len - number of of output coin bundles [1 or 2]
 * @param out_coins - input coin bundles (will be generated here)
 * @param out_masks - input coin masks (will be assigned here)
 * @param v_out - output coin amounts
 * @param in_len - number of of input coin bundles [1 or 2]
 * @param in_coins - input coin bundles (should be given)
 * @param in_masks - input coin masks (should be given)
 * @param v_in - input coin amounts
 */
void lactx_header_carry(
        context_t *ctx,
        poly_m *s_u,
        header_t *header,
        unsigned int out_len,
        coin_t *out_coins,
        uint8_t out_masks[][m - D][r_BYTES],
        uint64_t *v_out,
        unsigned int in_len,
        coin_t *in_coins,
        uint8_t in_masks[][m - D][r_BYTES],
        uint64_t *v_in) {

    keccak_state state;

    unsigned int in_carries = get_carry_range(in_len);
    unsigned int out_carries = get_carry_range(out_len);
    int in_carry_bits = ALPHA_BITS + ceil(log2(in_len - 1)/2);
    int out_carry_bits = ALPHA_BITS + ceil(log2(out_len - 1)/2);
    int in_alpha = (1 << in_carry_bits);
    int out_alpha = (1 << out_carry_bits);

    poly c0;
    poly c1;
    poly c0_hat;
    poly c1_hat;
    poly c0_hat_p;
    poly c1_hat_p;
    uint8_t d0_seed[in_carries][L][N/8 * (in_carry_bits + 1)];
    poly d0[in_carries][(L+1)];
    poly d0_ntt[in_carries][(L+1)];
    uint8_t d1_seed[out_carries][L][N/8 * (out_carry_bits + 1)];
    poly d1[out_carries][(L+1)];
    poly d1_ntt[out_carries][(L+1)];

    poly d0_hat;
    poly d1_hat;
    poly d0_hat_p;
    poly d1_hat_p;

    uint8_t r_bytes[out_len][m - D][r_BYTES];
    uint8_t r1_bytes[out_len][m - D][r1_BYTES];
    uint8_t r2_bytes[out_len][m - D][r2_BYTES];

    poly_m s;
    poly_m s_t1;
    poly_m s_t2;

    poly_n header_t2;

    uint8_t u_bytes[u_HIGHBITS];
    uint8_t t1_bytes[t1_HIGHBITS];
    uint8_t t2_bytes[t2_HIGHBITS];
    uint8_t x1_bytes[SEED_BYTES];

    poly x1_ntt;
    poly x2;
    poly x2_ntt;

    poly tmp;
    poly_n tmpn;

    header->v_in = 0;
    header->v_out = 0;

    unsigned int i, j, l;

    // Create output coins
    for (i = 0; i < out_len; i++) {
        lactx_coin_create(ctx, &out_coins[i], out_masks[i], v_out[i]);
    }

    // Create carry proof
    rejection_point_carry:

    header->in_len = in_len;
    header->out_len = out_len;

    // Create delta
    pack_poly_ring_custom(u_bytes, &out_coins[0].u, K1 - u_ERROR);
    coin_hash(ctx, header->delta, u_bytes);
    uint8_t tmp_delta[ORIGAMI_HASH_BYTES];
    for (i = 1; i < header->out_len; i++) {
        pack_poly_ring_custom(u_bytes, &out_coins[i].u, K1 - u_ERROR);
        coin_hash(ctx, tmp_delta, u_bytes);
        hash_self_mul(header->delta, tmp_delta, ctx->bn_q, ctx->bn_ctx);
    }
    for (i = 0; i < header->in_len; i++) {
        pack_poly_ring_custom(u_bytes, &in_coins[i].u, K1 - u_ERROR);
        coin_hash(ctx, tmp_delta, u_bytes);
        hash_self_div(header->delta, tmp_delta, ctx->bn_q, ctx->bn_ctx);
    }

    // Create input carriers if there are two inputs.
    if (header->in_len >= 2) {
        set_carries(&c0, v_in, in_len); // c0
        poly_set_zero(&c0_hat, 0, N);
        poly_set_zero(&c0_hat_p, 0, N);
        poly_set_zero(&d0_hat, 0, N);
        poly_set_zero(&d0_hat_p, 0, N);
        for (j = 0; j < L; j++) {
            // c0_hat_p = [c0_j - 2c0_(j+1)]_(j=0)^(L-1)
            c0_hat_p.coef[j] = c0.coef[j] - 2*c0.coef[j + 1];
        }

        // Carry Masks
        for (l = 0; l < in_carries; l++)
            get_custom_value_masks(d0[l], d0_seed[l], &c0, in_carry_bits);

        // Set zeros for j = 0 and j = L
        for (l = 0; l < in_carries; l++) {
            poly_set_zero(&d0[l][0], 0, N);
            poly_set_zero(&d0_ntt[l][0], 0, N);
            poly_set_zero(&d0[l][L], 0, N);
            poly_set_zero(&d0_ntt[l][L], 0, N);
        }

        for (l = 0; l < in_carries; l++) {
            for (j = 1; j < L; j++) {
                poly_set(&d0_ntt[l][j], &d0[l][j]);
                poly_ntt(&d0_ntt[l][j]);
            }
        }
        // c0_hat = sum_{j=0}^{L-1} d0_j * rot(2c0_j - 1, j)
        set_carries_hat(&c0_hat, &c0, d0, in_carries);
        set_d_hat(&d0_hat, d0_ntt, in_carries);

        // d0_hat_p = sum_{j=0}^{L-1} d0_j - 2(d0_{j+1}) * rot(1, 1)
        set_d_hat_p(&d0_hat_p, d0, in_carries);
    }

    // Create output headers if there are two outputs.
    if (header->out_len >= 2) {
        set_carries(&c1, v_out, out_len); // c1
        poly_set_zero(&c1_hat, 0, N);
        poly_set_zero(&c1_hat_p, 0, N);
        poly_set_zero(&d1_hat, 0, N);
        poly_set_zero(&d1_hat_p, 0, N);
        for (j = 0; j < L; j++) {
            // c1_hat_p = [c1_j - 2c1_(j+1)]_(j=0)^(L-1)
            c1_hat_p.coef[j] = c1.coef[j] - 2*c1.coef[j + 1];
        }
        // Carry Masks
        for (l = 0; l < out_carries; l++)
            get_custom_value_masks(d1[l], d1_seed[l], &c1, out_carry_bits);

        // Set zeros for j = 0 and j = L
        for (l = 0; l < out_carries; l++) {
            poly_set_zero(&d1[l][0], 0, N);
            poly_set_zero(&d1_ntt[l][0], 0, N);
            poly_set_zero(&d1[l][L], 0, N);
            poly_set_zero(&d1_ntt[l][L], 0, N);
        }

        for (l = 0; l < out_carries; l++) {
            for (j = 1; j < L; j++) {
                poly_set(&d1_ntt[l][j], &d1[l][j]);
                poly_ntt(&d1_ntt[l][j]);
            }
        }
        // c1_hat = sum_{j=0}^{L-1} d1_j * rot(2c1_j - 1, j)
        set_carries_hat(&c1_hat, &c1, d1, out_carries);
        set_d_hat(&d1_hat, d1_ntt, out_carries);

        // d1_hat_p = sum_{j=0}^{L-1} d1_j - 2(d1_{j+1}) * rot(1, 1)
        set_d_hat_p(&d1_hat_p, d1, out_carries);
    }

    // Assign u, t1, R, t2 if in_len >= 2 or out_len >= 2.
    if (header->in_len >= 2 || header->out_len >= 2) {
        poly_m_set_zero(s_u, 0, N);
        poly_m_set_zero(&s_t1, 0, N);
        poly_m_set_zero(&s_t2, 0, N);

        // u_i = H[0^N, 0^N, r_0, .., r_(m-3)]
        // t1_i = H[0^N, 0^N, r_(1,0), .., r_(1, m-3)]
        // t2_i = H[0^N, 0^N, r_(2,0), .., r_(2, m-3)]
        poly_m_set_zero(&s, 0, N);
        get_masks_tau(&s, r_bytes[0]);
        poly_m_add(s_u, s_u, &s);

        poly_m_set_zero(&s, 0, N);
        get_masks_tau1(&s, r1_bytes[0]);
        poly_m_add(&s_t1, &s_t1, &s);

        poly_m_set_zero(&s, 0, N);
        get_masks_tau2(&s, r2_bytes[0]);
        poly_m_add(&s_t2, &s_t2, &s);

        if (header->in_len >= 2) {
            // u_i = H[-c0_hat_p, 0^N, 0^N, r_0, .., r_(m-3)]
            // t1_i = H[0^N, 0^N, c0_hat, r_(1,0), .., r_(1, m-3)]
            // t2_i = H[-d0_hat_p, 0^N, d0_hat, r_(2,0), .., r_(2, m-3)]
            poly_sub(&s_u->vec[0], &s_u->vec[0], &c0_hat_p);
            poly_add(&s_t1.vec[2], &s_t1.vec[2], &c0_hat);
            poly_sub(&s_t2.vec[0], &s_t2.vec[0], &d0_hat_p);
            poly_add(&s_t2.vec[2], &s_t2.vec[2], &d0_hat);
        }
        if (header->out_len >= 2) {
            // u_i = H[c1_hat_p - c0_hat_p, 0^N, 0^N, r_0, .., r_(m-3)]
            // t1_i = H[0^N, c1_hat, c0_hat, r_(1,0), .., r_(1, m-3)]
            // t2_i = H[d1_hat_p - d0_hat_p, d1_hat, d0_hat, r_(2,0), .., r_(2, m-3)]
            poly_add(&s_u->vec[0], &s_u->vec[0], &c1_hat_p);
            poly_add(&s_t1.vec[1], &s_t1.vec[1], &c1_hat);
            poly_add(&s_t2.vec[0], &s_t2.vec[0], &d1_hat_p);
            poly_add(&s_t2.vec[1], &s_t2.vec[1], &d1_hat);
        }

        poly_m_ntt(s_u);
        poly_matrix_mul(&header->u, ctx->H, s_u);
        poly_n_inv_ntt_to_mont(&header->u);
        poly_n_reduce(&header->u);
        poly_n_highbits(&header->u, &header->u, u_ERROR);

        poly_m_ntt(&s_t1);
        poly_matrix_mul(&header->t1, ctx->H, &s_t1);
        poly_n_inv_ntt_to_mont(&header->t1);
        poly_n_reduce(&header->t1);
        poly_n_highbits(&header->t1, &header->t1, t1_ERROR);

    }


    if (in_len >= 2 || out_len >= 2) {
        pack_poly_ring_custom(u_bytes, &header->u, K1 - u_ERROR);
        pack_poly_ring_custom(t1_bytes, &header->t1, K1 - t1_ERROR);

        // challenge 1: x1 = hash(u, t1)
        shake256_init(&state);
        shake256_absorb(&state, u_bytes, u_HIGHBITS);
        shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
        shake256_finalize(&state);
        shake256_squeeze(x1_bytes, SEED_BYTES, &state);
        poly_challenge(&x1_ntt, x1_bytes);
        poly_ntt(&x1_ntt);

        // t2_i = H[x1(d1_hat_p - d0_hat_p), d1_hat - d0_hat, r_(2,0), .., r_(2, m-3)]
        poly_m_ntt(&s_t2);
        poly_pointwise_montgomery(&s_t2.vec[0], &s_t2.vec[0], &x1_ntt);
        poly_inv_ntt_to_mont(&s_t2.vec[0]);
        poly_reduce_exact(&s_t2.vec[0]);
        poly_ntt(&s_t2.vec[0]);
        poly_matrix_mul(&header_t2, ctx->H, &s_t2);
        poly_n_inv_ntt_to_mont(&header_t2);
        poly_n_reduce(&header_t2);
        poly_n_highbits(&header_t2, &header_t2, t2_ERROR);

        pack_poly_ring_custom(t2_bytes, &header_t2, K1 - t2_ERROR);

        // challenge 2: x2 = hash(u, t1, t2)
        shake256_init(&state);
        shake256_absorb(&state, u_bytes, u_HIGHBITS);
        shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
        shake256_absorb(&state, t2_bytes, t2_HIGHBITS);
        shake256_finalize(&state);
        shake256_squeeze(header->x2, SEED_BYTES, &state);
        poly_challenge(&x2, header->x2);
        poly_set(&x2_ntt, &x2);
        poly_ntt(&x2_ntt);

        if (in_len >= 2) {
            // z0_i = x2rot(c0_i, i) + d0_i
            for (i = 0; i < L; i++) {
                for (l = 0; l < in_carries; l++) {
                    poly_set_zero(&header->z0[l], 0, N);
                    if (c0.coef[i] == 0) {
                        poly_set(&header->z0[i*in_carries + l], &d0[l][i]);
                    } else {
                        poly_easy_mul(&tmp, &x2, i*in_carries + l, (int) ((c0.coef[i]) >> l) & 1);
                        poly_add(&header->z0[i*in_carries + l], &tmp, &d0[l][i]);
                    }
                    // Even though the valid range is [-(ALPHA - 1), ALPHA - 1],
                    // the secure range is [-(ALPHA - 2), ALPHA - 2] to prevent data leakage
                    if (poly_chknorm(&header->z0[i], in_alpha - 1) != 0) {
                        DEBUG_PRINT(("Rejected header z0_%d %d\n", i, poly_chknorm(&header->z0[i*in_carries + l], in_alpha - 1)));
                        goto rejection_point_carry;
                    }
                }
            }
        }

        if (out_len >= 2) {
            // z1_i = x2rot(c1_i, i) + d1_i
            for (i = 0; i < L; i++) {
                for (l = 0; l < out_carries; l++) {
                    poly_set_zero(&header->z1[l], 0, N);
                    if (c1.coef[i] == 0) {
                        poly_set(&header->z1[i*out_carries + l], &d1[l][i]);
                    } else {
                        poly_easy_mul(&tmp, &x2, i*out_carries + l, (int) ((c1.coef[i]) >> l) & 1);
                        poly_add(&header->z1[i*out_carries + l], &tmp, &d1[l][i]);
                    }

                    // Even though the valid range is [-(ALPHA - 1), ALPHA - 1],
                    // the secure range is [-(ALPHA - 2), ALPHA - 2] to prevent data leakage
                    if (poly_chknorm(&header->z1[i], out_alpha - 1) != 0) {
                        DEBUG_PRINT(("Rejected header z1_%d %d\n", i, poly_chknorm(&header->z1[i*out_carries + l], out_alpha - 1)));
                        goto rejection_point_carry;
                    }
                }
            }
        }

        // R_i = x2(x1*r + r1) + r2
        poly_m_inv_ntt(&s_t1);
        poly_m_reduce(&s_t1);
        poly_m_inv_ntt(&s_t2);
        poly_m_reduce(&s_t2);
        for (j = 0; j < m - D; j++) {
            poly_pointwise_montgomery(&header->R[j], &s_u->vec[j + D], &x1_ntt);
            poly_inv_ntt_to_mont(&header->R[j]);
            poly_add(&header->R[j], &header->R[j], &s_t1.vec[j + D]);
            poly_ntt(&header->R[j]);
            poly_pointwise_montgomery(&header->R[j], &header->R[j], &x2_ntt);
            poly_inv_ntt_to_mont(&header->R[j]);
            poly_add(&header->R[j], &header->R[j], &s_t2.vec[j + D]);
            poly_reduce_exact(&header->R[j]);

            if (poly_chknorm(&header->R[j], ((int64_t) TAU2 - BETA * BETA * TAU - BETA * TAU1)) != 0) {
                DEBUG_PRINT(("Rejected header R_%d %d\n", j, poly_chknorm(&header->R[j],
                                                                           ((int64_t) GAMMA2- 8*TAU1*CHI))));
                goto rejection_point_carry;
            }
        }

    }

    // Set hints for t2
    poly_n header_t22;

    if (header->in_len >= 2 || header->out_len >= 2) {

        poly_m_set_zero(&s, 0, N);
        if (header->in_len >= 2) {
            poly header_z0_ntt[in_carries][L + 1];
            for (l = 0; l < in_carries; l++) {
                poly_set_zero(&header_z0_ntt[l][0], 0, N);
                poly_set_zero(&header_z0_ntt[l][L], 0, N);
                for (j = 0; j < L; j++) {
                    poly_set(&header_z0_ntt[l][j], &header->z0[j*in_carries + l]);
                    poly_ntt(&header_z0_ntt[l][j]);
                }
            }

            set_z_hat_p(&tmp, header->z0, in_carries);
            poly_sub(&s.vec[0],&s.vec[0], &tmp);

            set_z_hat(&s.vec[2], header->z0, header_z0_ntt, &x2, in_carries);
            set_s_hat(&header->s0_hat, header->z0, in_carries);
            set_s_hat_pp(&header->s0_hat_pp, header_z0_ntt, in_carries);

            poly_ntt(&header->s0_hat);
            poly_pointwise_montgomery(&tmp, &header->s0_hat, &x2_ntt);
            poly_inv_ntt_to_mont(&tmp);
            poly_sub(&tmp, &header->s0_hat_pp, &tmp);
            poly_reduce_exact(&tmp);
            CHECK(poly_compare(&tmp, &s.vec[2]) == 0);
        }

        if (header->out_len >= 2) {
            poly header_z1_ntt[out_carries][L+1];
            for (l = 0; l < out_carries; l++) {
                poly_set_zero(&header_z1_ntt[l][0], 0, N);
                poly_set_zero(&header_z1_ntt[l][L], 0, N);
                for (j = 0; j < L; j++) {
                    poly_set(&header_z1_ntt[l][j], &header->z1[j*out_carries + l]);
                    poly_ntt(&header_z1_ntt[l][j]);
                }
            }

            set_z_hat_p(&tmp, header->z1, out_carries);
            poly_add(&s.vec[0],&s.vec[0], &tmp);

            set_z_hat(&s.vec[1], header->z1, header_z1_ntt, &x2, out_carries);
            set_s_hat(&header->s1_hat, header->z1, out_carries);
            set_s_hat_pp(&header->s1_hat_pp, header_z1_ntt, out_carries);

            poly_ntt(&header->s1_hat);
            poly_pointwise_montgomery(&tmp, &header->s1_hat, &x2_ntt);
            poly_inv_ntt_to_mont(&tmp);
            poly_sub(&tmp, &header->s1_hat_pp, &tmp);
            poly_reduce_exact(&tmp);
            CHECK(poly_compare(&tmp, &s.vec[1]) == 0);
        }

        poly_set(&header->s_hat_p, &s.vec[0]);

        poly_ntt(&s.vec[0]);
        poly_pointwise_montgomery(&s.vec[0], &s.vec[0], &x1_ntt);
        poly_inv_ntt_to_mont(&s.vec[0]);

        // Check aggregate z
        // z0_hat = ∑_(i=0)^(L−1)(z0_j− 2z0_j+1rot(1,i)
        if (poly_chknorm(&s.vec[1], ZAGG) != 0) {
            DEBUG_PRINT(("Rejected aggregated z1\n"));
            goto rejection_point_carry;;
        }

        if (poly_chknorm(&s.vec[2], ZAGG) != 0) {
            DEBUG_PRINT(("Rejected aggregated z1\n"));
            goto rejection_point_carry;;
        }

        for (j = 0; j < m - D; j++) {
            poly_set(&s.vec[j + D], &header->R[j]);
        }

        poly_n tmp1;

        poly_m_ntt(&s);
        poly_matrix_mul(&header_t22, ctx->H, &s);
        poly_n_roundup(&tmpn, &header->u, u_ERROR);
        poly_n_ntt(&tmpn);
        poly_n_pointwise_montgomery(&tmpn, &tmpn, &x1_ntt); // x1u
        poly_n_inv_ntt_to_mont(&tmpn);
        poly_n_roundup(&tmp1, &header->t1, t1_ERROR);
        poly_n_add(&tmpn, &tmpn, &tmp1); // x1u + t1
        poly_n_reduce(&tmpn);
        poly_n_ntt(&tmpn);
        poly_n_pointwise_montgomery(&tmpn, &tmpn, &x2_ntt); // x2(x1u + t1)
        poly_n_sub(&header_t22, &header_t22, &tmpn);
        poly_n_inv_ntt_to_mont(&header_t22);
        poly_n_reduce(&header_t22);
        poly_n_highbits(&header_t22, &header_t22, t2_ERROR);

        int res = poly_n_hints(&header->t2_hints, &header_t22, &header_t2);
        if (res == -1) {
            DEBUG_PRINT(("rejected t2_hints\n"));
            goto rejection_point_carry;
        }
    }
}

/**
 * Creates a header when all the inputs and outputs are belong to the SAME participant.
 * @param ctx - context object
 * @param header - header object (will be generated here)
 * @param out_len - number of of output coin bundles [1 or 2]
 * @param out_coins - input coin bundles (will be generated here)
 * @param out_masks - input coin masks (will be assigned here)
 * @param v_out - output coin amounts
 * @param in_len - number of of input coin bundles [1 or 2]
 * @param in_coins - input coin bundles (should be given)
 * @param in_masks - input coin masks (should be given)
 * @param v_in - input coin amounts
 */
int lactx_header_create(
        context_t *ctx,
        header_t *header,
        unsigned int out_len,
        coin_t *out_coins,
        uint8_t out_masks[][m - D][r_BYTES],
        uint64_t *v_out,
        unsigned int in_len,
        coin_t *in_coins,
        uint8_t in_masks[][m - D][r_BYTES],
        uint64_t *v_in) {


    unsigned int i, j;

    if (in_len > MAX_ADDITIONS || out_len > MAX_ADDITIONS) return 0;
    if (!test_mode_carrier) {
        uint64_t total_in = 0;
        uint64_t total_out = 0;
        for (i = 0; i < in_len; i++) total_in += v_in[i];
        for (i = 0; i < out_len; i++) total_out += v_out[i];
        if (total_in != total_out) {
            DEBUG_PRINT(("incorrect amounts\n"));
            return 0;
        }
    }

    keccak_state state;

    poly_n header_y;
    uint8_t pk_bytes[pk_HIGHBITS];
    uint8_t y_bytes[y_HIGHBITS];
    uint8_t sig_bytes[get_sig_bytes(in_len, out_len)];

    poly x0_ntt;
    uint8_t r3_bytes[out_len][m - D][r3_BYTES];

    poly tmp;
    poly_n tmpn;

    poly_m s;
    poly_m s_u;
    poly_m s_y;

    // Create the carry proof
    lactx_header_carry(ctx,
                       &s_u,
                       header,
                       out_len, out_coins, out_masks, v_out,
                       in_len, in_coins, in_masks, v_in);


    rejection_point_sig:

    // Create the summation proof
    // pk = sum out.u'_i - sum in.u_i + sum header.u_i
    // y = sum_{i=0}^{out_len - 1} y_i
    poly_n_set_zero(&header->pk, 0, N);
    poly_n_set_zero(&header_y, 0, N);
    poly_m_set_zero(&s_y, 0, N);
    for (j = 0; j < m - D; j++) {
        poly_set_zero(&header->sigma[j], 0, N);
    }
    for (i = 0; i < in_len; i++) {
        poly_n_sub(&header->pk, &header->pk, &in_coins[i].u);
        for (j = 0; j < m - D; j++) {
            set_mask_tau(&tmp, in_masks[i][j]);
            poly_sub(&header->sigma[j], &header->sigma[j], &tmp);
        }
    }

    for (i = 0; i < out_len; i++) {
        poly_n_add(&header->pk, &header->pk, &out_coins[i].u);
        for (j = 0; j < m - D; j++) {
            set_mask_tau(&tmp, out_masks[i][j]);
            poly_add(&header->sigma[j], &header->sigma[j], &tmp);

            get_mask_tau3(&tmp, r3_bytes[i][j]);
            poly_add(&s_y.vec[j + D], &s_y.vec[j + D], &tmp);
        }
    }

    if (header->in_len >= 2 || header->out_len >= 2) {
        poly_n_add(&header->pk, &header->pk, &header->u);
        for (j = 0; j < m - D; j++) {
            poly_set(&tmp, &s_u.vec[j + D]);
            poly_inv_ntt(&tmp);
            poly_reduce_exact(&tmp);
            poly_add(&header->sigma[j], &header->sigma[j], &tmp);
        }
    }

    poly_n_roundup(&header->pk, &header->pk, pk_ERROR);
    poly_n_reduce(&header->pk);
    poly_n_highbits(&header->pk, &header->pk, pk_ERROR);

    poly_m_ntt(&s_y);
    poly_matrix_mul(&header_y, ctx->H, &s_y);
    poly_n_inv_ntt_to_mont(&header_y);
    poly_n_reduce(&header_y);
    poly_n_highbits(&header_y, &header_y, y_ERROR);

    pack_poly_ring_custom(pk_bytes, &header->pk, K1 - pk_ERROR);
    pack_poly_ring_custom(y_bytes, &header_y, K1 - y_ERROR);

    // Challenge 0: x0 = hash(pk, y)
    shake256_init(&state);
    shake256_absorb(&state, pk_bytes, pk_HIGHBITS);
    shake256_absorb(&state, y_bytes, y_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(header->x0, SEED_BYTES, &state);
    poly_challenge(&x0_ntt, header->x0);
    poly_ntt(&x0_ntt);

    // Create the one-time signature
    for (j = 0; j < m - D; j++) {
        poly_ntt(&header->sigma[j]);
        poly_pointwise_montgomery(&header->sigma[j], &header->sigma[j], &x0_ntt);
        poly_inv_ntt_to_mont(&header->sigma[j]);
        poly_inv_ntt(&s_y.vec[j + D]);
        poly_add(&header->sigma[j], &header->sigma[j], &s_y.vec[j + D]);
        poly_reduce_exact(&header->sigma[j]);
        if (poly_chknorm(&header->sigma[j], (header->out_len + header->in_len) * (TAU3 - BETA))) {
            DEBUG_PRINT(("Rejected sigma_%d %ld\n", j, v_in[0]));
            goto rejection_point_sig;
        }
    }

    // Set hints for y
    poly_n header_y2;
    poly_m_set_zero(&s, 0, N);
    for (j = 0; j < m - D; j++) {
        poly_set(&s.vec[j + D], &header->sigma[j]);
        poly_ntt(&s.vec[j + D]);
    }

    poly_matrix_mul(&header_y2, ctx->H, &s);
    poly_n_inv_ntt_to_mont(&header_y2);
    poly_n_reduce(&header_y2);

    poly_n_set(&tmpn, &header->pk);
    poly_n_roundup(&tmpn, &tmpn, pk_ERROR);
    poly_n_ntt(&tmpn);
    poly_n_pointwise_montgomery(&tmpn, &tmpn, &x0_ntt);
    poly_n_inv_ntt_to_mont(&tmpn);
    poly_n_sub(&header_y2, &header_y2, &tmpn);
    poly_n_reduce(&header_y2);
    poly_n_highbits(&header_y2, &header_y2, y_ERROR);

    int res = poly_n_hints(&header->y_hints, &header_y2, &header_y);
    if (res == -1) {
        DEBUG_PRINT(("rejected y_hints\n"));
        goto rejection_point_sig;
    }

    return 1;
}


/**
 * Creates a header to transfer coins from the coinbase account.
 * @param ctx - context object
 * @param header - header object (will be generated here)
 * @param out_coins - input coin bundles (will be generated here)
 * @param out_mask - input coin masks (will be assigned here)
 * @param v_out - output coin amounts
 * @param in_coins - input coin bundles (should be given)
 * @param coinbase - input coin amount
 * @return 0 if v_out < coinbase
 */
int lactx_minted_header_create(
        context_t *ctx,
        header_t *header,
        coin_t *out_coins,
        uint8_t out_mask[m - D][r_BYTES],
        uint64_t v_out,
        coin_t *in_coins,
        uint64_t coinbase) {

    unsigned int j;

    if (v_out > coinbase) return 0;

    poly c1;
    poly c1_hat_p;

    poly_m s_u;
    poly_m s_y;

    poly_n header_y;

    uint8_t u_bytes[u_HIGHBITS];
    uint8_t pk_bytes[pk_HIGHBITS];
    uint8_t y_bytes[y_HIGHBITS];

    uint8_t r3_bytes[m - D][r3_BYTES];

    poly x0_ntt;
    poly_n tmp;

    keccak_state state;

    header->in_len = 1;
    header->out_len = 2;
    header->v_in = coinbase;
    header->v_out = v_out;

    rejection_point:

    poly_n_set_zero(&header_y, 0, N);

    // pk = sum out.u'_i - sum in.u_i + sum header.u_i
    // y = sum_{i=0}^{out_len - 1} y_i
    poly_m_set_zero(&s_y, 0, N);
    for (j = 0; j < m - D; j++) {
        poly_set_zero(&header->sigma[j], 0, N);
    }

    // create out_coins
    lactx_coin_create(ctx, &out_coins[0], out_mask, v_out);
    lactx_mint_coin_create(ctx, &out_coins[1], coinbase - v_out);

    // pk = header.u + sum out.u - sum in.u
    poly_n_sub(&header->pk, &out_coins[0].u, &in_coins[0].u);
    poly_n_add(&header->pk, &header->pk, &out_coins[1].u);

    // Create delta
    pack_poly_ring_custom(u_bytes, &out_coins[0].u, K1 - u_ERROR);
    coin_hash(ctx, header->delta, u_bytes);

    // sigma
    for (j = 0; j < m - D; j++) {
        set_mask_tau(&header->sigma[j], out_mask[j]);
        get_mask_tau3(&s_y.vec[j + D], r3_bytes[j]);
    }

    // Create output headers if there are two outputs.
    uint64_t  v_outs[2] = {v_out, coinbase - v_out};
    set_carries(&c1, v_outs, 2);
    poly_set_zero(&c1_hat_p, 0, N);
    for (j = 0; j < L; j++) {
        // c1_hat_p = [c1_j - 2c1_(j+1)]_(j=0)^(L-1)
        c1_hat_p.coef[j] = c1.coef[j] - 2*c1.coef[j + 1];
    }

    // Assign u.
    poly_m_set_zero(&s_u, 0, N);
    poly_add(&s_u.vec[0], &s_u.vec[0], &c1_hat_p);

    poly_m_ntt(&s_u);
    poly_matrix_mul(&header->u, ctx->H, &s_u);
    poly_n_inv_ntt_to_mont(&header->u);
    poly_n_reduce(&header->u);
    poly_n_highbits(&header->u, &header->u, u_ERROR);

    poly_n_add(&header->pk, &header->pk, &header->u);

    poly_n_roundup(&header->pk, &header->pk, u_ERROR);
    poly_n_reduce(&header->pk);
    poly_n_highbits(&header->pk, &header->pk, pk_ERROR);

    poly_m_ntt(&s_y);
    poly_matrix_mul(&header_y, ctx->H, &s_y);
    poly_n_inv_ntt_to_mont(&header_y);
    poly_n_reduce(&header_y);
    poly_n_highbits(&header_y, &header_y, y_ERROR);

    pack_poly_ring_custom(pk_bytes, &header->pk, K1 - pk_ERROR);
    pack_poly_ring_custom(y_bytes, &header_y, K1 - y_ERROR);

    // challenge 0: x0 = hash(pk, y)
    shake256_init(&state);
    shake256_absorb(&state, pk_bytes, pk_HIGHBITS);
    shake256_absorb(&state, y_bytes, y_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(header->x0, SEED_BYTES, &state);
    poly_challenge(&x0_ntt, header->x0);
    poly_ntt(&x0_ntt);

    // Create the one-time signature
    for (j = 0; j < m - D; j++) {
        poly_ntt(&header->sigma[j]);
        poly_pointwise_montgomery(&header->sigma[j], &header->sigma[j], &x0_ntt);
        poly_inv_ntt_to_mont(&header->sigma[j]);
        poly_inv_ntt(&s_y.vec[j + D]);
        poly_add(&header->sigma[j], &header->sigma[j], &s_y.vec[j + D]);
        poly_reduce_exact(&header->sigma[j]);
        if (poly_chknorm(&header->sigma[j], header->out_len * (TAU3 - BETA))) {
            DEBUG_PRINT(("Rejected sigma_%d\n", j));
            goto rejection_point;
        }
    }

    // Set hints for y
    poly_n header_y2;
    poly_m_set_zero(&s_u, 0, N);
    for (j = 0; j < m - D; j++) {
        poly_set(&s_u.vec[j + D], &header->sigma[j]);
        poly_ntt(&s_u.vec[j + D]);
    }

    poly_matrix_mul(&header_y2, ctx->H, &s_u);
    poly_n_inv_ntt_to_mont(&header_y2);
    poly_n_reduce(&header_y2);

    poly_n_set(&tmp, &header->pk);
    poly_n_roundup(&tmp, &tmp, pk_ERROR);
    poly_n_ntt(&tmp);
    poly_n_pointwise_montgomery(&tmp, &tmp, &x0_ntt);
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_sub(&header_y2, &header_y2, &tmp);
    poly_n_reduce(&header_y2);
    poly_n_highbits(&header_y2, &header_y2, y_ERROR);

    int res = poly_n_hints(&header->y_hints, &header_y2, &header_y);
    if (res == -1) {
        DEBUG_PRINT(("rejected y_hints\n"));
        goto rejection_point;
    }

    return res == 0;
}

/**
 * Verifies a minted header
 * @param ctx - context object
 * @param header - header
 * @return 1 - valid, 0 - invalid
 */
int lactx_minted_header_verify(context_t *ctx, header_t *header) {
    uint8_t pk_bytes[pk_HIGHBITS];
    uint8_t y_bytes[y_HIGHBITS];

    uint8_t x0_bytes[SEED_BYTES];

    poly c1;

    poly x0_ntt;

    poly_n header_y;
    poly_n pk_ntt;
    poly_n u;

    poly_m s;
    poly_n tmp;
    keccak_state state;

    unsigned int j;

    // Check norms
    for (j = 0; j < m - D; j++) {
        if (poly_chknorm(&header->sigma[j], header->out_len * TAU3) != 0)
            return 0;
    }

    poly_challenge(&x0_ntt, header->x0);
    poly_ntt(&x0_ntt);

    // Verify the signature
    poly_m_set_zero(&s, 0, N);
    for (j = 0; j < m - D; j++) {
        poly_set(&s.vec[j + D], &header->sigma[j]);
        poly_ntt(&s.vec[j + D]);
    }

    poly_matrix_mul(&header_y, ctx->H, &s);
    poly_n_inv_ntt_to_mont(&header_y);
    poly_n_reduce(&header_y);

    poly_n_set(&pk_ntt, &header->pk);
    poly_n_roundup(&pk_ntt, &pk_ntt, pk_ERROR);
    poly_n_ntt(&pk_ntt);
    poly_n_pointwise_montgomery(&tmp, &pk_ntt, &x0_ntt);
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_sub(&header_y, &header_y, &tmp);
    poly_n_reduce(&header_y);
    poly_n_highbits(&header_y, &header_y, y_ERROR);

    poly_n_makeup(&header_y, &header->y_hints);

    pack_poly_ring_custom(pk_bytes, &header->pk, K1 - pk_ERROR);
    pack_poly_ring_custom(y_bytes, &header_y, K1 - y_ERROR);

    // challenge 0: x0 = hash(pk, y)
    shake256_init(&state);
    shake256_absorb(&state, pk_bytes, pk_HIGHBITS);
    shake256_absorb(&state, y_bytes, y_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(x0_bytes, SEED_BYTES, &state);

    if (memcmp(x0_bytes, header->x0, SEED_BYTES) != 0) {
        DEBUG_PRINT(("mint header y failed %ld\n", header->pk.vec[0].coef[0]));
        return 0;
    }

    // Open u
    uint64_t  v_outs[2] = {header->v_out, header->v_in - header->v_out};
    set_carries(&c1, v_outs, 2);
    poly_m_set_zero(&s, 0, N);
    for (j = 0; j < L; j++) {
        // c1_hat_p = [c1_j - 2c1_(j+1)]_(j=0)^(L-1)
        s.vec[0].coef[j] = c1.coef[j] - 2*c1.coef[j + 1];
    }

    poly_ntt(&s.vec[0]);
    poly_matrix_mul(&u, ctx->H, &s);
    poly_n_inv_ntt_to_mont(&u);
    poly_n_reduce(&u);

    poly_n_highbits(&u, &u, u_ERROR);

    return !poly_n_compare(&u, &header->u);
}


/**
 * Verifies the one-time signature for the given public key and the range of the header
 * NOTE: this function doesn't verify the validity of the public key which should be verifies collectively with
 * coin bundles.
 * @param ctx  - the context object (cannot be null)
 * @param header - header object (cannot be null)
 * @return 1 - the header proof is valid, otherwise 0.
 */
int lactx_header_verify(context_t *ctx, header_t *header) {

    uint8_t pk_bytes[pk_HIGHBITS];
    uint8_t y_bytes[y_HIGHBITS];
    uint8_t u_bytes[u_HIGHBITS];
    uint8_t t1_bytes[t1_HIGHBITS];
    uint8_t t2_bytes[t2_HIGHBITS];
    uint8_t sig_bytes[get_sig_bytes(header->in_len, header->out_len)];

    uint8_t x0_bytes[SEED_BYTES];
    uint8_t x1_bytes[SEED_BYTES];
    uint8_t x2_bytes[SEED_BYTES];

    poly x0_ntt;
    poly x1_ntt;
    poly x2;
    poly x2_ntt;

    poly_n header_y;
    poly_n header_t2;
    poly_n pk_ntt;

    poly z;
    poly_m s;
    poly_n tmp;

    unsigned int in_carries = get_carry_range(header->in_len);
    unsigned int out_carries = get_carry_range(header->out_len);
    int in_carry_bits = ALPHA_BITS + ceil(log2(header->in_len - 1)/2);
    int out_carry_bits = ALPHA_BITS + ceil(log2(header->out_len - 1)/2);
    int in_alpha = (1 << in_carry_bits);
    int out_alpha = (1 << out_carry_bits);

    keccak_state state;
    unsigned int j, l;

    // Minted header proofs contain coin amounts in plaintext.
    if (header->v_in != 0 || header->v_out != 0) {
        return lactx_minted_header_verify(ctx, header);
    }

    // Check norms
    for (j = 0; j < m - D; j++) {
        if (poly_chknorm(&header->sigma[j], (header->out_len + header->in_len) * TAU3) != 0) {
            DEBUG_PRINT(("Large sigma\n"));
            return 0;
        }
    }

    if (header->in_len >= 2) {
        for (j = 0; j < L; j++)
            if (poly_chknorm(&header->z0[j], in_alpha) != 0)
                return 0;
    }

    if (header->out_len >= 2) {
        for (j = 0; j < L; j++)
            if (poly_chknorm(&header->z1[j], out_alpha) != 0)
                return 0;
    }

    if (header->in_len >= 2 || header->out_len >= 2) {
        for (j = 0; j < m - D; j++) {
            if (poly_chknorm(&header->R[j], TAU2) != 0)
                return 0;
        }
    }

    poly_challenge(&x0_ntt, header->x0);
    poly_ntt(&x0_ntt);

    // Verify the signature
    poly_m_set_zero(&s, 0, N);
    for (j = 0; j < m - D; j++) {
        poly_set(&s.vec[j + D], &header->sigma[j]);
        poly_ntt(&s.vec[j + D]);
    }

    poly_matrix_mul(&header_y, ctx->H, &s);
    poly_n_inv_ntt_to_mont(&header_y);
    poly_n_reduce_exact(&header_y);

    poly_n_set(&pk_ntt, &header->pk);
    poly_n_roundup(&pk_ntt, &pk_ntt, pk_ERROR);
    poly_n_ntt(&pk_ntt);
    poly_n_pointwise_montgomery(&tmp, &pk_ntt, &x0_ntt);
    poly_n_inv_ntt_to_mont(&tmp);
    poly_n_sub(&header_y, &header_y, &tmp);
    poly_n_reduce(&header_y);
    poly_n_highbits(&header_y, &header_y, y_ERROR);

    poly_n_makeup(&header_y, &header->y_hints);

    pack_poly_ring_custom(pk_bytes, &header->pk, K1 - pk_ERROR);
    pack_poly_ring_custom(y_bytes, &header_y, K1 - y_ERROR);

    // challenge 0: x0 = hash(pk, y)
    shake256_init(&state);
    shake256_absorb(&state, pk_bytes, pk_HIGHBITS);
    shake256_absorb(&state, y_bytes, y_HIGHBITS);
    shake256_finalize(&state);
    shake256_squeeze(x0_bytes, SEED_BYTES, &state);

    if (memcmp(x0_bytes, header->x0, SEED_BYTES) != 0) {
        DEBUG_PRINT(("header y failed %ld\n", header->pk.vec[0].coef[0]));
        return 0;
    }

    if (header->in_len >= 2 || header->out_len >= 2) {

        pack_poly_ring_custom(u_bytes, &header->u, K1 - u_ERROR);
        pack_poly_ring_custom(t1_bytes, &header->t1, K1 - t1_ERROR);
        pack_poly_sig(sig_bytes, header->sigma, (int)(header->in_len + header->out_len));

        // challenge 1: x1 = hash(u, t1)
        shake256_init(&state);
        shake256_absorb(&state, u_bytes, u_HIGHBITS);
        shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
        shake256_finalize(&state);
        shake256_squeeze(x1_bytes, SEED_BYTES, &state);
        poly_challenge(&x1_ntt, x1_bytes);
        poly_ntt(&x1_ntt);
        //poly_set_zero(&x1_ntt, 0, N);

        poly_challenge(&x2, header->x2);
        poly_set(&x2_ntt, &x2);
        poly_ntt(&x2_ntt);

        // z0_hat = ∑_(i=0)^(L−1)(z0_j− 2z0_j+1rot(1,i)
        poly_m_set_zero(&s, 0, N);
        if (header->in_len >= 2) {
            poly header_z0_ntt[in_carries][L + 1];
            for (l = 0; l < in_carries; l++) {
                poly_set_zero(&header_z0_ntt[l][0], 0, N);
                poly_set_zero(&header_z0_ntt[l][L], 0, N);
                for (j = 0; j < L; j++) {
                    poly_set(&header_z0_ntt[l][j], &header->z0[j*in_carries + l]);
                    poly_ntt(&header_z0_ntt[l][j]);
                }
            }

            set_z_hat_p(&z, header->z0, in_carries);
            poly_sub(&s.vec[0],&s.vec[0], &z);

            set_z_hat(&z, header->z0, header_z0_ntt, &x2, in_carries);
            poly_add(&s.vec[2],&s.vec[2], &z);
        }

        if (header->out_len >= 2) {
            poly header_z1_ntt[out_carries][L+1];
            for (l = 0; l < out_carries; l++) {
                poly_set_zero(&header_z1_ntt[l][0], 0, N);
                poly_set_zero(&header_z1_ntt[l][L], 0, N);
                for (j = 0; j < L; j++) {
                    poly_set(&header_z1_ntt[l][j], &header->z1[j*out_carries + l]);
                    poly_ntt(&header_z1_ntt[l][j]);
                }
            }

            set_z_hat_p(&z, header->z1, out_carries);
            poly_add(&s.vec[0],&s.vec[0], &z);

            set_z_hat(&z, header->z1, header_z1_ntt, &x2, out_carries);
            poly_add(&s.vec[1], &s.vec[1], &z);
        }

        poly_ntt(&s.vec[0]);
        poly_pointwise_montgomery(&s.vec[0], &s.vec[0], &x1_ntt);
        poly_inv_ntt_to_mont(&s.vec[0]);

        // Check aggregate z
        // z0_hat = ∑_(i=0)^(L−1)(z0_j− 2z0_j+1rot(1,i)
        if (poly_chknorm(&s.vec[1], ZAGG) != 0) {
            DEBUG_PRINT(("Larger z1_hat\n"));
            return 0;
        }

        if (poly_chknorm(&s.vec[2], ZAGG) != 0) {
            DEBUG_PRINT(("Larger z0_hat\n"));
            return 0;
        }

        for (j = 0; j < m - D; j++) {
            poly_set(&s.vec[j + D], &header->R[j]);
        }

        poly_n tmp1;

        poly_m_ntt(&s);
        poly_matrix_mul(&header_t2, ctx->H, &s);
        poly_n_roundup(&tmp, &header->u, u_ERROR);
        poly_n_ntt(&tmp);
        poly_n_pointwise_montgomery(&tmp, &tmp, &x1_ntt); // x1u
        poly_n_inv_ntt_to_mont(&tmp);
        poly_n_roundup(&tmp1, &header->t1, t1_ERROR);
        poly_n_add(&tmp, &tmp, &tmp1); // x1u + t1
        poly_n_reduce(&tmp);
        poly_n_ntt(&tmp);
        poly_n_pointwise_montgomery(&tmp, &tmp, &x2_ntt); // x2(x1u + t1)
        poly_n_sub(&header_t2, &header_t2, &tmp);
        poly_n_inv_ntt_to_mont(&header_t2);
        poly_n_reduce(&header_t2);
        poly_n_highbits(&header_t2, &header_t2, t2_ERROR);

        poly_n_makeup(&header_t2, &header->t2_hints);
        pack_poly_ring_custom(t2_bytes, &header_t2, K1 - t2_ERROR);

        // challenge 2: x2 = hash(u, t1, t2)
        shake256_init(&state);
        shake256_absorb(&state, u_bytes, u_HIGHBITS);
        shake256_absorb(&state, t1_bytes, t1_HIGHBITS);
        shake256_absorb(&state, t2_bytes, t2_HIGHBITS);
        shake256_finalize(&state);
        shake256_squeeze(x2_bytes, SEED_BYTES, &state);

        if (memcmp(x2_bytes, header->x2, SEED_BYTES) != 0) {
            DEBUG_PRINT(("header t2 failed %ld\n", header->t1.vec[0].coef[0]));
            return 0;
        }
    }

    return 1;

}



#endif //LACTX_LACTX_HEADER_IMPL_H
