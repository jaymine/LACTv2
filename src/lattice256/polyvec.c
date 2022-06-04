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

#ifndef LACTX_POLYVEC_IMPL_H
#define LACTX_POLYVEC_IMPL_H

#include <stdio.h>
#include "polyvec.h"


/**
 * Set b = a
 * @param b - output polynomial vector
 * @param a - input polynomial vector
 */
void poly_n_set(poly_n *b, poly_n *a) {
    unsigned int j;
    for (j = 0; j < n; j++)
        poly_set(&b->vec[j], &a->vec[j]);
}

void poly_m_set(poly_m *b, poly_m *a) {
    unsigned int j;
    for (j = 0; j < m; j++)
        poly_set(&b->vec[j], &a->vec[j]);
}

/**
 * Reduce all coefficients of a polynomial vector
 * @param a - the polynomial
 */
void poly_n_reduce(poly_n *a) {
    unsigned int i;
    for (i = 0; i < n; ++i) {
        poly_reduce(&a->vec[i]);
    }
}

/**
 * Reduce all coefficients of a polynomial vector
 * @param a - the polynomial
 */
void poly_m_reduce(poly_m *a) {
    unsigned int i;
    for (i = 0; i < m; ++i) {
        poly_reduce(&a->vec[i]);
    }
}

/**
 * Reduce all coefficients of a polynomial vector
 * @param a - the polynomial
 */
void poly_n_reduce_exact(poly_n *a) {
    unsigned int i;
    for (i = 0; i < n; ++i) {
        poly_reduce_exact(&a->vec[i]);
    }
}

/**
 * Reduce all coefficients of a polynomial vector
 * @param a - the polynomial
 */
void poly_m_reduce_exact(poly_m *a) {
    unsigned int i;
    for (i = 0; i < m; ++i) {
        poly_reduce_exact(&a->vec[i]);
    }
}

/**
 * Compare two polynomial vectors
 * @param s1 - input
 * @param s2 - input
 * @return 0 if s1 = s2; -1 otherwise
 */
int poly_n_compare(poly_n *s1, poly_n *s2) {
    unsigned int i;
    for (i = 0; i < n; ++i) {
        if (poly_compare(&s1->vec[i], &s2->vec[i]) != 0)
            return -1;
    }
    return 0;
}

/**
 * Compare two polynomial vectors
 * @param s1 - input
 * @param s2 - input
 * @return 0 if s1 = s2; -1 otherwise
 */
int poly_m_compare(poly_m *s1, poly_m *s2) {
    unsigned int i;
    for (i = 0; i < m; ++i) {
        if (poly_compare(&s1->vec[i], &s2->vec[i]) != 0)
            return -1;
    }
    return 0;
}

/**
 * Set a [start:end] of all polynomials to zero (except end)
 * @param a - polynomial vector
 * @param start - starting index
 * @param end - ending index
 */
void poly_n_set_zero(poly_n *a, unsigned int start, unsigned int end) {
    unsigned int i;
    for (i = 0; i < n; ++i) {
        poly_set_zero(&a->vec[i], start, end);
    }
}

/**
 * Set a [start:end] of all polynomials to zero (except end)
 * @param a - polynomial vector
 * @param start - starting index
 * @param end - ending index
 */
void poly_m_set_zero(poly_m *a, unsigned int start, unsigned int end) {
    unsigned int i;
    for (i = 0; i < m; ++i) {
        poly_set_zero(&a->vec[i], start, end);
    }
}

/**
 * Polynomial-wise addition of polynomial vectors
 * @param c - output (a + b)
 * @param a - input
 * @param b - input
 */
void poly_n_add(poly_n *c, poly_n *a, poly_n *b) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_add(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/**
 * Polynomial-wise addition of polynomial vectors
 * @param c - output (a + b)
 * @param a - input
 * @param b - input
 */
void poly_m_add(poly_m *c, poly_m *a, poly_m *b) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        poly_add(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/**
 * Polynomial-wise subtraction of polynomial vectors
 * @param c - output (a - b)
 * @param a - input
 * @param b - input
 */
void poly_n_sub(poly_n *c, poly_n *a, poly_n *b) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_sub(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/**
 * Polynomial-wise subtraction of polynomial vectors
 * @param c - output (a - b)
 * @param a - input
 * @param b - input
 */
void poly_m_sub(poly_m *c, poly_m *a, poly_m *b) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        poly_sub(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/**
 * Get high bits of polynomial vectors
 * @param a - output polynomial vector
 * @param b - input polynomial vector
 */
void poly_n_highbits(poly_n *a, poly_n *b, unsigned int p) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_highbits(&a->vec[i], &b->vec[i], p);
    }
}

/**
 * Get the rounded ups of polynomial vectors
 * @param a - output polynomial vector
 * @param b - input polynomial vector
 * @param b - power
 */
void poly_n_roundup(poly_n *a, poly_n *b, unsigned int p) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_roundup(&a->vec[i], &b->vec[i], p);
    }
}

/**
 * Create hints for a given b (b is the original high bit polynomial)
 * @param hint - hint polynomial with CHI +1 or -1
 * @param a - computed
 * @param b - original
 * @param p - the number of bits
 * @return 0 - successful, -1 - more hints, -2 - the difference is larger than 1
 */
int poly_n_hints(poly_n *hint, poly_n *a, poly_n *b) {
    unsigned int i, j, count = 0;
    for (i = 0; i < n; i++) {
        for (j = 0; j < N; j++) {
            hint->vec[i].coef[j] = ((a->vec[i].coef[j] - b->vec[i].coef[j]));
            if (hint->vec[i].coef[j] == 1 || hint->vec[i].coef[j] == -1) {
                //printf("%ld\n", a->vec[i].coef[j] - b->vec[i].coef[j]);
                count++;
            }
            else if (hint->vec[i].coef[j] != 0) {
                //printf("over one: %d %d %ld %ld %ld\n", i, j, a->vec[i].coef[j], b->vec[i].coef[j], hint->vec[i].coef[j]);
                return -1;
            }
        }
    }
    //printf("gen count: %d\n", count);
    if (count > CHI) { // Don't want to get an uninitiated value
        //printf("rejected hints: %d\n", count);
        return -1;
    }
    return 0;
}

/**
 * Construct the original polynomial high bits
 * @param a - computed
 * @param hint - hint polynomial with CHI +1 or -1
 * @return 0 - successful, -1 - more hints than CHI
 */
int poly_n_makeup(poly_n *a, poly_n *hint) {
    unsigned int i, j, count = 0;
    for (i = 0; i < n; i++) {
        for (j = 0; j < N; j++) {
            if (hint->vec[i].coef[j] == 1 || hint->vec[i].coef[j] == -1) {
                //printf("%ld\n", a->vec[i].coef[j] - b->vec[i].coef[j]);
                a->vec[i].coef[j] -= hint->vec[i].coef[j];
                count++;
            } else if (hint->vec[i].coef[j] != 0) {
                //printf("over one: %ld\n", hint->vec[i].coef[j]);
                return -1;
            }
        }
    }
    //
    // printf("ver count: %d\n", count);
    if (count > CHI) { // Don't want to get an uninitiated value
        //printf("rejected hints: %d\n", count);
        return -1;
    }
    return 0;
}

/**
 * NTT transformation of polynomial vectors
 * @param a - polynomial vector
 */
void poly_n_ntt(poly_n *a) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_ntt(&a->vec[i]);
    }
}

/**
 * NTT transformation of polynomial vectors
 * @param a - polynomial vector
 */
void poly_m_ntt(poly_m *a) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        poly_ntt(&a->vec[i]);
    }
}

/**
 * NTT inverse-transformation of polynomial vectors for montgomery reduction
 * @param a - polynomial vector
 */
void poly_n_inv_ntt_to_mont(poly_n *a) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_inv_ntt_to_mont(&a->vec[i]);
    }
}

/**
 * NTT inverse-transformation of polynomial vectors for montgomery reduction
 * @param a - polynomial vector
 */
void poly_m_inv_ntt_to_mont(poly_m *a) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        poly_inv_ntt_to_mont(&a->vec[i]);
    }
}

/**
 * NTT inverse-transformation of polynomial vectors
 * @param a - polynomial vector
 */
void poly_n_inv_ntt(poly_n *a) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_inv_ntt(&a->vec[i]);
    }
}

/**
 * NTT inverse-transformation of polynomial vectors
 * @param a - polynomial vector
 */
void poly_m_inv_ntt(poly_m *a) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        poly_inv_ntt(&a->vec[i]);
    }
}

/**
 * Pointwise multiplication
 * @param c - output  b(a)
 * @param a - input
 * @param b - input
 */
void poly_n_pointwise_montgomery(poly_n *c, poly_n *a, poly *b) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        poly_pointwise_montgomery(&c->vec[i], &a->vec[i], b);
    }
}

/**
 * Pointwise multiplication
 * @param c - output  b(a)
 * @param a - input
 * @param b - input
 */
void poly_m_pointwise_montgomery(poly_m *c, poly_m *a, poly *b) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        poly_pointwise_montgomery(&c->vec[i], &a->vec[i], b);
    }
}


void poly_matrix_expand(poly_m mat[n], const uint8_t rho[SEED_BYTES]) {
    unsigned int i, j;

    for(i = 0; i < n; ++i)
        for(j = 0; j < m; ++j)
            poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

/**
 * Multiply polynomial matrix in NTT domain (no inverse transform and no reduction)
 * @param u - output polynomial vector u = Hs (in NTT domain)
 * @param H - input polynomial matrix (in NTT domain)
 * @param s - input polynomial vector (in NTT domain)
 */
void poly_matrix_mul(poly_n *u, poly_m H[n], poly_m *s) {
    unsigned int i, j;
    for (i = 0; i < n; i++) {
        poly t;
        poly_pointwise_montgomery(&u->vec[i], &H[i].vec[0], &s->vec[0]);
        for(j = 1; j < m; ++j) {
            poly_pointwise_montgomery(&t, &H[i].vec[j], &s->vec[j]);
            poly_add(&u->vec[i], &u->vec[i], &t);
        }
    }
}

/**
 * Check infinity norm
 * @param a - polynomial vector
 * @param B - norm
 * @return 0 if B <= GAMMA2 and |a_i|_infinity < B; -1 otherwise
 */
int poly_n_chknorm(const poly_n *a, int64_t B) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (poly_chknorm(&a->vec[i], B) != 0)
            return -1;
    }
    return 0;
}

/**
 * Check infinity norm
 * @param a - polynomial vector
 * @param B - norm
 * @return 0 if B <= GAMMA2 and |a_i|_infinity < B; -1 otherwise
 */
int poly_m_chknorm(const poly_m *a, int64_t B) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        if (poly_chknorm(&a->vec[i], B) != 0)
            return -1;
    }
    return 0;
}

/**
 * Check infinity norm
 * @param a - polynomial vector
 * @param B - norm
 * @return 0 if B <= GAMMA2 and |a_i|_infinity < B; -1 otherwise
 */
int poly_L_chknorm(const poly a[L], int64_t B) {
    unsigned int i;
    for (i = 0; i < L; i++) {
        if (poly_chknorm(&a[i], B) != 0)
            return -1;
    }
    return 0;
}

/**
 * Check infinity norm for a customized range
 * @param a  - polynomial vector
 * @param B  - norm
 * @param start - start point
 * @param end - end point
 * @return 0 if B <= GAMMA2 and |a[start:end]|_infinity < B; -1 otherwise
 */
int poly_n_chknorm_custom(const poly_n *a, int64_t B, int start, int end) {
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (poly_chknorm_custom(&a->vec[i], B, start, end) != 0)
            return -1;
    }
    return 0;
}

/**
 * Check infinity norm for a customized range
 * @param a  - polynomial vector
 * @param B  - norm
 * @param start - start point
 * @param end - end point
 * @return 0 if B <= GAMMA2 and |a[start:end]|_infinity < B; -1 otherwise
 */
int poly_m_chknorm_custom(const poly_m *a, int64_t B, int start, int end) {
    unsigned int i;
    for (i = 0; i < m; i++) {
        if (poly_chknorm_custom(&a->vec[i], B, start, end) != 0)
            return -1;
    }
    return 0;
}

/**
 * Get a polynomial in [-ALPHA, ALPHA] and random seed
 * @param a - polynomial vector
 * @param seed - random seed vector
 * @param b - value (binary)
 */
void get_value_masks(poly a[L], uint8_t seed[L][a_BYTES], poly *b) {
    unsigned int i;
    for (i = 0; i < L; i++) {
        get_value_mask(&a[i], seed[i], b->coef[i]);
    }
}

/**
 * set polynomial from the given seed vector in [-ALPHA, ALPHA]
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void set_value_masks(poly a[L], const uint8_t seed[L][a_BYTES]) {
    unsigned int i;
    for (i = 0; i < L; i++) {
        set_value_mask(&a[i], seed[i]);
    }
}

/**
 * Get a polynomial in [-ALPHA, ALPHA] and random seed
 * @param a - polynomial vector
 * @param seed - random seed vector
 * @param b - value (binary)
 * @param bit_len - number of bits per coefficient
 */
void get_custom_value_masks(poly a[L], uint8_t seed[L][a_BYTES], poly *b, int bit_len) {
    unsigned int i;
    for (i = 0; i < L; i++) {
        get_custom_value_mask(&a[i], seed[i], b->coef[i], bit_len);
    }
}

/**
 * set polynomial from the given seed vector in [-ALPHA, ALPHA]
 * @param a - polynomial vector
 * @param seed - random seed vector
 * @param bit_len - number of bits per coefficient
 */
void set_custom_value_masks(poly a[L], const uint8_t seed[L][a_BYTES], int bit_len) {
    unsigned int i;
    for (i = 0; i < L; i++) {
        set_custom_value_mask(&a[i], seed[i], bit_len);
    }
}

/**
 * Get a polynomial in [-TAU, TAU] and random seed
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void get_masks_tau(poly_m *a, uint8_t seed[m - D][r_BYTES]) {
    unsigned int i;
    for (i = 0; i < m - D; i++) {
        get_mask_tau(&a->vec[i + D], seed[i]);
    }
}

/**
 * set polynomial from the given seed vector in [-TAU, TAU]
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void set_masks_tau(poly_m *a, const uint8_t seed[m - D][r_BYTES]) {
    unsigned int i;
    for (i = 0; i < m - D; i++) {
        set_mask_tau(&a->vec[i + D], seed[i]);
    }
}

/**
 * Get a polynomial in [-TAU1, TAU1] and random seed
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void get_masks_tau1(poly_m *a, uint8_t seed[m - D][r1_BYTES]) {
    unsigned int i;
    for (i = 0; i < m - D; i++) {
        get_mask_tau1(&a->vec[i + D], seed[i]);
    }
}

/**
 * set polynomial from the given seed vector in [-TAU1, TAU1]
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void set_masks_tau1(poly_m *a, const uint8_t seed[m - D][r1_BYTES]) {
    unsigned int i;
    for (i = 0; i < m - D; i++) {
        set_mask_tau1(&a->vec[i + D], seed[i]);
    }
}

/**
 * Get a polynomial in [-TAU2, TAU2] and random seed
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void get_masks_tau2(poly_m *a, uint8_t seed[m - D][r2_BYTES]) {
    unsigned int i;
    for (i = 0; i < m - D; i++) {
        get_mask_tau2(&a->vec[i + D], seed[i]);
    }
}

/**
 * set polynomial from the given seed vector in [-TAU2, TAU2]
 * @param a - polynomial vector
 * @param seed - random seed vector
 */
void set_masks_tau2(poly_m *a, const uint8_t seed[m - D][r2_BYTES]) {
    unsigned int i;
    for (i = 0; i < m - D; i++) {
        set_mask_tau2(&a->vec[i + D], seed[i]);
    }
}

#endif //LACTX_POLYVEC_IMPL_H
