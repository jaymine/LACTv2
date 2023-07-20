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

#ifndef LACTX_POLYVEC_H
#define LACTX_POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "fips202.h"
#include "poly.h"
#include "shake.h"
#include "random.h"
#include "ntt.h"

void poly_n_set(poly_n *b, poly_n *a);
void poly_m_set(poly_m *b, poly_m *a);

void poly_n_reduce(poly_n *a);
void poly_m_reduce(poly_m *a);

void poly_n_reduce_exact(poly_n *a);
void poly_m_reduce_exact(poly_m *a);

int poly_n_compare(poly_n *s1, poly_n *s2);
int poly_m_compare(poly_m *s1, poly_m *s2);

void poly_n_set_zero(poly_n *a, unsigned int start, unsigned int end);
void poly_m_set_zero(poly_m *a, unsigned int start, unsigned int end);

void poly_n_add(poly_n *c, poly_n *a, poly_n *b);
void poly_m_add(poly_m *c, poly_m *a, poly_m *b);

void poly_n_sub(poly_n *c, poly_n *a, poly_n *b);
void poly_m_sub(poly_m *c, poly_m *a, poly_m *b);

void poly_n_ntt(poly_n *a);
void poly_m_ntt(poly_m *a);

void poly_n_inv_ntt_to_mont(poly_n *a);
void poly_m_inv_ntt_to_mont(poly_m *a);

void poly_n_inv_ntt(poly_n *a);
void poly_m_inv_ntt(poly_m *a);

void poly_n_pointwise_montgomery(poly_n *c, poly_n *a, poly *b);
void poly_m_pointwise_montgomery(poly_m *c, poly_m *a, poly *b);

void poly_matrix_mul(poly_n *u, poly_m H[LACTX_n], poly_m *s);
void poly_matrix_expand(poly_m mat[LACTX_n], const uint8_t rho[SEED_BYTES]);

int poly_n_chknorm(const poly_n *a, int64_t B);
int poly_m_chknorm(const poly_m *a, int64_t B);
int poly_L_chknorm(const poly a[LACTX_L], int64_t B);

void poly_n_highbits(poly_n *a, poly_n *b, unsigned int p);
void poly_n_roundup(poly_n *a, poly_n *b, unsigned int p);
int poly_n_hints(poly_n *hint, poly_n *a, poly_n *b);
int poly_n_makeup(poly_n *b, poly_n *hint);

int poly_n_chknorm_custom(const poly_n *a, int64_t B, int start, int end);
int poly_m_chknorm_custom(const poly_m *a, int64_t B, int start, int end);

void get_value_masks(poly a[LACTX_L], uint8_t seed[LACTX_L][a_BYTES], poly *b);

void set_value_masks(poly a[LACTX_L], const uint8_t seed[LACTX_L][a_BYTES]);

void get_custom_value_masks(poly a[LACTX_L], uint8_t seed[LACTX_L][a_BYTES], poly *b, int bit_len);

void set_custom_value_masks(poly a[LACTX_L], const uint8_t seed[LACTX_L][a_BYTES], int bit_len);

void get_masks_tau(poly_m *a, uint8_t seed[LACTX_m - 3][r_BYTES]);

void get_masks_tau1(poly_m *a, uint8_t seed[LACTX_m - 3][r1_BYTES]);

void get_masks_tau2(poly_m *a, uint8_t seed[LACTX_m - 3][r2_BYTES]);

void set_masks_tau(poly_m *a, const uint8_t seed[LACTX_m - 3][r_BYTES]);

void set_masks_tau1(poly_m *a, const uint8_t seed[LACTX_m - 3][r1_BYTES]);

void set_masks_tau2(poly_m *a, const uint8_t seed[LACTX_m - 3][r2_BYTES]);


#endif //LACTX_POLYVEC_H
