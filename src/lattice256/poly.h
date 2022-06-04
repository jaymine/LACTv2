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

#ifndef LACTx_POLY_H
#define LACTx_POLY_H

#include <stdint.h>
#include "params.h"
#include "ntt.h"

typedef struct poly_struct {
    int64_t coef[N];
} poly;

typedef struct poly_n_struct {
    poly vec[n];
} poly_n;

typedef struct poly_m_struct {
    poly vec[m];
} poly_m;

int64_t reduce64(int64_t a);

int64_t reduce64_exact(int64_t a);

int64_t highbits(int64_t a, unsigned int p);

int64_t roundup(int64_t a, unsigned int p);

poly poly_from_vec(const int64_t vec[N]);

void poly_set(poly *b, poly *a);

int poly_compare(const poly *s1, const poly *s2);

int poly_highbits_compare(const poly *s1, const poly *s2, unsigned int p);

void poly_set_zero(poly *a, unsigned int start, unsigned int end);

static int64_t addq(int64_t a);

void poly_reduce(poly *a);

void poly_reduce_exact(poly *a);

void poly_highbits(poly *a, poly *b, unsigned int p);

void poly_roundup(poly *a, poly *b, unsigned int p);

void poly_add(poly *c, poly *a, poly *b);

void poly_sub(poly *c, poly *a, poly *b);

void poly_shift_l(poly *a, unsigned int l);

void poly_ntt(poly *a);

void poly_inv_ntt_to_mont(poly *a);

void poly_inv_ntt(poly *a);

void poly_pointwise_montgomery(poly *c, poly *a, poly *b);

void poly_easy_mul(poly *c, poly *a, unsigned int i, int value);

int poly_chknorm(const poly *a, int64_t B);

int poly_chknorm_custom(const poly *a, int64_t B, int start, int end);

void poly_challenge(poly *c, const uint8_t seed[SEED_BYTES]);



#endif //LACTx_POLY_H
