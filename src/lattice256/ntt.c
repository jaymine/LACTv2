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
