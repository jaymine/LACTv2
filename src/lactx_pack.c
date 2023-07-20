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


#ifndef LACTX_PACK_IMPL_H
#define LACTX_PACK_IMPL_H

#include "lactx_pack.h"
#include <math.h>

/**
 * Pack a polynomial
 * @param bytes - ouput byte array
 * @param a - input polynomial
 */
void pack_custom_poly_internal(uint8_t *bytes, poly *a, const int bound_byte) {
    int b, i, j, byte;
    int64_t coef;

    memset(bytes, 0x0, bound_byte * (256/8));

    for (b = 0; b < (LACTX_N / 8); b++) { // blocks
        byte = b * bound_byte;
        for (j = 0; j < 8; j++) {  // each byte while 0th byte is the sign byte
            coef = a->coef[b * 8 + j];
            if (coef < 0) {
                bytes[byte] |= (1 << j);
                coef = -coef;
            }
            for (i = 1; i < bound_byte; i++) {
                bytes[byte + i] |= (uint8_t) (((coef >> (i - 1)) & 1) << j);
            }
        }
    }
}

/**
 * Convert a byte array to a polynomial in [-Q2, Q2]
 * @param a - output polynomial
 * @param bytes - input byte array
 */
void unpack_custom_poly_internal(poly *a, const uint8_t *bytes, const int bound_byte) {
    unsigned int b, i, j, byte;

    for (b = 0; b < (LACTX_N / 8); b++) { // blocks
        byte = b * bound_byte;
        for (j = 0; j < 8; j++) {  // each byte while 0th byte is the sign byte
            a->coef[b * 8 + j] = 0;
            for (i = 1; i < bound_byte; i++) {
                a->coef[b * 8 + j] |= (((int64_t)(bytes[byte + i] >> j) & 1) << (i - 1));
            }
            if (((bytes[byte] & (1 << j)) >> j) == 1) {
                a->coef[b * 8 + j] = -a->coef[b * 8 + j];
            }
        }
    }
}

/**
 * Pack a polynomial
 * @param bytes - ouput byte array
 * @param a - input polynomial
 */
void pack_custom_poly(uint8_t *bytes, poly *a) {
    pack_custom_poly_internal(bytes, a, K1);
}

/**
 * Convert a byte array to a polynomial in [-Q2, Q2]
 * @param a - output polynomial
 * @param bytes - input byte array
 */
void unpack_custom_poly(poly *a, const uint8_t *bytes) {
    unpack_custom_poly_internal(a, bytes, K1);
}

/**
 * Pack a polynomial vector to a byte array
 * @param bytes - output byte array
 * @param u - input polynomial vector
 */
void pack_poly_ring(uint8_t bytes[LACTX_n * u_BYTES], poly_n *u) {
    unsigned int i;
    for (i = 0; i < LACTX_n; i++) {
        pack_custom_poly(bytes + u_BYTES*i, &u->vec[i]);
    }
}

/**
 * Convert a byte array to a polynomial vector
 * @param u - output polynomial vector
 * @param bytes - input byte array
 */
void unpack_poly_ring(poly_n *u, const uint8_t bytes[LACTX_n * u_BYTES]) {
    unsigned int i;
    for (i = 0; i < LACTX_n; i++) {
        unpack_custom_poly(&u->vec[i], bytes + u_BYTES*i);
    }
}

/**
 * Pack a polynomial vector to a byte array
 * @param bytes - output byte array
 * @param u - input polynomial vector
 * @param p - the number of higher bits
 */
void pack_poly_ring_custom(uint8_t bytes[], poly_n *u, int p) {
    unsigned int i;
    for (i = 0; i < LACTX_n; i++) {
        pack_custom_poly_internal(bytes + (p * LACTX_N / 8) * i, &u->vec[i], p);
    }
}

/**
 * Convert a byte array to a polynomial vector
 * @param u - output polynomial vector
 * @param bytes - input byte array
 * @param p - the number of higher bits
 */
void unpack_poly_ring_custom(poly_n *u, const uint8_t bytes[], int p) {
    unsigned int i;
    for (i = 0; i < LACTX_n; i++) {
        unpack_custom_poly_internal(&u->vec[i], bytes + (p * LACTX_N / 8) * i, p);
    }
}

/**
 * Pack the coefficients of a polynomial vector to a byte array. Note that
 * those coefficients must be in [-ALPHA, ALPHA]
 * @param bytes - output bytes
 * @param s - input polynomial
 */
#define BLOCK (((ALPHA_BITS + 1) * LACTX_N)/8)
void pack_poly_z(uint8_t bytes[z_BYTES], poly s[LACTX_L]) {
    int l;

    for (l = 0; l < LACTX_L; l++) {
        pack_custom_poly_internal(bytes + BLOCK * l, &s[l], (ALPHA_BITS + 1));
    }
}

/**
 * Convert a byte array to the coefficients of a polynomial. Note that
 * those coefficients are in [-ALPHA, ALPHA]
 * @param s - output polynomial
 * @param bytes - input bytes
 */
void unpack_poly_z(poly s[LACTX_L], const uint8_t bytes[z_BYTES]) {
    int l;

    for (l = 0; l < LACTX_L; l++) {
        unpack_custom_poly_internal(&s[l], bytes + BLOCK * l, (ALPHA_BITS + 1));
    }
}

/**
 * Pack the coefficients of a polynomial vector to a byte array. Note that
 * those coefficients must be in [-2^(bit_len), 2^(bit_len)]
 * @param bytes - output bytes
 * @param s - input polynomial
 * @param bit_len - number of coefficient bits
 */
void pack_poly_z_custom(uint8_t bytes[z_BYTES], poly s[LACTX_L], int bit_len) {
    int l;
    int block = (((bit_len + 1) * LACTX_N) / 8);

    for (l = 0; l < LACTX_L; l++) {
        pack_custom_poly_internal(bytes + block * l, &s[l], (bit_len + 1));
    }
}

/**
 * Convert a byte array to the coefficients of a polynomial. Note that
 * those coefficients are in [-2^(bit_len), 2^(bit_len)]
 * @param s - output polynomial
 * @param bytes - input bytes
 * @param bit_len - number of coefficient bits
 */
void unpack_poly_z_custom(poly s[LACTX_L], const uint8_t bytes[z_BYTES], int bit_len) {
    int l;
    int block = (((bit_len + 1) * LACTX_N) / 8);

    for (l = 0; l < LACTX_L; l++) {
        unpack_custom_poly_internal(&s[l], bytes + block * l, (bit_len + 1));
    }
}

/**
 * Pack all coefficients of a polynomial vector to a byte array. Note that
 * Those coefficients must be in [-TAU2, TAU2].
 * @param bytes - output byte array
 * @param s - input polynomial vector
 */
#define SINGLE_R_BYTES  (LACTX_N * (TAU2_BITS + 1)/8)
void pack_poly_m_R(uint8_t bytes[R_BYTES], poly s[LACTX_m - D]) {
    int l;

    for (l = 0; l < (LACTX_m - D); l++) {
        pack_custom_poly_internal(bytes + SINGLE_R_BYTES * l, &s[l], (TAU2_BITS + 1));
    }
}

/**
 * Convert a byte array to coefficients of a polynomial vector. Those coefficients will be in [-TAU2, TAU2]
 * @param s - output polynomial vector
 * @param bytes - input byte array
 */
void unpack_poly_m_R(poly s[LACTX_m - D], const uint8_t bytes[R_BYTES]) {
    int l;

    for (l = 0; l < (LACTX_m - D); l++) {
        unpack_custom_poly_internal(&s[l], bytes + SINGLE_R_BYTES * l, (TAU2_BITS + 1));
    }
}


int get_sig_bytes(unsigned int in_len, unsigned int out_len) {
    return (((int) ceil(log2(TAU3 * (out_len + in_len))) + 1) * LACTX_N) / 8 * (LACTX_m - D);
}

/**
 * Pack all coefficients of a polynomial vector of size LACTX_m - D to a byte array. Note that
 * Those coefficients must be in [-TAU3, TAU3].
 * @param bytes - output byte array
 * @param s - input polynomial vector
 */
void pack_poly_sig(uint8_t bytes[], poly s[LACTX_m - D], int additions) {
    int l;
    int SINGLE_sig_BYTES  = (((int) ceil(log2(TAU3 * additions)) + 1) * LACTX_N) / 8;
    for (l = 0; l < (LACTX_m - D); l++) {
        pack_custom_poly_internal(bytes + SINGLE_sig_BYTES * l, &s[l],
                                  ((int) ceil(log2(TAU3 * additions)) + 1));
    }
}

/**
 * Convert a byte array to coefficients of a polynomial vector. Those coefficients will be in [-TAU2, TAU2]
 * @param s - output polynomial vector
 * @param bytes - input byte array
 */
void unpack_poly_sig(poly s[LACTX_m - D], uint8_t bytes[], int additions) {
    int l;
    int SINGLE_sig_BYTES  = (((int) ceil(log2(TAU3 * additions)) + 1) * LACTX_N) / 8;
    for (l = 0; l < (LACTX_m - D); l++) {
        unpack_custom_poly_internal(&s[l], bytes + SINGLE_sig_BYTES * l,
                                  ((int) ceil(log2(TAU3 * additions)) + 1));
    }
}

#endif //LACTX_PACK_IMPL_H
