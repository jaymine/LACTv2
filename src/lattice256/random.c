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


#ifndef LACTX_RANDOM_IMPL_H
#define LACTX_RANDOM_IMPL_H

#include <stdint.h>
#include <openssl/rand.h>
#include "random.h"

#define PERIOD (LACTX_N/8)
/**
 * Get random mask in [-2^bound_bytes - 1, -2^bound_bytes - 1] for coefficients a[0:LACTX_N].
 * @param a - output polynomial
 * @param seed - output random seed (must be allocated)
 * @param bound_bytes - input
 */
void get_mask(poly *a, uint8_t *seed, int bound_bytes) {
    int i, j, byte, bit, sign;
    memset(seed, 0x0, PERIOD * (bound_bytes + 1));
    RAND_bytes(seed, PERIOD * (bound_bytes + 1));

    for (i = 0; i < LACTX_N; i++) {
        // used ‘‘truncation toward zero’’.
        byte = i / 8;
        bit = i % 8;
        sign = (seed[byte] >> bit) & 1;

        a->coef[i] = (seed[PERIOD + byte] >> bit) & 1;
        for (j = 1; j < bound_bytes; j++) {
            a->coef[i] += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
        }

        if (sign == 1) {
            a->coef[i] = -a->coef[i];
        }
    }
}

/**
 * Set polynomial from the given seed in [-2^bound_bytes - 1, -2^bound_bytes - 1] for coefficients a[0:LACTX_N].
 * @param a - output polynomial
 * @param seed - input random seed (must be allocated)
 * @param bound_bytes - input
 */
void set_mask(poly *a, const uint8_t *seed, int bound_bytes) {
    int i, j, byte, bit, sign;

    for (i = 0; i < LACTX_N; i++) {
        // used ‘‘truncation toward zero’’.
        byte = i / 8;
        bit = i % 8;
        sign = (seed[byte] >> bit) & 1;

        a->coef[i] = (seed[PERIOD + byte] >> bit) & 1;
        for (j = 1; j < bound_bytes; j++) {
            a->coef[i] += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
        }

        if (sign == 1) {
            a->coef[i] = -a->coef[i];
        }
    }
}

/**
 * Get random mask in (-TAU, TAU) or [-TAU + 1, TAU - 1] for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - output random seed
 */
void get_mask_tau(poly *a, uint8_t seed[r_BYTES]) {
    get_mask(a, seed, TAU_BITS);
}

/**
 * Get random mask in (-TAU1, TAU1) or [-TAU1 + 1, TAU1 - 1]  for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - output random seed
 */
void get_mask_tau1(poly *a, uint8_t seed[r1_BYTES]) {
    get_mask(a, seed, TAU1_BITS);
}

/**
 * Get random mask in (-TAU2, TAU2) or [-TAU2 + 1, TAU2 - 1]  for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - output random seed
 */
void get_mask_tau2(poly *a, uint8_t seed[r2_BYTES]) {
    get_mask(a, seed, TAU2_BITS);
}

/**
 * Get random mask in (-TAU3, TAU3) or [-TAU3 + 1, TAU3 - 1]  for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - output random seed
 */
void get_mask_tau3(poly *a, uint8_t seed[r3_BYTES]) {
    get_mask(a, seed, TAU3_BITS);
}

/**
 * Set polynomial from the given seed in (-TAU, TAU) or [-TAU + 1, TAU - 1]  for polynomial[2, LACTX_m].
 * Coefficients in [0:2] are left unchanged.
 * @param a - output polynomial
 * @param seed - input random seed
 */
void set_mask_tau(poly *a, const uint8_t seed[r_BYTES]) {
    set_mask(a, seed, TAU_BITS);
}

/**
 * Set polynomial from the given seed in (-TAU1, TAU1) or [-TAU1 + 1, TAU1 - 1] for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - input random seed
 */
void set_mask_tau1(poly *a, const uint8_t seed[r1_BYTES]) {
    set_mask(a, seed, TAU1_BITS);
}

/**
 * Set polynomial from the given seed in (-TAU2, TAU2) or [-TAU2 + 1, TAU2 - 1] for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - input random seed
 */
void set_mask_tau2(poly *a, const uint8_t seed[r2_BYTES]) {
    set_mask(a, seed, TAU2_BITS);
}

/**
 * Set polynomial from the given seed in (-TAU3, TAU3) or [-TAU3 + 1, TAU3 - 1] for polynomial[2, LACTX_m].
 * Coefficients in polynomial [0: 2] are left unchanged.
 * @param a - output polynomial
 * @param seed - input random seed
 */
void set_mask_tau3(poly *a, const uint8_t seed[r3_BYTES]) {
    set_mask(a, seed, TAU3_BITS);
}

/**
 * Get random mask in (-ALPHA, ALPHA) or [-ALPHA + 1, ALPHA -1] for LACTX_L polynomials.
 * @param a - output polynomial
 * @param seed - output random seed
 * @param b - value bit
 */
void get_value_mask(poly *a, uint8_t seed[a_BYTES], int64_t b) {
    int i, j, byte, bit, sign;
    memset(seed, 0x0, a_BYTES);
    RAND_bytes(seed, PERIOD * (ALPHA_BITS + 1));

    uint64_t coef;

    if (b == 0) {
        for (i = 0; i < LACTX_N; i++) {
            // used ‘‘truncation toward zero’’.
            byte = i / 8;
            bit = i % 8;

            if (((seed[PERIOD + byte] >> bit) & 1) == 0) continue; // (j + 1) == 1
            coef = (seed[PERIOD + byte] >> bit) & 1;
            for (j = 1; j < ALPHA_BITS; j++) {
                if (((seed[PERIOD * (j + 1) + byte] >> bit) & 1) == 0) {
                    break;
                }
                coef += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
            }
            if (coef >= ALPHA - 1) {
                //printf("breaker %d %d\LACTX_n", breaker, (seed[byte] >> bit) & 1);
                seed[PERIOD + byte] &= ~(1 << bit);
            }
        }
    }

    for (i = 0; i < LACTX_N; i++) {
        // used ‘‘truncation toward zero’’.
        byte = i / 8;
        bit = i % 8;
        sign = (seed[byte] >> bit) & 1;

        a->coef[i] = (seed[PERIOD + byte] >> bit) & 1;
        for (j = 1; j < ALPHA_BITS; j++) {
            a->coef[i] += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
        }

        if (sign == 1) {
            a->coef[i] = -a->coef[i];
        }
    }
}

/**
 * Set random mask from the given seed in (-ALPHA, ALPHA) or [-ALPHA + 1, ALPHA -1]  for LACTX_L polynomials.
 * @param a - output polynomial
 * @param seed - output random seed
 */
void set_value_mask(poly *a, const uint8_t seed[a_BYTES]) {
    int i, j, byte, bit, sign;

    for (i = 0; i < LACTX_N; i++) {
        // used ‘‘truncation toward zero’’.
        byte = i / 8;
        bit = i % 8;
        sign = (seed[byte] >> bit) & 1;

        a->coef[i] = (seed[PERIOD + byte] >> bit) & 1;
        for (j = 1; j < ALPHA_BITS; j++) {
            a->coef[i] += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
        }

        if (sign == 1) {
            a->coef[i] = -a->coef[i];
        }
    }
}

/**
 * Get random mask in (-ALPHA, ALPHA) or [-ALPHA + 1, ALPHA -1] for LACTX_L polynomials.
 * @param a - output polynomial
 * @param seed - output random seed
 * @param b - value bit
 * @param bit_len - number of coefficient bits
 */
void get_custom_value_mask(poly *a, uint8_t *seed, int64_t b, int bit_len) {
    int i, j, byte, bit, sign;
    int bytes = 1 << (bit_len);
    int total_bytes = (LACTX_N / 8 * (bit_len + 1));
    memset(seed, 0x0, total_bytes);
    RAND_bytes(seed, PERIOD * (bit_len + 1));

    uint64_t coef;

    if (b == 0) {
        for (i = 0; i < LACTX_N; i++) {
            // used ‘‘truncation toward zero’’.
            byte = i / 8;
            bit = i % 8;

            if (((seed[PERIOD + byte] >> bit) & 1) == 0) continue; // (j + 1) == 1
            coef = (seed[PERIOD + byte] >> bit) & 1;
            for (j = 1; j < bit_len; j++) {
                if (((seed[PERIOD * (j + 1) + byte] >> bit) & 1) == 0) {
                    break;
                }
                coef += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
            }
            if (coef >= bytes - 1) {
                //printf("breaker %d %d\LACTX_n", breaker, (seed[byte] >> bit) & 1);
                seed[PERIOD + byte] &= ~(1 << bit);
            }
        }
    }

    for (i = 0; i < LACTX_N; i++) {
        // used ‘‘truncation toward zero’’.
        byte = i / 8;
        bit = i % 8;
        sign = (seed[byte] >> bit) & 1;

        a->coef[i] = (seed[PERIOD + byte] >> bit) & 1;
        for (j = 1; j < bit_len; j++) {
            a->coef[i] += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
        }

        if (sign == 1) {
            a->coef[i] = -a->coef[i];
        }
    }
}

/**
 * Set random mask from the given seed in (-ALPHA, ALPHA) or [-ALPHA + 1, ALPHA -1]  for LACTX_L polynomials.
 * @param a - output polynomial
 * @param seed - output random seed
 * @param bit_len - number of coefficient bits
 */
void set_custom_value_mask(poly *a, const uint8_t *seed, int bit_len) {
    int i, j, byte, bit, sign;

    for (i = 0; i < LACTX_N; i++) {
        // used ‘‘truncation toward zero’’.
        byte = i / 8;
        bit = i % 8;
        sign = (seed[byte] >> bit) & 1;

        a->coef[i] = (seed[PERIOD + byte] >> bit) & 1;
        for (j = 1; j < bit_len; j++) {
            a->coef[i] += (((seed[PERIOD*(j+1) + byte] >> bit) & 1) << j);
        }

        if (sign == 1) {
            a->coef[i] = -a->coef[i];
        }
    }
}

#endif //LACTX_RANDOM_IMPL_H
