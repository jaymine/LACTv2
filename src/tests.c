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

#if defined HAVE_CONFIG_H
#include "liblactx-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include <openssl/rand.h>

#include "lattice256/polyvec.h"
#include "lactx_store.h"
#include "lactx_pack.h"

/**
 * Tests correctness of the reduction function
 */
void test_reduce64(void) {
    CHECK( 0 == reduce64(0));
    CHECK( 1 == reduce64(1));
    CHECK( -1 == reduce64(-1));
    CHECK( 255 == reduce64(255) && -6442450941 == reduce64(-6442450941));
    CHECK( -Q2 - 1 + 127 != reduce64(Q2 + 127));
    CHECK( Q2 + 1 -  127 != reduce64(-Q2 - 127));
    CHECK( -Q2 - 1 + 127 == reduce64_exact(Q2 + 127));
    CHECK( Q2 + 1 -  127 == reduce64_exact(-Q2 - 127));
    CHECK( -Q2 - 1 + 65536 == reduce64(Q2 + 65536));
    CHECK( Q2 + 1 -  65536 == reduce64(-Q2 - 65536));
    CHECK( 0 == reduce64(Q) && 0 == reduce64(-Q));
    CHECK( 1 == reduce64(Q + 1) && 1 == reduce64(-Q + 1));
    CHECK( -1 == reduce64(Q - 1) && -1 == reduce64(-Q - 1));
}

const int64_t t0[N] = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

const int64_t t1[N] = {4, 1, -1, -2, 4, -1, -1, 1, 4, 3, -1, -3, 3, 4, -1, 4, -1, 0, -2, 4, 0, 3, 2, 0, -2, -3, 1, -4, 2,
                       2, 4, -1, -1, -3, -4, 2, 4, 4, 0, 1, 2, 2, 0, -1, -2, -1, -2, -2, -1, 4, 2, 2, -3, 0, 4, -1, 3, -1,
                       3, -3, 2, -3, -4, -3, -1, 3, -3, -3, -3, -3, 0, 0, -1, 3, 2, 4, 1, 1, 2, 1, -1, 4, 1, 4, -2, 4, -4,
                       3, 2, 1, 3, 0, 0, 2, 1, -4, -4, -3, 4, -1, 4, 1, 4, -1, -4, 4, 4, -1, -1, -2, -4, -4, -3, 3, 2, 2,
                       -1, 1, -1, -2, 0, -4, -2, -2, -1, -4, 1, -2, 1, -2, 0, 3, 3, 1, 0, -3, -1, 3, -1, 4, 3, -1, 1, 2,
                       4, -4, 4, 4, 1, 1, 0, -2, 1, 4, -2, 4, 1, 2, -4, 1, 0, -2, 0, -2, 2, 1, -3, -3, 3, 1, -2, 2, -3, 2,
                       -2, -1, 0, -2, -1, 1, 4, 2, 3, 3, 2, 4, 0, -2, -2, 2, -3, -4, -3, 1, 3, -4, -4, -1, -4, 3, -3, -3,
                       3, 0, 2, 3, 3, 1, 3, -1, -4, 0, 1, -2, 3, 0, -4, 2, 3, 0, 2, -4, 2, 0, 0, 3, -3, -1, -4, 4, 4, 2,
                       1, 0, -4, 0, -1, 1, -1, -3, 2, -4, -1, -2, -4, 1, 3, 1, -1, 3, 3, 3, -2, -1, 2, 1};

const int64_t t2[N] = {-3, 1, -2, 4, -2, -1, 0, -2, 0, -1, -2, -1, 1, 0, -1, -3, 1, 3, -2, 0, 2, 4, -3, -2, -3, 2, 3, 2,
                       -2, 3, -3, 0, 0, -1, -4, -4, -1, -3, 3, -1, 3, 1, -1, -1, -4, -1, 2, -2, 2, 2, -3, 4, 1, -4, 2, 3,
                       -3, -4, -1, -4, 1, 4, 0, -1, 4, 1, -3, -4, -2, 1, -4, -4, 4, -3, 2, 2, -3, 0, 1, -2, -3, 2, 3, -2,
                       3, -3, 2, 1, 0, 0, -1, 1, -3, 0, -3, -1, 3, 1, -2, -1, 2, 4, 0, 0, 3, 1, 0, 3, 2, -2, -3, 3, 4, 4,
                       1, -1, -3, -4, -2, -1, -2, 0, -4, 1, 3, -2, 4, 1, -2, -3, 1, -1, -3, 1, -1, 3, -1, -3, 4, -2, -4,
                       0, 3, -2, 0, 1, -2, -2, 0, 2, 3, 0, 2, -4, -1, -2, 2, -1, 4, 0, 4, -3, 2, 3, -1, 0, 0, 0, -4, 2,
                       -2, 3, -3, -4, 0, 2, -3, -3, -1, 1, -2, 4, 3, 0, 0, 4, -2, 4, 3, 0, 4, 3, -4, 2, 4, -3, -3, 1, 3,
                       0, -3, 3, -3, 1, -3, 1, -4, -2, 1, 2, 4, 0, -1, -2, -1, 0, -1, 1, 4, 3, -1, -3, 2, -1, -3, -4, 0,
                       -4, 2, -2, 4, -2, 1, -1, -3, 1, -1, -4, 1, 0, -4, 3, -4, -4, 2, -2, 4, -4, 2, -4, 4, -3, -3, 3,
                       -3, 4};

const int64_t t3[N] = {2, 0, -3, 1, -1, -1, -2, 1, 4, -1, 1, 1, -2, 1, 3, 4, 3, 2, -4, -2, -3, 0, 3, -3, -4, -2, 4, -3, 1,
                       0, 1, -3, -2, -2, 2, -1, -2, -2, 4, -1, 1, -1, 0, 4, -4, 1, 4, 0, -1, 3, 3, 0, 0, -1, 1, -1, 2, -3,
                       -2, 1, 0, -4, 3, -1, -4, -3, -4, 0, -1, -2, 0, -2, -2, 3, 0, -2, 0, -2, -2, 0, 0, 4, 0, 4, -4, -2,
                       -3, 2, -3, -1, -2, -2, -2, -2, 4, 1, -4, 3, -2, -1, 1, 3, 4, 4, 1, -2, -2, 1, -4, 1, -1, 0, -4, -3,
                       2, 3, -2, -3, -4, 1, 2, 2, -3, 3, 4, 1, -2, -4, -3, -4, -2, -4, 0, -1, -1, 4, -2, -2, -4, -1, 2,
                       -1, 0, -2, -3, 1, 0, 4, 3, 4, 1, 0, -4, 1, -1, 3, -3, 4, -2, -4, 4, -4, 2, 4, 1, -2, 0, -1, 4, -2,
                       -1, 0, 3, 1, 4, -4, -2, 4, -3, 0, -2, 3, -1, 2, 3, -1, 4, 4, -2, 2, 4, 4, 0, -1, 3, -1, -2, -3, -1,
                       4, -1, 4, -1, 0, -2, -4, -2, 3, 4, 1, -1, 3, 3, 1, 3, -1, -1, 2, -3, 2, 0, -3, -1, 1, 0, -4, 4, 3,
                       1, 4, -4, -4, -1, 1, -4, -1, 0, -2, -3, 0, -1, -3, 1, -3, 3, 0, 2, -3, -2, 2, -3, 0, 0, 2, -1, 1};

const int64_t out0[N] = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -4, 8};

const int64_t out1[N] = {255, -32, -227, -300, 9, -108, -207, 44, 183, 228, -38, -2, -25, 112, -154, 96, 75, 126, 66, 232,
                         128, 218, 51, 14, 60, 28, -21, -116, 76, -108, -160, -438, 11, -70, 34, 46, 216, 126, 90, -200,
                         -205, 118, 190, -136, -30, 186, -176, -24, 11, -60, 135, -120, -161, 160, -58, -70, -229, 120,
                         256, 126, 138, -56, 160, -118, -229, 4, 21, -162, -20, -102, 150, 88, -14, 220, -185, -46, -207,
                         60, 174, 72, -133, -200, -211, -38, 50, 250, 271, 188, 59, -6, 57, 240, -106, 34, 211, -64, 11,
                         -6, -36, -172, 117, -38, 163, -24, 21, -208, -80, -76, -375, 120, 10, 6, -135, 162, 173, 174, -77,
                         -114, 103, 96, 140, -38, 121, -154, 245, 94, -143, 52, 188, 78, -18, -146, -214, -170, -49, 72,
                         73, -180, 36, 108, -118, 128, -219, 240, -138, -96, -174, 16, 19, -142, -42, -48, 131, 40, 102,
                         -104, 377, -144, -64, 154, -52, 50, 67, 86, 39, 210, -34, -4, 215, 120, -48, 18, 189, -78, -91,
                         -148, -40, 90, -167, -54, -48, 56, 16, 94, 12, 152, -38, 22, 133, 140, 382, 40, 72, 114, 46, -44,
                         -79, 6, -158, -278, -114, -128, 3, -46, -48, -18, 5, 36, -111, -216, -310, -22, -176, 0, -31, 110,
                         -182, -30, 171, 68, 243, 182, 255, -148, 3, 4, -107, -14, -173, 238, 90, 134, -13, 192, 284, -48,
                         -12, 192, 183, 2, 11, -194, 37, -40, 169, 44, 69, -130, -145, -152, -119, -312, -173, 80, 91, 196};

const int64_t out2[N] = {-11, 221, -93, 26, -38, -202, 82, -85, 11, -88, 58, 104, -128, 13, 28, -19, -86, -66, -20, -50,
                         80, 61, -73, 224, 83, -71, -32, 131, -261, 79, 27, 66, -61, 125, -105, -177, -19, 51, 78, -165,
                         87, 50, -199, 107, -115, -103, 141, 47, -108, -112, -28, -23, -21, -23, 17, 72, -139, -165, -117,
                         39, 67, -37, 104, 95, -96, 154, -54, 72, 26, 30, 7, 160, 76, -131, 80, 44, 61, -153, 5, -59, 60,
                         -44, -31, -40, -37, -50, -3, -92, 92, 94, 177, 16, 67, -40, -72, 51, -100, -110, 163, 2, 104,
                         -12, -92, -3, 134, -128, -63, 130, 15, -344, 165, -14, 16, -46, -41, -149, -65, -58, -27, -43,
                         55, -1, 21, 40, 19, -162, -51, 136, 121, 2, -23, 91, -101, 3, 124, 63, -32, -19, 28, -195, 66,
                         258, 43, 94, -43, -41, -4, -44, -129, 119, 108, 36, 127, -49, -114, 93, 41, -56, 124, 64, -29,
                         51, -115, 201, 47, 45, 118, 45, -78, 33, -1, -138, 139, -44, 34, 133, 151, -67, -9, 58, 19, -115,
                         -51, -74, 104, 144, -1, -49, 150, -36, -111, -231, -64, -17, 59, 142, -34, 221, 70, -147, 33, 94,
                         -52, 27, 146, -14, 47, -13, 28, 73, 83, -13, 22, -88, -84, 59, -166, -77, -192, -104, -20, -162,
                         -35, -132, -21, 55, -139, 23, 77, -21, -91, 43, 172, 36, -242, 97, -5, 144, -38, 99, -82, -11,
                         -211, -152, 98, 22, 16, 30, -8, 68, -55, -174, 49, -7, -20, -45};

/**
 * Test ntt correctness with Dilithium outputs where all polynomials are less than 2^23 - 2^13 + 1.
 */
void test_ntt(void) {
    int i;

    poly a = poly_from_vec(t0);
    poly_ntt(&a);
    poly out0_expected = poly_from_vec(out0);
    poly out0_returned;
    poly_pointwise_montgomery(&out0_returned, &a, &a);
    poly_inv_ntt_to_mont(&out0_returned);
    poly_reduce(&out0_returned);
    CHECK(poly_compare(&out0_returned, &out0_expected) == 0);

    a = poly_from_vec(t1);
    poly b = poly_from_vec(t1);
    poly_ntt(&a);
    poly out1_expected = poly_from_vec(out1);
    poly out1_returned;
    poly_pointwise_montgomery(&out1_returned, &a, &a);
    poly_inv_ntt_to_mont(&out1_returned);
    poly_inv_ntt(&a);
    poly_reduce(&a);
    poly_reduce(&out1_returned);

    CHECK(poly_compare(&a, &b) == 0);
    CHECK(poly_compare(&out1_returned, &out1_expected) == 0);

    poly c = poly_from_vec(t2);
    poly d = poly_from_vec(t3);
    poly_ntt(&c);
    poly_ntt(&d);
    poly out2_expected = poly_from_vec(out2);
    poly out2_returned;
    poly_pointwise_montgomery(&out2_returned, &c, &d);
    poly_inv_ntt_to_mont(&out2_returned);
    poly_inv_ntt(&c);
    poly_inv_ntt(&d);
    poly_reduce(&out2_returned);
    poly_reduce(&c);
    poly_reduce(&d);

    CHECK(poly_compare(&out2_returned, &out2_expected) == 0);
    poly tmp = poly_from_vec(t2);
    CHECK(poly_compare(&c, &tmp) == 0);
    tmp = poly_from_vec(t3);
    CHECK(poly_compare(&d, &tmp) == 0);

    for (i = 0; i < N; i++) {
        c.coef[i] <<= 10;
        d.coef[i] <<= 44;
        out2_expected.coef[i] <<= 54;  // Maximum is 2^55. because the montgomery factor is 2^55
    }
    poly_ntt(&c);
    poly_ntt(&d);
    poly_pointwise_montgomery(&out2_returned, &c, &d);
    poly_inv_ntt_to_mont(&out2_returned);
    poly_reduce_exact(&out2_returned);
    poly_reduce_exact(&out2_expected);

    CHECK(poly_compare(&out2_returned, &out2_expected) == 0);
}


void test_check_norm(void) {
    poly a = poly_from_vec(t1);
    CHECK(poly_chknorm(&a, 5) == 0);
    poly b = poly_from_vec(out1);
    CHECK(poly_chknorm(&b, 382) != 0);
    poly c = poly_from_vec(out2);
    CHECK(poly_chknorm(&c, 345) == 0);
}


void test_get_masks(void) {
    int i, j;
    poly a[L], a_set[L];
    poly r, r_set;
    poly r1, r1_set;
    poly r2, r2_set;
    uint8_t a_seed[a_BYTES];
    uint8_t a_seedl[L][a_BYTES];
    uint8_t seed[r_BYTES];
    uint8_t seed1[r1_BYTES];
    uint8_t seed2[r2_BYTES];
    poly b;

    for (i = 0; i < 100; i++) {
        binary_set(&b, i);
        get_value_mask(&a[0], a_seed, i % 2);
        set_value_mask(&a_set[0], a_seed);
        CHECK(poly_compare(&a[0], &a_set[0]) == 0);
        CHECK(poly_chknorm(&a[0], ALPHA) == 0);
        CHECK(poly_chknorm(&a[0], TAU) == -1);

        get_value_masks(a, a_seedl, &b);
        set_value_masks(a_set, a_seedl);
        for (j = 0; j < L; j++) {
            CHECK(poly_compare(&a[j], &a_set[j]) == 0);
            CHECK(poly_chknorm(&a[j], ALPHA) == 0);
            CHECK(poly_chknorm(&a[j], TAU) == -1);
        }
        CHECK(poly_L_chknorm(a, ALPHA) == 0);

        get_mask_tau(&r, seed);
        CHECK(poly_chknorm(&r, TAU) == 0);
        set_mask_tau(&r_set, seed);
        CHECK(poly_compare(&r, &r_set) == 0);

        get_mask_tau1(&r1, seed1);
        CHECK(poly_chknorm(&r1, TAU1) == 0);
        CHECK(poly_chknorm(&r1, TAU) == -1);
        set_mask_tau1(&r1_set, seed1);
        CHECK(poly_compare(&r1, &r1_set) == 0);

        get_mask_tau2(&r2, seed2);
        CHECK(poly_chknorm(&r2, TAU2) == 0);
        CHECK(poly_chknorm(&r2, TAU) == -1);
        CHECK(poly_chknorm(&r2, TAU1) == -1);
        set_mask_tau2(&r2_set, seed2);
        CHECK(poly_compare(&r2, &r2_set) == 0);
    }

}

void test_challenge_poly(void) {
    poly x;
    uint8_t h[SEED_BYTES];
    int i, j, count;

    for (i = 0; i < 16; i++) {
        memset(h, i, SEED_BYTES);
        poly_challenge(&x, h);
        count = 0;
        for (j = 0; j < N; j++) {
            if (x.coef[j] != 0) {
                count++;
            }
        }
        CHECK(count == BETA);
    }
}

void test_matrix_mul(void) {
    uint8_t ctx_seed[SEED_BYTES];
    memset(ctx_seed, 1, SEED_BYTES);
    context_t ctx = lactx_init(ctx_seed);
    int i;

    uint8_t seed[r_BYTES];
    poly_m s;
    poly_m s1;
    poly_m s2;
    poly_m_set_zero(&s1, 0, N);
    poly_m_set_zero(&s2, 0, N);
    for(i = 0; i < m; i++) get_mask_tau(&s1.vec[i], seed);
    for(i = 0; i < m; i++) get_mask_tau(&s2.vec[i], seed);

    poly_n A;
    poly_n B;
    poly_n C;
    poly_n U;
    poly_m_ntt(&s1);
    poly_m_ntt(&s2);
    poly_matrix_mul(&A, ctx.H, &s1);
    poly_matrix_mul(&B, ctx.H, &s2);
    poly_m_add(&s, &s1, &s2);
    poly_matrix_mul(&C, ctx.H, &s);
    poly_n_inv_ntt_to_mont(&A);
    poly_n_inv_ntt_to_mont(&B);
    poly_n_inv_ntt_to_mont(&C);

    poly_n_add(&U, &A, &B);
    poly_n_reduce_exact(&U);
    poly_n_reduce_exact(&C);
    CHECK(poly_n_compare(&U, &C) == 0);

    poly_m s11;
    poly_m s21;

    poly_m_set_zero(&s1, 0, N);
    poly_m_set_zero(&s2, 0, N);
    for(i = 0; i < m; i++) {get_mask_tau(&s1.vec[i], seed); poly_set(&s11.vec[i], &s1.vec[i]);}
    for(i = 0; i < m; i++) {get_mask_tau(&s2.vec[i], seed); poly_set(&s21.vec[i], &s2.vec[i]);}

    CHECK(poly_m_compare(&s1, &s11) == 0);
    CHECK(poly_m_compare(&s2, &s21) == 0);
    poly_m_add(&s, &s1, &s2);
    poly_m_ntt(&s1);
    poly_m_ntt(&s2);
    poly_m_inv_ntt(&s1);
    poly_m_inv_ntt(&s2);
    poly_m_reduce_exact(&s1);
    poly_m_reduce_exact(&s2);
    CHECK( poly_m_compare(&s1, &s11) == 0);
    CHECK(poly_m_compare(&s2, &s21) == 0);

    poly_matrix_mul(&A, ctx.H, &s1);
    poly_matrix_mul(&B, ctx.H, &s2);
    poly_matrix_mul(&C, ctx.H, &s);
    poly_n_inv_ntt_to_mont(&A);
    poly_n_inv_ntt_to_mont(&B);
    poly_n_inv_ntt_to_mont(&C);

    poly_n_add(&U, &A, &B);
    poly_n_reduce_exact(&U);
    poly_n_reduce_exact(&C);
    CHECK(poly_n_compare(&U, &C) == 0);


    poly_n RHS;
    poly_n LHS;
    poly x1;
    poly x1_ntt;
    uint8_t x1_bytes[SEED_BYTES];
    memset(x1_bytes, 0, SEED_BYTES);
    poly_challenge(&x1, x1_bytes);
    poly_set(&x1_ntt, &x1);
    poly_ntt(&x1_ntt);

    for(i = 0; i < m; i++) {get_mask_tau(&s.vec[i], seed);}
    poly_m_ntt(&s);
    poly_matrix_mul(&RHS, ctx.H, &s);
    poly_n_inv_ntt_to_mont(&RHS);
    poly_n_reduce_exact(&RHS);
    poly_n_ntt(&RHS);
    poly_n_pointwise_montgomery(&RHS, &RHS, &x1_ntt);
    poly_n_inv_ntt_to_mont(&RHS);
    poly_n_reduce_exact(&RHS);

    poly_m_pointwise_montgomery(&s, &s, &x1_ntt);
    poly_m_inv_ntt_to_mont(&s);
    poly_m_reduce_exact(&s);
    poly_m_ntt(&s);
    poly_matrix_mul(&LHS, ctx.H, &s);
    poly_n_inv_ntt_to_mont(&LHS);
    poly_n_reduce_exact(&LHS);

    CHECK(poly_n_compare(&LHS, &RHS) == 0);

    lactx_ctx_free(&ctx);

}

void test_pack(void) {
    poly a_expected = poly_from_vec(out2);
    poly a = poly_from_vec(out2);

    uint8_t buffer[u_BYTES];
    pack_custom_poly(buffer, &a);
    unpack_custom_poly(&a, buffer);

    //for (int i = 0; i < N; i++) printf("%ld %ld\n", a.coef[i], a_expected.coef[i]);

    CHECK(poly_compare(&a_expected, &a) == 0);

    // make large coefficients
    for (int i = 0; i < N; i++) {
        a.coef[i] = a.coef[i] * 140737488355327 + i; // 2^47 - 1
        a_expected.coef[i] = a.coef[i];
    }

    poly_reduce_exact(&a);
    poly_reduce_exact(&a_expected);

    pack_custom_poly(buffer, &a);
    unpack_custom_poly(&a, buffer);
    CHECK(poly_compare(&a_expected, &a) == 0);

    poly_n u;
    poly_n u_expected;
    for (int i = 0; i < n; i++) {
        u.vec[i] = a;
        u_expected.vec[i] = a_expected;
    }

    uint8_t buffer_n[n * u_BYTES];
    pack_poly_ring(buffer_n, &u);
    unpack_poly_ring(&u, buffer_n);

    CHECK(poly_n_compare(&u_expected, &u) == 0);

    poly b;
    binary_set(&b, GAMMA1);
    uint8_t a_seedl[L][a_BYTES];
    uint8_t buffer_a[z_BYTES];
    poly al[L];
    poly al_expected[L];
    get_value_masks(al, a_seedl, &b);
    set_value_masks(al_expected, a_seedl);
    for (int i = 0; i < L; i++) {
        CHECK(poly_compare(&al_expected[i], &al[i]) == 0);
    }
    pack_poly_z(buffer_a, al);
    unpack_poly_z(al, buffer_a);

    for (int i = 0; i < L; i++) {
        CHECK(poly_compare(&al_expected[i], &al[i]) == 0);
    }

    uint8_t r2_seed[m - D][r2_BYTES];
    uint8_t buffer_r2[R_BYTES];
    poly R[m - D];
    poly R_expected[m - D];
    for (int i = 0; i < m - D; i++) {
        poly_set_zero(&R[i], 0, N);
        poly_set_zero(&R_expected[i], 0, N);
        get_mask_tau2(&R[i], r2_seed[i]);
        set_mask_tau2(&R_expected[i], r2_seed[i]);
        CHECK(poly_compare(&R_expected[i], &R[i]) == 0);
    }

    pack_poly_m_R(buffer_r2, R);
    unpack_poly_m_R(R, buffer_r2);

    for (int i = 0; i < m - D; i++) {
        CHECK(poly_compare(&R_expected[i], &R[i]) == 0);
    }

    uint8_t r3_seed[m - D][r3_BYTES];
    uint8_t buffer_r3[get_sig_bytes(1, 0)];
    poly sigma[m - D];
    poly sigma_expected[m - D];
    for (int i = 0; i < m - D; i++) {
        poly_set_zero(&sigma[i], 0, N);
        poly_set_zero(&sigma_expected[i], 0, N);
        get_mask_tau3(&sigma[i], r3_seed[i]);
        set_mask_tau3(&sigma_expected[i], r3_seed[i]);
        CHECK(poly_compare(&sigma_expected[i], &sigma[i]) == 0);
    }

    pack_poly_sig(buffer_r3, sigma, 1);
    unpack_poly_sig(sigma, buffer_r3, 1);

    for (int i = 0; i < m - D; i++) {
        CHECK(poly_compare(&sigma_expected[i], &sigma[i]) == 0);
    }
}


void test_highbit_compare() {
    poly a = poly_from_vec(t1);
    CHECK(poly_highbits_compare(&a, &a, 0) == 0);
    poly b = poly_from_vec(out1);
    CHECK(poly_highbits_compare(&b, &b, 0) == 0);
    poly c = poly_from_vec(out2);
    CHECK(poly_highbits_compare(&c, &c, 0) == 0);

    CHECK(poly_highbits_compare(&c, &c, 1) == 0);
    CHECK(poly_highbits_compare(&c, &c, 2) == 0);
    CHECK(poly_highbits_compare(&c, &c, 3) == 0);
    a = poly_from_vec(t1);
    b = poly_from_vec(t2);
    CHECK(poly_highbits_compare(&a, &b, 0) == -1);
    CHECK(poly_highbits_compare(&a, &b, 1) == -1);
    CHECK(poly_highbits_compare(&a, &b, 2) == -1);
    CHECK(poly_highbits_compare(&a, &b, 3) == -1);
    CHECK(poly_highbits_compare(&a, &b, 4) == -1);
    CHECK(poly_highbits_compare(&a, &b, 5) == -1);

    uint8_t bytes[u_HIGHBITS];
    poly_n u;
    poly_n u2;
    poly_n t12;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < N; j++) {
            u.vec[i].coef[j] = rand() % ((int64_t) 1 << 43);
        }
    }
    poly_n_highbits(&u2, &u, u_ERROR);
    pack_poly_ring_custom(bytes, &u2, K1 - u_ERROR);
    unpack_poly_ring_custom(&u2, bytes, K1 - u_ERROR);

    poly_n_roundup(&u2, &u2, u_ERROR);

    CHECK(poly_highbits_compare(&u2.vec[0], &u.vec[0], u_ERROR) == 0);
    CHECK(poly_highbits_compare(&u2.vec[n - 1], &u.vec[n - 1], u_ERROR) == 0);

}

void test_headers(void) {
    poly zero;
    poly c_1;
    uint64_t v[4];

    v[0] = 10;
    v[1] = 5;
    poly_set_zero(&zero, 0, N);
    set_carries(&c_1, v, 2);
    CHECK(poly_compare(&c_1, &zero) == 0);

    v[0] = 5;
    v[1] = 3;
    zero.coef[1] = 1;
    zero.coef[2] = 1;
    zero.coef[3] = 1;
    set_carries(&c_1, v, 2);
    CHECK(poly_compare(&c_1, &zero) == 0);

    v[0] = 4;
    v[1] = 4;
    zero.coef[1] = 0;
    zero.coef[2] = 0;
    zero.coef[3] = 1;
    set_carries(&c_1, v, 2);
    CHECK(poly_compare(&c_1, &zero) == 0);

    v[0] = 3;
    v[1] = 3;
    v[2] = 3;
    zero.coef[0] = 0;
    zero.coef[1] = 1;
    zero.coef[2] = 2;
    zero.coef[3] = 1;
    set_carries(&c_1, v, 3);
    CHECK(poly_compare(&c_1, &zero) == 0);

    v[0] = 3;
    v[1] = 3;
    v[2] = 3;
    v[3] = 3;
    zero.coef[0] = 0;
    zero.coef[1] = 2;
    zero.coef[2] = 3;
    zero.coef[3] = 1;
    set_carries(&c_1, v, 4);
    CHECK(poly_compare(&c_1, &zero) == 0);

}


void test_poly_easy_mul(void) {
    for (int i = 0; i < N; i++) {
        poly b1, b2, c, c1, c2;

        poly_set_zero(&b1, 0, N);
        b1.coef[i] = 1;
        uint8_t ch_seed[SEED_BYTES];
        RAND_bytes(ch_seed, SEED_BYTES);
        poly_challenge(&c, ch_seed);

        poly_ntt(&b1);
        poly_ntt(&c);
        poly_pointwise_montgomery(&b1, &c, &b1);
        poly_inv_ntt_to_mont(&b1);
        poly_reduce_exact(&b1);
        poly_inv_ntt(&c);
        poly_reduce_exact(&c);

        poly_easy_mul(&c1, &c, i, 1);

        poly_set_zero(&b2, 0, N);
        b2.coef[i] = -1;
        memset(ch_seed, 0xff, SEED_BYTES);
        poly_challenge(&c, ch_seed);

        poly_ntt(&b2);
        poly_ntt(&c);
        poly_pointwise_montgomery(&b2, &c, &b2);
        poly_inv_ntt_to_mont(&b2);
        poly_reduce_exact(&b2);
        poly_inv_ntt(&c);
        poly_reduce_exact(&c);

        poly_easy_mul(&c2, &c, i, -1);

        CHECK(poly_compare(&b1, &c1) == 0 && poly_compare(&b2, &c2) == 0);
    }
}



void test_basic_coin_header(void) {
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store;
    store.ctx = lactx_init(seed);
    lactx_db_connect(&store, "test_ctx.db");

    ctx_t tx;

    CHECK(lactx_tx_init(&tx, 2, 2));

    uint8_t in_mask[2][m - D][r_BYTES];
    uint64_t v_in[2] = {500, 300};

    uint8_t out_mask[2][m - D][r_BYTES];
    uint64_t v_out[2] = {400, 400};

    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < m - D; j++) memset(in_mask[i][j], 0, r_BYTES);
    }

    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < m - D; j++) memset(out_mask[i][j], 0, r_BYTES);
    }

    for (int i = 0; i < 2; i++) {
        lactx_coin_create(&store.ctx, &tx.in[i], in_mask[i], v_in[i]);
        CHECK(lactx_coin_open(&store.ctx, &tx.in[i], in_mask[i], v_in[i]) == 1);
        CHECK(lactx_coin_verify(&store.ctx, &tx.in[i]) == 1);
        lactx_ucoin_add(&store, &tx.in[i]);
    }

    //CHECK(lactx_header_init(&tx.header, 2, 2));
    CHECK(lactx_header_create(&store.ctx, &tx.header, 2, tx.out, out_mask, v_out,
                              2, tx.in, in_mask, v_in) == 1);

    CHECK(lactx_header_verify(&store.ctx, &tx.header) == 1);

    CHECK(lactx_tx_verify(&store, &tx) == 1);
    CHECK(lactx_header_free(&tx.header));

    // one input and one output
    v_in[0] = 500;
    v_out[0] = 500;
    for (int i = 0; i < 1; i++) {
        lactx_coin_create(&store.ctx, &tx.in[i], in_mask[i], v_in[i]);
        lactx_ucoin_add(&store, &tx.in[i]);
    }
    CHECK(lactx_header_init(&tx.header, 1, 1));
    CHECK(lactx_header_create(&store.ctx, &tx.header, 1, tx.out, out_mask, v_out,
                              1, tx.in, in_mask, v_in) == 1);


    CHECK(lactx_header_verify(&store.ctx, &tx.header) == 1);

    CHECK(lactx_tx_verify(&store, &tx) == 1);
    CHECK(lactx_header_free(&tx.header));


    // one input and two outputs
    v_in[0] = 1500;
    v_out[0] = 500;
    v_out[1] = 1000;
    for (int i = 0; i < 1; i++) {
        lactx_coin_create(&store.ctx, &tx.in[i], in_mask[i], v_in[i]);
        lactx_ucoin_add(&store, &tx.in[i]);
    }
    CHECK(lactx_header_init(&tx.header, 2, 1));
    CHECK(lactx_header_create(&store.ctx, &tx.header, 2, tx.out, out_mask, v_out,
                              1, tx.in, in_mask, v_in) == 1);


    CHECK(lactx_header_verify(&store.ctx, &tx.header) == 1);

    CHECK(lactx_tx_verify(&store, &tx) == 1);
    CHECK(lactx_header_free(&tx.header));

    // two inputs and one output
    v_in[0] = 800;
    v_out[0] = 500;
    v_out[1] = 300;
    for (int i = 0; i < 2; i++) {
        lactx_coin_create(&store.ctx, &tx.in[i], in_mask[i], v_in[i]);
        lactx_ucoin_add(&store, &tx.in[i]);
    }
    CHECK(lactx_header_init(&tx.header, 2, 1));
    CHECK(lactx_header_create(&store.ctx, &tx.header, 2, tx.out, out_mask, v_out,
                              1, tx.in, in_mask, v_in) == 1);

    CHECK(lactx_header_verify(&store.ctx, &tx.header) == 1);

    CHECK(lactx_tx_verify(&store, &tx) == 1);
    //CHECK(lactx_header_free(&tx.header));
    lactx_tx_free(&tx);

    lactx_drop_store(&store);
}

void test_max_min_value(void) {
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    context_t ctx = lactx_init(seed);
    coin_t in_coins[2];

    uint8_t in_mask[2][m - D][r_BYTES];
    uint64_t v_in[2];

    v_in[0] = 0;
    v_in[1] = 9223372036854775807; // 2^63 - 1

    lactx_coin_create(&ctx, &in_coins[0], in_mask[0], v_in[0]);
    lactx_coin_create(&ctx, &in_coins[1], in_mask[1], v_in[1]);

    CHECK(lactx_coin_open(&ctx, &in_coins[0], in_mask[0], v_in[0]) == 1);
    CHECK(lactx_coin_verify(&ctx, &in_coins[0]) == 1);

    CHECK(lactx_coin_open(&ctx, &in_coins[1], in_mask[1], v_in[1]) == 1);
    CHECK(lactx_coin_verify(&ctx, &in_coins[1]) == 1);
}


void test_store(void) {
    remove("test_ctx.db");
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store;

    uint8_t in_mask[MAX_ADDITIONS][m - D][r_BYTES];
    uint64_t v_in[MAX_ADDITIONS];

    uint8_t out_mask[MAX_ADDITIONS][m - D][r_BYTES];
    uint64_t v_out[MAX_ADDITIONS];

    for (int i = 0; i < MAX_ADDITIONS; i++) {
        for (int j = 0; j < m - D; j++) memset(in_mask[i][j], 0, r_BYTES);
    }

    for (int i = 0; i < MAX_ADDITIONS; i++) {
        for (int j = 0; j < m - D; j++) memset(out_mask[i][j], 0, r_BYTES);
    }

    // Check tx adding
    store = lactx_get_store(seed, "test_ctx.db");
    CHECK(lactx_store_verify(&store) == 1);


    ctx_t tx00; // Minting transaction 1
    CHECK(lactx_tx_init(&tx00, 2, 1));

    // minting 500 coins from the coinbase account
    lactx_mint_tx_create(&store, &tx00, out_mask[0], 13);
    CHECK(lactx_coin_open(&store.ctx, &tx00.out[0], out_mask[0], 13) == 1);

    CHECK(lactx_tx_verify(&store, &tx00) == 1);
    CHECK(lactx_coin_verify(&store.ctx, &tx00.out[0]) == 1);

    lactx_tx_aggregate(&store, &tx00);

    CHECK(lactx_ucoin_check(&store, &tx00.out[0]) == 1);

    CHECK(lactx_store_verify(&store) == 1);

    ctx_t tx1; // The first transaction
    unsigned int in_len = 1;
    unsigned int out_len = (rand() % MAX_ADDITIONS) + 1;
    CHECK(lactx_tx_init(&tx1, out_len, in_len));
    uint64_t total = 13;

    v_in[0] = total;

    for (int i = 0; i < in_len; i++) {
        for (int j = 0; j < m - D; j++)
            memcpy(in_mask[i][j], out_mask[i][j], r_BYTES);
    }

    for (int i = 0; i < out_len; i++) {
        v_out[i] = rand() % (total + 1);
        total -= v_out[i];
    }
    v_out[out_len - 1] += total;

    tx1.in[0] = tx00.out[0];

    CHECK(lactx_coin_open(&store.ctx, &tx00.out[0], out_mask[0], 13) == 1);
    CHECK(lactx_coin_open(&store.ctx, &tx00.out[0], in_mask[0], 13) == 1);
    CHECK(lactx_coin_open(&store.ctx, &tx1.in[0], in_mask[0], 13) == 1);

    //lactx_header_init(&tx1.header, out_len, in_len);
    CHECK(lactx_header_create(&store.ctx, &tx1.header,
                              out_len, tx1.out, out_mask, v_out,
                              in_len, tx1.in, in_mask, v_in) == 1);
    CHECK(lactx_header_verify(&store.ctx, &tx1.header) == 1);

    CHECK(lactx_tx_verify(&store, &tx1) == 1);
    lactx_tx_aggregate(&store, &tx1);

    CHECK(lactx_store_verify(&store) == 1);

    //lactx_header_free(&tx1.header);

    lactx_tx_free(&tx00);
    lactx_tx_free(&tx1);

    lactx_drop_store(&store);
}


void test_store2(void) {
    remove("test_ctx.db");
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store;

    // Check tx adding
    store = lactx_get_store(seed, "test_ctx.db");
    CHECK(lactx_store_verify(&store) == 1);

    for (int t = 0; t < 10; t++) {

        unsigned int in_len = (rand() % MAX_ADDITIONS) + 1;
        unsigned int out_len = (rand() % MAX_ADDITIONS) + 1;

        uint8_t in_mask[in_len][m - D][r_BYTES];
        uint64_t v_in[in_len];
        uint8_t out_mask[out_len][m - D][r_BYTES];
        uint64_t v_out[out_len];
        coin_t in[in_len];
        coin_t out[out_len];
        uint64_t total = 0;

        for (int i = 0; i < in_len; i++) {
            for (int j = 0; j < m - D; j++) memset(in_mask[i][j], 0, r_BYTES);
            v_in[i] = rand() % 10;
            total += v_in[i];
            lactx_coin_create(&store.ctx, &in[i], in_mask[i], v_in[i]);
        }

        for (int i = 0; i < out_len; i++) {
            for (int j = 0; j < m - D; j++) memset(out_mask[i][j], 0, r_BYTES);
            v_out[i] = rand() % (total + 1);
            total -= v_out[i];
        }
        v_out[out_len - 1] += total;

        header_t header;
        lactx_header_init(&header, out_len, in_len);
        CHECK(lactx_header_create(&store.ctx, &header,
                                  out_len, out, out_mask, v_out,
                                  in_len, in, in_mask, v_in) == 1);
        CHECK(lactx_header_verify(&store.ctx, &header) == 1);
        lactx_header_free(&header);
    }

    lactx_drop_store(&store);
}


void test_stats(void) {
    remove("test_ctx.db");
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store;

    // Check tx adding
    store = lactx_get_store(seed, "test_ctx.db");
    CHECK(lactx_store_verify(&store) == 1);

    for (int t = 0; t < 10; t++) {
        unsigned int in_len = (rand() % MAX_ADDITIONS) + 1;
        unsigned int out_len = (rand() % MAX_ADDITIONS) + 1;

        uint8_t in_mask[in_len][m - D][r_BYTES];
        uint64_t v_in[in_len];
        uint8_t out_mask[out_len][m - D][r_BYTES];
        uint64_t v_out[out_len];
        coin_t in[in_len];
        coin_t out[out_len];
        uint64_t total = 0;

        for (int i = 0; i < in_len; i++) {
            for (int j = 0; j < m - D; j++) memset(in_mask[i][j], 0, r_BYTES);
            v_in[i] = rand() % 10;
            total += v_in[i];
            lactx_coin_create(&store.ctx, &in[i], in_mask[i], v_in[i]);
        }

        for (int i = 0; i < out_len; i++) {
            for (int j = 0; j < m - D; j++) memset(out_mask[i][j], 0, r_BYTES);
            v_out[i] = rand() % (total + 1);
            total -= v_out[i];
        }
        v_out[out_len - 1] += total;

        header_t header;
        lactx_header_init(&header, out_len, in_len);
        CHECK(lactx_header_create(&store.ctx, &header,
                                  out_len, out, out_mask, v_out,
                                  in_len, in, in_mask, v_in) == 1);
        CHECK(lactx_header_verify(&store.ctx, &header) == 1);
        lactx_header_free(&header);
    }

    lactx_drop_store(&store);
}

void poly_print(poly *a) {
    for (int i = 0; i < N; i++)
        printf("%ld ", a->coef[i]);
    printf("\n");
}


int main(void) {

    test_reduce64();
    test_ntt();
    test_matrix_mul();
    test_check_norm();
    test_get_masks();
    test_challenge_poly();
    test_pack();
    //test_max_min_value();

    test_headers();
    test_poly_easy_mul();
    test_highbit_compare();
    test_basic_coin_header();

    int64_t a = -((int64_t)1 << (18 + 33));
    printf("%ld %ld\n", ((((int64_t)(a + (((int64_t)1) << (33 - 1)) - 1)))>> (33)),
           highbits(((int64_t)1 << (18 + 44)), 33));

    a = -((int64_t)1 << (9 + t2_ERROR));
    printf("%ld %ld %ld\n", a, highbits(a, t2_ERROR),
           ((((int64_t)(a + (((int64_t)1) << (t2_ERROR - 1)) - 1)) << (64 - K11 + 1))>> (t2_ERROR + 64 - K11 + 1)));
    a = ((int64_t)1 << (9 + t2_ERROR));
    printf("%ld %ld %ld\n", a, highbits(a, t2_ERROR),
           ((((int64_t)(a + (((int64_t)1) << (t2_ERROR - 1)) - 1)) << (64 - K11 + 1))>> (t2_ERROR + 64 - K11 + 1)));
    a = ((int64_t)1 << (9 + t2_ERROR)) - 1;
    printf("%ld %ld %ld\n", a, highbits(a, t2_ERROR),
           ((((int64_t)(a + (((int64_t)1) << (t2_ERROR - 1)) - 1)) << (64 - K11 + 1))>> (t2_ERROR + 64 - K11 + 1)));

    printf("%ld %ld\n", reduce64(Q2), reduce64(-Q2));
    printf("%ld %ld\n", highbits(Q2, t2_ERROR), highbits(-Q2, t2_ERROR));
    printf("%ld %ld\n", roundup(highbits(Q2, t2_ERROR), t2_ERROR),
           roundup(highbits(-Q2, t2_ERROR), t2_ERROR));

    test_store();
    test_store2();

    for (unsigned int i = 0; i < 10; i++)
        printf("Carry Range: %d %d\n", i, get_carry_range(i));

    test_stats();

    printf("coin size: %d\n", (SEED_BYTES + u_HIGHBITS + t1_HIGHBITS + z_BYTES + R_BYTES + 8));
    printf("commitment size: %d\n", u_HIGHBITS);
    printf("t1 size: %d\n", t1_HIGHBITS);
    printf("R bytes: %d\n", R_BYTES);
    printf("z Bytes: %d\n", z_BYTES);
    printf("Hint bytes: %d\n", HINTBYTES);


    printf("\nTest passed!\n");
    return 0;
}

#include "lactx_db.c"
#include "lactx_coin.c"
#include "lactx_header.c"