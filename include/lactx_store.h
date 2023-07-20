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

#ifndef LCTx_STORE_H
#define LCTx_STORE_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "../src/lattice256/polyvec.h"
#include "../src/lactx_pack.h"

#define ORIGAMI_HASH_BYTES 49
/**
 * aggregate data store
 */

static int test_mode_carrier = 0;

typedef struct context_struct {
    poly_m H[LACTX_n];
    uint8_t seed[SEED_BYTES];
    poly one_N;
    uint8_t q[ORIGAMI_HASH_BYTES];
    BIGNUM *bn_q;
    BIGNUM *bn_one;
    BN_CTX *bn_ctx;
} context_t;

typedef struct coin_struct {
    uint8_t x2[SEED_BYTES];
    poly_n u;
    poly_n t1;
    poly_n t2_hints;
    poly z[LACTX_L];
    poly R[LACTX_m - D];
    uint64_t s;
} coin_t;

typedef struct header_struct {
    uint64_t v_in;  // coinbase amount when the carrier was created
    uint64_t v_out;  // coins transferred from the coinbase
    uint8_t x0[SEED_BYTES];
    uint8_t x2[SEED_BYTES];
    unsigned int in_len;
    unsigned int out_len;
    poly_n pk;
    poly sigma[LACTX_m - D];
    poly_n u;
    poly_n t1;
    poly *z0;
    poly *z1;
    poly R[LACTX_m - D];
    poly_n y_hints;
    poly_n t2_hints;
    uint8_t delta[ORIGAMI_HASH_BYTES];
    poly s_hat_p;
    poly s0_hat;
    poly s1_hat;
    poly s0_hat_pp;
    poly s1_hat_pp;
} header_t;

typedef struct ctx_struct {
    header_t header;
    coin_t *in;
    coin_t *out;
} ctx_t;

typedef struct store_struct {
    uint64_t supply;
    uint64_t coinbase;
    context_t ctx;
    sqlite3 *db;
    poly_n u;
} store_t;

typedef uint8_t key[LACTX_m - D][r_BYTES];

# if !defined(LCTx_GNUC_PREREQ)
#  if defined(__GNUC__) && defined(__GNUC_MINOR__)
#   define LCTx_GNUC_PREREQ(_maj, _min) \
 ((__GNUC__<<16)+__GNUC_MINOR__>=((_maj)<<16)+(_min))
#  else
#   define LCTx_GNUC_PREREQ(_maj,_min) 0
#  endif
# endif

# if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L))
#  if LCTx_GNUC_PREREQ(2,7)
#   define LCTx_INLINE __inline__
#  elif (defined(_MSC_VER))
#   define LCTx_INLINE __inline
#  else
#   define LCTx_INLINE
#  endif
# else
#  define LCTx_INLINE inline
# endif

#ifndef LCTx_API
# if defined(_WIN32)
#  ifdef LCTx_BUILD
#   define LCTx_API __declspec(dllexport)
#  else
#   define LCTx_API
#  endif
# elif defined(__GNUC__) && defined(LCTx_BUILD)
#  define LCTx_API __attribute__ ((visibility ("default")))
# else
#  define LCTx_API
# endif
#endif

# if defined(__GNUC__) && LCTx_GNUC_PREREQ(3, 4)
#  define LCTx_UNUSED __attribute__((unused))
# else
#  define LCTx_UNUSED
# endif

# if defined(__GNUC__) && LCTx_GNUC_PREREQ(3, 4)
#  define LCTx_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
# else
#  define LCTx_WARN_UNUSED_RESULT
# endif

# if !defined(LCTx_BUILD) && defined(__GNUC__) && LCTx_GNUC_PREREQ(3, 4)
#  define LCTx_ARG_NONNULL(_x)  __attribute__ ((__nonnull__(_x)))
# else
#  define LCTx_ARG_NONNULL(_x)
# endif


void hash_self_mul(uint8_t *hash0, const uint8_t *hash1, const BIGNUM *q, BN_CTX *ctx);
void hash_self_div(uint8_t *hash0, const uint8_t *hash1, const BIGNUM *q, BN_CTX *ctx);
void coin_hash(context_t *ctx, uint8_t *hash, uint8_t u_bytes[u_HIGHBITS]);

void binary_set(
        poly *b,
        uint64_t v
) LCTx_ARG_NONNULL(1);

LCTx_API void lactx_key_copy(
        key out,
        key in
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API void lactx_coin_copy(
        coin_t *a,
        coin_t *b
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

void lactx_coin_print(coin_t *a);
void lactx_carrier_print(header_t *a);
void lactx_carrier_compare(header_t *a, header_t *b);

LCTx_API void lactx_mint_coin_create(
        context_t *ctx,
        coin_t *coin,
        uint64_t s
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API int lactx_coin_create (
        context_t *ctx,
        coin_t *coin,
        uint8_t mask[LACTX_m - 3][r_BYTES],
        uint64_t v
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2) LCTx_ARG_NONNULL(3);

LCTx_API int lactx_coin_open (
        context_t *ctx,
        coin_t *coin,
        uint8_t mask[LACTX_m - 3][r_BYTES],
        uint64_t v
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API int lactx_coin_verify (
        context_t *ctx,
        coin_t *coin
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API int lactx_header_init(
        header_t *carrier,
        unsigned int out_len,
        unsigned int int_len
) LCTx_ARG_NONNULL(1);

LCTx_API int lactx_header_free(
        header_t *carrier
)LCTx_ARG_NONNULL(1);

LCTx_API int lactx_tx_init (
        ctx_t *tx,
        unsigned int out_len,
        unsigned int in_len
) LCTx_ARG_NONNULL(1);

LCTx_API void lactx_tx_free (
        ctx_t *tx
) LCTx_ARG_NONNULL(1);

LCTx_API int lactx_header_create(
        context_t *ctx,
        header_t *header,
        unsigned int out_len,
        coin_t *out_coins,
        uint8_t out_masks[][LACTX_m - D][r_BYTES],
        uint64_t *v_out,
        unsigned int in_len,
        coin_t *in_coins,
        uint8_t in_masks[][LACTX_m - D][r_BYTES],
        uint64_t *v_in)
LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2) LCTx_ARG_NONNULL(4)
LCTx_ARG_NONNULL(5) LCTx_ARG_NONNULL(6) LCTx_ARG_NONNULL(8)
LCTx_ARG_NONNULL(9) LCTx_ARG_NONNULL(10);

LCTx_API int lactx_minted_header_create(
        context_t *ctx,
        header_t *carrier,
        coin_t *out_coins,
        uint8_t out_mask[LACTX_m - 3][r_BYTES],
        uint64_t v_out,
        coin_t *in_coins,
        uint64_t coinbase)
LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2) LCTx_ARG_NONNULL(3)
LCTx_ARG_NONNULL(4) LCTx_ARG_NONNULL(6);

unsigned int get_carry_range(unsigned int additions);

LCTx_API void set_carries(
        poly *c,
        const uint64_t *v,
        unsigned int len
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API int lactx_header_verify(
        context_t *ctx,
        header_t *carrier)
LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API context_t lactx_init (
        uint8_t seed[48]
) LCTx_ARG_NONNULL(1);

LCTx_API void lactx_ctx_free(
        context_t *ctx
) LCTx_ARG_NONNULL(1);

void lactx_db_connect(
        store_t *store,
        char *db_path);

void lactx_db_close(store_t *store);

void lactx_db_drop(store_t *store);

void lactx_ucoin_add(store_t *store, coin_t *coin);

int lactx_ucoin_check(store_t *store, coin_t *coin);

void lactx_ucoin_delete(store_t *store, coin_t *coin);

void lactx_header_add(store_t *store, header_t *carrier);

int lactx_db_read(store_t *store, poly_n *aggr_pk, poly_n *aggr_u);

LCTx_API store_t lactx_get_store(
        uint8_t seed[48],
        char *db_path
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API void lactx_free_store(
        store_t *store
) LCTx_ARG_NONNULL(1);

LCTx_API void lactx_drop_store(
        store_t *store
) LCTx_ARG_NONNULL(1);

LCTx_API void lactx_mint_tx_create(
        store_t *store,
        ctx_t *tx,
        uint8_t mask[LACTX_m - D][r_BYTES],
        uint64_t s
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2) LCTx_ARG_NONNULL(3);

LCTx_API int lactx_tx_verify (
        store_t *store,
        ctx_t *tx
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API void lactx_tx_aggregate (
        store_t *store,
        ctx_t *tx
) LCTx_ARG_NONNULL(1) LCTx_ARG_NONNULL(2);

LCTx_API int lactx_store_verify(
        store_t *store
) LCTx_ARG_NONNULL(1);


#ifdef __cplusplus
}
#endif

#endif /* LCTx_STORE_H */
