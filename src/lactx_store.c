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

#include "lactx_store.h"
#include <stdio.h>

// if your checking this on sage or python; use shift to divide; they can not handle large numbers
const unsigned char ORIGAMI_Q[] = "143259550146864969418328063258684716677167666215049723840114992558692571926412012600818388418434147953731204478676739";
const unsigned char ORIGAMI_P[] =  "71629775073432484709164031629342358338583833107524861920057496279346285963206006300409194209217073976865602239338369";


/**
 * Returns delta = Hash(state, pk) mod q
 * @param store
 * @param e
 */
void coin_hash(context_t *ctx, uint8_t *hash, uint8_t u_bytes[u_HIGHBITS]) {
    SHA512_CTX sha384;
    SHA384_Init(&sha384);
    SHA384_Update(&sha384, u_bytes, u_HIGHBITS);
    SHA384_Final(hash + 1, &sha384);
    hash[0] = 0;
    BIGNUM *h = BN_new();
    BN_bin2bn(hash, ORIGAMI_HASH_BYTES, h);
    BN_mod(h, h, ctx->bn_q, ctx->bn_ctx);
    BN_bn2binpad(h, hash, ORIGAMI_HASH_BYTES);
    BN_clear(h);
    BN_free(h);
}

/**
 * Returns hash0 = (hash0 * hash1) mod q
 * @param hash0
 * @param hash1
 * @param q
 * @param ctx
 */
void hash_self_mul(uint8_t *hash0, const uint8_t *hash1, const BIGNUM *q, BN_CTX *ctx) {
    BIGNUM *h0 = BN_new();
    BIGNUM *h1 = BN_new();
    BN_bin2bn(hash0, ORIGAMI_HASH_BYTES, h0);
    BN_bin2bn(hash1, ORIGAMI_HASH_BYTES, h1);
    BN_mod_mul(h0, h0, h1, q, ctx);
    BN_bn2binpad(h0, hash0, ORIGAMI_HASH_BYTES);
    BN_clear(h0);
    BN_clear(h1);
    BN_free(h0);
    BN_free(h1);
}


/**
 * Returns hash0 = (hash0 / hash1) mod q
 * @param hash0
 * @param hash1
 * @param q
 * @param ctx
 */
void hash_self_div(uint8_t *hash0, const uint8_t *hash1, const BIGNUM *q, BN_CTX *ctx) {
    BIGNUM *h0 = BN_new();
    BIGNUM *h1 = BN_new();
    BN_bin2bn(hash0, ORIGAMI_HASH_BYTES, h0);
    BN_bin2bn(hash1, ORIGAMI_HASH_BYTES, h1);
    BN_mod_inverse(h1, h1, q, ctx);
    BN_mod_mul(h0, h0, h1, q, ctx);
    BN_bn2binpad(h0, hash0, ORIGAMI_HASH_BYTES);
    BN_clear(h0);
    BN_clear(h1);
    BN_free(h0);
    BN_free(h1);
}

/**
 * Initiate the context object
 * @param seed - the seed for the hash matrix
 * @return a context object
 */
context_t lactx_init(uint8_t seed[SEED_BYTES]) {
    context_t ctx;
    shake256(ctx.seed, SEED_BYTES, seed, SEED_BYTES);
    poly_matrix_expand(ctx.H, ctx.seed); // in NTT domain

    poly_set_zero(&ctx.one_N, 0, N);
    ctx.one_N.coef[N - 1] = -1;
    poly_ntt(&ctx.one_N);
    memset(ctx.q, 0x0, ORIGAMI_HASH_BYTES);
    ctx.bn_q = BN_bin2bn(ORIGAMI_Q, sizeof(ORIGAMI_Q), NULL);
    BN_bn2binpad(ctx.bn_q, ctx.q, ORIGAMI_HASH_BYTES);
    ctx.bn_ctx = BN_CTX_new();
    ctx.bn_one = BN_new();
    BN_one(ctx.bn_one);
    BN_bin2bn(ctx.q, ORIGAMI_HASH_BYTES, ctx.bn_q);
    return ctx;
}


/**
 * Free the context object
 */
void lactx_ctx_free(context_t *ctx) {
    BN_free(ctx->bn_q);
    BN_free(ctx->bn_one);
    BN_CTX_free(ctx->bn_ctx);
}


/**
 * Initiate the store with 2^63 - 1 coins
 * @param seed - seed for context
 * @param db_path - path for the database
 * @return store object
 */
store_t lactx_get_store(uint8_t seed[SEED_BYTES], char *db_path) {
    store_t store;
    store.ctx = lactx_init(seed);
    store.supply = 9223372036854775807;
    store.coinbase = 9223372036854775807;
    lactx_db_connect(&store, db_path);
    return store;
}

/**
 * Free the store object
 * @param store
 */
void lactx_free_store(store_t *store) {
    lactx_db_close(store);
    lactx_ctx_free(&store->ctx);
}

/**
 * Drop the store object
 * @param store
 */
void lactx_drop_store(store_t *store) {
    lactx_db_drop(store);
    lactx_db_close(store);
    lactx_ctx_free(&store->ctx);
}


void lactx_key_copy(key out, key in) {
    for (int i = 0; i < m - D; i++) {
        memcpy(out + i*r_BYTES, in + i*r_BYTES, r_BYTES);
    }
}

/**
 * Initiate the transaction struct
 * @param tx
 * @param out_len
 * @param in_len
 * @return 1 - successful, 0 - failed
 */
int lactx_tx_init (ctx_t *tx, unsigned int out_len, unsigned int in_len) {
    if (out_len > MAX_ADDITIONS || in_len > MAX_ADDITIONS)
        return 0;
    tx->in = (coin_t *) malloc(in_len * sizeof(coin_t));
    tx->out = (coin_t *) malloc(out_len * sizeof(coin_t));
    lactx_header_init(&tx->header, out_len, in_len);
    return 1;
}

/**
 * Free a transaction struct
 * @param tx
 */
void lactx_tx_free (ctx_t *tx) {
    lactx_header_free(&tx->header);
    free(tx->in);
    free(tx->out);
}

/**
 * Creates a minting transaction that takes coins from the coinbase account.
 * Input is the coinbase account.
 * @param ctx - context object
 * @param tx - confidential transaction object with one input and one output.
 * @param mask - secret mask for the output
 * @param s - supply coin.
 */
void lactx_mint_tx_create(store_t *store, ctx_t *tx, uint8_t mask[m - D][r_BYTES], uint64_t s) {
    tx->header.in_len = 1;
    tx->header.out_len = 2;

    // Create the input coin bundle without range proofs
    lactx_mint_coin_create(&store->ctx, &tx->in[0], store->coinbase);

    // Create the minted carrier
    lactx_minted_header_create(&store->ctx, &tx->header, tx->out, mask, s, tx->in, store->coinbase);
}


/**
 * Verifies coins, carrier proof, and the public key of a transactions
 * @param ctx - context object
 * @param tx - confidential transaction object
 * @return 1 if the transaction is valid, otherwise 0.
 */
int lactx_tx_verify(store_t *store, ctx_t *tx) {
    unsigned int i;

    uint8_t u_bytes[u_HIGHBITS];
    uint8_t delta[ORIGAMI_HASH_BYTES];
    pack_poly_ring_custom(u_bytes, &tx->out[0].u, K1 - u_ERROR);
    coin_hash(&store->ctx, delta, u_bytes);

    // Minting transaction
    if (tx->header.v_in != 0 || tx->header.v_out != 0) {
        if (tx->header.in_len != 1 && tx->header.out_len != 2)
            return 0;

        if (memcmp(delta, tx->header.delta, ORIGAMI_HASH_BYTES) != 0) {
            printf("delta error %d\n", __LINE__);
            return 0;
        }

        // verify the input
        if (lactx_coin_open(&store->ctx, &tx->in[0], NULL, tx->in[0].s) == 0)
            return 0;

        // verify the output
        if (lactx_coin_verify(&store->ctx, &tx->out[0]) == 0) {
            printf("error %d\n", __LINE__);
            return 0;
        }
        if (lactx_coin_open(&store->ctx, &tx->out[1], NULL, tx->out[1].s) == 0) {
            return 0;
            printf("error %d", __LINE__);
        }

        // verify the carrier
        if (lactx_header_verify(&store->ctx, &tx->header) == 0) {
            printf("error %d\n", __LINE__);
            return 0;
        }

        // check pk ?= carrier.u + \sum out.u - \sum in.u
        poly_n pk;
        poly_n_sub(&pk, &tx->out[0].u, &tx->in[0].u); // these two values must exist
        poly_n_add(&pk, &pk,  &tx->out[1].u);
        poly_n_add(&pk, &pk,  &tx->header.u);

        poly_n_roundup(&pk, &pk, u_ERROR);
        poly_n_reduce_exact(&pk);
        poly_n_highbits(&pk, &pk, pk_ERROR);

        return poly_n_compare(&pk, &tx->header.pk) == 0;
    }

    // Normal Transaction

    // Create delta
    uint8_t tmp_delta[ORIGAMI_HASH_BYTES];
    for (i = 1; i < tx->header.out_len; i++) {
        pack_poly_ring_custom(u_bytes, &tx->out[i].u, K1 - u_ERROR);
        coin_hash(&store->ctx, tmp_delta, u_bytes);
        hash_self_mul(delta, tmp_delta, store->ctx.bn_q, store->ctx.bn_ctx);
    }
    for (i = 0; i < tx->header.in_len; i++) {
        pack_poly_ring_custom(u_bytes, &tx->in[i].u, K1 - u_ERROR);
        coin_hash(&store->ctx, tmp_delta, u_bytes);
        hash_self_div(delta, tmp_delta, store->ctx.bn_q, store->ctx.bn_ctx);
    }

    if (memcmp(delta, tx->header.delta, ORIGAMI_HASH_BYTES) != 0) {
        printf("delta error %d\n", __LINE__);
        return 0;
    }

    // verify inputs
    for (i = 0; i < tx->header.in_len; i++) {
        if (lactx_coin_verify(&store->ctx, &tx->in[i]) == 0 || lactx_ucoin_check(store, &tx->in[i]) == 0){
            printf("error %d\n", __LINE__);
            return 0;
        }
    }

    // verify outputs
    for (i = 0; i < tx->header.out_len; i++) {
        if (lactx_coin_verify(&store->ctx, &tx->out[i]) == 0){
            printf("error %d\n", __LINE__);
            return 0;
        }
    }

    // verify the carrier
    if (lactx_header_verify(&store->ctx, &tx->header) == 0) {
        printf("error %d\n", __LINE__);
        return 0;
    }

    // check pk ?= carrier.u + \sum out.u - \sum in.u
    poly_n pk;
    poly_n_sub(&pk, &tx->out[0].u, &tx->in[0].u); // these two values must exist
    for (i = 1; i < tx->header.in_len; i++) {
        poly_n_sub(&pk, &pk, &tx->in[i].u);
    }
    for (i = 1; i < tx->header.out_len; i++) {
        poly_n_add(&pk, &pk, &tx->out[i].u);
    }
    if (tx->header.in_len >= 2 || tx->header.out_len >= 2) poly_n_add(&pk, &pk, &tx->header.u);

    poly_n_roundup(&pk, &pk, u_ERROR);
    poly_n_reduce_exact(&pk);
    poly_n_highbits(&pk, &pk, u_ERROR);

    return poly_n_compare(&pk, &tx->header.pk) == 0;
}


/**
 * Add a transaction to the database (the transaction will not be verified)
 * @param store - store object
 * @param tx - confidential transaction object
 */
void lactx_tx_aggregate(store_t *store, ctx_t *tx) {
    unsigned int i;

    // Minting transaction
    if (tx->header.v_in != 0 || tx->header.v_out != 0) {
        // update coinbase in store
        store->coinbase = store->coinbase - tx->header.v_out;

        // add outputs to the ucoin table
        lactx_ucoin_add(store, &tx->out[0]);
        lactx_header_add(store, &tx->header);
    }
    // Normal transaction
    else {
        // remove inputs from ucoin_table
        for (i = 0; i < tx->header.in_len; i++)
            lactx_ucoin_delete(store, &tx->in[i]);

        // add outputs to the ucoin table
        for (i = 0; i < tx->header.out_len; i++)
            lactx_ucoin_add(store, &tx->out[i]);

        lactx_header_add(store, &tx->header);
    }
}

/**
 * Verify the store or the cash system
 * @param store
 * @return 0 - valid, -1 - invalid
 */
int lactx_store_verify(store_t *store) {
    poly_m s;
    poly_n u;
    poly_n aggr_pk;
    poly_n aggr_u;

    if (lactx_db_read(store, &aggr_pk, &aggr_u) == 0)
        return 0;

    // u = H[bin(coinbase), 0^N, .., 0^N]
    poly_m_set_zero(&s, 0, N);
    binary_set(&s.vec[0], store->coinbase);
    poly_ntt(&s.vec[0]);
    poly_matrix_mul(&u, store->ctx.H, &s);
    poly_n_inv_ntt_to_mont(&u);
    poly_n_reduce_exact(&u);
    poly_n_highbits(&u, &u, u_ERROR);
    poly_n_add(&aggr_u, &aggr_u, &u);

    // u = H[bin(supply), 0^N, .., 0^N]
    poly_m_set_zero(&s, 0, N);
    binary_set(&s.vec[0], store->supply);
    poly_ntt(&s.vec[0]);
    poly_matrix_mul(&u, store->ctx.H, &s);
    poly_n_inv_ntt_to_mont(&u);
    poly_n_reduce_exact(&u);
    poly_n_highbits(&u, &u, u_ERROR);
    poly_n_sub(&aggr_u, &aggr_u, &u);

    poly_n_roundup(&aggr_u, &aggr_u, u_ERROR);
    poly_n_reduce_exact(&aggr_u);
    poly_n_highbits(&aggr_u, &aggr_u, aggr_ERROR);

    poly_n_roundup(&aggr_pk, &aggr_pk, u_ERROR);
    poly_n_reduce_exact(&aggr_pk);
    poly_n_highbits(&aggr_pk, &aggr_pk, aggr_ERROR);

    return poly_n_hints(&u, &aggr_u, &aggr_pk) == 0;
}
