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

#ifndef LACTX_LACTX_DB_IMPL_H
#define LACTX_LACTX_DB_IMPL_H

#include <math.h>
#include "lactx_store.h"
#include "util.h"

const char sql_open_ucoin_table[] = "CREATE TABLE IF NOT EXISTS UCOIN_TABLE("  \
      "ID           INTEGER    PRIMARY KEY     AUTOINCREMENT," \
      "X2           BLOB     NOT NULL," \
      "U            BLOB     NOT NULL," \
      "T1           BLOB     NOT NULL," \
      "T2_HINTS     BLOB     NOT NULL," \
      "ZL           BLOB     NOT NULL," \
      "R            BLOB     NOT NULL);";

const char sql_open_header_table[] = "CREATE TABLE IF NOT EXISTS HEADER_TABLE("  \
      "ID           INTEGER    PRIMARY KEY     AUTOINCREMENT," \
      "X0           BLOB     NOT NULL," \
      "X2           BLOB     ," \
      "IN_LEN       INT      NOT NULL," \
      "OUT_LEN      INT      NOT NULL," \
      "PK           BLOB     NOT NULL," \
      "SIGMA        BLOB     NOT NULL," \
      "U            BLOB     ," \
      "T1           BLOB     ," \
      "Z0L          BLOB     ," \
      "Z1L          BLOB     ," \
      "R            BLOB     ,"
      "V_IN         BLOB     NOT NULL,"
      "V_OUT        BLOB     NOT NULL,"
      "Y_HINTS      BLOB     NOT NULL,"
      "T2_HINTs     BLOB                );";

const char sql_open_ucoin_index_table[] = "CREATE INDEX IF NOT EXISTS X2_INDEX_TABLE ON UCOIN_TABLE (X2);";

const char sql_drop_ucoin_table[] = "DROP TABLE IF EXISTS UCOIN_TABLE;";

const char sql_drop_header_table[] = "DROP TABLE IF EXISTS HEADER_TABLE;";

const char sql_drop_ucoin_index_table[] = "DROP INDEX IF EXISTS X2_INDEX_TABLE;";

const char sql_read_ucoins[] = "SELECT * FROM UCOIN_TABLE;";

const char sql_read_headers[] = "SELECT * FROM HEADER_TABLE;";

const char sql_insert_ucoin[] = "INSERT INTO UCOIN_TABLE " \
        "(X2, U, T1, T2_HINTS, ZL, R) " \
        "values (?1, ?2, ?3, ?4, ?5, ?6);";

const char sql_insert_header[] =
        "INSERT INTO HEADER_TABLE " \
        "(X0, X2, IN_LEN, OUT_LEN, PK, SIGMA, U, T1, Z0L, Z1L, R, V_IN, V_OUT, Y_HINTS, T2_HINTS) " \
        "values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15);";

const char sql_insert_header_null_z0[] =
        "INSERT INTO HEADER_TABLE " \
        "(X0, X2, IN_LEN, OUT_LEN, PK, SIGMA, U, T1, Z1L, R, V_IN, V_OUT, Y_HINTS, T2_HINTS) " \
        "values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?10, ?11, ?12, ?13, ?14, ?15);";

const char sql_insert_header_null_z1[] =
        "INSERT INTO HEADER_TABLE " \
        "(X0, X2, IN_LEN, OUT_LEN, PK, SIGMA, U, T1, Z0L, R, V_IN, V_OUT, Y_HINTS, T2_HINTS) " \
        "values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?11, ?12, ?13, ?14, ?15);";

const char sql_insert_header_null_z[] =
        "INSERT INTO HEADER_TABLE " \
        "(X0, IN_LEN, OUT_LEN, PK, SIGMA, V_IN, V_OUT, Y_HINTS) " \
        "values (?1, ?3, ?4, ?5, ?6, ?12, ?13, ?14);";

const char sql_insert_minted_header[] =
        "INSERT INTO HEADER_TABLE " \
        "(X0, IN_LEN, OUT_LEN, PK, SIGMA, U, V_IN, V_OUT, Y_HINTS) " \
        "values (?1, ?3, ?4, ?5, ?6, ?7, ?12, ?13, ?14);";

const char sql_exists_ucoin[] = "SELECT EXISTS(SELECT 1 FROM UCOIN_TABLE WHERE X2 = ?1);";

const char sql_delete_ucoin[] = "DELETE FROM UCOIN_TABLE WHERE X2 = ?1;";


/**
 * Connect to DB
 * @param store - store object
 * @param db_path - file path to the db
 */
void lactx_db_connect(store_t *store, char *db_path) {
    char *error = 0;

    SQLITE3_NOFREE_CHECK(sqlite3_open(db_path, &store->db) == SQLITE_OK, sqlite3_errmsg(store->db), store->db, NULL);
    SQLITE3_CHECK(sqlite3_exec(store->db, sql_open_ucoin_table, NULL, 0, &error) == SQLITE_OK, error, store->db);
    SQLITE3_CHECK(sqlite3_exec(store->db, sql_open_header_table, NULL, 0, &error) == SQLITE_OK, error, store->db);
    SQLITE3_CHECK(sqlite3_exec(store->db, sql_open_ucoin_index_table, NULL, 0, &error) == SQLITE_OK, error, store->db);
}


/**
 * Close the connection to the DB
 * @param store - store object
 */
void lactx_db_close(store_t *store) {
    sqlite3_close(store->db);
}


/**
 * Drop all the tables from the DB
 * @param store - store object
 */
void lactx_db_drop(store_t *store) {
    char *error = 0;

    SQLITE3_CHECK(sqlite3_exec(store->db, sql_drop_ucoin_index_table, NULL, 0, &error) == SQLITE_OK, error, store->db);
    SQLITE3_CHECK(sqlite3_exec(store->db, sql_drop_ucoin_table, NULL, 0, &error) == SQLITE_OK, error, store->db);
    SQLITE3_CHECK(sqlite3_exec(store->db, sql_drop_header_table, NULL, 0, &error) == SQLITE_OK, error, store->db);
}


/**
 * Add a confidential coin object to the database
 * @param store - store object
 * @param coin - coin object
 */
void lactx_ucoin_add(store_t *store, coin_t *coin) {
    char *error = 0;
    sqlite3_stmt *stmt;

    uint8_t u_bytes[u_HIGHBITS];
    uint8_t t1_bytes[t1_HIGHBITS];
    uint8_t zl_bytes[z_BYTES];
    uint8_t R_bytes[R_BYTES];
    uint8_t t2_hint_bytes[HINTBYTES];

    SQLITE3_CHECK(sqlite3_exec(store->db, "BEGIN TRANSACTION", NULL, NULL, &error) == SQLITE_OK, error, store->db);

    sqlite3_prepare_v2(store->db, sql_insert_ucoin, -1, &stmt, NULL);

    // x2
    sqlite3_bind_blob(stmt, 1, coin->x2, SEED_BYTES, SQLITE_STATIC);
    // u
    pack_poly_ring_custom(u_bytes, &coin->u, K1 - u_ERROR);
    sqlite3_bind_blob(stmt, 2, u_bytes, u_HIGHBITS, SQLITE_STATIC);
    // t1
    pack_poly_ring_custom(t1_bytes, &coin->t1, K1 - t1_ERROR);
    sqlite3_bind_blob(stmt, 3, t1_bytes, t1_HIGHBITS, SQLITE_STATIC);
    // t2_hints
    pack_poly_ring_custom(t2_hint_bytes, &coin->t2_hints, HINTBITS);
    sqlite3_bind_blob(stmt, 4, t2_hint_bytes, HINTBYTES, SQLITE_STATIC);
    // z[LACTX_L]
    pack_poly_z(zl_bytes, coin->z);
    sqlite3_bind_blob(stmt, 5, zl_bytes, z_BYTES, SQLITE_STATIC);
    // R[LACTX_m - 3]
    pack_poly_m_R(R_bytes, coin->R);
    sqlite3_bind_blob(stmt, 6, R_bytes, R_BYTES, SQLITE_STATIC);

    SQLITE3_ROLLBACK_CHECK(sqlite3_step(stmt) == SQLITE_DONE, sqlite3_errmsg(store->db), store->db, stmt);
    sqlite3_finalize(stmt);

    SQLITE3_CHECK(sqlite3_exec(store->db, "END TRANSACTION", NULL, NULL, &error) == SQLITE_OK, error, store->db);

}


/**
 * Check whether coin exists or not
 * @param store - store object
 * @param coin - confidential coin bundles
 * @return 1 if the coin exists, otherwise return 0.
 */
int lactx_ucoin_check(store_t *store, coin_t *coin) {
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(store->db, sql_exists_ucoin, -1, &stmt, NULL);
    sqlite3_bind_blob(stmt, 1, coin->x2, SEED_BYTES, SQLITE_STATIC);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        if (sqlite3_column_int(stmt, 0) == 0) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    sqlite3_finalize(stmt);
    return 1;
}


/**
 * Delete a coin from the database
 * @param store - store object
 * @param coin - coin object
 */
void lactx_ucoin_delete(store_t *store, coin_t *coin) {
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(store->db, sql_delete_ucoin, -1, &stmt, NULL);
    // x2
    sqlite3_bind_blob(stmt, 1, coin->x2, SEED_BYTES, SQLITE_STATIC);

    SQLITE3_ROLLBACK_CHECK(sqlite3_step(stmt) == SQLITE_DONE, sqlite3_errmsg(store->db), store->db, stmt);
    sqlite3_finalize(stmt);
}


/**
 * Add a carrier proof
 * @param store - store object
 * @param carrier - carrier proof
 */
void lactx_header_add(store_t *store, header_t *carrier) {
    char *error = 0;
    sqlite3_stmt *stmt;
    int sig_BYTES = get_sig_bytes(carrier->in_len, carrier->out_len);

    unsigned int in_carries = get_carry_range(carrier->in_len);
    unsigned int out_carries = get_carry_range(carrier->out_len);
    int in_carry_bits = ALPHA_BITS + ceil(log2(carrier->in_len - 1)/2);
    int out_carry_bits = ALPHA_BITS + ceil(log2(carrier->out_len - 1)/2);
    int z0l_byte_len = (LACTX_L * LACTX_N * (in_carry_bits + 1)) / 8;
    int z1l_byte_len = (LACTX_L * LACTX_N * (out_carry_bits + 1)) / 8;

    uint8_t pk_bytes[pk_HIGHBITS];
    uint8_t sig_bytes[sig_BYTES];
    uint8_t u_bytes[u_HIGHBITS];
    uint8_t t1_bytes[t1_HIGHBITS];
    uint8_t z0l_bytes[z0l_byte_len*in_carries];
    uint8_t z1l_bytes[z1l_byte_len*out_carries];
    uint8_t R_bytes[R_BYTES];
    uint8_t y_hints_bytes[HINTBYTES];
    uint8_t t2_hints_bytes[HINTBYTES];

    int l;

    SQLITE3_CHECK(sqlite3_exec(store->db, "BEGIN TRANSACTION", NULL, NULL, &error) == SQLITE_OK, error, store->db);

    // Minted carrier proof
    if (carrier->v_in != 0 || carrier->v_out != 0) {
        sqlite3_prepare_v2(store->db, sql_insert_minted_header, -1, &stmt, NULL);

        // x0
        sqlite3_bind_blob(stmt, 1, carrier->x0, SEED_BYTES, SQLITE_STATIC);
        // in_len
        sqlite3_bind_int(stmt, 3, (int) carrier->in_len);
        // out_len
        sqlite3_bind_int(stmt, 4, (int) carrier->out_len);
        // pk
        pack_poly_ring_custom(pk_bytes, &carrier->pk, K1 - pk_ERROR);
        sqlite3_bind_blob(stmt, 5, pk_bytes, pk_HIGHBITS, SQLITE_STATIC);
        // sigma
        pack_poly_sig(sig_bytes, carrier->sigma, (int)(carrier->in_len + carrier->out_len));
        sqlite3_bind_blob(stmt, 6, sig_bytes, sig_BYTES, SQLITE_STATIC);
        // u
        pack_poly_ring_custom(u_bytes, &carrier->u, K1 - u_ERROR);
        sqlite3_bind_blob(stmt, 7, u_bytes, u_HIGHBITS, SQLITE_STATIC);
        // v_in
        sqlite3_bind_blob(stmt, 12, &carrier->v_in, sizeof(uint64_t), SQLITE_STATIC);
        // v_out
        sqlite3_bind_blob(stmt, 13, &carrier->v_out, sizeof(uint64_t), SQLITE_STATIC);
        // y_hints
        pack_poly_ring_custom(y_hints_bytes, &carrier->y_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 14, y_hints_bytes, HINTBYTES, SQLITE_STATIC);
    }
    // Normal carrier proofs
    else if (carrier->in_len >= 2 && carrier->out_len >= 2) {
        sqlite3_prepare_v2(store->db, sql_insert_header, -1, &stmt, NULL);

        // x0
        sqlite3_bind_blob(stmt, 1, carrier->x0, SEED_BYTES, SQLITE_STATIC);
        // x2
        sqlite3_bind_blob(stmt, 2, carrier->x2, SEED_BYTES, SQLITE_STATIC);
        // in_len
        sqlite3_bind_int(stmt, 3, (int) carrier->in_len);
        // out_len
        sqlite3_bind_int(stmt, 4, (int) carrier->out_len);
        // pk
        pack_poly_ring_custom(pk_bytes, &carrier->pk, K1 - pk_ERROR);
        sqlite3_bind_blob(stmt, 5, pk_bytes, pk_HIGHBITS, SQLITE_STATIC);
        // sigma
        pack_poly_sig(sig_bytes, carrier->sigma, (int)(carrier->in_len + carrier->out_len));
        sqlite3_bind_blob(stmt, 6, sig_bytes, sig_BYTES, SQLITE_STATIC);
        // u
        pack_poly_ring_custom(u_bytes, &carrier->u, K1 - u_ERROR);
        sqlite3_bind_blob(stmt, 7, u_bytes, u_HIGHBITS, SQLITE_STATIC);
        // t1
        pack_poly_ring_custom(t1_bytes, &carrier->t1, K1 - t1_ERROR);
        sqlite3_bind_blob(stmt, 8, t1_bytes, t1_HIGHBITS, SQLITE_STATIC);
        // z0[LACTX_L]
        for (l = 0; l < in_carries; l++) {
            pack_poly_z_custom(z0l_bytes + z0l_byte_len*l, carrier->z0 + LACTX_L * l, in_carry_bits);
        }
        sqlite3_bind_blob(stmt, 9, z0l_bytes, z0l_byte_len*in_carries, SQLITE_STATIC);
        // z1[LACTX_L]
        for (l = 0; l < out_carries; l++) {
            pack_poly_z_custom(z1l_bytes + z1l_byte_len*l, carrier->z1 + LACTX_L * l, out_carry_bits);
        }
        sqlite3_bind_blob(stmt, 10, z1l_bytes, z1l_byte_len*out_carries, SQLITE_STATIC);
        // R[LACTX_m - 3]
        pack_poly_m_R(R_bytes, carrier->R);
        sqlite3_bind_blob(stmt, 11, R_bytes, R_BYTES, SQLITE_STATIC);
        // v_in
        sqlite3_bind_blob(stmt, 12, &carrier->v_in, sizeof(uint64_t), SQLITE_STATIC);
        // v_out
        sqlite3_bind_blob(stmt, 13, &carrier->v_out, sizeof(uint64_t), SQLITE_STATIC);
        // y_hints
        pack_poly_ring_custom(y_hints_bytes, &carrier->y_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 14, y_hints_bytes, HINTBYTES, SQLITE_STATIC);
        // t2_hints
        pack_poly_ring_custom(t2_hints_bytes, &carrier->t2_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 15, t2_hints_bytes, HINTBYTES, SQLITE_STATIC);
    }
    else if (carrier->in_len == 1 && carrier->out_len >= 2) {
        sqlite3_prepare_v2(store->db, sql_insert_header_null_z0, -1, &stmt, NULL);
        // x0
        sqlite3_bind_blob(stmt, 1, carrier->x0, SEED_BYTES, SQLITE_STATIC);
        // x2
        sqlite3_bind_blob(stmt, 2, carrier->x2, SEED_BYTES, SQLITE_STATIC);
        // in_len
        sqlite3_bind_int(stmt, 3, (int) carrier->in_len);
        // out_len
        sqlite3_bind_int(stmt, 4, (int) carrier->out_len);
        // pk
        pack_poly_ring_custom(pk_bytes, &carrier->pk, K1 - pk_ERROR);
        sqlite3_bind_blob(stmt, 5, pk_bytes, pk_HIGHBITS, SQLITE_STATIC);
        // sigma
        pack_poly_sig(sig_bytes, carrier->sigma, (int)(carrier->in_len + carrier->out_len));
        sqlite3_bind_blob(stmt, 6, sig_bytes, sig_BYTES, SQLITE_STATIC);
        // u
        pack_poly_ring_custom(u_bytes, &carrier->u, K1 - u_ERROR);
        sqlite3_bind_blob(stmt, 7, u_bytes, u_HIGHBITS, SQLITE_STATIC);
        // t1
        pack_poly_ring_custom(t1_bytes, &carrier->t1, K1 - t1_ERROR);
        sqlite3_bind_blob(stmt, 8, t1_bytes, t1_HIGHBITS, SQLITE_STATIC);
        // no z0[LACTX_L]
        // z1[LACTX_L]
        for (l = 0; l < out_carries; l++) {
            pack_poly_z_custom(z1l_bytes+ z1l_byte_len*l, carrier->z1 + LACTX_L * l, out_carry_bits);
        }
        sqlite3_bind_blob(stmt, 10, z1l_bytes, z1l_byte_len*out_carries, SQLITE_STATIC);
        // R[LACTX_m - 3]
        pack_poly_m_R(R_bytes, carrier->R);
        sqlite3_bind_blob(stmt, 11, R_bytes, R_BYTES, SQLITE_STATIC);
        // v_in
        sqlite3_bind_blob(stmt, 12, &carrier->v_in, sizeof(uint64_t), SQLITE_STATIC);
        // v_out
        sqlite3_bind_blob(stmt, 13, &carrier->v_out, sizeof(uint64_t), SQLITE_STATIC);
        // y_hints
        pack_poly_ring_custom(y_hints_bytes, &carrier->y_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 14, y_hints_bytes, HINTBYTES, SQLITE_STATIC);
        // t2_hints
        pack_poly_ring_custom(t2_hints_bytes, &carrier->t2_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 15, t2_hints_bytes, HINTBYTES, SQLITE_STATIC);
    }
    else if (carrier->in_len >= 2 && carrier->out_len == 1) {
        sqlite3_prepare_v2(store->db, sql_insert_header_null_z1, -1, &stmt, NULL);

        // x0
        sqlite3_bind_blob(stmt, 1, carrier->x0, SEED_BYTES, SQLITE_STATIC);
        // x2
        sqlite3_bind_blob(stmt, 2, carrier->x2, SEED_BYTES, SQLITE_STATIC);
        // in_len
        sqlite3_bind_int(stmt, 3, (int) carrier->in_len);
        // out_len
        sqlite3_bind_int(stmt, 4, (int) carrier->out_len);
        // pk
        pack_poly_ring_custom(pk_bytes, &carrier->pk, K1 - pk_ERROR);
        sqlite3_bind_blob(stmt, 5, pk_bytes, pk_HIGHBITS, SQLITE_STATIC);
        // sigma
        pack_poly_sig(sig_bytes, carrier->sigma, (int)(carrier->in_len + carrier->out_len));
        sqlite3_bind_blob(stmt, 6, sig_bytes, sig_BYTES, SQLITE_STATIC);
        // u
        pack_poly_ring_custom(u_bytes, &carrier->u, K1 - u_ERROR);
        sqlite3_bind_blob(stmt, 7, u_bytes, u_HIGHBITS, SQLITE_STATIC);
        // t1
        pack_poly_ring_custom(t1_bytes, &carrier->t1, K1 - t1_ERROR);
        sqlite3_bind_blob(stmt, 8, t1_bytes, t1_HIGHBITS, SQLITE_STATIC);
        // z0[LACTX_L]
        for (l = 0; l < in_carries; l++) {
            pack_poly_z_custom(z0l_bytes + z0l_byte_len*l, carrier->z0 + l * LACTX_L, in_carry_bits);
        }
        sqlite3_bind_blob(stmt, 9, z0l_bytes, z0l_byte_len*in_carries, SQLITE_STATIC);
        // no z1[LACTX_L]
        // R[LACTX_m - 3]
        pack_poly_m_R(R_bytes, carrier->R);
        sqlite3_bind_blob(stmt, 11, R_bytes, R_BYTES, SQLITE_STATIC);
        // v_in
        sqlite3_bind_blob(stmt, 12, &carrier->v_in, sizeof(uint64_t), SQLITE_STATIC);
        // v_out
        sqlite3_bind_blob(stmt, 13, &carrier->v_out, sizeof(uint64_t), SQLITE_STATIC);
        // y_hints
        pack_poly_ring_custom(y_hints_bytes, &carrier->y_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 14, y_hints_bytes, HINTBYTES, SQLITE_STATIC);
        // t2_hints
        pack_poly_ring_custom(t2_hints_bytes, &carrier->t2_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 15, t2_hints_bytes, HINTBYTES, SQLITE_STATIC);
    }
    else {
        sqlite3_prepare_v2(store->db, sql_insert_header_null_z, -1, &stmt, NULL);

        // x0
        sqlite3_bind_blob(stmt, 1, carrier->x0, SEED_BYTES, SQLITE_STATIC);
        // in_len
        sqlite3_bind_int(stmt, 3, (int) carrier->in_len);
        // out_len
        sqlite3_bind_int(stmt, 4, (int) carrier->out_len);
        // pk
        pack_poly_ring_custom(pk_bytes, &carrier->pk, K1 - pk_ERROR);
        sqlite3_bind_blob(stmt, 5, pk_bytes, pk_HIGHBITS, SQLITE_STATIC);
        // sigma
        pack_poly_sig(sig_bytes, carrier->sigma, (int)(carrier->in_len + carrier->out_len));
        sqlite3_bind_blob(stmt, 6, sig_bytes, sig_BYTES, SQLITE_STATIC);
        // v_in
        sqlite3_bind_blob(stmt, 12, &carrier->v_in, sizeof(uint64_t), SQLITE_STATIC);
        // v_out
        sqlite3_bind_blob(stmt, 13, &carrier->v_out, sizeof(uint64_t), SQLITE_STATIC);
        // y_hints
        pack_poly_ring_custom(y_hints_bytes, &carrier->y_hints, HINTBITS);
        sqlite3_bind_blob(stmt, 14, y_hints_bytes, HINTBYTES, SQLITE_STATIC);
    }
    SQLITE3_ROLLBACK_CHECK(sqlite3_step(stmt) == SQLITE_DONE, sqlite3_errmsg(store->db), store->db, stmt);
    sqlite3_finalize(stmt);

    SQLITE3_CHECK(sqlite3_exec(store->db, "END TRANSACTION", NULL, NULL, &error) == SQLITE_OK, error, store->db);
}


/**
 * Read the database and get the aggregate public key and the aggregate u.
 * @param store - store object
 * @param aggr_pk - aggregate public key (polynomial vector)
 * @param aggr_u - aggregate u (polynomial vector)
 * @return 0 if coins or carriers are invalid, otherwise 1.
 */
int lactx_db_read(store_t *store, poly_n *aggr_pk, poly_n *aggr_u) {
    sqlite3_stmt *stmt;
    coin_t coin;
    header_t carrier;

    poly_n_set_zero(aggr_pk, 0, LACTX_N);
    poly_n_set_zero(aggr_u, 0, LACTX_N);

    coin.s = 0;

    int l;

    // read ucoin table
    sqlite3_prepare_v2(store->db, sql_read_ucoins, -1, &stmt, NULL);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        // coin
        memcpy(coin.x2, (uint8_t *) sqlite3_column_blob(stmt, 1), SEED_BYTES);
        unpack_poly_ring_custom(&coin.u, (uint8_t *) sqlite3_column_blob(stmt, 2), K1 - u_ERROR);
        unpack_poly_ring_custom(&coin.t1, (uint8_t *) sqlite3_column_blob(stmt, 3), K1 - t1_ERROR);
        unpack_poly_ring_custom(&coin.t2_hints, (uint8_t *) sqlite3_column_blob(stmt, 4), HINTBITS);
        unpack_poly_z(coin.z, (uint8_t *) sqlite3_column_blob(stmt, 5));
        unpack_poly_m_R(coin.R, (uint8_t *) sqlite3_column_blob(stmt, 6));

        // verify coin
        if (lactx_coin_verify(&store->ctx, &coin) == 0) {
            lactx_coin_print(&coin);
            sqlite3_finalize(stmt);
            return 0;
        }
        // add u
        poly_n_add(aggr_u, aggr_u, &coin.u);
        poly_n_reduce(aggr_u);
    }
    sqlite3_finalize(stmt);

    // read header table
    sqlite3_prepare_v2(store->db, sql_read_headers, -1, &stmt, NULL);

    while (sqlite3_step(stmt) != SQLITE_DONE) {
        // carrier
        memcpy(carrier.x0, (uint8_t *) sqlite3_column_blob(stmt, 1), SEED_BYTES);
        carrier.in_len = sqlite3_column_int(stmt, 3);
        carrier.out_len = sqlite3_column_int(stmt, 4);
        unsigned int in_carries = get_carry_range(carrier.in_len);
        unsigned int out_carries = get_carry_range(carrier.out_len);
        int in_carry_bits = ALPHA_BITS + ceil(log2(carrier.in_len - 1)/2);
        int out_carry_bits = ALPHA_BITS + ceil(log2(carrier.out_len - 1)/2);
        int z0l_byte_len = (LACTX_L * LACTX_N * (in_carry_bits + 1)) / 8;
        int z1l_byte_len = (LACTX_L * LACTX_N * (out_carry_bits + 1)) / 8;

        lactx_header_init(&carrier, carrier.out_len, carrier.in_len);
        unpack_poly_ring_custom(&carrier.pk, (uint8_t *) sqlite3_column_blob(stmt, 5), K1 - pk_ERROR);
        unpack_poly_sig(carrier.sigma, (uint8_t *) sqlite3_column_blob(stmt, 6), (int)(carrier.in_len + carrier.out_len));
        unpack_poly_ring_custom(&carrier.y_hints, (uint8_t *) sqlite3_column_blob(stmt, 14), HINTBITS);

        memcpy(&carrier.v_in, sqlite3_column_blob(stmt, 12), sizeof(uint64_t));
        memcpy(&carrier.v_out, sqlite3_column_blob(stmt, 13), sizeof(uint64_t));
        if (carrier.in_len >= 2 || carrier.out_len >= 2) {
            unpack_poly_ring_custom(&carrier.u, (uint8_t *) sqlite3_column_blob(stmt, 7), K1 - u_ERROR);
            if (carrier.v_in == 0 && carrier.v_out == 0) {
                memcpy(carrier.x2, (uint8_t *) sqlite3_column_blob(stmt, 2), SEED_BYTES);
                unpack_poly_ring_custom(&carrier.t1, (uint8_t *) sqlite3_column_blob(stmt, 8), K1 - t1_ERROR);
                unpack_poly_ring_custom(&carrier.t2_hints, (uint8_t *) sqlite3_column_blob(stmt, 15), HINTBITS);
                if (carrier.in_len >= 2)
                    for (l = 0; l < in_carries; l++) {
                        unpack_poly_z_custom(carrier.z0 + l * LACTX_L, (uint8_t *) sqlite3_column_blob(stmt, 9) + z0l_byte_len * l, in_carry_bits);
                    }
                if (carrier.out_len >= 2)
                    for (l = 0; l < out_carries; l++) {
                        unpack_poly_z_custom(carrier.z1 + l * LACTX_L, (uint8_t *) sqlite3_column_blob(stmt, 10) + z1l_byte_len * l, out_carry_bits);
                    }
                unpack_poly_m_R(carrier.R, (uint8_t *) sqlite3_column_blob(stmt, 11));
            }
        }

        // verify carrier
        if (lactx_header_verify(&store->ctx, &carrier) == 0) {
            lactx_header_free(&carrier);
            sqlite3_finalize(stmt);
            return 0;
        }
        // add pk
        poly_n_add(aggr_pk, aggr_pk, &carrier.pk);
        poly_n_reduce(aggr_pk);
        // add u
        if (carrier.in_len >= 2 || carrier.out_len >= 2) {
            poly_n_add(aggr_u, aggr_u, &carrier.u);
            poly_n_reduce(aggr_u);
        }
        lactx_header_free(&carrier);
    }

    sqlite3_finalize(stmt);
    return 1;
}

#endif //LACTX_LACTX_DB_IMPL_H