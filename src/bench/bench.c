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
#include <time.h>
#include <openssl/rand.h>
#include "lactx_store.h"

#include "../util.h"
#include "../lactx_pack.h"

#define TX_MAX 10
#define INTERVAL 1

char *sql_drop_key_table = "DROP TABLE IF EXISTS KEY_TABLE;";
const char *sql_open_key_table = "CREATE TABLE IF NOT EXISTS KEY_TABLE("  \
                                "ID   INTEGER  PRIMARY KEY     AUTOINCREMENT, " \
                                "V       INT     NOT NULL, " \
                                "X2       BLOB     NOT NULL, " \
                                "U       BLOB     NOT NULL, " \
                                "MASK    BLOB     NOT NULL);";

void save_ucoin_secrets(sqlite3 *db, ctx_t *tx, uint64_t v_out[], uint8_t out_mask[][LACTX_m - D][r_BYTES]) {
    sqlite3_stmt *stmt;
    uint8_t mask_bytes[(LACTX_m - D) * r_BYTES];
    uint8_t u_bytes[LACTX_n * u_BYTES];

    unsigned int t, j;
    for (t = 0; t < tx->header.out_len; t++) {
        sqlite3_prepare_v2(db, "INSERT INTO KEY_TABLE (V, X2, U, MASK)" \
                               " VALUES (?1, ?2, ?3, ?4);", -1, &stmt, NULL);

        sqlite3_bind_int(stmt, 1, (int) v_out[t]); // V
        sqlite3_bind_blob(stmt, 2, tx->out[t].x2, SEED_BYTES, SQLITE_STATIC); // X2

        pack_poly_ring(u_bytes, &tx->out[t].u);
        sqlite3_bind_blob(stmt, 3, u_bytes, LACTX_n * u_BYTES, SQLITE_STATIC); // U

        for (j = 0; j < LACTX_m - D; j++) memcpy(mask_bytes + r_BYTES * j, out_mask[t][j], r_BYTES); // MASK
        sqlite3_bind_blob(stmt, 4, mask_bytes, (LACTX_m - D) * r_BYTES, SQLITE_STATIC);

        SQLITE3_NOFREE_CHECK(sqlite3_step(stmt) == SQLITE_DONE, sqlite3_errmsg(db), db, stmt);
        sqlite3_finalize(stmt);
    }
}

void get_ucoin_secrets(sqlite3 *db, coin_t in[], uint64_t v_in[MAX_ADDITIONS], uint8_t in_mask[MAX_ADDITIONS][LACTX_m - D][r_BYTES], unsigned int count) {
    sqlite3_stmt *stmt;
    int id;

    unsigned int t, j;

    for (t = 0; t < count; t++) {
        sqlite3_prepare_v2(db, "SELECT * FROM KEY_TABLE ORDER BY ID ASC LIMIT 1;", -1, &stmt, NULL);

        while (sqlite3_step(stmt) != SQLITE_DONE) {
            id = sqlite3_column_int(stmt, 0);
            v_in[t] = sqlite3_column_int(stmt, 1); // V

            memcpy(in[t].x2, sqlite3_column_blob(stmt, 2), SEED_BYTES); // X2

            unpack_poly_ring(&in[t].u, sqlite3_column_blob(stmt, 3));  // U

            // MASK
            for (j = 0; j < LACTX_m - D; j++) memcpy(in_mask[t][j], sqlite3_column_blob(stmt, 4) + r_BYTES * j, r_BYTES);
        }

        sqlite3_finalize(stmt);

        /* Delete the popped item */
        sqlite3_prepare_v2(db, "DELETE FROM KEY_TABLE WHERE ID = ?1;", -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, id);
        SQLITE3_NOFREE_CHECK(sqlite3_step(stmt) == SQLITE_DONE, sqlite3_errmsg(db), db, stmt);
        sqlite3_finalize(stmt);
    }
}


uint64_t file_size(const char *path) {
    long int size;
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        printf("File Not Found!\n");
        return -1;
    }

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fclose(fp);

    return size;
}

#define COIN_SIZE (SEED_BYTES + (u_BYTES * LACTX_n * 2) + z_BYTES + R_BYTES + 8)

int main(int argc, char *arg[]) {
    char *sqlite3_error = 0;
    sqlite3 *db;
    FILE *lactx_metadata_file;
    unsigned int min_tx_count = TX_MAX;
    unsigned tx_per_block = 10;
    uint64_t reward = 2000;
    char db_path[] = "store_simulator.db";
    char key_db_path[] = "simulator_keys.db";

    uint8_t in_mask[MAX_ADDITIONS][LACTX_m - D][r_BYTES];
    uint8_t out_mask[MAX_ADDITIONS][LACTX_m - D][r_BYTES];
    uint64_t v_in[MAX_ADDITIONS];
    uint64_t v_out[MAX_ADDITIONS];

    clock_t start, end;

    unsigned int in_len;
    unsigned int out_len;
    unsigned int total_coin;
    unsigned int ucoin_table_size = 0;
    unsigned int tx_count = 0;
    unsigned int t, i, j, b = 0;
    unsigned int deleted_coins = 0;
    unsigned int added_coins = 0;

    for (i = 0; i < MAX_ADDITIONS; i++)
        for (j = 0; j < LACTX_m - D; j++)
            memset(in_mask[i][j], 0, r_BYTES);

    for (i = 0; i < MAX_ADDITIONS; i++)
        for (j = 0; j < LACTX_m - D; j++)
            memset(out_mask[i][j], 0, r_BYTES);

    // Initialize the generator
    srand(0x1);
    remove(db_path);
    remove(key_db_path);

    // Connect to the key db
    SQLITE3_NOFREE_CHECK(sqlite3_open(key_db_path, &db) == SQLITE_OK, sqlite3_errmsg(db), db, NULL);
    SQLITE3_CHECK(sqlite3_exec(db, sql_open_key_table, NULL, 0, &sqlite3_error) == SQLITE_OK, sqlite3_error, db);

    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store = lactx_get_store(seed, db_path);

    for (t = 0; t < min_tx_count; t++) {
        /* ============= Minting transactions ============= */
        if (t % tx_per_block == 0) {
            in_len = 1;
            out_len = 2;
            ctx_t tx;
            lactx_tx_init(&tx, out_len, in_len);
            v_in[0] = store.coinbase;
            v_out[0] = reward;
            v_out[1] = store.coinbase - reward;
            //Create the transaction
            lactx_mint_tx_create(&store, &tx, out_mask[0], reward);
            // Add tx
            lactx_tx_aggregate(&store, &tx);
            CHECK(lactx_store_verify(&store) == 1);
            ucoin_table_size += 1;
            // Save secrets
            tx.header.out_len = 1;
            save_ucoin_secrets(db, &tx, v_out, out_mask);
            tx_count += 1;
            lactx_tx_free(&tx);
        }
            /* ============= Normal transactions ============= */
        else {
            if (ucoin_table_size < MAX_ADDITIONS)
                in_len = (rand() % ucoin_table_size) + 1;
            else
                in_len = (rand() % MAX_ADDITIONS) + 1;
            out_len = (rand() % MAX_ADDITIONS) + 1;

            ctx_t tx;
            lactx_tx_init(&tx, out_len, in_len);
            get_ucoin_secrets(db, tx.in, v_in, in_mask, in_len);

            // Set coin amounts
            total_coin = 0;
            for (i = 0; i < in_len; i++)
                total_coin += v_in[i];

            if (out_len == 1)
                v_out[0] = total_coin;
            else {
                for (i = 0; i < out_len - 1; i++) {
                    v_out[i] = rand() % (total_coin + 1);
                    total_coin -= v_out[i];
                }
                v_out[out_len - 1] = total_coin;
            }

            // Create the transaction
            lactx_header_create(&store.ctx, &tx.header,
                                out_len, tx.out, out_mask, v_out,
                                in_len, tx.in, in_mask, v_in);

            // Add tx
            lactx_tx_aggregate(&store, &tx);
            ucoin_table_size -= in_len;
            ucoin_table_size += out_len;

            // Save secrets
            save_ucoin_secrets(db, &tx, v_out, out_mask);

            // Update size data
            deleted_coins += in_len;
            added_coins += out_len;
            tx_count += 1;

            lactx_tx_free(&tx);

        }

        if (b == INTERVAL) {
            start = clock();
            CHECK(lactx_store_verify(&store) == 1);
            end = clock();
            lactx_metadata_file = fopen("lactx_metadata_10000.csv", "a+");
            fprintf(lactx_metadata_file, "%d %d, %d, %d, %d %lu, %lu, %f\n", t, tx_count, ucoin_table_size,
                    deleted_coins, added_coins, file_size(db_path),
                    (uint64_t) COIN_SIZE * deleted_coins, ((double)(end - start)) / CLOCKS_PER_SEC);
            printf("%d %d, %d, %d, %d %lu, %lu, %f\n", t, tx_count, ucoin_table_size,
                    deleted_coins, added_coins, file_size(db_path),
                    (uint64_t) COIN_SIZE * deleted_coins, ((double)(end - start)) / CLOCKS_PER_SEC);
            b = 0;
            fclose(lactx_metadata_file);
        }
        b++;
    }


    start = clock();
    CHECK(lactx_store_verify(&store) == 1);
    end = clock();
    lactx_metadata_file = fopen("lactx_metadata_10000.csv", "a+");
    fprintf(lactx_metadata_file, "%d %d, %d, %d, %d %lu, %lu, %f\n", t, tx_count, ucoin_table_size,
            deleted_coins, added_coins, file_size(db_path),
            (uint64_t) COIN_SIZE * deleted_coins, ((double)(end - start)) / CLOCKS_PER_SEC);
    printf("%d %d, %d, %d, %d %lu, %lu, %f\n", t, tx_count, ucoin_table_size,
           deleted_coins, added_coins, file_size(db_path),
           (uint64_t) COIN_SIZE * deleted_coins, ((double)(end - start)) / CLOCKS_PER_SEC);


    fclose(lactx_metadata_file);

    lactx_drop_store(&store);
    sqlite3_close(db);

    remove(db_path);
    remove(key_db_path);
}

