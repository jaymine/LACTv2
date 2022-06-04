//
// Created by jayamine on 12/11/21.
//

#include <stdio.h>
#include "lactx_store.h"
#include "openssl/rand.h"

int main() {
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    coin_t in_coins[2];
    store_t store;
    key in_mask[2];
    uint64_t v_in[2] = {500, 300};
    key out_mask[3];
    uint64_t v_out[3] = {400, 400, 0};
    int i;

    // Initiate the store
    store = lactx_get_store(seed, "test_ctx.db");
    printf("Coinbase: %ld\n", store.coinbase);

    // Minting 1000 coins from the coinbase account
    ctx_t tx00; // Minting transaction 1
    lactx_tx_init(&tx00, 2, 1);
    lactx_mint_tx_create(&store, &tx00, out_mask[0], 1000);
    printf("TX1 is created to get 500 coins from the coinbase.\n");

    if (lactx_tx_verify(&store, &tx00))
        printf("TX1 is valid\n");

    lactx_tx_aggregate(&store, &tx00);
    printf("TX1 is aggregated\n");

    ctx_t tx01; // Minting transaction 2

    // Minting 500 coins from the coinbase account
    lactx_tx_init(&tx01, 2, 1);
    lactx_mint_tx_create(&store, &tx01, out_mask[0], 500);
    printf("TX2 is created to get 500 coins from the coinbase.\n");

    if (lactx_tx_verify(&store, &tx01) == 1)
        printf("TX2 is valid\n");

    lactx_tx_aggregate(&store, &tx01);
    printf("TX2 is aggregated\n");

    printf("Coinbase: %ld\n", store.coinbase);

    ctx_t tx1; // The first transaction
    lactx_tx_init(&tx1, 2, 1);
    // Copy keys for the next transaction
    lactx_key_copy(in_mask[0], out_mask[0]);

    v_in[0] = 500;
    v_out[0] = 100;
    v_out[1] = 400;

    lactx_coin_copy(&tx1.in[0], &tx01.out[0]);
    if(lactx_header_create(&store.ctx, &tx1.header,
                                  2, tx1.out, out_mask, v_out,
                                  1, tx1.in, in_mask, v_in) == 1) {
        printf("TX3 is created\n");
    }
    for (i = 0; i < tx1.header.in_len; i++) printf("\t\tin_coin[%d] : %ld\n", i, v_in[i]);
    for (i = 0; i < tx1.header.out_len; i++) printf("\t\tout_coin[%d] : %ld\n", i, v_out[i]);

    if (lactx_tx_verify(&store, &tx1) == 1)
        printf("TX3 is valid\n");

    lactx_tx_aggregate(&store, &tx1);
    printf("TX3 is aggregated\n");


    ctx_t tx2;  // The second transaction
    lactx_tx_init(&tx2, 3, 2);
    // Copy keys for the next transaction
    lactx_key_copy(in_mask[0], out_mask[0]);
    lactx_key_copy(in_mask[1], out_mask[1]);

    v_in[0] = 100;
    v_in[1] = 400;
    v_out[0] = 200;
    v_out[1] = 100;
    v_out[2] = 200;
    tx2.in[0] = tx1.out[0];
    tx2.in[1] = tx1.out[1];
    if(lactx_header_create(&store.ctx, &tx2.header,
                                     3, tx2.out, out_mask, v_out,
                                     2, tx2.in, in_mask, v_in) == 1) {
        printf("TX4 is created\n");
    }

    for (i = 0; i < tx2.header.in_len; i++) printf("\t\tin_coin[%d] : %ld\n", i, v_in[i]);
    for (i = 0; i < tx2.header.out_len; i++) printf("\t\tout_coin[%d] : %ld\n", i, v_out[i]);

    if (lactx_tx_verify(&store, &tx2) == 1)
        printf("TX4 is valid\n");

    lactx_tx_aggregate(&store, &tx2);
    printf("TX4 is aggregated\n");

    if(lactx_store_verify(&store) == 1)
        printf("LACTx store is valid\n");

    lactx_tx_free(&tx00);
    lactx_tx_free(&tx01);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_ctx.db");
}
