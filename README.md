# LACT+ : Post-Quantum Aggregable Confidential Transactions
LACT+ (Lattice-based Aggregable Confidential Transactions), a practical quantum-safe payment method based on the Approximate Short Integer Solution Problem (Approx-SIS). Aggregable Confidential Transactions hide coin amounts but verify the validity of hidden coins. Interestingly, an aggregated blockchain is a single transaction that only contains all unspent coin outputs and previous transaction headers. However, current aggregable transaction protocols cannot use aggregated transactions at the consensus level due to the malleability of headers, i.e., two different in/outputs can be created for the same header. Hence, all current aggregable cryptocurrencies insert full transactions into the consensus mechanism to provide immutability. Thus, aggregated blockchain verification requires trusted full nodes, which contradicts the idea of trustless verification. We provide a proper solution through the use of ``aggregable Origami activity proofs'' in headers to make creating two different in/outputs for the same activity proof infeasible. If a consensus mechanism secures LACT+ headers, it is sufficient to provide immutability to the whole blockchain, including the removed spent coin records. This library provides functionalities required to create LACT+ aggregable transactions.

To build: 

`mkdir build`

`cd build/`

`cmake .. `

To run test cases:

`./tests`

To run a simple example:

`./example`

## LACT+ Functions

Funtion Name | Description
------------- | -------------
lactx_mint_coin_create  | outputs a plain-text coin of minted coins
lactx_coin_create   | outputs a confidential coin with hidden coin amounts
lactx_coin_open | opens and see the hidden coin amount of a confidential coin
lactx_coin_verify | verifies the range of the confidential coin without opening it
lactx_header_create | create a header of a transaction to check the summation and ownership without opening any of the in/output confidential coins
lactx_header_verify | verifies the summation and ownership of in/outputs of a transaction without opening confidential coins 
lactx_get_store | creates a database for the aggregated transactions
lactx_drop_store | deletes the database of the aggregated transactions
lactx_tx_verify | verifies the header and output confidential coins and checks if the inputs are unspent
lactx_tx_aggregate | adds the new transaction into the aggregated transaction set by removing input coins
lactx_store_verify | verifies the aggregated transactions without spent coin history


Note: This project is a part of my Ph.D. Hence, the implementation mainly targets educational purposes. Any contributions are welcomed.
I would like to thank my supervisors, Associate Professor Xavier Boyen and Dr. Matthew McKague, for their guidance.

email: alupotha@qut.edu.au

