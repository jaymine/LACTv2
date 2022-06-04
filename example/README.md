## A simple example

Run the example

` ./example`

Output will be
```asm
Coinbase: 9223372036854775807
TX1 is created to get 500 coins from the coinbase.
TX1 is valid
TX1 is aggregated
TX2 is created to get 500 coins from the coinbase.
TX2 is valid
TX2 is aggregated
Coinbase: 9223372036854774307
TX3 is created
                in_coin[0] : 500
                out_coin[0] : 100
                out_coin[1] : 400
TX3 is valid
TX3 is aggregated
TX4 is created
                in_coin[0] : 100
                in_coin[1] : 400
                out_coin[0] : 200
                out_coin[1] : 100
                out_coin[2] : 200
TX4 is valid
TX4 is aggregated
LACTx store is valid
```
