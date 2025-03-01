Bitcoin PoW (BTCW) - White paper (10,000 ft view)
=====================================

https://www.bitcoin-pow.org

https://www.twitter.com/bitcoin_pow

https://t.me/BitcoinPoWPoT


BitcoinPoW is Bitcoin using Proof of Work(PoW) / Proof of Stake(Pos) / Proof of Transactions (PoT)
----------------
```
Satoshi's original Bitcoin has become very mining centralized. BitcoinPow enables a highly mining distributed 
system where every wallet is forced to solo mine by using a two part approach as follows:

1) Mining using utxos. Find a txid that solves the hashing function. The coinstake is created and the signature
   used in the coinstake will be checked against that in part 2. Keep utxos amount as small as possible, larger
   utxos amounts do not offer any benefit compared with small amounts, ex: use 0.00001 BTCW to send.

2) Mine using a new 64 bit nonce and combine with the block signature to create some mud. Throw the mud thru
   a sha256 hash function and check if the hash meets a new threshold. Repeat as PoW.


The validator will check to make sure that the signature in (1) matches the signature in (2) that was used
to sign the work and that both parts meet the thresholds for acceptance. Since the signatures must match,
the private key must be shared between (1) and (2). Sharing private keys will eliminate mining pools because all
trust is now lost.

The other attempt at pool formation will be to have the users only perform (1) and then send back to the pool for the
pool to finish doing (2). This will fail because the amount of work to do (1) is about 1% of the total work and the
remaining 99% of the work is in (2). This means that users would send work back to the pool and sit idle for 99% of 
the block time on average waiting for new work. Users have no benefit of using a pool and the pool will not form,
it they do form, they will be very unhealty pools that do not offer benefit to the users nor the pool owner.
```

How to mine
-------
```
Goals of mining are simple. Create as many transactions for your mining needs. You can also create more transaction as a reserve for the future.
Use the 'tx' command on the console to create transactions (type 'help tx').
```

Notable Algorithm sources
-------
https://github.com/bitcoin-pow/BitcoinPoW/blob/26.x_btcw/src/pos.cpp

https://github.com/bitcoin-pow/BitcoinPoW/blob/26.x_btcw/src/validation.cpp