Simple Ether Wallet API
==================================

Getting Started
---------------

```sh

git clone git@github.com:kokosro/simple-eth-wallet-api.git
cd simple-eth-wallet-api
npm init
# Install dependencies
npm install

```

.env file contains information used to connect to Ethereum Network

```
PORT=3000
ETHEREUM_TEST_RINKEBY=__CHANGE__WITH__YOUR_TRUSTED_ETHEREUM_NODE_MAINNET_URL
ETHEREUM_MAIN= __CHANGE__WITH__YOUR_TRUSTED_ETHEREUM_NODE_MAINNET_URL
ETHEREUM_RINKEBY_CHAIN=4
ETHEREUM_MAIN_CHAIN=1

```
After you have created your .env file you will be able to start the api with

```node start```

### Available routes

GET /api/ethereum/createWallet
    creates an ethereum account and returns an object containing address, public/private key and keystore json. as default password for keystore an empty string is used.

GET /api/ethereum/getBalance/:address
    returns balance in Wei for given address

POST /transaction {destination, privateKey, amount}
     sends the amount in ether to destination address signing the transaction with privateKey


License
-------

MIT
