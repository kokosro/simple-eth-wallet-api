var keythereum = require("keythereum");
var ethereumjsTx = require("ethereumjs-tx");
var ethereumjsAbi = require("ethereumjs-abi");
var ethUtil = require("ethereumjs-util");
var Web3 = require("web3");
var BigNumber = require("bignumber.js");
require("dotenv").config();
var client = {};

client.testnet = new Web3(new Web3.providers.HttpProvider(process.env.ETHEREUM_TEST_RINKEBY));
client.mainnet = new Web3(new Web3.providers.HttpProvider(process.env.ETHEREUM_MAIN));
var clientOptions = {testnet: {}, mainnet: {}};

clientOptions.testnet.chain = parseInt(process.env.ETHEREUM_RINKEBY_CHAIN);
clientOptions.mainnet.chain = parseInt(process.env.ETHEREUM_MAIN_CHAIN);




const hex2Arr = str => {
   if (!str) {
       return new Uint8Array()
   }
   const arr = []
   for (let i = 0, len = str.length; i < len; i+=2) {
       arr.push(parseInt(str.substr(i, 2), 16))
   }
   return new Uint8Array(arr)
}

const buf2Hex = buf => {
   return Array.from(new Uint8Array(buf))
       .map(x => ('00' + x.toString(16)).slice(-2))
       .join('')
}



function createKey(password){
    var params = { keyBytes: 32, ivBytes: 16 };
     
     // synchronous
     var dk = keythereum.create(params);
     // asynchronous
     
     // Note: if options is unspecified, the values in keythereum.constants are used.
     var options = {
     kdf: "pbkdf2",
     cipher: "aes-128-ctr",
     kdfparams: {
     c: 262144,
     dklen: 32,
     prf: "hmac-sha256"
     }
     };
     
    var keyObject = keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, options);
    return keyObject;
}

function changePassword(key, currentPassword, otherPassword){
    var privateKey = getPrivateKey(currentPassword, key, true);
     var options = {
     kdf: "pbkdf2",
     cipher: "aes-128-ctr",
     kdfparams: {
     c: 262144,
     dklen: 32,
     prf: "hmac-sha256"
     }
     };
 
    
    var x =  keythereum.dump(otherPassword, privateKey,
                           key.crypto.kdfparams.salt,
                           key.crypto.cipherparams.iv,
                           options);
   
    return x;
}


function encodeContractCall(fname, args){
//    return ethereumjsAbi.encode(abi, getFunctionOfABI(abi, fname), args);

    
}

function getFunctionOfABI(abi, name){
    for(var i in abi){
        if(abi[i].name == name && abi[i].type == "function"){
            var toReturn = abi[i].name+"(";
            var f = true;
            for(var o in abi[i].inputs){
                if(f){
                    f = false;
                    toReturn += abi[i].inputs[o].type+" "+abi[i].inputs[o].name;
                }else{
                    toReturn += ", "+abi[i].inputs[o].type+" "+abi[i].inputs[o].name;
                }
            }
            toReturn += ")";
            return toReturn;
        }
    }
    return false;
}

function getPrivateKey(password, key, h){
    if(typeof h == "undefined"){
        h = true;
    }
    if(h){
        return buf2Hex(keythereum.recover(password, key));
    }else{
        return keythereum.recover(password, key);
    }
}
function getPublicKey(privateKey){
    return ethUtil.privateToPublic(privateKey);
}

function transaction(password, key, data, chain){
    if(typeof(chain) == "undefined"){
        chain = 1;
    }
    var tx = new ethereumjsTx({chainId: chain}, chain);
    tx.to = data.to;
    tx.nonce = data.nonce | 0;
    tx.gasPrice = data.gasPrice;
    tx.gasLimit = data.gasLimit;
    tx.value = data.value;
    tx.data = "";
   
   
    tx.sign(getPrivateKey(password, key, false));
    
    return tx;
}

function rTx(chain){
    if(typeof(chain) == "undefined"){
        chain = 1;
    }
    var tx = new ethereumjsTx(null, chain);
    return tx; 
}

function fromRaw(txRaw, chain){
    var tx = new ethereumjsTx(txRaw, chain);
    return tx;
}

const rlp = require('rlp')  // {decode, toBuffer, isHexPrefixed, stripHexPrefix, padToEven, intToBuffer, safeParseInt, bufferToHex}

const field_sets = {
  params:    ["nonce","gasPrice","gasLimit","to","value","data"],
  signature: ["v","r","s"]
}

const format_fields = function(fields, rawData, to_hex, add_prefix) {
  let txData = {}

  fields.forEach((field, index) => {
    if (rawData[index] && rawData[index].length) {
      txData[field] = to_hex ? ethUtil.bufferToHex(rawData[index], add_prefix) : rawData[index]
    }
  })

  return txData
}

// ===
// API
// ===
const unsign = function(rawTx, to_hex=true, add_prefix_txData=true, add_prefix_signature=false) {
  let rawData
  if (typeof rawTx === 'string') {
    rawTx = Buffer.from(ethUtil.stripHexPrefix(rawTx), 'hex')
  }
  if (Buffer.isBuffer(rawTx)) {
    rawData = rlp.decode(rawTx)
  }

  if (rawData === undefined)
    throw new Error('TypeError: raw transaction must be either a Buffer or hex-encoded String value')
  if (! Array.isArray(rawData))
    throw new Error('TypeError: raw transaction is not RLP encoded')
  if (rawData.length < (field_sets.params.length + field_sets.signature.length))
    throw new Error('FormatError: RLP encoded raw transaction contains too few data fields')

  for (let i=0; i<rawData.length; i++) {
    rawData[i] = ethUtil.toBuffer(rawData[i])
  }

  let txData    = format_fields(field_sets.params,    rawData.slice(0, field_sets.params.length), to_hex, add_prefix_txData)
  let signature = format_fields(field_sets.signature, rawData.slice(field_sets.params.length),    to_hex, add_prefix_signature)

  let v_hex   = to_hex ? (add_prefix_signature ? ethUtil.stripHexPrefix(signature.v) : signature.v) : ethUtil.bufferToHex(signature.v, false)
  let v_int   = parseInt(v_hex, 16)
  let chainId = Math.floor((v_int - 35) / 2)
  if (chainId < 0) chainId = 0
  txData['chainId'] = chainId

  return {txData, signature}
}


function generate(password){
    if(typeof(password) == "undefined"){
        password = "";
    }
    return createKey(password);
}

function generateFromPK(pk, network){
    return new Promise(function(resolve, reject){
        var account = {};
        account.password = "";
        var x = createKey("");
        keythereum.dump("", pk,
                        x.crypto.kdfparams.salt,
                        x.crypto.cipherparams.iv,
                         {
                            kdf: "pbkdf2",
                            cipher: "aes-128-ctr",
                            kdfparams: {
                                c: 262144,
                                dklen: 32,
                                prf: "hmac-sha256"
                            }
                        },
                        function(keyObj){
                            account.file = keyObj;
                            account.keys = {};
                            account.address = "0x"+keyObj.address;
                            var pk = getPrivateKey(account.password, account.file, false);
                            var pubk = getPublicKey(pk);
                            account.keys.privateKey = buf2Hex(pk);
                            account.keys.publicKey = buf2Hex(pubk);
                            resolve(account);
                        });
    });
}


var Ethereum = {};

Ethereum.generate = function(password, network){
    return new Promise(function(resolve, reject){
    var account = {};
    if(typeof(password) == "undefined"){
        account.password = "";
    }else{
        account.password = password;
    }
    account.file = createKey(account.password);
    account.keys = {};
    var privateKeyBuf = getPrivateKey(account.password, account.file, false)
    var publicKeyBuf = getPublicKey(privateKeyBuf);
    account.keys.privateKey = buf2Hex(privateKeyBuf);
    account.keys.publicKey = buf2Hex(publicKeyBuf);
    account.address = "0x"+account.file.address;
        resolve(account);
    });
};
Ethereum.generateFromPK = function(pk, network){
    return generateFromPK(pk);
};

Ethereum.balance = function(address, network){
    return new Promise(function(resolve, reject){
        if(network != "testnet" && network != "mainnet"){
            reject({error: "unknown network."});
            return;
        }
        client[network].eth.getBalance(address)
            .then(function(result){
                resolve(result);
            }).catch(function(e){
             
                reject(e);
            });
    });
}

Ethereum.nextNonce = function(address, network){
    return new Promise(function(resolve, reject){
        if(network != "testnet" && network != "mainnet"){
            reject({error: "unknown network."});
            return;
        }
        
        client[network].eth.getTransactionCount(address)
            .then(function(nonce){
                resolve(nonce);
            }).catch(function(e){

               
                reject(e);
            });
    });
}
Ethereum.options = {};

Ethereum.options.FIXED_POINT = 10 ** 18;
Ethereum.options.OUTPUT_FIXED_POINT = 8;

Ethereum.to = {};
Ethereum.to.convertFromWei = function(n){
    return Ethereum.to.convert(n, "wei", "ether",Ethereum.options.OUTPUT_FIXED_POINT);
}
Ethereum.to.convertToWei = function(n){
    return Ethereum.to.convert(n, "ether", "wei", 0);
}
Ethereum.to.convert = function(n, fromUnit, toUnit, fixed){
        fromUnit = fromUnit || "wei";
        toUnit = toUnit || "ether";
        fixed = fixed || 8;
        var toWeiPower = {wei: 0,
                          kwei: 3,
                          mwei: 6,
                          gwei: 9,
                          szabo: 12,
                          finney: 15,
                          ether: 18};
        n = new BigNumber(n);
        var ten = new BigNumber(10);
        var inWei = n.multipliedBy(ten.exponentiatedBy(toWeiPower[fromUnit]));
        var toReq = inWei.dividedBy(ten.exponentiatedBy(toWeiPower[toUnit]));
        return toReq;
}

Ethereum.gasPrice = function(network){
    return new Promise(function(resolve, reject){
         if(network != "testnet" && network != "mainnet"){
            reject({error: "unknown network."});
            return;
        }
        client[network].eth.getGasPrice()
            .then(function(r){
                resolve(r);
            }).catch(reject);
    });
}
Ethereum.broadcast = {};
Ethereum.broadcast.signed = function(transactionHash, network, onReceipt, onError){
    return new Promise(function(resolve, reject){
        if(network != "testnet" && network != "mainnet"){
            reject({error: "unknown network."});
            return;
        }

        
        var already = false;
     
        try{
        client[network].eth.sendSignedTransaction(transactionHash)
                    .on("transactionHash", function(hash){
                     
                        if(!already){
                            already = true;
                            resolve(hash);
                        }
                    })
            .on("receipt",function(receipt){
                
                if(typeof(onReceipt) != "undefined"){
                    try{
                        onReceipt(transactionHash, network, receipt);
                    }catch(e){
                        console.log(e);
                        reject({error: e});
                    }
                }
                
            }).on("error",function(e){
                
                if(!already){
                    already = true;
                    reject({error: e});
                   
                }
                if(typeof(onError) != "undefined"){
                    try{
                    onError({th: transactionHash, n: network, error: e});
                    }catch(ex){
                        console.log(ex);
                    }
                }
            });
        }catch(e){
            reject(e);
        //    console.log("error on broadcasting ", e);
        }
    });
}

Ethereum.estimateGas = function(txData, network){
    return new Promise(function(resolve, reject){
        if(network != "testnet" && network != "mainnet"){
            reject({error: "unknown network."});
            return;
        }
      
 
        client[network].eth.estimateGas(txData)
            .then(function(gas){
 
                resolve(gas);
            }).catch(reject);
    });

}

Ethereum.estimateFees = function(txData, network){

    return new Promise(function(resolve, reject){
        var gasPriceP = Ethereum.gasPrice(network);
        var gasP = Ethereum.estimateGas(txData, network);
        var codeP = Ethereum.getCode(txData.to, network);
        Promise.all([gasPriceP, codeP, gasP])
            .then(function(r){
                var gasPrice, code, gas;
                [gasPrice, code, gas] = r;
                gasPrice = new BigNumber(gasPrice);
                gas = new BigNumber(gas);

                // if(code.result != "0x"){
                //    gas = gas.multipliedBy(1.5);
                // }
                
                var estimatedFees = gasPrice.multipliedBy(gas);
                resolve(estimatedFees.toString());
                
               
            }).catch(reject)
    });
    
}


Ethereum.transaction = {};
Ethereum.transaction.sign = function(txData, account, network, nonce_offset){
    return new Promise(function(resolve, reject){
        if(network != "testnet" && network != "mainnet"){
            reject({error: "unknown network."});
            return;
        }
        
        var missing = [];
        var missingKey = [];
        if(typeof(txData.nonce) == "undefined"){
            missingKey.push("nonce");
            missing.push(Ethereum.nextNonce(account.address, network))
        }
        if(typeof(txData.gasPrice) == "undefined"){
            missingKey.push("gasPrice");
            missing.push(Ethereum.gasPrice(network));
        }
        if(typeof(txData.gasLimit) == "undefined"){
            missingKey.push("gasLimit");
            missing.push(Ethereum.estimateGas(txData,network));
        }
        
        
  
        if(missing.length > 0){
            Promise.all(missing)
                .then(function(infos){
        
                    for(var i in infos){
                        var key = missingKey[i];
                        if(key == "nonce"){
                            
                            txData[key] = parseInt(infos[i]);
                        }else{
                            txData[key] = "0x"+parseInt(infos[i]).toString(16);
                        }
                    }
                    if(typeof(nonce_offset) != "undefined"){
                        txData.nonce = txData.nonce + nonce_offset;
                    }
                    
                    var chain = clientOptions[network].chain;
                    txData.chainId = chain;
                    
                    var tx = transaction(account.password, account.file, txData, chain);

                    resolve("0x"+tx.serialize().toString("hex"));
                })
                .catch(function(e){
                    reject({error: "error on signing"});
                });
        }else{
         
            var chain = clientOptions[network].chain;
            var tx = transaction(account.password, account.file, txData, chain);
            
            resolve("0x"+tx.serialize().toString("hex"));
        }
    });
}

Ethereum.isAcceptedNetwork = function(network){
    if(network != "testnet" && network != "mainnet"){
        return false;
        
    }
    return true;
}

Ethereum.getCode = function(address, network){
    return new Promise(function(resolve, reject){
        if(!Ethereum.isAcceptedNetwork(network)){
            reject({error: "network not accepted"});
            return;
        }
    
        client[network].eth.getCode(address)
            .then(function(code){
                resolve(code);
            }).catch(function(){
                resolve({result: "0x"});
            });
        
    });
}
Ethereum.getBlock = function(blockNumber, network){

    return new Promise(function(resolve, reject){
        if(!Ethereum.isAcceptedNetwork(network)){
            reject({error: "network not accepted"});
            return;
        }
        client[network].eth.getBlock(blockNumber).then(resolve).catch(reject);
        
    });
    
};
Ethereum.getTransaction = function(txHash, network){
    return new Promise(function(resolve, reject){
        if(!Ethereum.isAcceptedNetwork(network)){
            reject({error: "network not accepted"});
            return;
        }
        client[network].eth.getTransaction(txHash).then(resolve).catch(reject);
    });
};

export default  Ethereum;
