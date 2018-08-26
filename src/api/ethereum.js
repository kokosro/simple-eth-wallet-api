import Ethereum from "../lib/ethereum.js";
import {Router} from "express";
var NETWORK = "testnet";
import BigNumber from "bignumber.js"


export default ({config, db}) => {
    let r = Router();

    r.get("/createWallet", function(req, res, next){
        Ethereum.generate( "", NETWORK)
            .then(function(account){
                res.json(account);
            }).catch(function(){
                res.json({error: "unable to create account."});
            });
    });
    r.get("/getBalance/:address", function(req, res, next){
        Ethereum.balance(req.params.address, NETWORK)
            .then(function(response){
                res.json({result: response});
            }).catch(function(){
                res.json({error: "unable to fetch balance."});
            });
    });
    r.post("/transaction", function(req, res, next){
     
        var privateKey = req.body.privateKey;
        
        var destination = req.body.destination;
        /* amount is supposed to be Ether we need Wei */
        var amount = Ethereum.to.convertToWei(req.body.amount);
     
        Ethereum.generateFromPK(privateKey, NETWORK)
            .then((account)=>{
                console.log("signing transaction");
                Ethereum.transaction.sign({to: destination,
                                           value: parseInt(amount.integerValue().toString()) },
                                          account, NETWORK, 0)
                    .then(function(signed){
                        console.log("signed transaction: ");
                        console.log(signed);
                        var already = false;
                        Ethereum.broadcast.signed(signed, NETWORK,
                                                  function(r){
                                                    
                                                      res.json({result: arguments});
                                                  },
                                                  function(e){
                                                      res.json({error: e});
                                                  }).then(function(x){
                                                   //   res.json({result: arguments});
                                                  }).catch(function(e){
                                                    //  res.json({error: e});
                                                  });
                    }).catch(res.json);
            }).catch(res.json);
    });

    return r;

    
}

