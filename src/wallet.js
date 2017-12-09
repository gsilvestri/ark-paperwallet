
import crypto from 'crypto'

import bip39 from 'bip39'
import arkjs from 'arkjs'

angular.module('wallet', [])
  .factory('wallet', () => {

    return {
      mnemonicToData: (passphrase) => {
        if (!passphrase) {
          passphrase = bip39.generateMnemonic()
        }
        let kapuNetwork = 
          {
            network: {
              messagePrefix: '\x18Kapu Signed Message:\n',
              bip32: {
                public: 0x2bf4968, // base58 will have a prefix 'apub'
                private: 0x2bf4530 // base58Priv will have a prefix 'apriv'
              },
              pubKeyHash: 0x2D, // Addresses will begin with 'K'
              wif: 0xaa // Network prefix for wif generation                
            }
          }
        let ecpair = arkjs.ECPair.fromSeed(passphrase, kapuNetwork)

        let publicKey = ecpair.getPublicKeyBuffer().toString('hex')
        let address = ecpair.getAddress().toString('hex')
        let wif = ecpair.toWIF()

        return {
          passphrase,
          passphraseqr: '{"passphrase":"'+passphrase+'"}',
          address: address,
          addressqr: '{"a":"'+address+'"}',
          publicKey: publicKey,
          wif: wif,
          entropy: bip39.mnemonicToEntropy(passphrase),
          seed: bip39.mnemonicToSeedHex(passphrase),
        }
      },
      validateMnemonic: (mnemonic) => {
        return bip39.validateMnemonic(mnemonic)
      },
      randomBytes: crypto.randomBytes,
      entropyToMnemonic: bip39.entropyToMnemonic
    }
  })
