import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import binascii
from time import time
from collections import OrderedDict
import hashlib
import json

class Blockchain:
    def __init__(self) -> None:
        self.transactions = []
        self.chain = []
        self.complexity = 4

    def generateWalletAdress(self) -> dict[str, str]:
        random_gen = Crypto.Random.new().read
        private_key = RSA.generate(1024, random_gen)
        public_key = private_key.publickey()
        res = {
            'privateKey': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
            'publicKey': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
        }
        return res

    def generateTransaction(self, privateKey: str, senderAdress: str, recipientAdress: str, value: int) -> dict:
        transaction = {'senderAdress': senderAdress,
                       'recipientAdress': recipientAdress,
                       'value': value}
        signature = self.signTransaction(transaction, privateKey)
        res = {'transaction': transaction, 'signature': signature}
        return res

    def signTransaction(self, transaction: dict, privateKey: str) -> str:
        private_key = RSA.importKey(binascii.unhexlify(privateKey))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def verifyTransaction(self, senderAdress: str, transaction: dict, signature: str) -> bool:
        publicKey = RSA.importKey(binascii.unhexlify(senderAdress))
        verifier = PKCS1_v1_5.new(publicKey)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))

    def submitTransaction(self, transaction: dict, signature: str) -> None:
        #TODO: add mining fee reward
        if self.verifyTransaction(transaction['senderAdress'], transaction, signature):
            self.transactions.append(transaction)

    def createBlock(self, nonce: int, prevHash: str) -> OrderedDict:
        block = OrderedDict({'number': len(self.chain)+1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': prevHash})
        self.transactions = []
        self.chain.append(block)
        return block

    def hash(self, block: dict) -> str:
        blockString = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(blockString).hexdigest()

    def proofOfWork(self) -> int:
        lastBlock = self.chain[-1]
        lastHash = self.hash(lastBlock)
        nonce = 0
        while not self.validProof(self.transactions, lastHash, nonce):
            nonce += 1
        return nonce

    def validProof(self, transactions: list[dict], prevHash: str, nonce: int) -> bool:
        guess = (str(transactions)+str(prevHash)+str(nonce)).encode()
        guessHash = hashlib.sha256(guess).hexdigest()
        return guessHash[:self.complexity] == '0'*self.complexity

    def resolveConflicts(self):
        #TODO: add resolve conflit process
        pass

if __name__ == "__name__":
    blockchain = Blockchain()