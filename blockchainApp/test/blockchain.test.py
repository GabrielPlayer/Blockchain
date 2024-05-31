from blockchain import Blockchain

blockchain = Blockchain()

wallet1 = blockchain.generateWalletAdress()
print(wallet1)
wallet2 = blockchain.generateWalletAdress()
print(wallet2)

trans = blockchain.submitTransaction(wallet1['privateKey'],wallet1['publicKey'], wallet2['publicKey'], 100)
print(trans)