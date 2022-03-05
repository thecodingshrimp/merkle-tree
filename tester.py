import merkletree.merkletree

if __name__ == '__main__':
    test = merkletree.merkletree.EthashMerkleTree('./merkletree/cache-R23-290decd9548b62a8', 64, 4)
    # for i in range(len(test.ELEMENT_AMOUNT)):
    #     proof_path = test.get_proof_path(i)
    print(test.get_proof_path(0))
    