import merkletree.merkletree

if __name__ == '__main__':
    test = merkletree.merkletree.EthashMerkleTree('./merkletree/cache-R23-290decd9548b62a8')
    print(test.get_rlp_path(0).hex())