from multiprocessing import Pool
from typing import List, Optional
import merkletree.node
import rlp
import tqdm
import pathlib
import copy
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

class EthashMerkleTree:
    def __init__(self, file_path: str, element_size: int = 64, threads: int = 8) -> None:
        self.FILE_SIZE = pathlib.Path(file_path).stat().st_size - 8
        self.ELEMENT_AMOUNT = self.FILE_SIZE // element_size
        # self.ELEMENT_AMOUNT = 32
        self.ELEMENT_SIZE = element_size
        self.file_path = file_path
        with open(file_path, 'rb') as f:
            # skip 'magic' number 
            f.read(8)

            # initiate parent (Node) with first entry
            raw_value = f.read(64)
            self.height = 1
            self.root: merkletree.node.Node = merkletree.node.Node(0, raw_value)
            print('Building tree...')
            print(self.ELEMENT_AMOUNT)
            for i in tqdm.trange(1, self.ELEMENT_AMOUNT):
                raw_value = f.read(64)
                self.add_node(i, raw_value)
            print(f'MT Tree height: {self.height}')
            print('Setting hash values')
            self.hash_nodes_multithreaded(threads)
            print('Done')
            print('Get hash array')
            hash_array = self.fill_hash_array()
            print('write to file')
            self.write_hash_to_file(hash_array)
            print('Done')
    
    def hash_nodes(self, height: int, node: Optional[merkletree.node.Node], pbar: Optional[tqdm.tqdm]) -> merkletree.node.Node:
        working_list: List[merkletree.node.Node] = [self.root if node == None else node]
        own_pbar = tqdm.tqdm(total=((2 ** (self.height - height)) - 1)) if pbar == None else pbar
        curr_node = working_list[0]
        num_hashed = 0
        while len(working_list) > 0:
            curr_node = working_list[-1]
            if curr_node.left_node and curr_node.left_node.hash == b'':
                working_list.append(curr_node.left_node)
            elif curr_node.right_node and curr_node.right_node.hash == b'':
                working_list.append(curr_node.right_node)
            else:
                curr_node.get_hash()
                curr_node = working_list.pop()
                num_hashed += 1
                if num_hashed >= 10 or self.ELEMENT_AMOUNT < 100:
                    own_pbar.update(num_hashed)
                    num_hashed = 0
        if pbar == None:
            own_pbar.close()
        return curr_node
    
    def write_hash_to_file(self, hash_array: List[bytes]):
        with open(f'{self.file_path}_HASHES', 'wb') as f:
            for hash in hash_array:
                f.write(hash)
        
    def fill_hash_array(self) -> List[bytes]:
        working_list: List[merkletree.node.Node] = [self.root]
        hash_tree: List[bytes] = [b'0x'] * ((2 ** self.height) - 1)
        index = 0
        curr_node = self.root
        with tqdm.tqdm(total=((2 ** self.height) - 1)) as pbar:
            while len(working_list) > 0:
                curr_node = working_list[-1]
                hash_tree[index] = curr_node.hash
                if index * 2 + 1 < len(hash_tree) and hash_tree[index * 2 + 1] == b'0x' and curr_node.left_node and curr_node.left_node.hash != b'':
                    working_list.append(curr_node.left_node)
                    index = index * 2 + 1
                elif index * 2 + 2 < len(hash_tree) and hash_tree[index * 2 + 2] == b'0x' and curr_node.right_node and curr_node.right_node.hash != b'':
                    working_list.append(curr_node.right_node)
                    index = index * 2 + 2
                else:
                    working_list.pop()
                    index = index // 2 if index % 2 == 1 else (index // 2) - 1
                    pbar.update(1)
        hasher = PedersenHasher('Hasher')
        hash_tree = [b'\xa8\x93\xf1\xfa\x1fG\xfd3>\x97\x13\xb38\xbb\xbf\x05?c\x01\n\xd7\xae\xcf\xf5\x84-\x96K\r\xd2\xb8X' if hashed == b'0x' else hashed for hashed in hash_tree]
        return hash_tree
 
    def hash_nodes_multithreaded(self, threads: int) -> None:
        """Executes hashing in parallel. Assumes threads to be a multiple of 2.

        Args:
            threads (int): number of threads in parallel
        """
        if threads <= 1:
            return self.hash_nodes(0, None, None)
        
        multiple_of_two = 1
        height = 0
        while multiple_of_two < threads:
            height += 1
            multiple_of_two = 2 ** height
        args = []
        for j in range(threads):
            curr_node = self.root
            for k in range(height):
                current_bit = (j >> k) & 1
                if current_bit == 1:
                    # go deeper into right branch
                    if curr_node.right_node:
                        curr_node = curr_node.right_node
                    else:
                        break
                elif curr_node.left_node:
                    # left branch
                    curr_node = curr_node.left_node
                else:
                    break
            args.append((height, curr_node, None))
        with Pool(threads) as p:
            answer = p.starmap(self.hash_nodes, args)

        for j in range(threads):
            curr_node = self.root
            for k in range(height - 1):
                current_bit = (j >> k) & 1
                if current_bit == 1:
                    # go deeper into right branch
                    if curr_node.right_node:
                        curr_node = curr_node.right_node
                    else:
                        break
                elif curr_node.left_node:
                    # left branch
                    curr_node = curr_node.left_node
                else:
                    break
            current_bit = (j >> (height - 1)) & 1
            if current_bit == 1:
                curr_node.right_node = answer[j]
            else:
                curr_node.left_node = answer[j]
        print('Hashing the rest without multithreading...')
        self.hash_nodes(0, None, None)
        print('Done.')
    
    def add_node(self, index: int, value: bytes) -> None:
        inserted: bool = False
        curr_node = self.root
        i = 0
        while not inserted:
            current_bit = (index >> i) & 1
            if curr_node.index > -1:
                # we've reached a leaf
                if curr_node.index == index:
                    # new value for existing leaf
                    curr_node.value = value
                    inserted = True
                    break
                else:
                    # make branch out of leaf
                    if (curr_node.index >> i) & 1 == 1:
                        curr_node.right_node = merkletree.node.Node(curr_node.index, curr_node.value)
                    else:
                        curr_node.left_node = merkletree.node.Node(curr_node.index, curr_node.value)
                    curr_node.become_branch()
            if current_bit == 1:
                # go deeper into right branch
                if curr_node.right_node:
                    curr_node = curr_node.right_node
                else:
                    curr_node.right_node = merkletree.node.Node(index, value)
                    inserted = True
            elif curr_node.left_node:
                # left branch
                curr_node = curr_node.left_node
            else:
                curr_node.left_node = merkletree.node.Node(index, value)
                inserted = True
            i += 1

        # + 1 cause root is height 1
        if i + 1 > self.height:
            self.height = i + 1
                
    def get_node_path(self, index: int) -> List[merkletree.node.Node]:
        path: List[merkletree.node.Node] = []
        curr_node: merkletree.node.Node = self.root
        path_found: bool = False
        i = 0
        while not path_found:
            current_bit = (index >> i) & 1
            path.append(curr_node)
            if curr_node.index == index:
                path_found = True
            elif current_bit == 1 and curr_node.right_node:
                curr_node = curr_node.right_node
            elif curr_node.left_node:
                curr_node = curr_node.left_node
            else:
                raise Exception('Could not find path.')
        return path
    
    def get_rlp_path(self, index: int) -> bytes:
        path: List[merkletree.node.Node] = self.get_node_path(index)
        curr_node: merkletree.node.Node = path.pop()
        rlp_path = rlp.encode(curr_node.value)
        for i in range(len(path) - 1, 0, -1):
            curr_node = path.pop()
            current_bit: int = (index >> i) & 1
            if current_bit == 1 and curr_node.left_node:
                rlp_path = rlp.encode([curr_node.left_node.hash, rlp_path])
            elif curr_node.right_node:
                rlp_path = rlp.encode([rlp_path, curr_node.right_node.hash]) 
        return rlp_path

    def get_proof_path(self, index: int) -> List[bytes]:
        """Creates witness for an index

        Args:
            index (int): index

        Returns:
            List[bytes]: list of hashes from the other branch on each height
            -> e.g. on height 2, the index bit is 0 and therefore the path 
            to the value leaf would go down the left branch. This proof list
            would contain the hash of the right branch.
            Does not contain the leaf node itself.
        """
        path: List[merkletree.node.Node] = self.get_node_path(index)
        proof_path: List[bytes] = [path[0].hash]
        print(f'Building proof for index {index}...')
        hasher = PedersenHasher('get_proof_path_hasher')
        for i in tqdm.trange(len(path) - 1):
            current_bit: int = (index >> i) & 1
            current_node = path[i]
            if current_bit == 1:
                if current_node.left_node:
                    proof_path.append(current_node.left_node.hash)
                else:
                    proof_path.append(b'\xa8\x93\xf1\xfa\x1fG\xfd3>\x97\x13\xb38\xbb\xbf\x05?c\x01\n\xd7\xae\xcf\xf5\x84-\x96K\r\xd2\xb8X')
            else:
                if current_node.right_node:
                    proof_path.append(current_node.right_node.hash)
                else:
                    proof_path.append(b'\xa8\x93\xf1\xfa\x1fG\xfd3>\x97\x13\xb38\xbb\xbf\x05?c\x01\n\xd7\xae\xcf\xf5\x84-\x96K\r\xd2\xb8X')
        print('Done.')
        return proof_path
    
    # TODO function that gets path for a specific value
    # TODO funciton that gets index for a specific value