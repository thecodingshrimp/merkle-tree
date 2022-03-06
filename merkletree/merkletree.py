from multiprocessing import Pool
from typing import List
import merkletree.node
import rlp
import tqdm
import pathlib
import copy
import numpy as np
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

class EthashMerkleTree:
    def __init__(self, file_path: str, element_size: int = 64, threads: int = 8) -> None:
        self.FILE_SIZE = pathlib.Path(file_path).stat().st_size - 8
        # self.ELEMENT_AMOUNT = self.FILE_SIZE // element_size
        self.ELEMENT_AMOUNT = 8
        self.find_mt_height()
        self.ELEMENT_SIZE = element_size
        self.file_path = file_path
        print(f'#(Elements) = {self.ELEMENT_AMOUNT}')
        print(f'MT Tree height: {self.height}')
        with open(file_path, 'rb') as f:
            # skip 'magic' number 
            f.read(8)

            # initiate parent (Node) with first entry
            print('Building tree...')
            print('Creating mt array')
            self.mt_array = [b'0'] * ((2 ** self.height) - 1)
            self.mt_array_size = len(self.mt_array)
            for i in tqdm.trange(0, self.ELEMENT_AMOUNT):
                raw_value = f.read(64)
                self.add_value(i, raw_value)
            self.hash_array = self.fill_hash_array()
            print('Setting hash values')
            self.hash_nodes_multithreaded(threads)
            print('Done')
            print('Get hash array')
            print('write to file')
            self.write_hash_to_file(self.hash_array)
            print('Done')
    
    def find_mt_height(self) -> int:
        curr_height = 1
        # mt has 2 ** (h - 1) leafs.
        while 2 ** curr_height < self.ELEMENT_AMOUNT:
            curr_height += 1
        # mt has (2 ** h) - 1 leafs and branches
        self.height = curr_height + 1
        return self.height
    
    def hash_values_in_mt(self, start_index: int, height: int) -> List[bytes]:
        working_list: List[int] = np.array([start_index])
        own_pbar = tqdm.tqdm(total=((2 ** (self.height - height)) - 1))
        curr_index = working_list[0]
        num_hashed = 0
        hasher = PedersenHasher('hash_values_in_mt')
        while len(working_list) > 0:
            curr_index = working_list[-1]
            if curr_index * 2 + 1 < len(self.hash_array) and self.hash_array[curr_index * 2 + 1] == b'0x':
                working_list = np.append(working_list, curr_index * 2 + 1)
            elif curr_index * 2 + 2 < len(self.hash_array) and self.hash_array[curr_index * 2 + 2] == b'0x':
                working_list = np.append(working_list, curr_index * 2 + 2)
            else:
                # only checking left child since it is expected that the right child will be out of bounds too.
                if curr_index * 2 + 1 < len(self.hash_array):
                    self.hash_array[curr_index] = hasher.hash_bytes(self.hash_array[curr_index * 2 + 1] + self.hash_array[curr_index * 2 + 2]).compress()
                else:
                    self.hash_array[curr_index] = hasher.hash_bytes(self.mt_array[curr_index]).compress()
                working_list = np.delete(working_list, len(working_list) - 1)
                num_hashed += 1
                if num_hashed >= 10 or self.ELEMENT_AMOUNT < 100:
                    own_pbar.update(num_hashed)
                    num_hashed = 0
        own_pbar.close()
        return self.hash_array
    
    def write_hash_to_file(self, hash_array: List[bytes]):
        with open(f'{self.file_path}_HASHES', 'wb') as f:
            for hash in hash_array:
                f.write(hash)
        
    def fill_hash_array(self) -> List[bytes]:
        return [b'0x'] * ((2 ** self.height) - 1)
    
    def fill_sub_hash_array(self, start_index: int, other_array: List[bytes]) -> List[bytes]:
        working_list: List[int] = np.array([start_index])
        while len(working_list) > 0:
            curr_index = working_list[-1]
            if curr_index * 2 + 1 < len(self.hash_array) and self.hash_array[curr_index * 2 + 1] == b'0x':
                working_list = np.append(working_list, curr_index * 2 + 1)
            elif curr_index * 2 + 2 < len(self.hash_array) and self.hash_array[curr_index * 2 + 2] == b'0x':
                working_list = np.append(working_list, curr_index * 2 + 2)
            else:
                # only checking left child since it is expected that the right child will be out of bounds too.
                self.hash_array[curr_index] = other_array[curr_index]
                working_list = np.delete(working_list, len(working_list) - 1)
        return self.hash_array
        
 
    def hash_nodes_multithreaded(self, threads: int) -> None:
        """Executes hashing in parallel. Assumes threads to be a multiple of 2.

        Args:
            threads (int): number of threads in parallel
        """
        if threads <= 1:
            return self.hash_values_in_mt(0, 0)
        
        multiple_of_two = 1
        height = 0
        while multiple_of_two < threads:
            height += 1
            multiple_of_two = 2 ** height
        args = []
        for j in range(threads):
            curr_index = 0
            for k in range(height):
                current_bit = (j >> k) & 1
                if current_bit == 1 and curr_index * 2 + 2 < self.mt_array_size:
                    # go deeper into right branch
                    curr_index = curr_index * 2 + 2
                elif curr_index * 2 + 1 < self.mt_array_size:
                    # left branch
                    curr_index = curr_index * 2 + 1
                else:
                    break
            args.append((curr_index, height))
        with Pool(threads) as p:
            answer = p.starmap(self.hash_values_in_mt, args)

        for j in range(threads):
            curr_index = 0
            for k in range(height):
                current_bit = (j >> k) & 1
                if current_bit == 1 and curr_index * 2 + 2 < self.mt_array_size:
                    # go deeper into right branch
                    curr_index = curr_index * 2 + 2
                elif curr_index * 2 + 1 < self.mt_array_size:
                    # left branch
                    curr_index = curr_index * 2 + 1
                else:
                    break
            self.fill_sub_hash_array(curr_index, answer[j])
            
        print('Hashing the rest without multithreading...')
        self.hash_values_in_mt(0, 0)
        print('Done.')
    
    def add_value(self, index: int, value: bytearray) -> None:
        inserted: bool = False
        i = 0
        curr_index = 0
        while not inserted:
            current_bit = (index >> i) & 1
            if current_bit == 1 and curr_index * 2 + 2 < self.mt_array_size:
                # go deeper into right branch
                curr_index = curr_index * 2 + 2
            elif curr_index * 2 + 1 < self.mt_array_size:
                # left branch
                curr_index = curr_index * 2 + 1
            else:
                self.mt_array[curr_index] = value
                inserted = True
            i += 1
                
    def get_node_path(self, index: int) -> List[int]:
        path: List[int] = []
        curr_index = 0
        path_found: bool = False
        i = 0
        while not path_found:
            current_bit = (index >> i) & 1
            path.append(curr_index)
            if curr_index * 2 + 1 >= len(self.mt_array):
                path_found = True
            elif current_bit == 1:
                curr_index = curr_index * 2 + 2
            else:
                curr_index = curr_index * 2 + 1
            i += 1
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
        path: List[int] = self.get_node_path(index)
        proof_path: List[bytes] = []
        print(f'Building proof for index {index}...')
        for i in tqdm.trange(len(path)):
            proof_path.append(self.hash_array[path[i]])
        print('Done.')
        return proof_path
    
    # TODO function that gets path for a specific value
    # TODO funciton that gets index for a specific value