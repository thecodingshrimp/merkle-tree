from multiprocessing import Pool
from typing import List
import tqdm
import pathlib
import os
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

class EthashMerkleTree:
    def __init__(self, file_path: str, seed: str, element_size: int = 64, threads: int = 8) -> None:
        self.HASHING_SEED = seed
        self.FILE_SIZE = pathlib.Path(file_path).stat().st_size - 8
        # self.ELEMENT_AMOUNT = self.FILE_SIZE // element_size
        self.ELEMENT_AMOUNT = 32
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
            self.mt_array: list = [b'0'] * ((2 ** self.height) - 1)
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
    
    def hash_values_in_mt(self, thread: int, leaf_amount: int, height: int) -> List[bytes]:
        total_element_num = (((2 ** self.height) - 1) - ((2 ** height) - 1)) // ((2 ** (self.height - 1)) // leaf_amount)
        hashed = 0
        hasher = PedersenHasher(self.HASHING_SEED, segments=171)
        with tqdm.tqdm(total=total_element_num) as pbar:
            # initial walk through for the leafs
            curr_index = (2 ** (self.height - 1)) + (thread * leaf_amount) - 1
            for i in range(leaf_amount):
                self.hash_array[curr_index + i] = hasher.hash_bytes(self.mt_array[curr_index + i]).compress()
                hashed += 1
                if total_element_num < 100 or hashed % 10 == 0:
                    pbar.update(hashed)
                    hashed = 0
            
            # inside of the tree
            curr_node_amount = leaf_amount
            for i in range(self.height - 1, height, -1):
                curr_node_amount = curr_node_amount // 2
                curr_index = (2 ** (i - 1)) + (thread * curr_node_amount) - 1
                for j in range(curr_node_amount):
                    self.hash_array[curr_index + j] = hasher.hash_bytes(self.hash_array[((curr_index + j) * 2) + 1] + self.hash_array[((curr_index + j) * 2) + 2]).compress()
                    hashed += 1
                    if total_element_num < 100 or hashed % 10 == 0:
                        pbar.update(hashed)
                        hashed = 0
        return self.hash_array
    
    def write_hash_to_file(self, hash_array: List[bytes]):
        with open(f'{self.file_path}_HASHES', 'wb') as f:
            for hash in hash_array:
                f.write(hash)
        
    def fill_hash_array(self) -> List[bytes]:
        return [b'0x'] * ((2 ** self.height) - 1)
    
    def fill_sub_hash_array(self, thread: int, leaf_amount: int, height: int, other_array: List[bytes]) -> List[bytes]:
        total_element_num = (((2 ** self.height) - 1) - ((2 ** height) - 1)) // ((2 ** (self.height - 1)) // leaf_amount)
        with tqdm.tqdm(total=total_element_num) as pbar:
            hashed = 0
            curr_node_amount = leaf_amount
            for i in range(self.height, height, -1):
                curr_index = (2 ** (i - 1)) + (thread * curr_node_amount) - 1
                for j in range(curr_node_amount):
                    self.hash_array[curr_index + j] = other_array[curr_index + j]
                    hashed += 1
                    if total_element_num < 100 or hashed % 10 == 0:
                        pbar.update(hashed)
                        hashed = 0
                curr_node_amount = curr_node_amount // 2
                
        return self.hash_array
        
 
    def hash_nodes_multithreaded(self, threads: int) -> None:
        # TODO optimize for non-full binary trees e.g. don't hash the value of zero over and over again + what to do with empty subtrees?
        """Executes hashing in parallel. Assumes threads to be a multiple of 2.

        Args:
            threads (int): number of threads in parallel
        """
        if os.path.exists(f'{self.file_path}_HASHES'):
            hash_amount = pathlib.Path(f'{self.file_path}_HASHES').stat().st_size // 32
            with open(f'{self.file_path}_HASHES', 'rb') as f:
                self.hash_array = [f.read(32) for _ in range(hash_amount)]
            return

        if threads <= 1:
            return self.hash_values_in_mt(0, 2 ** (self.height - 1), 0)

        multiple_of_two = 1
        height = 0
        while multiple_of_two < threads:
            height += 1
            multiple_of_two = 2 ** height
        args = []
        for j in range(threads):
            args.append((j, (2 ** (self.height - 1)) // threads, height))
        with Pool(threads) as p:
            print(f'Starting threads processing { ((2 ** (self.height)) - 1) // threads} elements each')
            answer = p.starmap(self.hash_values_in_mt, args)

        print('Merging the subtrees from threads together')
        for j in range(threads):
            print(f'Merging thread {j}')
            self.fill_sub_hash_array(j, (2 ** (self.height - 1)) // threads, height, answer[j])
            
        print('Hashing the rest without multithreading...')
        # initial walk through for the leafs
        hasher = PedersenHasher(self.HASHING_SEED, segments=171)
        # hash a 64 byte value to set segments inside pedersen lib
        with tqdm.tqdm(total=2 ** (height) - 1) as pbar:
            for i in range(height, 0, -1):
                curr_index = (2 ** (i - 1)) - 1
                for j in range(2 ** (i - 1)):
                    self.hash_array[curr_index + j] = hasher.hash_bytes(self.hash_array[((curr_index + j) * 2) + 1] + self.hash_array[((curr_index + j) * 2) + 2]).compress()
                    pbar.update(1)
        print('Done.')
    
    def add_value(self, index: int, value: bytes) -> None:
        """Adding value depending on their index. Starting with the highest bit to compare which way to go.

        Args:
            index (int):
            value (bytes): little endian
        """
        # looking at highest relevant bit from index at first.
        i = self.height - 2
        curr_index = 0
        for i in range(self.height - 2, -1, -1):
            current_bit = (index >> i) & 1
            if current_bit == 1:
                # go deeper into right branch
                curr_index = curr_index * 2 + 2
            else:
                # left branch
                curr_index = curr_index * 2 + 1
        self.mt_array[curr_index] = value
                
    def get_node_path(self, value: int or bytes) -> List[int]:
        path: List[int] = [0]
        index: int
        if type(value) == bytes:
            # its a value
            index = self.get_index(value)
        else:
            index = value
        
        curr_index = 0
        i = 0
        for i in range(self.height - 1):
            current_bit = (index >> i) & 1
            if current_bit == 1:
                curr_index = curr_index * 2 + 2
            else:
                curr_index = curr_index * 2 + 1
            path.append(curr_index)
        return path

    def get_proof_path(self, value: int or bytes) -> List[bytes]:
        """Creates witness for an index or value

        Args:
            index (int): index

        Returns:
            List[bytes]: list of hashes from the other branch on each height
            -> e.g. Wanna get proof of value A:
                               B
                              / \ 
                             C   D
                            / \ 
                           A   E  
            You would get [B, D, E]
        """
        path: List[int] = self.get_node_path(value)
        print(f'Building proof for {"index" if type(value) == int else "value"} {value}...')
        proof_path: List[bytes] = [self.hash_array[0]] + [self.hash_array[node_index - 1] if node_index % 2 == 0 else self.hash_array[node_index + 1] for node_index in path[1:]]
        print('Done.')
        return proof_path
    
    def get_value(self, index: int) -> bytes:
        path: List[int] = self.get_node_path(index)
        return self.mt_array[path[-1]]
    
    def get_index(self, value: bytes) -> int:
        return self.mt_array.index(value, len(self.mt_array) - self.ELEMENT_AMOUNT, len(self.mt_array)) - (self.ELEMENT_AMOUNT - 1)