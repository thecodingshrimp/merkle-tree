from multiprocessing import Pool
from typing import List
import tqdm
import pathlib
import os
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

class EthashMerkleProof:
    def __init__(self, proof_path: List[bytes], value: bytes, index: int, seed: str) -> None:
        self.proof_path = proof_path
        self.value = value
        self.index = index
        self.hasher = PedersenHasher(seed, 171)
        
    def validate(self) -> bool:
        curr_hash = self.hasher.hash_bytes(self.value).compress()
        for i in range(len(self.proof_path) - 1):
            current_bit = (self.index >> i) & 1
            if current_bit == 1:
                curr_hash = self.hasher.hash_bytes(self.proof_path.pop() + curr_hash).compress()
            else:
                curr_hash = self.hasher.hash_bytes(curr_hash + self.proof_path.pop()).compress()
        return curr_hash == self.proof_path[0]

class EthashMerkleTree:
    def __init__(self, file_path: str, seed: str, element_size: int = 64, threads: int = 8) -> None:
        """_summary_

        Args:
            file_path (str): _description_
            seed (str): first 8 bytes of the seed
            element_size (int, optional): byte size of each element. Defaults to 64.
            threads (int, optional): threads to use to build the hashed merkle tree. Defaults to 8.
        """
        self.HASHING_SEED = seed
        self.FILE_SIZE = pathlib.Path(file_path).stat().st_size - 8
        self.HASHED_NULL_VALUE = b'\x17`\x8c\xa2d\xc1\xeb\xd3\xb7L\xcc[\xc8\x18J\xfc\x90\xab\xe5\x90\xd3\xe0\x91ZR9}\x12\xba\x8cS\xa3'
        self.NULL_VALUE = b'0x'
        self.ELEMENT_AMOUNT = self.FILE_SIZE // element_size
        # self.ELEMENT_AMOUNT = 64
        self.find_mt_height()
        self.ELEMENT_SIZE = element_size
        self.file_path = file_path
        print(f'#(Elements)/#Leafs = {self.ELEMENT_AMOUNT}/{2 ** (self.height - 1)}')
        print(f'#nodes = {(2 ** self.height) - 1}')
        print(f'MT Tree height: {self.height}')
        with open(file_path, 'rb') as f:
            # skip 'magic' number 
            f.read(8)
            # initiate parent (Node) with first entry
            print('Building tree...')
            print('Creating mt array')
            self.mt_array: List[bytes] = self.fill_mt_array()
            self.mt_array_size = len(self.mt_array)
            for i in tqdm.trange(0, self.ELEMENT_AMOUNT):
                raw_value = f.read(64)
                self.add_value(i, raw_value)
            self.hash_array: List[bytes] = self.fill_hash_array()
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
                value = self.mt_array[curr_index + i]
                if value != self.NULL_VALUE:
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
                    left_hash = self.hash_array[((curr_index + j) * 2) + 1]
                    right_hash = self.hash_array[((curr_index + j) * 2) + 2]
                    if left_hash != self.HASHED_NULL_VALUE or right_hash != self.HASHED_NULL_VALUE:
                        self.hash_array[curr_index + j] = hasher.hash_bytes(left_hash + right_hash).compress()
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
        return [self.HASHED_NULL_VALUE] * ((2 ** self.height) - 1)
    
    def fill_mt_array(self) -> List[bytes]:
        return [self.NULL_VALUE] * ((2 ** self.height) - 1)
    
    def fill_sub_hash_array(self, thread: int, leaf_amount: int, height: int, other_array: List[bytes]) -> List[bytes]:
        curr_node_amount = leaf_amount
        for i in range(self.height, height, -1):
            curr_index = (2 ** (i - 1)) + (thread * curr_node_amount) - 1
            for j in range(curr_node_amount):
                self.hash_array[curr_index + j] = other_array[curr_index + j]
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
            self.fill_sub_hash_array(j, (2 ** (self.height - 1)) // threads, height, answer[j])
            
        print('Hashing the rest without multithreading...')
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
        path = self.get_node_path(index)
        self.mt_array[path[-1]] = value
                
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
        for i in range(self.height - 2, -1, -1):
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
        return self.mt_array[index + (2 ** (self.height - 1) - 1)]
    
    def get_index(self, value: bytes) -> int:
        return self.mt_array.index(value, 2 ** (self.height - 1) - 1, 2 ** self.height - 1) - (2 ** (self.height - 1) - 1)