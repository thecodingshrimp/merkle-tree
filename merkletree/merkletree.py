from typing import List
import merkletree.node
import rlp
import tqdm
import pathlib

class EthashMerkleTree:
    def __init__(self, file_path: str, element_size: int = 64) -> None:
        self.FILE_SIZE = pathlib.Path(file_path).stat().st_size - 8
        self.ELEMENT_AMOUNT = self.FILE_SIZE // element_size
        self.ELEMENT_SIZE = element_size
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
            self.hash_nodes()
            print('Done')
    
    def hash_nodes(self) -> None:
        working_list: List[merkletree.node.Node] = [self.root]
        with tqdm.tqdm(total=(self.ELEMENT_AMOUNT - 1)) as pbar:
            while len(working_list) > 0:
                curr_node = working_list[-1]
                if curr_node.left_node and curr_node.left_node.hash < 0:
                    working_list.append(curr_node.left_node)
                elif curr_node.right_node and curr_node.right_node.hash < 0:
                    working_list.append(curr_node.right_node)
                else:
                    curr_node.set_hash()
                    working_list.pop()
                    pbar.update(1)
    
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
                    continue
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

        if i > self.height:
            self.height = i
                
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
        i = len(path) - 2
        curr_node: merkletree.node.Node = path.pop()
        rlp_path = rlp.encode(curr_node.value)
        while len(path) > 0:
            curr_node = path.pop()
            current_bit: int = (index >> i) & 1
            if current_bit == 1 and curr_node.left_node:
                rlp_path = rlp.encode([curr_node.left_node.hash, rlp_path])
            elif curr_node.right_node:
                rlp_path = rlp.encode([rlp_path, curr_node.right_node.hash])
            i -= 1
        return rlp_path
    
    def get_proof_path(self, index: int) -> List[int]:
        path: List[merkletree.node.Node] = self.get_node_path(index)
        
        