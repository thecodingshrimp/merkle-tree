from __future__ import annotations
from typing import List, Optional
from Crypto.Hash import SHA3_256
import rlp

class Node:
    def __init__(self, index: int, value: bytes, left_node: Node = None, right_node: Node = None) -> None:
        """Node in MT

        Args:
            index (int): index of item in dataset
            value (bytes): item in uint32[*][16] (little endian)
            left_node (Node, optional): _description_. Defaults to None.
            right_node (Node, optional): _description_. Defaults to None.
        """
        self.index: int = index
        self.value: bytes = value
        self.left_node: Optional[Node] = left_node
        self.right_node: Optional[Node] = right_node
        self.hash: int = index
    
    def become_branch(self) -> None:
        self.index = -1
        self.value = b''
        self.hash = -1
        
    def set_hash(self) -> int:
        # TODO create rlp of subtree nodes and then hash?
        if self.index > -1:
            # return SHA3_256.new(self.value).hexdigest()
            self.hash = self.index
        # TODO what if only one child?
        elif self.left_node and self.right_node:
            # return SHA3_256.new(bytes.fromhex(self.left_node.hash()) + bytes.fromhex(self.right_node.hash())).hexdigest()
            self.hash = self.left_node.hash + self.right_node.hash
        elif self.right_node:
            self.hash = self.right_node.hash - 1
        elif self.left_node:
            self.hash = self.left_node.hash - 1
        if self.hash > -1:
            return self.hash
        raise Exception
    
    def find(self, index: int, height: int) -> bytes:
        current_bit = (self.index >> height) & 1
        height += 1
        if self.index == index:
            return self.value
        if current_bit == 1 and self.right_node:
            return self.right_node.find(index, height)
        elif self.left_node:
            return self.left_node.find(index, height)
        raise Exception
    
    def remove(self, index: int, height: int) -> bool:
        current_bit = (self.index >> height) & 1
        height += 1
        if current_bit == 1 and self.right_node:
            if self.right_node.index == index:
                self.right_node = None
                return True
            return self.right_node.remove(index, height)
        if self.left_node:
            if self.left_node.index == index:
                self.left_node = None
                return True
            return self.left_node.remove(index, height)
        return False
    
    def path(self, index: int, height: int) -> List[Node]:
        curr_path = [self]
        if self.index == index:
            return curr_path
        
        current_bit = (self.index >> height) & 1
        height += 1
        if current_bit == 1 and self.right_node:
            curr_path.extend(self.right_node.path(index, height))
        elif self.left_node:
            curr_path.extend(self.left_node.path(index, height))
        return curr_path
    
    def rlp_path(self, index: int, height: int) -> bytes:
        if self.index == index:
            return rlp.encode(self.value, infer_serializer=False, cache=False)
        
        if self.right_node and self.left_node:
            current_bit = (self.index >> height) & 1
            height += 1
            if current_bit == 1:
                left_hash = self.left_node.hash()
                right_rlp = self.right_node.rlp_path(index, height)
                return rlp.encode([bytes.fromhex(left_hash), right_rlp], infer_serializer=False, cache=False)
            else:
                left_rlp = self.left_node.rlp_path(index, height)
                right_hash = self.right_node.hash()
                return rlp.encode([left_rlp, bytes.fromhex(right_hash)], infer_serializer=False, cache=False)
        raise Exception