import merkle
import rlp
from . import crypto

def merkle_tree_from_orders(orders):
    leaves = [crypto.sha256_utf8(rlp.encode(order)) for order in orders]
    merkle_tree = merkle.MerkleTree(leaves, prehashed=True, raw_digests=True)
    return merkle_tree

