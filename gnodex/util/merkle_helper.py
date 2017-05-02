import merkle
import rlp
from . import crypto


def rlp_list_to_digest_list(order_list):
    return [crypto.sha256_utf8(rlp.encode(order)) for order in order_list]


def merkle_tree_from_order_list(order_list):
    leaves = rlp_list_to_digest_list(order_list)
    merkle_tree = merkle.MerkleTree(leaves, prehashed=True, raw_digests=True)
    return merkle_tree
