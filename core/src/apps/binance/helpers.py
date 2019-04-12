from micropython import const

from trezor.crypto import bech32
from trezor.crypto.hashlib import ripemd160, sha256

from apps.common import HARDENED

def address_from_public_key(pubkey: bytes) -> str:
    # Address = RIPEMD160(SHA256(compressed public key))
    h = sha256(pubkey).digest()
    h = ripemd160(h).digest()

    convertedbits = bech32.convertbits(h, 8, 5, False)

    return bech32.bech32_encode("tbnb", convertedbits)

def validate_full_path(path: list) -> bool:
    """
    Validates derivation path to equal 44'/144'/a'/0/0,
    where `a` is an account index from 0 to 1 000 000.
    Similar to Ethereum this should be 44'/144'/a', but for
    compatibility with other HW vendors we use 44'/144'/a'/0/0.
    """
    if len(path) != 5:
        return False
    if path[0] != 44 | HARDENED:
        return False
    if path[1] != 714 | HARDENED:
        return False
    if path[2] < HARDENED or path[2] > 1000000 | HARDENED:
        return False
    if path[3] != 0:
        return False
    if path[4] != 0:
        return False
    return True