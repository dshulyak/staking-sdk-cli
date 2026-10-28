from typing import Optional

from coincurve import PrivateKey
from eth_keys import keys
from py_ecc.bls import G2ProofOfPossession as bls


class KeyGenerator:
    def __init__(self, secp_private_key: keys.PrivateKey, bls_private_key: int,
                 receiver_private_key: Optional[bytes] = None):
        self.secp_private_key = secp_private_key
        self.secp_public_key = self.secp_private_key.public_key.to_compressed_bytes()

        self.bls_private_key = bls_private_key
        self.bls_public_key = bls.SkToPk(self.bls_private_key)

        self.eth_address = self.secp_private_key.public_key.to_checksum_address()
        if receiver_private_key is not None and len(receiver_private_key) != 32:
            raise ValueError("Receiver private key must be 32 bytes")
        self.receiver_private_key = (
            PrivateKey(receiver_private_key) if receiver_private_key is not None else None
        )

    @classmethod
    def from_keys(cls, secp_private_key: str, bls_private_key: str,
                  receiver_private_key: Optional[str] = None):
        try:
            secp_private_key = cls.key_sanitation(secp_private_key)
            bls_private_key = cls.key_sanitation(bls_private_key)
            secp_private_key_bytes = bytes.fromhex(secp_private_key)
            bls_private_key_bytes = bytes.fromhex(bls_private_key)

            if len(secp_private_key_bytes) != 32:
                raise ValueError(f"KeyGenerator: [Error] Invalid length: a secp private key must be 32 bytes (64 hex characters), but this key is {len(secp_private_key_bytes)} bytes.")

            if len(bls_private_key_bytes) != 32:
                raise ValueError(f"KeyGenerator: [Error] Invalid length: a bls private key must be 32 bytes (64 hex characters), but this key is {len(bls_private_key_bytes)} bytes.")

            secp_private_key = keys.PrivateKey(secp_private_key_bytes)
            bls_private_key_int = int.from_bytes(bls_private_key_bytes, 'big')

            receiver_bytes = None
            if receiver_private_key is not None:
                receiver_bytes = bytes.fromhex(cls.key_sanitation(receiver_private_key))
            return cls(secp_private_key, bls_private_key_int, receiver_bytes)

        except ValueError as e:
            raise ValueError(f"\nKeyGenerator: [Error] Could not process key: {e}")

    @staticmethod
    def key_sanitation(hex_key: str) -> str:
        if not isinstance(hex_key, str):
            raise TypeError("Key must be a hex string.")
        if hex_key.startswith("0x"):
            sanitized_key = hex_key[2:]
        else:
            sanitized_key = hex_key
        return sanitized_key

    def pub_secp_key(self):
        return self.secp_public_key

    def priv_secp_key(self):
        return self.secp_private_key

    def pub_bls_key(self):
        return self.bls_public_key

    def priv_bls_key(self):
        return self.bls_private_key

    def pub_receiver_key(self):
        if self.receiver_private_key is None:
            return None
        return self.receiver_private_key.public_key.format()

    def priv_receiver_key(self):
        if self.receiver_private_key is None:
            return None
        return self.receiver_private_key.secret

    @property
    def get_eth_address(self):
        return self.eth_address


