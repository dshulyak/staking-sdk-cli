import unittest
from blake3 import blake3
from eth_abi import decode
from eth_keys import keys
from eth_utils import keccak
from py_ecc.bls import G2ProofOfPossession as bls

from staking_sdk_py.generateCalldata import add_validator, add_receiver_key, get_receiver_key
from staking_sdk_py.keyGenerator import KeyGenerator


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.secp = (1).to_bytes(32, "big").hex()
        self.bls = (2).to_bytes(32, "big").hex()
        self.receiver = (3).to_bytes(32, "big").hex()
        self.auth = "0x" + "11" * 20

    def verify_signatures(self, keygen, payload, secp_sig, bls_sig):
        signature = keys.NonRecoverableSignature(secp_sig)
        self.assertTrue(signature.verify_msg_hash(blake3(payload).digest(), keygen.priv_secp_key().public_key))
        self.assertTrue(bls.Verify(keygen.pub_bls_key(), payload, bls_sig))

    def test_legacy_registration(self):
        keygen = KeyGenerator.from_keys(self.secp, self.bls)
        calldata = bytes.fromhex(add_validator(keygen, 100, self.auth)[2:])
        self.assertEqual(calldata[:4], keccak(text="addValidator(bytes,bytes,bytes)")[:4])
        payload, secp_sig, bls_sig = decode(["bytes"] * 3, calldata[4:])
        self.assertEqual(len(payload), 165)
        self.verify_signatures(keygen, payload, secp_sig, bls_sig)

    def test_extended_registration(self):
        keygen = KeyGenerator.from_keys(self.secp, self.bls, self.receiver)
        calldata = bytes.fromhex(add_validator(keygen, 100, self.auth, 7, chain_id=143)[2:])
        self.assertEqual(calldata[:4], keccak(text="addValidator(bytes,bytes,bytes,(bytes,bytes32,bytes32))")[:4])
        payload, secp_sig, bls_sig, proof = decode(
            ["bytes", "bytes", "bytes", "(bytes,bytes32,bytes32)"], calldata[4:]
        )
        self.assertEqual(len(payload), 198)
        self.assertEqual(payload[:33], keygen.pub_secp_key())
        self.assertEqual(payload[33:81], keygen.pub_bls_key())
        self.assertEqual(payload[81:114], keygen.pub_receiver_key())
        self.assertEqual(payload[114:134], bytes.fromhex(self.auth[2:]))
        self.assertEqual(int.from_bytes(payload[134:166], "big"), 100)
        self.assertEqual(int.from_bytes(payload[166:], "big"), 7)
        self.assertEqual(tuple(map(len, proof)), (33, 32, 32))
        self.verify_signatures(keygen, payload, secp_sig, bls_sig)

    def test_receiver_registration_requires_chain(self):
        keygen = KeyGenerator.from_keys(self.secp, self.bls, self.receiver)
        with self.assertRaises(ValueError):
            add_validator(keygen, 100, self.auth)

    def test_receiver_key_enrollment(self):
        keygen = KeyGenerator.from_keys(self.secp, self.bls, self.receiver)
        calldata = bytes.fromhex(add_receiver_key(42, bytes.fromhex(self.receiver), 143, keygen.get_eth_address)[2:])
        self.assertEqual(calldata[:4], keccak(text="addReceiverKey(uint64,bytes,(bytes,bytes32,bytes32))")[:4])
        validator_id, public_key, proof = decode(
            ["uint64", "bytes", "(bytes,bytes32,bytes32)"], calldata[4:]
        )
        self.assertEqual(validator_id, 42)
        self.assertEqual(public_key, keygen.pub_receiver_key())
        self.assertEqual(tuple(map(len, proof)), (33, 32, 32))

    def test_receiver_key_getter(self):
        calldata = bytes.fromhex(get_receiver_key(42)[2:])
        self.assertEqual(calldata[:4], keccak(text="getReceiverKey(uint64)")[:4])
        self.assertEqual(decode(["uint64"], calldata[4:]), (42,))

    def test_receiver_key_validation(self):
        for secret in ["", "00" * 32, "ff" * 32]:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                KeyGenerator.from_keys(self.secp, self.bls, secret)


if __name__ == "__main__":
    unittest.main()
