import unittest
from unittest.mock import patch

from staking_sdk_py.receiver_key import (
    CHALLENGE_DST, SCALAR_ORDER, hash_to_secp256k1,
    prove_receiver_key_registration,
)
from staking_sdk_py import receiver_key


SECRET = bytes([7]) + bytes(31)
NONCE = bytes([11]) + bytes(31)
PUBLIC_KEY = "02308138e71be25e092fdc9da03d5357421bc7280356a1381a6186d63a0ca8dd7f"
PROOF = (
    "029b3fd64688f9e3dd531deebadd3a41bdeb176a38b2ca11d101c0ed860f0fc3f15"
    "21bff659947a96f2b8f48a7d81cd0b58aaa338729e17fa2a66c9acee19f564f87"
    "ecfa597ecc4c3eec8bcefbafe746f46b713257d9cd4f420ddc0f4550e6bccb"
)


class ReceiverKeyTests(unittest.TestCase):
    def test_rfc9380_vectors(self):
        vectors = [
            (b"", "03c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"),
            (b"abc", "023377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"),
            (b"abcdef0123456789", "02bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a"),
            (b"q128_" + b"q" * 128, "03e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9"),
            (b"a512_" + b"a" * 512, "02e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998"),
        ]
        dst = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
        for message, expected in vectors:
            with self.subTest(message=message):
                self.assertEqual(hash_to_secp256k1(message, dst).format().hex(), expected)

    @patch("staking_sdk_py.receiver_key.secrets.token_bytes", return_value=NONCE)
    def test_native_proof_fixture(self, entropy):
        key, proof = prove_receiver_key_registration(0, bytes(20), SECRET)
        self.assertEqual(key.hex(), PUBLIC_KEY)
        self.assertEqual(b"".join(proof).hex(), PROOF)
        entropy.assert_called_once_with(32)

    @patch("staking_sdk_py.receiver_key.secrets.token_bytes", return_value=NONCE)
    def test_chain_and_identity_change_proof(self, entropy):
        _, original = prove_receiver_key_registration(0, bytes(20), SECRET)
        _, other_chain = prove_receiver_key_registration(143, bytes(20), SECRET)
        _, other_address = prove_receiver_key_registration(0, bytes([1]) * 20, SECRET)
        self.assertNotEqual(original, other_chain)
        self.assertNotEqual(original, other_address)

    def test_invalid_inputs(self):
        for secret in [bytes(32), SCALAR_ORDER.to_bytes(32, "big"), bytes(31), bytes(33)]:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                prove_receiver_key_registration(143, bytes(20), secret)
        for chain in [-1, 2**256, True]:
            with self.subTest(chain=chain), self.assertRaises(ValueError):
                prove_receiver_key_registration(chain, bytes(20), SECRET)
        for address in [bytes(19), bytes(21), "0xgg"]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                prove_receiver_key_registration(143, address, SECRET)

    @patch("staking_sdk_py.receiver_key.secrets.token_bytes", side_effect=[bytes(32), NONCE])
    def test_zero_nonce_is_resampled(self, entropy):
        _, proof = prove_receiver_key_registration(0, bytes(20), SECRET)
        self.assertEqual(b"".join(proof).hex(), PROOF)
        self.assertEqual(entropy.call_count, 2)

    def test_invalid_domains(self):
        for dst in [b"", bytes(256)]:
            with self.subTest(dst=dst), self.assertRaises(ValueError):
                hash_to_secp256k1(b"message", dst)

    def test_maximum_domain_length(self):
        dst = bytes([0xa5]) * 255
        self.assertEqual(
            hash_to_secp256k1(b"receiver-key", dst).format().hex(),
            "02d1ca38ca4bfcb5b29dd503f74729fbe229df3cd6be35be071a8c690abe271502",
        )
        scalar = int.from_bytes(receiver_key._expand_xmd(b"receiver-key", dst, 48), "big")
        self.assertEqual(
            (scalar % SCALAR_ORDER).to_bytes(32, "big").hex(),
            "eff5c04bfc9817ed59473a65607cef0bfaeeb0b81ceabbcf01a478f8cdbf3da2",
        )

    def test_zero_challenge_and_response_encoding(self):
        # Force the two valid scalar-zero cases without changing the public API.
        expand = receiver_key._expand_xmd
        secret = int.from_bytes(SECRET, "big")
        nonce = int.from_bytes(NONCE, "big")
        cancel = -nonce * pow(secret, -1, SCALAR_ORDER) % SCALAR_ORDER
        for challenge in [0, cancel]:
            def fixed_challenge(message, dst, length):
                if dst == CHALLENGE_DST:
                    return challenge.to_bytes(48, "big")
                return expand(message, dst, length)
            with self.subTest(challenge=challenge), \
                 patch("staking_sdk_py.receiver_key._expand_xmd", side_effect=fixed_challenge), \
                 patch("staking_sdk_py.receiver_key.secrets.token_bytes", return_value=NONCE):
                _, proof = prove_receiver_key_registration(0, bytes(20), SECRET)
            self.assertEqual(len(proof.image), 33)
            self.assertEqual(int.from_bytes(proof.challenge, "big"), challenge)
            self.assertEqual(proof.response, NONCE if challenge == 0 else bytes(32))


if __name__ == "__main__":
    unittest.main()
