import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from eth_keys import keys
from eth_utils import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "staking-cli"))
from src.parser import init_parser
from src.add_receiver_key import register_receiver_key_cli


class CliTests(unittest.TestCase):
    def test_parser_accepts_receiver_options(self):
        args = init_parser().parse_args([
            "add-validator", "--secp-privkey", "01" * 32, "--bls-privkey", "02" * 32,
            "--receiver-privkey", "03" * 32, "--amount", "100000",
            "--auth-address", "0x" + "11" * 20,
        ])
        self.assertEqual(args.receiver_privkey, "03" * 32)
        args = init_parser().parse_args(["add-receiver-key", "--validator-id", "42", "--receiver-privkey", "03" * 32])
        self.assertEqual(args.validator_id, 42)

    def run_enrollment(self, auth, existing):
        config = {"log_level": "info", "rpc_url": "http://unused", "contract_address": "0x" + "10" * 20, "chain_id": 143}
        signer = Mock()
        signer.get_address.return_value = "0x" + "11" * 20
        validator = [None] * 12
        validator[0] = auth
        validator[10] = keys.PrivateKey(bytes([1]) * 32).public_key.to_compressed_bytes()
        with patch("src.add_receiver_key.Web3") as web3, \
             patch("src.add_receiver_key.call_getter", side_effect=[tuple(validator), (existing,)]), \
             patch("src.add_receiver_key.Confirm.ask", return_value=True), \
             patch("src.add_receiver_key.send_transaction") as send, \
             patch("src.add_receiver_key.init_logging"):
            web3.return_value.eth.wait_for_transaction_receipt.return_value = SimpleNamespace(status=1, transactionHash=bytes(32))
            register_receiver_key_cli(config, signer, 42, "03" * 32)
            return send.call_args

    def test_existing_validator_enrollment(self):
        call = self.run_enrollment("0x" + "11" * 20, bytes(33))
        self.assertIsNotNone(call)
        selector = keccak(text="addReceiverKey(uint64,bytes,(bytes,bytes32,bytes32))")[:4].hex()
        self.assertTrue(call.args[3].startswith("0x" + selector))
        self.assertEqual(call.args[5], 0)
        self.assertEqual(call.kwargs["gas_limit"], 300_000)

    def test_unauthorized_signer_is_rejected(self):
        self.assertIsNone(self.run_enrollment("0x" + "22" * 20, bytes(33)))

    def test_existing_key_is_rejected(self):
        self.assertIsNone(self.run_enrollment("0x" + "11" * 20, bytes([2]) + bytes(32)))


if __name__ == "__main__":
    unittest.main()
