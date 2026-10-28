from coincurve import PrivateKey
from eth_keys import keys
from rich.console import Console
from rich.prompt import Confirm, Prompt
from web3 import Web3

from staking_sdk_py.callGetters import call_getter
from staking_sdk_py.generateCalldata import add_receiver_key
from staking_sdk_py.keyGenerator import KeyGenerator
from src.helpers import send_transaction
from src.logger import init_logging


def register_receiver_key(config, signer):
    validator_id = Prompt.ask("Validator ID")
    receiver_secret = Prompt.ask("Receiver private key (hex)", password=True)
    try:
        validator_id = int(validator_id)
    except ValueError:
        Console().print("Invalid validator ID")
        return
    register_receiver_key_cli(config, signer, validator_id, receiver_secret)


def register_receiver_key_cli(config, signer, validator_id, receiver_privkey):
    log = init_logging(config["log_level"].upper())
    try:
        if not 0 < validator_id < 2**64:
            raise ValueError("Validator ID must be a nonzero uint64")
        secret = bytes.fromhex(KeyGenerator.key_sanitation(receiver_privkey))
        if len(secret) != 32:
            raise ValueError("Receiver private key must be 32 bytes")
        public_key = PrivateKey(secret).public_key.format()
        w3 = Web3(Web3.HTTPProvider(config["rpc_url"]))
        contract = config["contract_address"]
        validator = call_getter(w3, "get_validator", contract, validator_id)
        auth_address = validator[0]
        if int(auth_address, 16) == 0:
            raise ValueError("Unknown validator")
        if auth_address.lower() != signer.get_address().lower():
            raise ValueError("Receiver key enrollment requires the validator's authorized signer")
        existing_key, = call_getter(w3, "get_receiver_key", contract, validator_id)
        if any(existing_key):
            raise ValueError("Validator already has a receiver key")
        validator_address = keys.PublicKey.from_compressed_bytes(validator[10]).to_checksum_address()
        calldata = add_receiver_key(validator_id, secret, config["chain_id"], validator_address)
        log.info(f"Validator address: {validator_address}")
        log.info(f"Receiver Pubkey: {public_key.hex()}")
        if not Confirm.ask("Register this receiver key?", default=False):
            return
        tx_hash = send_transaction(
            w3, signer, contract, calldata, config["chain_id"], 0, gas_limit=300_000
        )
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        log.info(f"Tx status: {receipt.status}")
        log.info(f"Tx hash: 0x{receipt.transactionHash.hex()}")
    except Exception as error:
        log.error(f"Receiver key enrollment failed: {error}")
