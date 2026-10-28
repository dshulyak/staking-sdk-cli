from blake3 import blake3
import staking_sdk_py.constants as constants
import staking_sdk_py.keyGenerator as keyGenerator
from staking_sdk_py.receiver_key import prove_receiver_key_registration
from typing import Optional, Union
import eth_abi


from py_ecc.bls import G2ProofOfPossession as bls

def add_validator(
    k: "keyGenerator.KeyGenerator",
    amount: int,
    auth_address: str,
    commission: int = 0,
    *,
    chain_id: Optional[int] = None,
) -> str:
    secp_pub_key = k.pub_secp_key()
    bls_pub_key = k.pub_bls_key()
    auth_address_bytes = bytes.fromhex(strip_0x(auth_address))

    secp_priv_key = k.priv_secp_key()
    bls_privkey = k.priv_bls_key()

    # Build payload (everything except the signatures)
    payload_parts = [
        secp_pub_key,
        bls_pub_key,
        auth_address_bytes,
        int(amount).to_bytes(32, byteorder='big'),
        int(commission).to_bytes(32, byteorder='big'),
    ]
    receiver_secret = k.priv_receiver_key()
    receiver_proof = None
    if receiver_secret is not None:
        if chain_id is None:
            raise ValueError("Chain ID is required when registering a receiver key")
        receiver_public_key, receiver_proof = prove_receiver_key_registration(
            chain_id, k.get_eth_address, receiver_secret
        )
        payload_parts.insert(2, receiver_public_key)
    payload = b''.join(payload_parts)

    secp_sig = secp_priv_key.sign_msg_hash_non_recoverable(blake3(payload).digest()).to_bytes()
    bls_sig = bls.Sign(bls_privkey, payload)

    values = [payload, secp_sig, bls_sig]
    types = ['bytes'] * 3
    selector = constants.ADD_VALIDATOR_SELECTOR
    if receiver_proof is not None:
        selector = constants.ADD_VALIDATOR_RECEIVER_SELECTOR
        values.append(receiver_proof)
        types.append('(bytes,bytes32,bytes32)')
    return "0x" + selector + eth_abi.encode(types, values).hex()


def add_receiver_key(validator_id: int, receiver_secret: bytes, chain_id: int,
                     validator_address: str) -> str:
    public_key, proof = prove_receiver_key_registration(
        chain_id, validator_address, receiver_secret
    )
    return "0x" + constants.ADD_RECEIVER_KEY_SELECTOR + eth_abi.encode(
        ['uint64', 'bytes', '(bytes,bytes32,bytes32)'], [validator_id, public_key, proof]
    ).hex()


def get_receiver_key(validator_id: int) -> str:
    return "0x" + constants.GET_RECEIVER_KEY_SELECTOR + eth_abi.encode(
        ['uint64'], [validator_id]
    ).hex()


def strip_0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s

def delegate(validator_id: Union[int, str]) -> str:
    return "0x" + constants.DELEGATE_SELECTOR + eth_abi.encode(['uint64'], [validator_id]).hex()

def undelegate(validator_id: Union[int, str], amount: Union[int, str], withdraw_id: int) -> str:
    return "0x" + constants.UNDELEGATE_SELECTOR + eth_abi.encode(['uint64', 'uint256', 'uint8'], [validator_id, amount, withdraw_id]).hex()

def withdraw(validator_id: Union[int, str], withdraw_id: int) -> str:
    return "0x" + constants.WITHDRAW_SELECTOR + eth_abi.encode(['uint64', 'uint8'], [validator_id, withdraw_id]).hex()

def compound(validator_id: Union[int, str]) -> str:
    return "0x" + constants.COMPOUND_SELECTOR + eth_abi.encode(['uint64'], [validator_id]).hex()

def claim_rewards(validator_id: Union[int, str]) -> str:
    return "0x" + constants.CLAIM_REWARDS_SELECTOR + eth_abi.encode(['uint64'], [validator_id]).hex()

def change_commission(validator_id: Union[int, str], commission: int) -> str:
    return "0x" + constants.CHANGE_COMMISSION_SELECTOR + eth_abi.encode(['uint64', 'uint256'], [validator_id, commission]).hex()

def get_epoch() -> str:
    return "0x" + constants.GET_EPOCH_SELECTOR

def get_validator(validator_id: Union[int, str]) -> str:
    return "0x" + constants.GET_VALIDATOR_SELECTOR + eth_abi.encode(['uint64'], [validator_id]).hex()

def get_delegator(validator_id: Union[int, str], delegator_address: str) -> str:
    address_hex = strip_0x(delegator_address)
    return "0x" + constants.GET_DELEGATOR_SELECTOR + eth_abi.encode(['uint64', 'address'], [validator_id, address_hex]).hex()

def get_withdrawal_request(validator_id: Union[int, str], delegator_address: str, withdrawal_id: int) -> str:
    address_hex = strip_0x(delegator_address)
    return "0x" + constants.GET_WITHDRAWAL_REQUEST_SELECTOR + eth_abi.encode(['uint64', 'address', 'uint8'], [int(validator_id), address_hex, withdrawal_id]).hex()
    
def get_proposer_val_id() -> str:
    return "0x" + constants.GET_PROPOSER_VAL_ID

def get_consensus_valset(index: Union[int, str]) -> str:
    return "0x" + constants.GET_CONSENSUS_VALSET_SELECTOR + eth_abi.encode(['uint64'], [index]).hex()

def get_snapshot_valset(index: Union[int, str]) -> str:
    return "0x" + constants.GET_SNAPSHOT_VALSET_SELECTOR + eth_abi.encode(['uint64'], [index]).hex()

def get_execution_valset(index: Union[int, str]) -> str:
    return "0x" + constants.GET_EXECUTION_VALSET_SELECTOR + eth_abi.encode(['uint64'], [index]).hex()

def get_delegations(delegator_address: str, index: int) -> str:
    address_hex = delegator_address[2:] if delegator_address.startswith("0x") else delegator_address
    return "0x" + constants.GET_DELEGATIONS_SELECTOR + eth_abi.encode(['address','uint64'], [address_hex, index]).hex()

def get_delegators(val_id: int, delegator_address: str) -> str:
    address_hex = delegator_address[2:] if delegator_address.startswith("0x") else delegator_address
    return "0x" + constants.GET_DELEGATORS_SELECTOR + eth_abi.encode(['uint64', 'address'], [val_id, address_hex]).hex()
