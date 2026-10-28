"""RFC 9380 receiver-key registration proof for the native staking contract.

The SWU mapping follows RFC 9380 Section 8.7 and Appendices E.1 and F.2:
https://www.rfc-editor.org/rfc/rfc9380
Only public hash inputs use Python integer arithmetic. Secret operations use
coincurve's libsecp256k1 implementation.
"""

import hashlib
import secrets
from typing import NamedTuple, Tuple, Union

from coincurve import PrivateKey, PublicKey


# SEC 2, version 2.0, Section 2.4.1: coordinate modulus p and base-point order n.
# https://www.secg.org/sec2-v2.pdf#page=13
FIELD_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SCALAR_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE_DST = b"BTX-DKG/receiver-key-registration/v1/secp256k1_XMD:SHA-256_SSWU_RO_"
CHALLENGE_DST = b"BTX-DKG/receiver-key-registration-proof/v1"
MAP_A = 0x3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533
MAP_B = 1771
Z = FIELD_ORDER - 11
SQRT_MINUS_Z = 0x31FDF302724013E57AD13FB38F842AFEEC184F00A74789DD286729C8303C4A59
# Section 5.3.1 permits reusing the hash state after the fixed zero prefix.
_XMD_PREFIX = hashlib.sha256(bytes(64))


class ReceiverKeyProof(NamedTuple):
    image: bytes
    challenge: bytes
    response: bytes


def _expand_xmd(message: bytes, dst: bytes, length: int) -> bytes:
    if not 0 < len(dst) <= 255 or length not in (48, 96):
        raise ValueError("Expected a nonempty DST of at most 255 bytes and 48/96 output bytes")
    dst_prime = dst + bytes([len(dst)])
    initial = _XMD_PREFIX.copy()
    initial.update(message + length.to_bytes(2, "big") + b"\x00" + dst_prime)
    b0 = initial.digest()
    previous = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    output = previous
    for index in range(2, (length + 31) // 32 + 1):
        mixed = bytes(a ^ b for a, b in zip(b0, previous))
        previous = hashlib.sha256(mixed + bytes([index]) + dst_prime).digest()
        output += previous
    return output[:length]


def _mul(x: int, y: int) -> int:
    return x * y % FIELD_ORDER


def _sqrt_ratio(numerator: int, denominator: int) -> Tuple[bool, int]:
    # Appendix F.2.1.2, for a nonzero denominator and p = 3 mod 4.
    uv = _mul(numerator, denominator)
    radicand = _mul(_mul(denominator, denominator), uv)
    root = _mul(pow(radicand, (FIELD_ORDER - 3) // 4, FIELD_ORDER), uv)
    square = _mul(_mul(root, root), denominator) == numerator
    return square, root if square else _mul(root, SQRT_MINUS_Z)


def _map_swu(u: int) -> Tuple[int, int, int]:
    # Appendix F.2, retaining x as a ratio through the isogeny.
    p = FIELD_ORDER
    zu2 = _mul(Z, _mul(u, u))
    total = (_mul(zu2, zu2) + zu2) % p
    xn = _mul(MAP_B, (total + 1) % p)
    xd = _mul(MAP_A, Z if total == 0 else -total % p)
    xd2 = _mul(xd, xd)
    xd3 = _mul(xd2, xd)
    curve_numerator = (_mul(xn, (_mul(xn, xn) + _mul(MAP_A, xd2)) % p)
                       + _mul(MAP_B, xd3)) % p
    square, root = _sqrt_ratio(curve_numerator, xd3)
    y = root if square else _mul(_mul(zu2, u), root)
    if (u & 1) != (y & 1):
        y = -y % p
    return xn if square else _mul(zu2, xn), xd, y


def _polynomial(x: int, denominator: int, coefficients: Tuple[int, ...]) -> int:
    # Return denominator^degree * f(x / denominator), without inversion.
    value = 0
    scale = 1
    for coefficient in coefficients:
        value = (value * x + coefficient * scale) % FIELD_ORDER
        scale = _mul(scale, denominator)
    return value


def _isogeny(x: int, denominator: int, y: int):
    # RFC 9380 Appendix E.1, highest-degree coefficient first.
    x_num = _polynomial(x, denominator, (
        0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C,
        0x534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262,
        0x7D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581,
        0x8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7,
    ))
    x_den = _polynomial(x, denominator, (
        1,
        0xEDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14,
        0xD35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B,
    ))
    y_num = _polynomial(x, denominator, (
        0x2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84,
        0x29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931,
        0xC75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3,
        0x4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C,
    ))
    y_den = _polynomial(x, denominator, (
        1,
        0x6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F,
        0x7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B,
    ))
    if x_den == 0 or y_den == 0:
        return None
    return x_num, _mul(denominator, x_den), _mul(y, y_num), y_den


def hash_to_secp256k1(message: bytes, dst: bytes = BASE_DST) -> PublicKey:
    """RFC 9380 secp256k1_XMD:SHA-256_SSWU_RO_, for public messages."""
    uniform = _expand_xmd(message, dst, 96)
    points = []
    for offset in (0, 48):
        u = int.from_bytes(uniform[offset:offset + 48], "big") % FIELD_ORDER
        point = _isogeny(*_map_swu(u))
        if point is not None:
            points.append(point)
    if not points:
        raise ValueError("Hash-to-curve produced the identity")
    # Normalize both points with one shared inversion (Appendix G.1).
    denominators = [_mul(point[1], point[3]) for point in points]
    reciprocal = pow(denominators[0] if len(points) == 1
                     else _mul(*denominators), FIELD_ORDER - 2, FIELD_ORDER)
    mapped = []
    for index, (xn, xd, yn, yd) in enumerate(points):
        inverse = reciprocal if len(points) == 1 else _mul(reciprocal, denominators[1 - index])
        mapped.append(PublicKey.from_point(_mul(_mul(xn, yd), inverse),
                                           _mul(_mul(yn, xd), inverse)))
    return mapped[0] if len(mapped) == 1 else PublicKey.combine_keys(mapped)


def _nonce() -> PrivateKey:
    while True:
        try:
            return PrivateKey(secrets.token_bytes(32))
        except ValueError:
            continue


def prove_receiver_key_registration(
    chain_id: int, validator_address: Union[str, bytes], secret: bytes
) -> Tuple[bytes, ReceiverKeyProof]:
    """Return the receiver public key and proof tuple (image, challenge, response)."""
    if type(chain_id) is not int or not 0 <= chain_id < 2**256:
        raise ValueError("Chain ID must fit in 32 bytes")
    if isinstance(validator_address, str):
        address = validator_address[2:] if validator_address.startswith("0x") else validator_address
        validator_address = bytes.fromhex(address)
    if not isinstance(validator_address, bytes) or len(validator_address) != 20:
        raise ValueError("Validator address must be 20 bytes")
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ValueError("Receiver private key must be 32 bytes")
    receiver = PrivateKey(secret)
    public_key = receiver.public_key.format()
    base = hash_to_secp256k1(chain_id.to_bytes(32, "big") + validator_address + public_key)
    image = base.multiply(receiver.secret).format()
    nonce = _nonce()
    a = nonce.public_key.format()
    b = base.multiply(nonce.secret).format()
    transcript = b"".join((base.format(), public_key, image, a, b))
    challenge = int.from_bytes(_expand_xmd(transcript, CHALLENGE_DST, 48), "big") % SCALAR_ORDER
    challenge_bytes = challenge.to_bytes(32, "big")
    response = nonce.secret
    if challenge:
        product = receiver.multiply(challenge_bytes)
        try:
            response = product.add(nonce.secret).secret
        except ValueError:
            # Both inputs are valid nonzero scalars; a failed sum is zero mod n.
            response = bytes(32)
    return public_key, ReceiverKeyProof(image, challenge_bytes, response)
