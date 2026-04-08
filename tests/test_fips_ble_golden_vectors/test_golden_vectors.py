import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import pytest


PROTOCOL_NAME_IK = b"Noise_IK_secp256k1_ChaChaPoly_SHA256"
PROTOCOL_NAME_XK = b"Noise_XK_secp256k1_ChaChaPoly_SHA256"
EMPTY = b""
SECP256K1 = ec.SECP256K1()


def _vector_id(vector: dict) -> str:
    return vector["name"]


def _load_vectors() -> list[dict]:
    json_path = os.path.join(os.path.dirname(__file__), "golden_vectors.json")
    with open(json_path, encoding="utf-8") as fh:
        return json.load(fh)["vectors"]


VECTORS = _load_vectors()
VECTORS_BY_TYPE: dict[str, list[dict]] = {}
for _vector in VECTORS:
    VECTORS_BY_TYPE.setdefault(_vector["type"], []).append(_vector)


def _hx(value: str) -> bytes:
    return bytes.fromhex(value)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha256")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac_sha256(prk, block + info + bytes((counter,)))
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def hkdf(salt: bytes, ikm: bytes, length: int = 64) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), EMPTY, length)


def mix_key(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    okm = hkdf(ck, ikm, 64)
    return okm[:32], okm[32:64]


def split(ck: bytes) -> tuple[bytes, bytes]:
    okm = hkdf_expand(hkdf_extract(ck, EMPTY), EMPTY, 64)
    return okm[:32], okm[32:64]


def _private_key(secret_key: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(secret_key, "big"), SECP256K1)


def _public_key(pub_key: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(SECP256K1, pub_key)


def x_only_ecdh(secret_key: bytes, pub_key: bytes) -> bytes:
    shared = _private_key(secret_key).exchange(ec.ECDH(), _public_key(pub_key))
    return sha256(shared)


def ecdh_pubkey(secret_key: bytes) -> bytes:
    return _private_key(secret_key).public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )


def parity_normalize(pubkey: bytes) -> bytes:
    return b"\x02" + pubkey[1:]


def make_nonce(n: int) -> bytes:
    return b"\x00\x00\x00\x00" + n.to_bytes(8, "little")


def aead_encrypt(key: bytes, nonce_ctr: int, aad: bytes, plaintext: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(make_nonce(nonce_ctr), plaintext, aad)


def aead_decrypt(key: bytes, nonce_ctr: int, aad: bytes, ciphertext: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(make_nonce(nonce_ctr), ciphertext, aad)


def _mix_hash(current_hash: bytes, data: bytes) -> bytes:
    return sha256(current_hash + data)


class NoiseIKInitiator:
    def __init__(self, eph_secret: bytes, s_secret: bytes, rs_pub: bytes) -> None:
        self.eph_secret = eph_secret
        self.s_secret = s_secret
        self.rs_pub = rs_pub
        self.eph_pub = ecdh_pubkey(eph_secret)
        self.s_pub = ecdh_pubkey(s_secret)
        self.ck = sha256(PROTOCOL_NAME_IK)
        self.h = self.ck
        self.h = _mix_hash(self.h, parity_normalize(rs_pub))
        self.k = EMPTY
        self.n = 0
        self.re_pub = b""

    def write_message1(self, my_static_pub: bytes, epoch: bytes) -> bytes:
        assert my_static_pub == self.s_pub
        self.h = _mix_hash(self.h, self.eph_pub)
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.eph_secret, self.rs_pub))
        self.n = 0
        enc_s = aead_encrypt(self.k, self.n, EMPTY, my_static_pub)
        self.n += 1
        self.h = _mix_hash(self.h, enc_s)
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.s_secret, self.rs_pub))
        self.n = 0
        enc_epoch = aead_encrypt(self.k, self.n, EMPTY, epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return self.eph_pub + enc_s + enc_epoch

    def read_message2(self, data: bytes) -> bytes:
        self.re_pub = data[:33]
        enc_epoch = data[33:]
        self.h = _mix_hash(self.h, self.re_pub)
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.eph_secret, self.re_pub))
        self.n = 0
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.eph_secret, self.rs_pub))
        self.n = 0
        epoch = aead_decrypt(self.k, self.n, EMPTY, enc_epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return epoch

    def finalize(self) -> tuple[bytes, bytes]:
        return split(self.ck)


class NoiseIKResponder:
    def __init__(self, eph_secret: bytes, s_secret: bytes) -> None:
        self.eph_secret = eph_secret
        self.s_secret = s_secret
        self.eph_pub = ecdh_pubkey(eph_secret)
        self.s_pub = ecdh_pubkey(s_secret)
        self.ck = sha256(PROTOCOL_NAME_IK)
        self.h = self.ck
        self.h = _mix_hash(self.h, parity_normalize(self.s_pub))
        self.k = EMPTY
        self.n = 0
        self.received_initiator_ephemeral_pub = b""
        self.received_initiator_static_pub = b""

    def read_message1(self, data: bytes) -> tuple[bytes, bytes]:
        self.received_initiator_ephemeral_pub = data[:33]
        enc_s = data[33:82]
        enc_epoch = data[82:]
        self.h = _mix_hash(self.h, self.received_initiator_ephemeral_pub)
        self.ck, self.k = mix_key(
            self.ck,
            x_only_ecdh(self.s_secret, self.received_initiator_ephemeral_pub),
        )
        self.n = 0
        initiator_static_pub = aead_decrypt(self.k, self.n, EMPTY, enc_s)
        self.n += 1
        self.h = _mix_hash(self.h, enc_s)
        self.received_initiator_static_pub = initiator_static_pub
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.s_secret, initiator_static_pub))
        self.n = 0
        epoch = aead_decrypt(self.k, self.n, EMPTY, enc_epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return initiator_static_pub, epoch

    def write_message2(self, epoch: bytes) -> bytes:
        self.h = _mix_hash(self.h, self.eph_pub)
        self.ck, self.k = mix_key(
            self.ck,
            x_only_ecdh(self.eph_secret, self.received_initiator_ephemeral_pub),
        )
        self.n = 0
        self.ck, self.k = mix_key(
            self.ck,
            x_only_ecdh(self.s_secret, self.received_initiator_ephemeral_pub),
        )
        self.n = 0
        enc_epoch = aead_encrypt(self.k, self.n, EMPTY, epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return self.eph_pub + enc_epoch

    def finalize(self) -> tuple[bytes, bytes]:
        recv_key, send_key = split(self.ck)
        return send_key, recv_key


class NoiseXKInitiator:
    def __init__(self, eph_secret: bytes, s_secret: bytes, rs_pub: bytes) -> None:
        self.eph_secret = eph_secret
        self.s_secret = s_secret
        self.rs_pub = rs_pub
        self.eph_pub = ecdh_pubkey(eph_secret)
        self.s_pub = ecdh_pubkey(s_secret)
        self.ck = sha256(PROTOCOL_NAME_XK)
        self.h = self.ck
        self.h = _mix_hash(self.h, parity_normalize(rs_pub))
        self.k = EMPTY
        self.n = 0
        self.re_pub = b""

    def write_message1(self) -> bytes:
        self.h = _mix_hash(self.h, self.eph_pub)
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.eph_secret, self.rs_pub))
        self.n = 0
        return self.eph_pub

    def read_message2(self, data: bytes) -> bytes:
        self.re_pub = data[:33]
        enc_epoch = data[33:]
        self.h = _mix_hash(self.h, self.re_pub)
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.eph_secret, self.re_pub))
        self.n = 0
        epoch = aead_decrypt(self.k, self.n, EMPTY, enc_epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return epoch

    def write_message3(self, my_static_pub: bytes, epoch: bytes) -> bytes:
        assert my_static_pub == self.s_pub
        enc_s = aead_encrypt(self.k, self.n, EMPTY, my_static_pub)
        self.n += 1
        self.h = _mix_hash(self.h, enc_s)
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.s_secret, self.re_pub))
        self.n = 0
        enc_epoch = aead_encrypt(self.k, self.n, EMPTY, epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return enc_s + enc_epoch

    def finalize(self) -> tuple[bytes, bytes]:
        return split(self.ck)


class NoiseXKResponder:
    def __init__(self, eph_secret: bytes, s_secret: bytes) -> None:
        self.eph_secret = eph_secret
        self.s_secret = s_secret
        self.eph_pub = ecdh_pubkey(eph_secret)
        self.s_pub = ecdh_pubkey(s_secret)
        self.ck = sha256(PROTOCOL_NAME_XK)
        self.h = self.ck
        self.h = _mix_hash(self.h, parity_normalize(self.s_pub))
        self.k = EMPTY
        self.n = 0
        self.received_initiator_ephemeral_pub = b""
        self.received_initiator_static_pub = b""

    def read_message1(self, data: bytes) -> None:
        self.received_initiator_ephemeral_pub = data
        self.h = _mix_hash(self.h, data)
        self.ck, self.k = mix_key(
            self.ck,
            x_only_ecdh(self.s_secret, self.received_initiator_ephemeral_pub),
        )
        self.n = 0

    def write_message2(self, epoch: bytes) -> bytes:
        self.h = _mix_hash(self.h, self.eph_pub)
        self.ck, self.k = mix_key(
            self.ck,
            x_only_ecdh(self.eph_secret, self.received_initiator_ephemeral_pub),
        )
        self.n = 0
        enc_epoch = aead_encrypt(self.k, self.n, EMPTY, epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return self.eph_pub + enc_epoch

    def read_message3(self, data: bytes) -> tuple[bytes, bytes]:
        enc_s = data[:49]
        enc_epoch = data[49:]
        initiator_static_pub = aead_decrypt(self.k, self.n, EMPTY, enc_s)
        self.n += 1
        self.h = _mix_hash(self.h, enc_s)
        self.received_initiator_static_pub = initiator_static_pub
        self.ck, self.k = mix_key(self.ck, x_only_ecdh(self.eph_secret, initiator_static_pub))
        self.n = 0
        epoch = aead_decrypt(self.k, self.n, EMPTY, enc_epoch)
        self.n += 1
        self.h = _mix_hash(self.h, enc_epoch)
        return initiator_static_pub, epoch

    def finalize(self) -> tuple[bytes, bytes]:
        recv_key, send_key = split(self.ck)
        return send_key, recv_key


def _transport_roundtrip(key: bytes, nonce: int, aad: bytes, plaintext: bytes) -> bytes:
    ciphertext = aead_encrypt(key, nonce, aad, plaintext)
    assert aead_decrypt(key, nonce, aad, ciphertext) == plaintext
    return ciphertext


def test_all_vector_types_are_covered() -> None:
    assert set(VECTORS_BY_TYPE) == {
        "aead",
        "ecdh",
        "hkdf",
        "ik_handshake",
        "mix_key",
        "pubkey",
        "split",
        "transport",
        "xk_handshake",
    }


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["pubkey"], ids=_vector_id)
def test_pubkey_vectors(vector: dict) -> None:
    assert ecdh_pubkey(_hx(vector["secret_hex"])) == _hx(vector["pubkey_hex"])


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["ecdh"], ids=_vector_id)
def test_ecdh_vectors(vector: dict) -> None:
    assert x_only_ecdh(
        _hx(vector["initiator_secret_hex"]),
        _hx(vector["responder_pubkey_hex"]),
    ) == _hx(vector["shared_secret_hex"])


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["hkdf"], ids=_vector_id)
def test_hkdf_vectors(vector: dict) -> None:
    assert hkdf(_hx(vector["salt_hex"]), _hx(vector["ikm_hex"]), 64) == _hx(vector["output_hex"])


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["aead"], ids=_vector_id)
def test_aead_vectors(vector: dict) -> None:
    key = _hx(vector["key_hex"])
    aad = _hx(vector["aad_hex"])
    plaintext = _hx(vector["plaintext_hex"])
    expected = _hx(vector["ciphertext_hex"])
    assert aead_encrypt(key, vector["nonce"], aad, plaintext) == expected
    assert aead_decrypt(key, vector["nonce"], aad, expected) == plaintext


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["mix_key"], ids=_vector_id)
def test_mix_key_vectors(vector: dict) -> None:
    assert mix_key(_hx(vector["chaining_key_hex"]), _hx(vector["dh_output_hex"])) == (
        _hx(vector["new_chaining_key_hex"]),
        _hx(vector["new_key_hex"]),
    )


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["split"], ids=_vector_id)
def test_split_vectors(vector: dict) -> None:
    assert split(_hx(vector["chaining_key_hex"])) == (_hx(vector["k1_hex"]), _hx(vector["k2_hex"]))


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["ik_handshake"], ids=_vector_id)
def test_ik_handshake_vectors(vector: dict) -> None:
    initiator = NoiseIKInitiator(
        _hx(vector["initiator_ephemeral_secret_hex"]),
        _hx(vector["initiator_static_secret_hex"]),
        _hx(vector["responder_static_pubkey_hex"]),
    )
    responder = NoiseIKResponder(
        _hx(vector["responder_ephemeral_secret_hex"]),
        _hx(vector["responder_static_secret_hex"]),
    )

    msg1 = initiator.write_message1(
        _hx(vector["initiator_static_pubkey_hex"]),
        _hx(vector["initiator_epoch_hex"]),
    )
    assert msg1 == _hx(vector["msg1_hex"])

    initiator_pub, responder_seen_epoch = responder.read_message1(msg1)
    assert initiator_pub == _hx(vector["initiator_static_pubkey_hex"])
    assert responder_seen_epoch == _hx(vector["initiator_epoch_hex"])

    msg2 = responder.write_message2(_hx(vector["responder_epoch_hex"]))
    assert msg2 == _hx(vector["msg2_hex"])

    initiator_seen_epoch = initiator.read_message2(msg2)
    assert initiator_seen_epoch == _hx(vector["responder_epoch_hex"])

    initiator_send_key, initiator_recv_key = initiator.finalize()
    responder_send_key, responder_recv_key = responder.finalize()

    assert initiator.h == _hx(vector["handshake_hash_hex"])
    assert responder.h == _hx(vector["handshake_hash_hex"])
    assert initiator_send_key == _hx(vector["initiator_transport_send_key_hex"])
    assert initiator_recv_key == _hx(vector["initiator_transport_recv_key_hex"])
    assert responder_send_key == _hx(vector["responder_transport_send_key_hex"])
    assert responder_recv_key == _hx(vector["responder_transport_recv_key_hex"])


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["xk_handshake"], ids=_vector_id)
def test_xk_handshake_vectors(vector: dict) -> None:
    initiator = NoiseXKInitiator(
        _hx(vector["initiator_ephemeral_secret_hex"]),
        _hx(vector["initiator_static_secret_hex"]),
        _hx(vector["responder_static_pubkey_hex"]),
    )
    responder = NoiseXKResponder(
        _hx(vector["responder_ephemeral_secret_hex"]),
        _hx(vector["responder_static_secret_hex"]),
    )

    msg1 = initiator.write_message1()
    assert msg1 == _hx(vector["msg1_hex"])

    responder.read_message1(msg1)
    msg2 = responder.write_message2(_hx(vector["responder_epoch_hex"]))
    assert msg2 == _hx(vector["msg2_hex"])

    initiator_seen_epoch = initiator.read_message2(msg2)
    assert initiator_seen_epoch == _hx(vector["responder_epoch_hex"])

    msg3 = initiator.write_message3(
        _hx(vector["initiator_static_pubkey_hex"]),
        _hx(vector["initiator_epoch_hex"]),
    )
    assert msg3 == _hx(vector["msg3_hex"])

    initiator_pub, responder_seen_epoch = responder.read_message3(msg3)
    assert initiator_pub == _hx(vector["initiator_static_pubkey_hex"])
    assert responder_seen_epoch == _hx(vector["initiator_epoch_hex"])

    initiator_send_key, initiator_recv_key = initiator.finalize()
    responder_send_key, responder_recv_key = responder.finalize()

    assert initiator.h == _hx(vector["handshake_hash_hex"])
    assert responder.h == _hx(vector["handshake_hash_hex"])
    assert initiator_send_key == _hx(vector["initiator_transport_send_key_hex"])
    assert initiator_recv_key == _hx(vector["initiator_transport_recv_key_hex"])
    assert responder_send_key == _hx(vector["responder_transport_send_key_hex"])
    assert responder_recv_key == _hx(vector["responder_transport_recv_key_hex"])


@pytest.mark.parametrize("vector", VECTORS_BY_TYPE["transport"], ids=_vector_id)
def test_transport_vectors(vector: dict) -> None:
    initiator_send_key = _hx(vector["initiator_transport_send_key_hex"])
    initiator_recv_key = _hx(vector["initiator_transport_recv_key_hex"])
    responder_send_key = _hx(vector["responder_transport_send_key_hex"])
    responder_recv_key = _hx(vector["responder_transport_recv_key_hex"])

    for frame in vector["frames"]:
        aad = _hx(frame["aad_hex"])
        plaintext = _hx(frame["plaintext_hex"])
        expected = _hx(frame["ciphertext_hex"])

        if frame["direction"] == "initiator_to_responder":
            assert _transport_roundtrip(initiator_send_key, frame["nonce"], aad, plaintext) == expected
            assert aead_decrypt(responder_recv_key, frame["nonce"], aad, expected) == plaintext
        else:
            assert _transport_roundtrip(responder_send_key, frame["nonce"], aad, plaintext) == expected
            assert aead_decrypt(initiator_recv_key, frame["nonce"], aad, expected) == plaintext
