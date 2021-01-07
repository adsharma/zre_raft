import base64

from collections import defaultdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES
from enum import IntEnum
from serde import serialize, deserialize
from serde.msgpack import from_msgpack, to_msgpack
from dataclasses import dataclass
from typing import Optional


@deserialize
@serialize
@dataclass
class EncryptedMessage:
    cipher: str
    dh_public_key: str


class RatchetState(IntEnum):
    INIT = 0
    SENDING = 1
    RECEIVING = 2


class SymmRatchet:
    def __init__(self, key):
        self.state = key

    def next(self, inp=b""):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


@dataclass
class SessionState:
    state: RatchetState
    shared_key: bytes
    dh_ratchet: Optional[X25519PrivateKey]
    dh_public_key: Optional[X25519PublicKey]
    root_ratchet: Optional[SymmRatchet]
    send_ratchet: Optional[SymmRatchet]
    recv_ratchet: Optional[SymmRatchet]

    @classmethod
    def new(cls):
        """
        Generate a new default state
        """
        return SessionState(RatchetState.INIT, b"", None, None, None, None, None)


def b64(msg: bytes) -> str:
    # base64 encoding helper function
    return base64.encodebytes(msg).decode("utf-8").strip()


def b64k(public_key: X25519PublicKey) -> str:
    # base64 encoding helper function
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(key_bytes).decode("utf-8").strip()


def hkdf(inp: bytes, length: int) -> bytes:
    # use HKDF on an input to derive a key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"",
        info=b"",
        backend=default_backend(),
    )
    return hkdf.derive(inp)


def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)


def unpad(msg):
    # remove pkcs7 padding
    return msg[: -msg[-1]]


class SignalState:
    def __init__(self, logger):
        self.IK = X25519PrivateKey.generate()
        self.SPK = X25519PrivateKey.generate()
        self.OPK = X25519PrivateKey.generate()
        self.peer_keys = defaultdict(dict)
        self.sessions = defaultdict(lambda: SessionState.new())
        self.logger = logger

    def x3dh_receiver(self, other):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.SPK.exchange(other["IK"])
        EK = other["EK"]
        dh2 = self.IK.exchange(EK)
        dh3 = self.SPK.exchange(EK)
        dh4 = self.OPK.exchange(EK)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        shared_key = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        peer = other["peer"]
        self.sessions[peer].shared_key = shared_key
        self.logger.info(f"Established session with: {peer}")
        self.logger.debug(f"Shared key: {shared_key}")

    def x3dh_sender(self, other):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.IK.exchange(other["SPK"])
        dh2 = self.EK.exchange(other["IK"])
        dh3 = self.EK.exchange(other["SPK"])
        dh4 = self.EK.exchange(other["OPK"])
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        shared_key = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        peer = other["peer"]
        self.sessions[peer].shared_key = shared_key
        self.logger.info(f"Established session with: {peer}")
        self.logger.debug(f"Shared key: {shared_key}")

    def establish_session(self, n, other):
        self.EK = EK = X25519PrivateKey.generate()
        self.peer_keys[other]["EK"] = EK.public_key()
        message = " ".join(["/ephemeral", b64k(EK.public_key())])
        n.whisper(other, message.encode("utf-8"))
        self._on_message_send(other)

    def _on_message_send(self, peer_id):
        if peer_id in self.sessions:
            return
        self.x3dh_sender(self.peer_keys[peer_id])
        self.init_ratchets(peer_id, sender=True)

    def _on_new_session(self, n, peer_id, rest):
        self.peer_keys[peer_id]["EK"] = X25519PublicKey.from_public_bytes(
            base64.b64decode(rest)
        )
        if peer_id in self.sessions:
            return
        self.x3dh_receiver(self.peer_keys[peer_id])
        self.init_ratchets(peer_id, sender=False)
        self.sessions[peer_id].dh_ratchet = dh_ratchet = X25519PrivateKey.generate()
        dh_key = b64k(dh_ratchet.public_key())
        message = " ".join(["/dhkey", dh_key])
        n.whisper(peer_id, message.encode("utf-8"))

    def _on_peer_enter(self, peer_id, headers):
        for key in ["IK", "SPK", "OPK"]:
            self.peer_keys[peer_id][key] = X25519PublicKey.from_public_bytes(
                base64.b64decode(headers[key])
            )
        self.peer_keys[peer_id]["peer"] = peer_id

    def _on_dhkey(self, peer_id, dh_key):
        """Used only on session establishment. Subsequently it's
           sent via EncryptedMessage.
        """
        self.logger.debug(f"peer dhkey: {dh_key}")
        dh_public_key = X25519PublicKey.from_public_bytes(base64.b64decode(dh_key))
        self.sessions[peer_id].dh_public_key = dh_public_key
        self.dh_ratchet(peer_id, dh_public_key)
        self.sessions[peer_id].state = RatchetState.SENDING

    def init_ratchets(self, peer_id, sender: bool):
        # initialise the root chain with the shared key
        shared_key = self.sessions[peer_id].shared_key
        self.sessions[peer_id].root_ratchet = root_ratchet = SymmRatchet(shared_key)
        # initialise the sending and recving chains
        if sender:
            send_ratchet = SymmRatchet(root_ratchet.next()[0])
            recv_ratchet = SymmRatchet(root_ratchet.next()[0])
        else:
            recv_ratchet = SymmRatchet(root_ratchet.next()[0])
            send_ratchet = SymmRatchet(root_ratchet.next()[0])
        self.sessions[peer_id].send_ratchet = send_ratchet
        self.sessions[peer_id].recv_ratchet = recv_ratchet
        # Ignore sender here, just so that on recv we force a dh_ratchet
        self.sessions[peer_id].state = RatchetState.INIT
        self.logger.debug(
            f"init_ratchet: {peer_id} {b64(send_ratchet.state)} {b64(recv_ratchet.state)}"
        )

    def dh_ratchet(self, peer_id, peer_public):
        root_ratchet = self.sessions[peer_id].root_ratchet
        shared_recv = b""
        # perform a DH ratchet rotation using Other User's public key
        dh_ratchet = self.sessions[peer_id].dh_ratchet
        if dh_ratchet is not None:
            # First time we don't have a DH ratchet yet, so we do this only
            # on subsequent ratchets
            dh_recv = dh_ratchet.exchange(peer_public)
            shared_recv = root_ratchet.next(dh_recv)[0]
            # use Other User's public and our old private key
            # to get a new recv ratchet
            self.sessions[peer_id].recv_ratchet = SymmRatchet(shared_recv)
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Other User
        self.sessions[peer_id].dh_ratchet = dh_ratchet = X25519PrivateKey.generate()
        dh_send = dh_ratchet.exchange(peer_public)
        shared_send = root_ratchet.next(dh_send)[0]
        self.sessions[peer_id].send_ratchet = SymmRatchet(shared_send)
        self.logger.debug(
            f"dh_ratchet: {peer_id} {b64k(peer_public)} {b64(shared_send)} {b64(shared_recv)}"
        )

    def send(self, n, peer_id, msg):
        old_state = self.sessions[peer_id].state
        if old_state != RatchetState.SENDING:
            self.sessions[peer_id].state = RatchetState.SENDING
        send_ratchet = self.sessions[peer_id].send_ratchet
        key, iv = send_ratchet.next()
        self.logger.debug(f"send_ratchet: {peer_id} {b64(send_ratchet.state)}")
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        self.logger.debug(f"cipher: {cipher}")
        dh_ratchet = self.sessions[peer_id].dh_ratchet
        encrypted_message = EncryptedMessage(
            b64(cipher), b64k(dh_ratchet.public_key())
        )
        n.whisper(peer_id, to_msgpack(encrypted_message))

    def recv(self, peer_id, raw_message):
        encrypted_message = from_msgpack(EncryptedMessage, raw_message)
        peer_public_key = X25519PublicKey.from_public_bytes(
            base64.b64decode(encrypted_message.dh_public_key)
        )
        old_state = self.sessions[peer_id].state
        if old_state != RatchetState.RECEIVING:
            self.dh_ratchet(peer_id, peer_public_key)
            self.sessions[peer_id].state = RatchetState.RECEIVING
        recv_ratchet = self.sessions[peer_id].recv_ratchet
        key, iv = recv_ratchet.next()
        self.logger.debug(f"recv_ratchet: {peer_id} {b64(recv_ratchet.state)}")
        cipher = base64.b64decode(encrypted_message.cipher)
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        return msg
