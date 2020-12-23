import base64

from collections import defaultdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES


def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode("utf-8").strip()


def b64k(public_key):
    # base64 encoding helper function
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(key_bytes).decode("utf-8").strip()


def hkdf(inp, length):
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


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b""):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


class SignalState:
    def __init__(self, logger):
        self.IK = X25519PrivateKey.generate()
        self.SPK = X25519PrivateKey.generate()
        self.OPK = X25519PrivateKey.generate()
        self.DHratchet = X25519PrivateKey.generate()
        self.peer_keys = defaultdict(dict)
        self.sessions = {}
        self.logger = logger

    def x3dh_receiver(self, other):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.SPK.exchange(other["IK"])
        EK = other["EK"]
        dh2 = self.IK.exchange(EK)
        dh3 = self.SPK.exchange(EK)
        dh4 = self.OPK.exchange(EK)
        # print("receiver: ", EK.public_bytes(), dh1, dh2, dh3, dh4)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = shared_key = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        peer = other["peer"]
        self.sessions[peer] = shared_key
        self.logger.info(f"Established session with: {peer}")
        self.logger.debug(f"Shared key: {shared_key}")

    def x3dh_sender(self, other):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.IK.exchange(other["SPK"])
        dh2 = self.EK.exchange(other["IK"])
        dh3 = self.EK.exchange(other["SPK"])
        dh4 = self.EK.exchange(other["OPK"])
        # print("sender: ", self.EK.public_key().public_bytes(), dh1, dh2, dh3, dh4)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.sk = shared_key = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        peer = other["peer"]
        self.sessions[peer] = shared_key
        self.logger.info(f"Established session with: {peer}")
        self.logger.debug(f"Shared key: {shared_key}")

    def establish_session(self, n, other, message):
        self.EK = EK = X25519PrivateKey.generate()
        self.peer_keys[other]["EK"] = EK.public_key()
        message = " ".join(["/ephemeral", b64k(EK.public_key())])
        n.whisper(other, message.encode("utf-8"))
        self._on_message_send(other)

    def _on_message_send(self, peer_id):
        if peer_id in self.sessions:
            return
        self.x3dh_sender(self.peer_keys[peer_id])
        self.init_ratchets()

    def _on_message_receive(self, peer_id):
        if peer_id in self.sessions:
            return
        self.x3dh_receiver(self.peer_keys[peer_id])
        self.init_ratchets()

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, other_public):
        # perform a DH ratchet rotation using Other User's public key
        dh_recv = self.DHratchet.exchange(other_public)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        # use Other User's public and our old private key
        # to get a new recv ratchet
        self.recv_ratchet = SymmRatchet(shared_recv)
        print("Recv ratchet seed:", b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Other User
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(other_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print("Send ratchet seed:", b64(shared_send))

    def send(self, other, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print("Sending ciphertext to Other User:", b64(cipher))
        # send ciphertext and current DH public key
        other.recv(cipher, self.DHratchet.public_key())

    def recv(self, cipher, other_public_key):
        # receive Other User's new public key and use it to perform a DH
        self.dh_ratchet(other_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print("Decrypted message:", msg)
