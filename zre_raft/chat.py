#!/usr/bin/env python3


try:
    from zyre_pyzmq import Zyre as Pyre
except Exception as e:
    print("using Python native module")
    from pyre import Pyre

from aiostream.stream import ziplatest
from aiostream.aiter_utils import aitercontext
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

import argparse
import asyncio
import base64
import json
import logging
import random
import sys
import threading
import uuid

import zmq
import zmq.asyncio
import zre_raft
from zre_signal import b64k, SignalState


exit_event = threading.Event()


class ZRENode:
    GROUP = "raft"

    def __init__(self, name):
        self.peers = {}
        self.directory = {}  # peer by name. Should use consensus to maintain
        self.create_node(name)
        self.groups = defaultdict(list)
        self.queue = asyncio.Queue()
        self.ctx = zmq.asyncio.Context()
        self.pipe1, self.pipe2 = self.zcreate_pipe(self.ctx)
        self.session = PromptSession(f"{self.n.name()} {self.GROUP}: ")

        self.threads = []
        t = threading.Thread(target=self.worker, args=[self.pipe2, self.queue])
        self.threads.append(t)
        t.start()

    def create_signal_headers(self):
        n = self.n
        n.set_header("IK", b64k(self.signal.IK.public_key()))
        # TODO: Generate many pre keys and delete the one-time keys after use
        n.set_header("SPK", b64k(self.signal.SPK.public_key()))
        n.set_header("OPK", b64k(self.signal.OPK.public_key()))

    def create_node(self, name: str):
        self.n = n = Pyre(name)
        self.n.signal = SignalState()
        # Convenience members self.signal/peer_keys
        self.signal = self.n.signal
        self.peer_keys = self.signal.peer_keys
        n.set_header("Version", str(zre_raft.__version__))
        self.create_signal_headers()
        n.join(ZRENode.GROUP)
        n.start()
        return n

    async def handle_command(self, command, peer=None):
        cmd, rest = command.split(" ", maxsplit=1)
        print("command: ", cmd, rest, peer)
        if cmd == "/whisper":
            out = rest.split(" ", maxsplit=1)
            if len(out) == 2:
                target, rest = out
                if target in self.directory:
                    target = self.directory[target]
                self.n.whisper(target, rest.encode("utf-8"))
            else:
                print("syntax: /whisper peer message")
        elif cmd == "/encrypt":
            out = rest.split(" ", maxsplit=1)
            if len(out) == 2:
                target, rest = out
                if target in self.directory:
                    target = self.directory[target]
                self.n.signal.establish_session(self.n, target, rest.encode("utf-8"))
            else:
                print("syntax: /encrypt peer message")
        elif cmd == "/ephemeral":
            if rest:
                self.peer_keys[peer]["EK"] = X25519PublicKey.from_public_bytes(
                    base64.b64decode(rest)
                )
                self.signal._on_message_receive(peer)
            else:
                print("syntax: /ephemeral key")

    async def chat_task(self, pipe, queue):
        n = self.n
        poller = zmq.Poller()
        poller.register(pipe, zmq.POLLIN)
        poller.register(n.socket(), zmq.POLLIN)
        while not exit_event.is_set():
            items = dict(poller.poll(100))
            if not len(items):
                continue
            if pipe in items and items[pipe] == zmq.POLLIN:
                message = await pipe.recv()
                message = message.decode("utf-8")
                if message and message[0] == "/":
                    # special commands
                    await self.handle_command(message)
                else:
                    n.shouts(ZRENode.GROUP, message)
            else:
                cmds = n.recv()
                queue.put_nowait(cmds)
                queue._loop._write_to_self()
        n.stop()
        queue.put_nowait(None)

    def worker(self, pipe, queue):
        global worker_loop
        n = self.n
        worker_loop = loop = asyncio.new_event_loop()
        task = loop.create_task(self.chat_task(pipe, queue))
        loop.run_until_complete(task)

    @staticmethod
    def zcreate_pipe(ctx, hwm=1000):
        backend = ctx.socket(zmq.PAIR)
        frontend = ctx.socket(zmq.PAIR)
        backend.set_hwm(hwm)
        frontend.set_hwm(hwm)
        # close immediately on shutdown
        backend.setsockopt(zmq.LINGER, 0)
        frontend.setsockopt(zmq.LINGER, 0)

        endpoint = "inproc://zactor-%04x-%04x\n" % (
            random.randint(0, 0x10000),
            random.randint(0, 0x10000),
        )
        while True:
            try:
                frontend.bind(endpoint)
            except:
                endpoint = "inproc://zactor-%04x-%04x\n" % (
                    random.randint(0, 0x10000),
                    random.randint(0, 0x10000),
                )
            else:
                break
        backend.connect(endpoint)
        return (frontend, backend)

    async def handle_shout(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        group = cmds.pop(0).decode("utf-8")
        msg = cmds.pop(0).decode("utf-8")
        print(f"{name} {group}: {msg}")

    async def handle_whisper(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        message = cmds.pop(0).decode("utf-8")
        if message and message[0] == "/":
            # special commands
            await self.handle_command(message, peer)
        else:
            print(f"{name}: {message}")

    async def _on_enter(self, peer_id):
        peer = self.peers[peer_id]
        headers = peer[2]
        print(headers)
        for key in ["IK", "SPK", "OPK"]:
            self.peer_keys[peer_id][key] = X25519PublicKey.from_public_bytes(
                base64.b64decode(headers[key])
            )
        self.peer_keys[peer_id]["peer"] = peer_id

    async def handle_enter(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        headers = json.loads(cmds.pop(0).decode("utf-8"))
        logger.debug(headers)
        self.peers[peer] = [name, cmds, headers]
        self.directory[name] = peer
        print(f"{name} {peer} entered")
        await self._on_enter(peer)

    async def handle_join(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        group = cmds.pop(0).decode("utf-8")
        self.groups[group].append(peer)
        print(f"{name} {peer} joined {group}")
        print(self.peers, self.groups)

    async def handle_leave(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        group = cmds.pop(0).decode("utf-8")
        self.groups[group].remove(peer)
        print(f"{peer} left {group}")

    async def handle_exit(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        self.peers.pop(peer, None)
        print(f"{peer} exit ")
        for g in self.groups:
            self.groups[g].remove(peer)
        print(self.peers, self.groups)

    async def networkstream(self, queue):
        seq = 0
        while True:
            item = await self.queue.get()
            if item is None:
                break
            cmds = item
            msg_type = cmds.pop(0)
            msg_type = msg_type.decode("utf-8")
            meth = getattr(self, f"handle_{msg_type.lower()}")
            await meth(cmds)
            yield (seq, item)
            seq += 1


async def readline(session):
    seq = 0
    while True:
        with patch_stdout():
            line = await session.prompt_async()
        yield (seq, bytes(line, "utf-8"))
        seq += 1


async def async_main(pipe, node):
    queue = node.queue

    last_seq = -1
    merged = ziplatest(readline(node.session), node.networkstream(queue))
    async with aitercontext(merged) as safe_merged:
        async for out in safe_merged:
            msg, nmsg = out
            if msg:
                seq, msg = msg
                if seq != last_seq:
                    pipe.send(msg)
                    last_seq = seq


def main():
    global logger
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", help="chat client name")
    args = parser.parse_args()
    # Create a StreamHandler for debugging
    logger = logging.getLogger("raft")
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
    logger.propagate = False

    node = ZRENode(args.name)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(async_main(node.pipe1, node))
    except KeyboardInterrupt:
        exit_event.set()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
