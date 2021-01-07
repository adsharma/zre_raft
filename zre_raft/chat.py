#!/usr/bin/env python3


try:
    from zyre_pyzmq import Zyre as Pyre  # type: ignore
except Exception as e:
    print("using Python native module")
    from pyre import Pyre

from aiostream.stream import ziplatest
from aiostream.aiter_utils import aitercontext
from collections import defaultdict
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

from simpleRaft.servers.zre_server import ZREServer as Raft
from simpleRaft.states.candidate import Candidate
from simpleRaft.states.leader import Leader
from simpleRaft.states.follower import Follower

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

try:
    from zre_raft.zre_signal import b64k, SignalState

    DISABLE_SIGNAL = False
except Exception as e:
    print("Encryption disabled", e)
    DISABLE_SIGNAL = True


exit_event = threading.Event()


class ZRENode:
    GROUP = "raft"

    def __init__(self, name):
        self.peers = {}
        self.directory = {}  # peer by name. Should use consensus to maintain
        self.signal = None
        self.create_node(name)
        role = random.choice([Follower, Follower, Candidate])
        self.consensus = Raft(name, role(), self.n)
        self.groups = defaultdict(list)
        self.queue = asyncio.Queue()
        self.ctx = zmq.asyncio.Context()
        self.pipe1, self.pipe2 = self.zcreate_pipe(self.ctx)
        self.session = PromptSession(f"{self.n.name()} {self.GROUP}: ")
        self.pending_messages = {}

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
        n.set_header("Version", str(zre_raft.__version__))
        if not DISABLE_SIGNAL:
            self.n.signal = SignalState(logger)
            # Convenience members self.signal/peer_keys
            self.signal = self.n.signal
            self.peer_keys = self.signal.peer_keys
            self.create_signal_headers()
        n.join(ZRENode.GROUP)
        n.start()
        return n

    async def handle_outgoing_command(self, raw_command, peer=None):
        command = raw_command.decode("utf-8")
        logger.debug(f"{peer}: {command}")
        split_command = command.split(" ", maxsplit=1)
        if len(split_command) == 2:
            cmd, rest = split_command
        else:
            cmd = split_command[0]
            rest = None
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
            if DISABLE_SIGNAL:
                print("Encryption disabled. Can't encrypt")
                return
            out = rest.split(" ", maxsplit=1)
            if len(out) == 2:
                target, rest = out
                if target in self.directory:
                    target = self.directory[target]
                if target not in self.n.signal.sessions:
                    self.n.signal.establish_session(self.n, target)
                    self.pending_messages[target] = rest
                else:
                    self.n.signal.send(self.n, target, rest.encode("utf-8"))
            else:
                print("syntax: /encrypt peer message")
        elif cmd == "/raft":
            prefix_len = len("/raft ")
            if self.consensus:
                self.consensus.send_message(raw_command[prefix_len:])
        elif cmd == "/status":
            print(f"{self.n.uuid()}")
            print(f"consensus: {self.consensus}")
        else:
            raise Exception(f"unknown cmd: {command}")

    async def handle_incoming_command(self, raw_command, peer=None):
        # we handle this in a special way since the raw bytes
        # can not always be decoded as utf-8
        prefix_len = len("/raft ")
        if raw_command[:prefix_len] == b"/raft ":
            if self.consensus:
                await self.consensus.receive_message(raw_command[prefix_len:])
            return
        try:
            command = raw_command.decode("utf-8")
        except UnicodeDecodeError:
            command = None
        logger.debug(f"{peer}: {command}")
        cmd, rest = command.split(" ", maxsplit=1)
        if cmd == "/ephemeral":
            if rest and self.signal:
                self.signal._on_new_session(self.n, peer, rest)
            else:
                print("syntax: /ephemeral key")
        elif cmd == "/dhkey":
            if rest and self.signal:
                self.signal._on_dhkey(peer, rest)
                if peer in self.pending_messages:
                    message = self.pending_messages.pop(peer)
                    self.n.signal.send(self.n, peer, message.encode("utf-8"))
            else:
                print("syntax: /dhkey key")
        else:
            raise Exception(f"unknown cmd: {command}")

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
                raw_message = await pipe.recv()
                message = raw_message.decode("utf-8")
                if message and message[0] == "/":
                    # special commands
                    await self.handle_outgoing_command(raw_message)
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
        raw_message = cmds.pop(0)
        if raw_message and raw_message[0] == ord('/'):
            # special commands
            await self.handle_incoming_command(raw_message, peer)
        else:
            try:
                message = raw_message.decode("utf-8")
            except UnicodeDecodeError:
                message = None

            print(f"{name} {group}: {message}")

    async def handle_whisper(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        raw_message = cmds.pop(0)
        if raw_message and raw_message[0] == ord('/'):
            # special commands
            await self.handle_incoming_command(raw_message, peer)
        else:
            if self.signal and peer in self.signal.sessions:
                message = self.signal.recv(peer, raw_message).decode("utf-8")
            else:
                try:
                    message = raw_message.decode("utf-8")
                except UnicodeDecodeError:
                    message = None

            print(f"{name}: {message}")

    async def _on_enter(self, peer_id):
        peer = self.peers[peer_id]
        headers = peer[2]
        logger.debug(headers)
        if self.signal:
            self.signal._on_peer_enter(peer_id, headers)

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
        if self.consensus:
            self.consensus.add_neighbor(peer)
        print(f"{name} {peer} joined {group}")
        logger.debug(f"Config: {self.peers}, {self.groups}")

    async def handle_leave(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        group = cmds.pop(0).decode("utf-8")
        self.groups[group].remove(peer)
        if self.consensus:
            self.consensus.remove_neighbor(peer)
        print(f"{name} {peer} left {group}")
        print(f"{peer} left {group}")

    async def handle_exit(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        self.peers.pop(peer, None)
        print(f"{peer} exit ")
        for g in self.groups:
            self.groups[g].remove(peer)
            if self.consensus:
                self.consensus.remove_neighbor(peer)
        logger.debug(f"Config: {self.peers}, {self.groups}")

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
    parser.add_argument("-v", "--verbose", help="verbose logging")
    args = parser.parse_args()
    # Create a StreamHandler for debugging
    logger = logging.getLogger("raft")
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
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
