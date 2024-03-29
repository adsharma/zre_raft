#!/usr/bin/env python3


try:
    from zyre_pyzmq import Zyre as Pyre  # type: ignore
except ModuleNotFoundError:
    print("using Python native module")
    from pyre import Pyre

import argparse
import asyncio
import dbm
import json
import logging
import random
import sys
import threading
import uuid
from collections import defaultdict

import zmq
import zmq.asyncio
import zre_raft
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

try:
    from zre_raft.zre_signal import b64k, SignalState

    DISABLE_SIGNAL = False
except Exception as e:
    print("Encryption disabled", e)
    DISABLE_SIGNAL = True

try:
    from raft.boards.db_board import DBBoard
    from raft.servers.zre_server import ZREServer as Raft
    from raft.states.follower import Follower
    from raft.states.learner import Learner

    DISABLE_CONSENSUS = False
except Exception as e:
    print("Consensus disabled", e)
    DISABLE_CONSENSUS = True


exit_event = threading.Event()


class ZRENode:
    GROUP = "raft"

    def __init__(self, name, groups, board=None, learner=False):
        self.groups_joined = set(groups) if groups is not None else set()
        self.peers = {}
        self.directory = {}  # peer by name. Should use consensus to maintain
        self.blocked = set()  # set of peers from whom we don't what to hear
        self.signal = None
        self.create_node(name)
        if DISABLE_CONSENSUS:
            self.consensus = None
        else:
            opts = {}
            opts["stable_storage"] = dbm.open(f"/tmp/{name}-raft.db", "cs")
            if board == "db":
                opts["messageBoard"] = DBBoard(prefix=f"/tmp/{name}")
            role = Learner() if learner else Follower()
            self.consensus = Raft(ZRENode.GROUP, name, role, self.n, **opts)
        self.groups = defaultdict(list)
        self.queue = asyncio.Queue()
        self.ctx = zmq.asyncio.Context()
        self.pipe1, self.pipe2 = self.zcreate_pipe(self.ctx)
        self.session = PromptSession(f"{self.n.name()} {self.GROUP}: ")
        self.pending_messages = {}

        self.tasks = []
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
        for g in self.groups_joined:
            n.join(g)
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
        if cmd == "/shout":
            out = rest.split(" ", maxsplit=1)
            if len(out) == 2:
                group, rest = out
                self.n.shout(group, rest.encode("utf-8"))
            else:
                print("syntax: /group name message")
        elif cmd == "/set":
            out = rest.split(" ", maxsplit=1)
            if len(out) == 2:
                key, value = out
                return await self.consensus.set(key, value)
            else:
                print("syntax: /set key value")
        elif cmd == "/get":
            key = rest
            value = await self.consensus.get(key)
            if value is not None:
                print(value)
        elif cmd == "/block":
            try:
                peer = rest
                peer_uuid = uuid.UUID(rest)
                if peer_uuid not in self.peers.keys():
                    print(f"{peer} not known")
                    print(f"{self.peers.keys()}")
                self.blocked.add(peer)
            except Exception as e:
                print(e)
        elif cmd == "/unblock":
            try:
                peer = rest
                if peer not in self.blocked:
                    print(f"{peer} not currently blocked")
                self.blocked.remove(peer)
            except Exception as e:
                print(e)
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
                    task = await self.handle_outgoing_command(raw_message)
                    if task is not None:
                        self.tasks.append(task)
                else:
                    n.shouts(ZRENode.GROUP, message)
            else:
                cmds = n.recv()
                queue.put_nowait(cmds)
                queue._loop._write_to_self()
        n.stop()
        queue.put_nowait(None)

    def worker(self, pipe, queue):
        self.worker_loop = loop = asyncio.new_event_loop()
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
            except Exception:
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
        if str(peer) in self.blocked:
            logger.debug(f"dropping message from {peer}")
            return
        name = cmds.pop(0).decode("utf-8")
        group = cmds.pop(0).decode("utf-8")
        raw_message = cmds.pop(0)
        if raw_message and raw_message[0] == ord("/"):
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
        if str(peer) in self.blocked:
            logger.debug(f"dropping message from {peer}")
            return
        name = cmds.pop(0).decode("utf-8")
        raw_message = cmds.pop(0)
        if raw_message and raw_message[0] == ord("/"):
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
            task = self.consensus.add_neighbor(peer.hex)
            if task is not None:
                self.tasks.append(task)
        print(f"{name} {peer} joined {group}")
        logger.debug(f"Config: {self.peers}, {self.groups}")

    async def handle_leave(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0).decode("utf-8")
        group = cmds.pop(0).decode("utf-8")
        self.groups[group].remove(peer)
        if self.consensus:
            task = self.consensus.remove_neighbor(peer.hex)
            if task is not None:
                self.tasks.append(task)
        print(f"{name} {peer} left {group}")
        print(f"{peer} left {group}")

    async def handle_exit(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        _name = cmds.pop(0).decode("utf-8")  # noqa: unused
        self.peers.pop(peer, None)
        print(f"{peer} exit ")
        for g in self.groups:
            if peer in self.groups[g]:
                self.groups[g].remove(peer)
            if self.consensus:
                self.consensus.remove_neighbor(peer.hex)
        logger.debug(f"Config: {self.peers}, {self.groups}")

    async def networkstream(self, queue):
        loop = asyncio.get_event_loop()
        while True:
            item = await self.queue.get()
            if item is None:
                break
            cmds = item
            msg_type = cmds.pop(0)
            msg_type = msg_type.decode("utf-8")
            meth = getattr(self, f"handle_{msg_type.lower()}")
            loop.create_task(meth(cmds))


async def readline(session):
    while True:
        with patch_stdout():
            line = await session.prompt_async()
        yield bytes(line, "utf-8")


async def network_loop(event, args):
    thread = threading.current_thread()
    thread.loop = loop = asyncio.get_event_loop()
    thread.node = node = ZRENode(args.name, args.groups, args.board, args.learner)
    task = loop.create_task(node.networkstream(node.queue))
    event.set()
    await task


def network_worker(event: threading.Event, args):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(network_loop(event, args))


async def read_loop(network_thread):
    node = network_thread.node
    loop = network_thread.loop

    def wait_for_consensus():
        while node.tasks:
            task = node.tasks.pop()
            coro = None
            if isinstance(task, asyncio.Task):
                if task.done():
                    # TODO: simplify this chaining by potentially using another coroutine
                    res = task.result()
                    if isinstance(res, tuple):
                        (coro, expected_index, expected_id) = res
            else:
                (coro, expected_index, expected_id) = task
            if coro is None:
                continue
            _future = asyncio.run_coroutine_threadsafe(  # noqa: unused
                coro(expected_index, expected_id), loop
            )
            node.consensus._condition_event.wait(timeout=3)

    async for msg in readline(node.session):
        if msg:
            node.pipe1.send(msg)
        wait_for_consensus()


async def async_main(args):
    node_created_event = threading.Event()
    network_thread = threading.Thread(
        target=network_worker, args=[node_created_event, args]
    )
    network_thread.start()
    node_created_event.wait()
    await read_loop(network_thread)


def main():
    global logger
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", help="chat client name")
    parser.add_argument("-g", "--groups", action="append", help="which groups to join")
    parser.add_argument("-v", "--verbose", help="verbose logging")
    parser.add_argument("-b", "--board", default="db", help="type of message board")
    parser.add_argument("-l", "--learner", help="if I should be a learner or follower")

    args, rest = parser.parse_known_args()
    # Create a StreamHandler for debugging
    logger = logging.getLogger("raft")
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
    logger.propagate = False

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(async_main(args))
    except KeyboardInterrupt:
        exit_event.set()

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
