#!/usr/bin/env python3


try:
    from zyre_pyzmq import Zyre as Pyre
except Exception as e:
    print("using Python native module")
    from pyre import Pyre

from aiostream.stream import ziplatest
from aiostream.aiter_utils import aitercontext
from collections import defaultdict
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession

import argparse
import asyncio
import json
import logging
import random
import sys
import threading
import uuid

import zmq
import zmq.asyncio
import zre_raft


exit_event = threading.Event()


class ZRENode:
    GROUP = "raft"

    def __init__(self, name):
        self.n = self.create_node(name)
        self.peers = {}
        self.groups = defaultdict(list)
        self.queue = asyncio.Queue()
        self.ctx = zmq.asyncio.Context()
        self.pipe1, self.pipe2 = self.zcreate_pipe(self.ctx)
        self.session = PromptSession(f"{self.n.name()} {self.GROUP}: ")

        self.threads = []
        t = threading.Thread(target=self.worker, args=[self.n, self.pipe2, self.queue])
        self.threads.append(t)
        t.start()

    @staticmethod
    def create_node(name: str):
        n = Pyre(name)
        n.set_header("Version", str(zre_raft.__version__))
        n.join(ZRENode.GROUP)
        n.start()
        return n

    @staticmethod
    async def chat_task(n, pipe, queue):
        poller = zmq.Poller()
        poller.register(pipe, zmq.POLLIN)
        poller.register(n.socket(), zmq.POLLIN)
        while not exit_event.is_set():
            items = dict(poller.poll(100))
            if not len(items):
                continue
            if pipe in items and items[pipe] == zmq.POLLIN:
                message = await pipe.recv()
                n.shouts(ZRENode.GROUP, message.decode("utf-8"))
            else:
                cmds = n.recv()
                queue.put_nowait(cmds)
                queue._loop._write_to_self()
        n.stop()
        queue.put_nowait(None)

    @staticmethod
    def worker(n, pipe, queue):
        global worker_loop
        worker_loop = loop = asyncio.new_event_loop()
        task = loop.create_task(ZRENode.chat_task(n, pipe, queue))
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
        name = cmds.pop(0)
        group = cmds.pop(0).decode("utf-8")
        msg = cmds.pop(0).decode("utf-8")
        print(f"{peer}: {group} {msg}")

    async def handle_whisper(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0)
        print(f"{peer}: {cmds}")

    async def handle_enter(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0)
        headers = json.loads(cmds.pop(0).decode("utf-8"))
        logger.debug(headers)
        self.peers[peer] = [cmds, headers]
        print(f"{peer} entered")

    async def handle_join(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0)
        group = cmds.pop(0).decode("utf-8")
        self.groups[group].append(peer)
        print(f"{peer} joined {group}")
        print(self.peers, self.groups)

    async def handle_leave(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0)
        group = cmds.pop(0).decode("utf-8")
        self.groups[group].remove(peer)
        print(f"{peer} left {group}")

    async def handle_exit(self, cmds):
        peer = uuid.UUID(bytes=cmds.pop(0))
        name = cmds.pop(0)
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
        yield (seq, bytes(line, 'utf-8'))
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
