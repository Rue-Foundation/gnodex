import collections
import functools
import json
import logging
import os
import requests
import signal
import subprocess
import tempfile

from contextlib import ExitStack, contextmanager
from datetime import datetime

import psutil
import pytest

from gnodex.ecdkg import util


BIN_NAME = 'gnodex'
NUM_SUBPROCESSES = 10
PORTS_START = 59828

NodeInfo = collections.namedtuple('NodeInfo', (
    'process',
    'private_key',
))


@contextmanager
def Popen_with_interrupt_at_exit(cmdargs, *args, **kwargs):
    p = None
    try:
        p = psutil.Popen(cmdargs, *args, **kwargs)
        yield p
    finally:
        if p is not None:
            # start by trying to end process gently, but escalate
            for endfn in (functools.partial(p.send_signal, signal.SIGINT), p.terminate, p.kill):
                if p.poll() is None:
                    endfn()
                    try:
                        # TODO: switch to asyncio???
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        continue

@pytest.fixture
def nodes():
    subprocess.check_call((BIN_NAME, '-h'), stdout=subprocess.DEVNULL)
    with ExitStack() as exitstack:
        proc_dir = exitstack.enter_context(tempfile.TemporaryDirectory())
        proc_dir_file = functools.partial(os.path.join, proc_dir)

        private_keys = tuple(util.get_or_generate_private_value(
            proc_dir_file('private.key.{}'.format(i)))
            for i in range(NUM_SUBPROCESSES))

        with open(proc_dir_file('addresses.txt'), 'w') as addrf:
            for privkey in private_keys:
                addrf.write("{:040x}\n".format(util.private_value_to_eth_address(privkey)))

        with open(proc_dir_file('locations.txt'), 'w') as locf:
            for i in range(NUM_SUBPROCESSES):
                locf.write("localhost:{}\n".format(PORTS_START+i))

        processes = [exitstack.enter_context(Popen_with_interrupt_at_exit((
            BIN_NAME, 'ecdkg',
            '--port', str(PORTS_START+i),
            '--private-key-file', proc_dir_file('private.key.{}'.format(i)),
            '--addresses-file', proc_dir_file('addresses.txt'),
            '--locations', proc_dir_file('locations.txt'),
            # '--log-level', str(logging.DEBUG),
        ))) for i in range(NUM_SUBPROCESSES)]

        yield tuple(NodeInfo(process=proc, private_key=privkey) for proc, privkey in zip(processes, private_keys))


def is_node_listening(node: NodeInfo):
    return any(True for con in node.process.connections() if con.status == psutil.CONN_LISTEN)


def wait_for_all_nodes_listening(nodes):
    # TODO: Do something better than spinlock maybe?
    #       This could maybe be improved if transitioning to an asyncio version
    #       but then would lose psutil interop
    while any(not is_node_listening(n) for n in nodes):
        pass


def test_nodes_match_state(nodes):
    wait_for_all_nodes_listening(nodes)

    node_ids = range(NUM_SUBPROCESSES)
    deccond = 'past {}'.format(datetime.utcnow().isoformat())
    responses = [requests.post('https://localhost:{}'.format(PORTS_START + nid),
        verify=False,
        data=json.dumps({
            'id': 'honk',
            'method': 'get_ecdkg_state',
            'params': [deccond],
        })) for nid in node_ids]

    assert(all(r.json()['result']['decryption_condition'] == responses[0].json()['result']['decryption_condition'] for r in responses[1:]))


def test_nodes_match_pubkey(nodes):
    wait_for_all_nodes_listening(nodes)

    node_ids = range(NUM_SUBPROCESSES)
    deccond = 'past {}'.format(datetime.utcnow().isoformat())
    responses = [requests.post('https://localhost:{}'.format(PORTS_START + nid),
        verify=False,
        data=json.dumps({
            'id': 'honk',
            'method': 'get_encryption_key',
            'params': [deccond],
        })) for nid in node_ids]
