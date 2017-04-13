import functools
import json
import logging
import os
import requests
import signal
import subprocess
import tempfile
import time

from contextlib import ExitStack, contextmanager
from datetime import datetime

from gnodex.ecdkg import util


BIN_NAME = 'gnodex'
NUM_SUBPROCESSES = 10
PORTS_START = 59828


@contextmanager
def Popen_with_interrupt_at_exit(cmdargs, *args, **kwargs):
    p = None
    try:
        p = subprocess.Popen(cmdargs, *args, **kwargs)
        yield p
    finally:
        if p is not None:
            for endfn in (functools.partial(p.send_signal, signal.SIGINT), p.terminate, p.kill):
                if p.poll() is None:
                    endfn()
                    try:
                        # TODO: switch to asyncio???
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        continue


def test_nodes_match_state():
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

        # TODO: Figure out how to sleep until ports are bound
        time.sleep(2)

        # THIS IS WHERE STUFF HAPPENS
        node_ids = util.random.sample(range(NUM_SUBPROCESSES), 2)
        responses = [requests.post('https://localhost:{}'.format(PORTS_START + nid),
            verify=False,
            data=json.dumps({
                'id': 'honk',
                'method': 'get_ecdkg_state',
                'params': ['past Apr 13, 2017 1:07 PM CST'],
            })) for nid in node_ids]

        assert(all(r.json()['result']['decryption_condition'] == responses[0].json()['result']['decryption_condition'] for r in responses))
