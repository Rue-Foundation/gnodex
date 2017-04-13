import functools
import os
import requests
import signal
import subprocess
import tempfile
import time

from contextlib import ExitStack

from gnodex.ecdkg import util


BIN_NAME = 'gnodex'
NUM_SUBPROCESSES = 10
PORTS_START = 59828


def test_nodes():
    subprocess.check_call((BIN_NAME, '-h'))
    with ExitStack() as exitstack:
        proc_dir = exitstack.enter_context(tempfile.TemporaryDirectory())
        proc_dir_file = functools.partial(os.path.join, proc_dir)

        private_keys = tuple(util.get_or_generate_private_value(
            proc_dir_file('private.key.{}'.format(i)))
            for i in range(NUM_SUBPROCESSES))

        with open(proc_dir_file('addresses.txt'), 'w') as addrf:
            addrf.writelines(hex(util.private_value_to_eth_address(privkey)) for privkey in private_keys)

        processes = [exitstack.enter_context(subprocess.Popen((
            BIN_NAME, 'ecdkg',
            '--port', str(PORTS_START+i),
            '--private-key-file', proc_dir_file('private.key.{}'.format(i)),
            '--addresses-file', proc_dir_file('addresses.txt')))) for i in range(NUM_SUBPROCESSES)]

        # TODO: Figure out how to sleep until ports are bound
        time.sleep(2)

        # THIS IS WHERE STUFF HAPPENS
        print(requests.get('https://localhost:{}'.format(PORTS_START + util.random.randrange(NUM_SUBPROCESSES)),
            verify=False,
            data={
                'id': 'honk',
                'method': 'get_ecdkg_state',
                'param': ['past 2017-04-13T18:07:00'],
            }))

        # TODO: switch to asyncio???
        # TODO: write this into contextmanager
        for p in processes:
            for endfn in (functools.partial(p.send_signal, signal.SIGINT), p.terminate, p.kill):
                if p.poll() is None:
                    endfn()
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        continue
