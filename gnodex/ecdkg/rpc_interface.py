import asyncio
import functools
import logging
import math

import bitcoin

from jsonrpc.dispatcher import Dispatcher

from . import ecdkg, util, db, networking


class ProtocolError(Exception): pass


def create_dispatcher(address: int = None):
    # TODO: make loop use uniform
    loop = asyncio.get_event_loop()

    dispatcher = Dispatcher()

    dispatcher['echo'] = lambda value: value

    def dispatcher_add_async_method(corofunc):
        @functools.wraps(corofunc)
        def wrapper(*args, **kwargs):
            return loop.create_task(corofunc(*args, **kwargs))
        return dispatcher.add_method(wrapper)


    @dispatcher_add_async_method
    async def get_ecdkg_state(decryption_condition):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        return ecdkg_obj.to_state_message(address)


    @dispatcher_add_async_method
    async def get_encryption_key(decryption_condition, notify_others=True):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)

        async def update_participants():
            state_futs = {}
            states = {}
            for addr, cinfo in networking.channels.items():
                state_futs[addr] = networking.make_jsonrpc_call(cinfo, 'get_ecdkg_state', decryption_condition)

            await asyncio.wait(state_futs.values(), timeout=ecdkg.COMS_TIMEOUT)

            for addr, state_fut in state_futs.items():
                if state_fut.done():
                    try:
                        result = state_fut.result()
                    except e:
                        logging.error(e)
                    else:
                        states[addr] = result

            for addr, state in states.items():
                participant = ecdkg_obj.get_or_create_participant_by_address(addr)
                participant.update_with_ecdkg_state_message(state)
                # TODO: make and handle complaints for bad state updates?


        # TODO: Is there a better pattern here...?
        if notify_others:
            for addr, cinfo in networking.channels.items():
                networking.make_jsonrpc_call(cinfo, 'get_encryption_key', decryption_condition, False, is_notification=True)


        # TODO: Refactor this crazy method

        if ecdkg_obj.phase == ecdkg.ECDKGPhase.uninitialized:
            await update_participants()
            # in order to move onto the key distribution phase, everyone must agree on participants and alt_generator
            # TODO: handle hella improbable event parts sum up to EC group identity
            ecdkg_obj.alt_generator = functools.reduce(bitcoin.fast_add,
                (p.alt_generator_part for p in ecdkg_obj.participants),
                ecdkg_obj.alt_generator_part)
            ecdkg_obj.threshold = math.ceil(ecdkg.THRESHOLD_FACTOR * (len(ecdkg_obj.participants)+1))

            spoly1 = ecdkg.random_polynomial(ecdkg_obj.threshold)
            spoly2 = ecdkg.random_polynomial(ecdkg_obj.threshold)

            ecdkg_obj.secret_poly1 = spoly1
            ecdkg_obj.secret_poly2 = spoly2

            ecdkg_obj.phase = ecdkg.ECDKGPhase.key_distribution
            ecdkg_obj.verification_points = tuple(bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, a), bitcoin.fast_multiply(ecdkg_obj.alt_generator, b)) for a, b in zip(spoly1, spoly2))

            db.Session.commit()

        if ecdkg_obj.phase == ecdkg.ECDKGPhase.key_distribution:

            for participant in ecdkg_obj.participants:
                address = participant.eth_address
                if address in networking.channels:
                    cinfo = networking.channels[address]
                    share1 = ecdkg.eval_polynomial(ecdkg_obj.secret_poly1, address)
                    share2 = ecdkg.eval_polynomial(ecdkg_obj.secret_poly2, address)

                    networking.make_jsonrpc_call(cinfo, 'receive_secret_shares',
                        decryption_condition,
                        '{:064x}'.format(share1),
                        '{:064x}'.format(share2),
                        is_notification = True)

            ecdkg_obj.phase = ecdkg.ECDKGPhase.key_verification

            db.Session.commit()

        if ecdkg_obj.phase == ecdkg.ECDKGPhase.key_verification:
            await update_participants()
            await asyncio.wait([ecdkg.secret_share_futures[sfid] for sfid in ((ecdkg_obj.id, p.eth_address) for p in ecdkg_obj.participants) if sfid in ecdkg.secret_share_futures], timeout=ecdkg.COMS_TIMEOUT)

            for participant in ecdkg_obj.participants:
                address = participant.eth_address
                share1 = participant.secret_share1
                share2 = participant.secret_share2
                if share1 is not None and share2 is not None:
                    vlhs = bitcoin.fast_add(bitcoin.fast_multiply(bitcoin.G, share1),
                                            bitcoin.fast_multiply(ecdkg_obj.alt_generator, share2))
                    vrhs = functools.reduce(bitcoin.fast_add, (bitcoin.fast_multiply(ps, pow(ecdkg.own_address, k, bitcoin.N)) for k, ps in enumerate(participant.verification_points)))

                    if vlhs != vrhs:
                        # TODO: Produce complaints and continue instead of halting here
                        raise ProtocolError('verification of shares failed')
                else:
                    raise ProtocolError('missing some shares')

            ecdkg_obj.phase = ecdkg.ECDKGPhase.key_check

            db.Session.commit()

        if ecdkg_obj.phase == ecdkg.ECDKGPhase.key_check:
            # TODO: Track complaints and filter qualifying set

            ecdkg_obj.phase = ecdkg.ECDKGPhase.key_generation

            db.Session.commit()

        if ecdkg_obj.phase == ecdkg.ECDKGPhase.key_generation:
            ecdkg_obj.encryption_key_part = bitcoin.fast_multiply(bitcoin.G, ecdkg_obj.secret_poly1[0])

            for participant in ecdkg_obj.participants:
                address = participant.eth_address
                if address in networking.channels:
                    cinfo = networking.channels[address]
                    networking.make_jsonrpc_call(cinfo, 'receive_encryption_key_part',
                        decryption_condition,
                        '{0[0]:064x}{0[1]:064x}'.format(ecdkg_obj.encryption_key_part),
                        is_notification = True)

            await asyncio.wait([ecdkg.encryption_key_part_futures[sfid] for sfid in ((ecdkg_obj.id, p.eth_address) for p in ecdkg_obj.participants) if sfid in ecdkg.encryption_key_part_futures], timeout=ecdkg.COMS_TIMEOUT)

            ecdkg_obj.encryption_key = functools.reduce(bitcoin.fast_add,
                (p.encryption_key_part for p in ecdkg_obj.participants), ecdkg_obj.encryption_key_part)

            ecdkg_obj.phase == ecdkg.ECDKGPhase.key_publication

            db.Session.commit()

        return '{0[0]:064x}{0[1]:064x}'.format(ecdkg_obj.encryption_key)


    @dispatcher_add_async_method
    async def get_decryption_key_part(decryption_condition):
        await get_encryption_key(decryption_condition)
        await util.decryption_condition_satisfied(decryption_condition)
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        return '{:064x}'.format(ecdkg_obj.secret_poly1[0])


    @dispatcher_add_async_method
    async def get_decryption_key(decryption_condition):
        await get_encryption_key(decryption_condition)
        await util.decryption_condition_satisfied(decryption_condition)

        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)

        if ecdkg_obj.decryption_key is None:
            for participant in ecdkg_obj.participants:
                address = participant.eth_address
                if address in networking.channels:
                    cinfo = networking.channels[address]
                    res = await networking.make_jsonrpc_call(cinfo, 'get_decryption_key_part',
                        decryption_condition)
                    participant.decryption_key_part = int(res, 16)

            ecdkg_obj.decryption_key = (sum(p.decryption_key_part for p in ecdkg_obj.participants) + ecdkg_obj.secret_poly1[0]) % bitcoin.N

            db.Session.commit()

        return '{:064x}'.format(ecdkg_obj.decryption_key)


    if address is not None:
        @dispatcher.add_method
        def receive_encryption_key_part(decryption_condition, pubkey):
            ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
            participant = ecdkg_obj.get_or_create_participant_by_address(address)
            participant.encryption_key_part = tuple(int(pubkey[i:i+64], 16) for i in (0, 64))
            sfid = (ecdkg_obj.id, participant.eth_address)
            if sfid in ecdkg.encryption_key_part_futures:
                pubkfut = ecdkg.encryption_key_part_futures[sfid]
                if not pubkfut.done():
                    pubkfut.set_result(participant.encryption_key_part)
            db.Session.commit()


        @dispatcher.add_method
        def receive_secret_shares(decryption_condition, share1, share2):
            ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
            participant = ecdkg_obj.get_or_create_participant_by_address(address)
            share1 = int(share1, 16)
            share2 = int(share2, 16)
            participant.secret_share1 = share1
            participant.secret_share2 = share2
            sfid = (ecdkg_obj.id, participant.eth_address)
            if sfid in ecdkg.secret_share_futures:
                sshfut = ecdkg.secret_share_futures[sfid]
                if not sshfut.done():
                    sshfut.set_result((share1, share2))
            db.Session.commit()


    return dispatcher
