import asyncio
import functools
import logging

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
    async def get_ecdkg_state(decryption_condition: str, phase: ecdkg.ECDKGPhase = ecdkg.ECDKGPhase.uninitialized):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        return ecdkg_obj.to_state_message()


    @dispatcher_add_async_method
    async def get_encryption_key(decryption_condition, notify_others=True):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)

        # TODO: Make this pull-based
        if notify_others:
            await networking.broadcast_jsonrpc_call_on_all_channels(
                'get_encryption_key', decryption_condition, False,
                is_notification=True)

        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_publication)

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
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.complete)
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
