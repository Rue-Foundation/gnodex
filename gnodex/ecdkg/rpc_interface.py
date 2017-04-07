import asyncio
import functools

import bitcoin

from jsonrpc.dispatcher import Dispatcher

from . import ecdkg, util, db


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


    if address is not None:
        @dispatcher_add_async_method
        async def receive_alt_generator_part(decryption_condition, alt_generator_part):
            ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
            participant = ecdkg_obj.get_or_create_participant_by_address(address)
            participant.alt_generator_part = alt_generator_part
            db.Session.commit()


        @dispatcher.add_method
        def receive_share(share):
            print('got', share, 'from', address)

    return dispatcher
