import bitcoin

from jsonrpc.dispatcher import Dispatcher

from . import ecdkg, util, db


class ProtocolError(Exception): pass


def create_dispatcher(address: int = None):
    dispatcher = Dispatcher()

    dispatcher['echo'] = lambda value: value


    @dispatcher.add_method
    def get_ecdkg_state(decryption_condition):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        return ecdkg_obj.to_state_message(address)


    if address is not None:
        @dispatcher.add_method
        def receive_alt_generator_part(decryption_condition, alt_generator_part):
            ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
            participant = ecdkg_obj.get_or_create_participant_by_address(address)
            participant.alt_generator_part = alt_generator_part
            db.Session.commit()


        @dispatcher.add_method
        def receive_share(share):
            print('got', share, 'from', address)

    return dispatcher
