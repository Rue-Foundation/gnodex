from jsonrpc.dispatcher import Dispatcher


def create_dispatcher(address: int = None):
    dispatcher = Dispatcher()
    dispatcher['echo'] = lambda value: value

    if address is not None:
        @dispatcher.add_method
        def receive_share(share):
            print('got', share, 'from', address)

    return dispatcher
