from jsonrpc.dispatcher import Dispatcher

def create_dispatcher(address: int = None):
    dispatcher = Dispatcher()
    dispatcher['echo'] = lambda s: address
    return dispatcher
