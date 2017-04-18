import json
import base64
from .ssl_sock_helper import send_ssl_msg, recv_ssl_msg, recv_ssl_msg_timeout
from .ssl_context import wrap_server_socket
from jsonrpc import JSONRPCResponseManager
from jsonrpc.exceptions import JSONRPCMethodNotFound


def rpc_call_rlp(ssl_sock, method, params, default_timeout=False):
    for (key, val) in params.items():
        params[key] = base64.standard_b64encode(val).decode()
    result = rpc_call(ssl_sock, method, params, default_timeout)
    return base64.standard_b64decode(result.encode()) if result else None


def rpc_call(ssl_sock, method, params, default_timeout=False):
    rpc_payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 0,
    }
    send_ssl_msg(ssl_sock, json.dumps(rpc_payload).encode())
    rpc_response = recv_ssl_msg(ssl_sock) if not default_timeout \
              else recv_ssl_msg_timeout(ssl_sock)
    decoded_response = json.loads(rpc_response)
    return decoded_response["result"] if decoded_response and ('result' in decoded_response) else None


def rpc_response(resp):
    return base64.standard_b64encode(resp).decode()


def rpc_param_decode(param):
    return base64.standard_b64decode(param.encode())


# One thread per client
def handle_rpc_client(sock, cert, key_file, dispatcher):
    ssl_sock = wrap_server_socket(sock, cert, key_file)

    # Wait for input, and respond
    while True:
        data = recv_ssl_msg(ssl_sock)
        rpc_input = data.decode()
        print("RPC DEBUG INPUT: " + str(rpc_input)[0:120])
        rpc_output = JSONRPCResponseManager.handle(rpc_input, dispatcher)
        if rpc_output:
            print("RPC DEBUG OUTPUT: " + str(rpc_output.json)[0:120])
            send_ssl_msg(ssl_sock, rpc_output.json.encode())


# One thread per client
def handle_rpc_client_stateful(sock, cert, key_file, state_dispatchers, global_dispatcher, get_state_lock_func):
    ssl_sock = wrap_server_socket(sock, cert, key_file)

    # Wait for input, and respond
    with ssl_sock:
        while True:
            data = recv_ssl_msg(ssl_sock)
            rpc_input = data.decode()
            print("RPC DEBUG INPUT: " + str(rpc_input)[0:120])
            (state, rwlock) = get_state_lock_func()
            with rwlock.reader:
                rpc_output = JSONRPCResponseManager.handle(rpc_input, state_dispatchers[state])
                if rpc_output.error and rpc_output.error["code"] == JSONRPCMethodNotFound.CODE:
                    rpc_output = JSONRPCResponseManager.handle(rpc_input, global_dispatcher)
            if rpc_output:
                print("RPC DEBUG OUTPUT: " + str(rpc_output.json)[0:120])
                send_ssl_msg(ssl_sock, rpc_output.json.encode())
