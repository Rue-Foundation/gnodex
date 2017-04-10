from .ssl_sock_helper import send_ssl_msg, recv_ssl_msg, recv_ssl_msg_timeout
import json
import base64


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
    return decoded_response["result"]

def rpc_response(resp):
    return base64.standard_b64encode(resp).decode()

def rpc_param_decode(param):
    return base64.standard_b64decode(param.encode())