import ssl


def get_pfs_ssl_client_context(cert):
    # This context will be used to authenticate valid servers that have certificates signed by cert
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=cert)
    # Require server to provide cert
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Ignore host names
    ctx.check_hostname = False
    # Use strong cipher
    ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    # Disable broken protocols
    ctx.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
    # Use ephemeral session keys
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    return ctx


def wrap_client_socket(sock, cert):
    return get_pfs_ssl_client_context(cert).wrap_socket(sock)


def get_pfs_ssl_server_context(cert, key_file):
    # This context will be used to establish secure connections with any client
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.CLIENT_AUTH,
        cafile=cert)
    # This server's private key needs to be loaded
    ctx.load_cert_chain(cert, key_file)
    # Do not authenticate clients
    ctx.verify_mode = ssl.CERT_NONE
    # Ignore host names
    ctx.check_hostname = False
    # Use strong cipher
    ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    # Disable broken protocols
    ctx.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
    # Use ephemeral session keys
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    return ctx


def wrap_server_socket(sock, cert, key_file):
    return get_pfs_ssl_server_context(cert, key_file).wrap_socket(sock, server_side=True)
