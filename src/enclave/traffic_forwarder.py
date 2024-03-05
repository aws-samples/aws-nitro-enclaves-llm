"""
Moduled to forward traffic between enclave and parent instance
"""
import socket
import sys
import threading
import time


def server(local_ip, local_port, remote_cid, remote_port):
    """
    Function to socket server and connection
    """
    try:
        dock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dock_socket.bind((local_ip, local_port))
        dock_socket.listen(5)

        while True:
            client_socket = dock_socket.accept()[0]

            server_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            server_socket.connect((remote_cid, remote_port))

            outgoing_thread = threading.Thread(target=forward,
                                               args=(client_socket,
                                                     server_socket))
            incoming_thread = threading.Thread(target=forward,
                                               args=(server_socket,
                                                     client_socket))

            outgoing_thread.start()
            incoming_thread.start()
    finally:
        new_thread = threading.Thread(target=server,
                                      args=(local_ip, local_port, remote_cid,
                                            remote_port))
        new_thread.start()


def forward(source, destination):
    """
    Function to forward data
    """
    string = ' '
    while string:
        string = source.recv(1024)
        if string:

            destination.sendall(string)
        else:
            source.shutdown(socket.SHUT_RD)
            destination.shutdown(socket.SHUT_WR)


def main(args):
    """
    Main functoin to establish traffic forwarding
    """
    local_ip = str(args[0])
    local_port = int(args[1])
    remote_cid = int(args[2])
    remote_port = int(args[3])

    thread = threading.Thread(target=server,
                              args=(local_ip, local_port, remote_cid,
                                    remote_port))
    thread.start()
    print(
        f"starting forwarder on {local_ip}:{local_port} {remote_cid}:{remote_port}"
    )
    while True:
        time.sleep(60)


if __name__ == '__main__':
    print("starting traffic forwarder")
    main(sys.argv[1:])
