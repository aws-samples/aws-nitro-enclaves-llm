"""
Imported mdoules for parent instance nitro enclave capabilities
"""
import json
import socket
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_cid():
    """
    Determine CID of Current Enclave
    """
    with subprocess.Popen(
        ["/bin/nitro-cli", "describe-enclaves"],
        stdout=subprocess.PIPE
    ) as proc:
        output = json.loads(proc.communicate()[0].decode())
        enclave_cid = output[0]["EnclaveCID"]
        return enclave_cid


@app.route('/', methods=['POST'])
def encrypted_payload():
    body = request.get_json()
    response = payload(body)
    print(f'Respnse: {response}')
    return jsonify(response)

def payload(request_body):

    # Create a vsock socket object
    sock_connect = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Get CID from command line parameter
    cid = get_cid()

    # The port should match the server running in enclave
    port = 5000

    # Connect to the server
    sock_connect.connect((cid, port))

    # Send AWS credential to the server running in enclave
    sock_connect.send(str.encode(json.dumps(request_body)))

    # receive data from the server
    received_data = sock_connect.recv(4096).decode()

    #parse response
    parsed = json.loads(received_data)

    #pretty print response
    print(json.dumps(parsed, indent=4, sort_keys=True))

    return parsed

def main():
    """
    Main function for enclave connection, S3, data transfer 
    """
    app.run(host="0.0.0.0",port=5001)

if __name__ == '__main__':
    main()
