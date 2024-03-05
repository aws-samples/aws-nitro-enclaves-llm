"""
Moduled to run an LLM inside of a nitro enclave
"""
import json
import base64
import socket
import os
from transformers import AutoTokenizer, AutoModelForCausalLM
import boto3


KMS_PROXY_PORT="8000"
KMS_KEY_ID=os.environ["KMS_KEY_ID"]

def get_plaintext(credentials):
    """
    prepare inputs and invoke decrypt function
    """
    ciphertext= credentials['ciphertext']
    creds = decrypt_cipher(credentials, ciphertext)
    print(credentials)
    return creds

def decrypt_cipher(credentials, cipher_data):
    """
    use KMS Tool Enclave Cli to decrypt cipher text
    """
    kms_client = boto3.client('kms', region_name=credentials['region'], aws_access_key_id=credentials['access_key_id'],
    aws_secret_access_key=credentials['secret_access_key'],
    aws_session_token=credentials['token']
    )

    ciphertext_blob = base64.b64decode(cipher_data)
    response = kms_client.decrypt(CiphertextBlob=ciphertext_blob)
    decrypted_data = response['Plaintext'].decode()
    return decrypted_data


def encrypt_cipher(credentials, data):
    """
    Encrypt LLM response with KMS
    """
    # Initialize the Boto3 KMS client
    kms_client = boto3.client('kms', region_name=credentials['region'], aws_access_key_id=credentials['access_key_id'],
    aws_secret_access_key=credentials['secret_access_key'],
    aws_session_token=credentials['token']
    )

    # Encrypt data using KMS
    response = kms_client.encrypt(
        KeyId=KMS_KEY_ID,  # Replace with your KMS key ID
        Plaintext=data,
    )

    # Extract the ciphertext from the response
    ciphertext = response['CiphertextBlob']

    return ciphertext

def main(): #pylint: disable=R0914
    """
    Main function to load model, create socket connections, encrypt/decrypt
    """
    model_name = "/app/bloom"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    tokenizer.add_special_tokens({'pad_token': '[PAD]'})
    model = AutoModelForCausalLM.from_pretrained(model_name)

    sock_connect = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    cid = socket.VMADDR_CID_ANY
    port = 5000
    sock_connect.bind((cid, port))
    sock_connect.listen()
    print(f"Started server on port {port} and cid {cid}")

    while True:
        connection, addr = sock_connect.accept() #pylint: disable=w0612
        payload = connection.recv(4096)
        result_dict = {}
        credentials = json.loads(payload.decode())
        print(credentials)
        plaintext = get_plaintext(credentials)
        print(plaintext)

        if plaintext == "KMS Error. Decryption Failed.":
            result_dict["error"] = plaintext
        else:
            # Encode the input text with padding enabled
            inputs = tokenizer(plaintext, return_tensors="pt", padding=True, truncation=True)

            # Ensure that the input tensor has the proper shape for batch generation
            input_ids = inputs.input_ids.repeat(1, 1)

            # Generate text with padding
            outputs = model.generate(
                input_ids,
                max_length=20,
                do_sample=True,
                top_k=5,
                num_return_sequences=1,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

            generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
            print(f"Result: {generated_text}")

            result_dict["Results"] = generated_text

            # Use the plaintext_data_key obtained from encrypt_cipher
            data_to_encrypt = json.dumps(result_dict)  # Convert the result to a JSON string
            encrypted_data = encrypt_cipher(credentials, data_to_encrypt)
            result_dict = {"EncryptedData": base64.b64encode(encrypted_data).decode('utf-8')}

        connection.send(str.encode(json.dumps(result_dict)))

        connection.close()

if __name__ == '__main__':
    main()
