"""
Modules for a basic chatbot like application and AWS communications
"""
import base64
import requests
import boto3


def get_identity_document():
    """
    Get identity document for current EC2 Host
    """
    identity_doc = requests.get(
        "http://169.254.169.254/latest/dynamic/instance-identity/document", timeout=30)
    return identity_doc

def get_region(identity):
    """
    Get account of current instance identity
    """
    region = identity.json()["region"]
    return region

def get_account(identity):
    """
    Get account of current instance identity
    """
    account = identity.json()["accountId"]
    return account

def set_identity():
    """
    Set region and account for KMS
    """
    identity = get_identity_document()
    region = get_region(identity)
    account = get_account(identity)
    return region, account

def prepare_server_request(ciphertext):
    """
    Get the AWS credential from EC2 instance metadata
    """
    instance_prof = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/", timeout=30)
    instance_profile_name = instance_prof.text

    instance_prof_json = requests.get(
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{instance_profile_name}",
        timeout=30)
    response = instance_prof_json.json()

    credential = {
        'access_key_id': response['AccessKeyId'],
        'secret_access_key': response['SecretAccessKey'],
        'token': response['Token'],
        'region': REGION,
        'ciphertext': ciphertext
    }
    return credential


def get_user_input():
    """
    Start chatbot to collect user input
    """
    print("Chatbot: Hello! How can I assist you?")
    user_input = input('Your Question: ')
    return user_input.lower()

def encrypt_string(user_input, alias, kms):
    """
    Encrypt user input using AWS KMS
    """
    file_contents = user_input
    encrypted_file = kms.encrypt(KeyId=f'alias/{alias}', Plaintext=file_contents)
    encrypted_file_contents = encrypted_file[u'CiphertextBlob']
    encrypted_file_contents_base64 = base64.b64encode(encrypted_file_contents)
    return encrypted_file_contents_base64.decode()

def decrypt_data(encrypted_data, kms):
    """
    Decrypt the LLM response using AWS KMS
    """
    try:
        ciphertext_blob = base64.b64decode(encrypted_data)
        response = kms.decrypt(CiphertextBlob=ciphertext_blob)
        decrypted_data = response['Plaintext'].decode()
        return decrypted_data
    except ImportError as e_decrypt:
        print("Decryption failed:", e_decrypt)
        return None

REGION, ACCOUNT = set_identity()


def main():
    """
    Main function to encrypt/decrypt data and send/recieve with parent instance
    """
    kms = boto3.client('kms', region_name=REGION)
    alias = "ncsnitro"


    user_input = get_user_input()
    encrypted_input = encrypt_string(user_input, alias, kms)

    server_request = prepare_server_request(encrypted_input)

    url = 'http://172.25.1.94:5001'
    x = requests.post(url, json = server_request, timeout=20)
    response_body = x.json()

    llm_response = decrypt_data(response_body["EncryptedData"], kms)
    print(llm_response)

if __name__ == '__main__':
    main()
