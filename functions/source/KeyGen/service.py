import json
from botocore.vendored import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import traceback


def generate_pem(keysize):
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=keysize)
    pem = key.private_bytes(encoding=serialization.Encoding.PEM, 
                            format=serialization.PrivateFormat.TraditionalOpenSSL, 
                            encryption_algorithm=serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, 
                                        serialization.PublicFormat.OpenSSH)
    private = pem.decode('utf-8')
    public = pub.decode('utf-8')
    return private, public


def send_response(event, context, response_status, response_data):
    response_body = {'Status': response_status,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'PhysicalResourceId': context.log_stream_name,
                    'Reason': 'For details see AWS CloudWatch LogStream: ' + context.log_stream_name,
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': response_data}
    request = requests.put(event['ResponseURL'], data=json.dumps(response_body))
    if request.status_code != 200:
        print(request.text)
        raise Exception('Error detected in [CFN RESPONSE != 200.')


def handler(event, context):
    status = 'SUCCESS'
    data = {}
    try:
        if event['RequestType'] == 'Create':
            data['PEM'], data['PUB'] = generate_pem(2048)
        elif event['RequestType'] == 'Update':
            data = event['OldResourceProperties']
    except:
        status = 'FAILED'
        traceback.print_exc()
    finally:
        send_response(event, context, status, data)

