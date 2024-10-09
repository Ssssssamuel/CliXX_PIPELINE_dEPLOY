#!/usr/bin/env python3
import boto3,botocore
from botocore.exceptions import ClientError
import time
import sys
import base64

# Global Variables
AWS_REGION = 'us-east-1'
SUBNET_ID = 'subnet-077c0abf304d257a5'
AMI_ID = 'ami-00f251754ac5da7f0'

# Assume IAM Role for Boto3 session
sts_client = boto3.client('sts')
try:
    assumed_role_object=sts_client.assume_role(
        RoleArn='arn:aws:iam::222634373909:role/Engineer', 
        RoleSessionName='mysession')

    credentials=assumed_role_object['Credentials']
    print(credentials)
except ClientError as e:
    print("Error Assuming role:", str(e))
 
    

# Creating Security group
try:
    ec2 = boto3.client('ec2',
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'])
    response = ec2.create_security_group(
        Description='My security group',
        GroupName='my-security-group',
        VpcId='vpc-09c489f7e7f6ccbfe'
    )
    
    security_group_id = response['GroupId']
    print(f"Created security group {security_group_id}")
    
    # Authorize Ingress rules for NFS (2049), SSH (22), HTTP (80), HTTPS (443), and MySQL/Aurora (3306)
    ec2.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            # NFS (port 2049), restrict to this security group only
            {
                'IpProtocol': 'tcp',
                'FromPort': 2049,
                'ToPort': 2049,
                'UserIdGroupPairs': [
                    {
                        'GroupId': security_group_id
                    }
                ]
            },
            # MySQL/Aurora (port 3306), allow from anywhere
            {
                'IpProtocol': 'tcp',
                'FromPort': 3306,
                'ToPort': 3306,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
            # SSH (port 22), allow from anywhere
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
            # HTTP (port 80), allow from anywhere
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
            # HTTPS (port 443), allow from anywhere
            {
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            },
        ]
    )
    
    print("Ingress rules authorized successfully.")

except ClientError as e:
    print("Error creating security group or adding rules:", str(e))
    sys.exit()
    

