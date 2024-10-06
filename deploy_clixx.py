#!/usr/bin/python

import boto3,botocore

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)

# s3=boto3.client('s3',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
# response = s3.list_buckets(
#     MaxBuckets=123)

# print(response)

ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
response = ec2.create_security_group(
    Description='My security group',
    GroupName='my-security-group',
    VpcId='vpc-0c6460b8c3c8fe62f'
    )

print(response)
