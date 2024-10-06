#!/usr/bin/python

import boto3,botocore

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::222634373909:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)

ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
response = ec2.create_security_group(
    Description='My security group',
    GroupName='my-security-group',
    VpcId='vpc-09c489f7e7f6ccbfe'
    )

print(response)
