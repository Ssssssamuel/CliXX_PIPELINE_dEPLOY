#!/usr/bin/env python3
import boto3,botocore
from botocore.exceptions import ClientError
import time
import sys
import base64

# Global Variables
AWS_REGION = 'us-east-1'
SUBNET_ID = 'subnet-077c0abf304d257a5'
SUBNET_ID1 = 'subnet-09c91fae22777bc26'
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
    

# Creating EFS
try:
    efs = boto3.client('efs',
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'])
    response = efs.create_file_system(
        CreationToken='myefstoken',
        PerformanceMode='generalPurpose',
        Encrypted=False,
        ThroughputMode='bursting',
        Backup=False,
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CliXX-EFS'
            },
        ]
    )    
    print(response)   
    time.sleep (15) 
except ClientError as e:
    print("Error creating efs:", str(e))
    sys.exit()

# Attaching security group to EFS mount targets
efs_id = response['FileSystemId']

# Getting all subnets for my VPC
subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': ['vpc-09c489f7e7f6ccbfe']}])['Subnets']

# Creating a mount target for each subnet
for subnet in subnets:
    try:
        mount_target_response = efs.create_mount_target(
            FileSystemId=efs_id,
            SubnetId=subnet['SubnetId'],
            SecurityGroups=[security_group_id]
        )
        print(f"Created mount target in {subnet['AvailabilityZone']} with ID: {mount_target_response['MountTargetId']}")
    except ClientError as e:
        print(f"Error creating mount target in {subnet['AvailabilityZone']}: {e}")
        

# Creating Target Group
try:
    elbv2_client = boto3.client('elbv2', 
                                aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'],
                                region_name=AWS_REGION)
    response = elbv2_client.create_target_group(
        Name='my-target-group',
        Protocol='HTTPS',
        Port=443,
        VpcId='vpc-09c489f7e7f6ccbfe',
        HealthCheckProtocol='HTTP',
        HealthCheckPort='80',
        HealthCheckPath='/index.php',
        TargetType='instance',
    )
    target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
    print(f"Target Group created successfully: {target_group_arn}")      
except ClientError as e:
    print(f"Error creating target group: {str(e)}")
    sys.exit()
    

# Creating Certificate
try:
    acm_client = boto3.client('acm',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=AWS_REGION)
    response = acm_client.request_certificate(
        DomainName='*.clixx-samuel.com',
        ValidationMethod='DNS',
        SubjectAlternativeNames=[
            'www.*.clixx-samuel.com',
        ],
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CliXX-Certificate'
            },
            {
                'Key': 'OwnerEmail',
                'Value': 'samyfedyrob.sf+development@gmail.com'
            }
        ]
    )
    
    certificate_arn = response['CertificateArn']
    certificate_details = acm_client.describe_certificate(CertificateArn=certificate_arn)
    validation_options = certificate_details['Certificate']['DomainValidationOptions']

    for option in validation_options:
        dns_record = option['ResourceRecord']
        print(f"Create a DNS record with the following details to validate the certificate:")
        print(f"Name: {dns_record['Name']}")
        print(f"Type: {dns_record['Type']}")
        print(f"Value: {dns_record['Value']}")
    print(f"Certificate requested successfully. ARN: {certificate_arn}")
except ClientError as e:
    print(f"Error creating Certificate: {str(e)}")
    sys.exit()


# Creating Load Balancer
try:
    response = elbv2_client.create_load_balancer(
        Name='my-load-balancer',
        Subnets=[SUBNET_ID, SUBNET_ID1],
        SecurityGroups=[security_group_id],
        Scheme='internet-facing',
        Type='application',
        IpAddressType='ipv4'
    )
    lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    lb_dns = response['LoadBalancers'][0]['DNSName']
    lb_HZ = response['LoadBalancers'][0]['CanonicalHostedZoneId']
    print(f"Load Balancer created: {lb_arn}, DNS: {lb_dns}")
    
except ClientError as e:
    print(f"Error creating load balancer: {str(e)}")
    sys.exit()

# Attaching Certificate to Load Balancer Listener
try:
    response = elbv2_client.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol='HTTPS',
        Port=443,
        Certificates=[{'CertificateArn': certificate_arn}],
        DefaultActions=[
            {
                'Type': 'forward',
                'TargetGroupArn': target_group_arn
            }
        ]
    )
    print(f"Listener created and certificate attached: {response['Listeners'][0]['ListenerArn']}")
except ClientError as e:
    print(f"Error attaching certificate: {str(e)}")
    sys.exit()


