#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError
import time
import sys
import base64

# Global Variables
AWS_REGION = 'us-east-1'
SUBNET_ID = 'subnet-077c0abf304d257a5'
SUBNET_ID1 = 'subnet-09c91fae22777bc26'
AMI_ID = 'ami-00f251754ac5da7f0'

# Assume IAM Role
def assume_iam_role():
    sts_client = boto3.client('sts')
    try:
        assumed_role_object = sts_client.assume_role(
            RoleArn='arn:aws:iam::222634373909:role/Engineer',
            RoleSessionName='mysession'
        )
        credentials = assumed_role_object['Credentials']
        print("IAM Role assumed successfully")
        return credentials
    except ClientError as e:
        print("Error assuming IAM role:", str(e))
        sys.exit()

# Create Security Group
def create_security_group(ec2):
    try:
        response = ec2.create_security_group(
            Description='My security group',
            GroupName='my-security-group',
            VpcId='vpc-09c489f7e7f6ccbfe'
        )
        security_group_id = response['GroupId']
        print(f"Created security group {security_group_id}")

        # Ingress rules for HTTP, HTTPS, SSH, MySQL, NFS
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'UserIdGroupPairs': [{'GroupId': security_group_id}]},
                {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            ]
        )
        print("Ingress rules authorized successfully")
        return security_group_id
    except ClientError as e:
        print("Error creating security group or adding rules:", str(e))
        sys.exit()

# Create EFS and Mount Targets
def create_efs(efs, ec2, security_group_id):
    try:
        response = efs.create_file_system(
            CreationToken='myefstoken',
            PerformanceMode='generalPurpose',
            Encrypted=False,
            ThroughputMode='bursting',
            Backup=False,
            Tags=[{'Key': 'Name', 'Value': 'CliXX-EFS'}]
        )
        efs_id = response['FileSystemId']
        print(f"EFS created with ID: {efs_id}")

        # Delay to allow for propagation
        time.sleep(15)

        # Get all subnets for the VPC
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': ['vpc-09c489f7e7f6ccbfe']}])['Subnets']

        # Create a mount target for each subnet
        for subnet in subnets:
            try:
                efs.create_mount_target(
                    FileSystemId=efs_id,
                    SubnetId=subnet['SubnetId'],
                    SecurityGroups=[security_group_id]
                )
                print(f"Created mount target in {subnet['AvailabilityZone']}")
            except ClientError as e:
                print(f"Error creating mount target in {subnet['AvailabilityZone']}: {e}")
                sys.exit()
        return efs_id
    except ClientError as e:
        print("Error creating EFS:", str(e))
        sys.exit()

# Create Target Group
def create_target_group(elbv2_client):
    try:
        response = elbv2_client.create_target_group(
            Name='my-tg-group',
            Protocol='HTTPS',
            Port=443,
            VpcId='vpc-09c489f7e7f6ccbfe',
            HealthCheckProtocol='HTTP',
            HealthCheckPort='80',
            HealthCheckPath='/index.php',
            TargetType='instance',
        )
        target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
        print(f"Target Group created: {target_group_arn}")
        return target_group_arn
    except ClientError as e:
        print("Error creating target group:", str(e))
        sys.exit()

# Create Load Balancer
def create_load_balancer(elbv2_client, security_group_id):
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
        lb_hz = response['LoadBalancers'][0]['CanonicalHostedZoneId']
        print(f"Load Balancer created: {lb_arn}, DNS: {lb_dns}")
        return lb_arn, lb_dns, lb_hz
    except ClientError as e:
        print(f"Error creating load balancer: {str(e)}")
        sys.exit()

# Attach Certificate to Listener
def attach_certificate(elbv2_client, lb_arn, target_group_arn):
    try:
        response = elbv2_client.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol='HTTPS',
            Port=443,
            Certificates=[{'CertificateArn': 'arn:aws:acm:us-east-1:222634373909:certificate/0fa98a61-2d96-4c25-ae03-68388e8eb588'}],
            DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
        )
        print("Listener created and certificate attached")
    except ClientError as e:
        print(f"Error attaching certificate: {str(e)}")
        sys.exit()

# Create Keypair
def create_keypair(ec2):
    try:
        response = ec2.create_key_pair(KeyName='my-key-pair')
        print(f"Key Pair created: {response['KeyName']}")
    except ClientError as e:
        print(f"Error creating key pair: {str(e)}")
        sys.exit()

# Create Launch Template
def create_launch_template(ec2, security_group_id, efs_id, lb_dns):
    user_data = '''#!/bin/bash
    # ... (Bootstrap script as defined previously)
    ''' % efs_id

    user_data_encoded = base64.b64encode(user_data.encode('utf-8')).decode('utf-8')

    try:
        response = ec2.create_launch_template(
            LaunchTemplateName='my-launch-template',
            VersionDescription='v1',
            LaunchTemplateData={
                'ImageId': AMI_ID,
                'InstanceType': 't2.micro',
                'KeyName': 'my-key-pair',
                'SecurityGroupIds': [security_group_id],
                'UserData': user_data_encoded
            }
        )
        launch_template_id = response['LaunchTemplate']['LaunchTemplateId']
        print(f"Launch Template created: {launch_template_id}")
        return launch_template_id
    except ClientError as e:
        print(f"Error creating launch template: {str(e)}")
        sys.exit()

# Create Auto Scaling Group
def create_auto_scaling_group(autoscaling, launch_template_id, target_group_arn):
    try:
        response = autoscaling.create_auto_scaling_group(
            AutoScalingGroupName='my-auto-scaling-group',
            LaunchTemplate={'LaunchTemplateId': launch_template_id, 'Version': '1'},
            MinSize=1,
            MaxSize=3,
            DesiredCapacity=1,
            TargetGroupARNs=[target_group_arn],
            VPCZoneIdentifier=f"{SUBNET_ID},{SUBNET_ID1}"
        )
        print("Auto Scaling Group created")
    except ClientError as e:
        print(f"Error creating Auto Scaling Group: {str(e)}")
        sys.exit()

# Create Route 53 Record
def create_route_53_record(route53, lb_dns, lb_hz):
    try:
        response = route53.change_resource_record_sets(
            HostedZoneId='Z01063533B95XIB5GVOHL',
            ChangeBatch={
                'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': 'dev.clixx-samuel.com',
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': lb_hz,
                            'DNSName': lb_dns,
                            'EvaluateTargetHealth': False
                        }
                    }
                }]
            }
        )
        print("Route 53 record created")
    except ClientError as e:
        print(f"Error creating Route 53 record: {str(e)}")
        sys.exit()

# Store Variables in SSM Parameter Store
def store_in_ssm(ssm, parameter_name, parameter_value):
    try:
        response = ssm.put_parameter(
            Name=parameter_name,
            Value=parameter_value,
            Type='String',
            Overwrite=True
        )
        print(f"Stored {parameter_name} in SSM")
    except ClientError as e:
        print(f"Error storing parameter {parameter_name} in SSM: {str(e)}")

# Main Function
def main():
    # Set up clients
    credentials = assume_iam_role()
    ec2 = boto3.client('ec2', region_name=AWS_REGION, 
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'])
    
    efs = boto3.client('efs', region_name=AWS_REGION, 
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'])

    elbv2_client = boto3.client('elbv2', region_name=AWS_REGION, 
                                aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'])

    autoscaling = boto3.client('autoscaling', region_name=AWS_REGION, 
                               aws_access_key_id=credentials['AccessKeyId'],
                               aws_secret_access_key=credentials['SecretAccessKey'],
                               aws_session_token=credentials['SessionToken'])

    route53 = boto3.client('route53', region_name=AWS_REGION, 
                           aws_access_key_id=credentials['AccessKeyId'],
                           aws_secret_access_key=credentials['SecretAccessKey'],
                           aws_session_token=credentials['SessionToken'])
    
    ssm = boto3.client('ssm', region_name=AWS_REGION, 
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'])

    # Call functions in order
    security_group_id = create_security_group(ec2)
    efs_id = create_efs(efs, ec2, security_group_id)
    target_group_arn = create_target_group(elbv2_client)
    lb_arn, lb_dns, lb_hz = create_load_balancer(elbv2_client, security_group_id)
    attach_certificate(elbv2_client, lb_arn, target_group_arn)
    create_keypair(ec2)
    launch_template_id = create_launch_template(ec2, security_group_id, efs_id, lb_dns)
    create_auto_scaling_group(autoscaling, launch_template_id, target_group_arn)
    create_route_53_record(route53, lb_dns, lb_hz)

    # Store important variables in SSM
    store_in_ssm(ssm, 'EFS_ID', efs_id)
    store_in_ssm(ssm, 'TARGET_GROUP_ARN', target_group_arn)
    store_in_ssm(ssm, 'LOAD_BALANCER_DNS', lb_dns)
    store_in_ssm(ssm, 'SECURITY_GROUP_ID', security_group_id)
    store_in_ssm(ssm, 'LAUNCH_TEMPLATE_ID', launch_template_id)

if __name__ == "__main__":
    main()


