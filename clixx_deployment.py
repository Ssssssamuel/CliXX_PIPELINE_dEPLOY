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
    sys.exit()
 
    

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
            {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'UserIdGroupPairs': [{'GroupId': security_group_id}]},
            {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
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
    
    # Get EFS ID from the response
    efs_id = response['FileSystemId']    
    print(response) 
      
    time.sleep (15) 
except ClientError as e:
    print("Error creating efs:", str(e))
    sys.exit()

# Attaching security group to EFS mount targets
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
        sys.exit()
        

# Creating Target Group
try:
    elbv2_client = boto3.client('elbv2', 
                                aws_access_key_id=credentials['AccessKeyId'],
                                aws_secret_access_key=credentials['SecretAccessKey'],
                                aws_session_token=credentials['SessionToken'],
                                region_name=AWS_REGION)
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
    print(f"Target Group created successfully: {target_group_arn}")      
except ClientError as e:
    print(f"Error creating target group: {str(e)}")
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
        Certificates=[{'CertificateArn': 'arn:aws:acm:us-east-1:222634373909:certificate/0fa98a61-2d96-4c25-ae03-68388e8eb588'}],
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


# Creating Keypair
try:
        response = ec2.create_key_pair(KeyName='my-key-pair')
        print(f"Key Pair created: {response['KeyName']}")
except ClientError as e:
        print(f"Error creating key pair: {str(e)}")
        sys.exit()

# Creating  Launch Template
USER_DATA = '''#!/bin/bash -xe

# Declaring Variables
DB_NAME="wordpressdb"
DB_USER="wordpressuser"
DB_PASS="W3lcome123"
LB_DNS="https://dev.clixx-samuel.com"
EP_DNS="wordpressdbclixx-ecs.cfmgy6w021vw.us-east-1.rds.amazonaws.com"

exec > >(tee -a /var/log/userdata.log) 2>&1
 
# Install the needed packages and enable the services (MariaDB, Apache)
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl is-enabled httpd

# Mounting EFS
FILE_SYSTEM_ID=%s
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=${AVAILABILITY_ZONE:0:-1}
MOUNT_POINT=/var/www/html
sudo mkdir -p ${MOUNT_POINT}
sudo chown ec2-user:ec2-user ${MOUNT_POINT}
echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount -a -t nfs4

# Verifying if EFS mounted correctly
if ! mount | grep -q efs; then
    echo "EFS mount failed" >> /var/log/userdata.log
else
    echo "EFS mount succeeded" >> /var/log/userdata.log
fi
sudo chmod -R 755 ${MOUNT_POINT}
 
# Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;
cd /var/www/html

# Cloning repository
if [ -f /var/www/html/wp-config.php ]; then
    echo "Repository already exists..." >> /var/log/userdata.log
else
    echo "Now cloning repository..." >> /var/log/userdata.log
    git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
    cp -r CliXX_Retail_Repository/* /var/www/html
fi 

# Replacing localhost URLs with RDS Endpoint in wp-config.php
sudo sed -i "s/define( 'DB_HOST', .*/define( 'DB_HOST', '$EP_DNS' );/" /var/www/html/wp-config.php

# Updating WordPress site URLs in RDS database
echo "Running DB update statement..." >> /var/log/userdata.log
RESULT=$(mysql -u $DB_USER -p"$DB_PASS" -h $EP_DNS -D $DB_NAME -sse "SELECT option_value FROM wp_options WHERE option_value LIKE 'CliXX-APP-NLB%%';" 2>&1)
echo $RESULT >> /var/log/userdata.log

# Check if result is empty
if [[ -n "$RESULT" ]]; then
    echo "Matching values found. Proceeding with UPDATE query..." >> /var/log/userdata.log
    mysql -u $DB_USER -p"$DB_PASS" -h $EP_DNS -D $DB_NAME <<EOF
UPDATE wp_options SET option_value ="$LB_DNS" WHERE option_value LIKE 'CliXX-APP-NLB%%';
EOF
    echo "UPDATE query executed." >> /var/log/userdata.log
else
    echo "No matching values found. Skipping update..." >> /var/log/userdata.log
fi
 
# Allow WordPress to use Permalinks
echo "Now allowing WordPress to use Permalinks..." >> /var/log/userdata.log
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Updating WordPress to recognize client session
#config='if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
#    $_SERVER['HTTPS'] = 'on';
#}'
#sed -i '10s/.*/${config}/' /var/www/html/wp-config.php

# Grant file ownership of /var/www & its contents to apache user
sudo chown -R apache /var/www
 
# Grant group ownership of /var/www & contents to apache group
sudo chgrp -R apache /var/www
 
# Change directory permissions of /var/www & its subdirectories to add group write
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;

# Recursively change file permission of /var/www & subdirectories to add group write permissions
sudo find /var/www -type f -exec sudo chmod 0664 {} \;

# Restart Apache
sudo systemctl restart httpd
sudo service httpd restart
 
# Enable httpd
sudo systemctl enable httpd 
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5

echo "End of Bootstrap!" >> /var/log/userdata.log

''' % (efs_id)

USER_DATA_ENCODED = base64.b64encode(USER_DATA.encode('utf-8')).decode('utf-8')

try:       
        response = ec2.create_launch_template(
            LaunchTemplateName='my-launch-template',
            VersionDescription='v1',
            LaunchTemplateData={
                'ImageId': AMI_ID,
                'InstanceType': 't2.micro',
                'KeyName': 'my-key-pair',
                'SecurityGroupIds': [security_group_id],
                'UserData': USER_DATA_ENCODED
                }
        )
        launch_temp_id = response['LaunchTemplate']['LaunchTemplateId']
        print(f"Launch Template created: {response['LaunchTemplate']['LaunchTemplateId']}")
except ClientError as e:
        print(f"Error creating launch template: {str(e)}")
        sys.exit()


# Creating Route 53 Record
try:
        route53 = boto3.client('route53',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
    )
        response = route53.change_resource_record_sets(
            HostedZoneId='Z01063533B95XIB5GVOHL',
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': 'dev.clixx-samuel.com',
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': lb_HZ,
                                'DNSName': lb_dns,
                                'EvaluateTargetHealth': False
                            }
                        }
                    }
                ]
            }
        )
        print(f"Route 53 record created: {response}")
except ClientError as e:
    print(f"Error creating Route 53 record: {str(e)}")
    sys.exit()
        
  
# Restore DB instance from snapshot
try:
    rds_client = boto3.client('rds',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    response = rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier='wordpressdbclixx-ecs',
        DBSnapshotIdentifier='arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot',
        DBInstanceClass='db.m6gd.large',
        AvailabilityZone='us-east-1a',
        MultiAZ=False,
        PubliclyAccessible=True
    )
    print("DB instance restored:", response)
    
    DB_id = response['DBInstance']['DBInstanceIdentifier']

    # waiter = rds_client.get_waiter('db_instance_available')
    # waiter.wait(DBInstanceIdentifier= DB_id)
    
    time.sleep(360)
       
except ClientError as e:
    print("Error restoring Database:", str(e))
    sys.exit()       
  

# Creating Auto scale
try:
        autoscaling = boto3.client('autoscaling',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
    )
        response = autoscaling.create_auto_scaling_group(
            AutoScalingGroupName='my-auto-scaling-group',
            LaunchTemplate={
                'LaunchTemplateId': launch_temp_id,
                'Version': '1'
            },
            MinSize=1,
            MaxSize=3,
            DesiredCapacity=1,
            TargetGroupARNs=[target_group_arn],
            VPCZoneIdentifier=f"{SUBNET_ID},{SUBNET_ID1}"
        )
        print(f"Auto Scaling Group created: {response}")
except ClientError as e:
    print(f"Error creating Auto Scaling Group: {str(e)}")
    sys.exit()

# Storing values in SSM
try:
    ssm = boto3.client('ssm',
                   aws_access_key_id=credentials['AccessKeyId'],
                   aws_secret_access_key=credentials['SecretAccessKey'],
                   aws_session_token=credentials['SessionToken'])
    
    ssm.put_parameter(Name='/myapp/DB_id', Value=DB_id, Type='String', Overwrite=True)
    ssm.put_parameter(Name='/myapp/lb_dns', Value=lb_dns, Type='String', Overwrite=True)
    ssm.put_parameter(Name='/myapp/lb_arn', Value=lb_arn, Type='String', Overwrite=True)
    ssm.put_parameter(Name='/myapp/target_group_arn', Value=target_group_arn, Type='String', Overwrite=True)
    ssm.put_parameter(Name='/myapp/efs_id', Value=efs_id, Type='String', Overwrite=True)
    ssm.put_parameter(Name='/myapp/security_group_id', Value=security_group_id, Type='String', Overwrite=True)

    print("Resource details saved to SSM Parameter Store")
except ClientError as e:
    print(f"Error saving to SSM Parameter Store: {str(e)}")
    sys.exit()