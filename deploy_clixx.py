#!/usr/bin/env python3
import boto3,botocore
import time

# Assume IAM Role for Boto3 session
sts_client = boto3.client('sts')
assumed_role_object=sts_client.assume_role(
    RoleArn='arn:aws:iam::222634373909:role/Engineer', 
    RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']
print(credentials)

# RDS client using assumed credentials
rds_client = boto3.client('rds',
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken']
)
# Restore DB instance from snapshot
response = rds_client.restore_db_instance_from_db_snapshot(
    DBInstanceIdentifier='wordpressdbclixx-ecs',
    DBSnapshotIdentifier='arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot',
    DBInstanceClass='db.m6gd.large',
    AvailabilityZone='us-east-1a',
    MultiAZ=False,
    PubliclyAccessible=True
)
print("DB instance restored:", response)

time.sleep(300)

# EC2 instance variables
AWS_REGION = 'us-east-1'
KEY_PAIR_NAME = 'stack_devops_kp7'
AMI_ID = 'ami-00f251754ac5da7f0'
SUBNET_ID = 'subnet-0c6f53069ca4e9922'
SECURITY_GROUP_ID = 'sg-05048737fb0f14c99'
TARGET_GROUP_ARN = 'arn:aws:elasticloadbalancing:us-east-1:222634373909:targetgroup/CliXX-App-TG/90fae24863253e24'
#INSTANCE_PROFILE = 'EC2-Admin'

# User data script to be run on the instance
USER_DATA = '''#!/bin/bash
DB_NAME="wordpressdb"
DB_USER="wordpressuser"
DB_PASS="W3lcome123"
LB_DNS="https://dev.clixx-samuel.com"
EP_DNS="wordpressdbclixx.cfmgy6w021vw.us-east-1.rds.amazonaws.com"

exec > >(tee -a /var/log/userdata.log) 2>&1

# Update system and install packages
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd

# Mount EFS
FILE_SYSTEM_ID=fs-06414348d110197ce
REGION=${AVAILABILITY_ZONE:0:-1}
MOUNT_POINT=/var/www/html
sudo mkdir -p ${MOUNT_POINT}
sudo chown ec2-user:ec2-user ${MOUNT_POINT}
echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount -a -t nfs4

# Clone Git repository and configure WordPress
cd /var/www/html
if [ ! -f wp-config.php ]; then
    git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
    cp -r CliXX_Retail_Repository/* /var/www/html
fi

# Configure wp-config.php with RDS details
sudo sed -i "s/define( 'DB_HOST', .*/define( 'DB_HOST', '$EP_DNS' );/" /var/www/html/wp-config.php

# Update WordPress site URLs in the database
mysql -u $DB_USER -p"$DB_PASS" -h $EP_DNS -D $DB_NAME <<EOF
UPDATE wp_options SET option_value='$LB_DNS' WHERE option_value LIKE 'CliXX-APP-NLB%';
EOF

# Update .htaccess and restart Apache
sudo sed -i "s|/\* That's all, stop editing! \*/|if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') { \$_SERVER['HTTPS'] = 'on'; }\n/* That's all, stop editing! */|" /var/www/html/wp-config.php
sudo systemctl restart httpd
'''

# Create EC2 instance
EC2_RESOURCE = boto3.resource('ec2',
                              aws_access_key_id=credentials['AccessKeyId'],
                              aws_secret_access_key=credentials['SecretAccessKey'],
                              aws_session_token=credentials['SessionToken'],
                              region_name=AWS_REGION)

EC2_CLIENT = boto3.client('ec2', region_name=AWS_REGION)
instance = EC2_RESOURCE.create_instances(
    MinCount=1,
    MaxCount=1,
    ImageId=AMI_ID,
    InstanceType='t2.micro',
    KeyName=KEY_PAIR_NAME,
    UserData=USER_DATA,
    # Security Group and Subnet are now set via Network Interface
    NetworkInterfaces=[
        {
            'AssociatePublicIpAddress': True,
            'DeviceIndex': 0,
            'SubnetId': SUBNET_ID,
            'Groups': [SECURITY_GROUP_ID]
        }
    ],
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': 'my-ec2-instance'}]
        }
    ],
    # Metadata Options for the instance
    MetadataOptions={
        'HttpTokens': 'optional',
        'HttpPutResponseHopLimit': 1,
        'HttpEndpoint': 'enabled'
    }
)[0]
instance.wait_until_running()

print(f'EC2 instance {instance.id} launched.')

# Register the instance with the target group
elbv2_client = boto3.client('elbv2', 
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'],
                            region_name=AWS_REGION)

response = elbv2_client.register_targets(
    TargetGroupArn=TARGET_GROUP_ARN,
    Targets=[{'Id': instance.id}]
)

print(f'EC2 instance {instance.id} registered with target group {TARGET_GROUP_ARN}.')

# Attach IAM instance profile
#ec2_client = boto3.client('ec2', region_name=AWS_REGION)
#ec2_client.associate_iam_instance_profile(
#    IamInstanceProfile={'Name': INSTANCE_PROFILE},
#    InstanceId=instance.id
#)
#print(f'Instance Profile "{INSTANCE_PROFILE}" attached to instance {instance.id}.')
