#!/usr/bin/env python3
import boto3,botocore
import time

# Assume IAM Role for Boto3 session
sts_client = boto3.client('sts')
try:
    assumed_role_object=sts_client.assume_role(
        RoleArn='arn:aws:iam::222634373909:role/Engineer', 
        RoleSessionName='mysession')

    credentials=assumed_role_object['Credentials']
    print(credentials)
except ClientError as e:
    print("Error creating bucket:", str(e))
except Exception as e:
    print("Unexpected error has just occured:", str(e))
    sys.exit()
    
# RDS client using assumed credentials
try:
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

    time.sleep(360)
    
except ClientError as e:
    print("Error creating bucket:", str(e))
except Exception as e:
    print("Unexpected error has just occured:", str(e))
    sys.exit()

# EC2 instance variables
AWS_REGION = 'us-east-1'
KEY_PAIR_NAME = 'stack_devops_kp7'
AMI_ID = 'ami-00f251754ac5da7f0'
SUBNET_ID = 'subnet-077c0abf304d257a5'
SECURITY_GROUP_ID = 'sg-05048737fb0f14c99'
TARGET_GROUP_ARN = 'arn:aws:elasticloadbalancing:us-east-1:222634373909:targetgroup/CliXX-App-TG/90fae24863253e24'
#INSTANCE_PROFILE = 'EC2-Admin'

# User data script for instance
USER_DATA = '''#!/bin/bash -xe

# Declaring Variables
DB_NAME="wordpressdb"
DB_USER="wordpressuser"
DB_PASS="W3lcome123"
LB_DNS="http://dev.clixx-samuel.com"
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
 
# Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;
sudo mkdir -p /var/www/html
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
RESULT=$(mysql -u $DB_USER -p"$DB_PASS" -h $EP_DNS -D $DB_NAME -sse "SELECT option_value FROM wp_options WHERE option_value LIKE 'CliXX-APP-NLB%';" 2>&1)
echo $RESULT >> /var/log/userdata.log

# Check if result is empty
if [[ -n "$RESULT" ]]; then
    echo "Matching values found. Proceeding with UPDATE query..." >> /var/log/userdata.log
    mysql -u $DB_USER -p"$DB_PASS" -h $EP_DNS -D $DB_NAME <<EOF
UPDATE wp_options SET option_value ="$LB_DNS" WHERE option_value LIKE 'CliXX-APP-NLB%';
EOF
    echo "UPDATE query executed." >> /var/log/userdata.log
else
    echo "No matching values found. Skipping update..." >> /var/log/userdata.log
fi
 
# Allow WordPress to use Permalinks
echo "Now allowing WordPress to use Permalinks..." >> /var/log/userdata.log
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

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

'''

# Creating EC2 instance
try:
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
        # Security Group and Subnet set via Network Interface
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
    
except ClientError as e:
    print("Error creating bucket:", str(e))
except Exception as e:
    print("Unexpected error has just occured:", str(e))
    sys.exit()

# Registering the instance with target group
try:
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

except ClientError as e:
    print("Error creating bucket:", str(e))
except Exception as e:
    print("Unexpected error has just occured:", str(e))
    sys.exit()
    
# Attach IAM instance profile
#ec2_client = boto3.client('ec2', region_name=AWS_REGION)
#ec2_client.associate_iam_instance_profile(
#    IamInstanceProfile={'Name': INSTANCE_PROFILE},
#    InstanceId=instance.id
#)
#print(f'Instance Profile "{INSTANCE_PROFILE}" attached to instance {instance.id}.')
