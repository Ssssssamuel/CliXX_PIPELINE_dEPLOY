#!/usr/bin/env python3
import boto3

# Assume IAM Role for Boto3 session
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(
    RoleArn='arn:aws:iam::222634373909:role/Engineer',
    RoleSessionName='mysession'
)
credentials = assumed_role_object['Credentials']
print("Assumed role credentials received.")

# EC2 instance variables
AWS_REGION = "us-east-1"
KEY_PAIR_NAME = 'stack_devops_kp7.pem'
AMI_ID = 'ami-00f251754ac5da7f0'  # Amazon Linux 2
SUBNET_ID = 'subnet-0c6f53069ca4e9922' 
SECURITY_GROUP_ID = 'sg-05048737fb0f14c99'
INSTANCE_PROFILE = 'EC2-Admin'

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
FILE_SYSTEM_ID=fs-0c7225b6c50e6deff
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
ec2_resource = boto3.resource('ec2', region_name=AWS_REGION)
instance = ec2_resource.create_instances(
    MinCount=1,
    MaxCount=1,
    ImageId=AMI_ID,
    InstanceType='t2.micro',
    KeyName=KEY_PAIR_NAME,
    SecurityGroupIds=[SECURITY_GROUP_ID],
    SubnetId=SUBNET_ID,
    UserData=USER_DATA,
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Name', 'Value': 'my-ec2-instance'}]
        }
    ]
)[0]
instance.wait_until_running()
print(f'EC2 instance {instance.id} launched.')

# Attach IAM instance profile
ec2_client = boto3.client('ec2', region_name=AWS_REGION)
ec2_client.associate_iam_instance_profile(
    IamInstanceProfile={'Name': INSTANCE_PROFILE},
    InstanceId=instance.id
)
print(f'Instance Profile "{INSTANCE_PROFILE}" attached to instance {instance.id}.')
