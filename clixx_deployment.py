import boto3
import json
from botocore.exceptions import ClientError
import time
import sys
import base64

# Global Variables
AWS_REGION = 'us-east-1'
AMI_ID = 'ami-00f251754ac5da7f0'

# Assume IAM Role for Boto3 session
sts_client = boto3.client('sts')

try:
    assumed_role_object = sts_client.assume_role(
        RoleArn='arn:aws:iam::222634373909:role/Engineer',
        RoleSessionName='mysession'
    )

    credentials = assumed_role_object['Credentials']
    print(credentials)
except ClientError as e:
    print("Error Assuming role:", str(e))
    exit(1)

# Initialize clients with assumed role credentials
ec2 = boto3.client('ec2',
                   aws_access_key_id=credentials['AccessKeyId'],
                   aws_secret_access_key=credentials['SecretAccessKey'],
                   aws_session_token=credentials['SessionToken'],
                   region_name=AWS_REGION)

efs = boto3.client('efs',
                   aws_access_key_id=credentials['AccessKeyId'],
                   aws_secret_access_key=credentials['SecretAccessKey'],
                   aws_session_token=credentials['SessionToken'],
                   region_name=AWS_REGION)

elbv2_client = boto3.client('elbv2',
                             aws_access_key_id=credentials['AccessKeyId'],
                             aws_secret_access_key=credentials['SecretAccessKey'],
                             aws_session_token=credentials['SessionToken'],
                             region_name=AWS_REGION)

rds_client = boto3.client('rds',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=AWS_REGION)

ssm = boto3.client('ssm',
                   aws_access_key_id=credentials['AccessKeyId'],
                   aws_secret_access_key=credentials['SecretAccessKey'],
                   aws_session_token=credentials['SessionToken'],
                   region_name=AWS_REGION)

route53 = boto3.client('route53',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'])

autoscaling = boto3.client('autoscaling',
                   aws_access_key_id=credentials['AccessKeyId'],
                   aws_secret_access_key=credentials['SecretAccessKey'],
                   aws_session_token=credentials['SessionToken'],
                   region_name=AWS_REGION)

def save_to_ssm(param_name, param_value):
    try:
        ssm.put_parameter(
            Name=param_name,
            Value=param_value,
            Type='String',
            Overwrite=True
        )
        print(f"Parameter {param_name} saved in SSM.")
    except ClientError as e:
        print(f"Error saving {param_name} to SSM: {e}")
        sys.exit()

def create_vpc():
    try:
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc['Vpc']['VpcId']
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "PYTVPC"}])
        print(f"VPC created with ID: {vpc_id}")
        save_to_ssm('/python/vpc_id', vpc_id)
        return vpc_id
    except ClientError as e:
        print(f"Error creating VPC: {e}")
        sys.exit()

def create_subnet(vpc_id, cidr_block, availability_zone, name):
    try:
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=availability_zone
        )
        subnet_id = subnet['Subnet']['SubnetId']
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": name}])
        print(f"Subnet created with ID: {subnet_id}")
        save_to_ssm(f'/python/{name.lower().replace(" ", "_")}_subnet_id', subnet_id)
        return subnet_id
    except ClientError as e:
        print(f"Error creating subnet: {e}")
        sys.exit()

def create_internet_gateway(vpc_id):
    try:
        igw = ec2.create_internet_gateway()
        igw_id = igw['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2.create_tags(Resources=[igw_id], Tags=[{"Key": "Name", "Value": "PYT_GW"}])
        print(f"Internet Gateway created with ID: {igw_id}")
        save_to_ssm('/python/internet_gateway_id', igw_id)
        return igw_id
    except ClientError as e:
        print(f"Error creating Internet Gateway: {e}")
        sys.exit()
        

def create_nat_gateway(subnet_id):
    try:
        # Allocating a new Elastic IP
        eip = ec2.allocate_address(Domain='vpc')
        allocation_id = eip['AllocationId'] 

        # Creating NAT Gateway using the new Elastic IP allocation ID
        nat_gateway = ec2.create_nat_gateway(SubnetId=subnet_id, AllocationId=allocation_id)
        
        time.sleep(60)  
        nat_gateway_id = nat_gateway['NatGateway']['NatGatewayId']
        print(f"NAT Gateway created with ID: {nat_gateway_id}")
        
        save_to_ssm('/python/nat_gateway_id', nat_gateway_id)
        return nat_gateway_id
    except ClientError as e:
        print(f"Error creating NAT Gateway: {e}")
        sys.exit(1)

def create_route_table(vpc_id, gateway_id=None, nat_gateway_id=None, is_public=True):
    try:
        response = ec2.create_route_table(VpcId=vpc_id)
        print("Route Table creation response: ", response)
        #route_table = ec2.create_route_table(VpcId=vpc_id)
        #route_table_id = route_table['RouteTableId']
        route_table = response['RouteTable']
        route_table_id = route_table['RouteTableId']
        print(f"Route Table '{route_table_id}' created successfully.")

        if is_public:
            ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=gateway_id)
            print(f"Public Route Table created with ID: {route_table_id}")
        else:
            ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_gateway_id)
            print(f"Private Route Table created with ID: {route_table_id}")
        
        save_to_ssm(f'/python/route_table_id_{"public" if is_public else "private"}', route_table_id)
        return route_table_id
    except ClientError as e:
        print(f"Error creating Route Table: {e}")
        sys.exit()

def associate_route_table(subnet_id, route_table_id):
    try:
        association = ec2.associate_route_table(SubnetId=subnet_id, RouteTableId=route_table_id)
        association_id = association['AssociationId']
        print(f"Associated Route Table {route_table_id} with Subnet {subnet_id}")
        return association_id
    except ClientError as e:
        print(f"Error associating Route Table: {e}")
        sys.exit()

def create_key_pair():
    try:
        key_pair = ec2.create_key_pair(KeyName="stackkp")
        save_to_ssm('/python/key_pair_name', "stackkp")
        print(f"Key pair 'stackkp' created and saved.")
    except ClientError as e:
        print(f"Error creating Key Pair: {e}")
        sys.exit()


def create_web_security_group(vpc_id):
    try:
        sg = ec2.create_security_group(
            GroupName="web-pyt-sg",
            Description="Security group for web servers",
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']
        print(f"Web Security Group created with ID: {sg_id}")

        # Add ingress and egress rules
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            ]
        )

        ec2.authorize_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 0, 'ToPort': 0, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ]
        )

        print(f"Rules added to Web Security Group {sg_id}.")
        save_to_ssm('/python/web_sg_id', sg_id)
        return sg_id

    except ClientError as e:
        print(f"Error creating Web Security Group: {e}")
        sys.exit()


def create_db_security_group(vpc_id):
    try:
        sg = ec2.create_security_group(
            GroupName="db-pyt-sg",
            Description="Security group for database",
            VpcId=vpc_id
        )
        sg_id = sg['GroupId']
        print(f"DB Security Group created with ID: {sg_id}")

        # Add ingress rules
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
                {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
            ]
        )        
        print(f"Rules added to DB Security Group {sg_id}.")
        save_to_ssm('/python/db_sg_id', sg_id) 
        return sg_id
    except ClientError as e:
        print(f"Error creating DB Security Group: {e}")
        sys.exit()

def create_db_subnet_group(subnet_ids):
    try:
        db_subnet_group = rds_client.create_db_subnet_group(
            DBSubnetGroupName='db-subnet-group',
            SubnetIds=subnet_ids,
            DBSubnetGroupDescription="Subnet group for RDS"
        )
        db_subnet_group_name = db_subnet_group['DBSubnetGroup']['DBSubnetGroupName']
        print(f"DB Subnet Group '{db_subnet_group_name}' created.")
        save_to_ssm('/python/db_subnet_group_name', db_subnet_group_name) 
        return db_subnet_group_name
    except ClientError as e:
        print(f"Error creating DB Subnet Group: {e}")
        sys.exit()

def restore_db_from_snapshot(snapshot_id, db_subnet_group_name, db_security_group_id):
    try:
        db_instance = rds_client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier='wordpressdbclixx-ecs',
            DBSnapshotIdentifier=snapshot_id,
            AvailabilityZone='us-east-1a',
            DBInstanceClass='db.m6gd.large',
            MultiAZ=False,
            DBSubnetGroupName=db_subnet_group_name,
            VpcSecurityGroupIds=[db_security_group_id],
            AutoMinorVersionUpgrade=False
        )
        
        db_instance_id = db_instance['DBInstance']['DBInstanceIdentifier']
        print(f"Restored DB Instance with ID: {db_instance_id} from snapshot {snapshot_id}.")
        save_to_ssm('/python/db_instance_id', db_instance_id) 
        return db_instance_id
    except ClientError as e:
        print(f"Error restoring DB from snapshot: {e}")
        sys.exit()

def create_efs_file_system():
    try:
        file_system = efs.create_file_system(CreationToken="efs-token")
        file_system_id = file_system['FileSystemId']
        print(f"EFS File System created with ID: {file_system_id}.")
        save_to_ssm('/python/efs_file_system_id', file_system_id) 
        return file_system_id
    except ClientError as e:
        print(f"Error creating EFS File System: {e}")
        sys.exit()

def create_efs_mount_target(file_system_id, subnet_id, security_group_id):
    try:
        time.sleep(15)
        mount_target = efs.create_mount_target(
            FileSystemId=file_system_id,
            SubnetId=subnet_id,
            SecurityGroups=[security_group_id]
        )
        mount_target_id = mount_target['MountTargetId']
        print(f"EFS Mount Target created with ID: {mount_target_id}.")
        return mount_target_id
    except ClientError as e:
        print(f"Error creating EFS Mount Target: {e}")
        sys.exit()

def create_target_group(vpc_id):
    try:
        target_group = elbv2_client.create_target_group(
            Name="web-pyth-tg",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
            HealthCheckProtocol="HTTP",
            HealthCheckPath='/index.php',
            HealthCheckPort="80",
            HealthyThresholdCount=2,      
            UnhealthyThresholdCount=10,    
            HealthCheckTimeoutSeconds=120,    
            HealthCheckIntervalSeconds=121, 
            TargetType='instance',

        )
        target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']
        print(f"Target Group created with ARN: {target_group_arn}")
        save_to_ssm('/python/target_group_arn', target_group_arn) 
        return target_group_arn
    except ClientError as e:
        print(f"Error creating Target Group: {e}")
        sys.exit()

def create_application_load_balancer(subnet_ids, security_group_id):
    try:
        load_balancer = elbv2_client.create_load_balancer(
            Name="pyth-web-alb",
            Subnets=subnet_ids,
            SecurityGroups=[security_group_id],
            Scheme='internet-facing',
            Type='application'
        )
        alb_arn = load_balancer['LoadBalancers'][0]['LoadBalancerArn']
        alb_hz = load_balancer['LoadBalancers'][0]['CanonicalHostedZoneId']
        alb_dns = load_balancer['LoadBalancers'][0]['DNSName']
        print(f"Application Load Balancer created with ARN: {alb_arn}")
        save_to_ssm('/python/alb_arn', alb_arn) 
        save_to_ssm('/python/alb_hz', alb_hz)   
        save_to_ssm('/python/alb_dns', alb_dns)  
        return alb_arn, alb_hz, alb_dns
    except ClientError as e:
        print(f"Error creating Application Load Balancer: {e}")
        sys.exit()
        
        
def create_listener(load_balancer_arn, target_group_arn):
    try:
        listener = elbv2_client.create_listener(
            LoadBalancerArn=load_balancer_arn,
            Port=80,
            Protocol='HTTP',
            DefaultActions=[{
                'Type': 'forward',
                'TargetGroupArn': target_group_arn
            }]
        )
        print(f"Listener created with ARN: {listener['Listeners'][0]['ListenerArn']}")
    except ClientError as e:
        print(f"Error creating Listener: {e}")
        sys.exit()


def attach_target_group_to_listener(load_balancer_arn, target_group_arn):
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
        listener_arn = listeners['Listeners'][0]['ListenerArn']
        elbv2_client.modify_listener(
            ListenerArn=listener_arn,
            DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
        )
        print(f"Target Group {target_group_arn} attached to Load Balancer listener {listener_arn}.")
    except ClientError as e:
        print(f"Error attaching Target Group to Listener: {e}")
        sys.exit()

def create_route_53_record(alb_hz, alb_dns):
    try:
        route53.change_resource_record_sets(
            HostedZoneId='Z01063533B95XIB5GVOHL',
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': 'dev2.clixx-samuel.com',
                            'Type': 'A',
                            'AliasTarget': {
                                'HostedZoneId': alb_hz,
                                'DNSName': alb_dns,
                                'EvaluateTargetHealth': False
                            }
                        }
                    }
                ]
            }
        )
        print(f"Route 53 record created for dev2.clixx-samuel.com.")
    except ClientError as e:
        print(f"Error creating Route 53 record: {e}")
        sys.exit()



def create_launch_template(file_system_id, sg_id, base64, public_subnet_id1):
    # UserData script
    USERDATA = '''#!/bin/bash
# Declaring Variables
DB_NAME="wordpressdb"
DB_USER="wordpressuser"
DB_PASS="W3lcome123"
LB_DNS="https://dev2.clixx-samuel.com"
EP_DNS="wordpressdbclixx-ecs.cfmgy6w021vw.us-east-1.rds.amazonaws.com"

exec > >(tee -a /var/log/userdata.log) 2>&1

# Install needed packages and enable services (MariaDB, Apache)
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd

# Mounting EFS
FILE_SYSTEM_ID=%s
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=${AVAILABILITY_ZONE:0:-1}
MOUNT_POINT=/var/www/html
sudo mkdir -p ${MOUNT_POINT}
sudo chown ec2-user:ec2-user ${MOUNT_POINT}
echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount -a -t nfs4

# Verify if EFS mounted correctly
if [ $? -eq 0 ]; then
    echo "EFS mount succeeded" >> /var/log/userdata.log
else
    echo "EFS mount failed" >> /var/log/userdata.log
fi
sudo chmod -R 755 ${MOUNT_POINT}

# Add ec2-user to Apache group and grant permissions
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

# Updating wordpress file
sed -i "s/define( 'WP_DEBUG', false );/define( 'WP_DEBUG', false ); \nif (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) \&\& \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {\$_SERVER['HTTPS'] = 'on';}/" /var/www/html/wp-config.php

# Check if result is empty
if [[ -n "$RESULT" ]]; then
    echo "Matching values found. Proceeding with UPDATE query..." >> /var/log/userdata.log
    mysql -u $DB_USER -p"$DB_PASS" -h $EP_DNS -D $DB_NAME <<EOF
UPDATE wp_options SET option_value ="$LB_DNS" WHERE option_value LIKE 'CliXX-APP-NLB%%';
EOF
    echo "UPDATE query executed." >> /var/log/userda:ta.log
else
    echo "No matching values found. Skipping update..." >> /var/log/userdata.log
fi

# Allow WordPress to use Permalinks
echo "Now allowing WordPress to use Permalinks…" >> /var/log/userdata.log
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Grant file ownership of /var/www to apache
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;

# Restart Apache
echo "Now restarting services..." >> /var/log/userdata.log
sudo systemctl restart httpd
sudo service httpd restart

# Enable httpd and adjust kernel settings
sudo systemctl enable httpd
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5

echo "End of Bootstrap!" >> /var/log/userdata.log
''' % (file_system_id)
    
    USER_DATA_ENCODED = base64.b64encode(USERDATA.encode('utf-8')).decode('utf-8')

    try:
        response = ec2.create_launch_template(
            LaunchTemplateName='pyt-launch-template',
            LaunchTemplateData={
                'ImageId': AMI_ID,
                'InstanceType': 't2.micro',
                'KeyName': 'stackkp',
                'UserData': USER_DATA_ENCODED,
                'NetworkInterfaces': [
                    {
                        'DeviceIndex': 0,
                        'SubnetId': public_subnet_id1,
                        'AssociatePublicIpAddress': True,
                        'Groups': [sg_id]
                    }
                ],
                'EbsOptimized': False,
                'BlockDeviceMappings': [
                    {
                        'DeviceName': '/dev/xvda',
                        'Ebs': {
                            'VolumeSize': 20,
                            'VolumeType': 'gp2',
                            'DeleteOnTermination': True
                        }
                    }
                ]
            }
        )
        
        launch_template_id = response['LaunchTemplate']['LaunchTemplateId']
        print(f"Launch template created successfully: {launch_template_id}")
        
        # Store the launch template ID in SSM for future use
        ssm.put_parameter(Name='/python/launch_template_id', Value=launch_template_id, Type='String', Overwrite=True)
        return launch_template_id
    except ClientError as e:
        print(f"Error creating launch template: {e}")
        sys.exit(1)

def create_auto_scaling_group(launch_template_id, subnet_ids, target_group_arn):
    try:
        time.sleep(390)
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName="pyt-asg",
            LaunchTemplate={
                'LaunchTemplateId': launch_template_id,
                'Version': '1'
            },
            MinSize=1,
            MaxSize=3,
            DesiredCapacity=1,
            TargetGroupARNs=[target_group_arn],
            VPCZoneIdentifier=",".join(subnet_ids),
        )
        print("Auto Scaling Group created.")
    except ClientError as e:
        print(f"Error creating Auto Scaling Group: {e}")
        sys.exit()

def main():
    # Create VPC
    vpc_id = create_vpc()

    # Create Subnets
    public_subnet_id1 = create_subnet(vpc_id, "10.0.1.0/24", "us-east-1a", "Public Subnet 1")
    public_subnet_id2 = create_subnet(vpc_id, "10.0.2.0/24", "us-east-1b", "Public Subnet 2")
    private_subnet_id1 = create_subnet(vpc_id, "10.0.3.0/24", "us-east-1a", "Private Subnet 1")
    private_subnet_id2 = create_subnet(vpc_id, "10.0.4.0/24", "us-east-1b", "Private Subnet 2")

    # Create Internet Gateway
    igw_id = create_internet_gateway(vpc_id)

    # Create NAT Gateway
    nat_gateway_id = create_nat_gateway(public_subnet_id1)

    # Create Route Tables and associate them with subnets
    time.sleep(30)
    public_route_table_id = create_route_table(vpc_id, gateway_id=igw_id, is_public=True)
    private_route_table_id = create_route_table(vpc_id, nat_gateway_id=nat_gateway_id, is_public=False)

    associate_route_table(public_subnet_id1, public_route_table_id)
    associate_route_table(public_subnet_id2, public_route_table_id)
    associate_route_table(private_subnet_id1, private_route_table_id)
    associate_route_table(private_subnet_id2, private_route_table_id)

    # Create Security Groups
    web_sg_id = create_web_security_group(vpc_id)
    db_sg_id = create_db_security_group(vpc_id)

    # Create Key Pair
    create_key_pair()

    # Create RDS Subnet Group
    db_subnet_group_name = create_db_subnet_group([private_subnet_id1, private_subnet_id2])

    # Restore RDS from Snapshot
    snapshot_id = 'arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot'
    db_instance_id = restore_db_from_snapshot(snapshot_id, db_subnet_group_name, db_sg_id)

    # Create EFS
    efs_id = create_efs_file_system()
    create_efs_mount_target(efs_id, private_subnet_id1, web_sg_id)
    create_efs_mount_target(efs_id, private_subnet_id2, web_sg_id)

    # Create Load Balancer and Target Group
    target_group_arn = create_target_group(vpc_id)
    alb_arn, alb_hz, alb_dns = create_application_load_balancer([public_subnet_id1, public_subnet_id2], web_sg_id)
    create_listener(alb_arn, target_group_arn)
    attach_target_group_to_listener(alb_arn, target_group_arn)


    # Create Route 53 record for Load Balancer
    create_route_53_record(alb_hz, alb_dns)

    # Create Launch Template
    launch_template_id = create_launch_template(efs_id, web_sg_id, base64, public_subnet_id1)

    # Create Auto Scaling Group
    create_auto_scaling_group(launch_template_id, [public_subnet_id1, public_subnet_id2], target_group_arn)

    print("Infrastructure creation complete!")

if __name__ == "__main__":
    main()
