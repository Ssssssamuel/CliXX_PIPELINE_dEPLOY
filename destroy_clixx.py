import boto3
import json
from botocore.exceptions import ClientError
import time
import sys

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

def get_from_ssm(parameter_name):
    try:
        response = ssm.get_parameter(Name=parameter_name)
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Error retrieving parameter {parameter_name} from SSM: {e}")
        return None
    

def delete_key_pair():
    try:
        key_pair_name = get_from_ssm('/python/key_pair_name')
        if not key_pair_name:
            print("Key Pair name not found in SSM. Skipping deletion.")
            return

        ec2.delete_key_pair(KeyName=key_pair_name)
        print(f"Key Pair {key_pair_name} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Key Pair: {e}")
        

def delete_auto_scaling_group():
    try:
        auto_scaling_group_name = "pyt-asg" 
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName=auto_scaling_group_name,
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0
        )
        print(f"Scaling down Auto Scaling Group '{auto_scaling_group_name}' to zero instances.")
        time.sleep(30) 

        autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=auto_scaling_group_name,
            ForceDelete=True 
        )
        print(f"Auto Scaling Group '{auto_scaling_group_name}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Auto Scaling Group: {e}")
        

def delete_launch_template():
    try:
        launch_template_id = get_from_ssm('/python/launch_template_id')
        if not launch_template_id:
            print("Launch Template ID not found in SSM. Skipping deletion.")
            return

        ec2.delete_launch_template(LaunchTemplateId=launch_template_id)
        print(f"Launch Template '{launch_template_id}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Launch Template: {e}")
        

def delete_application_load_balancer():
    try:
        alb_arn = get_from_ssm('/python/alb_arn')
        if not alb_arn:
            print("ALB ARN not found in SSM. Skipping deletion.")
            return
        
        # Deleting listeners associated with the load balancer
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
        for listener in listeners['Listeners']:
            elbv2_client.delete_listener(ListenerArn=listener['ListenerArn'])
            print(f"Deleted listener: {listener['ListenerArn']}")


        elbv2_client.delete_load_balancer(LoadBalancerArn=alb_arn)
        print(f"Application Load Balancer '{alb_arn}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Application Load Balancer: {e}")
        

def delete_target_group():
    try:
        target_group_arn = get_from_ssm('/python/target_group_arn')
        if not target_group_arn:
            print("Target Group ARN not found in SSM. Skipping deletion.")
            return

        elbv2_client.delete_target_group(TargetGroupArn=target_group_arn)
        print(f"Target Group '{target_group_arn}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Target Group: {e}")
        
        
def delete_efs_mount_target():
    try:
        file_system_id = get_from_ssm('/python/efs_file_system_id')
        if not file_system_id:
            print("EFS File System ID not found in SSM. Skipping Mount Target deletion.")
            return

        # Retrieve all mount targets for the given file system
        mount_targets = efs.describe_mount_targets(FileSystemId=file_system_id)['MountTargets']
        for mount_target in mount_targets:
            efs.delete_mount_target(MountTargetId=mount_target['MountTargetId'])
            print(f"EFS Mount Target '{mount_target['MountTargetId']}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting EFS Mount Target: {e}")        
        

def delete_efs_file_system():
    try:
        time.sleep(15)
        file_system_id = get_from_ssm('/python/efs_file_system_id')
        if not file_system_id:
            print("EFS File System ID not found in SSM. Skipping deletion.")
            return

        efs.delete_file_system(FileSystemId=file_system_id)
        print(f"EFS File System '{file_system_id}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting EFS File System: {e}")
        

def delete_db_instance():
    try:
        db_instance_id = get_from_ssm('/python/db_instance_id')
        if not db_instance_id:
            print("DB Instance ID not found in SSM. Skipping deletion.")
            return

        rds_client.delete_db_instance(DBInstanceIdentifier=db_instance_id, SkipFinalSnapshot=True)
        print(f"DB Instance '{db_instance_id}' deleted successfully.")
        time.sleep(20)
    except ClientError as e:
        print(f"Error deleting DB Instance: {e}")
        

def delete_db_subnet_group(subnet_id):
    try:
        time.sleep(20)
        db_subnet_group_name = get_from_ssm('/python/db_subnet_group_name')
        if not db_subnet_group_name:
            print("DB Subnet Group name not found in SSM. Skipping deletion.")
            return
        
        # Checking if there are any network interfaces attached to the subnet
        network_interfaces = ec2.describe_network_interfaces(Filters=[{'Name': 'subnet-id', 'Values': [subnet_id]}])['NetworkInterfaces']
        for ni in network_interfaces:
            ec2.delete_network_interface(NetworkInterfaceId=ni['NetworkInterfaceId'])
            print(f"Network Interface {ni['NetworkInterfaceId']} deleted successfully.")

        rds_client.delete_db_subnet_group(DBSubnetGroupName=db_subnet_group_name)
        print(f"DB Subnet Group '{db_subnet_group_name}' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting DB Subnet Group: {e}")
        

def delete_security_group(sg_name):
    try:
        sg_id = get_from_ssm(f'/python/{sg_name}_sg_id')
        if not sg_id:
            print(f"Security Group {sg_name} ID not found in SSM. Skipping deletion.")
            return

        ec2.delete_security_group(GroupId=sg_id)
        print(f"Security Group {sg_id} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Security Group: {e}")
        

def delete_internet_gateway():
    try:
        igw_id = get_from_ssm('/python/internet_gateway_id')
        if not igw_id:
            print("Internet Gateway ID not found in SSM. Skipping deletion.")
            return
        
         # Unmapping public IP addresses
        addresses = ec2.describe_addresses(Filters=[{'Name': 'domain', 'Values': ['vpc']}])['Addresses']
        for address in addresses:
            ec2.release_address(AllocationId=address['AllocationId'])
            print(f"Elastic IP {address['PublicIp']} released successfully.")

        vpc_id = get_from_ssm('/python/vpc_id')
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        print(f"Internet Gateway {igw_id} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Internet Gateway: {e}")
        

def delete_route_53_record():
    try:
        h_z= 'Z01063533B95XIB5GVOHL'
        alb_hz = get_from_ssm('/python/alb_hz')
        alb_dns = get_from_ssm('/python/alb_dns')
        # Getting the existing record set
        existing_record = route53.list_resource_record_sets(
            HostedZoneId=h_z,
            StartRecordName='dev.clixx-samuel.com',
            StartRecordType='A',
            MaxItems="1"
        )
        
        # Checking if the record exists and matches the expected values
        if existing_record['ResourceRecordSets']:
            current_record = existing_record['ResourceRecordSets'][0]
            
            route53.change_resource_record_sets(
                HostedZoneId=h_z,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': current_record
                            }
                        ]
                    }
                )

        print(f"Route 53 record for 'dev.clixx-samuel.com' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Route 53 record: {e}")
        

def delete_nat_gateway():
    try:
        nat_gateway_id = get_from_ssm('/python/nat_gateway_id')
        if not nat_gateway_id:
            print("NAT Gateway ID not found in SSM. Skipping deletion.")
            return

        ec2.delete_nat_gateway(NatGatewayId=nat_gateway_id)
        print(f"NAT Gateway {nat_gateway_id} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting NAT Gateway: {e}")
        

def delete_route_table(route_type):
    try:
        route_table_id = get_from_ssm(f'/python/route_table_id_{route_type}')
        if not route_table_id:
            print(f"Route Table {route_type} ID not found in SSM. Skipping deletion.")
            return
        
        # Disassociating route table from any subnets
        associations = ec2.describe_route_tables(RouteTableIds=[route_table_id])['RouteTables'][0]['Associations']
        for association in associations:
            if not association['Main']:  # Skipping the main route table association
                ec2.disassociate_route_table(AssociationId=association['RouteTableAssociationId'])
                print(f"Disassociated Route Table {route_table_id} from Subnet.")
                
        ec2.delete_route_table(RouteTableId=route_table_id)
        print(f"Route Table {route_table_id} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting Route Table: {e}")
        

def delete_subnet(subnet_name):
    try:
        time.sleep(70)
        subnet_id = get_from_ssm(f'/python/{subnet_name.lower().replace(" ", "_")}_subnet_id')
        if not subnet_id:
            print(f"Subnet {subnet_name} ID not found in SSM. Skipping deletion.")
            return
        
        ec2.delete_subnet(SubnetId=subnet_id)
        print(f"Subnet {subnet_id} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting subnet: {e}")
        

def delete_vpc():
    try:
        time.sleep(15)
        vpc_id = get_from_ssm('/python/vpc_id')
        if not vpc_id:
            print("VPC ID not found in SSM. Skipping VPC deletion.")
            return
        
        ec2.delete_vpc(VpcId=vpc_id)
        print(f"VPC {vpc_id} deleted successfully.")
    except ClientError as e:
        print(f"Error deleting VPC: {e}")

def delete_all_resources():
    # Delete resources in reverse order of their creation
    delete_db_instance()
    delete_nat_gateway()
    delete_subnet('public_subnet_1')
    delete_subnet('private_subnet_2')
    delete_subnet('public_subnet_2')
    delete_subnet('private_subnet_1')
    delete_internet_gateway()
    delete_route_table('public')
    delete_route_table('private')
    delete_vpc()
    delete_key_pair()
    delete_route_53_record()
    delete_application_load_balancer()
    delete_target_group()
    delete_efs_mount_target()
    delete_efs_file_system()  
    delete_auto_scaling_group()
    delete_launch_template()
    delete_db_subnet_group()
    delete_security_group('db')
    delete_security_group('web')

if __name__ == "__main__":
    delete_all_resources()
