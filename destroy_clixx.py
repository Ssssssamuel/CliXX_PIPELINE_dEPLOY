#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError
import time

# Global Variables
AWS_REGION = 'us-east-1'

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

# Retrieving parameters from SSM
def get_ssm_parameter(**args):
    var1 = args.get('var1')
    try:
        response = ssm.get_parameter(Name=var1)
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Error retrieving SSM parameter {var1}: {str(e)}")
        return None
    
 # Deleting Keypair
def delete_key_pair():
    try:
        ec2.delete_key_pair(KeyName='my-key-pair')
        print("Key Pair 'my-key-pair' deleted successfully.")
    except ClientError as e:
        print(f"Error deleting key pair: {str(e)}")

        

# Deleting Route 53 record with dynamic domain name
def delete_route53_record(**args):
    var1 = args.get('var1')
    try:
        H_Z = 'Z01063533B95XIB5GVOHL' 
        LB_DNS = get_ssm_parameter(var1='/myapp/{}'.format(var1))

        # Getting the existing record set
        existing_record = route53.list_resource_record_sets(
            HostedZoneId=H_Z,
            StartRecordName='dev.clixx-samuel.com',
            StartRecordType='A',
            MaxItems="1"
        )

        # Checking if the record exists and matches the expected values
        if existing_record['ResourceRecordSets']:
            current_record = existing_record['ResourceRecordSets'][0]
            current_dns_name = current_record.get('AliasTarget', {}).get('DNSName')

            # Proceeding with deleting record
            response = route53.change_resource_record_sets(
                HostedZoneId=H_Z,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': current_record
                        }
                    ]
                }
            )
            print(f"Deleted Route 53 record: {response}")
        else:
            print("No matching Route 53 record found.")
            
    except ClientError as e:
        print(f"Error deleting Route 53 record: {str(e)}")


# Deleting load balancer and target group
def delete_load_balancer_and_target_group(**args):
    var1 = args.get('var1')
    var2 = args.get('var2')
    try:
        L_B = get_ssm_parameter(var1='/myapp/{}'.format(var1))
        if not L_B:
            print(f"Could not retrieve Load Balancer ARN, skipping deletion.")
            return

        # Deleting listeners associated with the load balancer
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=L_B)
        for listener in listeners['Listeners']:
            elbv2_client.delete_listener(ListenerArn=listener['ListenerArn'])
            print(f"Deleted listener: {listener['ListenerArn']}")

        # Deleting the load balancer
        elbv2_client.delete_load_balancer(LoadBalancerArn=L_B)
        print(f"Deleted load balancer: {L_B}")

        # Deleting the target group
        T_G = get_ssm_parameter(var1='/myapp/{}'.format(var2))
        if not T_G:
            print(f"Could not retrieve Target Group ARN, skipping deletion.")
            return

        elbv2_client.delete_target_group(TargetGroupArn=T_G)
        print(f"Deleted target group: {T_G}")

    except ClientError as e:
        print(f"Error deleting load balancer or target group: {str(e)}")

# Deleting EFS along with its mount targets
def delete_efs(**args):
    var1 = args.get('var1')
    try:
        # Getting EFS ID from SSM parameter store
        F_S = get_ssm_parameter(var1='/myapp/{}'.format(var1))
        if not F_S:
            print(f"Could not retrieve EFS ID, skipping deletion.")
            return

        # Listing and deleting mount targets for EFS
        mount_targets = efs.describe_mount_targets(FileSystemId=F_S)
        for mount_target in mount_targets['MountTargets']:
            mount_target_id = mount_target['MountTargetId']
            efs.delete_mount_target(MountTargetId=mount_target_id)
            print(f"Deleted mount target: {mount_target_id}")

        time.sleep(15)
        
        # Deleting EFS file system
        efs.delete_file_system(FileSystemId=F_S)
        print(f"Deleted EFS: {F_S}")

    except ClientError as e:
        print(f"Error deleting EFS: {str(e)}")


# Deleting security group
def delete_security_group(**args):
    var1 = args.get('var1')
    try:
        S_G = get_ssm_parameter(var1='/myapp/{}'.format(var1))
        if not S_G:
            print(f"Could not retrieve security group ID, skipping deletion.")
            return

        ec2.delete_security_group(GroupId=S_G)
        print(f"Deleted security group: {S_G}")
    except ClientError as e:
        print(f"Error deleting security group: {str(e)}")

# Deleting RDS instance
def delete_rds_instance():
    try:
        DB_id = get_ssm_parameter(var1 = '/myapp/DB_id') 
        if not DB_id:
            print(f"Could not retrieve RDS instance ID, skipping deletion.")
            return

        rds_client.delete_db_instance(
            DBInstanceIdentifier=DB_id,
            SkipFinalSnapshot=True 
        )
        print(f"Deleted RDS instance: {DB_id}")
    except ClientError as e:
        print(f"Error deleting RDS instance: {str(e)}")

# Deleting launch template
def delete_launch_template():
    try:
        L_T = 'my-launch-template'

        ec2.delete_launch_template(LaunchTemplateName=L_T)
        print(f"Deleted launch template: {L_T}")
    except ClientError as e:
        print(f"Error deleting Launch Template: {str(e)}")

# Deleting Auto Scaling Group
def delete_auto_scaling_group():
    try:   
        A_S_G = 'my-auto-scaling-group'
        # Setting desired capacity to 0 to terminate instances
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName= A_S_G,
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0
        )
        print(f"Set desired capacity to 0 for Auto Scaling Group: {'my-auto-scaling-group'}")
        
        time.sleep(100)
        # Deleting Auto Scaling Group
        autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=A_S_G,
            ForceDelete=True
        )
        print(f"Deleted Auto Scaling Group: {A_S_G}")
        
    except ClientError as e:
        print(f"Error deleting Auto Scaling Group: {str(e)}")


if __name__ == "__main__":
    # Calling deletion functions
    delete_rds_instance()
    delete_route53_record(var1='lb_dns')
    delete_load_balancer_and_target_group(var1='lb_arn', var2='target_group_arn')
    delete_efs(var1='efs_id')
    delete_launch_template()
    delete_auto_scaling_group()
    delete_key_pair()
    delete_security_group(var1='security_group_id')
