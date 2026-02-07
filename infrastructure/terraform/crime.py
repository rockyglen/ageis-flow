import boto3
import os
import sys
import time

def get_client(service):
    # Use specific keys if provided (Simulating Insider Threat)
    if os.environ.get('AWS_ACCESS_KEY_ID'):
        return boto3.client(
            service,
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
            region_name=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        )
    # Fallback to default credentials (for cleanup)
    return boto3.client(service, region_name=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))

def simulate_crime():
    bucket_name = os.environ.get('BUCKET_NAME')
    sg_id = os.environ.get('SG_ID')
    instance_id = os.environ.get('INSTANCE_ID')

    print("⏳ Waiting 20s for IAM keys to propagate...")
    time.sleep(20)
    print("😈 SIMULATING INSIDER THREAT: Logging in as dev-user-01...")

    # 1. S3 CRIME
    s3 = get_client('s3')
    try:
        print(f"Creating bucket {bucket_name}...")
        s3.create_bucket(Bucket=bucket_name)
        s3.delete_public_access_block(Bucket=bucket_name)
        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [{'Key': 'CreatedBy', 'Value': 'dev-user-01'}, {'Key': 'Risk', 'Value': 'High'}]}
        )
    except Exception as e:
        print(f"⚠️ S3 Crime Warning: {e}")

    # 2. NETWORK CRIME
    ec2 = get_client('ec2')
    print("🔓 Opening Security Group to the world...")
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpProtocol='tcp',
            FromPort=22,
            ToPort=22,
            CidrIp='0.0.0.0/0'
        )
    except Exception as e:
        print(f"⚠️ SG Crime Warning: {e}")

    # 3. COMPUTE CRIME
    print("🔓 Downgrading EC2 Metadata security...")
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',
            HttpEndpoint='enabled'
        )
    except Exception as e:
        print(f"⚠️ EC2 Crime Warning: {e}")

    print("✅ CRIME SPREE COMPLETE")

def cleanup():
    bucket_name = os.environ.get('BUCKET_NAME')
    if not bucket_name: return
    
    s3 = get_client('s3')
    try:
        # Empty bucket first
        objs = s3.list_objects_v2(Bucket=bucket_name).get('Contents', [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
        
        s3.delete_bucket(Bucket=bucket_name)
        print(f"Bucket {bucket_name} deleted.")
    except Exception as e:
        print(f"Cleanup Warning: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "destroy":
        cleanup()
    else:
        simulate_crime()