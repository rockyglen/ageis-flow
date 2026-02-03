##mcp_server/main.py

import boto3
import json
import time
import requests
import datetime
import os
from mcp.server.fastmcp import FastMCP
from botocore.exceptions import ClientError
from mcp_server.database import update_status

# Initialize the MCP Server
mcp = FastMCP("Aegis-Hands-Full-Defense")

TARGET_REGION = "us-east-1"
UI_SERVER_URL = os.environ.get("UI_SERVER_URL", "http://localhost:3000")


def get_boto_client(service_name):
    """Helper to ensure we always target the vulnerable region."""
    return boto3.client(service_name, region_name=TARGET_REGION)


def log_to_ui(message: str):
    """Helper to send logs to the React Dashboard and stdout."""
    print(f"[AGENT LOG]: {message}")
    try:
        requests.post(
            f"{UI_SERVER_URL}/log",
            json={"source": "AGENT", "message": message},
            timeout=2,
        )
    except:
        pass


# =============================================================================
# 0. AGENT SELF-CHECK
# =============================================================================


@mcp.tool()
def get_agent_identity() -> str:
    """Verifies the Agent's credentials and target region before acting."""
    sts = get_boto_client("sts")
    try:
        id_info = sts.get_caller_identity()
        return f"Agent Active: {id_info['Arn']} | Target Region: {TARGET_REGION}"
    except Exception as e:
        return f"CRITICAL ERROR: Agent cannot authenticate. {str(e)}"


# =============================================================================
# 1. IAM DOMAIN
# =============================================================================


@mcp.tool()
def list_iam_users() -> str:
    """Lists all IAM users."""
    iam = get_boto_client("iam")
    try:
        paginator = iam.get_paginator("list_users")
        users = [u["UserName"] for page in paginator.paginate() for u in page["Users"]]
        return f"Found Users: {', '.join(users)}"
    except Exception as e:
        return f"Error listing users: {str(e)}"


@mcp.tool()
def list_attached_user_policies(username: str) -> str:
    """Lists managed and inline policies."""
    iam = get_boto_client("iam")
    try:
        policies = []
        for page in iam.get_paginator("list_attached_user_policies").paginate(
            UserName=username
        ):
            for policy in page["AttachedPolicies"]:
                policies.append(f"Managed: {policy['PolicyName']}")
        for page in iam.get_paginator("list_user_policies").paginate(UserName=username):
            for policy_name in page["PolicyNames"]:
                policies.append(f"Inline: {policy_name}")

        return (
            f"User '{username}' Policies: {', '.join(policies)}"
            if policies
            else f"User '{username}' has no attached policies."
        )
    except Exception as e:
        return f"Error checking policies for {username}: {str(e)}"


@mcp.tool()
def restrict_iam_user(user_name: str) -> str:
    """
    REMEDIATION: Nukes permissions and applies ReadOnlyAccess.
    """
    iam = get_boto_client("iam")
    log = []
    read_only_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    try:
        # Detach Managed
        for page in iam.get_paginator("list_attached_user_policies").paginate(
            UserName=user_name
        ):
            for policy in page["AttachedPolicies"]:
                iam.detach_user_policy(
                    UserName=user_name, PolicyArn=policy["PolicyArn"]
                )
                log.append(f"Detached: {policy['PolicyName']}")
        # Remove from Groups
        for page in iam.get_paginator("list_groups_for_user").paginate(
            UserName=user_name
        ):
            for group in page["Groups"]:
                iam.remove_user_from_group(
                    UserName=user_name, GroupName=group["GroupName"]
                )
                log.append(f"Removed from group: {group['GroupName']}")
        # Delete Inline
        for page in iam.get_paginator("list_user_policies").paginate(
            UserName=user_name
        ):
            for policy_name in page["PolicyNames"]:
                iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                log.append(f"Deleted inline policy: {policy_name}")
        # Attach ReadOnly
        iam.attach_user_policy(UserName=user_name, PolicyArn=read_only_arn)
        log.append("Attached ReadOnlyAccess")

        update_status("check_iam","SAFE")

        return f"SUCCESS: {user_name} neutralized.\nACTIONS: {'; '.join(log)}"
    except Exception as e:
        return f"ERROR: Failed to restrict {user_name}: {str(e)}"


# =============================================================================
# 2. STORAGE DOMAIN
# =============================================================================


@mcp.tool()
def list_s3_buckets() -> str:
    """Lists all bucket names."""
    s3 = get_boto_client("s3")
    try:
        response = s3.list_buckets()
        names = [b["Name"] for b in response.get("Buckets", [])]
        return f"Buckets: {', '.join(names)}"
    except Exception as e:
        return f"Error listing buckets: {str(e)}"


@mcp.tool()
def check_s3_security(bucket_name: str) -> dict:
    """Checks for public access blocks."""
    s3 = get_boto_client("s3")
    try:
        res = s3.get_public_access_block(Bucket=bucket_name)
        c = res["PublicAccessBlockConfiguration"]
        is_public = not all(
            [
                c["BlockPublicAcls"],
                c["IgnorePublicAcls"],
                c["BlockPublicPolicy"],
                c["RestrictPublicBuckets"],
            ]
        )
        return {"bucket": bucket_name, "is_public_risk": is_public}
    except ClientError:
        return {
            "bucket": bucket_name,
            "is_public_risk": True,
            "note": "No Public Access Block found.",
        }
    except Exception as e:
        return {"bucket": bucket_name, "error": str(e)}


@mcp.tool()
def remediate_s3(bucket_name: str) -> str:
    """
    REMEDIATION: Blocks ALL public access.
    """
    s3 = get_boto_client("s3")
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        update_status("check_s3","SAFE")
        return f"SUCCESS: Public access blocked for bucket '{bucket_name}'."
    except Exception as e:
        return f"ERROR: Failed to remediate S3: {str(e)}"


# =============================================================================
# 3. NETWORK DOMAIN
# =============================================================================


@mcp.tool()
def audit_vpc_network() -> list:
    """
    DISCOVERY: Checks for VPC Flow Logs.
    """
    ec2 = get_boto_client("ec2")
    network_findings = []
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]
            network_findings.append(
                {
                    "VpcId": vpc_id,
                    "FlowLogs": "ENABLED" if flow_logs else "DISABLED (Risk)",
                    "CidrBlock": vpc.get("CidrBlock", "Unknown"),
                }
            )
        return network_findings
    except Exception as e:
        return [f"Network Audit Error: {str(e)}"]


@mcp.tool()
def remediate_vpc_flow_logs(vpc_id: str) -> str:
    """
    REMEDIATION: Creates CloudWatch Log Group, IAM Role, and enables Flow Logs.
    """
    ec2 = get_boto_client("ec2")
    logs = get_boto_client("logs")
    iam = get_boto_client("iam")

    role_name = "AegisFlowLogRole"
    log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"

    try:
        # 1. Create Log Group
        try:
            logs.create_log_group(logGroupName=log_group_name)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass

        # 2. Create IAM Role
        try:
            assume_role = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            )
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_role)

            policy = json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams",
                            ],
                            "Resource": "*",
                        }
                    ],
                }
            )
            iam.put_role_policy(
                RoleName=role_name, PolicyName="FlowLogPolicy", PolicyDocument=policy
            )
            time.sleep(5)
        except iam.exceptions.EntityAlreadyExistsException:
            pass

        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

        # 3. Enable Flow Logs
        ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=role_arn,
        )
        update_status("check_vpc","SAFE")
        return f"SUCCESS: Flow Logs enabled for {vpc_id}."
    except Exception as e:
        return f"ERROR enabling flow logs: {str(e)}"


@mcp.tool()
def audit_security_groups() -> list:
    """
    DISCOVERY: Scans for 0.0.0.0/0 ingress.
    """
    ec2 = get_boto_client("ec2")
    risky_groups = []
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for perm in sg["IpPermissions"]:
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        risky_groups.append(
                            {
                                "GroupId": sg["GroupId"],
                                "Port": perm.get("FromPort", "All"),
                                "Protocol": perm.get("IpProtocol"),
                                "Risk": "OPEN TO WORLD (0.0.0.0/0)",
                            }
                        )
    except Exception as e:
        return [f"Error auditing SGs: {str(e)}"]
    return risky_groups if risky_groups else ["No risky Security Groups found."]


@mcp.tool()
def revoke_security_group_ingress(
    group_id: str, protocol: str, from_port: int, to_port: int
) -> str:
    """
    REMEDIATION: Revokes a specific ingress rule. Requires exact match.
    """
    ec2 = get_boto_client("ec2")
    try:
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            CidrIp="0.0.0.0/0",
            FromPort=from_port,
            ToPort=to_port,
            IpProtocol=protocol,
        )
        update_status("check_ssh","SAFE")
        return f"SUCCESS: Revoked 0.0.0.0/0 on port {from_port} for SG {group_id}."
    except Exception as e:
        return f"ERROR: Failed to revoke ingress on {group_id}: {str(e)}"


# =============================================================================
# 4. COMPUTE DOMAIN
# =============================================================================


@mcp.tool()
def audit_ec2_vulnerabilities() -> list:
    """
    DISCOVERY: Scans running instances for IMDSv1 and Unencrypted Root Volumes.
    """
    ec2 = get_boto_client("ec2")
    findings = []
    try:
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )["Reservations"]
        for res in reservations:
            for inst in res["Instances"]:
                imds_status = inst.get("MetadataOptions", {}).get(
                    "HttpTokens", "optional"
                )

                root_dev = inst.get("RootDeviceName")
                encrypted = False
                for bdm in inst.get("BlockDeviceMappings", []):
                    if bdm["DeviceName"] == root_dev:
                        encrypted = bdm.get("Ebs", {}).get("Encrypted", False)

                findings.append(
                    {
                        "InstanceId": inst["InstanceId"],
                        "PublicIP": inst.get("PublicIpAddress", "None"),
                        "IMDSv1_Enabled": (imds_status == "optional"),
                        "RootVolume_Encrypted": encrypted,
                    }
                )
        return findings if findings else ["No running instances found."]
    except Exception as e:
        return [f"Audit Error: {str(e)}"]


@mcp.tool()
def enforce_imdsv2(instance_id: str) -> str:
    """
    REMEDIATION: Enforces IMDSv2.
    """
    ec2 = get_boto_client("ec2")
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled"
        )
        update_status("check_ec2","SAFE")
        return f"SUCCESS: IMDSv2 enforced on {instance_id}."
    except Exception as e:
        return f"ERROR: Failed to enforce IMDSv2 on {instance_id}: {str(e)}"


@mcp.tool()
def stop_instance(instance_id: str) -> str:
    """
    REMEDIATION: Stops an instance (Quarantine).
    """
    ec2 = get_boto_client("ec2")
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
        update_status("check_ec2","SAFE")
        return f"SUCCESS: Instance {instance_id} stopped (Quarantined)."
    except Exception as e:
        return f"ERROR: Failed to stop instance {instance_id}: {str(e)}"


# =============================================================================
# 5. FORENSICS
# =============================================================================


@mcp.tool()
def get_resource_owner(resource_name: str) -> str:
    """
    FORENSICS: Queries CloudTrail for creation events.
    """
    client = get_boto_client("cloudtrail")
    try:
        response = client.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_name}
            ],
            MaxResults=10,
        )
        for event in response.get("Events", []):
            if any(x in event.get("EventName", "") for x in ["Create", "Run", "Put"]):
                return f"CloudTrail: '{resource_name}' touched by {event.get('Username')} ({event.get('EventName')})."
        return f"Trace: No recent events for '{resource_name}'."
    except Exception as e:
        return f"Forensic Error: {str(e)}"


# @mcp.tool()
# def archive_security_incident(report_summary: str) -> str:
#     """Saves findings to JSON."""
#     timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
#     filename = f"aegis_audit_{timestamp}.json"
#     try:
#         with open(filename, "w") as f:
#             json.dump({"timestamp": timestamp, "report": report_summary}, f, indent=4)
#         return f"SUCCESS: Report saved to {filename}."
#     except Exception as e:
#         return f"ERROR: {str(e)}"

if __name__ == "__main__":
    mcp.run()
