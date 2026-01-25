############################################
# AEGIS-FLOW | INTENTIONALLY INSECURE LAB
# Purpose: Security Detection & Remediation
# Region: us-east-1
############################################

provider "aws" {
  region = "us-east-1"
}

# =============================================================================
# 1. IAM VULNERABILITY: OVER-PRIVILEGED USER
# =============================================================================

data "aws_iam_user" "dev_user" {
  user_name = "dev-user-01"
}

# Vulnerability: Attaching Admin Access
resource "aws_iam_user_policy_attachment" "risky_user_admin" {
  user       = data.aws_iam_user.dev_user.user_name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_policy_attachment" "risky_user_readonly" {
  user       = data.aws_iam_user.dev_user.user_name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ⚠️ CRITICAL: Generating Keys for the "Crime" script
resource "aws_iam_access_key" "dev_user_key" {
  user = data.aws_iam_user.dev_user.user_name
}

# =============================================================================
# 2. NETWORK INFRASTRUCTURE
# =============================================================================

resource "aws_vpc" "public_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "aegis-public-vpc-no-logs"
    Risk = "CRITICAL"
  }
}

resource "aws_internet_gateway" "public_gw" {
  vpc_id = aws_vpc.public_vpc.id
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.public_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  
  # FIX: Hardcoded AZ to prevent 't3.micro not supported' errors
  availability_zone       = "us-east-1a"

  tags = {
    Name = "aegis-public-subnet"
  }
}

resource "aws_route" "public_route" {
  route_table_id         = aws_vpc.public_vpc.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.public_gw.id
}

# PRIVATE VPC (Secondary target)
resource "aws_vpc" "private_vpc" {
  cidr_block = "10.1.0.0/16"

  tags = {
    Name = "aegis-private-vpc-no-logs"
    Risk = "MEDIUM"
  }
}

# =============================================================================
# 3. BASELINE STORAGE (The Control Group)
# =============================================================================

resource "aws_s3_bucket" "insecure_bucket" {
  bucket_prefix = "aegis-audit-target-"
  force_destroy = true

  tags = {
    Risk = "CRITICAL"
  }
}

resource "aws_s3_bucket_public_access_block" "insecure_bucket_access" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# =============================================================================
# 4. EC2 INFRASTRUCTURE
# =============================================================================

resource "aws_security_group" "vulnerable_sg" {
  name   = "aegis-open-sg"
  vpc_id = aws_vpc.public_vpc.id

  # Egress allow all
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # NOTE: Ingress is CLOSED by default. The "Crime Script" will force it open.
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  owners = ["amazon"]
}

resource "aws_instance" "vulnerable_ec2" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_subnet.id
  vpc_security_group_ids      = [aws_security_group.vulnerable_sg.id]
  associate_public_ip_address = true

  # Secure by default (will be downgraded by crime script)
  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "aegis-vulnerable-ec2"
  }
}

# =============================================================================
# 5. THE CRIME (Insider Threat Simulation)
# =============================================================================

resource "null_resource" "insider_threat_simulation" {
  # FIX: Ensure user has permissions BEFORE running the crime script
  depends_on = [
    aws_iam_user_policy_attachment.risky_user_admin,
    aws_instance.vulnerable_ec2
  ]

  triggers = {
    key_id = aws_iam_access_key.dev_user_key.id
  }

  # CREATION: Executed as dev-user-01 to generate accurate CloudTrail logs
  provisioner "local-exec" {
    environment = {
      AWS_ACCESS_KEY_ID     = aws_iam_access_key.dev_user_key.id
      AWS_SECRET_ACCESS_KEY = aws_iam_access_key.dev_user_key.secret
      AWS_DEFAULT_REGION    = "us-east-1"
      BUCKET_NAME           = "aegis-rogue-bucket-static-demo"
    }

    command = <<EOT
      # Fail immediately if any command fails
      set -e 
      
      echo "⏳ Waiting 20s for IAM keys to propagate (avoiding InvalidToken error)..."
      sleep 20

      echo "😈 SIMULATING INSIDER THREAT: Logging in as dev-user-01..."
      
      # --- CRIME 1: S3 VULNERABILITY ---
      # 1. Create Bucket
      aws s3api create-bucket --bucket $BUCKET_NAME
      # 2. Disable Public Block
      aws s3api delete-public-access-block --bucket $BUCKET_NAME
      # 3. Tagging (Evidence)
      aws s3api put-bucket-tagging --bucket $BUCKET_NAME --tagging 'TagSet=[{Key=CreatedBy,Value=dev-user-01},{Key=Risk,Value=High}]'

      # --- CRIME 2: NETWORK VULNERABILITY ---
      # 4. Open Security Group (SSH 0.0.0.0/0)
      echo "🔓 Opening Security Group to the world..."
      aws ec2 authorize-security-group-ingress --group-id ${aws_security_group.vulnerable_sg.id} --protocol tcp --port 22 --cidr 0.0.0.0/0

      # --- CRIME 3: COMPUTE VULNERABILITY ---
      # 5. Downgrade IMDS (Enable IMDSv1)
      echo "🔓 Downgrading EC2 Metadata security..."
      aws ec2 modify-instance-metadata-options --instance-id ${aws_instance.vulnerable_ec2.id} --http-tokens optional --http-endpoint enabled

      echo "✅ CRIME SPREE COMPLETE: S3, Network, and Compute compromised by dev-user-01"
    EOT
  }

  # DESTRUCTION: Cleanup on 'terraform destroy'
  provisioner "local-exec" {
    when    = destroy
    command = "aws s3 rb s3://aegis-rogue-bucket-static-demo --force || echo 'Bucket already deleted or not found'"
  }
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "aegis_security_summary" {
  value = <<EOT
AEGIS-FLOW SECURITY AUDIT SUMMARY
--------------------------------
✔ IAM: Admin-level IAM user (dev-user-01)
✔ Network: Public VPC without flow logs
✔ Storage: Rogue Public S3 bucket created (Static Name)
✔ Compute: EC2 Instance downgraded to IMDSv1 & SSH Open

⚠️ INTENTIONALLY INSECURE ENVIRONMENT
EOT
}