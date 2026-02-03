# AEGIS-FLOW: Secure Agentic Orchestration

**AEGIS-FLOW** is an autonomous security orchestration system designed to detect and remediate infrastructure vulnerabilities in AWS environments. It leverages an **agentic workflow powered by LangGraph** to perform automated security audits, identify risks, and execute remediations with a **human-in-the-loop safety gate**.

---

## Project Architecture

### Infrastructure (Lab)
A Terraform-managed AWS environment that intentionally deploys insecure resources, including:
- Publicly accessible S3 buckets  
- Over-privileged IAM users  
- EC2 instances with IMDSv1 enabled  

### Agentic Brain
A **LangGraph-based state machine** that controls auditing, decision-making, and remediation flow.

### Execution Layer
An **MCP (Model Context Protocol) server** exposing tools for AWS service interaction:
- IAM  
- S3  
- EC2  
- CloudTrail  

### Dashboard
A **Next.js frontend** for visualizing agent logs, findings, and remediation status.

---

## Key Features

### Automated Auditing
Detects common misconfigurations such as:
- Open security groups  
- Unencrypted EBS volumes  
- Public S3 buckets  
- Disabled VPC Flow Logs  

### Forensics
Uses **CloudTrail** to determine:
- Which user created a vulnerable resource  
- Which event introduced the risk  

### Human-in-the-Loop Safety Gate
A mandatory approval step that prevents remediation until explicit human authorization is granted.

### Automated Remediation
Once approved, the agent can:
- Strip excessive IAM permissions  
- Enforce IMDSv2 on EC2 instances  
- Revoke risky ingress rules  

---

## Getting Started

### Prerequisites
- AWS CLI configured with appropriate credentials  
- Terraform installed  
- Python 3.11+  
- Node.js  

---

## Installation

### 1. Deploy the Lab Environment
```bash
cd infrastructure/terraform
terraform init
terraform apply
```

### 2. Set Up the MCP Server
```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python mcp_server/main.py
```

### 3. Launch the Dashboard
```bash
cd aegis-dashboard
npm install
npm run dev
```



### 4. Run the agent
```bash
python main.py
```

## Usage

  - Audit: Upon execution, the agent automatically initializes a security scan of the us-east-1 region.



