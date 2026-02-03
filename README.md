AEGIS-FLOW: Secure Agentic Orchestration
AEGIS-FLOW is an autonomous security orchestration system designed to detect and remediate infrastructure vulnerabilities in AWS environments. It utilizes an agentic workflow powered by LangGraph to perform automated security audits, identify risks, and execute remediations with a human-in-the-loop safety gate.

Project Architecture
Infrastructure (Lab): A Terraform-managed AWS environment that intentionally deploys insecure resources, such as S3 buckets with public access, over-privileged IAM users, and EC2 instances with IMDSv1 enabled.

Agentic Brain: A LangGraph-based state machine that manages the logic for auditing and remediation.

Execution Layer: An MCP (Model Context Protocol) server that provides the agent with specific tools to interact with AWS services like IAM, S3, EC2, and CloudTrail.

Dashboard: A Next.js frontend to visualize agent logs and remediation status.
