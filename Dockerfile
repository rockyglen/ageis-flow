# 1. Use Python slim image to keep the image size manageable
FROM python:3.11-slim

# 2. Install System Dependencies
# Need gnupg and lsb-release for the Hashicorp repository setup
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# 3. Install Terraform
# Adding the official Hashicorp repo ensures we get a stable, modern version
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y terraform

# 4. Install AWS CLI (v2)
# Required for the agent to authenticate and manage cloud resources
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf aws awscliv2.zip

# 5. Set Working Directory
WORKDIR /app

# 6. Install Python Dependencies
# We do this before copying the full code to utilize Docker layer caching
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn boto3 langchain langchain-google-genai pydantic python-dotenv

# 7. Copy Infrastructure and Initialize Terraform
# This is the "Fix": We copy the TF files and RUN init during the build.
# This downloads the AWS and Null providers into the image itself.
COPY infrastructure/ ./infrastructure/
RUN terraform -chdir=infrastructure/terraform init

# 8. Copy remaining Application Code
COPY agents/ ./agents/
COPY mcp_server/ ./mcp_server/
COPY main.py .
COPY server.py .

# 9. Initialize the SQLite Database
# Ensures the 'Vulnerable' vs 'Secure' status tracking is ready
RUN python -c "from mcp_server.database import init_db; init_db()"

# 10. Final Configuration
EXPOSE 8000
# -u flag ensures Python logs are unbuffered (visible in real-time in 'docker logs')
CMD ["python", "-u", "server.py"]