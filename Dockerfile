# Use Python slim image to keep it small
FROM python:3.11-slim

# 1. Install System Dependencies 
# ADDED: gnupg (for gpg keys), lsb-release (to find OS version)
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Terraform
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y terraform

# 3. Install AWS CLI (v2)
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf aws awscliv2.zip

# 4. Set Working Directory
WORKDIR /app

# 5. Install Python Dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn boto3 langchain langchain-google-genai pydantic python-dotenv

# 6. Copy Application Code
COPY infrastructure/ ./infrastructure/
RUN terraform -chdir=infrastructure/terraform init
COPY agents/ ./agents/
COPY mcp_server/ ./mcp_server/
COPY main.py .
COPY server.py .

# 7. Initialize DB
RUN python -c "from mcp_server.database import init_db; init_db()"

# 8. Expose Port & Start
EXPOSE 8000
CMD ["python", "-u", "server.py"]