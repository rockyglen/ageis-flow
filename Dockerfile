# Use Python slim image to keep it small
FROM python:3.11-slim

# 1. Install System Dependencies (Terraform, AWS CLI, curl, unzip)
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Terraform
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y terraform

# Install AWS CLI (v2)
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf aws awscliv2.zip

# 2. Set Working Directory
WORKDIR /app

# 3. Install Python Dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn boto3 langchain langchain-google-genai pydantic python-dotenv

# 4. Copy Application Code
# We copy specific folders to keep the image clean
COPY infrastructure/ ./infrastructure/
COPY agents/ ./agents/
COPY mcp_server/ ./mcp_server/
COPY main.py .
COPY server.py .

# 5. Initialize DB (Optional, ensures file exists)
RUN python -c "from mcp_server.database import init_db; init_db()"

# 6. Expose the API Port
EXPOSE 8000

# 7. Start the Server (Unbuffered for live logs)
CMD ["python", "-u", "server.py"]