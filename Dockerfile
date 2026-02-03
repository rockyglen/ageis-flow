# 1. Use Python slim image to keep the image size manageable
FROM python:3.11-slim

# 2. Install System Dependencies
# Need gnupg and lsb-release for the Hashicorp repository setup
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    gnupg \
    lsb-release \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# 3. Install Terraform
# Adding the official Hashicorp repo ensures we get a stable, modern version
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y terraform

# 4. Install Google Cloud SDK
# Required for the agent to authenticate and manage cloud resources
RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update && apt-get install -y google-cloud-cli

# 5. Set Working Directory
WORKDIR /app

# 6. Install Python Dependencies
# We do this before copying the full code to utilize Docker layer caching
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn google-cloud-storage langchain langchain-google-genai pydantic python-dotenv mcp boto3 psycopg2-binary

# 7. Copy Infrastructure and Initialize Terraform
# This is the "Fix": We copy the TF files and RUN init during the build.
# This downloads the Google and Null providers into the image itself.
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
ENV PORT=8080
EXPOSE 8080
# -u flag ensures Python logs are unbuffered (visible in real-time in 'docker logs')
CMD ["python", "-u", "server.py"]