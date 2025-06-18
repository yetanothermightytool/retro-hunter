# Image with Python
FROM python:3.10-slim
# Set working directory
WORKDIR /app
# Install updates
RUN apt-get update && apt-get install -y \
   build-essential \
   yara \
&& rm -rf /var/lib/apt/lists/*
# Copy data
COPY requirements.txt ./
COPY app.py ./
COPY file_index.db ./
COPY badfiles.db ./
COPY certs ./certs/
# Install Python Modules from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# Expose Port
EXPOSE 8501
# HTTPS Setup
CMD ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.enableCORS=true", \
    "--server.headless=true", \
    "--server.runOnSave=true", \
    "--server.sslCertFile=/app/certs/cert.pem", \
    "--server.sslKeyFile=/app/certs/key.pem"]
