# docker/Dockerfile
FROM python:3.10-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
   build-essential \
   yara \
&& rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
COPY app.py ./
COPY certs ./certs/
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8501
CMD ["streamlit", "run", "app.py", \
    "--server.port=8501", \
    "--server.enableCORS=true", \
    "--server.headless=true", \
    "--server.runOnSave=true", \
    "--server.sslCertFile=/app/certs/cert.pem", \
    "--server.sslKeyFile=/app/certs/key.pem"]
