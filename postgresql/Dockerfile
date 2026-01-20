FROM postgres:18
ENV LANG en_US.utf8

RUN apt-get update && \
    apt-get install -y postgresql-18-pgvector && \
    rm -rf /var/lib/apt/lists/*
