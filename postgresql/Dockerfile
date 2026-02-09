FROM postgres:18

ENV LANG=en_US.utf8

RUN apt-get update && \
   apt-get upgrade -y && \
   apt-get install -y --no-install-recommends postgresql-18-pgvector && \
   rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
