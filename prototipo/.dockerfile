FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y tshark inotify-tools iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY json2udm.py /app/json2udm.py
COPY ingestion_comm.py /app/ingestion_comm.py
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]