FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y tshark inotify-tools iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY wireshark_to_udm_parser.py /app/wireshark_to_udm_parser.py
COPY monitor_files.sh /app/monitor_files.sh

RUN chmod +x /app/monitor_files.sh

ENTRYPOINT ["/app/monitor_files.sh"]