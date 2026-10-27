FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pcap_evidence.py check_evidence.py ./

ENTRYPOINT ["python", "pcap_evidence.py", "--db", "/data/mits.db", "--pcap-dir", "/pcap"]
