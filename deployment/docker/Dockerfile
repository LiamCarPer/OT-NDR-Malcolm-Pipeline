# NDR pipeline image: Python, tshark, and the repository.
#
# tshark is a runtime dependency, not a test dependency: the DPI profiler reads
# the capture with it. DEBIAN_FRONTEND is set because the tshark package asks a
# debconf question about letting non-superusers capture packets, and a build that
# hangs on it is a build that fails in CI only.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    MALCOLM_PCAP_DIR=/malcolm-pcap

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY automation/ automation/
COPY pcaps/ pcaps/
COPY detection-engineering/ detection-engineering/
COPY incident-response/ incident-response/
COPY metrics/ metrics/

# Reports and the audit log are written into the repository, so mount it
# read-write and run as the invoking user rather than as root:
#   docker run --rm -u $(id -u):$(id -g) -v "$PWD:/app" ...
ENTRYPOINT ["python3", "automation/malcolm_ingest.py"]
CMD ["--help"]
