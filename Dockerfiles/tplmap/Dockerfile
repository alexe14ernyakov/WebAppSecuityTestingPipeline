FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/epinna/tplmap.git /opt/tplmap

WORKDIR /opt/tplmap
RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "tplmap.py"]
