FROM python:3.11-slim

RUN pip install --no-cache-dir sslyze

RUN mkdir -p /results

WORKDIR /app

ENTRYPOINT ["sslyze"]
