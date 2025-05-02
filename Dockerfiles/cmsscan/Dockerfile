FROM python:3.11-slim

RUN apt-get update && apt-get install -y git

RUN git clone https://github.com/ajinabraham/CMSScan.git /opt/cmsscan

RUN pip install -r /opt/cmsscan/requirements.txt

WORKDIR /scan

RUN ln -s /opt/cmsscan/cmsscan.py /usr/local/bin/cmsscan

RUN chmod +x /opt/cmsscan/cmsscan.py

ENTRYPOINT ["cmsscan"]
