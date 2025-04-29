FROM perl:latest

RUN apt-get update && apt-get install -y \
    git \
    openssl \
    make \
    build-essential \
    libssl-dev \
    cpanminus

RUN git clone https://github.com/sullo/nikto.git /opt/nikto

RUN cpanm --notest Net::SSLeay \
    && cpanm --notest IO::Socket::SSL \
    && cpanm --notest LWP::UserAgent

WORKDIR /opt/nikto/program

ENTRYPOINT ["perl", "nikto.pl"]
