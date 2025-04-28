FROM ruby:3.0

RUN apt-get update && apt-get install -y \
    libgmp-dev \
    && gem install bundler

RUN git clone https://github.com/urbanadventurer/whatweb.git /whatweb

WORKDIR /whatweb
RUN bundle install

ENTRYPOINT ["ruby", "whatweb"]
