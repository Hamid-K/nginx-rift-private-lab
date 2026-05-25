FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    ca-certificates \
    clang \
    curl \
    git \
    libpcre2-dev \
    libssl-dev \
    make \
    python3 \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ARG NGINX_REF=98fc3bb78

RUN git clone https://github.com/nginx/nginx.git /nginx-src \
    && cd /nginx-src \
    && git checkout "${NGINX_REF}"

RUN cd /nginx-src \
    && ./auto/configure \
        --builddir=build \
        --with-cc=clang \
        --with-cc-opt='-O1 -g -fno-omit-frame-pointer -fsanitize=address -DNGX_DEBUG_PALLOC' \
        --with-ld-opt='-fsanitize=address' \
        --with-http_ssl_module \
        --with-http_v2_module \
        --without-http_gzip_module \
    && make -j"$(nproc)"

COPY run-nginx.sh /usr/local/bin/run-nginx
RUN chmod +x /usr/local/bin/run-nginx

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/run-nginx"]

