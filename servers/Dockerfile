FROM ubuntu:22.04
ARG MBEDTLS=
ARG PRIVKEY=
ARG CERT=
ARG STAGE=
ARG NUM_SERVERS=
RUN apt-get -y update 
RUN apt-get install -y build-essential
RUN apt-get install -y python3
COPY ${MBEDTLS} /etc/mbedtls
WORKDIR /etc/mbedtls
RUN make programs
COPY ${PRIVKEY} /etc/priv.key.pem
COPY ${CERT} /etc/cert.crt
ENV STAGE_ARG ${STAGE}
ENV NUM_SERVERS_ARG ${NUM_SERVERS}
CMD /etc/mbedtls/programs/ssl/ssl_server3 key_file=/etc/priv.key.pem crt_file=/etc/cert.crt force_version=tls12 force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256 psk=abcdef stage=${STAGE_ARG} num_servers=${NUM_SERVERS_ARG}