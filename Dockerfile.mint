FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
ENV LANG C.UTF-8
ENV GOROOT /usr/local/go
ENV GOPATH /usr/local/gopath
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH
ENV MINT_ROOT_DIR /mint
ENV MINT_RUN_CORE_DIR $MINT_ROOT_DIR/run/core
ENV MINT_RUN_SECURITY_DIR $MINT_ROOT_DIR/run/security
ENV WGET wget --quiet --no-check-certificate

RUN apt-get --yes update && apt-get --yes upgrade && \
    apt-get --yes --quiet install wget jq curl git dnsmasq

WORKDIR $MINT_ROOT_DIR

COPY mint/create-data-files.sh ./create-data-files.sh
RUN ./create-data-files.sh

COPY mint/preinstall.sh ./preinstall.sh
COPY mint/install-packages.list ./install-packages.list
RUN ./preinstall.sh

COPY mint/run/core/aws-sdk-go ./run/core/aws-sdk-go
COPY mint/build/aws-sdk-go ./build/aws-sdk-go
RUN ./build/aws-sdk-go/install.sh

COPY mint/run/core/aws-sdk-java ./run/core/aws-sdk-java
COPY mint/build/aws-sdk-java ./build/aws-sdk-java
RUN ./build/aws-sdk-java/install.sh

COPY mint/run/core/aws-sdk-php ./run/core/aws-sdk-php
COPY mint/build/aws-sdk-php ./build/aws-sdk-php
RUN ./build/aws-sdk-php/install.sh

COPY mint/run/core/aws-sdk-ruby ./run/core/aws-sdk-ruby
COPY mint/build/aws-sdk-ruby ./build/aws-sdk-ruby
RUN ./build/aws-sdk-ruby/install.sh

COPY mint/run/core/awscli ./run/core/awscli
COPY mint/build/awscli ./build/awscli
RUN ./build/awscli/install.sh

COPY mint/run/core/mc ./run/core/mc
COPY mint/build/mc ./build/mc
RUN ./build/mc/install.sh

COPY mint/run/core/minio-dotnet ./run/core/minio-dotnet
COPY mint/build/minio-dotnet ./build/minio-dotnet
RUN ./build/minio-dotnet/install.sh

COPY mint/run/core/minio-java ./run/core/minio-java
COPY mint/build/minio-java ./build/minio-java
RUN ./build/minio-java/install.sh

COPY mint/run/core/minio-js ./run/core/minio-js
COPY mint/build/minio-js ./build/minio-js
RUN ./build/minio-js/install.sh

COPY mint/run/core/minio-py ./run/core/minio-py
COPY mint/build/minio-py ./build/minio-py
RUN ./build/minio-py/install.sh

COPY mint/run/core/s3cmd ./run/core/s3cmd
COPY mint/build/s3cmd ./build/s3cmd
RUN ./build/s3cmd/install.sh

COPY mint/run/core/s3select ./run/core/s3select
COPY mint/build/s3select ./build/s3select
RUN ./build/s3select/install.sh

COPY mint/run/core/security ./run/core/security
COPY mint/build/security ./build/security
RUN ./build/security/install.sh

COPY mint/postinstall.sh ./postinstall.sh
COPY mint/remove-packages.list ./remove-packages.list
RUN ./postinstall.sh

COPY mint/mint.sh ./mint.sh
COPY mint/entrypoint.sh ./entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
