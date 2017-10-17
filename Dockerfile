# Dockerfile
#
# Ubuntu 16.04 (Xenial) for MAAS Java SDK
#
# @author      Kealan McCusker <kealan.mccusker@miracl.com>
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# NOTES:
#
# To create the image execute:
#     docker build --tag="miracl/javasdk:latest" .
#
# To run container:
#     docker run -it  -p 5000:5000 miracl/javasdk
#
# To get the container ID:
#     CONTAINER_ID=`docker ps -a | grep miracl/javasdk | cut -c1-12`
#
# To attach to the docker container:
#     docker exec -ti $CONTAINER_ID bash
#
# To delete the docker container:
#     docker rm -f $CONTAINER_ID
#
# To delete the docker image:
#     docker rmi -f miracl/javasdk
#
# ------------------------------------------------------------------------------

FROM ubuntu:xenial
MAINTAINER support@miracl.com

ENV TERM linux
ENV HOME /app

# add repositories and update
RUN apt-get update -y && apt-get -y dist-upgrade && \
    apt-get install -y apt-utils software-properties-common && \
    apt-add-repository universe && \
    apt-add-repository multiverse && \
    apt-get update

# install packages
RUN apt-get install -y  git build-essentiallibssl-dev default-jdk

# Install SDK
COPY . /app
WORKDIR /app
RUN ./gradlew maas-sdk:publishToMavenLocal

# Run service
CMD ["/app/start.sh"]
