FROM ubuntu:16.04

# Build:
#   docker build -t tuf ./
#
# Run:
#   docker run -it --rm --volume $PWD:/tuf --workdir=/tuf tuf
#
RUN apt-get update && apt-get -y upgrade && \
  apt-get install -y build-essential libssl-dev libffi-dev python python-dev python-pip && \
  rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip
RUN pip install tuf

COPY README.rst dev-requirements.txt setup.py /build/
COPY tuf/ /build/tuf/

WORKDIR /build
RUN pip install -r dev-requirements.txt
