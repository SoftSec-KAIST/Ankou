FROM golang:latest

# Install auxiliary package
RUN apt update
RUN apt -y install \
        xz-utils \
        m4 \
        libssl-dev \
        libxml2-dev \
        zlib1g-dev
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /Ankou
WORKDIR /Ankou

# Build AFL
RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
RUN tar xf afl-latest.tgz
WORKDIR /Ankou/afl-2.52b
RUN make
RUN make install
WORKDIR /Ankou

# Build Ankou
RUN go get github.com/SoftSec-KAIST/Ankou
RUN go build github.com/SoftSec-KAIST/Ankou

# Download Benchmark
RUN git clone https://github.com/SoftSec-KAIST/Ankou-Benchmark
WORKDIR /Ankou/Ankou-Benchmark
RUN tar xf seeds.tar.xz
WORKDIR /Ankou/Ankou-Benchmark/sources
RUN ls *.tar.xz | xargs -n1 tar xf

# Build cflow package
WORKDIR /Ankou/Ankou-Benchmark/sources/cflow-1.6
RUN CC=afl-gcc CXX=afl-g++ ./configure --prefix=`pwd`/build
RUN make -j
RUN make install

# Build clamav package
WORKDIR /Ankou/Ankou-Benchmark/sources/clamav-0.101.2
RUN CC=afl-gcc CXX=afl-g++ ./configure --prefix=`pwd`/build
RUN make -j; make
RUN make install

WORKDIR /Ankou
