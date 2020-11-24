# Example DTLS Echo service

This is an example demonstrating how to use OpenSSL in order to implement an DTSL enabled echo server.

## Installation

Make sure that libssl can be found by your compiling environment, e. g. by installing necessary packages:

```
sudo apt update
sudo apt install build-essential libssl-dev openssl stunnel
```

After that, enjoy the compilation process:

```
make
```

## Usage

First, generate certification files using "cert.sh"

```
./cert.sh
```

In the following using the DTSL echo server

```
./echo_server
```

And start echo client

```
./echo_client 127.0.0.1
```
