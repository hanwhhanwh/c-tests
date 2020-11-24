#!/bin/bash
OPENSSL_BIN="openssl"
#OPENSSL_BIN="/usr/local/opt/openssl@1.1/bin/openssl"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

touch ca-db-index
echo 01 > ca-db-serial

# Certificate Authority
$OPENSSL_BIN req -nodes -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem \
	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh"

# Server Certificate
$OPENSSL_BIN req -nodes -new -newkey rsa:2048 -keyout server-key.pem -out server.csr \
	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh"

# Sign Server Certificate
$OPENSSL_BIN ca -config $SCRIPT_DIR/ca.conf -days 365 -in server.csr -out server-cert.pem

# Client Certificate
$OPENSSL_BIN req -nodes -new -newkey rsa:2048 -keyout client-key.pem -out client.csr \
	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh"

# Sign Client Certificate
$OPENSSL_BIN ca -config $SCRIPT_DIR/ca.conf -days 365 -in client.csr -out client-cert.pem

mkdir -p certs/
cp client-cert.pem certs/
cp client-key.pem certs/
cp server-cert.pem certs/
cp server-key.pem certs/
