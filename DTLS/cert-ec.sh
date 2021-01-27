#!/bin/bash
OPENSSL_BIN="openssl"
#OPENSSL_BIN="/usr/local/opt/openssl@1.1/bin/openssl"
#OPENSSL_BIN="/data/openssl/bin/openssl"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

touch ca-db-index
echo 01 > ca-db-serial

# Certificate Authority
$OPENSSL_BIN req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -nodes \
	-days 365 -out ca-cert.pem -keyout ca-key.pem \
	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh-ec-ca"
#$OPENSSL_BIN req -nodes -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem \
#	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh-ca"

# Server Certificate
$OPENSSL_BIN req -nodes -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout server-key.pem -out server.csr \
	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh-ec-server"
#$OPENSSL_BIN req -nodes -new -newkey rsa:2048 -keyout server-key.pem -out server.csr \
#	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh-server"

# Sign Server Certificate
$OPENSSL_BIN ca -config $SCRIPT_DIR/ca.conf -days 365 -in server.csr -out server-cert.pem

# Client Certificate
$OPENSSL_BIN req -nodes -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	 -keyout client-key.pem -out client.csr \
	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh-ec-client"
#$OPENSSL_BIN req -nodes -new -newkey rsa:2048 -keyout client-key.pem -out client.csr \
#	-subj "/C=KR/ST=Seoul/L=Uljiro/O=Hunature/OU=MakersAIOT/CN=hanwh-client"

# Sign Client Certificate
$OPENSSL_BIN ca -config $SCRIPT_DIR/ca.conf -days 365 -in client.csr -out client-cert.pem

mkdir -p certs/
cp client-cert.pem certs/
cp client-key.pem certs/
cp server-cert.pem certs/
cp server-key.pem certs/
