#!/bin/sh
# A throwaway certificate authority for the example in this folder: a CA, and a server certificate
# for 127.0.0.1 and localhost that receiver.py presents. Thirty days, ECDSA P-256, nothing published.
#
#   sh make-certs.sh            # writes ./tls/{ca.pem,server.pem,server.key}
#
# Two-Key verifies the certificate and the host name on every TLS sink and has no setting that turns
# either check off, so the collector needs a certificate the client's ca_file can check. Use your own
# CA in anything that is not a local test.
set -eu
dir="${1:-tls}"
mkdir -p "$dir"
cd "$dir"

cat > openssl.cnf <<'CNF'
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = IP:127.0.0.1,DNS:localhost
CNF

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc -days 30 \
  -subj "/CN=two-key example CA" -extensions ca -config openssl.cnf \
  -keyout ca.key -out ca.pem

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -subj "/CN=localhost" -keyout server.key -out server.csr

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -days 30 \
  -extensions server -extfile openssl.cnf -out server.pem

rm -f server.csr
chmod 600 ca.key server.key
# The webhook's secrets, if you turn that sink on. Two-Key refuses a file another account can read.
[ -f token ] || { printf 'Bearer example-token\n' > token; chmod 600 token; }
[ -f hmac ] || { printf 'example-hmac-key\n' > hmac; chmod 600 hmac; }
echo "wrote $(pwd)/ca.pem, server.pem, server.key, token, hmac"
