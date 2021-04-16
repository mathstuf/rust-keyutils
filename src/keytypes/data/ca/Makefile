PROJECT := rust-keyutils
OPENSSL_CONF := openssl.cnf

MAIN_CERT_NAME := ca-1
MAIN_ROOT_CERT := $(MAIN_CERT_NAME).root.crt
ROOT_CERTS := $(MAIN_ROOT_CERT) ca-2.root.crt
INTERMEDIATE_CERTS := ca.intermediate.crt
CA_CERTS := $(ROOT_CERTS) $(INTERMEDIATE_CERTS)
SERVER_CERTS := intermediate.term.crt $(MAIN_CERT_NAME).term.crt self.term.crt

SIGNING_BITS := certindex serial

all: $(foreach cert,$(CA_CERTS) $(SERVER_CERTS),$(cert).der)

certindex:
	touch certindex

serial:
	echo 1000 > serial

%.root.crt %.key: $(OPENSSL_CONF)
	openssl req -config $< -new -subj "/CN=$(PROJECT) CA $*" -x509 -passout pass:$(PROJECT) -newkey rsa:4096 -keyout $*.key -out $@ -extensions v3_root_ca

%.intermediate.crt %.key: $(OPENSSL_CONF) $(SIGNING_BITS) $(MAIN_ROOT_CERT)
	openssl req -config $< -new -subj "/CN=$(PROJECT) Intermediate CA" -passout pass:$(PROJECT) -newkey rsa:4096 -keyout $*.key -out $@.csr -extensions v3_intermediate_ca
	openssl ca -config $< -notext -passin pass:$(PROJECT) -batch -in $@.csr -out $@

self.term.crt %.key: $(OPENSSL_CONF) $(SIGNING_BITS)
	openssl req -config $< -new -subj "/CN=$(PROJECT) self-signed Certificate" -passout pass:$(PROJECT) -newkey rsa:4096 -keyout $*.term.key -out $@.csr -extensions v3_server_cert
	openssl x509 -req -signkey $*.term.key -passin pass:$(PROJECT) -days 3650 -in $@.csr -out $@

%.term.crt %.key: $(OPENSSL_CONF) $(SIGNING_BITS) $(CA_CERTS)
	openssl req -config $< -new -subj "/CN=$(PROJECT) $*-signed Certificate" -passout pass:$(PROJECT) -newkey rsa:4096 -keyout $*.term.key -out $@.csr -extensions v3_server_cert
	openssl ca -config $< -notext -passin pass:$(PROJECT) -batch -in $@.csr -out $@ -name $*

%.crt.der: %.crt
	openssl x509 -outform der -in $< -out $@
