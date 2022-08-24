# Testing and developing the TLS client

Our TLS client is tested against a reference running TLS server provided by OpenSSL. 
In addition, our TLS client is also compared to the reference OpenSSL TLS client.

The usage of the OpenSSL client / serves are documented in the  [guyingbo](https://github.com/guyingbo/tls1.3) TLS implementation.

The `openssl` directory contains the necessary information to start a default TLS server or TLS client with the following commands:

```
## Starting OpenSSL TLS server:
cd  openssl
openssl s_server -accept 1799  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -key server.key -cert server.crt -debug -keylogfile key.txt -msg -state -tlsextdebug

## Starting OpenSS TLS Client:
openssl s_client -connect 127.0.0.1:1799 -tls1_3 -debug -keylogfile keylog.txt -msg -state -tlsextdebug
```

https://newbedev.com/testing-ssl-tls-client-authentication-with-openssl/

The exchange can be observed using wireshark with the following filter:

```
wiresharks tcp.port==1799
```


The procedure for generating Ed25519 certificates can be found [here](https://blog.pinterjann.is/ed25519-certificates.html). The procedure for generating RSA certificates can be found [here](https://www.vertica.com/docs/9.2.x/HTML/Content/Authoring/Security/SSL/GeneratingCertificationsAndKeys.htm) and reminded below:


In this section we only used RSA certificates 

```
Generate CA files serverca.crt and servercakey.pem. This allows the signing of server and client keys:
$ openssl genrsa -out servercakey.pem
$ openssl req -new -x509 -key servercakey.pem -out serverca.crt
Create the server private key (server.crt) and public key (server.key):
$ openssl genrsa -out server.key
$ openssl req -new -key server.key -out server_reqout.txt
$ openssl x509 -req -in server_reqout.txt -days 3650 -sha256 -CAcreateserial -CA serverca.crt -CAkey servercakey.pem -out server.crt
Create the client private key (client.crt) and public key (client.key):
$ openssl genrsa -out client.key
$ openssl req -new -key client.key -out client_reqout.txt
$ openssl x509 -req -in client_reqout.txt -days 3650 -sha256 -CAcreateserial -CA serverca.crt -CAkey servercakey.pem -out client.crt		
Set file permissions:
$ chmod 700 server.crt server.key
$ chmod 700 client.crt client.key

```


