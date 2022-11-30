# Testing and developing the TLS client with OpenSSL

Our TLS client is tested against a reference running TLS server provided by OpenSSL. 
In addition, our TLS client is also compared to the reference OpenSSL TLS client.

The `openssl` directory contains the necessary information to start a default TLS server or TLS client with the following commands:

```
cd pytls13/tests/openssl
## Starting OpenSSL TLS server (no client authentication):
cd  openssl
openssl s_server -accept 8402  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -key server.key -cert server.crt -debug -keylogfile key.txt -msg -state -tlsextdebug -www

## Starting OpenSS TLS Client (no client authentication):
openssl s_client -connect 127.0.0.1:8402 -tls1_3 -debug -keylogfile keylog.txt -msg -state -tlsextdebug
```

The following [page](https://newbedev.com/testing-ssl-tls-client-authentication-with-openssl/) details how to configure and test TLS client authentication.


```
## Starting OpenSSL TLS server (client authentication):
cd  pytls13/tests/openssl/openssl
openssl s_server -cert server.crt -key server.key -WWW -port 8403 -CAfile client.crt  -debug -keylogfile key.txt -msg -state -tlsextdebug -verify_return_error -Verify 1

```


# Observing the exchanges with OpenSSL

The exchange can be observed using wireshark with the following filter:

```
wiresharks tcp.port==1799

```

# Generating TLS certificates with openSSL 

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

# Illustrated TLS

Illustrated TLS 1.3 is very convenient to begin with as, it provided a TLS Key Exchange with an certificate authentication with every steps being documented in a very comprehensive way. 
More precisely, many of the internal states are revealed which eases to track issues.
Now that these issues have been addressed, we may question the usefulness of it which can be seen as redundant with the client provided by illustrated TLS. 

This server is listening to port 8400 just start 

```
## For a single exchange
./server 

## For  multiple exchanges:
while true; do ./server ; done

```

The downsides are that only the ECDHE TLS mode is implemented, that is PSK or PSK-ECDHE has not been considered. In addition, it only work with a single precise example, so the tool may not be convenient for some sort of general purpose debugging.

Our TLS client implements the considers exchange by playing that exact exchange. 
The information sent is actually read from a json file, and each packet sent is checked. 
In theory, such approach would enable to implement validation of a number of exchanges, but we have not gone that far, and the client currently only works with a TLS server that responds.


The line below provides more explanation on the configuration to be used - though the configuration is also stored in the json file.



```
clt_conf = {
  'role' : 'client',
  'server' : {
    'fqdn' : None,
    'ip' : '127.0.0.1',
    'port' : 8400       #(debug illustrated TLS1.3)
  },
  'debug' : {
    'trace' : True,        # prints multiple useful information
    'test_vector' : True,  # indicate the use of a test vector
    'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
     # test_vector has currenlty 2 modes: check / record 
     # In our case, we sinply want to check our values against 
     # the one found in the test vector. This makes sure we 
     # are sending exactly what we expect.
    'test_vector_mode' : 'check',

    ## in some cases, the test vector is performed by establishing a real
    ## TCP connection. In such cases, sent packets are __effectively__
    ## being sent to the other peer and incoming packets are __effectively__
    ## being received by the other peer.  If that is the case, than 'remote'
    ## should be picked.
    ## In other cases, packets are not sent and received, but instead locally
    ## provided from a file.
    ## This is not implemeneted
    'test_vector_tls_traffic' : True, #'local' # / remote
  },
    ## as we replay an existing TLS exchange we ned to bypass the anti replay 
    ## protection mechanism.
  'lurk_client' : {
    'freshness' : 'null'
  },
```

# to run sajjad's client



cargo run -- --cert ../scert.pem --ccert ../ccert.pem --key ../sprivate-key-8.pem  127.0.0.1:4443

export CUSTOM_EDL_PATH=/opt/incubator-teaclave-sgx-sdk/edl/
export CUSTOM_COMMON_PATH=/opt/incubator-teaclave-sgx-sdk/common/


# tls1.3-idoBn


[IdoBn/tls1.3](https://github.com/IdoBn/tls1.3.git) is a python implementation of a TLS client which uses the same cryptographic library as us. 
It also has a OpenSSL server version that can be used for debugging purpose. 
It relies on a patch applied to an old OpenSSL version. 
The server can be run by:

* Installing the source of the old OpenSSL version
* Patching the old OpenSSL version with the patch provided by IdoBn
* Installing a [locally openssl](https://help.dreamhost.com/hc/en-us/articles/360001435926-Installing-OpenSSL-locally-under-your-username)
* Configuring OpenSSL
* Running OpenSSL 


```
# Installation of OpenSSL
git clone https://github.com/openssl/openssl.git 
git checkout fd4a6e7d1e51ad53f70ae75317da36418cae645
cd openssl

# Patching OpenSSL 
git apply IdoBn/tls1.3/resources/openssl.diff
./config
make
make install

# Installing OpenSSL locally

./config --prefix=/home/username/openssl --openssldir=/home/username/openssl no-ssl2make
make test
make install
export PATH=$HOME/openssl/bin:$PATH
export LD_LIBRARY_PATH=$HOME/openssl/lib
export LC_ALL="en_US.UTF-8"
export LDFLAGS="-L /home/username/openssl/lib -Wl,-rpath,/home/username/openssl/lib"
. ~/.bash_profile
which openssl

# Configuring OpenSSL
cd /home/emigdan/gitlab/tls1.3-idoBn/openssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout myPKey.pem \
    -out myCert.crt \
    -subj '/CN=US'

# Running OpenSSL
openssl s_server -accept 8401 -cert myCert.crt -key myPKey.pem  -debug -keylogfile key.txt -msg -state -tlsextdebug

```

When the installation has been performed once, there is no need to come through all the steps.

```
cd /home/emigdan/gitlab/tls1.3-idoBn/openssl
export PATH=$HOME/openssl/bin:$PATH
export LD_LIBRARY_PATH=$HOME/openssl/lib
export LC_ALL="en_US.UTF-8"
export LDFLAGS="-L $HOME/openssl/lib -Wl,-rpath,$HOME/openssl/lib"
. ~/.bash_profile
which openssl

# Running OpenSSL
openssl s_server -accept 8401 -cert myCert.crt -key myPKey.pem  -debug -keylogfile key.txt -msg -state -tlsextdebug


```

## Related Projects:

Here are some of the projects that also implement a TLS1.3 in python. 

[guyingbo/tls1.3](https://github.com/guyingbo/tls1.3) is a python implementation of a TLS client.

[IdoBn/tls1.3](https://github.com/IdoBn/tls1.3.git) is a python implementation of a TLS client. 
It also provides a OpenSSL implementation that can be used to debug. The debugging is in a very beta stage and as described in this page needs to run a old version of OpenSSL. I still believe this is useful to have such versions.

