# LURK-T TLS 1.3 client


## Architecture Overview

`pytls13` is a proof of concept of TLS 1.3  designed with Limited Use of Remote Keys with Added Trust (LURK-T).
The ultimate goal of LURK-T is to leverage Trusted Execution Environment (TEE) to ensure **Trustworthy TLS authentication credentials**.

Unlike standard TLS 1.3 libraries, `pytls13` splits the library into two sub modules as depicted below:

* a Cryptographic Service (CS) responsible to host the authentication credentials (secret key, PSK, ...) and perform all associated cryptographic operations.
* a TLS Engine (E) responsible to interact with the CS to handle the TLS 1.3 Handshake

The communication between E and CS is defined in the TLS 1.3 extension of the general LURK framework design to provide various types of cryptographic -based micro-services.

```
+----------------------------+
|       TLS Engine (E)       |
+------------^---------------+
             | (LURK/TLS 1.3)
+------------v---------------+
| Cryptographic Service (CS) |
| private_keys               |
+----------------------------+
```

When the CS runs into a Trusted Execution Environment (TEE), `pytls13` enables __a trustworthy deployment of TLS in untrusted environment__.
More specifically, LURK-T secures the cryptographic credentials and prevent their leaks against vulnerabilities either of the upper layer application or the infrastructure.

The figure below compares the deployment of TLS using a LURK-T versus the deployment of a standard TLS deployment.
In a standard deployment, the TLS library completely runs in an untrusted environment which opens the TLS library to:
* Lateral Attacks (A): Lateral attacks are performed by any __other__ applications than the TLS library, which includes any application the cloud provider may be hosting but also the legitimate application for which the TLS library is expected to provide a protection.
* Cloud Provider (B): The cloud provider can access any hosting resources such as the RAM in which the TLS private key is stored.

With LURK-T, the CS hosts the private keys and other authentication credentials.
Having the CS running in to a TEE considerably limit the exposure of the credentials to interface provided by LURK.
The TEE enclave enforces an isolation that is likely to be the most secure isolation that can be performed today.
More precisely, this isolation is enforced by the CPU.
Note that other isolation mechanisms may also be used including running the E and CS in different processes. At that point isolation is guaranteed by the OS as opposed to the CPU.


```
     LURK-T           Standard TLS
                      Library
 +-------------+  +--------------+
 | Upper Layer |  | Upper Layer  |   <#######
 | Application |  | Application  |    Lateral
 +-------------+  +--------------+    Attacks
 |       E     |  | Standard TLS |     (A)
 +------ ^-----+  |  Library     |   <#######
         |        +--------------+
---------|-----------------^------
 +=======v=====+           #
 |   CS (TEE)  |           #
 +=============+  Cloud Provider (B)

```

LURK-T does not protects the TLS session keys and limits its scope to the keeping authentication credentials trustworthy.
This provides for example the following operational and concrete advantages.

## LURK-T Use Cases

Use Case 1: Upon suspected attacks or any disclosed vulnerabilities, upper layer application MUST be patched.
In the case of a standard TLS Library,  and authentication credential MUST be re-issued, there are no guarantee authentication credentials  have not been leaked and as such ALL authentication credentials MUST be re-issued.
This is not the case with LURK-T.

Use Case 2: Upon changing Cloud provider, deployment that considered a Standard TLS library MUST be re-issued as these have been shared with the former Cloud provider.
With LURK-T the deployment can change cloud providers and benefit from elastic resources from any Cloud provider without impacting the trustworthiness of the credentials.

## Why only protecting authentication credentials ?

One can reasonably wonder why limiting the protection provided by TEE to only the authentication credential as opposed to the full TLS library, for example  which would include  some protection of the session keys.

The short answer is that the additional security provided is very limited with a huge cost associated.
The cost can be easily understood by considering that any interaction with an enclave requires a very heavy context switching. In particular, for SGX enclaves, the interaction between TEE and REE results in 8,200 - 17,000 cycles overhead, as opposed to 150 cycles for a standard system call.
With such paradigm, network application like TLS undergo a huge penalty as incoming always come from outside the enclave.
Respectively outgoing packets are going outside the enclave as well.


On the other hand, that overhead needs to be balanced with the security advantages, it could provide.
Securing the TLS session keys, and the encryption process provides little advantages unless the application itself is trusted.
As a result, the Upper Layer Application is also expected to be in the enclave.
However, depending on the complexity of the application, the application MAY likely contain a bunch of potential vulnerabilities and as such expose the TLS sessions keys and authentication credentials to a large surface of attack.

As a result, one MUST not forget that one reason LURK-T provides the expected security is that in addition to isolating the authentication credential, it provides a very limited ways to interact with these authentication credentials, implemented in a relatively few Line of Codes to limit the probabilities to introduce some vulnerabilities.

We cannot undermine that technology will evolve and that at some points, the overhead associated to context switching might become acceptable in term of performance.
In that case, isolating the CS within the TEE via some hypervisor, nested enclaves would remain areas to investigate.

## Remote Attestation and RA-TLS Overview

While the architecture of the LURK-T TLS remains pretty simple, it remains challenging to set up the CS in a remote data center provisioned with the private key that we do not share with the data center.
This is done in two steps:

1. Ensuring the *expected* CS has been loaded into the TEE (of a remote Cloud provider)
2. Provisioning the private key via a TLS channel that is terminated into this *attested* Enclave.


Defining the Certificate based identity enclave by the *Software Vendor*
with an enclave building tool chain.
```
+--------------------+  +------------+ +-----------------+
| Enclave            |  | Software   | | Software vendor |
+--------------------+  +------------+ +-----------------+
| ATTRIBUTES: DEBUG, |  | ISVPROID   | | K_vendor (RSA)  |
|   XFRM, MODE64BIT  |  | ISVSVN     | | VENDOR          |
+--------------------+  +------------+ +-----------------+

+--------------------------------------------------------+
|            Enclave building tool chain                 |
+--------------------------------------------------------+
                             |
                             v
      +------------------------------------------+
      | SIGSTRUCT:                               |
      +------------------------------------------+
      |   MRMEASUREMENT                          |
      |   MRSIGNER (SHA256( K_vendor module)))   |
      |   ATTRIBUTES                             |
      |   VENDOR                                 |
      |   ISVPRODID                              |
      |   ISVSVN                                 |
      |   DATE                                   |
      |   MODULE   ---- K_vendor                 |
      |   EXPONENT                               |
      |   SIGNATURE                              |
      |   Q1, Q2                                 |
      +------------------------------------------+
```

Initialization and Attestation of the Enclave by the *Cloud Provider*

```
Software               SIGSTRUCT --------------+
   |                       |                   |
   v                       |                   v
+------------------------+ |         +-------------------------+
| ECREATE                | |         | Launch Enclave (LE)     |
+------------------------+ |         +-------------------------+
| Computes SECS          | |         |  Creates/MAC EINITTOKEN |
|   MRENCLAVE            | |         |    MRSIGNER,            |
|   BASEADDR             | |         |    MRENCLAVE,           |
|   SIZE                 | |         |    ISVPRODID,           |
|   SSAFRAMESIZE         | |         |    ISVSVN,    # Key accessed only
|   ATTRIBUTES           | | +-------|    MAC( Key ) # by SGX and ENCLAVE
+------------------------+ | |       +-------------------------+
   |          +------------+ |
+--v----------|--------------|----+  +-------------+
| ENCLAVE     |              |    |  | APPLICATION |
| +-----------v--------------v--+ |  |             |
| | EINIT SIGSTRUCT, EINITTOKEN | |  |             |
| +-----------------------------+ |  |             |
| | Checks:                     | |  |             |
| |   EINITTOKEN.SIGNATURE      | |  |             |
| |   SECS.MRENCLAVE =          | |  |             |
| |     EINITTOKEN.MRENCLAVE    | |  |             |
| |   SECS.ATTRIBUTES =         | |  |             |
| |     EINITTOKEN.ATTRIBUTES   | |  |             |
| +-----------------------------+ |  |             |
| | Complete SECS               | |  |             |
| |   MRENCLAVE                 | |  |             |
| |   BASEADDR                  | |  |             |
| |   SIZE                      | |  |             |
| |   SSAFRAMESIZE              | |  |             |
| |   ATTRIBUTES                | |  |             |
| |   ISVPRODID                 | |  |             |
| |   ISVSVN                    | |  |             |
| |   MRSIGNER                  | |  |             |
| +-----------------------------+ |  |             |
|                                 |  |             |
| +--------------------------+    |  | REPORTDATA  |
| | EREPORT REPORTDATA       |<-------------       |
| +--------------------------+    |  |             |
| | SGX creates/MAC REPORT:  |    |  |             |
| |   MRSIGNER,              |    |  |             |
| |   MRENCLAVE,             |    |  |             |
| |   ISVPRODID,             |    |  |             |
| |   ISVSVN,                |    |  |             |
| |   REPORTDATA=Challenge,  |    |  |             |
| |   CPUSVN,                |    |  | REPORT      |
| |   MAC( Key )*            |----|--|-->          | *Key only accessed
| +--------------------------+    |  |             |  by SGX and QE
+---------------------------------+  |             |
+--------------------------+         | REPORT      |
| Quoting Enclave (QE)     |<----------            |
+--------------------------+         |             |
| K_attestation (EPID)     | (proviosioned and     |
+--------------------------+  certirfied by Intel) |
| Check MAC                |         |             |
| Quote:                   |         |             |
|   REPORT                 |         | QUOTE       |
|   SIGNATURE              |---------------->      |
+--------------------------+         |             |
                                     +-------------+

```
### RA-TLS

Thanks to the attestation response, one knows the appropriated software is running, but we need a bit more to be able to provision some secrets, i.e. we need to set an encrypted channel and use the attestation to authenticate the terminating end point as being  the expected software.


```
+-----------------------+ +-------------+
| ENCLAVE               | | Application |
| Generates             | |             |
|   Public (K) /        | |             |
|   Private Key (k)     | |             |
| CERTIFICATE:          | |             |
|   K                   | |             |          SIGSTRUCT
|   Attribute:          | |             |              |
|     REPORT            | |             |              v
|       REPORTDATA=H(K) | |             |        +-------------+  +-------------+
|     Intel cert.chain  | |             |        | Verifier    |  | Intel       |
|   Signature( k )      | |             |        |             |  |             |
| TLS server            | |             |   ClientHello        |  | Attestation |
|   <----------------------------------------------------      |  | Service     |
|   ServerHello         | |             |        |             |  | (IAS)       |
|   EncryptedExtensions,| |             |        |             |  |             |
|   Certificate,        | |             |        |             |  |             |
|   CertificateVerify   | |             |        |             |  |             |
|   ServerFinished      | |             |        |             |  |             |
|   ---------------------------------------------------->      |  |             |
|                       | |             |        |     REPORT, SIG(EPID)        |
|                       | |             |        |     ----------------->       |
|                       | |             |        |      Attestation Result      |
|                       | |             |        |     <----------------        |
|                       | |             |        | Validates   |  |             |
|                       | |             |        | Result      |  |             |
|                       | |             |        |   MRENCLAVE |  |             |
|                       | |             |        |   ...       |  |             |
|                       | |             |    ClientFinished    |  |             |
|   <----------------------------------------------------      |  |             |
|                       | |             |        |             |  |             |
+-----------------------+ +-------------+        +-------------+  +-------------+
```

Note that this only works because:
1. we know the code is generating a fresh pair of keys, and REPORTS tells us this is the code running in the enclave.
2. the key involved is the correct key we are setting the TLS session as that key is bound to the REPORT


Thanks to RA-TLS we have been able to establish a **trustworthy TLS session with the TEE** and we can trustworthy
provision the Enclave with secrets.

Note that in this scheme the ENCLAVE does not authenticate the Verifier, so if secrets are expected by the ENCLAVE, it might be reasonable to use a mutually authenticated TLS.

### Secret provisioning

Secret provisioning heavily relies on RA-TLS, but instead of being initiated by the Verifier, it is initiated by the ENCLAVE.
The Verifier, implements a TLS server and after the authentication of the TLS client (using attestation), the TLS server provides the different secrets.

```
+-----------------------+ +-------------+
| ENCLAVE               | | Application |
| Generates             | |             |
|   Public (K) /        | |             |
|   Private Key (k)     | |             |
| CERTIFICATE:          | |             |
|   K                   | |             |          SIGSTRUCT
|   Attribute:          | |             |              |
|     REPORT            | |             |              v
|       REPORTDATA=H(K) | |             |        +-------------+  +-------------+
|     Intel cert.chain  | |             |        | Secret Prov |  | Intel       |
|   Signature( k )      | |             |        |             |  | Attestation |
| CA (TLS server)       | |             |        |             |  | Service     |
|    ClientHello        | |             |        |             |  | (IAS)       |
|   ---------------------------------------------------->      |  |             |
|                                   ServerHello                |  |             |
|                                   EncryptedExtensions,       |  |             |
|                                   Certificate,               |  |             |
|                                   CertificateRequest,        |  |             |
|                                   CertificateVerify,         |  |             |
|                                   ServerFinished             |  |             |
|   <----------------------------------------------------      |  |             |
| server Authentication | |             |        |             |  |             |
| (CeritifcateVerify)   | |             |        |             |  |             |
|                       | |             |        |             |  |             |
| Certificate           | |             |        |             |  |             |
| CertificateVerify     | |             |        |             |  |             |
| clientFinished        | |             |        |             |  |             |
|   ---------------------------------------------------->      |  |             |
|                       | |             |        |     REPORT, SIG(EPID)        |
|                       | |             |        |     ----------------->       |
|                       | |             |        |      Attestation Result      |
|                       | |             |        |     <----------------        |
|                       | |             |        | Validates   |  |             |
|                       | |             |        | Result      |  |             |
|                       | |             |        |   MRENCLAVE |  |             |
|                       | |             |        |   ...       |  |             |
|                       | |           Secrets Provisionning    |  |             |
|   <----------------------------------------------------      |  |             |
|                       | |             |        |             |  |             |
+-----------------------+ +-------------+        +-------------+  +-------------+

```

## LURK-T TLS 1.3 Conclusion

This results in the following high level architecture:

```
+---------------------------------------+          +-----------------+
|        Software Vendor                |          |     (Intel)     |
|                        +------------+ |          | +-------------+ |      
| Crypto Service Code -->| building   | |          | | Attestation | |
| Service Provider ID -->| tool chain | |          | | Service     | |        
|                        +------------+ |          | +-------------+ |
+----------------------------|----------+          +-----------------+ 
                             | CS lib + SIGSTRUCT            ^     
                             +--------------------------+    |     
                             v                          v    |     
                       +--------------------+     +------------------+ 
                       |  Cloud Provider    |     | Service  |       |
 (Web Server)          |                    |     | Provider |       |
+------------+         | +----------------+ |     |          |       |           
| TLS Server |         | |    TLS Client  | |     |          |       |
+------------+         | +----------------+ |     |          |       |
|            <-----------> TLS Engine     | |     |          v       |
|            |         | +- - - - - - - - + |     | +--------------+ |
|            |         | | SGX Enclave    | |     | | Secret       | |
|            |         | | Crypto Service <-------->  Provisioning | |
+------------+         | +----------------+ |     | +--------------+ |
                       +--------------------+     +------------------+
```


LURK-T provides a __trustworthy infrastructure__ that is:
* prevents identity hijacking - thus making vulnerabilities very localized
* ensures patches are sufficient to return into a trustworthy state

LURK-T overhead associated to TEE is minimal as it only happens during the TLS handshake.

TLS 1.3 with LURK-T does prevent an __ongoing TLS session__ against a rogue application or cloud provider performing a man-in-the-middle attack.
TLS sessions secrets are not protected and requires the system to be trustworthy at the time the session is established.

## LURK-T TLS client with  `pytls13` and `pylurk` modules

* [pytls13](https://github.com/mglt/pytls13) implements the TLS engine (E) (version 0.0.1 in this document)
* [pylurk](https://github.com/mglt/pylurk) implements the TLS Crypto Service (CS) (version 0.0.3 in this document)
* We use the libOS [Gramine](https://gramine.readthedocs.io/) to run the CS in a SGX TEE

The figure below extracted from [Graphene-SGX: A Practical Library OS for Unmodified Applications on SGX](https://www.usenix.org/conference/atc17/technical-sessions/presentation/tsai) provides a high level description of Gramine.
 
![](./fig/gramine_architecture.png "Gramine Architecture")
The shield library (provided by Gramine) is __responsible__ for loading all the necessary components into the enclave. It includes.
* The Linux librairy OS (`libLinux.so`), the standard C librairues (`ld-linux-x86-64.so` and `libc.so`) __emulates__ the host. These are librarires provided by Gramine.
* Application specific files described in the `manifest`.
Before being loaded each file is checked against its hash contained in the `manifest`.

## Starting the Web Server

In this example, the web server will require the TLS client to authenticate.
```
cd pytls13/tests/openssl
## Starting OpenSSL TLS server (client authentication):
cd  pytls13/tests/openssl/openssl
openssl s_server -cert server.crt -key server.key -www -port 8403 -CAfile client.crt  -debug -keylogfile key.txt -msg -state -tlsextdebug -Verify 1

## note 1: that -verify error validates the certificates up 
## to the CA which needs to be trusted and raises an error. 
## This is why we do not have this option here.
## note 2: that with Verify 1 the signature generated by 
## the client is checked
## note 3: -www indicate sthe Web server returns a Web page
## that contains all connection information. The point here 
## is to receive a response upon sending HTTP GET. 
verify depth is 1, must return a certificate
Using default temp DH parameters
ACCEPT
```

## 1. Service Provider generates a Service Provider ID (SPID)

When EPID is used for attestation, the Service Provider MUST Register to Intel to get a Service Provider ID (SPID) and provide it to the Software Vendor. 
The SPID is part of the Quote and the Quote is used by the Service Provider to attest (via the IAS) the software (in our case the CS). 
As a result, the Quote be generated prior to contact the Service Provider. 

SPID is retrieved by subscribing to [Intel® SGX Attestation Service Utilizing Enhanced Privacy ID (EPID)](https://api.portal.trustedservices.intel.com/EPID-attestation).
The service provides two type of subscriptions:
1. unlinkable service that prevents to even determine if attestation occurs on the same CPU
2. linkable service.

The considered values for the unlinkable service are as mentioned below:
* SPID: 3A2053D125F7AB3642C3FAC6A22BABFD
* primary key: 646457af6dea4427a2aae2e78a7b6ecf
* secondary key: 1dc980e2ada84af1a78383f65557f546

## 2. Software Vendor builds the CS

To enable EPID remote attestation, the Software Vendor MUST build the enclave by specifying the `--ra_type`, `--ra_spid`, `--ra_linkable` to charasterise th eremote attestation as well as `--gramine_dir` to specify the the necessary libraries shipped that implement the ra_tls client.

Note that these arguments are only used by Gramine and as such are only stored in the `python.manifest`.
 
```
cd pylurk.git/example/cli
pylurk.git/example/cli$ ./crypto_service --gramine_build  --ra_type 'epid' --ra_spid 3A2053D125F7AB3642C3FAC6A22BABFD --ra_linkable 0 
 --- Executing: /home/mglt/gitlab/pylurk.git/example/cli/./crypto_service with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9400, sig_scheme="'ed25519'", key=None, cert=None, debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=True, secret_provisioning=False, ra_type="'epid'", ra_spid="'3A2053D125F7AB3642C3FAC6A22BABFD'", ra_linkable="'0'", gramine_dir="'None'")
key file not provided. New key will be generated in /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir
certificate file not provided. New certificate will be stored in /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir
Buildinging: make -f Makefile_server_prov clean && make -f Makefile_server_prov app epid GRAMINEDIR=/home/mglt/gramine
Building: make -f Makefile_server_prov clean && make -f Makefile_server_prov app epid GRAMINEDIR=/home/mglt/gramine
rm -f *.manifest *.manifest.sgx *.token *.sig OUTPUT* *.PID TEST_STDOUT TEST_STDERR
rm -f OUTPUT
mglt@nuc:~/gitlab/pylurk.git/example/cli$ cd secret_prov;         rm -f client server_* *.token *.sig *.manifest.sgx *.manifest
rm -f -r scripts/__pycache__
cd secret_prov && \
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dra_type=none \
        -Dra_client_spid= \
        -Dra_client_linkable=0 \
        client.manifest.template > client.manifest
gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dentrypoint=/usr/bin/python3.10 \
        -Dra_type=epid \
        -Dra_client_spid=3A2053D125F7AB3642C3FAC6A22BABFD \
        -Dra_client_linkable=0 \
        python.manifest.template >python.manifest
cc secret_prov/client.c -O2 -fPIE -Wall -std=c11 -I/home/mglt/gramine/tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_attest -o secret_prov/client
gramine-sgx-sign \
        --manifest python.manifest \
        --output python.manifest.sgx
cd secret_prov && \
gramine-sgx-sign \
        --manifest client.manifest \
        --output client.manifest.sgx
Attributes:
    size:        0x20000000
    thread_num:  4
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0x6
    attr.xfrm:   0x3
    misc_select: 0x0
SGX remote attestation:
    None
Memory:
    000000003fd18000-0000000040000000 [REG:R--] (manifest) measured
    000000003fcf8000-000000003fd18000 [REG:RW-] (ssa) measured
    000000003fcf4000-000000003fcf8000 [TCS:---] (tcs) measured
    000000003fcf0000-000000003fcf4000 [REG:RW-] (tls) measured
    000000003fcb0000-000000003fcf0000 [REG:RW-] (stack) measured
    000000003fc70000-000000003fcb0000 [REG:RW-] (stack) measured
    000000003fc30000-000000003fc70000 [REG:RW-] (stack) measured
    000000003fbf0000-000000003fc30000 [REG:RW-] (stack) measured
    000000003fbe0000-000000003fbf0000 [REG:RW-] (sig_stack) measured
    000000003fbd0000-000000003fbe0000 [REG:RW-] (sig_stack) measured
    000000003fbc0000-000000003fbd0000 [REG:RW-] (sig_stack) measured
    000000003fbb0000-000000003fbc0000 [REG:RW-] (sig_stack) measured
    000000003f793000-000000003f7d7000 [REG:R-X] (code) measured
    000000003f7d8000-000000003fbb0000 [REG:RW-] (data) measured
    0000000020000000-000000003f793000 [REG:RWX] (free)
Measurement:
    b88865b1741bf87a7f3c6aaae173ce0e9d7884d1a4e9ed4abdf4473c18f1ca19
gramine-sgx-get-token --output secret_prov/client.token --sig secret_prov/client.sig
Attributes:
    mr_enclave:  b88865b1741bf87a7f3c6aaae173ce0e9d7884d1a4e9ed4abdf4473c18f1ca19
    mr_signer:   e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    isv_prod_id: 0
    isv_svn:     0
    attr.flags:  0000000000000006
    attr.xfrm:   0000000000000003
    mask.flags:  ffffffffffffffff
    mask.xfrm:   fffffffffff9ff1b
    misc_select: 00000000
    misc_mask:   ffffffff
    modulus:     f19f15a643fbadc6714cbe9e8d670a8a...
    exponent:    3
    signature:   f676be580b9824c423934016f0f82631...
    date:        2023-04-04
cc secret_prov/server.c -O2 -fPIE -Wall -std=c11 -I/home/mglt/gramine/tools/sgx/ra-tls -pie -Wl,--enable-new-dtags -lsgx_util -Wl,-rpath,/usr/lib/x86_64-linux-gnu -lsecret_prov_verify_epid -pthread -o secret_prov/server_epid
Attributes:
    size:        0x20000000
    thread_num:  32
    isv_prod_id: 29539
    isv_svn:     0
    attr.flags:  0x4
    attr.xfrm:   0x3
    misc_select: 0x0
SGX remote attestation:
    EPID (spid = `3A2053D125F7AB3642C3FAC6A22BABFD`, linkable = False)
Memory:
    000000001f929000-0000000020000000 [REG:R--] (manifest) measured
    000000001f829000-000000001f929000 [REG:RW-] (ssa) measured
    000000001f809000-000000001f829000 [TCS:---] (tcs) measured
    000000001f7e9000-000000001f809000 [REG:RW-] (tls) measured
    000000001f7a9000-000000001f7e9000 [REG:RW-] (stack) measured
    000000001f769000-000000001f7a9000 [REG:RW-] (stack) measured
    000000001f729000-000000001f769000 [REG:RW-] (stack) measured
    000000001f6e9000-000000001f729000 [REG:RW-] (stack) measured
    000000001f6a9000-000000001f6e9000 [REG:RW-] (stack) measured
    000000001f669000-000000001f6a9000 [REG:RW-] (stack) measured
    000000001f629000-000000001f669000 [REG:RW-] (stack) measured
    000000001f5e9000-000000001f629000 [REG:RW-] (stack) measured
    000000001f5a9000-000000001f5e9000 [REG:RW-] (stack) measured
    000000001f569000-000000001f5a9000 [REG:RW-] (stack) measured
    000000001f529000-000000001f569000 [REG:RW-] (stack) measured
    000000001f4e9000-000000001f529000 [REG:RW-] (stack) measured
    000000001f4a9000-000000001f4e9000 [REG:RW-] (stack) measured
    000000001f469000-000000001f4a9000 [REG:RW-] (stack) measured
    000000001f429000-000000001f469000 [REG:RW-] (stack) measured
    000000001f3e9000-000000001f429000 [REG:RW-] (stack) measured
    000000001f3a9000-000000001f3e9000 [REG:RW-] (stack) measured
    000000001f369000-000000001f3a9000 [REG:RW-] (stack) measured
    000000001f329000-000000001f369000 [REG:RW-] (stack) measured
    000000001f2e9000-000000001f329000 [REG:RW-] (stack) measured
    000000001f2a9000-000000001f2e9000 [REG:RW-] (stack) measured
    000000001f269000-000000001f2a9000 [REG:RW-] (stack) measured
    000000001f229000-000000001f269000 [REG:RW-] (stack) measured
    000000001f1e9000-000000001f229000 [REG:RW-] (stack) measured
    000000001f1a9000-000000001f1e9000 [REG:RW-] (stack) measured
    000000001f169000-000000001f1a9000 [REG:RW-] (stack) measured
    000000001f129000-000000001f169000 [REG:RW-] (stack) measured
    000000001f0e9000-000000001f129000 [REG:RW-] (stack) measured
    000000001f0a9000-000000001f0e9000 [REG:RW-] (stack) measured
    000000001f069000-000000001f0a9000 [REG:RW-] (stack) measured
    000000001f029000-000000001f069000 [REG:RW-] (stack) measured
    000000001efe9000-000000001f029000 [REG:RW-] (stack) measured
    000000001efd9000-000000001efe9000 [REG:RW-] (sig_stack) measured
    000000001efc9000-000000001efd9000 [REG:RW-] (sig_stack) measured
    000000001efb9000-000000001efc9000 [REG:RW-] (sig_stack) measured
    000000001efa9000-000000001efb9000 [REG:RW-] (sig_stack) measured
    000000001ef99000-000000001efa9000 [REG:RW-] (sig_stack) measured
    000000001ef89000-000000001ef99000 [REG:RW-] (sig_stack) measured
    000000001ef79000-000000001ef89000 [REG:RW-] (sig_stack) measured
    000000001ef69000-000000001ef79000 [REG:RW-] (sig_stack) measured
    000000001ef59000-000000001ef69000 [REG:RW-] (sig_stack) measured
    000000001ef49000-000000001ef59000 [REG:RW-] (sig_stack) measured
    000000001ef39000-000000001ef49000 [REG:RW-] (sig_stack) measured
    000000001ef29000-000000001ef39000 [REG:RW-] (sig_stack) measured
    000000001ef19000-000000001ef29000 [REG:RW-] (sig_stack) measured
    000000001ef09000-000000001ef19000 [REG:RW-] (sig_stack) measured
    000000001eef9000-000000001ef09000 [REG:RW-] (sig_stack) measured
    000000001eee9000-000000001eef9000 [REG:RW-] (sig_stack) measured
    000000001eed9000-000000001eee9000 [REG:RW-] (sig_stack) measured
    000000001eec9000-000000001eed9000 [REG:RW-] (sig_stack) measured
    000000001eeb9000-000000001eec9000 [REG:RW-] (sig_stack) measured
    000000001eea9000-000000001eeb9000 [REG:RW-] (sig_stack) measured
    000000001ee99000-000000001eea9000 [REG:RW-] (sig_stack) measured
    000000001ee89000-000000001ee99000 [REG:RW-] (sig_stack) measured
    000000001ee79000-000000001ee89000 [REG:RW-] (sig_stack) measured
    000000001ee69000-000000001ee79000 [REG:RW-] (sig_stack) measured
    000000001ee59000-000000001ee69000 [REG:RW-] (sig_stack) measured
    000000001ee49000-000000001ee59000 [REG:RW-] (sig_stack) measured
    000000001ee39000-000000001ee49000 [REG:RW-] (sig_stack) measured
    000000001ee29000-000000001ee39000 [REG:RW-] (sig_stack) measured
    000000001ee19000-000000001ee29000 [REG:RW-] (sig_stack) measured
    000000001ee09000-000000001ee19000 [REG:RW-] (sig_stack) measured
    000000001edf9000-000000001ee09000 [REG:RW-] (sig_stack) measured
    000000001ede9000-000000001edf9000 [REG:RW-] (sig_stack) measured
    000000001e9cc000-000000001ea10000 [REG:R-X] (code) measured
    000000001ea11000-000000001ede9000 [REG:RW-] (data) measured
    0000000000010000-000000001e9cc000 [REG:RWX] (free)
Measurement:
    7eddfc41ba3a4f1bc4c5fbfbd85b53eee48ab65430b3bd7d259eb29b33ef2d33
gramine-sgx-get-token --output python.token --sig python.sig
Attributes:
    mr_enclave:  7eddfc41ba3a4f1bc4c5fbfbd85b53eee48ab65430b3bd7d259eb29b33ef2d33
    mr_signer:   e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    isv_prod_id: 29539
    isv_svn:     0
    attr.flags:  0000000000000004
    attr.xfrm:   0000000000000003
    mask.flags:  ffffffffffffffff
    mask.xfrm:   fffffffffff9ff1b
    misc_select: 00000000
    misc_mask:   ffffffff
    modulus:     f19f15a643fbadc6714cbe9e8d670a8a...
    exponent:    3
    signature:   6ea4c330222c453171282aa8f44a884a...
    date:        2023-04-04

```

The CS is composed of the following files:
* `python.manifest.template`: which contains the main configuration parameters for Gramine to run the CS in the SGX enclave
* `python.manifest`: contains the exhaustive configuration parameters for Gramine.
* `python.manifest.sgx`: contains an exhaustive list of files and their associated hash that are included in the SGX enclave by Gramine 
* `python.sig`: defines the SIGSTRUCT
* `python.token` : contains the EINITTOKEN (or SIGSTRUCT)

## 3. The Service Provider starts the Service Provisioning

Eventually you may build (aka compile the service Provisioning Service). 
In our case, this is not useful as the building phase has been performed while building the CS.

```
$ cd ~/gitlab/pylurk.git/example/cli
$ ./secret_prov_service --build
```

The Secret Provisioning Service takes as argument:
* `secret`: the secret to be provisioned. In our case, this is the private key.
* `sig_file`: the file containing the SIGSTRUCTURE
* `epid_api_key`:the key to be authenticated by the IAS (RA_TLS_EPID_API_KEY).
* `key`, `cert`: TLS key and certificate (stored in the pylurk.git/example/cli/tls_secret_prov directory

```
$ cd ~/gitlab/pylurk.git/example/cli
./secret_prov_service --secret ~/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --sig_file ~/gitlab/pylurk.git/example/cli/python.sig --epid_api_key 646457af6dea4427a2aae2e78a7b6ecf
Starting Secret Provision Service:
(Reading attributes from /home/mglt/gitlab/pylurk.git/example/cli/python.sig)
    - mrenclave: 7eddfc41ba3a4f1bc4c5fbfbd85b53eee48ab65430b3bd7d259eb29b33ef2d33
    - mrsigner: e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
    - isv_prod_id: 29539
    - isv_svn: 0 
    - secret: /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der

secret_key [48 bytes]:
30 2E 2 1 0 30 5 6 3 2B 65 70 4 22 4 20 12 F 12 D8 DB 8F ED B0 15 49 EC 5C 63 6D DB 55 D9 7A 66 BE A7 17 6A 2C 96 47 BD A5 12 82 23 9A 
--- Starting the Secret Provisioning server on port 4433 ---
```

This results in the Secret Provisioning Service Listening on port 4433. 
The port can be configured, but it is currently hard coded in the client. 

## 4. The Service Provider starts the CS in the Cloud Provider


At first the Service Provider checks the Cloud Provider supports attestation and Gramine.

Documentation of the API can be found [here](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf)

[Intel® SGX Software Installation Guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) provides installation of the SGX SDK and the Platform Software (PSW), which is detailed below for Linux 2022.



```
$ uname -a
Linux nuc 5.15.0-67-generic #74-Ubuntu SMP Wed Feb 22 14:14:39 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
$ echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc

$ wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
$ sudo apt-get update
$ sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libsgx-ae-epid libsgx-ae-id-enclave libsgx-ae-pce libsgx-ae-qe3
  libsgx-ae-qve libsgx-aesm-ecdsa-plugin libsgx-aesm-epid-plugin
  libsgx-aesm-pce-plugin libsgx-aesm-quote-ex-plugin
  libsgx-dcap-quote-verify libsgx-pce-logic libsgx-qe3-logic
  sgx-aesm-service
The following NEW packages will be installed:
  libsgx-ae-epid libsgx-ae-id-enclave libsgx-ae-pce libsgx-ae-qe3
  libsgx-aesm-ecdsa-plugin libsgx-aesm-epid-plugin
  libsgx-aesm-pce-plugin libsgx-aesm-quote-ex-plugin
  libsgx-dcap-ql libsgx-epid libsgx-pce-logic libsgx-qe3-logic
  libsgx-quote-ex sgx-aesm-service
The following packages will be upgraded:
  libsgx-ae-qve libsgx-dcap-quote-verify
2 upgraded, 14 newly installed, 0 to remove and 8 not upgraded.
Need to get 4,127 kB of archives.
After this operation, 9,907 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
$ sudo apt-get install libsgx-urts-dbgsym libsgx-enclave-common-dbgsym libsgx-dcap-ql-dbgsym libsgx-dcap-default-qpl-dbgsym
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libsgx-dcap-default-qpl libsgx-enclave-common libsgx-urts
Recommended packages:
  libsgx-launch
The following NEW packages will be installed:
  libsgx-dcap-default-qpl libsgx-dcap-default-qpl-dbgsym
  libsgx-dcap-ql-dbgsym libsgx-enclave-common-dbgsym
  libsgx-urts-dbgsym
The following packages will be upgraded:
  libsgx-enclave-common libsgx-urts
2 upgraded, 5 newly installed, 0 to remove and 6 not upgraded.
Need to get 2,529 kB of archives.
After this operation, 3,976 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
```

The results shows that AESMD and SGX PSW has been successfully installed.

```
$ is-sgx-available
SGX supported by CPU: true
SGX1 (ECREATE, EENTER, ...): true
SGX2 (EAUG, EACCEPT, EMODPR, ...): true
Flexible Launch Control (IA32_SGXPUBKEYHASH{0..3} MSRs): true
SGX extensions for virtualizers (EINCVIRTCHILD, EDECVIRTCHILD, ESETCONTEXT): false
Extensions for concurrent memory management (ETRACKC, ELDBC, ELDUC, ERDINFO): false
CET enclave attributes support (See Table 37-5 in the SDM): false
Key separation and sharing (KSS) support (CONFIGID, CONFIGSVN, ISVEXTPRODID, ISVFAMILYID report fields): false
Max enclave size (32-bit): 0x80000000
Max enclave size (64-bit): 0x1000000000
EPC size: 0x5e00000
SGX driver loaded: true
AESMD installed: true
SGX PSW/libsgx installed: true
```




Once the Secret Provisioning Service has been started, the Service Provider starts the CS in the Cloud Provider infrastructure. 
The CS will be a TCP server running in a SGX enclave and provisioned upon being attested listening on port 9401.
   
```
$ cd ~/gitlab/pylurk.git/example/cli
$ ./crypto_service --connectivity tcp --port 9401 --cert sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --gramine_sgx --secret_provisioning 
 --- Executing: /home/mglt/gitlab/pylurk.git/example/cli/./crypto_service with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=None, cert=PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=True, gramine_direct=False, gramine_build=False, secret_provisioning=True, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'")
key file not provided. New key will be generated in /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir
cmd: ./start_cs.py --connectivity tcp --host 127.0.0.1 --port 9401 --sig_scheme ed25519 --key sig_key_dir --cert ./sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --secret_provisioning
Gramine is starting. Parsing TOML manifest file, this may take some time...
mglt@nuc:~/gitlab/pylurk.git/example/cli$ Detected a huge manifest, preallocating 64MB of internal memory.
-----------------------------------------------------------------------------------------------------------------------
Gramine detected the following insecure configurations:

  - loader.insecure__use_cmdline_argv = true   (forwarding command-line args from untrusted host to the app)
  - sgx.allowed_files = [ ... ]                (some files are passed through from untrusted host without verification)

Gramine will continue application execution, but this configuration must not be used in production!
-----------------------------------------------------------------------------------------------------------------------

Detected a huge manifest, preallocating 64MB of internal memory.
secret_received [48]:
30 2E 2 1 0 30 5 6 3 2B 65 70 4 22 4 20 12 F 12 D8 DB 8F ED B0 15 49 EC 5C 63 6D DB 55 D9 7A 66 BE A7 17 6A 2C 96 47 BD A5 12 82 23 9A 0 
--- secret successfully stored
 --- Executing: //./start_cs.py with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=PosixPath('sig_key_dir'), cert=PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=False, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=True, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'")
Provisionning the secret key (and overwritting existing value if present)
cs_template_conf: {'log': None, 'connectivity': {'type': 'tcp', 'ip': '127.0.0.1', 'port': 9401}, ('tls13', 'v1'): {'sig_scheme': ['ed25519'], 'public_key': [PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')], 'private_key': 'secret_prov/secret.bin', 'debug': {'trace': False}}}
Configuration Template (from end user arguments ):

{'log': None,
 'connectivity': {'type': 'tcp',
                  'ip': '127.0.0.1',
                  'port': 9401},
 ('tls13', 'v1'): {'sig_scheme': ['ed25519'],
                   'public_key': [PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                   'private_key': 'secret_prov/secret.bin',
                   'debug': {'trace': False}}}
Full configuration:

{'profile': 'explicit configuration',
 'description': 'LURK Cryptographic Service configuration '
                'template',
 'connectivity': {'type': 'tcp',
                  'ip': '127.0.0.1',
                  'port': 9401},
 'enabled_extensions': [('lurk', 'v1'), ('tls13', 'v1')],
 ('lurk', 'v1'): {'type_authorized': ['ping', 'capabilities']},
 ('tls13', 'v1'): {'debug': {'trace': False},
                   'role': 'client',
                   'type_authorized': ['c_init_client_finished',
                                       'c_post_hand_auth',
                                       'c_init_client_hello',
                                       'c_server_hello',
                                       'c_client_finished',
                                       'c_register_tickets'],
                   'ephemeral_method_list': ['no_secret',
                                             'cs_generated',
                                             'e_generated'],
                   'authorized_ecdhe_group': ['secp256r1',
                                              'secp384r1',
                                              'secp521r1',
                                              'x25519',
                                              'x448'],
                   'sig_scheme': ['ed25519'],
                   'client_early_secret_authorized': True,
                   'early_exporter_secret_authorized': True,
                   'exporter_secret_authorized': True,
                   'app_secret_authorized': True,
                   'resumption_secret_authorized': True,
                   's_init_early_secret_session_id': True,
                   'last_exchange': {'s_init_cert_verify': False,
                                     's_hand_and_app_secret': False,
                                     'c_init_client_finished': False,
                                     'c_init_post_auth': False,
                                     'c_client_finished': False},
                   'max_tickets': 6,
                   'ticket_life_time': 172800,
                   'ticket_nonce_len': 20,
                   'ticket_generation_method': 'ticket',
                   'ticket_len': 4,
                   'post_handshake_authentication': True,
                   'max_post_handshake_authentication': 1,
                   'public_key': [PosixPath('sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                   'private_key': 'secret_prov/secret.bin',
                   '_private_key': <cryptography.hazmat.backends.openssl.ed25519._Ed25519PrivateKey object at 0x9588310>,
                   '_public_key': <cryptography.hazmat.backends.openssl.ed25519._Ed25519PublicKey object at 0x95890c0>,
                   '_cert_type': 'X509',
                   '_cert_entry_list': [{'cert': b'0\x82\x01.'
                                                 b'0\x81\xe1\xa0'
                                                 b'\x03\x02\x01\x02'
                                                 b'\x02\x14&?'
                                                 b'V\xc5s\xf6'
                                                 b'k6\xd8\x9a'
                                                 b'\x0f\xc7\xdb\xaf'
                                                 b'J\xcf\xf7\xa3'
                                                 b'r\x0f0\x05'
                                                 b'\x06\x03+e'
                                                 b'p0\x1a1'
                                                 b'\x180\x16\x06'
                                                 b'\x03U\x04\x03'
                                                 b'\x0c\x0fcr'
                                                 b'yptography.i'
                                                 b'o0\x1e\x17'
                                                 b'\r23032320151'
                                                 b'4Z\x17\r2304'
                                                 b'23201514'
                                                 b'Z0\x1a1'
                                                 b'\x180\x16\x06'
                                                 b'\x03U\x04\x03'
                                                 b'\x0c\x0fcr'
                                                 b'yptography.i'
                                                 b'o0*0'
                                                 b'\x05\x06\x03+'
                                                 b'ep\x03!'
                                                 b'\x00o~\xb8'
                                                 b'\xf5\xa3(\xa4'
                                                 b'\xb9\xc5V\xfc'
                                                 b'3\x88\x94\x96'
                                                 b'QK\xa3\x14'
                                                 b'\xa6\xcc\xaf\x86'
                                                 b'tX|$'
                                                 b'\x93\xad\\\xa6'
                                                 b'\xd8\xa390'
                                                 b'70\x1a\x06'
                                                 b'\x03U\x1d\x11'
                                                 b'\x04\x130\x11'
                                                 b'\x82\x0fcr'
                                                 b'yptography.i'
                                                 b'o0\x0b\x06'
                                                 b'\x03U\x1d\x0f'
                                                 b'\x04\x04\x03\x02'
                                                 b'\x02\xd40\x0c'
                                                 b'\x06\x03U\x1d'
                                                 b'\x13\x01\x01\xff'
                                                 b'\x04\x020\x00'
                                                 b'0\x05\x06\x03'
                                                 b'+ep\x03'
                                                 b'A\x00I\xd2'
                                                 b'L\x07\\\x93'
                                                 b'\xae\xaa\x98\x03'
                                                 b'j\xd6\xe4%'
                                                 b'etE\xbd'
                                                 b'N\x15\xfb\x14'
                                                 b'\xfd\x8dW\x9b'
                                                 b'\x80\xc5\xf5\x81'
                                                 b'\x95\x9f\xa0\xaa'
                                                 b'u\x04\xf1\xf8'
                                                 b'l\xfa\xfc\x0e'
                                                 b'\xbd\xee:\xf7'
                                                 b'\xfa\xec\xd3d'
                                                 b"\xff\x86'\xa6"

```

Once can see that the secret has been received by the CS.

Looking at the Secret Provisioning Service one can see the information provided by the QUOTE matches those expected - that is read from the SIGSTRUCT in `python.sig`.

```
IAS report: signature verified correctly
IAS report: allowing quote status GROUP_OUT_OF_DATE
            [ advisory URL: https://security-center.intel.com ]
            [ advisory IDs: ["INTEL-SA-00381", "INTEL-SA-00389", "INTEL-SA-00465", "INTEL-SA-00477", "INTEL-SA-00528", "INTEL-SA-00617", "INTEL-SA-00657", "INTEL-SA-00767"] ]
Received the following measurements from the client:
  - MRENCLAVE:   7eddfc41ba3a4f1bc4c5fbfbd85b53eee48ab65430b3bd7d259eb29b33ef2d33
  - MRSIGNER:    e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9
  - ISV_PROD_ID: 29539
  - ISV_SVN:     0
Comparing with provided values:
```
Note that Comparing with provided values is only followed by unexpected values, so here it means everything works as expected.

## 5. Testing CS connectivity

The Service Provider may be willing to check the connectivity of the CS before starting the TLS E. 

```
pylurk.git/example/cli$ ./lurk_ping --con tcp --port 9401
 --- Executing: /home/mglt/gitlab/pylurk.git/example/cli/./lurk_ping with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401)
--- E -> CS: Sending ping Request:
--- E <- CS: Receiving ping Response:
LURK PING (127.0.0.1:9401): time 0.0029506683349609375 ms.
```

## 6. Example 1: mutually authenticated TLS 1.3 to https://127.0.0.1:8403

In our configuration, th eServioce Provider starts the TLS Engine (E) that is configured to interact with CS to establish a TLS 1.3 mutually authenticated session. 

The `tls_client` performs an HTTP GET to the web server (127.0.0.1:8403), via the CS (tcp, 127.0.0.1:9401). 

[tls_client_8403](./lurk-t_tls_client/6_tls_client_8403.html) provides the  complete log output of the mutually authenticated TLS session with LURK.
To improve readability we have removed most of the binary formats which considerably increases the size of the log.
In fact when the debug mode is activated a received TLS message is showed using both a structure (like json) format as well as a binary the encrypted fragments, the decrypted fragment, the reassembled decrypted message whiuch results in the same information being displayed multiple times.

The `reconnect` option indicates that a first session is established using certificate authentication followed by PSK authentication.

The `debug` indicate sthat all messages are provided as well as internal variable used by TLS to establish a secure session.


```
cd pytls13/example/cli
./tls_client https://127.0.0.1:8403 --cert ~/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --connectivity tcp --host 127.0.0.1 --port 9401 --reconnect --debug > log.log

 --- Executing: /home/mglt/gitlab/pytls13/example/cli/./tls_client with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=None, cert=PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=True, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=False, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'", url="'https://127.0.0.1:8403'", no_session_resumption=False, freshness="'sha256'", ephemeral_method="'cs_generated'", supported_ecdhe_groups="'x25519'", reconnect=True, cs_auto_start=False, cs_gramine_sgx=False, cs_gramine_direct=False, cs_gramine_build=False)
cmd: ./start_e.py --freshness 'sha256' --ephemeral_method cs_generated --supported_ecdhe_groups 'x25519'  --reconnect   --debug --connectivity tcp --host 127.0.0.1 --port 9401 --sig_scheme ed25519 --key None --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der  'https://127.0.0.1:8403'
 --- Executing: /home/mglt/gitlab/pytls13/example/cli/./start_e.py with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=PosixPath('None'), cert=PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=True, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=False, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'", url="'https://127.0.0.1:8403'", no_session_resumption=False, freshness="'sha256'", ephemeral_method="'cs_generated'", supported_ecdhe_groups="'x25519'", reconnect=True, cs_auto_start=False, cs_gramine_sgx=False, cs_gramine_direct=False, cs_gramine_build=False)

Configuration Template (from end user arguments ):

{'destination': {'ip': '127.0.0.1', 'port': 8403},
 'sent_data': b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nuser-agent:'
              b' pytls13/0.1\r\naccept: */*\r\n\r\n',
 'debug': {'trace': True},
 'lurk_client': {'connectivity': {'type': 'tcp',
                                  'ip': '127.0.0.1',
                                  'port': 9401},
                 'freshness': 'sha256'},
 'tls13': {'ephemeral_method': 'cs_generated',
           'supported_ecdhe_groups': ['x25519'],
           'session_resumption': True},
 'cs': {'log': None,
        'connectivity': {'type': 'tcp',
                         'ip': '127.0.0.1',
                         'port': 9401},
        ('tls13', 'v1'): {'sig_scheme': ['ed25519'],
                          'public_key': [PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                          'debug': {'trace': True}}}}

Full configuration:

{'role': 'client',
 'description': 'TLS 1.3 Client configuration template',
 'debug': {'trace': True},
 'lurk_client': {'freshness': 'sha256',
                 'connectivity': {'type': 'tcp',
                                  'ip': '127.0.0.1',
                                  'port': 9401}},
 'tls13': {'ke_modes': ['psk_dhe_ke'],
           'session_resumption': True,
           'post_handshake_authentication': False,
           'signature_algorithms': ['rsa_pkcs1_sha256',
                                    'rsa_pkcs1_sha384',
                                    'rsa_pkcs1_sha512',
                                    'ecdsa_secp256r1_sha256',
                                    'ecdsa_secp384r1_sha384',
                                    'ecdsa_secp521r1_sha512',
                                    'rsa_pss_rsae_sha256',
                                    'rsa_pss_rsae_sha384',
                                    'rsa_pss_pss_sha256',
                                    'rsa_pss_pss_sha384',
                                    'rsa_pss_pss_sha256',
                                    'ed25519',
                                    'ed448',
                                    'rsa_pkcs1_sha1'],
           'ephemeral_method': 'cs_generated',
           'supported_ecdhe_groups': ['x25519']},
 'cs': {('tls13', 'v1'): {'public_key': [PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                          'sig_scheme': ['ed25519'],
                          '_public_key': <cryptography.hazmat.backends.openssl.ed25519._Ed25519PublicKey object at 0x7f1553229cc0>,
                          '_cert_type': 'X509',
                          '_cert_entry_list': [{'cert': b'0\x82\x01.'
                                                        [...]
                                                        b'\x8f\t',
                                                'extensions': []}],
                          '_finger_print_entry_list': [{'finger_print': b'Y3{\xe1',
                                                        'extensions': []}],
                          '_finger_print_dict': {b'Y3{\xe1': b'0\x82\x01.'
                                                             [...]
                                                             b'\x8f\t'}}},
 'destination': {'ip': '127.0.0.1', 'port': 8403},
 'sent_data': b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nuser-agent:'
              b' pytls13/0.1\r\naccept: */*\r\n\r\n'}
======================================================
========= TLS with certificate authentication ========
======================================================

::Instantiating the Lurk client
--- E -> CS: Sending ping Request:
--- E <- CS: Receiving ping Response:
::TCP session with the TLS server
--- E -> CS: Sending c_init_client_hello Request:
--- E <- CS: Receiving c_init_client_hello Response:
:: 
Sending client_hello
  - TLS record 1 client_client_hello [177 bytes]:
16 03 03 00 ac 01 00 00 a8 03 03 70 1b 1d 81 2e
12 4c 9e ba 0b df f6 62 3a 2d 73 ce [...]
  - TLS record 1 client_client_hello: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        msg_type = (enum) client_hello 1
        data = Container: 
            legacy_version = b'\x03\x03' (total 2)
            random = b'p\x1b\x1d\x81.\x12L\x9e\xba\x0b\xdf\xf6b:-s'... (truncated, total 32)
            legacy_session_id = b'\x85-\x0c\x1b\x00\x8d\xc9\xaf\xd1\x8d\xca\xde\xf9\x88\x8d\xc0'... (truncated, total 32)
            cipher_suites = ListContainer: 
                TLS_AES_128_GCM_SHA256
                TLS_CHACHA20_POLY1305_SHA256
            legacy_compression_methods = b'\x00' (total 1)
            extensions = ListContainer: 
                Container: 
                    extension_type = (enum) supported_versions 43
                    extension_data = Container: 
                        versions = ListContainer: 
                            b'\x03\x04'
                Container: 
                    extension_type = (enum) signature_algorithms 13
                    extension_data = Container: 
                        supported_signature_algorithms = ListContainer: 
                            rsa_pkcs1_sha256
                            rsa_pkcs1_sha384
                            rsa_pkcs1_sha512
                            ecdsa_secp256r1_sha256
                            ecdsa_secp384r1_sha384
                            ecdsa_secp521r1_sha512
                            rsa_pss_rsae_sha256
                            rsa_pss_rsae_sha384
                            rsa_pss_pss_sha256
                            rsa_pss_pss_sha384
                            rsa_pss_pss_sha256
                            ed25519
                            ed448
                            rsa_pkcs1_sha1
                Container: 
                    extension_type = (enum) supported_groups 10
                    extension_data = Container: 
                        named_group_list = ListContainer: 
                            x25519
                Container: 
                    extension_type = (enum) key_share 51
                    extension_data = Container: 
                        client_shares = ListContainer: 
                            Container: 
                                group = (enum) x25519 b'\x00\x1d'
                                key_exchange = b'A\x07\xb7\x9a\xba\x03\xef\xf4Er\xdd?/\x8a\xb5\xad'... (truncated, total 32)

:: Receiving new plain text fragment
  - TLS record 1 server_fragment_bytes [127 bytes]:
16 03 03 00 7a 02 00 00 76 03 03 8e 43 52 f1 cc
6d 75 9d c0 36 37 17 d6 ac b8 f9 4e [...]
  - TLS record 1 server_fragment_bytes: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x02\x00\x00v\x03\x03\x8eCR\xf1\xccmu\x9d\xc06'... (truncated, total 122)
  - handshake_message: [122 bytes]:
02 00 00 76 03 03 8e 43 52 f1 cc 6d 75 9d c0 36
37 17 d6 ac b8 f9 4e 8f f1 3a 6f 49 e3 [...]
handshake_message: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'\x8eCR\xf1\xccmu\x9d\xc067\x17\xd6\xac\xb8\xf9'... (truncated, total 32)
        legacy_session_id_echo = b'\x85-\x0c\x1b\x00\x8d\xc9\xaf\xd1\x8d\xca\xde\xf9\x88\x8d\xc0'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'\xac\x9f\xe5\x17\x02\xdb\x80\xd1\xfe\xd7\x86\x11\x80\x96\x7f\n'... (truncated, total 32)
:: server_hello received

  - TLS message 1 server_server_hello [122 bytes]:
02 00 00 76 03 03 8e 43 52 f1 cc 6d 75 9d c0 36
37 17 d6 ac b8 f9 4e 8f f1 3a 6f 49 e3 [...]
  - TLS message 1 server_server_hello: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'\x8eCR\xf1\xccmu\x9d\xc067\x17\xd6\xac\xb8\xf9'... (truncated, total 32)
        legacy_session_id_echo = b'\x85-\x0c\x1b\x00\x8d\xc9\xaf\xd1\x8d\xca\xde\xf9\x88\x8d\xc0'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'\xac\x9f\xe5\x17\x02\xdb\x80\xd1\xfe\xd7\x86\x11\x80\x96\x7f\n'... (truncated, total 32)
:: server_hello received

--- E -> CS: Sending c_server_hello Request:
--- E <- CS: Receiving c_server_hello Response:
  - Transcript Hash [mode h] [32 bytes]:
06 3a af da 4b 5a 91 de 5f 7f 23 d7 c0 4f a8 38
12 00 95 8a 98 a7 12 a1 47 9d a7 b1 52 e3 c7 b6
  - server_handshake_write_key [16 bytes]:
44 e3 a3 98 ab 68 21 0e 59 fb 8e e9 22 c1 dd 81
  - server_handshake_write_iv [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - client_handshake_write_key [16 bytes]:
80 b3 6a 77 f8 f0 a7 25 d4 70 e9 b4 77 ed 89 ef
  - client_handshake_write_iv [12 bytes]:
27 d3 d1 1f 83 46 71 f4 75 2a 0d ff

:: Receiving new plain text fragment
  - TLS record 2 server_change_cipher_spec [6 bytes]:
14 03 03 00 01 01
  - TLS record 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 20
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        type = (enum) change_cipher_spec 1
  - TLS message 2 server_change_cipher_spec [1 bytes]:
01
  - TLS message 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 1
:: change_cipher_spec received


:: Receiving new plain text fragment
  - TLS record 3 server_application_data [28 bytes]:
17 03 03 00 17 2f 40 64 27 d4 fc 28 28 ae 2e bc
36 a1 36 54 76 ba f5 b2 53 8d 7f 8b
  - TLS record 3 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b"/@d'\xd4\xfc((\xae.\xbc6\xa16Tv"... (truncated, total 23)
  - fragment (encrypted) [23 bytes]:
2f 40 64 27 d4 fc 28 28 ae 2e bc 36 a1 36 54 76
ba f5 b2 53 8d 7f 8b
  - write_key [16 bytes]:
44 e3 a3 98 ab 68 21 0e 59 fb 8e e9 22 c1 dd 81
  - write_iv [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - nonce [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - additional_data [5 bytes]:
17 03 03 00 17
'  - sequence_number: 0'
  - Inner TLS message 3 server_fragment_bytes_(decrypted) [7 bytes]:
08 00 00 02 00 00 16
  - Inner TLS message 3 server_fragment_bytes_(decrypted): Container: 
    content = b'\x08\x00\x00\x02\x00\x00' (total 6)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [6 bytes]:
08 00 00 02 00 00
handshake_message: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received

  - TLS message 3 server_encrypted_extensions [6 bytes]:
08 00 00 02 00 00
  - TLS message 3 server_encrypted_extensions: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received


:: Receiving new plain text fragment
  - TLS record 4 server_application_data [172 bytes]:
17 03 03 00 a7 d1 40 bc f3 bc 4a b7 cd 80 12 9a
75 3e 59 d8 5e 34 f0 eb fe 07 1f 0a c7 [...]
  - TLS record 4 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xd1@\xbc\xf3\xbcJ\xb7\xcd\x80\x12\x9au>Y\xd8^'... (truncated, total 167)
  - fragment (encrypted) [167 bytes]:
d1 40 bc f3 bc 4a b7 cd 80 12 9a 75 3e 59 d8 5e
34 f0 eb fe 07 1f 0a c7 2a f9 2e 1c 30 [...]
  - write_key [16 bytes]:
44 e3 a3 98 ab 68 21 0e 59 fb 8e e9 22 c1 dd 81
  - write_iv [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - nonce [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d9
  - additional_data [5 bytes]:
17 03 03 00 a7
'  - sequence_number: 1'
  - Inner TLS message 4 server_fragment_bytes_(decrypted) [151 bytes]:
0d 00 00 92 00 00 8f 00 0d 00 22 00 20 04 03 05
03 06 03 08 07 08 08 08 09 08 0a 08 0b [...]
  - Inner TLS message 4 server_fragment_bytes_(decrypted): Container: 
    content = b'\r\x00\x00\x92\x00\x00\x8f\x00\r\x00"\x00 \x04\x03\x05'... (truncated, total 150)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [150 bytes]:
0d 00 00 92 00 00 8f 00 0d 00 22 00 20 04 03 05
03 06 03 08 07 08 08 08 09 08 0a 08 0b [...]
handshake_message: Container: 
    msg_type = (enum) certificate_request 13
    data = Container: 
        certificate_request_context = b'' (total 0)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) signature_algorithms 13
                extension_data = Container: 
                    supported_signature_algorithms = ListContainer: 
                        ecdsa_secp256r1_sha256
                        ecdsa_secp384r1_sha384
                        ecdsa_secp521r1_sha512
                        ed25519
                        ed448
                        rsa_pss_pss_sha256
                        rsa_pss_pss_sha384
                        rsa_pss_pss_sha512
                        rsa_pss_rsae_sha256
                        rsa_pss_rsae_sha384
                        rsa_pss_rsae_sha512
                        rsa_pkcs1_sha256
                        rsa_pkcs1_sha384
                        rsa_pkcs1_sha512
                        backward_compatibility_sha224_ecdsa
                        backward_compatibility_sha224_rsa
            Container: 
                extension_type = (enum) certificate_authorities 47
                extension_data = b'\x00a0_1\x0b0\t\x06\x03U\x04\x06\x13\x02C'... (truncated, total 99)
:: certificate_request received

  - TLS message 4 server_certificate_request [150 bytes]:
0d 00 00 92 00 00 8f 00 0d 00 22 00 20 04 03 05
03 06 03 08 07 08 08 08 09 08 0a 08 0b [...]
  - TLS message 4 server_certificate_request: Container: 
    msg_type = (enum) certificate_request 13
    data = Container: 
        certificate_request_context = b'' (total 0)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) signature_algorithms 13
                extension_data = Container: 
                    supported_signature_algorithms = ListContainer: 
                        ecdsa_secp256r1_sha256
                        ecdsa_secp384r1_sha384
                        ecdsa_secp521r1_sha512
                        ed25519
                        ed448
                        rsa_pss_pss_sha256
                        rsa_pss_pss_sha384
                        rsa_pss_pss_sha512
                        rsa_pss_rsae_sha256
                        rsa_pss_rsae_sha384
                        rsa_pss_rsae_sha512
                        rsa_pkcs1_sha256
                        rsa_pkcs1_sha384
                        rsa_pkcs1_sha512
                        backward_compatibility_sha224_ecdsa
                        backward_compatibility_sha224_rsa
            Container: 
                extension_type = (enum) certificate_authorities 47
                extension_data = b'\x00a0_1\x0b0\t\x06\x03U\x04\x06\x13\x02C'... (truncated, total 99)
:: certificate_request received

  - built certificate_request [150 bytes]:
0d 00 00 92 00 00 8f 00 0d 00 22 00 20 04 03 05
03 06 03 08 07 08 08 08 09 08 0a 08 [...]

:: Receiving new plain text fragment
  - TLS record 5 server_application_data [862 bytes]:
17 03 03 03 59 70 4d d1 07 d1 12 36 26 5f 53 70
ee 63 eb 80 36 2d 79 d7 0e c7 ad 1c [...]
  - TLS record 5 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'pM\xd1\x07\xd1\x126&_Sp\xeec\xeb\x806'... (truncated, total 857)
  - fragment (encrypted) [857 bytes]:
70 4d d1 07 d1 12 36 26 5f 53 70 ee 63 eb 80 36
2d 79 d7 0e c7 ad 1c 75 cb 9f 08 40 [...]
  - write_key [16 bytes]:
44 e3 a3 98 ab 68 21 0e 59 fb 8e e9 22 c1 dd 81
  - write_iv [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - nonce [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 da
  - additional_data [5 bytes]:
17 03 03 03 59
'  - sequence_number: 2'
  - Inner TLS message 5 server_fragment_bytes_(decrypted) [841 bytes]:
0b 00 03 44 00 00 03 40 00 03 3b 30 82 03 37 30
82 02 1f 02 14 07 c8 5c f3 c2 19 85 [...]
  - Inner TLS message 5 server_fragment_bytes_(decrypted): Container: 
    content = b'\x0b\x00\x03D\x00\x00\x03@\x00\x03;0\x82\x0370'... (truncated, total 840)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [840 bytes]:
0b 00 03 44 00 00 03 40 00 03 3b 30 82 03 37 30
82 02 1f 02 14 07 c8 5c f3 c2 19 85 9a [...]
handshake_message: Container: 
    msg_type = (enum) certificate 11
    data = Container: 
        certificate_request_context = b'' (total 0)
        certificate_list = ListContainer: 
            Container: 
                cert = b'0\x82\x0370\x82\x02\x1f\x02\x14\x07\xc8\\\xf3\xc2\x19'... (truncated, total 827)
                extensions = ListContainer: 
:: certificate received

  - TLS message 5 server_certificate [840 bytes]:
0b 00 03 44 00 00 03 40 00 03 3b 30 82 03 37 30
82 02 1f 02 14 07 c8 5c f3 c2 19 85 [...]
  - TLS message 5 server_certificate: Container: 
    msg_type = (enum) certificate 11
    data = Container: 
        certificate_request_context = b'' (total 0)
        certificate_list = ListContainer: 
            Container: 
                cert = b'0\x82\x0370\x82\x02\x1f\x02\x14\x07\xc8\\\xf3\xc2\x19'... (truncated, total 827)
                extensions = ListContainer: 
:: certificate received


:: Receiving new plain text fragment
  - TLS record 6 server_application_data [286 bytes]:
17 03 03 01 19 95 a6 03 1c 9c dd fc fe e1 89 77
97 57 72 9e 35 eb a7 3b dd bd f7 83 [...]
  - TLS record 6 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x95\xa6\x03\x1c\x9c\xdd\xfc\xfe\xe1\x89w\x97Wr\x9e5'... (truncated, total 281)
  - fragment (encrypted) [281 bytes]:
95 a6 03 1c 9c dd fc fe e1 89 77 97 57 72 9e 35
eb a7 3b dd bd f7 83 58 f4 4b da 6f d7 [...]
  - write_key [16 bytes]:
44 e3 a3 98 ab 68 21 0e 59 fb 8e e9 22 c1 dd 81
  - write_iv [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - nonce [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 db
  - additional_data [5 bytes]:
17 03 03 01 19
'  - sequence_number: 3'
  - Inner TLS message 6 server_fragment_bytes_(decrypted) [265 bytes]:
0f 00 01 04 08 04 01 00 67 ca 9f f5 b9 e5 e6 56
65 40 76 5d bd 1c 25 f6 9e 4f db b6 91 [...]
  - Inner TLS message 6 server_fragment_bytes_(decrypted): Container: 
    content = b'\x0f\x00\x01\x04\x08\x04\x01\x00g\xca\x9f\xf5\xb9\xe5\xe6V'... (truncated, total 264)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [264 bytes]:
0f 00 01 04 08 04 01 00 67 ca 9f f5 b9 e5 e6 56
65 40 76 5d bd 1c 25 f6 9e 4f db b6 [...]
handshake_message: Container: 
    msg_type = (enum) certificate_verify 15
    data = Container: 
        algorithm = (enum) rsa_pss_rsae_sha256 b'\x08\x04'
        signature = b'g\xca\x9f\xf5\xb9\xe5\xe6Ve@v]\xbd\x1c%\xf6'... (truncated, total 256)
:: certificate_verify received

  - TLS message 6 server_certificate_verify [264 bytes]:
0f 00 01 04 08 04 01 00 67 ca 9f f5 b9 e5 e6 56
65 40 76 5d bd 1c 25 f6 9e 4f db b6 91 [...]
  - TLS message 6 server_certificate_verify: Container: 
    msg_type = (enum) certificate_verify 15
    data = Container: 
        algorithm = (enum) rsa_pss_rsae_sha256 b'\x08\x04'
        signature = b'g\xca\x9f\xf5\xb9\xe5\xe6Ve@v]\xbd\x1c%\xf6'... (truncated, total 256)
:: certificate_verify received

  - Transcript Hash [mode sig] [32 bytes]:
43 85 8d a2 f7 50 64 e1 cb 77 5d e1 f9 95 b1 f9
e2 78 b0 7b cf 12 40 b3 a6 6c d8 a7 09 09 31 7d
  - ctx_string [33 bytes]: b'TLS 1.3, server CertificateVerify'
  - ctx_string [33 bytes]:
54 4c 53 20 31 2e 33 2c 20 73 65 72 76 65 72 20
43 65 72 74 69 66 69 63 61 74 65 56 65 72 69 66
79
  - content to be signed [130 bytes]:
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
54 4c 53 20 31 2e 33 2c 20 73 65 72 76 65 72 20
43 65 72 74 69 66 69 63 61 74 65 56 65 72 69 66
79 00 43 85 8d a2 f7 50 64 e1 cb 77 5d e1 f9 95
b1 f9 e2 78 b0 7b cf 12 40 b3 a6 6c d8 a7 09 09
31 7d

:: Receiving new plain text fragment
  - TLS record 7 server_application_data [58 bytes]:
17 03 03 00 35 90 b0 a9 bd 7e c6 57 c8 6b db 3a
13 ae 16 f3 d9 6b 6a a4 ac 07 f3 6f 7e 3a 32 23
60 b1 0f 39 40 d9 13 c3 b7 ea 0e b6 c4 b2 ca a2
35 cf 95 4a de de 75 34 6d 98
  - TLS record 7 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x90\xb0\xa9\xbd~\xc6W\xc8k\xdb:\x13\xae\x16\xf3\xd9'... (truncated, total 53)
  - fragment (encrypted) [53 bytes]:
90 b0 a9 bd 7e c6 57 c8 6b db 3a 13 ae 16 f3 d9
6b 6a a4 ac 07 f3 6f 7e 3a 32 23 60 b1 0f 39 40
d9 13 c3 b7 ea 0e b6 c4 b2 ca a2 35 cf 95 4a de
de 75 34 6d 98
  - write_key [16 bytes]:
44 e3 a3 98 ab 68 21 0e 59 fb 8e e9 22 c1 dd 81
  - write_iv [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 d8
  - nonce [12 bytes]:
b6 89 f2 c6 5e 6e a1 f4 15 bd c1 dc
  - additional_data [5 bytes]:
17 03 03 00 35
'  - sequence_number: 4'
  - Inner TLS message 7 server_fragment_bytes_(decrypted) [37 bytes]:
14 00 00 20 0e b6 a5 a9 b2 9d ef 67 29 e7 a8 bc
3e 5d 23 f5 35 39 16 0c fe 4e 32 7a 7f f3 3b 5c
29 74 a4 97 16
  - Inner TLS message 7 server_fragment_bytes_(decrypted): Container: 
    content = b'\x14\x00\x00 \x0e\xb6\xa5\xa9\xb2\x9d\xefg)\xe7\xa8\xbc'... (truncated, total 36)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [36 bytes]:
14 00 00 20 0e b6 a5 a9 b2 9d ef 67 29 e7 a8 bc
3e 5d 23 f5 35 39 16 0c fe 4e 32 7a 7f f3 3b 5c
29 74 a4 97
handshake_message: Container: 
    msg_type = (enum) finished 20
    data = Container: 
        verify_data = b'\x0e\xb6\xa5\xa9\xb2\x9d\xefg)\xe7\xa8\xbc>]#\xf5'... (truncated, total 32)
:: finished received

  - TLS message 7 server_finished [36 bytes]:
14 00 00 20 0e b6 a5 a9 b2 9d ef 67 29 e7 a8 bc
3e 5d 23 f5 35 39 16 0c fe 4e 32 7a 7f f3 3b 5c
29 74 a4 97
  - TLS message 7 server_finished: Container: 
    msg_type = (enum) finished 20
    data = Container: 
        verify_data = b'\x0e\xb6\xa5\xa9\xb2\x9d\xefg)\xe7\xa8\xbc>]#\xf5'... (truncated, total 32)
:: finished received

  - Transcript Hash [mode server finished] [32 bytes]:
86 53 59 e6 8e a6 70 80 a4 f4 3e 38 11 90 52 22
c6 88 3b ea b6 60 79 b8 6a 91 dd c6 3e 6b 58 a1
  - client computed verify_data [32 bytes]:
0e b6 a5 a9 b2 9d ef 67 29 e7 a8 bc 3e 5d 23 f5
35 39 16 0c fe 4e 32 7a 7f f3 3b 5c 29 74 a4 97
  - server provided verify_data [32 bytes]:
0e b6 a5 a9 b2 9d ef 67 29 e7 a8 bc 3e 5d 23 f5
35 39 16 0c fe 4e 32 7a 7f f3 3b 5c 29 74 a4 97
:: Sending certificate

  - Inner TLS message 9 client_certificate [320 bytes]:
0b 00 01 3b 00 00 01 37 00 01 32 30 82 01 2e 30
81 e1 a0 03 02 01 02 02 14 26 3f 56 c5 73 f6 6b
36 d8 9a 0f c7 db af 4a cf f7 a3 72 0f 30 05 06
03 2b 65 70 30 1a 31 18 30 16 06 03 55 04 03 0c
0f 63 72 79 70 74 6f 67 72 61 70 68 79 2e 69 6f
30 1e 17 0d 32 33 30 33 32 33 32 30 31 35 31 34
5a 17 0d 32 33 30 34 32 33 32 30 31 35 31 34 5a
30 1a 31 18 30 16 06 03 55 04 03 0c 0f 63 72 79
70 74 6f 67 72 61 70 68 79 2e 69 6f 30 2a 30 05
06 03 2b 65 70 03 21 00 6f 7e b8 f5 a3 28 a4 b9
c5 56 fc 33 88 94 96 51 4b a3 14 a6 cc af 86 74
58 7c 24 93 ad 5c a6 d8 a3 39 30 37 30 1a 06 03
55 1d 11 04 13 30 11 82 0f 63 72 79 70 74 6f 67
72 61 70 68 79 2e 69 6f 30 0b 06 03 55 1d 0f 04
04 03 02 02 d4 30 0c 06 03 55 1d 13 01 01 ff 04
02 30 00 30 05 06 03 2b 65 70 03 41 00 49 d2 4c
07 5c 93 ae aa 98 03 6a d6 e4 25 65 74 45 bd 4e
15 fb 14 fd 8d 57 9b 80 c5 f5 81 95 9f a0 aa 75
04 f1 f8 6c fa fc 0e bd ee 3a f7 fa ec d3 64 ff
86 27 a6 0d 48 dd 7c c5 72 6b 64 8f 09 00 00 16
  - Inner TLS message 9 client_certificate: Container: 
    content = Container: 
        msg_type = (enum) certificate 11
        data = Container: 
            certificate_request_context = b'' (total 0)
            certificate_list = ListContainer: 
                Container: 
                    cert = b'0\x82\x01.0\x81\xe1\xa0\x03\x02\x01\x02\x02\x14&?'... (truncated, total 306)
                    extensions = ListContainer: 
    type = (enum) handshake 22
    zeros = None
  - TLS record 9 client_application_data [341 bytes]:
17 03 03 01 50 0c 19 d5 fc 55 e0 de aa ad df 5c
9a df 8e 57 0a e0 46 1c 60 0c 57 3d c9 c8 2c 8e
78 6e d7 83 37 f3 25 d4 ba be 26 ae cc f8 18 c9
5f 8a 42 cc 56 04 74 e8 ea 90 57 2e ef 6d 6c ae
98 bc 6b 9b 5a bc 92 31 bc 11 40 17 db ac 63 5b
36 b3 2a 31 9a 67 90 70 cd 4a 43 28 53 5b 5d dc
9d f5 12 fb e7 9c 60 47 4a 44 d3 0d 65 73 49 61
ed c2 c8 23 7d b9 e3 fb a9 a7 19 be 32 a0 49 bd
36 61 28 1a 4b 72 81 c5 1f 2c 12 cf 57 aa 02 ed
10 1a 03 55 fa 7b 5b c0 e2 6c f0 86 d8 26 f4 a2
e3 89 b8 6e 38 7b ac eb e0 07 b3 f0 c0 25 12 65
f7 0c fc 0a 19 ca 0e e4 d4 ac 08 0e aa 17 c3 04
c4 3d dc 60 08 1f 55 57 92 83 ab 29 4d 11 65 51
08 25 04 bf ed 7b 8e d8 b7 3f c3 3c 68 e7 7d 98
4d 96 52 21 4e 15 ce f5 2f 9b 58 11 7a 09 c2 47
57 2b d2 16 0e 7e 50 49 df 95 6f 45 85 99 2e 16
81 8d 09 75 f3 bb 63 25 0e 49 04 dd 57 63 90 8e
ab 87 15 eb 5a 4d 41 f2 b8 f7 d0 20 56 36 2d f8
4a 12 89 27 a7 a4 fb bb 87 f3 a9 79 17 b5 db 48
82 f6 50 b5 08 40 96 56 68 f5 bc 16 cc d0 e3 d6
e1 61 cb f6 04 d6 40 e5 c5 a8 3d be f7 3b d2 d7
43 eb 17 f4 00
  - TLS record 9 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x0c\x19\xd5\xfcU\xe0\xde\xaa\xad\xdf\\\x9a\xdf\x8eW\n'... (truncated, total 336)
--- E -> CS: Sending c_client_finished Request:
--- E <- CS: Receiving c_client_finished Response:
:: Sending certificate_verify

  - Inner TLS message 11 client_certificate_verify [73 bytes]:
0f 00 00 44 08 07 00 40 83 5c b2 f9 5a de be 9d
6d 13 8a 7b df ea 42 bc 08 1e 09 44 1b a7 e1 a1
60 d5 2a c2 55 52 ba c2 a6 4f 05 47 d1 a1 ce 39
63 f8 a9 f9 7c 78 e3 bf 9a 2b c0 2c a3 19 a6 99
79 13 1d cc 00 f7 d1 0c 16
  - Inner TLS message 11 client_certificate_verify: Container: 
    content = Container: 
        msg_type = (enum) certificate_verify 15
        data = Container: 
            algorithm = (enum) ed25519 b'\x08\x07'
            signature = b'\x83\\\xb2\xf9Z\xde\xbe\x9dm\x13\x8a{\xdf\xeaB\xbc'... (truncated, total 64)
    type = (enum) handshake 22
    zeros = None
  - TLS record 11 client_application_data [94 bytes]:
17 03 03 00 59 fc 92 98 91 10 91 82 6b 9f 6f 26
0d 06 41 0a 6e 70 89 ac fc 4d f4 9e 66 64 52 dd
7d ed cb 26 22 f1 a9 3d 8d 29 eb a2 1a 5c 35 80
25 42 84 50 db ec 9d d6 f2 6d 9b f7 d4 af 75 9e
1e 19 c6 e4 3a 0c 44 77 1d 8d 0f e4 85 cd d4 cd
4d 84 fc c0 5e ed 35 62 33 09 5f 7c 31 7a
  - TLS record 11 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xfc\x92\x98\x91\x10\x91\x82k\x9fo&\r\x06A\nn'... (truncated, total 89)
  - Transcript Hash [mode client finished] [32 bytes]:
3f 75 e8 a9 5e 9f 25 78 5c 15 8e 72 69 f2 c6 66
a7 53 91 29 0e 8d 14 8c 00 32 73 f5 a1 42 b3 4b
:: Sending finished

  - Inner TLS message 13 client_finished [37 bytes]:
14 00 00 20 28 8d ed 2c 4b 4a f1 d8 d4 fa 6f 53
cb b9 97 02 3a ea 7f 7d 45 b4 30 9c 1c 3f c6 9c
ea 9c 23 c9 16
  - Inner TLS message 13 client_finished: Container: 
    content = Container: 
        msg_type = (enum) finished 20
        data = Container: 
            verify_data = b'(\x8d\xed,KJ\xf1\xd8\xd4\xfaoS\xcb\xb9\x97\x02'... (truncated, total 32)
    type = (enum) handshake 22
    zeros = None
  - TLS record 13 client_application_data [58 bytes]:
17 03 03 00 35 08 3f c2 58 1f cd 5c e2 aa 69 5d
d0 f0 45 05 e1 68 b4 18 09 9e c4 e1 64 c4 89 4b
11 61 81 fa d6 66 2e 08 e0 dd 18 c3 1f e6 84 15
b1 58 c4 cf b4 cc 72 25 bd f4
  - TLS record 13 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x08?\xc2X\x1f\xcd\\\xe2\xaai]\xd0\xf0E\x05\xe1'... (truncated, total 53)
  - server_application_write_key [16 bytes]:
a5 d5 ff 5a 5b 0b df aa fb d6 fe 66 00 6c 67 4c
  - server_application_write_iv [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f6
  - client_application_write_key [16 bytes]:
b5 7a 57 3b 52 3b 5b c7 bd 26 8b 26 8e 7b e7 ad
  - client_application_write_iv [12 bytes]:
12 f0 92 d5 10 ad bc 2d bc f3 eb 9a
:: Sending application_data

  - Inner TLS message 15 client_application_data [74 bytes]:
47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
48 6f 73 74 3a 20 31 32 37 2e 30 2e 30 2e 31 0d
0a 75 73 65 72 2d 61 67 65 6e 74 3a 20 70 79 74
6c 73 31 33 2f 30 2e 31 0d 0a 61 63 63 65 70 74
3a 20 2a 2f 2a 0d 0a 0d 0a 17
  - Inner TLS message 15 client_application_data: Container: 
    content = b'GET / HTTP/1.1\r\n'... (truncated, total 73)
    type = (enum) application_data 23
    zeros = None
  - TLS record 15 client_application_data [95 bytes]:
17 03 03 00 5a 00 a8 6f 80 d7 c6 4e 2e 17 24 31
39 e0 b7 d1 1b f4 33 b6 60 87 3f 3f e3 31 85 18
2e cc 22 88 5e ec 64 cf c1 c0 32 01 31 49 4d 34
fc ba 2b 24 83 b6 e3 86 fb 44 dd 93 d1 17 00 e7
15 f0 41 22 03 cb e1 10 23 82 98 e6 d8 a9 fa a8
ab 79 4a c3 60 22 65 40 35 1a a5 46 eb 1c ce
  - TLS record 15 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x00\xa8o\x80\xd7\xc6N.\x17$19\xe0\xb7\xd1\x1b'... (truncated, total 90)

:: Receiving new plain text fragment
  - TLS record 8 server_application_data [559 bytes]:
17 03 03 02 2a 3b ab ab 8d 85 ea 57 07 95 7d 84
24 4e bf c5 f6 8b 4f da 0d 08 33 c8 5c [...]
  - TLS record 8 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b';\xab\xab\x8d\x85\xeaW\x07\x95}\x84$N\xbf\xc5\xf6'... (truncated, total 554)
  - fragment (encrypted) [554 bytes]:
3b ab ab 8d 85 ea 57 07 95 7d 84 24 4e bf c5 f6
8b 4f da 0d 08 33 c8 5c 09 c8 0f 25 [...]
  - write_key [16 bytes]:
a5 d5 ff 5a 5b 0b df aa fb d6 fe 66 00 6c 67 4c
  - write_iv [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f6
  - nonce [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f6
  - additional_data [5 bytes]:
17 03 03 02 2a
'  - sequence_number: 0'
  - Inner TLS message 8 server_fragment_bytes_(decrypted) [538 bytes]:
04 00 02 15 00 00 1c 20 35 08 0f f4 08 00 00 00
00 00 00 00 00 02 00 43 08 3d ec 3a [...]
  - Inner TLS message 8 server_fragment_bytes_(decrypted): Container: 
    content = b'\x04\x00\x02\x15\x00\x00\x1c 5\x08\x0f\xf4\x08\x00\x00\x00'... (truncated, total 537)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [537 bytes]:
04 00 02 15 00 00 1c 20 35 08 0f f4 08 00 00 00
00 00 00 00 00 02 00 43 08 3d ec 3a [...]
handshake_message: Container: 
    msg_type = (enum) new_session_ticket 4
    data = Container: 
        ticket_lifetime = 7200
        ticket_age_add = 889720820
        ticket_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00' (total 8)
        ticket = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
        extensions = ListContainer: 
:: new_session_ticket received

  - TLS message 8 server_new_session_ticket [537 bytes]:
04 00 02 15 00 00 1c 20 35 08 0f f4 08 00 00 00
00 00 00 00 00 02 00 43 08 3d ec 3a [...]
  - TLS message 8 server_new_session_ticket: Container: 
    msg_type = (enum) new_session_ticket 4
    data = Container: 
        ticket_lifetime = 7200
        ticket_age_add = 889720820
        ticket_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00' (total 8)
        ticket = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
        extensions = ListContainer: 
:: new_session_ticket received

--- E -> CS: Sending c_register_tickets Request:
--- E <- CS: Receiving c_register_tickets Response:

:: Receiving new plain text fragment
  - TLS record 9 server_application_data [559 bytes]:
17 03 03 02 2a 71 d9 40 82 0b 77 8f 67 c1 af 7d
bc 6d b2 ff f2 e5 2a 11 2d d5 7f e5 [...]
  - TLS record 9 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'q\xd9@\x82\x0bw\x8fg\xc1\xaf}\xbcm\xb2\xff\xf2'... (truncated, total 554)
  - fragment (encrypted) [554 bytes]:
71 d9 40 82 0b 77 8f 67 c1 af 7d bc 6d b2 ff f2
e5 2a 11 2d d5 7f e5 f0 0f b6 5f 74 [...]
  - write_key [16 bytes]:
a5 d5 ff 5a 5b 0b df aa fb d6 fe 66 00 6c 67 4c
  - write_iv [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f6
  - nonce [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f7
  - additional_data [5 bytes]:
17 03 03 02 2a
'  - sequence_number: 1'
  - Inner TLS message 9 server_fragment_bytes_(decrypted) [538 bytes]:
04 00 02 15 00 00 1c 20 15 fc 54 53 08 00 00 00
00 00 00 00 01 02 00 43 08 3d ec 3a [...]
  - Inner TLS message 9 server_fragment_bytes_(decrypted): Container: 
    content = b'\x04\x00\x02\x15\x00\x00\x1c \x15\xfcTS\x08\x00\x00\x00'... (truncated, total 537)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [537 bytes]:
04 00 02 15 00 00 1c 20 15 fc 54 53 08 00 00 00
00 00 00 00 01 02 00 43 08 3d ec 3a [...]
handshake_message: Container: 
    msg_type = (enum) new_session_ticket 4
    data = Container: 
        ticket_lifetime = 7200
        ticket_age_add = 368858195
        ticket_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x01' (total 8)
        ticket = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
        extensions = ListContainer: 
:: new_session_ticket received

  - TLS message 9 server_new_session_ticket [537 bytes]:
04 00 02 15 00 00 1c 20 15 fc 54 53 08 00 00 00
00 00 00 00 01 02 00 43 08 3d ec 3a [...]
  - TLS message 9 server_new_session_ticket: Container: 
    msg_type = (enum) new_session_ticket 4
    data = Container: 
        ticket_lifetime = 7200
        ticket_age_add = 368858195
        ticket_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x01' (total 8)
        ticket = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
        extensions = ListContainer: 
:: new_session_ticket received

--- E -> CS: Sending c_register_tickets Request:
--- E <- CS: Receiving c_register_tickets Response:

:: Receiving new plain text fragment
  - TLS record 10 server_application_data [5928 bytes]:
17 03 03 17 23 73 33 46 8c 44 f1 bb f3 7d 11 98
7f ad 74 8d a6 a6 08 3a fe f4 c7 d7 [...]
  - TLS record 10 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b's3F\x8cD\xf1\xbb\xf3}\x11\x98\x7f\xadt\x8d\xa6'... (truncated, total 5923)
  - fragment (encrypted) [5923 bytes]:
73 33 46 8c 44 f1 bb f3 7d 11 98 7f ad 74 8d a6
a6 08 3a fe f4 c7 d7 3d 0c d8 4a b1 [...]
  - write_key [16 bytes]:
a5 d5 ff 5a 5b 0b df aa fb d6 fe 66 00 6c 67 4c
  - write_iv [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f6
  - nonce [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f4
  - additional_data [5 bytes]:
17 03 03 17 23
'  - sequence_number: 2'
  - Inner TLS message 10 server_application_data_(decrypted) [5907 bytes]:
48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d
0a 43 6f 6e 74 65 6e 74 2d 74 79 [...]
  - Inner TLS message 10 server_application_data_(decrypted): Container: 
    content = b'HTTP/1.0 200 ok\r'... (truncated, total 5906)
    type = (enum) application_data 23
    zeros = None
  - TLS message 10 server_application_data [5906 bytes]:
48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d
0a 43 6f 6e 74 65 6e 74 2d 74 79 [...]
  - TLS message 10 server_application_data [5906 bytes]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">[...]</BODY></HTML>\r\n\r\n'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 11 server_application_data [24 bytes]:
17 03 03 00 13 b3 f7 02 4f 0b 7f e6 39 bf ce d5
c6 a9 1f 6d 5b 25 5d b6
  - TLS record 11 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xb3\xf7\x02O\x0b\x7f\xe69\xbf\xce\xd5\xc6\xa9\x1fm['... (truncated, total 19)
  - fragment (encrypted) [19 bytes]:
b3 f7 02 4f 0b 7f e6 39 bf ce d5 c6 a9 1f 6d 5b
25 5d b6
  - write_key [16 bytes]:
a5 d5 ff 5a 5b 0b df aa fb d6 fe 66 00 6c 67 4c
  - write_iv [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f6
  - nonce [12 bytes]:
4f de 75 81 10 cb c4 7c 0d 68 d0 f5
  - additional_data [5 bytes]:
17 03 03 00 13
'  - sequence_number: 3'
  - Inner TLS message 11 server_alert_(decrypted) [3 bytes]:
01 00 15
  - Inner TLS message 11 server_alert_(decrypted): Container: 
    content = Container: 
        level = (enum) warning 1
        description = (enum) close_notify 0
    type = (enum) alert 21
    zeros = None
  - TLS message 11 server_alert [2 bytes]:
01 00
  - TLS message 11 server_alert: Container: 
    level = (enum) warning 1
    description = (enum) close_notify 0
:: alert received

APPLICATION DATA - [cert]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">[...]</BODY></HTML>\r\n\r\n'
======================================================
============= TLS with PSK authentication ============
======================================================

::Instantiating the Lurk client
--- E -> CS: Sending ping Request:
--- E <- CS: Receiving ping Response:
::TCP session with the TLS server
--- E -> CS: Sending c_init_client_hello Request:
--- E <- CS: Receiving c_init_client_hello Response:
  - binder_key (0) [32 bytes]:
10 cc f6 f2 3f 8d 07 44 a2 c9 a2 40 e4 d5 12 df
2c 71 3b 9f cc 21 ee 31 c8 41 1a d6 4c 67 35 8a
  - binder_finished_key (0) [32 bytes]:
59 8b 49 0e 9d 5f 86 25 7f fd 6b 97 b4 b9 79 da
f6 ee 0e 39 de 3e 45 d5 4b 09 8b d7 87 93 d5 36
  - binder_key (1) [32 bytes]:
04 8d 02 23 80 47 b9 62 e5 76 36 f5 df 78 43 19
85 5e ec ee 34 45 e2 cc 3e 7c bf 02 6f 95 e8 0b
  - binder_finished_key (1) [32 bytes]:
13 3d bf 7a 0b ca 91 6c d4 10 7e 73 4f 5d c0 1d
38 90 80 43 5c ce 2a 5f 1a 6d 71 45 87 4a 6a 5e
  - truncated_client_hello [1220 bytes]:
01 00 05 04 03 03 44 83 cd 4f 3e 1d c1 a3 41 29
c3 00 b1 0d c3 06 36 0c e5 d6 41 [...]
  - compute_binder: (0) binder_finished_key [32 bytes]:
59 8b 49 0e 9d 5f 86 25 7f fd 6b 97 b4 b9 79 da
f6 ee 0e 39 de 3e 45 d5 4b 09 8b d7 87 93 d5 36
  - Transcript( truncated_client_hello ) (0) [32 bytes]:
ae 39 19 bc 5c 70 51 9f 48 f4 59 60 8c 35 b7 fd
a3 7e 46 1c a6 d2 39 30 cf c6 83 79 3b 48 4b 11
  - binder (0) [32 bytes]:
b2 04 89 fc 8d 85 d2 45 a7 09 c7 e9 59 8f a1 1d
1a 6b 8e e3 9f 52 13 2e 61 ea 0a 41 b7 96 61 d1
  - compute_binder: (1) binder_finished_key [32 bytes]:
13 3d bf 7a 0b ca 91 6c d4 10 7e 73 4f 5d c0 1d
38 90 80 43 5c ce 2a 5f 1a 6d 71 45 87 4a 6a 5e
  - Transcript( truncated_client_hello ) (1) [32 bytes]:
ae 39 19 bc 5c 70 51 9f 48 f4 59 60 8c 35 b7 fd
a3 7e 46 1c a6 d2 39 30 cf c6 83 79 3b 48 4b 11
  - binder (1) [32 bytes]:
14 89 7f 5b f9 50 5b 0d 59 33 43 24 bd f4 7c 7f
31 b9 98 31 79 e2 3a 0f af 58 26 d3 02 4c 1f b1
:: 
Sending client_hello
  - TLS record 1 client_client_hello [1293 bytes]:
16 03 03 05 08 01 00 05 04 03 03 44 83 cd 4f 3e
1d c1 a3 41 29 c3 00 b1 0d c3 [...]
  - TLS record 1 client_client_hello: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        msg_type = (enum) client_hello 1
        data = Container: 
            legacy_version = b'\x03\x03' (total 2)
            random = b'D\x83\xcdO>\x1d\xc1\xa3A)\xc3\x00\xb1\r\xc3\x06'... (truncated, total 32)
            legacy_session_id = b'\xde\xe1\xe5\x8b\xcc\x84wm\x91`\xc2\x91\x1cL\x02R'... (truncated, total 32)
            cipher_suites = ListContainer: 
                TLS_AES_128_GCM_SHA256
                TLS_CHACHA20_POLY1305_SHA256
            legacy_compression_methods = b'\x00' (total 1)
            extensions = ListContainer: 
                Container: 
                    extension_type = (enum) supported_versions 43
                    extension_data = Container: 
                        versions = ListContainer: 
                            b'\x03\x04'
                Container: 
                    extension_type = (enum) signature_algorithms 13
                    extension_data = Container: 
                        supported_signature_algorithms = ListContainer: 
                            rsa_pkcs1_sha256
                            rsa_pkcs1_sha384
                            rsa_pkcs1_sha512
                            ecdsa_secp256r1_sha256
                            ecdsa_secp384r1_sha384
                            ecdsa_secp521r1_sha512
                            rsa_pss_rsae_sha256
                            rsa_pss_rsae_sha384
                            rsa_pss_pss_sha256
                            rsa_pss_pss_sha384
                            rsa_pss_pss_sha256
                            ed25519
                            ed448
                            rsa_pkcs1_sha1
                Container: 
                    extension_type = (enum) supported_groups 10
                    extension_data = Container: 
                        named_group_list = ListContainer: 
                            x25519
                Container: 
                    extension_type = (enum) key_share 51
                    extension_data = Container: 
                        client_shares = ListContainer: 
                            Container: 
                                group = (enum) x25519 b'\x00\x1d'
                                key_exchange = b'=@\x0c\xe9S\xa4j\xd1\xd4\x0fK,\x00\x7f\xf7\xb9'... (truncated, total 32)
                Container: 
                    extension_type = (enum) psk_key_exchange_modes 45
                    extension_data = Container: 
                        ke_modes = ListContainer: 
                            psk_dhe_ke
                Container: 
                    extension_type = (enum) pre_shared_key 41
                    extension_data = Container: 
                        identities = ListContainer: 
                            Container: 
                                identity = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
                                obfuscated_ticket_age = b'5\x08\x10\x0e' (total 4)
                            Container: 
                                identity = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
                                obfuscated_ticket_age = b'\x15\xfcTf' (total 4)
                        binders = ListContainer: 
                            Container: 
                                binder = b'\xb2\x04\x89\xfc\x8d\x85\xd2E\xa7\t\xc7\xe9Y\x8f\xa1\x1d'... (truncated, total 32)
                            Container: 
                                binder = b'\x14\x89\x7f[\xf9P[\rY3C$\xbd\xf4|\x7f'... (truncated, total 32)

:: Receiving new plain text fragment
  - TLS record 1 server_fragment_bytes [133 bytes]:
16 03 03 00 80 02 00 00 7c 03 03 6e 22 6e 63 ff
c4 13 a7 a2 5b 8a 4e e4 ab ca ea aa 2e 20 02 69
55 f4 e7 32 d8 ae 7a 97 97 04 ad 20 de e1 e5 8b
cc 84 77 6d 91 60 c2 91 1c 4c 02 52 55 55 06 df
e1 4f c0 76 4a 87 c0 80 f8 6b 90 8c 13 01 00 00
34 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 77
8b 78 b4 8e a4 e9 ae a9 fe b4 6d c0 51 09 b3 a2
ce 3b eb 73 6a d9 28 cd 14 76 8d a1 32 9a 1a 00
29 00 02 00 00
  - TLS record 1 server_fragment_bytes: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x02\x00\x00|\x03\x03n"nc\xff\xc4\x13\xa7\xa2['... (truncated, total 128)
  - handshake_message: [128 bytes]:
02 00 00 7c 03 03 6e 22 6e 63 ff c4 13 a7 a2 5b
8a 4e e4 ab ca ea aa 2e 20 02 69 55 f4 e7 32 d8
ae 7a 97 97 04 ad 20 de e1 e5 8b cc 84 77 6d 91
60 c2 91 1c 4c 02 52 55 55 06 df e1 4f c0 76 4a
87 c0 80 f8 6b 90 8c 13 01 00 00 34 00 2b 00 02
03 04 00 33 00 24 00 1d 00 20 77 8b 78 b4 8e a4
e9 ae a9 fe b4 6d c0 51 09 b3 a2 ce 3b eb 73 6a
d9 28 cd 14 76 8d a1 32 9a 1a 00 29 00 02 00 00
handshake_message: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'n"nc\xff\xc4\x13\xa7\xa2[\x8aN\xe4\xab\xca\xea'... (truncated, total 32)
        legacy_session_id_echo = b'\xde\xe1\xe5\x8b\xcc\x84wm\x91`\xc2\x91\x1cL\x02R'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'w\x8bx\xb4\x8e\xa4\xe9\xae\xa9\xfe\xb4m\xc0Q\t\xb3'... (truncated, total 32)
            Container: 
                extension_type = (enum) pre_shared_key 41
                extension_data = 0
:: server_hello received

  - TLS message 1 server_server_hello [128 bytes]:
02 00 00 7c 03 03 6e 22 6e 63 ff c4 13 a7 a2 5b
8a 4e e4 ab ca ea aa 2e 20 02 69 55 f4 e7 32 d8
ae 7a 97 97 04 ad 20 de e1 e5 8b cc 84 77 6d 91
60 c2 91 1c 4c 02 52 55 55 06 df e1 4f c0 76 4a
87 c0 80 f8 6b 90 8c 13 01 00 00 34 00 2b 00 02
03 04 00 33 00 24 00 1d 00 20 77 8b 78 b4 8e a4
e9 ae a9 fe b4 6d c0 51 09 b3 a2 ce 3b eb 73 6a
d9 28 cd 14 76 8d a1 32 9a 1a 00 29 00 02 00 00
  - TLS message 1 server_server_hello: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'n"nc\xff\xc4\x13\xa7\xa2[\x8aN\xe4\xab\xca\xea'... (truncated, total 32)
        legacy_session_id_echo = b'\xde\xe1\xe5\x8b\xcc\x84wm\x91`\xc2\x91\x1cL\x02R'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'w\x8bx\xb4\x8e\xa4\xe9\xae\xa9\xfe\xb4m\xc0Q\t\xb3'... (truncated, total 32)
            Container: 
                extension_type = (enum) pre_shared_key 41
                extension_data = 0
:: server_hello received

--- E -> CS: Sending c_server_hello Request:
--- E <- CS: Receiving c_server_hello Response:
  - Transcript Hash [mode h] [32 bytes]:
28 8d 37 80 32 33 ac 43 0c 0c d9 b2 6b a2 b4 37
8d 8e fb ca 8a 48 29 6e 9e a3 0c 4c c8 71 2a bf
  - server_handshake_write_key [16 bytes]:
0d ac e3 b1 00 57 00 c3 ac d2 11 03 f4 99 13 76
  - server_handshake_write_iv [12 bytes]:
e6 17 43 5b 68 a7 d2 b3 3d 53 08 35
  - client_handshake_write_key [16 bytes]:
6d 85 a9 74 21 67 bf d9 03 46 57 10 32 95 1b 97
  - client_handshake_write_iv [12 bytes]:
a5 c0 89 42 ad 0d 94 c1 b2 68 7a 8f

:: Receiving new plain text fragment
  - TLS record 2 server_change_cipher_spec [6 bytes]:
14 03 03 00 01 01
  - TLS record 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 20
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        type = (enum) change_cipher_spec 1
  - TLS message 2 server_change_cipher_spec [1 bytes]:
01
  - TLS message 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 1
:: change_cipher_spec received


:: Receiving new plain text fragment
  - TLS record 3 server_application_data [28 bytes]:
17 03 03 00 17 be 8e c3 03 26 d7 66 19 73 36 d2
4a 62 fb 9b 88 d4 7a bb ce 9d c6 96
  - TLS record 3 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xbe\x8e\xc3\x03&\xd7f\x19s6\xd2Jb\xfb\x9b\x88'... (truncated, total 23)
  - fragment (encrypted) [23 bytes]:
be 8e c3 03 26 d7 66 19 73 36 d2 4a 62 fb 9b 88
d4 7a bb ce 9d c6 96
  - write_key [16 bytes]:
0d ac e3 b1 00 57 00 c3 ac d2 11 03 f4 99 13 76
  - write_iv [12 bytes]:
e6 17 43 5b 68 a7 d2 b3 3d 53 08 35
  - nonce [12 bytes]:
e6 17 43 5b 68 a7 d2 b3 3d 53 08 35
  - additional_data [5 bytes]:
17 03 03 00 17
'  - sequence_number: 0'
  - Inner TLS message 3 server_fragment_bytes_(decrypted) [7 bytes]:
08 00 00 02 00 00 16
  - Inner TLS message 3 server_fragment_bytes_(decrypted): Container: 
    content = b'\x08\x00\x00\x02\x00\x00' (total 6)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [6 bytes]:
08 00 00 02 00 00
handshake_message: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received

  - TLS message 3 server_encrypted_extensions [6 bytes]:
08 00 00 02 00 00
  - TLS message 3 server_encrypted_extensions: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received


:: Receiving new plain text fragment
  - TLS record 4 server_application_data [58 bytes]:
17 03 03 00 35 a5 64 8f ff 98 f8 08 3c fe 35 c3
0f 35 aa 3d 08 12 ac ab 13 ba 42 18 58 57 77 70
d3 70 d9 e9 07 05 0d 78 f7 46 98 18 d0 c6 cc ef
fa 33 41 ce 59 9f 4c f8 e4 f0
  - TLS record 4 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xa5d\x8f\xff\x98\xf8\x08<\xfe5\xc3\x0f5\xaa=\x08'... (truncated, total 53)
  - fragment (encrypted) [53 bytes]:
a5 64 8f ff 98 f8 08 3c fe 35 c3 0f 35 aa 3d 08
12 ac ab 13 ba 42 18 58 57 77 70 d3 70 d9 e9 07
05 0d 78 f7 46 98 18 d0 c6 cc ef fa 33 41 ce 59
9f 4c f8 e4 f0
  - write_key [16 bytes]:
0d ac e3 b1 00 57 00 c3 ac d2 11 03 f4 99 13 76
  - write_iv [12 bytes]:
e6 17 43 5b 68 a7 d2 b3 3d 53 08 35
  - nonce [12 bytes]:
e6 17 43 5b 68 a7 d2 b3 3d 53 08 34
  - additional_data [5 bytes]:
17 03 03 00 35
'  - sequence_number: 1'
  - Inner TLS message 4 server_fragment_bytes_(decrypted) [37 bytes]:
14 00 00 20 87 5f d7 80 4f 3a d5 9f e4 f6 64 fd
51 9d ed 1e 68 74 8b 7a be 48 de f2 17 5f 90 76
5a 11 b6 cd 16
  - Inner TLS message 4 server_fragment_bytes_(decrypted): Container: 
    content = b'\x14\x00\x00 \x87_\xd7\x80O:\xd5\x9f\xe4\xf6d\xfd'... (truncated, total 36)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [36 bytes]:
14 00 00 20 87 5f d7 80 4f 3a d5 9f e4 f6 64 fd
51 9d ed 1e 68 74 8b 7a be 48 de f2 17 5f 90 76
5a 11 b6 cd
handshake_message: Container: 
    msg_type = (enum) finished 20
    data = Container: 
        verify_data = b'\x87_\xd7\x80O:\xd5\x9f\xe4\xf6d\xfdQ\x9d\xed\x1e'... (truncated, total 32)
:: finished received

  - TLS message 4 server_finished [36 bytes]:
14 00 00 20 87 5f d7 80 4f 3a d5 9f e4 f6 64 fd
51 9d ed 1e 68 74 8b 7a be 48 de f2 17 5f 90 76
5a 11 b6 cd
  - TLS message 4 server_finished: Container: 
    msg_type = (enum) finished 20
    data = Container: 
        verify_data = b'\x87_\xd7\x80O:\xd5\x9f\xe4\xf6d\xfdQ\x9d\xed\x1e'... (truncated, total 32)
:: finished received

  - Transcript Hash [mode server finished] [32 bytes]:
d3 03 6b 65 ef 12 48 ef 08 b1 7c 84 dc 6d 63 18
4f 07 90 79 fa 97 55 e2 f1 ee f6 98 8e 4c 50 f9
  - client computed verify_data [32 bytes]:
87 5f d7 80 4f 3a d5 9f e4 f6 64 fd 51 9d ed 1e
68 74 8b 7a be 48 de f2 17 5f 90 76 5a 11 b6 cd
  - server provided verify_data [32 bytes]:
87 5f d7 80 4f 3a d5 9f e4 f6 64 fd 51 9d ed 1e
68 74 8b 7a be 48 de f2 17 5f 90 76 5a 11 b6 cd
--- E -> CS: Sending c_client_finished Request:
--- E <- CS: Receiving c_client_finished Response:
  - Transcript Hash [mode client finished] [32 bytes]:
d8 23 8b e6 f3 cf 3e 0f bb 28 71 17 15 20 17 4f
d0 cf 33 29 59 4d 11 ee 48 87 71 90 7b e9 01 c6
:: Sending finished

  - Inner TLS message 6 client_finished [37 bytes]:
14 00 00 20 98 3b 66 d9 8a 1d b1 c0 26 f8 60 a3
cd 6b 9e 6f 7d f0 85 c4 63 95 c8 8d ac 89 c2 27
fd f1 58 5c 16
  - Inner TLS message 6 client_finished: Container: 
    content = Container: 
        msg_type = (enum) finished 20
        data = Container: 
            verify_data = b'\x98;f\xd9\x8a\x1d\xb1\xc0&\xf8`\xa3\xcdk\x9eo'... (truncated, total 32)
    type = (enum) handshake 22
    zeros = None
  - TLS record 6 client_application_data [58 bytes]:
17 03 03 00 35 9e c0 2d 91 d1 f8 0e 21 c2 93 6e
77 ef a6 77 23 66 8a e1 95 ec a3 cc 1b af 0f ae
76 b7 51 d8 79 65 ba d1 fd 59 34 e2 2e cd 2d 8f
d4 a1 18 23 ef 38 85 35 9e 14
  - TLS record 6 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x9e\xc0-\x91\xd1\xf8\x0e!\xc2\x93nw\xef\xa6w#'... (truncated, total 53)
  - server_application_write_key [16 bytes]:
50 72 82 5a 1f 0c 52 fe f1 15 ca 93 1d 80 3a 28
  - server_application_write_iv [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7f
  - client_application_write_key [16 bytes]:
5d f2 4f b1 8d 74 83 c2 a4 e3 35 20 e9 6c 7e ff
  - client_application_write_iv [12 bytes]:
e6 b3 49 59 6a d3 ad 45 18 20 a7 60
:: Sending application_data

  - Inner TLS message 8 client_application_data [74 bytes]:
47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
48 6f 73 74 3a 20 31 32 37 2e 30 2e 30 2e 31 0d
0a 75 73 65 72 2d 61 67 65 6e 74 3a 20 70 79 74
6c 73 31 33 2f 30 2e 31 0d 0a 61 63 63 65 70 74
3a 20 2a 2f 2a 0d 0a 0d 0a 17
  - Inner TLS message 8 client_application_data: Container: 
    content = b'GET / HTTP/1.1\r\n'... (truncated, total 73)
    type = (enum) application_data 23
    zeros = None
  - TLS record 8 client_application_data [95 bytes]:
17 03 03 00 5a 27 0c a7 e7 e5 f1 99 4b 5b da df
06 84 79 23 c8 60 1b 4c e9 85 05 bf 77 57 93 d3
33 8f 5c db 06 ef ee 5c 64 7b 01 c0 b6 7a 3d 2d
78 67 b1 82 9f f7 af a7 a2 e7 e1 c8 c2 2d ba 9d
a2 f2 1d 14 08 3b ac 64 5a 95 79 cc c3 6a b2 71
f7 3c 2f c0 bf ee da a2 ac c9 3a 0a 4d c8 eb
  - TLS record 8 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b"'\x0c\xa7\xe7\xe5\xf1\x99K[\xda\xdf\x06\x84y#\xc8"... (truncated, total 90)

:: Receiving new plain text fragment
  - TLS record 5 server_application_data [559 bytes]:
17 03 03 02 2a eb 0c a4 06 da e5 49 b7 a3 19 d9
8c 31 76 0b 8c 86 39 c4 0f 42 [...]
  - TLS record 5 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xeb\x0c\xa4\x06\xda\xe5I\xb7\xa3\x19\xd9\x8c1v\x0b\x8c'... (truncated, total 554)
  - fragment (encrypted) [554 bytes]:
eb 0c a4 06 da e5 49 b7 a3 19 d9 8c 31 76 0b 8c
86 39 c4 0f 42 5b 12 c5 bb [...]
  - write_key [16 bytes]:
50 72 82 5a 1f 0c 52 fe f1 15 ca 93 1d 80 3a 28
  - write_iv [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7f
  - nonce [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7f
  - additional_data [5 bytes]:
17 03 03 02 2a
'  - sequence_number: 0'
  - Inner TLS message 5 server_fragment_bytes_(decrypted) [538 bytes]:
04 00 02 15 00 00 1c 20 0d 29 16 62 08 00 00 00
00 00 00 00 00 02 00 43 08 [...]
  - Inner TLS message 5 server_fragment_bytes_(decrypted): Container: 
    content = b'\x04\x00\x02\x15\x00\x00\x1c \r)\x16b\x08\x00\x00\x00'... (truncated, total 537)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [537 bytes]:
04 00 02 15 00 00 1c 20 0d 29 16 62 08 00 00 00
00 00 00 00 00 02 00 43 08 [...]
handshake_message: Container: 
    msg_type = (enum) new_session_ticket 4
    data = Container: 
        ticket_lifetime = 7200
        ticket_age_add = 220796514
        ticket_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00' (total 8)
        ticket = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
        extensions = ListContainer: 
:: new_session_ticket received

  - TLS message 5 server_new_session_ticket [537 bytes]:
04 00 02 15 00 00 1c 20 0d 29 16 62 08 00 00 00
00 00 00 00 00 02 00 43 08 [...]
  - TLS message 5 server_new_session_ticket: Container: 
    msg_type = (enum) new_session_ticket 4
    data = Container: 
        ticket_lifetime = 7200
        ticket_age_add = 220796514
        ticket_nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00' (total 8)
        ticket = b'C\x08=\xec:%\xbf-\x1a\xa5\x0b\xf9knZ\x89'... (truncated, total 512)
        extensions = ListContainer: 
:: new_session_ticket received

--- E -> CS: Sending c_register_tickets Request:
--- E <- CS: Receiving c_register_tickets Response:

:: Receiving new plain text fragment
  - TLS record 6 server_application_data [5520 bytes]:
17 03 03 15 8b 75 b1 26 cd [...]
  - TLS record 6 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'u\xb1&\xcd\x12\x02\t\xa8\xcb9\xa1\x96qov\xf7'... (truncated, total 5515)
  - fragment (encrypted) [5515 bytes]:
75 b1 26 cd 12 02 09 a8 cb 39 a1 96 71 6f 76 f7
cc af 2e 0c 2a 14 a6 4d [...]
  - write_key [16 bytes]:
50 72 82 5a 1f 0c 52 fe f1 15 ca 93 1d 80 3a 28
  - write_iv [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7f
  - nonce [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7e
  - additional_data [5 bytes]:
17 03 03 15 8b
'  - sequence_number: 1'
  - Inner TLS message 6 server_application_data_(decrypted) [5499 bytes]:
48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d
0a 43 6f 6e 74 65 6e [...]
  - Inner TLS message 6 server_application_data_(decrypted): Container: 
    content = b'HTTP/1.0 200 ok\r'... (truncated, total 5498)
    type = (enum) application_data 23
    zeros = None
  - TLS message 6 server_application_data [5498 bytes]:
48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d
0a 43 6f 6e 74 65 6e 74 [...]
  - TLS message 6 server_application_data [5498 bytes]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n
  [...]
  </BODY></HTML>\r\n\r\n'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 7 server_application_data [24 bytes]:
17 03 03 00 13 74 9f c5 82 40 d0 3a 4b 09 47 b9
86 56 e5 2f 5a b0 0e b5
  - TLS record 7 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b't\x9f\xc5\x82@\xd0:K\tG\xb9\x86V\xe5/Z'... (truncated, total 19)
  - fragment (encrypted) [19 bytes]:
74 9f c5 82 40 d0 3a 4b 09 47 b9 86 56 e5 2f 5a
b0 0e b5
  - write_key [16 bytes]:
50 72 82 5a 1f 0c 52 fe f1 15 ca 93 1d 80 3a 28
  - write_iv [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7f
  - nonce [12 bytes]:
05 a3 d9 78 01 71 4f bc c9 61 94 7d
  - additional_data [5 bytes]:
17 03 03 00 13
'  - sequence_number: 2'
  - Inner TLS message 7 server_alert_(decrypted) [3 bytes]:
01 00 15
  - Inner TLS message 7 server_alert_(decrypted): Container: 
    content = Container: 
        level = (enum) warning 1
        description = (enum) close_notify 0
    type = (enum) alert 21
    zeros = None
  - TLS message 7 server_alert [2 bytes]:
01 00
  - TLS message 7 server_alert: Container: 
    level = (enum) warning 1
    description = (enum) close_notify 0
:: alert received

APPLICATION DATA - [psk]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n
[...]
</BODY></HTML>\r\n\r\n'
```
## 7. Example 2: standard (server authentication only) TLS 1.3 to  www.google.com


[7_tls_client_www.google.com](./lurk-t_tls_client/7_tls_client_www.google.com.html) provides the  complete log output of the unauthenticated TLS session with LURK to https://www.google.com.

```
./tls_client https://www.google.com --cert ~/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --connectivity tcp --host 127.0.0.1 --port 9401 --reconnect --debug > log.log
 --- Executing: /home/mglt/gitlab/pytls13/example/cli/./tls_client with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=None, cert=PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=True, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=False, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'", url="'https://www.google.com'", no_session_resumption=False, freshness="'sha256'", ephemeral_method="'cs_generated'", supported_ecdhe_groups="'x25519'", reconnect=True, cs_auto_start=False, cs_gramine_sgx=False, cs_gramine_direct=False, cs_gramine_build=False)
cmd: ./start_e.py --freshness 'sha256' --ephemeral_method cs_generated --supported_ecdhe_groups 'x25519'  --reconnect   --debug --connectivity tcp --host 127.0.0.1 --port 9401 --sig_scheme ed25519 --key None --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der  'https://www.google.com'
 --- Executing: /home/mglt/gitlab/pytls13/example/cli/./start_e.py with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=PosixPath('None'), cert=PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=True, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=False, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'", url="'https://www.google.com'", no_session_resumption=False, freshness="'sha256'", ephemeral_method="'cs_generated'", supported_ecdhe_groups="'x25519'", reconnect=True, cs_auto_start=False, cs_gramine_sgx=False, cs_gramine_direct=False, cs_gramine_build=False)

Configuration Template (from end user arguments ):

{'destination': {'ip': '172.217.13.164', 'port': 443},
 'sent_data': b'GET / HTTP/1.1\r\nHost: www.google.com\r\nuser-a'
              b'gent: pytls13/0.1\r\naccept: */*\r\n\r\n',
 'debug': {'trace': True},
 'lurk_client': {'connectivity': {'type': 'tcp',
                                  'ip': '127.0.0.1',
                                  'port': 9401},
                 'freshness': 'sha256'},
 'tls13': {'ephemeral_method': 'cs_generated',
           'supported_ecdhe_groups': ['x25519'],
           'session_resumption': True},
 'cs': {'log': None,
        'connectivity': {'type': 'tcp',
                         'ip': '127.0.0.1',
                         'port': 9401},
        ('tls13', 'v1'): {'sig_scheme': ['ed25519'],
                          'public_key': [PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                          'debug': {'trace': True}}}}

Full configuration:

{'role': 'client',
 'description': 'TLS 1.3 Client configuration template',
 'debug': {'trace': True},
 'lurk_client': {'freshness': 'sha256',
                 'connectivity': {'type': 'tcp',
                                  'ip': '127.0.0.1',
                                  'port': 9401}},
 'tls13': {'ke_modes': ['psk_dhe_ke'],
           'session_resumption': True,
           'post_handshake_authentication': False,
           'signature_algorithms': ['rsa_pkcs1_sha256',
                                    'rsa_pkcs1_sha384',
                                    'rsa_pkcs1_sha512',
                                    'ecdsa_secp256r1_sha256',
                                    'ecdsa_secp384r1_sha384',
                                    'ecdsa_secp521r1_sha512',
                                    'rsa_pss_rsae_sha256',
                                    'rsa_pss_rsae_sha384',
                                    'rsa_pss_pss_sha256',
                                    'rsa_pss_pss_sha384',
                                    'rsa_pss_pss_sha256',
                                    'ed25519',
                                    'ed448',
                                    'rsa_pkcs1_sha1'],
           'ephemeral_method': 'cs_generated',
           'supported_ecdhe_groups': ['x25519']},
 'cs': {('tls13', 'v1'): {'public_key': [PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der')],
                          'sig_scheme': ['ed25519'],
                          '_public_key': <cryptography.hazmat.backends.openssl.ed25519._Ed25519PublicKey object at 0x7f9985ec5870>,
                          '_cert_type': 'X509',
                          '_cert_entry_list': [{'cert': b'0\x82\x01.'
                                                        [...]
                                                        b'\x8f\t',
                                                'extensions': []}],
                          '_finger_print_entry_list': [{'finger_print': b'Y3{\xe1',
                                                        'extensions': []}],
                          '_finger_print_dict': {b'Y3{\xe1': b'0\x82\x01.'
                                                             [...]
                                                             b'\x8f\t'}}},
 'destination': {'ip': '172.217.13.164', 'port': 443},
 'sent_data': b'GET / HTTP/1.1\r\nHost: www.google.com\r\nuser-a'
              b'gent: pytls13/0.1\r\naccept: */*\r\n\r\n'}
======================================================
========= TLS with certificate authentication ========
======================================================

::Instantiating the Lurk client
--- E -> CS: Sending ping Request:
--- E <- CS: Receiving ping Response:
::TCP session with the TLS server
--- E -> CS: Sending c_init_client_hello Request:
--- E <- CS: Receiving c_init_client_hello Response:
:: 
Sending client_hello
  - TLS record 1 client_client_hello [177 bytes]:
16 03 03 00 ac 01 00 00 a8 03 03 d6 ff 9e ff 97
f8 5e 1c 61 57 dc 4e f0 b0 81 45 0f b8 ed 8f 1b
b8 5c 1b 39 ba 8a 7c fc bb 4a 91 20 07 41 cd 4f
6e 4d 1b f6 84 c0 da 72 76 a0 dc 13 54 13 f5 cf
af 44 97 81 2b 75 f9 b9 ae 41 a5 2c 00 04 13 01
13 03 01 00 00 5b 00 2b 00 03 02 03 04 00 0d 00
1e 00 1c 04 01 05 01 06 01 04 03 05 03 06 03 08
04 08 05 08 09 08 0a 08 09 08 07 08 08 02 01 00
0a 00 04 00 02 00 1d 00 33 00 26 00 24 00 1d 00
20 7e 97 06 c2 25 8d 9f ce 44 c3 86 bb 6b 4e 6c
21 97 70 ea 30 c6 84 be 58 6a 73 60 80 1a cc 98
65
  - TLS record 1 client_client_hello: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        msg_type = (enum) client_hello 1
        data = Container: 
            legacy_version = b'\x03\x03' (total 2)
            random = b'\xd6\xff\x9e\xff\x97\xf8^\x1caW\xdcN\xf0\xb0\x81E'... (truncated, total 32)
            legacy_session_id = b'\x07A\xcdOnM\x1b\xf6\x84\xc0\xdarv\xa0\xdc\x13'... (truncated, total 32)
            cipher_suites = ListContainer: 
                TLS_AES_128_GCM_SHA256
                TLS_CHACHA20_POLY1305_SHA256
            legacy_compression_methods = b'\x00' (total 1)
            extensions = ListContainer: 
                Container: 
                    extension_type = (enum) supported_versions 43
                    extension_data = Container: 
                        versions = ListContainer: 
                            b'\x03\x04'
                Container: 
                    extension_type = (enum) signature_algorithms 13
                    extension_data = Container: 
                        supported_signature_algorithms = ListContainer: 
                            rsa_pkcs1_sha256
                            rsa_pkcs1_sha384
                            rsa_pkcs1_sha512
                            ecdsa_secp256r1_sha256
                            ecdsa_secp384r1_sha384
                            ecdsa_secp521r1_sha512
                            rsa_pss_rsae_sha256
                            rsa_pss_rsae_sha384
                            rsa_pss_pss_sha256
                            rsa_pss_pss_sha384
                            rsa_pss_pss_sha256
                            ed25519
                            ed448
                            rsa_pkcs1_sha1
                Container: 
                    extension_type = (enum) supported_groups 10
                    extension_data = Container: 
                        named_group_list = ListContainer: 
                            x25519
                Container: 
                    extension_type = (enum) key_share 51
                    extension_data = Container: 
                        client_shares = ListContainer: 
                            Container: 
                                group = (enum) x25519 b'\x00\x1d'
                                key_exchange = b'~\x97\x06\xc2%\x8d\x9f\xceD\xc3\x86\xbbkNl!'... (truncated, total 32)

:: Receiving new plain text fragment
  - TLS record 1 server_fragment_bytes [127 bytes]:
16 03 03 00 7a 02 00 00 76 03 03 9c 1e 06 8e 3c
46 4f c4 7d 9c d8 1b 88 c1 b0 c5 56 77 a1 02 1f
d5 c1 38 bf d6 d9 3c 31 cf e4 fa 20 07 41 cd 4f
6e 4d 1b f6 84 c0 da 72 76 a0 dc 13 54 13 f5 cf
af 44 97 81 2b 75 f9 b9 ae 41 a5 2c 13 01 00 00
2e 00 33 00 24 00 1d 00 20 cf d3 21 d1 62 9d 87
ae 7e c0 89 19 bb 19 c8 2d 84 c1 cb a0 28 36 14
3c 8e a0 8d fe 95 a0 5d 3f 00 2b 00 02 03 04
  - TLS record 1 server_fragment_bytes: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x02\x00\x00v\x03\x03\x9c\x1e\x06\x8e<FO\xc4}\x9c'... (truncated, total 122)
  - handshake_message: [122 bytes]:
02 00 00 76 03 03 9c 1e 06 8e 3c 46 4f c4 7d 9c
d8 1b 88 c1 b0 c5 56 77 a1 02 1f d5 c1 38 bf d6
d9 3c 31 cf e4 fa 20 07 41 cd 4f 6e 4d 1b f6 84
c0 da 72 76 a0 dc 13 54 13 f5 cf af 44 97 81 2b
75 f9 b9 ae 41 a5 2c 13 01 00 00 2e 00 33 00 24
00 1d 00 20 cf d3 21 d1 62 9d 87 ae 7e c0 89 19
bb 19 c8 2d 84 c1 cb a0 28 36 14 3c 8e a0 8d fe
95 a0 5d 3f 00 2b 00 02 03 04
handshake_message: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'\x9c\x1e\x06\x8e<FO\xc4}\x9c\xd8\x1b\x88\xc1\xb0\xc5'... (truncated, total 32)
        legacy_session_id_echo = b'\x07A\xcdOnM\x1b\xf6\x84\xc0\xdarv\xa0\xdc\x13'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'\xcf\xd3!\xd1b\x9d\x87\xae~\xc0\x89\x19\xbb\x19\xc8-'... (truncated, total 32)
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
:: server_hello received

  - TLS message 1 server_server_hello [122 bytes]:
02 00 00 76 03 03 9c 1e 06 8e 3c 46 4f c4 7d 9c
d8 1b 88 c1 b0 c5 56 77 a1 02 1f d5 c1 38 bf d6
d9 3c 31 cf e4 fa 20 07 41 cd 4f 6e 4d 1b f6 84
c0 da 72 76 a0 dc 13 54 13 f5 cf af 44 97 81 2b
75 f9 b9 ae 41 a5 2c 13 01 00 00 2e 00 33 00 24
00 1d 00 20 cf d3 21 d1 62 9d 87 ae 7e c0 89 19
bb 19 c8 2d 84 c1 cb a0 28 36 14 3c 8e a0 8d fe
95 a0 5d 3f 00 2b 00 02 03 04
  - TLS message 1 server_server_hello: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'\x9c\x1e\x06\x8e<FO\xc4}\x9c\xd8\x1b\x88\xc1\xb0\xc5'... (truncated, total 32)
        legacy_session_id_echo = b'\x07A\xcdOnM\x1b\xf6\x84\xc0\xdarv\xa0\xdc\x13'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'\xcf\xd3!\xd1b\x9d\x87\xae~\xc0\x89\x19\xbb\x19\xc8-'... (truncated, total 32)
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
:: server_hello received

--- E -> CS: Sending c_server_hello Request:
--- E <- CS: Receiving c_server_hello Response:
  - Transcript Hash [mode h] [32 bytes]:
6f 00 48 74 0c bc 77 e8 04 fe 06 79 06 31 c2 2b
c6 6d 4e cb a2 0a f9 8c ba 7e df 54 df 55 e8 a2
  - server_handshake_write_key [16 bytes]:
0d fe c4 e2 3e 62 0a 01 70 da c2 09 72 e6 3f b9
  - server_handshake_write_iv [12 bytes]:
54 09 eb c6 a0 d6 28 21 db d9 60 86
  - client_handshake_write_key [16 bytes]:
94 09 23 77 4a d9 d7 57 92 36 51 7b 90 b4 c7 9a
  - client_handshake_write_iv [12 bytes]:
dd 9f 18 93 20 9b 1b ac bc fc 7d e1

:: Receiving new plain text fragment
  - TLS record 2 server_change_cipher_spec [6 bytes]:
14 03 03 00 01 01
  - TLS record 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 20
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        type = (enum) change_cipher_spec 1
  - TLS message 2 server_change_cipher_spec [1 bytes]:
01
  - TLS message 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 1
:: change_cipher_spec received


:: Receiving new plain text fragment
  - TLS record 3 server_application_data [1237 bytes]:
17 03 03 04 d0 7f eb f5 d5 6c 34 6b 21 b8 ab 08
bb 88 3b e9 5e 72 ac d0 31 0d a7 80 35 [...]
  - TLS record 3 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x7f\xeb\xf5\xd5l4k!\xb8\xab\x08\xbb\x88;\xe9^'... (truncated, total 1232)
  - fragment (encrypted) [1232 bytes]:
7f eb f5 d5 6c 34 6b 21 b8 ab 08 bb 88 3b e9 5e
72 ac d0 31 0d a7 80 35 66 4e f7 01 64 [...]
  - write_key [16 bytes]:
0d fe c4 e2 3e 62 0a 01 70 da c2 09 72 e6 3f b9
  - write_iv [12 bytes]:
54 09 eb c6 a0 d6 28 21 db d9 60 86
  - nonce [12 bytes]:
54 09 eb c6 a0 d6 28 21 db d9 60 86
  - additional_data [5 bytes]:
17 03 03 04 d0
'  - sequence_number: 0'
  - Inner TLS message 3 server_fragment_bytes_(decrypted) [1216 bytes]:
08 00 00 02 00 00 0b 00 03 89 00 00 03 85 00 03
80 30 82 03 7c 30 82 02 64 a0 03 02 01 [...]
  - Inner TLS message 3 server_fragment_bytes_(decrypted): Container: 
    content = b'\x08\x00\x00\x02\x00\x00\x0b\x00\x03\x89\x00\x00\x03\x85\x00\x03'... (truncated, total 1215)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [6 bytes]:
08 00 00 02 00 00
handshake_message: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received

  - TLS message 3 server_encrypted_extensions [6 bytes]:
08 00 00 02 00 00
  - TLS message 3 server_encrypted_extensions: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received

  - handshake_message: [909 bytes]:
0b 00 03 89 00 00 03 85 00 03 80 30 82 03 7c 30
82 02 64 a0 03 02 01 02 02 09 00 90 76 [...]
handshake_message: Container: 
    msg_type = (enum) certificate 11
    data = Container: 
        certificate_request_context = b'' (total 0)
        certificate_list = ListContainer: 
            Container: 
                cert = b'0\x82\x03|0\x82\x02d\xa0\x03\x02\x01\x02\x02\t\x00'... (truncated, total 896)
                extensions = ListContainer: 
:: certificate received

  - handshake_message: [264 bytes]:
0f 00 01 04 08 04 01 00 0f 37 a3 ab fe 09 89 31
63 00 06 6f fd bd 1a 88 b3 4f cb 95 d0 [...]
handshake_message: Container: 
    msg_type = (enum) certificate_verify 15
    data = Container: 
        algorithm = (enum) rsa_pss_rsae_sha256 b'\x08\x04'
        signature = b'\x0f7\xa3\xab\xfe\t\x891c\x00\x06o\xfd\xbd\x1a\x88'... (truncated, total 256)
:: certificate_verify received

  - Transcript Hash [mode sig] [32 bytes]:
45 dc 10 36 fd c4 21 ea 0b d9 63 00 5b b7 e0 c1
40 4d 46 12 1b 00 f5 29 f9 1a 07 64 14 35 de 10
  - ctx_string [33 bytes]: b'TLS 1.3, server CertificateVerify'
  - ctx_string [33 bytes]:
54 4c 53 20 31 2e 33 2c 20 73 65 72 76 65 72 20
43 65 72 74 69 66 69 63 61 74 65 56 65 72 69 66
79
  - content to be signed [130 bytes]:
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
54 4c 53 20 31 2e 33 2c 20 73 65 72 76 65 72 20
43 65 72 74 69 66 69 63 61 74 65 56 65 72 69 66
79 00 45 dc 10 36 fd c4 21 ea 0b d9 63 00 5b b7
e0 c1 40 4d 46 12 1b 00 f5 29 f9 1a 07 64 14 35
de 10
  - handshake_message: [36 bytes]:
14 00 00 20 ad 94 e5 af 1b 5d e9 5e b6 3f 05 80
77 a7 1a 5c 7e ca 31 03 ba 18 0a 39 7e 38 17 bf
24 dd 62 f1
handshake_message: Container: 
    msg_type = (enum) finished 20
    data = Container: 
        verify_data = b'\xad\x94\xe5\xaf\x1b]\xe9^\xb6?\x05\x80w\xa7\x1a\\'... (truncated, total 32)
:: finished received

  - Transcript Hash [mode server finished] [32 bytes]:
79 cc fc 12 4a 63 0e 99 1c 4c 07 63 04 d0 80 14
79 40 dd 8b 92 2e d6 0e f4 92 74 37 46 d1 06 dc
  - client computed verify_data [32 bytes]:
ad 94 e5 af 1b 5d e9 5e b6 3f 05 80 77 a7 1a 5c
7e ca 31 03 ba 18 0a 39 7e 38 17 bf 24 dd 62 f1
  - server provided verify_data [32 bytes]:
ad 94 e5 af 1b 5d e9 5e b6 3f 05 80 77 a7 1a 5c
7e ca 31 03 ba 18 0a 39 7e 38 17 bf 24 dd 62 f1
--- E -> CS: Sending c_client_finished Request:
--- E <- CS: Receiving c_client_finished Response:
  - Transcript Hash [mode client finished] [32 bytes]:
11 94 da 72 6c 13 a6 71 cf 05 c6 0d d8 a7 62 66
8a ce 45 c3 f3 ea 04 ee 9c 46 47 91 0b c3 c3 69
:: Sending finished

  - Inner TLS message 5 client_finished [37 bytes]:
14 00 00 20 e0 74 16 68 3d 0a a1 6e cb 01 81 d3
ac a3 e7 d7 c9 14 6c fd 15 b7 02 75 93 a7 46 a5
59 e9 8b 7e 16
  - Inner TLS message 5 client_finished: Container: 
    content = Container: 
        msg_type = (enum) finished 20
        data = Container: 
            verify_data = b'\xe0t\x16h=\n\xa1n\xcb\x01\x81\xd3\xac\xa3\xe7\xd7'... (truncated, total 32)
    type = (enum) handshake 22
    zeros = None
  - TLS record 5 client_application_data [58 bytes]:
17 03 03 00 35 eb 4f ef b1 66 5b 75 d4 60 7b b3
72 66 7d 70 ec 11 ae 4d 24 ba d7 4f 79 d2 c1 7e
06 b9 b6 f9 82 56 95 31 36 54 d8 b7 91 63 cb d1
7c 99 be 04 b4 cb 81 27 95 a6
  - TLS record 5 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xebO\xef\xb1f[u\xd4`{\xb3rf}p\xec'... (truncated, total 53)
  - server_application_write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - server_application_write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - client_application_write_key [16 bytes]:
fe d2 91 b8 c2 6a 34 49 1a 6c ec c1 a9 a2 8b 41
  - client_application_write_iv [12 bytes]:
1e 25 3f 17 5e 20 01 61 80 87 5e ce
:: Sending application_data

  - Inner TLS message 7 client_application_data [79 bytes]:
47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
48 6f 73 74 3a 20 77 77 77 2e 67 6f 6f 67 6c 65
2e 63 6f 6d 0d 0a 75 73 65 72 2d 61 67 65 6e 74
3a 20 70 79 74 6c 73 31 33 2f 30 2e 31 0d 0a 61
63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 17
  - Inner TLS message 7 client_application_data: Container: 
    content = b'GET / HTTP/1.1\r\n'... (truncated, total 78)
    type = (enum) application_data 23
    zeros = None
  - TLS record 7 client_application_data [100 bytes]:
17 03 03 00 5f 4a 39 f2 a0 1f 98 45 82 a0 9d 9d
e2 e9 88 75 0e ff 92 53 7f 39 35 76 02 ba c2 5a
dc a2 24 14 5c 64 d3 ae 8b 5e 90 40 b5 b2 b7 e6
39 bf 9e 69 d0 e6 f0 9d 62 86 45 78 24 7a ca 9c
3e 6f 65 1f 91 67 7a 62 69 0a 1a 57 65 54 8a d4
d6 8d 22 bf 3b 08 4b da 57 d6 aa 02 73 e5 28 da
60 02 d3 47
  - TLS record 7 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'J9\xf2\xa0\x1f\x98E\x82\xa0\x9d\x9d\xe2\xe9\x88u\x0e'... (truncated, total 95)

:: Receiving new plain text fragment
  - TLS record 4 server_application_data [1400 bytes]:
17 03 03 05 73 fd db 1f 81 72 19 72 10 25 1e 9b
5a fd c1 3e f3 6d 39 46 ca 37 31 be 20 [...]
  - TLS record 4 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xfd\xdb\x1f\x81r\x19r\x10%\x1e\x9bZ\xfd\xc1>\xf3'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
fd db 1f 81 72 19 72 10 25 1e 9b 5a fd c1 3e f3
6d 39 46 ca 37 31 be 20 12 cc 30 ad a3 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 0'
  - Inner TLS message 4 server_application_data_(decrypted) [1379 bytes]:
48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d
0a 44 61 74 65 3a 20 54 75 65 2c 20 30 [...]
  - Inner TLS message 4 server_application_data_(decrypted): Container: 
    content = b'HTTP/1.1 200 OK\r'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 4 server_application_data [1378 bytes]:
48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d
0a 44 61 74 65 3a 20 54 75 65 2c 20 30 [...]
  - TLS message 4 server_application_data [1378 bytes]: b'HTTP/1.1 200 OK\r\nDate: Tue, 04 Apr 2023 16:38:15 GMT\r\nExpires: -1\r\nCache-Control: private, max-age=0\r\nContent-Type: text/html; charset=ISO-8859-1\r\nContent-Security-Policy-Report-Only: object-src \'none\';base-uri \'self\';script-src \'nonce-yWZbd7mE6PqhRDqwWJsivw\' \'strict-dynamic\' \'report-sample\' \'unsafe-eval\' \'unsafe-inline\' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp\r\nP3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."\r\nServer: gws\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nSet-Cookie: 1P_JAR=2023-04-04-16; expires=Thu, 04-May-2023 16:38:15 GMT; path=/; domain=.google.com; Secure\r\nSet-Cookie: AEC=AUEFqZfsb9EwBG3VaUuNAk-yQpI-KCRpr00Er0wggmkIZbD7sfRfSWBJuOI; expires=Sun, 01-Oct-2023 16:38:15 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax\r\nSet-Cookie: NID=511=uG7fsvXappgu_xN4b5Y8wpxPjhmombKvzpE6fr2ZcIFY6bxsLrKZd2wAKgemYSFkpjwYdr2F2dAVCvCpabbowX0U5fpoFC6_d6Qj2d0c2AhQzFjHiNZ9SDM46qz7V1IuhnGR8zat5ZPpB8gK3XYq1VTm6F9xK-uFqONR-ezZ9_o; expires=Wed, 04-Oct-2023 16:38:15 GMT; path=/; domain=.google.com; HttpOnly\r\nAlt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Accept-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n3aba\r\n<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en-CA"><head><meta content="text/html; charset=UTF-8" http-equiv="Content-Type"><meta'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 5 server_application_data [1400 bytes]:
17 03 03 05 73 35 b6 3d 80 6e a6 22 d2 90 cd c1
dd 81 77 1d 24 98 d5 f1 2e be f8 b2 45 [...]
  - TLS record 5 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'5\xb6=\x80n\xa6"\xd2\x90\xcd\xc1\xdd\x81w\x1d$'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
35 b6 3d 80 6e a6 22 d2 90 cd c1 dd 81 77 1d 24
98 d5 f1 2e be f8 b2 45 e3 83 12 4b 3a [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b0
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 1'
  - Inner TLS message 5 server_application_data_(decrypted) [1379 bytes]:
20 63 6f 6e 74 65 6e 74 3d 22 2f 69 6d 61 67 65
73 2f 62 72 61 6e 64 69 6e 67 2f 67 6f [...]
  - Inner TLS message 5 server_application_data_(decrypted): Container: 
    content = b' content="/image'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 5 server_application_data [1378 bytes]:
20 63 6f 6e 74 65 6e 74 3d 22 2f 69 6d 61 67 65
73 2f 62 72 61 6e 64 69 6e 67 2f 67 6f [...]
  - TLS message 5 server_application_data [1378 bytes]: b' content="/images/branding/googleg/1x/googleg_standard_color_128dp.png" itemprop="image"><title>Google</title><script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){window.google={kEI:\'d1IsZM3cGffL0PEPg6-G4Aw\',kEXPI:\'0,1359409,6059,206,4804,2316,383,246,5,1129120,1197713,677,380100,16115,19397,9287,22430,1362,12313,17586,4998,13228,3847,35733,2711,2872,2891,3926,8434,60690,2614,13142,3,346,230,1014,1,16916,2652,4,1528,2304,923,11003,30201,13658,21223,5827,2530,4094,7596,1,42154,2,14022,2715,21266,1758,6699,31122,4569,6258,23418,1252,5835,14967,4333,7484,445,2,2,1,6959,3997,15676,8155,6680,701,2,15967,874,19633,7,1922,5600,4179,7783,13608,1517,13246,6305,2007,18191,17619,2518,14,82,20206,1622,1779,2,4974,8239,4227,662,1763,8484,988,3030,427,5683,1411,890,2740,6469,7734,495,1152,1091,1757,1128,2494,5846,10643,342,415,2882,250,2647,667,1,2753,1758,1330,1697,1634,1607,3883,4,2150,21,6,278,888,872,4,1628,3251,395,4101,2,840,2401,678,349,259,1116,605,706,653,3,952,1216,100,461,153,475,277,1818,690,345,168,467,130,1108,879,894,3,127,645,537,1,708,382,1354,381,175,360,124,77,742,120,124,2,3,212,513,782,1071,107,402,112,16,104,5,294,273,578,955,733,806,74,446,338,103,114,163,580,1394,273,1002,2,5211384,303,137,255,5994027,2804424,4247,2,2,19731,302,2,44,4650,110,3,14,23945707,397,4041746,1964,16672,2894,6250,12561,3358,1537,1413340,194319\',kBL:\'RbSe\',kOPI:89978449};goo'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 6 server_application_data [1400 bytes]:
17 03 03 05 73 15 5a 35 98 53 d0 08 6b 6f b2 6b
4f b0 99 7a e3 1a 2c 63 f5 25 73 1f f0 [...]
  - TLS record 6 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x15Z5\x98S\xd0\x08ko\xb2kO\xb0\x99z\xe3'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
15 5a 35 98 53 d0 08 6b 6f b2 6b 4f b0 99 7a e3
1a 2c 63 f5 25 73 1f f0 a5 12 9b 5c c8 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b3
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 2'
  - Inner TLS message 6 server_application_data_(decrypted) [1379 bytes]:
67 6c 65 2e 73 6e 3d 27 77 65 62 68 70 27 3b 67
6f 6f 67 6c 65 2e 6b 48 4c 3d 27 65 6e [...]
  - Inner TLS message 6 server_application_data_(decrypted): Container: 
    content = b"gle.sn='webhp';g"... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 6 server_application_data [1378 bytes]:
67 6c 65 2e 73 6e 3d 27 77 65 62 68 70 27 3b 67
6f 6f 67 6c 65 2e 6b 48 4c 3d 27 65 6e [...]
7b 7d
  - TLS message 6 server_application_data [1378 bytes]: b'gle.sn=\'webhp\';google.kHL=\'en-CA\';})();(function(){\nvar f=this||self;var h,k=[];function l(a){for(var b;a&&(!a.getAttribute||!(b=a.getAttribute("eid")));)a=a.parentNode;return b||h}function m(a){for(var b=null;a&&(!a.getAttribute||!(b=a.getAttribute("leid")));)a=a.parentNode;return b}\nfunction n(a,b,c,d,g){var e="";c||-1!==b.search("&ei=")||(e="&ei="+l(d),-1===b.search("&lei=")&&(d=m(d))&&(e+="&lei="+d));d="";!c&&f._cshid&&-1===b.search("&cshid=")&&"slh"!==a&&(d="&cshid="+f._cshid);c=c||"/"+(g||"gen_204")+"?atyp=i&ct="+a+"&cad="+b+e+"&zx="+Date.now()+d;/^http:/i.test(c)&&"https:"===window.location.protocol&&(google.ml&&google.ml(Error("a"),!1,{src:c,glmm:1}),c="");return c};h=google.kEI;google.getEI=l;google.getLEI=m;google.ml=function(){return null};google.log=function(a,b,c,d,g){if(c=n(a,b,c,d,g)){a=new Image;var e=k.length;k[e]=a;a.onerror=a.onload=a.onabort=function(){delete k[e]};a.src=c}};google.logUrl=n;}).call(this);(function(){google.y={};google.sy=[];google.x=function(a,b){if(a)var c=a.id;else{do c=Math.random();while(google.y[c])}google.y[c]=[a,b];return!1};google.sx=function(a){google.sy.push(a)};google.lm=[];google.plm=function(a){google.lm.push.apply(google.lm,a)};google.lq=[];google.load=function(a,b,c){google.lq.push([[a],b,c])};google.loadAll=function(a,b){google.lq.push([a,b])};google.bx=!1;google.lx=function(){};}).call(this);google.f={}'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 7 server_application_data [1400 bytes]:
17 03 03 05 73 46 90 3a 9c 82 b9 0f 98 11 72 06
59 5c 90 17 66 0c da 33 20 82 85 6f 20 [...]
  - TLS record 7 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'F\x90:\x9c\x82\xb9\x0f\x98\x11r\x06Y\\\x90\x17f'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
46 90 3a 9c 82 b9 0f 98 11 72 06 59 5c 90 17 66
0c da 33 20 82 85 6f 20 e8 5a 78 ee 33 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b2
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 3'
  - Inner TLS message 7 server_application_data_(decrypted) [1379 bytes]:
3b 28 66 75 6e 63 74 69 6f 6e 28 29 7b 0a 64 6f
63 75 6d 65 6e 74 2e 64 6f 63 75 6d 65 [...]
  - Inner TLS message 7 server_application_data_(decrypted): Container: 
    content = b';(function(){\ndo'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 7 server_application_data [1378 bytes]:
3b 28 66 75 6e 63 74 69 6f 6e 28 29 7b 0a 64 6f
63 75 6d 65 6e 74 2e 64 6f 63 75 6d 65 [...]
  - TLS message 7 server_application_data [1378 bytes]: b';(function(){\ndocument.documentElement.addEventListener("submit",function(b){var a;if(a=b.target){var c=a.getAttribute("data-submitfalse");a="1"===c||"q"===c&&!a.elements.q.value?!0:!1}else a=!1;a&&(b.preventDefault(),b.stopPropagation())},!0);document.documentElement.addEventListener("click",function(b){var a;a:{for(a=b.target;a&&a!==document.documentElement;a=a.parentElement)if("A"===a.tagName){a="1"===a.getAttribute("data-nohref");break a}a=!1}a&&b.preventDefault()},!0);}).call(this);</script><style>#gbar,#guser{font-size:13px;padding-top:1px !important;}#gbar{height:22px}#guser{padding-bottom:7px !important;text-align:right}.gbh,.gbd{border-top:1px solid #c9d7f1;font-size:1px}.gbh{height:0;position:absolute;top:24px;width:100%}@media all{.gb1{height:22px;margin-right:.5em;vertical-align:top}#gbar{float:left}}a.gb1,a.gb4{text-decoration:underline !important}a.gb1,a.gb4{color:#00c !important}.gbi .gb4{color:#dd8e27 !important}.gbf .gb4{color:#900 !important}\n</style><style>body,td,a,p,.h{font-family:arial,sans-serif}body{margin:0;overflow-y:scroll}#gog{padding:3px 8px 0}td{line-height:.8em}.gac_m td{line-height:17px}form{margin-bottom:20px}.h{color:#1558d6}em{font-weight:bold;font-style:normal}.lst{height:25px;width:496px}.gsfi,.lst{font:18px arial,sans-serif}.gsfs{font:17px arial,sans-serif}.ds{display:inline-box;display:inline-block;margin:3px 0 4px;ma'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 8 server_application_data [1400 bytes]:
17 03 03 05 73 3f 34 8a f6 da 0d 11 05 e4 d4 3f
43 e7 96 ab 10 94 d9 70 09 f3 9a 12 ba [...]
  - TLS record 8 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'?4\x8a\xf6\xda\r\x11\x05\xe4\xd4?C\xe7\x96\xab\x10'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
3f 34 8a f6 da 0d 11 05 e4 d4 3f 43 e7 96 ab 10
94 d9 70 09 f3 9a 12 ba a6 14 88 4d 66 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b5
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 4'
  - Inner TLS message 8 server_application_data_(decrypted) [1379 bytes]:
72 67 69 6e 2d 6c 65 66 74 3a 34 70 78 7d 69 6e
70 75 74 7b 66 6f 6e 74 2d 66 61 6d 69 [...]
  - Inner TLS message 8 server_application_data_(decrypted): Container: 
    content = b'rgin-left:4px}in'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 8 server_application_data [1378 bytes]:
72 67 69 6e 2d 6c 65 66 74 3a 34 70 78 7d 69 6e
70 75 74 7b 66 6f 6e 74 2d 66 61 6d 69 [...]
  - TLS message 8 server_application_data [1378 bytes]: b'rgin-left:4px}input{font-family:inherit}body{background:#fff;color:#000}a{color:#4b11a8;text-decoration:none}a:hover,a:active{text-decoration:underline}.fl a{color:#1558d6}a:visited{color:#4b11a8}.sblc{padding-top:5px}.sblc a{display:block;margin:2px 0;margin-left:13px;font-size:11px}.lsbb{background:#f8f9fa;border:solid 1px;border-color:#dadce0 #70757a #70757a #dadce0;height:30px}.lsbb{display:block}#WqQANb a{display:inline-block;margin:0 12px}.lsb{background:url(/images/nav_logo229.png) 0 -261px repeat-x;border:none;color:#000;cursor:pointer;height:30px;margin:0;outline:0;font:15px arial,sans-serif;vertical-align:top}.lsb:active{background:#dadce0}.lst:focus{outline:none}</style><script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){window.google.erd={jsr:1,bv:1770,de:true};\nvar h=this||self;var k,l=null!=(k=h.mei)?k:1,n,p=null!=(n=h.sdo)?n:!0,q=0,r,t=google.erd,v=t.jsr;google.ml=function(a,b,d,m,e){e=void 0===e?2:e;b&&(r=a&&a.message);if(google.dl)return google.dl(a,e,d),null;if(0>v){window.console&&console.error(a,d);if(-2===v)throw a;b=!1}else b=!a||!a.message||"Error loading script"===a.message||q>=l&&!m?!1:!0;if(!b)return null;q++;d=d||{};b=encodeURIComponent;var c="/gen_204?atyp=i&ei="+b(google.kEI);google.kEXPI&&(c+="&jexpid="+b(google.kEXPI));c+="&srcpg="+b(google.sn)+"&jsr="+b(t.jsr)+"&bver="+b(t.bv);var f=a.lineNumber;void 0!==f&&(c+="&line="+f);va'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 9 server_application_data [1400 bytes]:
17 03 03 05 73 b5 5b 74 63 f5 c7 f9 b6 c8 18 fb
14 22 ed 5f 58 a3 6f 8f ca 7b 80 a1 3b [...]
  - TLS record 9 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xb5[tc\xf5\xc7\xf9\xb6\xc8\x18\xfb\x14"\xed_X'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
b5 5b 74 63 f5 c7 f9 b6 c8 18 fb 14 22 ed 5f 58
a3 6f 8f ca 7b 80 a1 3b 63 b4 1c 7c 9a [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b4
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 5'
  - Inner TLS message 9 server_application_data_(decrypted) [1379 bytes]:
72 20 67 3d 0a 61 2e 66 69 6c 65 4e 61 6d 65 3b
67 26 26 28 30 3c 67 2e 69 6e 64 65 78 [...]
  - Inner TLS message 9 server_application_data_(decrypted): Container: 
    content = b'r g=\na.fileName;'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 9 server_application_data [1378 bytes]:
72 20 67 3d 0a 61 2e 66 69 6c 65 4e 61 6d 65 3b
67 26 26 28 30 3c 67 2e 69 6e 64 65 78 [...]
  - TLS message 9 server_application_data [1378 bytes]: b'r g=\na.fileName;g&&(0<g.indexOf("-extension:/")&&(e=3),c+="&script="+b(g),f&&g===window.location.href&&(f=document.documentElement.outerHTML.split("\\n")[f],c+="&cad="+b(f?f.substring(0,300):"No script found.")));c+="&jsel="+e;for(var u in d)c+="&",c+=b(u),c+="=",c+=b(d[u]);c=c+"&emsg="+b(a.name+": "+a.message);c=c+"&jsst="+b(a.stack||"N/A");12288<=c.length&&(c=c.substr(0,12288));a=c;m||google.log(0,"",a);return a};window.onerror=function(a,b,d,m,e){r!==a&&(a=e instanceof Error?e:Error(a),void 0===d||"lineNumber"in a||(a.lineNumber=d),void 0===b||"fileName"in a||(a.fileName=b),google.ml(a,!1,void 0,!1,"SyntaxError"===a.name||"SyntaxError"===a.message.substring(0,11)||-1!==a.message.indexOf("Script error")?3:0));r=null;p&&q>=l&&(window.onerror=null)};})();</script></head><body bgcolor="#fff"><script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){var src=\'/images/nav_logo229.png\';var iesg=false;document.body.onload = function(){window.n && window.n();if (document.images){new Image().src=src;}\nif (!iesg){document.f&&document.f.q.focus();document.gbqf&&document.gbqf.q.focus();}\n}\n})();</script><div id="mngb"><div id=gbar><nobr><b class=gb1>Search</b> <a class=gb1 href="https://www.google.ca/imghp?hl=en&tab=wi">Images</a> <a class=gb1 href="https://maps.google.ca/maps?hl=en&tab=wl">Maps</a> <a class=gb1 href="https://play.google.com/?hl=en&tab=w8">Play</a> <a class='
:: application_data received


:: Receiving new plain text fragment
  - TLS record 10 server_application_data [1400 bytes]:
17 03 03 05 73 0a 30 6c cb 48 e3 86 96 b9 98 7a
9e 5a 9f 9e 68 f9 6b 81 4f f8 3c 6c ec [...]
  - TLS record 10 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\n0l\xcbH\xe3\x86\x96\xb9\x98z\x9eZ\x9f\x9eh'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
0a 30 6c cb 48 e3 86 96 b9 98 7a 9e 5a 9f 9e 68
f9 6b 81 4f f8 3c 6c ec 9a 14 2c 6d 90 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b7
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 6'
  - Inner TLS message 10 server_application_data_(decrypted) [1379 bytes]:
67 62 31 20 68 72 65 66 3d 22 68 74 74 70 73 3a
2f 2f 77 77 77 2e 79 6f 75 74 75 62 65 [...]
  - Inner TLS message 10 server_application_data_(decrypted): Container: 
    content = b'gb1 href="https:'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 10 server_application_data [1378 bytes]:
67 62 31 20 68 72 65 66 3d 22 68 74 74 70 73 3a
2f 2f 77 77 77 2e 79 6f 75 74 75 62 65 [...]
  - TLS message 10 server_application_data [1378 bytes]: b'gb1 href="https://www.youtube.com/?tab=w1">YouTube</a> <a class=gb1 href="https://news.google.com/?tab=wn">News</a> <a class=gb1 href="https://mail.google.com/mail/?tab=wm">Gmail</a> <a class=gb1 href="https://drive.google.com/?tab=wo">Drive</a> <a class=gb1 style="text-decoration:none" href="https://www.google.ca/intl/en/about/products?tab=wh"><u>More</u> &raquo;</a></nobr></div><div id=guser width=100%><nobr><span id=gbn class=gbi></span><span id=gbf class=gbf></span><span id=gbe></span><a href="http://www.google.ca/history/optout?hl=en" class=gb4>Web History</a> | <a  href="/preferences?hl=en" class=gb4>Settings</a> | <a target=_top id=gb_70 href="https://accounts.google.com/ServiceLogin?hl=en&passive=true&continue=https://www.google.com/&ec=GAZAAQ" class=gb4>Sign in</a></nobr></div><div class=gbh style=left:0></div><div class=gbh style=right:0></div></div><center><br clear="all" id="lgpd"><div id="lga"><img alt="Google" height="92" src="/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png" style="padding:28px 0 14px" width="272" id="hplogo"><br><br></div><form action="/search" name="f"><table cellpadding="0" cellspacing="0"><tr valign="top"><td width="25%">&nbsp;</td><td align="center" nowrap=""><input name="ie" value="ISO-8859-1" type="hidden"><input value="en-CA" name="hl" type="hidden"><input name="source" type="hidden" valu'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 11 server_application_data [1400 bytes]:
17 03 03 05 73 06 4f 23 a9 05 75 81 ff 58 be d6
c8 ae a7 8c f5 2c 5c b8 64 e7 4b 65 af [...]
  - TLS record 11 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x06O#\xa9\x05u\x81\xffX\xbe\xd6\xc8\xae\xa7\x8c\xf5'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
06 4f 23 a9 05 75 81 ff 58 be d6 c8 ae a7 8c f5
2c 5c b8 64 e7 4b 65 af a1 f2 18 11 9e [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b6
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 7'
  - Inner TLS message 11 server_application_data_(decrypted) [1379 bytes]:
65 3d 22 68 70 22 3e 3c 69 6e 70 75 74 20 6e 61
6d 65 3d 22 62 69 77 22 20 74 79 70 65 [...]
  - Inner TLS message 11 server_application_data_(decrypted): Container: 
    content = b'e="hp"><input na'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 11 server_application_data [1378 bytes]:
65 3d 22 68 70 22 3e 3c 69 6e 70 75 74 20 6e 61
6d 65 3d 22 62 69 77 22 20 74 79 70 65 [...]
  - TLS message 11 server_application_data [1378 bytes]: b'e="hp"><input name="biw" type="hidden"><input name="bih" type="hidden"><div class="ds" style="height:32px;margin:4px 0"><input class="lst" style="margin:0;padding:5px 8px 0 6px;vertical-align:top;color:#000" autocomplete="off" value="" title="Google Search" maxlength="2048" name="q" size="57"></div><br style="line-height:0"><span class="ds"><span class="lsbb"><input class="lsb" value="Google Search" name="btnG" type="submit"></span></span><span class="ds"><span class="lsbb"><input class="lsb" id="tsuid_1" value="I\'m Feeling Lucky" name="btnI" type="submit"><script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){var id=\'tsuid_1\';document.getElementById(id).onclick = function(){if (this.form.q.value){this.checked = 1;if (this.form.iflsig)this.form.iflsig.disabled = false;}\nelse top.location=\'/doodles/\';};})();</script><input value="AOEireoAAAAAZCxgh47H_q_kkZoEvPaUaejB5F2-IuH2" name="iflsig" type="hidden"></span></span></td><td class="fl sblc" align="left" nowrap="" width="25%"><a href="/advanced_search?hl=en-CA&amp;authuser=0">Advanced search</a></td></tr></table><input id="gbv" name="gbv" type="hidden" value="1"><script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){var a,b="1";if(document&&document.getElementById)if("undefined"!=typeof XMLHttpRequest)b="2";else if("undefined"!=typeof ActiveXObject){var c,d,e=["MSXML2.XMLHTTP.6.0","MSXML2.XMLHTTP.3.0","MSXML2.XMLHTT'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 12 server_application_data [1400 bytes]:
17 03 03 05 73 b4 1f eb cf 29 77 4d f8 4f 79 d0
96 b4 ef f2 f1 3d 07 2a 34 09 2a 07 4f [...]
  - TLS record 12 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xb4\x1f\xeb\xcf)wM\xf8Oy\xd0\x96\xb4\xef\xf2\xf1'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
b4 1f eb cf 29 77 4d f8 4f 79 d0 96 b4 ef f2 f1
3d 07 2a 34 09 2a 07 4f b2 33 77 e1 f4 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b9
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 8'
  - Inner TLS message 12 server_application_data_(decrypted) [1379 bytes]:
50 22 2c 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d
4c 48 54 54 50 22 5d 3b 66 6f 72 28 63 [...]
  - Inner TLS message 12 server_application_data_(decrypted): Container: 
    content = b'P","Microsoft.XM'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 12 server_application_data [1378 bytes]:
50 22 2c 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d
4c 48 54 54 50 22 5d 3b 66 6f 72 28 63 [...]
  - TLS message 12 server_application_data [1378 bytes]: b'P","Microsoft.XMLHTTP"];for(c=0;d=e[c++];)try{new ActiveXObject(d),b="2"}catch(h){}}a=b;if("2"==a&&-1==location.search.indexOf("&gbv=2")){var f=google.gbvu,g=document.getElementById("gbv");g&&(g.value=a);f&&window.setTimeout(function(){location.href=f},0)};}).call(this);</script></form><div id="gac_scont"></div><div style="font-size:83%;min-height:3.5em"><br><div id="prm"><style>.szppmdbYutt__middle-slot-promo{font-size:small;margin-bottom:32px}.szppmdbYutt__middle-slot-promo a.ZIeIlb{display:inline-block;text-decoration:none}.szppmdbYutt__middle-slot-promo img{border:none;margin-right:5px;vertical-align:middle}</style><div class="szppmdbYutt__middle-slot-promo" data-ved="0ahUKEwiN9Nrq1JD-AhX3JTQIHYOXAcwQnIcBCAQ"><a class="NKcBbd" href="https://www.google.com/url?q=https://blog.google/products/search/google-search-new-fact-checking-misinformation/&amp;source=hpp&amp;id=19034203&amp;ct=3&amp;usg=AOvVaw3UxG35a-5UX1Rl8M_VwPbd&amp;sa=X&amp;ved=0ahUKEwiN9Nrq1JD-AhX3JTQIHYOXAcwQ8IcBCAU" rel="nofollow">Helpful tips to fact check information online</a></div></div><div id="gws-output-pages-elements-homepage_additional_languages__als"><style>#gws-output-pages-elements-homepage_additional_languages__als{font-size:small;margin-bottom:24px}#SIvCob{color:#3c4043;display:inline-block;line-height:28px;}#SIvCob a{padding:0 3px;}.H6sW5{display:inline-block;margin:0 2px;whit'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 13 server_application_data [1400 bytes]:
17 03 03 05 73 25 46 de ee 71 7b da a5 10 16 75
db 87 c0 d8 13 dc 67 be 34 f4 0b 99 d0 [...]
  - TLS record 13 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'%F\xde\xeeq{\xda\xa5\x10\x16u\xdb\x87\xc0\xd8\x13'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
25 46 de ee 71 7b da a5 10 16 75 db 87 c0 d8 13
dc 67 be 34 f4 0b 99 d0 1b bc 61 d7 5a [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b8
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 9'
  - Inner TLS message 13 server_application_data_(decrypted) [1379 bytes]:
65 2d 73 70 61 63 65 3a 6e 6f 77 72 61 70 7d 2e
7a 34 68 67 57 65 7b 64 69 73 70 6c 61 [...]
  - Inner TLS message 13 server_application_data_(decrypted): Container: 
    content = b'e-space:nowrap}.'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 13 server_application_data [1378 bytes]:
65 2d 73 70 61 63 65 3a 6e 6f 77 72 61 70 7d 2e
7a 34 68 67 57 65 7b 64 69 73 70 6c 61 [...]
  - TLS message 13 server_application_data [1378 bytes]: b'e-space:nowrap}.z4hgWe{display:inline-block;margin:0 2px}</style><div id="SIvCob">Google offered in:  <a href="https://www.google.com/setprefs?sig=0_2IjtamdCyF9GD472hcVETonAmbw%3D&amp;hl=fr&amp;source=homepage&amp;sa=X&amp;ved=0ahUKEwiN9Nrq1JD-AhX3JTQIHYOXAcwQ2ZgBCAc">Fran\xe7ais</a>  </div></div></div><span id="footer"><div style="font-size:10pt"><div style="margin:19px auto;text-align:center" id="WqQANb"><a href="/intl/en/ads/">Advertising</a><a href="/services/">Business Solutions</a><a href="/intl/en/about.html">About Google</a><a href="https://www.google.com/setprefdomain?prefdom=CA&amp;prev=https://www.google.ca/&amp;sig=K_psl4LFhcP6ZZpMnZdhDYJvrP3LA%3D">Google.ca</a></div></div><p style="font-size:8pt;color:#70757a">&copy; 2023 - <a href="/intl/en/policies/privacy/">Privacy</a> - <a href="/intl/en/policies/terms/">Terms</a></p></span></center><script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){window.google.cdo={height:757,width:1440};(function(){var a=window.innerWidth,b=window.innerHeight;if(!a||!b){var c=window.document,d="CSS1Compat"==c.compatMode?c.documentElement:c.body;a=d.clientWidth;b=d.clientHeight}a&&b&&(a!=google.cdo.width||b!=google.cdo.height)&&google.log("","","/client_204?&atyp=i&biw="+a+"&bih="+b+"&ei="+google.kEI);}).call(this);})();</script> <script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){google.xjs={ck:\'xjs.hp.7OK0Zk1e1VY.L.X.O\',c'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 14 server_application_data [1400 bytes]:
17 03 03 05 73 ec bd 90 4a 24 8a 23 f8 d4 75 44
4c 97 d3 93 ee ae 2c 86 dc 23 aa 90 51 [...]
  - TLS record 14 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xec\xbd\x90J$\x8a#\xf8\xd4uDL\x97\xd3\x93\xee'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
ec bd 90 4a 24 8a 23 f8 d4 75 44 4c 97 d3 93 ee
ae 2c 86 dc 23 aa 90 51 0f f8 0f fc bc [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e bb
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 10'
  - Inner TLS message 14 server_application_data_(decrypted) [1379 bytes]:
73 3a 27 41 43 54 39 30 6f 47 33 4b 67 30 50 54
66 6f 4e 59 4b 39 4d 73 6b 79 70 75 6d [...]
  - Inner TLS message 14 server_application_data_(decrypted): Container: 
    content = b"s:'ACT90oG3Kg0PT"... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 14 server_application_data [1378 bytes]:
73 3a 27 41 43 54 39 30 6f 47 33 4b 67 30 50 54
66 6f 4e 59 4b 39 4d 73 6b 79 70 75 6d [...]
  - TLS message 14 server_application_data [1378 bytes]: b's:\'ACT90oG3Kg0PTfoNYK9MskypumscD_JjWQ\',excm:[]};})();</script>  <script nonce="yWZbd7mE6PqhRDqwWJsivw">(function(){var u=\'/xjs/_/js/k\\x3dxjs.hp.en.c8Y5Z0nJNyE.O/am\\x3dAAAAdAIAKACw/d\\x3d1/ed\\x3d1/rs\\x3dACT90oHFQ7EvjWWPBTWpfHye_KR8s4v6TQ/m\\x3dsb_he,d\';var amd=0;\nvar e=this||self,g=function(c){return c};var k;var n=function(c,f){this.g=f===l?c:""};n.prototype.toString=function(){return this.g+""};var l={};\nfunction p(){var c=u,f=function(){};google.lx=google.stvsc?f:function(){google.timers&&google.timers.load&&google.tick&&google.tick("load","xjsls");var a=document;var b="SCRIPT";"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());b=a.createElement(b);b.id="base-js";a=null===c?"null":void 0===c?"undefined":c;if(void 0===k){var d=null;var m=e.trustedTypes;if(m&&m.createPolicy){try{d=m.createPolicy("goog#html",{createHTML:g,createScript:g,createScriptURL:g})}catch(r){e.console&&e.console.error(r.message)}k=\nd}else k=d}a=(d=k)?d.createScriptURL(a):a;a=new n(a,l);b.src=a instanceof n&&a.constructor===n?a.g:"type_error:TrustedResourceUrl";var h,q;(h=(a=null==(q=(h=(b.ownerDocument&&b.ownerDocument.defaultView||window).document).querySelector)?void 0:q.call(h,"script[nonce]"))?a.nonce||a.getAttribute("nonce")||"":"")&&b.setAttribute("nonce",h);document.body.appendChild(b);google.psa=!0;google.lx=f};google.bx||google.lx()};google.xjsu=u;setTimeout(function'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 15 server_application_data [1116 bytes]:
17 03 03 04 57 ba cd 6e af 87 d3 d4 c7 93 75 7d
67 7b 7b 42 67 71 69 2f ae 2b 8c 73 90 [...]
  - TLS record 15 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xba\xcdn\xaf\x87\xd3\xd4\xc7\x93u}g{{Bg'... (truncated, total 1111)
  - fragment (encrypted) [1111 bytes]:
ba cd 6e af 87 d3 d4 c7 93 75 7d 67 7b 7b 42 67
71 69 2f ae 2b 8c 73 90 1d 9b 35 aa 78 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e ba
  - additional_data [5 bytes]:
17 03 03 04 57
'  - sequence_number: 11'
  - Inner TLS message 15 server_application_data_(decrypted) [1095 bytes]:
28 29 7b 30 3c 61 6d 64 3f 67 6f 6f 67 6c 65 2e
63 61 66 74 28 66 75 6e 63 74 69 6f 6e [...]
  - Inner TLS message 15 server_application_data_(decrypted): Container: 
    content = b'(){0<amd?google.'... (truncated, total 1094)
    type = (enum) application_data 23
    zeros = None
  - TLS message 15 server_application_data [1094 bytes]:
28 29 7b 30 3c 61 6d 64 3f 67 6f 6f 67 6c 65 2e
63 61 66 74 28 66 75 6e 63 74 69 6f 6e [...]
  - TLS message 15 server_application_data [1094 bytes]: b"(){0<amd?google.caft(function(){return p()},amd):p()},0);})();window._ = window._ || {};window._DumpException = _._DumpException = function(e){throw e;};window._s = window._s || {};_s._DumpException = _._DumpException;window._qs = window._qs || {};_qs._DumpException = _._DumpException;function _F_installCss(c){}\n(function(){google.jl={blt:'none',chnk:0,dw:false,dwu:true,emtn:0,end:0,ico:false,ikb:0,ine:false,injs:'none',injt:0,injth:0,injv2:false,lls:'default',pdt:0,rep:0,snet:true,strt:0,ubm:false,uwp:true};})();(function(){var pmc='{\\x22d\\x22:{},\\x22sb_he\\x22:{\\x22agen\\x22:true,\\x22cgen\\x22:true,\\x22client\\x22:\\x22heirloom-hp\\x22,\\x22dh\\x22:true,\\x22ds\\x22:\\x22\\x22,\\x22fl\\x22:true,\\x22host\\x22:\\x22google.com\\x22,\\x22jsonp\\x22:true,\\x22msgs\\x22:{\\x22cibl\\x22:\\x22Clear Search\\x22,\\x22dym\\x22:\\x22Did you mean:\\x22,\\x22lcky\\x22:\\x22I\\\\u0026#39;m Feeling Lucky\\x22,\\x22lml\\x22:\\x22Learn more\\x22,\\x22psrc\\x22:\\x22This search was removed from your \\\\u003Ca href\\x3d\\\\\\x22/history\\\\\\x22\\\\u003EWeb History\\\\u003C/a\\\\u003E\\x22,\\x22psrl\\x22:\\x22Remove\\x22,\\x22sbit\\x22:\\x22Search by image\r\n"
:: application_data received


:: Receiving new plain text fragment
  - TLS record 16 server_application_data [310 bytes]:
17 03 03 01 31 3b 37 02 37 64 a9 74 4c cd 22 e7
30 a4 59 59 e7 8f 83 b1 75 5e 90 bd 2e [...]
  - TLS record 16 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b';7\x027d\xa9tL\xcd"\xe70\xa4YY\xe7'... (truncated, total 305)
  - fragment (encrypted) [305 bytes]:
3b 37 02 37 64 a9 74 4c cd 22 e7 30 a4 59 59 e7
8f 83 b1 75 5e 90 bd 2e 44 56 a3 97 81 [...]
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e bd
  - additional_data [5 bytes]:
17 03 03 01 31
'  - sequence_number: 12'
  - Inner TLS message 16 server_application_data_(decrypted) [289 bytes]:
31 31 39 0d 0a 5c 78 32 32 2c 5c 78 32 32 73 72
63 68 5c 78 32 32 3a 5c 78 32 32 47 6f [...]
  - Inner TLS message 16 server_application_data_(decrypted): Container: 
    content = b'119\r\n\\x22,\\x22sr'... (truncated, total 288)
    type = (enum) application_data 23
    zeros = None
  - TLS message 16 server_application_data [288 bytes]:
31 31 39 0d 0a 5c 78 32 32 2c 5c 78 32 32 73 72
63 68 5c 78 32 32 3a 5c 78 32 32 47 6f [...]
  - TLS message 16 server_application_data [288 bytes]: b"119\r\n\\x22,\\x22srch\\x22:\\x22Google Search\\x22},\\x22ovr\\x22:{},\\x22pq\\x22:\\x22\\x22,\\x22rfs\\x22:[],\\x22sbas\\x22:\\x220 3px 8px 0 rgba(0,0,0,0.2),0 0 0 1px rgba(0,0,0,0.08)\\x22,\\x22stok\\x22:\\x22H8NYXHRXgKcHhhQ9anBA4ahQcpE\\x22}}';google.pmc=JSON.parse(pmc);})();</script>       </body></html>\r\n"
:: application_data received


:: Receiving new plain text fragment
  - TLS record 17 server_application_data [27 bytes]:
17 03 03 00 16 ee d8 c6 1c 53 cb b3 42 24 ba e0
c6 33 d5 ce ea d7 16 a3 d9 de c9
  - TLS record 17 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xee\xd8\xc6\x1cS\xcb\xb3B$\xba\xe0\xc63\xd5\xce\xea'... (truncated, total 22)
  - fragment (encrypted) [22 bytes]:
ee d8 c6 1c 53 cb b3 42 24 ba e0 c6 33 d5 ce ea
d7 16 a3 d9 de c9
  - write_key [16 bytes]:
f7 c6 9d a4 87 fb c4 ad 31 87 fa 87 1b 4c 36 23
  - write_iv [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e b1
  - nonce [12 bytes]:
76 37 7e 6b 51 67 7d 47 eb 28 3e bc
  - additional_data [5 bytes]:
17 03 03 00 16
'  - sequence_number: 13'
  - Inner TLS message 17 server_application_data_(decrypted) [6 bytes]:
30 0d 0a 0d 0a 17
  - Inner TLS message 17 server_application_data_(decrypted): Container: 
    content = b'0\r\n\r\n' (total 5)
    type = (enum) application_data 23
    zeros = None
  - TLS message 17 server_application_data [5 bytes]:
30 0d 0a 0d 0a
  - TLS message 17 server_application_data [5 bytes]: b'0\r\n\r\n'
:: application_data received

APPLICATION DATA - [cert]: b'HTTP/1.1 200 OK\r\nDate: Tue, 04 Apr 2023 16:38:15 GMT\r\nExpires: -1\r\nCache-Control: private, max-age=0\r\nContent-Type: text/html; charset=ISO-8859-1\r\nContent-Security-Policy-Report-Only: object-src \'none\';base-uri \'self\';script-src \'nonce-yWZbd7mE6PqhRDqwWJsivw\' \'strict-dynamic\' \'report-sample\' \'unsafe-eval\' \'unsafe-inline\' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp\r\nP3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."\r\nServer: gws\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nSet-Cookie: 1P_JAR=2023-04-04-16; expires=Thu, 04-May-2023 16:38:15 GMT; path=/; domain=.google.com; Secure\r\nSet-Cookie: AEC=AUEFqZfsb9EwBG3VaUuNAk-yQpI-KCRpr00Er0wggmkIZbD7sfRfSWBJuOI; expires=Sun, 01-Oct-2023 16:38:15 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax\r\nSet-Cookie: NID=511=uG7fsvXappgu_xN4b5Y8wpxPjhmombKvzpE6fr2ZcIFY6bxsLrKZd2wAKgemYSFkpjwYdr2F2dAVCvCpabbowX0U5fpoFC6_d6Qj2d0c2AhQzFjHiNZ9SDM46qz7V1IuhnGR8zat5ZPpB8gK3XYq1VTm6F9xK-uFqONR-ezZ9_o; expires=Wed, 04-Oct-2023 16:38:15 GMT; path=/; domain=.google.com; HttpOnly\r\nAlt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Accept-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n3aba\r\n<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en-CA"><head>[...]</head><body bgcolor="#fff">[...]</body></html>\r\n0\r\n\r\n'
======================================================
============= TLS with PSK authentication ============
======================================================

::Instantiating the Lurk client
--- E -> CS: Sending ping Request:
--- E <- CS: Receiving ping Response:
::TCP session with the TLS server
--- E -> CS: Sending c_init_client_hello Request:
--- E <- CS: Receiving c_init_client_hello Response:
:: 
Sending client_hello
  - TLS record 1 client_client_hello [177 bytes]:
16 03 03 00 ac 01 00 00 a8 03 03 fd 9f 37 26 fb
55 fc 41 bd 67 16 50 69 84 1a bf 22 cd 30 98 43
61 c6 02 e5 73 bd 53 04 7e bf ab 20 56 9b 1e 8f
0d b0 02 37 88 20 15 3d c6 3c 57 9d 03 59 79 a8
1d 9c 71 a2 5c a8 80 09 fb 03 62 84 00 04 13 01
13 03 01 00 00 5b 00 2b 00 03 02 03 04 00 0d 00
1e 00 1c 04 01 05 01 06 01 04 03 05 03 06 03 08
04 08 05 08 09 08 0a 08 09 08 07 08 08 02 01 00
0a 00 04 00 02 00 1d 00 33 00 26 00 24 00 1d 00
20 17 9b d8 3c d0 2f c8 e8 27 84 a9 75 87 36 bc
5a 7f 53 f2 86 ea 44 32 37 52 48 ab 96 cd 0a 72
33
  - TLS record 1 client_client_hello: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        msg_type = (enum) client_hello 1
        data = Container: 
            legacy_version = b'\x03\x03' (total 2)
            random = b'\xfd\x9f7&\xfbU\xfcA\xbdg\x16Pi\x84\x1a\xbf'... (truncated, total 32)
            legacy_session_id = b'V\x9b\x1e\x8f\r\xb0\x027\x88 \x15=\xc6<W\x9d'... (truncated, total 32)
            cipher_suites = ListContainer: 
                TLS_AES_128_GCM_SHA256
                TLS_CHACHA20_POLY1305_SHA256
            legacy_compression_methods = b'\x00' (total 1)
            extensions = ListContainer: 
                Container: 
                    extension_type = (enum) supported_versions 43
                    extension_data = Container: 
                        versions = ListContainer: 
                            b'\x03\x04'
                Container: 
                    extension_type = (enum) signature_algorithms 13
                    extension_data = Container: 
                        supported_signature_algorithms = ListContainer: 
                            rsa_pkcs1_sha256
                            rsa_pkcs1_sha384
                            rsa_pkcs1_sha512
                            ecdsa_secp256r1_sha256
                            ecdsa_secp384r1_sha384
                            ecdsa_secp521r1_sha512
                            rsa_pss_rsae_sha256
                            rsa_pss_rsae_sha384
                            rsa_pss_pss_sha256
                            rsa_pss_pss_sha384
                            rsa_pss_pss_sha256
                            ed25519
                            ed448
                            rsa_pkcs1_sha1
                Container: 
                    extension_type = (enum) supported_groups 10
                    extension_data = Container: 
                        named_group_list = ListContainer: 
                            x25519
                Container: 
                    extension_type = (enum) key_share 51
                    extension_data = Container: 
                        client_shares = ListContainer: 
                            Container: 
                                group = (enum) x25519 b'\x00\x1d'
                                key_exchange = b"\x17\x9b\xd8<\xd0/\xc8\xe8'\x84\xa9u\x876\xbcZ"... (truncated, total 32)

:: Receiving new plain text fragment
  - TLS record 1 server_fragment_bytes [127 bytes]:
16 03 03 00 7a 02 00 00 76 03 03 57 b5 6f 71 50
44 41 54 f6 da 2d cf 59 ef 89 67 4f 58 7b 36 b5
cc 24 75 6a 61 33 eb c1 61 ba d8 20 56 9b 1e 8f
0d b0 02 37 88 20 15 3d c6 3c 57 9d 03 59 79 a8
1d 9c 71 a2 5c a8 80 09 fb 03 62 84 13 01 00 00
2e 00 33 00 24 00 1d 00 20 de d0 95 6d ed 55 46
01 26 c6 a5 cc 0f 6c 21 57 4d 42 bc ed 99 52 80
43 91 81 b9 82 7b 0f 96 4f 00 2b 00 02 03 04
  - TLS record 1 server_fragment_bytes: Container: 
    type = (enum) handshake 22
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x02\x00\x00v\x03\x03W\xb5oqPDAT\xf6\xda'... (truncated, total 122)
  - handshake_message: [122 bytes]:
02 00 00 76 03 03 57 b5 6f 71 50 44 41 54 f6 da
2d cf 59 ef 89 67 4f 58 7b 36 b5 cc 24 75 6a 61
33 eb c1 61 ba d8 20 56 9b 1e 8f 0d b0 02 37 88
20 15 3d c6 3c 57 9d 03 59 79 a8 1d 9c 71 a2 5c
a8 80 09 fb 03 62 84 13 01 00 00 2e 00 33 00 24
00 1d 00 20 de d0 95 6d ed 55 46 01 26 c6 a5 cc
0f 6c 21 57 4d 42 bc ed 99 52 80 43 91 81 b9 82
7b 0f 96 4f 00 2b 00 02 03 04
handshake_message: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'W\xb5oqPDAT\xf6\xda-\xcfY\xef\x89g'... (truncated, total 32)
        legacy_session_id_echo = b'V\x9b\x1e\x8f\r\xb0\x027\x88 \x15=\xc6<W\x9d'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'\xde\xd0\x95m\xedUF\x01&\xc6\xa5\xcc\x0fl!W'... (truncated, total 32)
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
:: server_hello received

  - TLS message 1 server_server_hello [122 bytes]:
02 00 00 76 03 03 57 b5 6f 71 50 44 41 54 f6 da
2d cf 59 ef 89 67 4f 58 7b 36 b5 cc 24 75 6a 61
33 eb c1 61 ba d8 20 56 9b 1e 8f 0d b0 02 37 88
20 15 3d c6 3c 57 9d 03 59 79 a8 1d 9c 71 a2 5c
a8 80 09 fb 03 62 84 13 01 00 00 2e 00 33 00 24
00 1d 00 20 de d0 95 6d ed 55 46 01 26 c6 a5 cc
0f 6c 21 57 4d 42 bc ed 99 52 80 43 91 81 b9 82
7b 0f 96 4f 00 2b 00 02 03 04
  - TLS message 1 server_server_hello: Container: 
    msg_type = (enum) server_hello 2
    data = Container: 
        legacy_version = b'\x03\x03' (total 2)
        random = b'W\xb5oqPDAT\xf6\xda-\xcfY\xef\x89g'... (truncated, total 32)
        legacy_session_id_echo = b'V\x9b\x1e\x8f\r\xb0\x027\x88 \x15=\xc6<W\x9d'... (truncated, total 32)
        cipher_suite = (enum) TLS_AES_128_GCM_SHA256 b'\x13\x01'
        legacy_compression_method = b'\x00' (total 1)
        extensions = ListContainer: 
            Container: 
                extension_type = (enum) key_share 51
                extension_data = Container: 
                    server_share = Container: 
                        group = (enum) x25519 b'\x00\x1d'
                        key_exchange = b'\xde\xd0\x95m\xedUF\x01&\xc6\xa5\xcc\x0fl!W'... (truncated, total 32)
            Container: 
                extension_type = (enum) supported_versions 43
                extension_data = Container: 
                    selected_version = b'\x03\x04' (total 2)
:: server_hello received

--- E -> CS: Sending c_server_hello Request:
--- E <- CS: Receiving c_server_hello Response:
  - Transcript Hash [mode h] [32 bytes]:
1e 42 35 88 ff df 09 cb 60 03 a3 20 88 4f 74 45
4d ac 96 7d e7 e2 2a 88 d6 40 30 9c 69 76 2a eb
  - server_handshake_write_key [16 bytes]:
81 ec 5d 67 aa d9 38 b4 4b db c8 df d7 dc d9 85
  - server_handshake_write_iv [12 bytes]:
45 6c 25 14 92 15 3d ef 35 51 8b e9
  - client_handshake_write_key [16 bytes]:
91 b9 e0 99 25 4d 3d a1 5e 14 5c 36 33 e1 01 38
  - client_handshake_write_iv [12 bytes]:
77 40 11 7b 59 b9 6b ad d8 97 fd 51

:: Receiving new plain text fragment
  - TLS record 2 server_change_cipher_spec [6 bytes]:
14 03 03 00 01 01
  - TLS record 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 20
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = Container: 
        type = (enum) change_cipher_spec 1
  - TLS message 2 server_change_cipher_spec [1 bytes]:
01
  - TLS message 2 server_change_cipher_spec: Container: 
    type = (enum) change_cipher_spec 1
:: change_cipher_spec received


:: Receiving new plain text fragment
  - TLS record 3 server_application_data [1237 bytes]:
17 03 03 04 d0 88 b9 0c e5 1f 36 98 1b 96 c7 0b
bf bf ed a1 e7 3c 95 78 98 c1 74 d8 32 [...]
  - TLS record 3 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x88\xb9\x0c\xe5\x1f6\x98\x1b\x96\xc7\x0b\xbf\xbf\xed\xa1\xe7'... (truncated, total 1232)
  - fragment (encrypted) [1232 bytes]:
88 b9 0c e5 1f 36 98 1b 96 c7 0b bf bf ed a1 e7
3c 95 78 98 c1 74 d8 32 7a c0 2f 38 bf [...]
  - write_key [16 bytes]:
81 ec 5d 67 aa d9 38 b4 4b db c8 df d7 dc d9 85
  - write_iv [12 bytes]:
45 6c 25 14 92 15 3d ef 35 51 8b e9
  - nonce [12 bytes]:
45 6c 25 14 92 15 3d ef 35 51 8b e9
  - additional_data [5 bytes]:
17 03 03 04 d0
'  - sequence_number: 0'
  - Inner TLS message 3 server_fragment_bytes_(decrypted) [1216 bytes]:
08 00 00 02 00 00 0b 00 03 89 00 00 03 85 00 03
80 30 82 03 7c 30 82 02 64 a0 03 02 01 [...]
  - Inner TLS message 3 server_fragment_bytes_(decrypted): Container: 
    content = b'\x08\x00\x00\x02\x00\x00\x0b\x00\x03\x89\x00\x00\x03\x85\x00\x03'... (truncated, total 1215)
    type = (enum) handshake 22
    zeros = None
  - handshake_message: [6 bytes]:
08 00 00 02 00 00
handshake_message: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received

  - TLS message 3 server_encrypted_extensions [6 bytes]:
08 00 00 02 00 00
  - TLS message 3 server_encrypted_extensions: Container: 
    msg_type = (enum) encrypted_extensions 8
    data = Container: 
        extensions = ListContainer: 
:: encrypted_extensions received

  - handshake_message: [909 bytes]:
0b 00 03 89 00 00 03 85 00 03 80 30 82 03 7c 30
82 02 64 a0 03 02 01 02 02 09 00 90 76 [...]
handshake_message: Container: 
    msg_type = (enum) certificate 11
    data = Container: 
        certificate_request_context = b'' (total 0)
        certificate_list = ListContainer: 
            Container: 
                cert = b'0\x82\x03|0\x82\x02d\xa0\x03\x02\x01\x02\x02\t\x00'... (truncated, total 896)
                extensions = ListContainer: 
:: certificate received

  - handshake_message: [264 bytes]:
0f 00 01 04 08 04 01 00 1d c9 ac b0 1e cf fa 57
33 e4 ce d2 d0 c3 1b dd 11 71 a6 e9 af [...]
handshake_message: Container: 
    msg_type = (enum) certificate_verify 15
    data = Container: 
        algorithm = (enum) rsa_pss_rsae_sha256 b'\x08\x04'
        signature = b'\x1d\xc9\xac\xb0\x1e\xcf\xfaW3\xe4\xce\xd2\xd0\xc3\x1b\xdd'... (truncated, total 256)
:: certificate_verify received

  - Transcript Hash [mode sig] [32 bytes]:
c3 27 b4 af 63 c5 40 8d 87 72 22 94 17 bc ca 91
a5 6c 90 f2 fe 44 1c b6 7e 2a 6f 4d 62 26 ab b7
  - ctx_string [33 bytes]: b'TLS 1.3, server CertificateVerify'
  - ctx_string [33 bytes]:
54 4c 53 20 31 2e 33 2c 20 73 65 72 76 65 72 20
43 65 72 74 69 66 69 63 61 74 65 56 65 72 69 66
79
  - content to be signed [130 bytes]:
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
54 4c 53 20 31 2e 33 2c 20 73 65 72 76 65 72 20
43 65 72 74 69 66 69 63 61 74 65 56 65 72 69 66
79 00 c3 27 b4 af 63 c5 40 8d 87 72 22 94 17 bc
ca 91 a5 6c 90 f2 fe 44 1c b6 7e 2a 6f 4d 62 26
ab b7
  - handshake_message: [36 bytes]:
14 00 00 20 65 73 dd 13 60 de 53 ba d9 1f df c0
73 27 16 90 28 a2 16 f6 bc 82 b9 9b 95 ba bf 5b
f4 61 69 49
handshake_message: Container: 
    msg_type = (enum) finished 20
    data = Container: 
        verify_data = b"es\xdd\x13`\xdeS\xba\xd9\x1f\xdf\xc0s'\x16\x90"... (truncated, total 32)
:: finished received

  - Transcript Hash [mode server finished] [32 bytes]:
4e 65 e3 c4 e7 19 1c 6f 03 05 8e 61 ce 10 fd 78
75 63 10 bc e4 fe c9 d8 75 3a b3 67 42 48 dd 32
  - client computed verify_data [32 bytes]:
65 73 dd 13 60 de 53 ba d9 1f df c0 73 27 16 90
28 a2 16 f6 bc 82 b9 9b 95 ba bf 5b f4 61 69 49
  - server provided verify_data [32 bytes]:
65 73 dd 13 60 de 53 ba d9 1f df c0 73 27 16 90
28 a2 16 f6 bc 82 b9 9b 95 ba bf 5b f4 61 69 49
--- E -> CS: Sending c_client_finished Request:
--- E <- CS: Receiving c_client_finished Response:
  - Transcript Hash [mode client finished] [32 bytes]:
3f dc 5b 1c 1e 75 d8 4f d2 9c f2 68 50 f9 b2 82
ca 2b c0 e0 db 5a 98 8f dd 5d b2 a5 0d 35 79 8a
:: Sending finished

  - Inner TLS message 5 client_finished [37 bytes]:
14 00 00 20 9c 22 a0 51 78 e3 6c a8 28 48 cb d6
bb f6 fe 05 5b 7d a4 8e 41 4a 55 a0 a0 34 23 70
63 dd bd ec 16
  - Inner TLS message 5 client_finished: Container: 
    content = Container: 
        msg_type = (enum) finished 20
        data = Container: 
            verify_data = b'\x9c"\xa0Qx\xe3l\xa8(H\xcb\xd6\xbb\xf6\xfe\x05'... (truncated, total 32)
    type = (enum) handshake 22
    zeros = None
  - TLS record 5 client_application_data [58 bytes]:
17 03 03 00 35 b5 0d 97 87 02 62 ff c0 ba c7 e9
ef 91 f5 9a c7 8c 69 35 31 dc 1a ac ca c5 77 31
3f 4c a3 1e bb 25 51 8c 7c e8 e8 96 8e 8b a0 2d
f8 51 98 63 50 8e ab f3 51 39
  - TLS record 5 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xb5\r\x97\x87\x02b\xff\xc0\xba\xc7\xe9\xef\x91\xf5\x9a\xc7'... (truncated, total 53)
  - server_application_write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - server_application_write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - client_application_write_key [16 bytes]:
82 4a f4 85 84 58 e2 a4 10 a3 da 34 ea 4c a9 08
  - client_application_write_iv [12 bytes]:
af 79 68 71 ee b4 33 9d 26 99 ea 0c
:: Sending application_data

  - Inner TLS message 7 client_application_data [79 bytes]:
47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a
48 6f 73 74 3a 20 77 77 77 2e 67 6f 6f [...]
  - Inner TLS message 7 client_application_data: Container: 
    content = b'GET / HTTP/1.1\r\n'... (truncated, total 78)
    type = (enum) application_data 23
    zeros = None
  - TLS record 7 client_application_data [100 bytes]:
17 03 03 00 5f 3c 42 83 45 ff 77 24 19 fc 99 56
d3 d6 27 13 a1 bf cf 93 0c 10 34 b4 9a [...]
  - TLS record 7 client_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b"<B\x83E\xffw$\x19\xfc\x99V\xd3\xd6'\x13\xa1"... (truncated, total 95)

:: Receiving new plain text fragment
  - TLS record 4 server_application_data [1400 bytes]:
17 03 03 05 73 95 9e b8 1a 48 d1 88 29 ce 49 c5
f5 39 89 45 fa eb 76 93 23 e0 62 c6 1f [...]
  - TLS record 4 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x95\x9e\xb8\x1aH\xd1\x88)\xceI\xc5\xf59\x89E\xfa'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
95 9e b8 1a 48 d1 88 29 ce 49 c5 f5 39 89 45 fa
eb 76 93 23 e0 62 c6 1f 71 96 b5 f8 66 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 0'
  - Inner TLS message 4 server_application_data_(decrypted) [1379 bytes]:
48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d
0a 44 61 74 65 3a 20 54 75 65 2c 20 30 [...]
  - Inner TLS message 4 server_application_data_(decrypted): Container: 
    content = b'HTTP/1.1 200 OK\r'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 4 server_application_data [1378 bytes]:
48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d
0a 44 61 74 65 3a 20 54 75 65 2c 20 30 [...]
  - TLS message 4 server_application_data [1378 bytes]: b'HTTP/1.1 200 OK\r\nDate: Tue, 04 Apr 2023 16:38:16 GMT\r\nExpires: -1\r\nCache-Control: private, max-age=0\r\nContent-Type: text/html; charset=ISO-8859-1\r\nContent-Security-Policy-Report-Only: object-src \'none\';base-uri \'self\';script-src \'nonce-q0yFkpqJIaIXSgDGLkwpWQ\' \'strict-dynamic\' \'report-sample\' \'unsafe-eval\' \'unsafe-inline\' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp\r\nP3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."\r\nServer: gws\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nSet-Cookie: 1P_JAR=2023-04-04-16; expires=Thu, 04-May-2023 16:38:16 GMT; path=/; domain=.google.com; Secure\r\nSet-Cookie: AEC=AUEFqZeTXcWiBGazgK7YCmgHtZhy00Ouqbyb-6Vh_mwB6dypkWzFaIyy6hc; expires=Sun, 01-Oct-2023 16:38:16 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax\r\nSet-Cookie: NID=511=tBUu6pHTctk5Bc4eOevG1pwYD89EObffJU44xYciRZOgTBveZ1pbhW2S3WtQZxuCZdq5ixRmANmrcUxiasKisGYHpzS4YsJYKHn9Oji5yt8lq28Cy7F0ap6n_rKVp5TmwUG3O_z2LNP2msx2uE3dJNx1oxoboqfbtOgQ1gSYzdQ; expires=Wed, 04-Oct-2023 16:38:16 GMT; path=/; domain=.google.com; HttpOnly\r\nAlt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Accept-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n3a54\r\n<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en-CA"><head><meta content="text/html; charset=UTF-8" http-equiv="Content-Type"><meta'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 5 server_application_data [1400 bytes]:
17 03 03 05 73 d0 09 57 27 36 7a a0 bc 39 d5 ed
27 64 a2 1b 62 77 6e ae 30 7f 2b c6 78 [...]
  - TLS record 5 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b"\xd0\tW'6z\xa0\xbc9\xd5\xed'd\xa2\x1bb"... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
d0 09 57 27 36 7a a0 bc 39 d5 ed 27 64 a2 1b 62
77 6e ae 30 7f 2b c6 78 41 a1 bf 03 06 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c0
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 1'
  - Inner TLS message 5 server_application_data_(decrypted) [1379 bytes]:
20 63 6f 6e 74 65 6e 74 3d 22 2f 69 6d 61 67 65
73 2f 62 72 61 6e 64 69 6e 67 2f 67 6f [...]
  - Inner TLS message 5 server_application_data_(decrypted): Container: 
    content = b' content="/image'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 5 server_application_data [1378 bytes]:
20 63 6f 6e 74 65 6e 74 3d 22 2f 69 6d 61 67 65
73 2f 62 72 61 6e 64 69 6e 67 2f 67 6f [...]
  - TLS message 5 server_application_data [1378 bytes]: b' content="/images/branding/googleg/1x/googleg_standard_color_128dp.png" itemprop="image"><title>Google</title><script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){window.google={kEI:\'eFIsZN3qIcuu0PEP-puWyAs\',kEXPI:\'0,1359409,6058,207,4804,2316,383,246,5,1129120,1197751,650,380090,16114,28684,22430,1362,284,12035,2816,1929,12835,4998,13228,3847,38444,889,1983,2891,3926,214,7614,606,60690,2614,13142,3,346,230,1014,1,16916,2652,4,1528,2304,42127,11443,2215,4437,16786,5827,2530,4094,7596,1,42154,2,14022,2715,23024,5679,1021,31121,4569,6258,23418,1246,5841,14967,4333,7484,445,2,2,1,24626,2006,8155,7381,2,1477,14491,872,19634,7,1922,9779,21391,14763,6305,2007,18192,20136,14,82,12151,8055,1622,1779,11,4965,8048,6843,8481,991,1542,1488,426,5203,481,1411,890,6637,768,1804,7734,495,2243,1757,1127,450,2047,5159,685,1724,8922,7,331,416,2881,736,2829,1,2753,1758,3027,476,775,176,87,121,1607,564,3318,4,308,2,2145,888,2504,1075,1272,903,396,400,3698,2,843,956,2115,9,348,263,1717,220,486,653,3,956,408,628,137,60,79,460,155,766,1366,1127,201,144,168,467,132,2117,3,2,341,424,3,121,208,969,1,349,1,361,382,297,1438,535,123,1064,2,3,211,1295,412,11,328,102,860,100,5,163,130,1609,197,1540,75,446,339,2578,47,1002,2,308,5205100,11,5933,34,301,396,8798447,3311,141,795,19735,1,1,346,4650,36,12,44,20,14,23945709,397,4041745,1964,14297,2375,2894,6250,12561,4889,1413346,194320\',kBL:\'RbS'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 6 server_application_data [1400 bytes]:
17 03 03 05 73 79 1e ef a3 ca f4 b9 4b 0f 1d 33
60 6e 32 ce a2 ca 1f c1 1c 9d 23 bc d8 [...]
  - TLS record 6 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'y\x1e\xef\xa3\xca\xf4\xb9K\x0f\x1d3`n2\xce\xa2'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
79 1e ef a3 ca f4 b9 4b 0f 1d 33 60 6e 32 ce a2
ca 1f c1 1c 9d 23 bc d8 3e dc f0 f7 a8 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c3
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 2'
  - Inner TLS message 6 server_application_data_(decrypted) [1379 bytes]:
65 27 2c 6b 4f 50 49 3a 38 39 39 37 38 34 34 39
7d 3b 67 6f 6f 67 6c 65 2e 73 6e 3d 27 [...]
  - Inner TLS message 6 server_application_data_(decrypted): Container: 
    content = b"e',kOPI:89978449"... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 6 server_application_data [1378 bytes]:
65 27 2c 6b 4f 50 49 3a 38 39 39 37 38 34 34 39
7d 3b 67 6f 6f 67 6c 65 2e 73 6e 3d 27 [...]
  - TLS message 6 server_application_data [1378 bytes]: b'e\',kOPI:89978449};google.sn=\'webhp\';google.kHL=\'en-CA\';})();(function(){\nvar f=this||self;var h,k=[];function l(a){for(var b;a&&(!a.getAttribute||!(b=a.getAttribute("eid")));)a=a.parentNode;return b||h}function m(a){for(var b=null;a&&(!a.getAttribute||!(b=a.getAttribute("leid")));)a=a.parentNode;return b}\nfunction n(a,b,c,d,g){var e="";c||-1!==b.search("&ei=")||(e="&ei="+l(d),-1===b.search("&lei=")&&(d=m(d))&&(e+="&lei="+d));d="";!c&&f._cshid&&-1===b.search("&cshid=")&&"slh"!==a&&(d="&cshid="+f._cshid);c=c||"/"+(g||"gen_204")+"?atyp=i&ct="+a+"&cad="+b+e+"&zx="+Date.now()+d;/^http:/i.test(c)&&"https:"===window.location.protocol&&(google.ml&&google.ml(Error("a"),!1,{src:c,glmm:1}),c="");return c};h=google.kEI;google.getEI=l;google.getLEI=m;google.ml=function(){return null};google.log=function(a,b,c,d,g){if(c=n(a,b,c,d,g)){a=new Image;var e=k.length;k[e]=a;a.onerror=a.onload=a.onabort=function(){delete k[e]};a.src=c}};google.logUrl=n;}).call(this);(function(){google.y={};google.sy=[];google.x=function(a,b){if(a)var c=a.id;else{do c=Math.random();while(google.y[c])}google.y[c]=[a,b];return!1};google.sx=function(a){google.sy.push(a)};google.lm=[];google.plm=function(a){google.lm.push.apply(google.lm,a)};google.lq=[];google.load=function(a,b,c){google.lq.push([[a],b,c])};google.loadAll=function(a,b){google.lq.push([a,b])};google.bx=!1;google.lx=function(){};}).c'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 7 server_application_data [1400 bytes]:
17 03 03 05 73 99 bc 70 fe 46 47 86 89 2d e3 38
1d 58 be 95 80 94 11 0c 1e b3 af 18 59 [...]
  - TLS record 7 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x99\xbcp\xfeFG\x86\x89-\xe38\x1dX\xbe\x95\x80'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
99 bc 70 fe 46 47 86 89 2d e3 38 1d 58 be 95 80
94 11 0c 1e b3 af 18 59 cb c1 15 0c e8 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c2
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 3'
  - Inner TLS message 7 server_application_data_(decrypted) [1379 bytes]:
61 6c 6c 28 74 68 69 73 29 3b 67 6f 6f 67 6c 65
2e 66 3d 7b 7d 3b 28 66 75 6e 63 74 69 [...]
  - Inner TLS message 7 server_application_data_(decrypted): Container: 
    content = b'all(this);google'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 7 server_application_data [1378 bytes]:
61 6c 6c 28 74 68 69 73 29 3b 67 6f 6f 67 6c 65
2e 66 3d 7b 7d 3b 28 66 75 6e 63 74 69 [...]
  - TLS message 7 server_application_data [1378 bytes]: b'all(this);google.f={};(function(){\ndocument.documentElement.addEventListener("submit",function(b){var a;if(a=b.target){var c=a.getAttribute("data-submitfalse");a="1"===c||"q"===c&&!a.elements.q.value?!0:!1}else a=!1;a&&(b.preventDefault(),b.stopPropagation())},!0);document.documentElement.addEventListener("click",function(b){var a;a:{for(a=b.target;a&&a!==document.documentElement;a=a.parentElement)if("A"===a.tagName){a="1"===a.getAttribute("data-nohref");break a}a=!1}a&&b.preventDefault()},!0);}).call(this);</script><style>#gbar,#guser{font-size:13px;padding-top:1px !important;}#gbar{height:22px}#guser{padding-bottom:7px !important;text-align:right}.gbh,.gbd{border-top:1px solid #c9d7f1;font-size:1px}.gbh{height:0;position:absolute;top:24px;width:100%}@media all{.gb1{height:22px;margin-right:.5em;vertical-align:top}#gbar{float:left}}a.gb1,a.gb4{text-decoration:underline !important}a.gb1,a.gb4{color:#00c !important}.gbi .gb4{color:#dd8e27 !important}.gbf .gb4{color:#900 !important}\n</style><style>body,td,a,p,.h{font-family:arial,sans-serif}body{margin:0;overflow-y:scroll}#gog{padding:3px 8px 0}td{line-height:.8em}.gac_m td{line-height:17px}form{margin-bottom:20px}.h{color:#1558d6}em{font-weight:bold;font-style:normal}.lst{height:25px;width:496px}.gsfi,.lst{font:18px arial,sans-serif}.gsfs{font:17px arial,sans-serif}.ds{display:inline-box;display:inline-bloc'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 8 server_application_data [1400 bytes]:
17 03 03 05 73 76 63 20 16 99 76 0c ba ff bf 07
2b bd 88 cd 78 e4 21 82 b8 46 29 c3 e9 [...]
  - TLS record 8 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'vc \x16\x99v\x0c\xba\xff\xbf\x07+\xbd\x88\xcdx'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
76 63 20 16 99 76 0c ba ff bf 07 2b bd 88 cd 78
e4 21 82 b8 46 29 c3 e9 7a 86 a8 19 c9 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c5
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 4'
  - Inner TLS message 8 server_application_data_(decrypted) [1379 bytes]:
6b 3b 6d 61 72 67 69 6e 3a 33 70 78 20 30 20 34
70 78 3b 6d 61 72 67 69 6e 2d 6c 65 66 [...]
  - Inner TLS message 8 server_application_data_(decrypted): Container: 
    content = b'k;margin:3px 0 4'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 8 server_application_data [1378 bytes]:
6b 3b 6d 61 72 67 69 6e 3a 33 70 78 20 30 20 34
70 78 3b 6d 61 72 67 69 6e 2d 6c 65 66 [...]
  - TLS message 8 server_application_data [1378 bytes]: b'k;margin:3px 0 4px;margin-left:4px}input{font-family:inherit}body{background:#fff;color:#000}a{color:#4b11a8;text-decoration:none}a:hover,a:active{text-decoration:underline}.fl a{color:#1558d6}a:visited{color:#4b11a8}.sblc{padding-top:5px}.sblc a{display:block;margin:2px 0;margin-left:13px;font-size:11px}.lsbb{background:#f8f9fa;border:solid 1px;border-color:#dadce0 #70757a #70757a #dadce0;height:30px}.lsbb{display:block}#WqQANb a{display:inline-block;margin:0 12px}.lsb{background:url(/images/nav_logo229.png) 0 -261px repeat-x;border:none;color:#000;cursor:pointer;height:30px;margin:0;outline:0;font:15px arial,sans-serif;vertical-align:top}.lsb:active{background:#dadce0}.lst:focus{outline:none}</style><script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){window.google.erd={jsr:1,bv:1770,de:true};\nvar h=this||self;var k,l=null!=(k=h.mei)?k:1,n,p=null!=(n=h.sdo)?n:!0,q=0,r,t=google.erd,v=t.jsr;google.ml=function(a,b,d,m,e){e=void 0===e?2:e;b&&(r=a&&a.message);if(google.dl)return google.dl(a,e,d),null;if(0>v){window.console&&console.error(a,d);if(-2===v)throw a;b=!1}else b=!a||!a.message||"Error loading script"===a.message||q>=l&&!m?!1:!0;if(!b)return null;q++;d=d||{};b=encodeURIComponent;var c="/gen_204?atyp=i&ei="+b(google.kEI);google.kEXPI&&(c+="&jexpid="+b(google.kEXPI));c+="&srcpg="+b(google.sn)+"&jsr="+b(t.jsr)+"&bver="+b(t.bv);var f=a.lineNumber;void 0!=='
:: application_data received


:: Receiving new plain text fragment
  - TLS record 9 server_application_data [1400 bytes]:
17 03 03 05 73 23 b7 ee 58 ce 12 9c 6f e2 94 28
f3 e8 9d 69 20 2b dd a0 f4 e4 77 86 7f [...]
  - TLS record 9 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'#\xb7\xeeX\xce\x12\x9co\xe2\x94(\xf3\xe8\x9di '... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
23 b7 ee 58 ce 12 9c 6f e2 94 28 f3 e8 9d 69 20
2b dd a0 f4 e4 77 86 7f b2 35 5f 64 40 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c4
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 5'
  - Inner TLS message 9 server_application_data_(decrypted) [1379 bytes]:
66 26 26 28 63 2b 3d 22 26 6c 69 6e 65 3d 22 2b
66 29 3b 76 61 72 20 67 3d 0a 61 2e 66 [...]
  - Inner TLS message 9 server_application_data_(decrypted): Container: 
    content = b'f&&(c+="&line="+'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 9 server_application_data [1378 bytes]:
66 26 26 28 63 2b 3d 22 26 6c 69 6e 65 3d 22 2b
66 29 3b 76 61 72 20 67 3d 0a 61 2e 66 [...]
  - TLS message 9 server_application_data [1378 bytes]: b'f&&(c+="&line="+f);var g=\na.fileName;g&&(0<g.indexOf("-extension:/")&&(e=3),c+="&script="+b(g),f&&g===window.location.href&&(f=document.documentElement.outerHTML.split("\\n")[f],c+="&cad="+b(f?f.substring(0,300):"No script found.")));c+="&jsel="+e;for(var u in d)c+="&",c+=b(u),c+="=",c+=b(d[u]);c=c+"&emsg="+b(a.name+": "+a.message);c=c+"&jsst="+b(a.stack||"N/A");12288<=c.length&&(c=c.substr(0,12288));a=c;m||google.log(0,"",a);return a};window.onerror=function(a,b,d,m,e){r!==a&&(a=e instanceof Error?e:Error(a),void 0===d||"lineNumber"in a||(a.lineNumber=d),void 0===b||"fileName"in a||(a.fileName=b),google.ml(a,!1,void 0,!1,"SyntaxError"===a.name||"SyntaxError"===a.message.substring(0,11)||-1!==a.message.indexOf("Script error")?3:0));r=null;p&&q>=l&&(window.onerror=null)};})();</script></head><body bgcolor="#fff"><script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){var src=\'/images/nav_logo229.png\';var iesg=false;document.body.onload = function(){window.n && window.n();if (document.images){new Image().src=src;}\nif (!iesg){document.f&&document.f.q.focus();document.gbqf&&document.gbqf.q.focus();}\n}\n})();</script><div id="mngb"><div id=gbar><nobr><b class=gb1>Search</b> <a class=gb1 href="https://www.google.ca/imghp?hl=en&tab=wi">Images</a> <a class=gb1 href="https://maps.google.ca/maps?hl=en&tab=wl">Maps</a> <a class=gb1 href="https://play.google.com/?hl=en&tab=w'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 10 server_application_data [1400 bytes]:
17 03 03 05 73 67 71 9e 52 da a7 a3 0f 7e 9e 3d
93 1a b3 f7 fb 9a 69 cb 52 d8 3d 6f 1d [...]
  - TLS record 10 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'gq\x9eR\xda\xa7\xa3\x0f~\x9e=\x93\x1a\xb3\xf7\xfb'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
67 71 9e 52 da a7 a3 0f 7e 9e 3d 93 1a b3 f7 fb
9a 69 cb 52 d8 3d 6f 1d 34 0b c5 e9 e0 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c7
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 6'
  - Inner TLS message 10 server_application_data_(decrypted) [1379 bytes]:
38 22 3e 50 6c 61 79 3c 2f 61 3e 20 3c 61 20 63
6c 61 73 73 3d 67 62 31 20 68 72 65 66 [...]
  - Inner TLS message 10 server_application_data_(decrypted): Container: 
    content = b'8">Play</a> <a c'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 10 server_application_data [1378 bytes]:
38 22 3e 50 6c 61 79 3c 2f 61 3e 20 3c 61 20 63
6c 61 73 73 3d 67 62 31 20 68 72 65 66 [...]
  - TLS message 10 server_application_data [1378 bytes]: b'8">Play</a> <a class=gb1 href="https://www.youtube.com/?tab=w1">YouTube</a> <a class=gb1 href="https://news.google.com/?tab=wn">News</a> <a class=gb1 href="https://mail.google.com/mail/?tab=wm">Gmail</a> <a class=gb1 href="https://drive.google.com/?tab=wo">Drive</a> <a class=gb1 style="text-decoration:none" href="https://www.google.ca/intl/en/about/products?tab=wh"><u>More</u> &raquo;</a></nobr></div><div id=guser width=100%><nobr><span id=gbn class=gbi></span><span id=gbf class=gbf></span><span id=gbe></span><a href="http://www.google.ca/history/optout?hl=en" class=gb4>Web History</a> | <a  href="/preferences?hl=en" class=gb4>Settings</a> | <a target=_top id=gb_70 href="https://accounts.google.com/ServiceLogin?hl=en&passive=true&continue=https://www.google.com/&ec=GAZAAQ" class=gb4>Sign in</a></nobr></div><div class=gbh style=left:0></div><div class=gbh style=right:0></div></div><center><br clear="all" id="lgpd"><div id="lga"><img alt="Google" height="92" src="/images/branding/googlelogo/1x/googlelogo_white_background_color_272x92dp.png" style="padding:28px 0 14px" width="272" id="hplogo"><br><br></div><form action="/search" name="f"><table cellpadding="0" cellspacing="0"><tr valign="top"><td width="25%">&nbsp;</td><td align="center" nowrap=""><input name="ie" value="ISO-8859-1" type="hidden"><input value="en-CA" name="hl" type="hidden"><input name="sourc'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 11 server_application_data [1400 bytes]:
17 03 03 05 73 0f 6d 02 47 c8 79 99 38 ad ea 2f
c0 4d 35 f2 de 41 84 9e 1f 4e e2 79 fc [...]
  - TLS record 11 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x0fm\x02G\xc8y\x998\xad\xea/\xc0M5\xf2\xde'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
0f 6d 02 47 c8 79 99 38 ad ea 2f c0 4d 35 f2 de
41 84 9e 1f 4e e2 79 fc af 21 7e e0 60 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c6
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 7'
  - Inner TLS message 11 server_application_data_(decrypted) [1379 bytes]:
65 22 20 74 79 70 65 3d 22 68 69 64 64 65 6e 22
20 76 61 6c 75 65 3d 22 68 70 22 3e 3c [...]
  - Inner TLS message 11 server_application_data_(decrypted): Container: 
    content = b'e" type="hidden"'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 11 server_application_data [1378 bytes]:
65 22 20 74 79 70 65 3d 22 68 69 64 64 65 6e 22
20 76 61 6c 75 65 3d 22 68 70 22 3e 3c [...]
  - TLS message 11 server_application_data [1378 bytes]: b'e" type="hidden" value="hp"><input name="biw" type="hidden"><input name="bih" type="hidden"><div class="ds" style="height:32px;margin:4px 0"><input class="lst" style="margin:0;padding:5px 8px 0 6px;vertical-align:top;color:#000" autocomplete="off" value="" title="Google Search" maxlength="2048" name="q" size="57"></div><br style="line-height:0"><span class="ds"><span class="lsbb"><input class="lsb" value="Google Search" name="btnG" type="submit"></span></span><span class="ds"><span class="lsbb"><input class="lsb" id="tsuid_1" value="I\'m Feeling Lucky" name="btnI" type="submit"><script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){var id=\'tsuid_1\';document.getElementById(id).onclick = function(){if (this.form.q.value){this.checked = 1;if (this.form.iflsig)this.form.iflsig.disabled = false;}\nelse top.location=\'/doodles/\';};})();</script><input value="AOEireoAAAAAZCxgiKrJ4IiLbY2hE9Y2Qo-kO38aG4bO" name="iflsig" type="hidden"></span></span></td><td class="fl sblc" align="left" nowrap="" width="25%"><a href="/advanced_search?hl=en-CA&amp;authuser=0">Advanced search</a></td></tr></table><input id="gbv" name="gbv" type="hidden" value="1"><script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){var a,b="1";if(document&&document.getElementById)if("undefined"!=typeof XMLHttpRequest)b="2";else if("undefined"!=typeof ActiveXObject){var c,d,e=["MSXML2.XMLHTTP.6.0","MSXML2.XMLHTT'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 12 server_application_data [1400 bytes]:
17 03 03 05 73 80 87 fe 7a 2e 27 bb 60 aa 81 59
14 ea a3 55 a3 81 39 96 ac 56 b4 3a 24 [...]
  - TLS record 12 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b"\x80\x87\xfez.'\xbb`\xaa\x81Y\x14\xea\xa3U\xa3"... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
80 87 fe 7a 2e 27 bb 60 aa 81 59 14 ea a3 55 a3
81 39 96 ac 56 b4 3a 24 df 2a d8 ef b3 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c9
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 8'
  - Inner TLS message 12 server_application_data_(decrypted) [1379 bytes]:
50 2e 33 2e 30 22 2c 22 4d 53 58 4d 4c 32 2e 58
4d 4c 48 54 54 50 22 2c 22 4d 69 63 72 [...]
  - Inner TLS message 12 server_application_data_(decrypted): Container: 
    content = b'P.3.0","MSXML2.X'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 12 server_application_data [1378 bytes]:
50 2e 33 2e 30 22 2c 22 4d 53 58 4d 4c 32 2e 58
4d 4c 48 54 54 50 22 2c 22 4d 69 63 72 [...]
  - TLS message 12 server_application_data [1378 bytes]: b'P.3.0","MSXML2.XMLHTTP","Microsoft.XMLHTTP"];for(c=0;d=e[c++];)try{new ActiveXObject(d),b="2"}catch(h){}}a=b;if("2"==a&&-1==location.search.indexOf("&gbv=2")){var f=google.gbvu,g=document.getElementById("gbv");g&&(g.value=a);f&&window.setTimeout(function(){location.href=f},0)};}).call(this);</script></form><div id="gac_scont"></div><div style="font-size:83%;min-height:3.5em"><br><div id="prm"><style>.szppmdbYutt__middle-slot-promo{font-size:small;margin-bottom:32px}.szppmdbYutt__middle-slot-promo a.ZIeIlb{display:inline-block;text-decoration:none}.szppmdbYutt__middle-slot-promo img{border:none;margin-right:5px;vertical-align:middle}</style><div class="szppmdbYutt__middle-slot-promo" data-ved="0ahUKEwjdhqDr1JD-AhVLFzQIHfqNBbkQnIcBCAQ"><a class="NKcBbd" href="https://www.google.com/url?q=https://blog.google/products/search/google-search-new-fact-checking-misinformation/&amp;source=hpp&amp;id=19034203&amp;ct=3&amp;usg=AOvVaw3UxG35a-5UX1Rl8M_VwPbd&amp;sa=X&amp;ved=0ahUKEwjdhqDr1JD-AhVLFzQIHfqNBbkQ8IcBCAU" rel="nofollow">Helpful tips to fact check information online</a></div></div><div id="gws-output-pages-elements-homepage_additional_languages__als"><style>#gws-output-pages-elements-homepage_additional_languages__als{font-size:small;margin-bottom:24px}#SIvCob{color:#3c4043;display:inline-block;line-height:28px;}#SIvCob a{padding:0 3px;}.H6sW5{display:inline-bl'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 13 server_application_data [1400 bytes]:
17 03 03 05 73 6f 99 3e c5 a3 ac 59 a0 39 b5 8e
f3 1f a0 ec 8b d2 e2 fa 9b 79 70 c7 40 [...]
  - TLS record 13 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'o\x99>\xc5\xa3\xacY\xa09\xb5\x8e\xf3\x1f\xa0\xec\x8b'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
6f 99 3e c5 a3 ac 59 a0 39 b5 8e f3 1f a0 ec 8b
d2 e2 fa 9b 79 70 c7 40 5e d9 d3 53 5b [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c8
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 9'
  - Inner TLS message 13 server_application_data_(decrypted) [1379 bytes]:
6f 63 6b 3b 6d 61 72 67 69 6e 3a 30 20 32 70 78
3b 77 68 69 74 65 2d 73 70 61 63 65 3a [...]
  - Inner TLS message 13 server_application_data_(decrypted): Container: 
    content = b'ock;margin:0 2px'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 13 server_application_data [1378 bytes]:
6f 63 6b 3b 6d 61 72 67 69 6e 3a 30 20 32 70 78
3b 77 68 69 74 65 2d 73 70 61 63 65 3a [...]
  - TLS message 13 server_application_data [1378 bytes]: b'ock;margin:0 2px;white-space:nowrap}.z4hgWe{display:inline-block;margin:0 2px}</style><div id="SIvCob">Google offered in:  <a href="https://www.google.com/setprefs?sig=0_KNct30qZGFHnNmuchgcZvCc0e6c%3D&amp;hl=fr&amp;source=homepage&amp;sa=X&amp;ved=0ahUKEwjdhqDr1JD-AhVLFzQIHfqNBbkQ2ZgBCAc">Fran\xe7ais</a>  </div></div></div><span id="footer"><div style="font-size:10pt"><div style="margin:19px auto;text-align:center" id="WqQANb"><a href="/intl/en/ads/">Advertising</a><a href="/services/">Business Solutions</a><a href="/intl/en/about.html">About Google</a><a href="https://www.google.com/setprefdomain?prefdom=CA&amp;prev=https://www.google.ca/&amp;sig=K_fKWqcXdJGJWOqaTJBIA5wK65TVc%3D">Google.ca</a></div></div><p style="font-size:8pt;color:#70757a">&copy; 2023 - <a href="/intl/en/policies/privacy/">Privacy</a> - <a href="/intl/en/policies/terms/">Terms</a></p></span></center><script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){window.google.cdo={height:757,width:1440};(function(){var a=window.innerWidth,b=window.innerHeight;if(!a||!b){var c=window.document,d="CSS1Compat"==c.compatMode?c.documentElement:c.body;a=d.clientWidth;b=d.clientHeight}a&&b&&(a!=google.cdo.width||b!=google.cdo.height)&&google.log("","","/client_204?&atyp=i&biw="+a+"&bih="+b+"&ei="+google.kEI);}).call(this);})();</script> <script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){google.xjs={ck:\'xjs.hp'
:: application_data received


:: Receiving new plain text fragment
  - TLS record 14 server_application_data [1400 bytes]:
17 03 03 05 73 e0 c1 55 03 db 3d 85 bf e3 31 b5
31 63 ad cc ea 3e 5b 74 b4 eb ca ee 70 [...]
  - TLS record 14 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xe0\xc1U\x03\xdb=\x85\xbf\xe31\xb51c\xad\xcc\xea'... (truncated, total 1395)
  - fragment (encrypted) [1395 bytes]:
e0 c1 55 03 db 3d 85 bf e3 31 b5 31 63 ad cc ea
3e 5b 74 b4 eb ca ee 70 d7 0d 50 c6 39 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 cb
  - additional_data [5 bytes]:
17 03 03 05 73
'  - sequence_number: 10'
  - Inner TLS message 14 server_application_data_(decrypted) [1379 bytes]:
2e 37 4f 4b 30 5a 6b 31 65 31 56 59 2e 4c 2e 58
2e 4f 27 2c 63 73 3a 27 41 43 54 39 30 [...]
  - Inner TLS message 14 server_application_data_(decrypted): Container: 
    content = b'.7OK0Zk1e1VY.L.X'... (truncated, total 1378)
    type = (enum) application_data 23
    zeros = None
  - TLS message 14 server_application_data [1378 bytes]:
2e 37 4f 4b 30 5a 6b 31 65 31 56 59 2e 4c 2e 58
2e 4f 27 2c 63 73 3a 27 41 43 54 39 30 [...]
  - TLS message 14 server_application_data [1378 bytes]: b'.7OK0Zk1e1VY.L.X.O\',cs:\'ACT90oG3Kg0PTfoNYK9MskypumscD_JjWQ\',excm:[]};})();</script>  <script nonce="q0yFkpqJIaIXSgDGLkwpWQ">(function(){var u=\'/xjs/_/js/k\\x3dxjs.hp.en.c8Y5Z0nJNyE.O/am\\x3dAAAAdAIAKACw/d\\x3d1/ed\\x3d1/rs\\x3dACT90oHFQ7EvjWWPBTWpfHye_KR8s4v6TQ/m\\x3dsb_he,d\';var amd=0;\nvar e=this||self,g=function(c){return c};var k;var n=function(c,f){this.g=f===l?c:""};n.prototype.toString=function(){return this.g+""};var l={};\nfunction p(){var c=u,f=function(){};google.lx=google.stvsc?f:function(){google.timers&&google.timers.load&&google.tick&&google.tick("load","xjsls");var a=document;var b="SCRIPT";"application/xhtml+xml"===a.contentType&&(b=b.toLowerCase());b=a.createElement(b);b.id="base-js";a=null===c?"null":void 0===c?"undefined":c;if(void 0===k){var d=null;var m=e.trustedTypes;if(m&&m.createPolicy){try{d=m.createPolicy("goog#html",{createHTML:g,createScript:g,createScriptURL:g})}catch(r){e.console&&e.console.error(r.message)}k=\nd}else k=d}a=(d=k)?d.createScriptURL(a):a;a=new n(a,l);b.src=a instanceof n&&a.constructor===n?a.g:"type_error:TrustedResourceUrl";var h,q;(h=(a=null==(q=(h=(b.ownerDocument&&b.ownerDocument.defaultView||window).document).querySelector)?void 0:q.call(h,"script[nonce]"))?a.nonce||a.getAttribute("nonce")||"":"")&&b.setAttribute("nonce",h);document.body.appendChild(b);google.psa=!0;google.lx=f};google.bx||google.lx()};google.xjsu='
:: application_data received


:: Receiving new plain text fragment
  - TLS record 15 server_application_data [1014 bytes]:
17 03 03 03 f1 11 65 fd f2 d0 91 86 5c 7e c8 91
92 2c 8f 78 fa e0 a5 39 97 63 fb 0c 0e [...]
  - TLS record 15 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\x11e\xfd\xf2\xd0\x91\x86\\~\xc8\x91\x92,\x8fx\xfa'... (truncated, total 1009)
  - fragment (encrypted) [1009 bytes]:
11 65 fd f2 d0 91 86 5c 7e c8 91 92 2c 8f 78 fa
e0 a5 39 97 63 fb 0c 0e 8a 45 e6 74 a2 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 ca
  - additional_data [5 bytes]:
17 03 03 03 f1
'  - sequence_number: 11'
  - Inner TLS message 15 server_application_data_(decrypted) [993 bytes]:
75 3b 73 65 74 54 69 6d 65 6f 75 74 28 66 75 6e
63 74 69 6f 6e 28 29 7b 30 3c 61 6d 64 [...]
  - Inner TLS message 15 server_application_data_(decrypted): Container: 
    content = b'u;setTimeout(fun'... (truncated, total 992)
    type = (enum) application_data 23
    zeros = None
  - TLS message 15 server_application_data [992 bytes]:
75 3b 73 65 74 54 69 6d 65 6f 75 74 28 66 75 6e
63 74 69 6f 6e 28 29 7b 30 3c 61 6d 64 [...]
  - TLS message 15 server_application_data [992 bytes]: b"u;setTimeout(function(){0<amd?google.caft(function(){return p()},amd):p()},0);})();window._ = window._ || {};window._DumpException = _._DumpException = function(e){throw e;};window._s = window._s || {};_s._DumpException = _._DumpException;window._qs = window._qs || {};_qs._DumpException = _._DumpException;function _F_installCss(c){}\n(function(){google.jl={blt:'none',chnk:0,dw:false,dwu:true,emtn:0,end:0,ico:false,ikb:0,ine:false,injs:'none',injt:0,injth:0,injv2:false,lls:'default',pdt:0,rep:0,snet:true,strt:0,ubm:false,uwp:true};})();(function(){var pmc='{\\x22d\\x22:{},\\x22sb_he\\x22:{\\x22agen\\x22:true,\\x22cgen\\x22:true,\\x22client\\x22:\\x22heirloom-hp\\x22,\\x22dh\\x22:true,\\x22ds\\x22:\\x22\\x22,\\x22fl\\x22:true,\\x22host\\x22:\\x22google.com\\x22,\\x22jsonp\\x22:true,\\x22msgs\\x22:{\\x22cibl\\x22:\\x22Clear Search\\x22,\\x22dym\\x22:\\x22Did you mean:\\x22,\\x22lcky\\x22:\\x22I\\\\u0026#39;m Feeling Lucky\\x22,\\x22lml\\x22:\\x22Learn more\\x22,\\x22psrc\\x22:\\x22This search was removed from your \\\\u003Ca href\r\n"
:: application_data received


:: Receiving new plain text fragment
  - TLS record 16 server_application_data [433 bytes]:
17 03 03 01 ac b7 88 37 6b 63 5f 87 31 07 63 60
76 2c de f7 f6 a0 3e b6 8b b7 79 b1 87 [...]
  - TLS record 16 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xb7\x887kc_\x871\x07c`v,\xde\xf7\xf6'... (truncated, total 428)
  - fragment (encrypted) [428 bytes]:
b7 88 37 6b 63 5f 87 31 07 63 60 76 2c de f7 f6
a0 3e b6 8b b7 79 b1 87 5d 23 3b b9 87 [...]
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 cd
  - additional_data [5 bytes]:
17 03 03 01 ac
'  - sequence_number: 12'
  - Inner TLS message 16 server_application_data_(decrypted) [412 bytes]:
31 39 34 0d 0a 5c 78 33 64 5c 5c 5c 78 32 32 2f
68 69 73 74 6f 72 79 5c 5c 5c 78 32 32 [...]
  - Inner TLS message 16 server_application_data_(decrypted): Container: 
    content = b'194\r\n\\x3d\\\\\\x22/'... (truncated, total 411)
    type = (enum) application_data 23
    zeros = None
  - TLS message 16 server_application_data [411 bytes]:
31 39 34 0d 0a 5c 78 33 64 5c 5c 5c 78 32 32 2f
68 69 73 74 6f 72 79 5c 5c 5c 78 32 32 [...]
  - TLS message 16 server_application_data [411 bytes]: b"194\r\n\\x3d\\\\\\x22/history\\\\\\x22\\\\u003EWeb History\\\\u003C/a\\\\u003E\\x22,\\x22psrl\\x22:\\x22Remove\\x22,\\x22sbit\\x22:\\x22Search by image\\x22,\\x22srch\\x22:\\x22Google Search\\x22},\\x22ovr\\x22:{},\\x22pq\\x22:\\x22\\x22,\\x22rfs\\x22:[],\\x22sbas\\x22:\\x220 3px 8px 0 rgba(0,0,0,0.2),0 0 0 1px rgba(0,0,0,0.08)\\x22,\\x22stok\\x22:\\x22weYZ43T9PfLBLwRS1j-1Ys34-jA\\x22}}';google.pmc=JSON.parse(pmc);})();</script>       </body></html>\r\n"
:: application_data received


:: Receiving new plain text fragment
  - TLS record 17 server_application_data [27 bytes]:
17 03 03 00 16 f8 ee 62 07 bd cb c2 e3 46 0d 4b
ae 53 3f d8 aa ee c5 b6 cb 24 b7
  - TLS record 17 server_application_data: Container: 
    type = (enum) application_data 23
    legacy_record_version = b'\x03\x03' (total 2)
    fragment = b'\xf8\xeeb\x07\xbd\xcb\xc2\xe3F\rK\xaeS?\xd8\xaa'... (truncated, total 22)
  - fragment (encrypted) [22 bytes]:
f8 ee 62 07 bd cb c2 e3 46 0d 4b ae 53 3f d8 aa
ee c5 b6 cb 24 b7
  - write_key [16 bytes]:
c3 7f c1 2c d9 0b 62 83 c0 4f 34 c5 be ac 8a 3d
  - write_iv [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 c1
  - nonce [12 bytes]:
fa ac a8 6a d2 9d 7f d9 9f cc f2 cc
  - additional_data [5 bytes]:
17 03 03 00 16
'  - sequence_number: 13'
  - Inner TLS message 17 server_application_data_(decrypted) [6 bytes]:
30 0d 0a 0d 0a 17
  - Inner TLS message 17 server_application_data_(decrypted): Container: 
    content = b'0\r\n\r\n' (total 5)
    type = (enum) application_data 23
    zeros = None
  - TLS message 17 server_application_data [5 bytes]:
30 0d 0a 0d 0a
  - TLS message 17 server_application_data [5 bytes]: b'0\r\n\r\n'
:: application_data received

APPLICATION DATA - [psk]: b'HTTP/1.1 200 OK\r\nDate: Tue, 04 Apr 2023 16:38:16 GMT\r\nExpires: -1\r\nCache-Control: private, max-age=0\r\nContent-Type: text/html; charset=ISO-8859-1\r\nContent-Security-Policy-Report-Only: object-src \'none\';base-uri \'self\';script-src \'nonce-q0yFkpqJIaIXSgDGLkwpWQ\' \'strict-dynamic\' \'report-sample\' \'unsafe-eval\' \'unsafe-inline\' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp\r\nP3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."\r\nServer: gws\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nSet-Cookie: 1P_JAR=2023-04-04-16; expires=Thu, 04-May-2023 16:38:16 GMT; path=/; domain=.google.com; Secure\r\nSet-Cookie: AEC=AUEFqZeTXcWiBGazgK7YCmgHtZhy00Ouqbyb-6Vh_mwB6dypkWzFaIyy6hc; expires=Sun, 01-Oct-2023 16:38:16 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax\r\nSet-Cookie: NID=511=tBUu6pHTctk5Bc4eOevG1pwYD89EObffJU44xYciRZOgTBveZ1pbhW2S3WtQZxuCZdq5ixRmANmrcUxiasKisGYHpzS4YsJYKHn9Oji5yt8lq28Cy7F0ap6n_rKVp5TmwUG3O_z2LNP2msx2uE3dJNx1oxoboqfbtOgQ1gSYzdQ; expires=Wed, 04-Oct-2023 16:38:16 GMT; path=/; domain=.google.com; HttpOnly\r\nAlt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Accept-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n3a54\r\n<!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="en-CA"><head>
[...]
</head><body bgcolor="#fff">
[...]
</body></html>\r\n0\r\n\r\n'

```
