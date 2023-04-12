# Welcome to pytls13 !

`pytls13` implements a TLS 1.3 client and relies on `pylurk` for all cryptographic operations related to the client authentication. 
 
`pytl13` can be used as follows:
 
```
$ cd examples/cli/
$ ./tls_client --connectivity 'lib_cs' https://www.google.com
```

`pytls13` leverages the Limited Use of Remote Keys (LURK) framework as well as it extension for TLS 1.3. [draft-mglt-lurk-lurk](https://datatracker.ietf.org/doc/draft-mglt-lurk-lurk/) [draft-mglt-lurk-tls13](https://datatracker.ietf.org/doc/draft-mglt-lurk-tls13/).
LURK is a generic protocol whose purpose is to support specific interactions with a given cryptographic material, which is also known as Cryptographic Service (CS). In our case `pytls13` implements the TLS Engine (E) while `pylurk` implements the CS as depicted below:

```
+----------------------------+
|       TLS Engine (E)       |
+------------^---------------+
             | (LURK/TLS 1.3)
+------------v---------------+
| Cryptographic Service (CS) |
| private_keys               |
+----------------------------+

TLS being split into a CS and an Engine
```

[pytls13 documentation](https://pytls13.readthedocs.io/en/latest/) provides **Examples of TLS 1.3 client** and  **Using `pytls13` and `pylurk`** sections with detailed examples on how to combine the TLS engine (E) and the Crypto Service (CS) with.  The **LURK-T TLS 1.3 client** section providing a complete example where the CS runs into a Trusted Execution Enclave (TEE) - SGX in our case. 

## Installation

Currently the cli scripts are not installed via pip3 package, so one need to install it manually from the git repo.

The simple installation is as follows:
1. Install `pytls13` and `pylurk` from the git repo.
  ```
   `git clone https://github.com/mglt/pytls13.git`
   `git clone https://github.com/mglt/pylurk.git tls13`. Note that for a very limited usage pip3 pylurk maybe sufficient. 
3. Update in `tls_client`, in pytls13.git/example/cli`
  * `CS_GRAMINE_DIR`: the location of the `pylurk.git/example/cli` directory
  * `GRAMINE_DIR` the directory of the Gramine directory
  * The path of the `pylurk` and `pytls13` modules indicated by the `sys.path.insert` directive.

For a more advamce usage - that is the CS please follow the `pylurk` installation steps.

For a more advance us involving to use of TEE please install Gramine.

## TODO:

* Include the cli in the pip3 package.
* Implement a tls server
  * Re-organize classes and move TLS generic classes from tls_client_handler to tls_hanlder. 
* Implement the post handshake authentication as well as 0-rtt
* Provide more standard TLS client API / server.  
