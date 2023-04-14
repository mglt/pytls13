
.. code-block::

   cd pytls13/example/cli
   ./tls_client https://127.0.0.1:8403 --cert ~/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --connectivity tcp --host 127.0.0.1 --port 9401 --reconnect --debug > log.log

    --- Executing: /home/mglt/gitlab/pytls13/example/cli/./tls_client with Namespace(connectivity="'tcp'", host="'127.0.0.1'", port=9401, sig_scheme="'ed25519'", key=None, cert=PosixPath('/home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der'), debug=True, test_vector_mode=None, test_vector_file=None, gramine_sgx=False, gramine_direct=False, gramine_build=False, secret_provisioning=False, ra_type="'None'", ra_spid="'None'", ra_linkable="'None'", gramine_dir="'None'", url="'https://127.0.0.1:8403'", no_session_resumption=False, freshness="'sha256'", ephemeral_method="'cs_generated'", supported_ecdhe_groups="'x25519'", reconnect=True, cs_auto_start=False, cs_gramine_sgx=False, cs_gramine_direct=False, cs_gramine_build=False)
   args.key: None
   args.cert: /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der
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
                                                           b'ypto'
                                                           b'grap'
                                                           b'hy.i'
                                                           b'o0\x1e\x17'
                                                           b'\r230'
                                                           b'3232'
                                                           b'0151'
                                                           b'4Z\x17\r'
                                                           b'2304'
                                                           b'2320'
                                                           b'1514'
                                                           b'Z0\x1a1'
                                                           b'\x180\x16\x06'
                                                           b'\x03U\x04\x03'
                                                           b'\x0c\x0fcr'
                                                           b'ypto'
                                                           b'grap'
                                                           b'hy.i'
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
                                                           b'ypto'
                                                           b'grap'
                                                           b'hy.i'
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
                                                           b'\rH\xdd|'
                                                           b'\xc5rkd'
                                                           b'\x8f\t',
                                                   'extensions': []}],
                             '_finger_print_entry_list': [{'finger_print': b'Y3{\xe1',
                                                           'extensions': []}],
                             '_finger_print_dict': {b'Y3{\xe1': b'0\x82\x01.'
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
                                                                b'ypto'
                                                                b'grap'
                                                                b'hy.i'
                                                                b'o0\x1e\x17'
                                                                b'\r230'
                                                                b'3232'
                                                                b'0151'
                                                                b'4Z\x17\r'
                                                                b'2304'
                                                                b'2320'
                                                                b'1514'
                                                                b'Z0\x1a1'
                                                                b'\x180\x16\x06'
                                                                b'\x03U\x04\x03'
                                                                b'\x0c\x0fcr'
                                                                b'ypto'
                                                                b'grap'
                                                                b'hy.i'
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
                                                                b'ypto'
                                                                b'grap'
                                                                b'hy.i'
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
                                                                b'\rH\xdd|'
                                                                b'\xc5rkd'
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
   12 4c 9e ba 0b df f6 62 3a 2d 73 ce 00 6d 9a 0f
   a2 c7 c3 3f 98 d3 98 4b 26 0f f3 20 85 2d 0c 1b
   00 8d c9 af d1 8d ca de f9 88 8d c0 43 64 72 dc
   94 5d d7 b9 ad 60 36 6b 3c 62 6f 9c 00 04 13 01
   13 03 01 00 00 5b 00 2b 00 03 02 03 04 00 0d 00
   1e 00 1c 04 01 05 01 06 01 04 03 05 03 06 03 08
   04 08 05 08 09 08 0a 08 09 08 07 08 08 02 01 00
   0a 00 04 00 02 00 1d 00 33 00 26 00 24 00 1d 00
   20 41 07 b7 9a ba 03 ef f4 45 72 dd 3f 2f 8a b5
   ad d6 5f 66 dd e3 f6 64 d0 7e e8 0e ce d1 42 02
   54
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
   6d 75 9d c0 36 37 17 d6 ac b8 f9 4e 8f f1 3a 6f
   49 e3 80 06 d1 3c b0 83 14 c8 0f 20 85 2d 0c 1b
   00 8d c9 af d1 8d ca de f9 88 8d c0 43 64 72 dc
   94 5d d7 b9 ad 60 36 6b 3c 62 6f 9c 13 01 00 00
   2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 ac
   9f e5 17 02 db 80 d1 fe d7 86 11 80 96 7f 0a 89
   60 91 bf 8b 4e 80 66 0b ea b1 f5 61 cc 96 0e
     - TLS record 1 server_fragment_bytes: Container: 
       type = (enum) handshake 22
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'\x02\x00\x00v\x03\x03\x8eCR\xf1\xccmu\x9d\xc06'... (truncated, total 122)
     - handshake_message: [122 bytes]:
   02 00 00 76 03 03 8e 43 52 f1 cc 6d 75 9d c0 36
   37 17 d6 ac b8 f9 4e 8f f1 3a 6f 49 e3 80 06 d1
   3c b0 83 14 c8 0f 20 85 2d 0c 1b 00 8d c9 af d1
   8d ca de f9 88 8d c0 43 64 72 dc 94 5d d7 b9 ad
   60 36 6b 3c 62 6f 9c 13 01 00 00 2e 00 2b 00 02
   03 04 00 33 00 24 00 1d 00 20 ac 9f e5 17 02 db
   80 d1 fe d7 86 11 80 96 7f 0a 89 60 91 bf 8b 4e
   80 66 0b ea b1 f5 61 cc 96 0e
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
   37 17 d6 ac b8 f9 4e 8f f1 3a 6f 49 e3 80 06 d1
   3c b0 83 14 c8 0f 20 85 2d 0c 1b 00 8d c9 af d1
   8d ca de f9 88 8d c0 43 64 72 dc 94 5d d7 b9 ad
   60 36 6b 3c 62 6f 9c 13 01 00 00 2e 00 2b 00 02
   03 04 00 33 00 24 00 1d 00 20 ac 9f e5 17 02 db
   80 d1 fe d7 86 11 80 96 7f 0a 89 60 91 bf 8b 4e
   80 66 0b ea b1 f5 61 cc 96 0e
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
   75 3e 59 d8 5e 34 f0 eb fe 07 1f 0a c7 2a f9 2e
   1c 30 a4 25 8c 33 9e 01 29 f2 ae e2 dd 69 b3 6c
   55 b1 04 00 93 49 1f 91 72 f3 95 99 3b 34 c4 68
   60 9d 67 4d 2c a1 a9 3a 00 de f6 f7 06 da 92 22
   1c 2b 34 a7 1c c0 4c f4 dc 8b 94 fc 3a f5 31 2d
   28 6e 3e 94 90 91 55 1b ed be 52 31 ee 29 6e db
   54 95 33 fa 96 3a 8c cf 9a 47 24 dc a8 b4 ec a8
   54 41 a7 87 60 d6 36 31 44 d9 f5 7d da 6e fb 77
   80 ca 32 53 51 b9 8d 24 e8 59 1e fb 16 54 ca 41
   7c f6 e5 54 09 40 54 4f e4 6d 18 23
     - TLS record 4 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'\xd1@\xbc\xf3\xbcJ\xb7\xcd\x80\x12\x9au>Y\xd8^'... (truncated, total 167)
     - fragment (encrypted) [167 bytes]:
   d1 40 bc f3 bc 4a b7 cd 80 12 9a 75 3e 59 d8 5e
   34 f0 eb fe 07 1f 0a c7 2a f9 2e 1c 30 a4 25 8c
   33 9e 01 29 f2 ae e2 dd 69 b3 6c 55 b1 04 00 93
   49 1f 91 72 f3 95 99 3b 34 c4 68 60 9d 67 4d 2c
   a1 a9 3a 00 de f6 f7 06 da 92 22 1c 2b 34 a7 1c
   c0 4c f4 dc 8b 94 fc 3a f5 31 2d 28 6e 3e 94 90
   91 55 1b ed be 52 31 ee 29 6e db 54 95 33 fa 96
   3a 8c cf 9a 47 24 dc a8 b4 ec a8 54 41 a7 87 60
   d6 36 31 44 d9 f5 7d da 6e fb 77 80 ca 32 53 51
   b9 8d 24 e8 59 1e fb 16 54 ca 41 7c f6 e5 54 09
   40 54 4f e4 6d 18 23
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
   03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08
   05 08 06 04 01 05 01 06 01 03 03 03 01 00 2f 00
   65 00 63 00 61 30 5f 31 0b 30 09 06 03 55 04 06
   13 02 43 41 31 0f 30 0d 06 03 55 04 08 0c 06 51
   75 65 62 65 63 31 11 30 0f 06 03 55 04 07 0c 08
   4d 6f 6e 74 72 65 61 6c 31 0f 30 0d 06 03 55 04
   0a 0c 06 43 6c 69 65 6e 74 31 1b 30 19 06 03 55
   04 03 0c 12 63 6c 69 65 6e 74 2e 65 78 61 6d 70
   6c 65 2e 63 6f 6d 16
     - Inner TLS message 4 server_fragment_bytes_(decrypted): Container: 
       content = b'\r\x00\x00\x92\x00\x00\x8f\x00\r\x00"\x00 \x04\x03\x05'... (truncated, total 150)
       type = (enum) handshake 22
       zeros = None
     - handshake_message: [150 bytes]:
   0d 00 00 92 00 00 8f 00 0d 00 22 00 20 04 03 05
   03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08
   05 08 06 04 01 05 01 06 01 03 03 03 01 00 2f 00
   65 00 63 00 61 30 5f 31 0b 30 09 06 03 55 04 06
   13 02 43 41 31 0f 30 0d 06 03 55 04 08 0c 06 51
   75 65 62 65 63 31 11 30 0f 06 03 55 04 07 0c 08
   4d 6f 6e 74 72 65 61 6c 31 0f 30 0d 06 03 55 04
   0a 0c 06 43 6c 69 65 6e 74 31 1b 30 19 06 03 55
   04 03 0c 12 63 6c 69 65 6e 74 2e 65 78 61 6d 70
   6c 65 2e 63 6f 6d
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
   03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08
   05 08 06 04 01 05 01 06 01 03 03 03 01 00 2f 00
   65 00 63 00 61 30 5f 31 0b 30 09 06 03 55 04 06
   13 02 43 41 31 0f 30 0d 06 03 55 04 08 0c 06 51
   75 65 62 65 63 31 11 30 0f 06 03 55 04 07 0c 08
   4d 6f 6e 74 72 65 61 6c 31 0f 30 0d 06 03 55 04
   0a 0c 06 43 6c 69 65 6e 74 31 1b 30 19 06 03 55
   04 03 0c 12 63 6c 69 65 6e 74 2e 65 78 61 6d 70
   6c 65 2e 63 6f 6d
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
   03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08
   05 08 06 04 01 05 01 06 01 03 03 03 01 00 2f 00
   65 00 63 00 61 30 5f 31 0b 30 09 06 03 55 04 06
   13 02 43 41 31 0f 30 0d 06 03 55 04 08 0c 06 51
   75 65 62 65 63 31 11 30 0f 06 03 55 04 07 0c 08
   4d 6f 6e 74 72 65 61 6c 31 0f 30 0d 06 03 55 04
   0a 0c 06 43 6c 69 65 6e 74 31 1b 30 19 06 03 55
   04 03 0c 12 63 6c 69 65 6e 74 2e 65 78 61 6d 70
   6c 65 2e 63 6f 6d

   :: Receiving new plain text fragment
     - TLS record 5 server_application_data [862 bytes]:
   17 03 03 03 59 70 4d d1 07 d1 12 36 26 5f 53 70
   ee 63 eb 80 36 2d 79 d7 0e c7 ad 1c 75 cb 9f 08
   40 f9 53 b1 71 c5 f7 44 a8 a6 83 15 d0 58 65 eb
   6f ff 03 f7 f1 0a 14 5f a0 52 a1 1f 41 17 b5 87
   f4 5d a2 48 ab 66 fa fa ff 9c 72 8d e2 44 fd 12
   72 57 1f e8 d1 91 6b 9d df eb 17 59 b6 51 0a ce
   19 01 c6 d2 b8 bf 65 8d 97 59 d0 7c c5 23 3d 6a
   54 a4 a0 ec 07 85 5b f0 56 fc 41 09 b9 9a 09 f4
   73 1c 69 26 59 10 b2 ab a6 e4 c4 73 68 fa 6f 1a
   4d e0 1c 6a 53 3b 89 54 98 cb d3 19 39 5c 36 bb
   93 e2 59 11 7b 88 3c 8f ba a5 f3 47 6c a6 95 e7
   7c 84 84 3e 7e a2 99 18 60 99 b2 b2 df 15 cf 50
   a2 4f c2 a9 45 81 b1 e9 09 fc 95 3c 6f 2c 06 62
   8a 18 10 c8 a3 2d 64 9d 14 45 a1 14 7a ef 96 40
   3f c5 19 26 b5 a5 a5 f6 4d 16 99 0b 6a 4f 58 31
   f8 d0 b4 b0 ec 6b d2 a0 71 10 bd 31 50 bc 11 d1
   c1 d6 8b 99 c6 f6 de 28 69 14 23 e3 0d 96 ae ce
   d3 77 38 5e 3a 42 30 f4 aa a5 cc ea fb 36 2d 68
   16 b1 05 c6 97 d1 4f 3c 32 ff b0 38 6b 6d 2c e1
   fa 54 de 8b 92 64 3f 8c 1a b2 db d1 b7 26 d7 04
   d3 b7 45 0f ff 96 78 96 19 d2 50 70 d4 b9 6c a9
   a9 23 06 d1 bd 41 74 b1 ad 78 ae e7 b5 4d 78 7a
   0b 76 1a b5 d7 ba 77 0c 1e 87 83 6d e4 5b 79 5d
   a0 a5 3f ad 31 8c 02 be dd c0 1f a5 8f 9b 97 dc
   f7 e9 12 78 74 61 39 bd 32 c1 a9 11 d6 82 5c 4d
   34 a9 2e a0 42 d6 bb c5 b1 da 3e 9b d8 ab 99 54
   ad bb bb 8c a2 d5 13 ce fe 8c 50 f6 8c 40 9d a5
   f4 69 c9 46 09 da f4 b8 58 a8 83 9a 5b 26 3e 52
   92 e2 f3 f6 60 a5 4b ff 6a af 0e 12 1c 3c 88 87
   b8 48 6a 07 ba fe 8d b3 1f 04 df 70 85 6d 31 b3
   65 25 43 6f 4a 03 ba be 1b 70 b1 dd 1c 16 71 dd
   16 8e 7f ff 56 e7 e0 77 5b 7a d6 00 00 48 5f af
   08 4b 05 39 1b 48 0b c7 e1 1f 9e da 75 fd 0a 22
   8a 7c 07 41 5b 7b e7 25 5a 08 48 38 21 89 08 28
   ec ad 36 ad 0a 51 b9 7e 6e 98 9f 17 08 cd b5 aa
   71 2a a8 1f c4 0d 60 33 59 ed 8b 54 17 bc 56 db
   62 7e 84 bb 3b d8 bb db 98 08 44 72 62 29 23 67
   84 d7 46 9e e4 4d aa cb 21 40 56 88 a7 e8 de 89
   9c 70 38 33 8a 29 01 a0 02 be ff ea 69 97 43 4d
   bb a8 eb 91 36 45 09 ea 49 63 67 b8 9e 43 4e 97
   39 15 1f 15 53 ec 31 25 11 ae 58 14 39 75 f4 9a
   d6 1b 53 c1 bd e1 13 5d 15 90 61 43 06 47 3f c0
   f2 f8 82 db 45 6f c2 e4 31 e7 53 70 6b 0e bb c4
   5f 8c 14 54 ef 14 67 18 0f 8c 96 89 1b 87 d2 c1
   bd 6a 04 dd 84 d9 89 61 04 72 a2 9d fc 69 11 45
   22 a7 db 0f 31 f9 29 b4 21 66 e2 43 b4 b1 d8 86
   e5 c5 46 0e a5 99 ec ce 9b 3e 2c cc 93 cc b0 1d
   1a db 39 ad 77 83 00 15 d5 be 5a c4 73 59 b8 88
   1c 2e 1d 9e f5 57 de 8c 56 e8 94 74 f7 49 db 2a
   dc 2e eb c9 ce 92 1d 43 17 de 70 9c 19 2d 6d 89
   e1 da 75 64 8b b7 4c db f2 f2 51 70 1f 60 5e 31
   66 a9 89 b1 af 30 4c 97 7f 93 46 6f b4 7a 68 c1
   3d fe 13 4f 27 23 2a 09 7d ac 8d 36 e5 ce c9 81
   79 25 3e 59 78 ff cf 3a 3c d8 67 59 54 23
     - TLS record 5 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'pM\xd1\x07\xd1\x126&_Sp\xeec\xeb\x806'... (truncated, total 857)
     - fragment (encrypted) [857 bytes]:
   70 4d d1 07 d1 12 36 26 5f 53 70 ee 63 eb 80 36
   2d 79 d7 0e c7 ad 1c 75 cb 9f 08 40 f9 53 b1 71
   c5 f7 44 a8 a6 83 15 d0 58 65 eb 6f ff 03 f7 f1
   0a 14 5f a0 52 a1 1f 41 17 b5 87 f4 5d a2 48 ab
   66 fa fa ff 9c 72 8d e2 44 fd 12 72 57 1f e8 d1
   91 6b 9d df eb 17 59 b6 51 0a ce 19 01 c6 d2 b8
   bf 65 8d 97 59 d0 7c c5 23 3d 6a 54 a4 a0 ec 07
   85 5b f0 56 fc 41 09 b9 9a 09 f4 73 1c 69 26 59
   10 b2 ab a6 e4 c4 73 68 fa 6f 1a 4d e0 1c 6a 53
   3b 89 54 98 cb d3 19 39 5c 36 bb 93 e2 59 11 7b
   88 3c 8f ba a5 f3 47 6c a6 95 e7 7c 84 84 3e 7e
   a2 99 18 60 99 b2 b2 df 15 cf 50 a2 4f c2 a9 45
   81 b1 e9 09 fc 95 3c 6f 2c 06 62 8a 18 10 c8 a3
   2d 64 9d 14 45 a1 14 7a ef 96 40 3f c5 19 26 b5
   a5 a5 f6 4d 16 99 0b 6a 4f 58 31 f8 d0 b4 b0 ec
   6b d2 a0 71 10 bd 31 50 bc 11 d1 c1 d6 8b 99 c6
   f6 de 28 69 14 23 e3 0d 96 ae ce d3 77 38 5e 3a
   42 30 f4 aa a5 cc ea fb 36 2d 68 16 b1 05 c6 97
   d1 4f 3c 32 ff b0 38 6b 6d 2c e1 fa 54 de 8b 92
   64 3f 8c 1a b2 db d1 b7 26 d7 04 d3 b7 45 0f ff
   96 78 96 19 d2 50 70 d4 b9 6c a9 a9 23 06 d1 bd
   41 74 b1 ad 78 ae e7 b5 4d 78 7a 0b 76 1a b5 d7
   ba 77 0c 1e 87 83 6d e4 5b 79 5d a0 a5 3f ad 31
   8c 02 be dd c0 1f a5 8f 9b 97 dc f7 e9 12 78 74
   61 39 bd 32 c1 a9 11 d6 82 5c 4d 34 a9 2e a0 42
   d6 bb c5 b1 da 3e 9b d8 ab 99 54 ad bb bb 8c a2
   d5 13 ce fe 8c 50 f6 8c 40 9d a5 f4 69 c9 46 09
   da f4 b8 58 a8 83 9a 5b 26 3e 52 92 e2 f3 f6 60
   a5 4b ff 6a af 0e 12 1c 3c 88 87 b8 48 6a 07 ba
   fe 8d b3 1f 04 df 70 85 6d 31 b3 65 25 43 6f 4a
   03 ba be 1b 70 b1 dd 1c 16 71 dd 16 8e 7f ff 56
   e7 e0 77 5b 7a d6 00 00 48 5f af 08 4b 05 39 1b
   48 0b c7 e1 1f 9e da 75 fd 0a 22 8a 7c 07 41 5b
   7b e7 25 5a 08 48 38 21 89 08 28 ec ad 36 ad 0a
   51 b9 7e 6e 98 9f 17 08 cd b5 aa 71 2a a8 1f c4
   0d 60 33 59 ed 8b 54 17 bc 56 db 62 7e 84 bb 3b
   d8 bb db 98 08 44 72 62 29 23 67 84 d7 46 9e e4
   4d aa cb 21 40 56 88 a7 e8 de 89 9c 70 38 33 8a
   29 01 a0 02 be ff ea 69 97 43 4d bb a8 eb 91 36
   45 09 ea 49 63 67 b8 9e 43 4e 97 39 15 1f 15 53
   ec 31 25 11 ae 58 14 39 75 f4 9a d6 1b 53 c1 bd
   e1 13 5d 15 90 61 43 06 47 3f c0 f2 f8 82 db 45
   6f c2 e4 31 e7 53 70 6b 0e bb c4 5f 8c 14 54 ef
   14 67 18 0f 8c 96 89 1b 87 d2 c1 bd 6a 04 dd 84
   d9 89 61 04 72 a2 9d fc 69 11 45 22 a7 db 0f 31
   f9 29 b4 21 66 e2 43 b4 b1 d8 86 e5 c5 46 0e a5
   99 ec ce 9b 3e 2c cc 93 cc b0 1d 1a db 39 ad 77
   83 00 15 d5 be 5a c4 73 59 b8 88 1c 2e 1d 9e f5
   57 de 8c 56 e8 94 74 f7 49 db 2a dc 2e eb c9 ce
   92 1d 43 17 de 70 9c 19 2d 6d 89 e1 da 75 64 8b
   b7 4c db f2 f2 51 70 1f 60 5e 31 66 a9 89 b1 af
   30 4c 97 7f 93 46 6f b4 7a 68 c1 3d fe 13 4f 27
   23 2a 09 7d ac 8d 36 e5 ce c9 81 79 25 3e 59 78
   ff cf 3a 3c d8 67 59 54 23
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
   82 02 1f 02 14 07 c8 5c f3 c2 19 85 9a 8c 62 12
   94 38 23 64 87 82 a3 4c aa 30 0d 06 09 2a 86 48
   86 f7 0d 01 01 0b 05 00 30 57 31 0b 30 09 06 03
   55 04 06 13 02 43 41 31 0f 30 0d 06 03 55 04 08
   0c 06 51 75 65 62 65 63 31 11 30 0f 06 03 55 04
   07 0c 08 4d 6f 6e 74 72 65 61 6c 31 0b 30 09 06
   03 55 04 0a 0c 02 43 41 31 17 30 15 06 03 55 04
   03 0c 0e 63 61 2e 65 78 61 6d 70 6c 65 2e 63 6f
   6d 30 1e 17 0d 32 32 30 35 30 36 31 37 32 31 33
   39 5a 17 0d 33 32 30 35 30 33 31 37 32 31 33 39
   5a 30 59 31 0b 30 09 06 03 55 04 06 13 02 43 41
   31 0f 30 0d 06 03 55 04 08 0c 06 51 75 65 62 65
   63 31 11 30 0f 06 03 55 04 07 0c 08 4d 6f 6e 74
   72 65 61 6c 31 10 30 0e 06 03 55 04 0a 0c 07 45
   78 61 6d 70 6c 65 31 14 30 12 06 03 55 04 03 0c
   0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 30 82 01 22
   30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03
   82 01 0f 00 30 82 01 0a 02 82 01 01 00 c7 2b c8
   3c f4 ba bf 78 47 a2 26 85 71 b3 fb 4a ea 4e 3d
   d0 5a 48 a2 54 ec c5 b5 be 8f 08 01 d8 f3 10 50
   80 57 62 44 55 57 f5 49 bd f7 2b 49 13 6f 9f f1
   da 99 aa bc 12 bb 56 f7 c4 10 01 ca 35 50 ae a1
   67 c5 3d 89 8d d6 32 19 55 0c 75 f1 45 ef 1a 38
   8d 96 0c 5d 89 c4 28 dd d9 20 a7 6f ae fa ba 36
   2d 52 16 a0 97 be 08 2d 7c b5 f4 4e 20 59 94 e3
   6e ba 55 a9 01 ba 4d f8 6d 36 d2 71 61 90 6a ef
   92 a3 06 67 81 91 d6 ba 02 fd b6 ae d9 a0 2e 38
   31 fe 56 1a 6d ab 67 fb 7d da 86 83 aa 1a d5 26
   f3 41 85 07 96 ac 86 d5 b4 89 d6 55 74 e4 0c f7
   d1 d5 74 34 63 9e a2 3c f6 3a 54 f6 cb 5c df 2c
   bc a0 81 81 28 0a bd f6 ec e6 aa 2d 2e ff 19 a0
   3b 68 fc bd 48 58 59 d1 b2 8f 5d fd ec 82 3b cb
   e8 40 f0 55 b8 4b 27 88 76 1c f4 d4 54 53 ae ba
   ac e1 71 09 d3 7b 56 29 3e 0e 69 1e f1 02 03 01
   00 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
   00 03 82 01 01 00 23 d2 a6 93 26 67 a4 63 11 42
   93 c3 40 ef b8 98 0c dc 7b 4a 67 86 31 dd 3d 17
   a5 b2 eb b7 a6 42 01 bf cf 01 d1 f1 d6 f0 e6 d9
   df 59 aa e6 7d 96 8b 9b 5b 15 19 b7 64 8d 06 1d
   e0 71 e5 b1 b4 6c bc 82 db 2e 08 79 a4 c8 15 41
   dd 21 dd fa 31 f4 ba c4 d9 c0 2d 00 f8 48 37 2a
   a7 3e 70 8b c5 8c 44 37 5c 03 ea 14 f5 ee 94 f8
   82 27 0d d9 d6 39 5c f9 0d a8 ff 19 cc 64 d7 81
   fa b7 2e 2f 01 a2 56 cc ce cc 66 68 e6 e5 c4 1a
   e4 83 8d e5 a6 09 d8 b9 17 dc 3a 85 2e 2d c6 38
   ce 73 da ee fa ad eb 8a 17 74 9e bc 48 ab 9c c0
   0b 86 97 ed 6a b6 09 49 f2 0a 6f 63 a5 f9 22 8d
   97 25 e1 6a c4 0b 0c e1 dd d5 a0 d1 aa a3 ef 63
   8f 69 38 c6 60 d0 ec 01 1c 00 10 01 f8 7c 00 78
   af 47 02 92 ab d8 3d 6c 18 df 3b ed 15 5c af 0b
   3d 40 bf 76 92 57 3b 17 6d 7b 0a b8 83 fe 52 c6
   50 56 e6 15 51 5c 00 00 16
     - Inner TLS message 5 server_fragment_bytes_(decrypted): Container: 
       content = b'\x0b\x00\x03D\x00\x00\x03@\x00\x03;0\x82\x0370'... (truncated, total 840)
       type = (enum) handshake 22
       zeros = None
     - handshake_message: [840 bytes]:
   0b 00 03 44 00 00 03 40 00 03 3b 30 82 03 37 30
   82 02 1f 02 14 07 c8 5c f3 c2 19 85 9a 8c 62 12
   94 38 23 64 87 82 a3 4c aa 30 0d 06 09 2a 86 48
   86 f7 0d 01 01 0b 05 00 30 57 31 0b 30 09 06 03
   55 04 06 13 02 43 41 31 0f 30 0d 06 03 55 04 08
   0c 06 51 75 65 62 65 63 31 11 30 0f 06 03 55 04
   07 0c 08 4d 6f 6e 74 72 65 61 6c 31 0b 30 09 06
   03 55 04 0a 0c 02 43 41 31 17 30 15 06 03 55 04
   03 0c 0e 63 61 2e 65 78 61 6d 70 6c 65 2e 63 6f
   6d 30 1e 17 0d 32 32 30 35 30 36 31 37 32 31 33
   39 5a 17 0d 33 32 30 35 30 33 31 37 32 31 33 39
   5a 30 59 31 0b 30 09 06 03 55 04 06 13 02 43 41
   31 0f 30 0d 06 03 55 04 08 0c 06 51 75 65 62 65
   63 31 11 30 0f 06 03 55 04 07 0c 08 4d 6f 6e 74
   72 65 61 6c 31 10 30 0e 06 03 55 04 0a 0c 07 45
   78 61 6d 70 6c 65 31 14 30 12 06 03 55 04 03 0c
   0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 30 82 01 22
   30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03
   82 01 0f 00 30 82 01 0a 02 82 01 01 00 c7 2b c8
   3c f4 ba bf 78 47 a2 26 85 71 b3 fb 4a ea 4e 3d
   d0 5a 48 a2 54 ec c5 b5 be 8f 08 01 d8 f3 10 50
   80 57 62 44 55 57 f5 49 bd f7 2b 49 13 6f 9f f1
   da 99 aa bc 12 bb 56 f7 c4 10 01 ca 35 50 ae a1
   67 c5 3d 89 8d d6 32 19 55 0c 75 f1 45 ef 1a 38
   8d 96 0c 5d 89 c4 28 dd d9 20 a7 6f ae fa ba 36
   2d 52 16 a0 97 be 08 2d 7c b5 f4 4e 20 59 94 e3
   6e ba 55 a9 01 ba 4d f8 6d 36 d2 71 61 90 6a ef
   92 a3 06 67 81 91 d6 ba 02 fd b6 ae d9 a0 2e 38
   31 fe 56 1a 6d ab 67 fb 7d da 86 83 aa 1a d5 26
   f3 41 85 07 96 ac 86 d5 b4 89 d6 55 74 e4 0c f7
   d1 d5 74 34 63 9e a2 3c f6 3a 54 f6 cb 5c df 2c
   bc a0 81 81 28 0a bd f6 ec e6 aa 2d 2e ff 19 a0
   3b 68 fc bd 48 58 59 d1 b2 8f 5d fd ec 82 3b cb
   e8 40 f0 55 b8 4b 27 88 76 1c f4 d4 54 53 ae ba
   ac e1 71 09 d3 7b 56 29 3e 0e 69 1e f1 02 03 01
   00 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
   00 03 82 01 01 00 23 d2 a6 93 26 67 a4 63 11 42
   93 c3 40 ef b8 98 0c dc 7b 4a 67 86 31 dd 3d 17
   a5 b2 eb b7 a6 42 01 bf cf 01 d1 f1 d6 f0 e6 d9
   df 59 aa e6 7d 96 8b 9b 5b 15 19 b7 64 8d 06 1d
   e0 71 e5 b1 b4 6c bc 82 db 2e 08 79 a4 c8 15 41
   dd 21 dd fa 31 f4 ba c4 d9 c0 2d 00 f8 48 37 2a
   a7 3e 70 8b c5 8c 44 37 5c 03 ea 14 f5 ee 94 f8
   82 27 0d d9 d6 39 5c f9 0d a8 ff 19 cc 64 d7 81
   fa b7 2e 2f 01 a2 56 cc ce cc 66 68 e6 e5 c4 1a
   e4 83 8d e5 a6 09 d8 b9 17 dc 3a 85 2e 2d c6 38
   ce 73 da ee fa ad eb 8a 17 74 9e bc 48 ab 9c c0
   0b 86 97 ed 6a b6 09 49 f2 0a 6f 63 a5 f9 22 8d
   97 25 e1 6a c4 0b 0c e1 dd d5 a0 d1 aa a3 ef 63
   8f 69 38 c6 60 d0 ec 01 1c 00 10 01 f8 7c 00 78
   af 47 02 92 ab d8 3d 6c 18 df 3b ed 15 5c af 0b
   3d 40 bf 76 92 57 3b 17 6d 7b 0a b8 83 fe 52 c6
   50 56 e6 15 51 5c 00 00
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
   82 02 1f 02 14 07 c8 5c f3 c2 19 85 9a 8c 62 12
   94 38 23 64 87 82 a3 4c aa 30 0d 06 09 2a 86 48
   86 f7 0d 01 01 0b 05 00 30 57 31 0b 30 09 06 03
   55 04 06 13 02 43 41 31 0f 30 0d 06 03 55 04 08
   0c 06 51 75 65 62 65 63 31 11 30 0f 06 03 55 04
   07 0c 08 4d 6f 6e 74 72 65 61 6c 31 0b 30 09 06
   03 55 04 0a 0c 02 43 41 31 17 30 15 06 03 55 04
   03 0c 0e 63 61 2e 65 78 61 6d 70 6c 65 2e 63 6f
   6d 30 1e 17 0d 32 32 30 35 30 36 31 37 32 31 33
   39 5a 17 0d 33 32 30 35 30 33 31 37 32 31 33 39
   5a 30 59 31 0b 30 09 06 03 55 04 06 13 02 43 41
   31 0f 30 0d 06 03 55 04 08 0c 06 51 75 65 62 65
   63 31 11 30 0f 06 03 55 04 07 0c 08 4d 6f 6e 74
   72 65 61 6c 31 10 30 0e 06 03 55 04 0a 0c 07 45
   78 61 6d 70 6c 65 31 14 30 12 06 03 55 04 03 0c
   0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 30 82 01 22
   30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03
   82 01 0f 00 30 82 01 0a 02 82 01 01 00 c7 2b c8
   3c f4 ba bf 78 47 a2 26 85 71 b3 fb 4a ea 4e 3d
   d0 5a 48 a2 54 ec c5 b5 be 8f 08 01 d8 f3 10 50
   80 57 62 44 55 57 f5 49 bd f7 2b 49 13 6f 9f f1
   da 99 aa bc 12 bb 56 f7 c4 10 01 ca 35 50 ae a1
   67 c5 3d 89 8d d6 32 19 55 0c 75 f1 45 ef 1a 38
   8d 96 0c 5d 89 c4 28 dd d9 20 a7 6f ae fa ba 36
   2d 52 16 a0 97 be 08 2d 7c b5 f4 4e 20 59 94 e3
   6e ba 55 a9 01 ba 4d f8 6d 36 d2 71 61 90 6a ef
   92 a3 06 67 81 91 d6 ba 02 fd b6 ae d9 a0 2e 38
   31 fe 56 1a 6d ab 67 fb 7d da 86 83 aa 1a d5 26
   f3 41 85 07 96 ac 86 d5 b4 89 d6 55 74 e4 0c f7
   d1 d5 74 34 63 9e a2 3c f6 3a 54 f6 cb 5c df 2c
   bc a0 81 81 28 0a bd f6 ec e6 aa 2d 2e ff 19 a0
   3b 68 fc bd 48 58 59 d1 b2 8f 5d fd ec 82 3b cb
   e8 40 f0 55 b8 4b 27 88 76 1c f4 d4 54 53 ae ba
   ac e1 71 09 d3 7b 56 29 3e 0e 69 1e f1 02 03 01
   00 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
   00 03 82 01 01 00 23 d2 a6 93 26 67 a4 63 11 42
   93 c3 40 ef b8 98 0c dc 7b 4a 67 86 31 dd 3d 17
   a5 b2 eb b7 a6 42 01 bf cf 01 d1 f1 d6 f0 e6 d9
   df 59 aa e6 7d 96 8b 9b 5b 15 19 b7 64 8d 06 1d
   e0 71 e5 b1 b4 6c bc 82 db 2e 08 79 a4 c8 15 41
   dd 21 dd fa 31 f4 ba c4 d9 c0 2d 00 f8 48 37 2a
   a7 3e 70 8b c5 8c 44 37 5c 03 ea 14 f5 ee 94 f8
   82 27 0d d9 d6 39 5c f9 0d a8 ff 19 cc 64 d7 81
   fa b7 2e 2f 01 a2 56 cc ce cc 66 68 e6 e5 c4 1a
   e4 83 8d e5 a6 09 d8 b9 17 dc 3a 85 2e 2d c6 38
   ce 73 da ee fa ad eb 8a 17 74 9e bc 48 ab 9c c0
   0b 86 97 ed 6a b6 09 49 f2 0a 6f 63 a5 f9 22 8d
   97 25 e1 6a c4 0b 0c e1 dd d5 a0 d1 aa a3 ef 63
   8f 69 38 c6 60 d0 ec 01 1c 00 10 01 f8 7c 00 78
   af 47 02 92 ab d8 3d 6c 18 df 3b ed 15 5c af 0b
   3d 40 bf 76 92 57 3b 17 6d 7b 0a b8 83 fe 52 c6
   50 56 e6 15 51 5c 00 00
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
   97 57 72 9e 35 eb a7 3b dd bd f7 83 58 f4 4b da
   6f d7 09 84 6c d2 c2 13 62 72 b2 77 a5 ab f6 88
   2c d3 03 cf 0f 87 e3 2c 97 07 5e c7 87 ca af 1c
   0f 1d 4f 01 57 60 08 a7 34 d4 3c 9e bd 54 7b 3a
   1f a9 9c ca 0c aa 7e 55 dc 51 42 62 bb e5 38 1f
   5e 11 ec 04 4d 4e 01 1b e5 e1 fa 49 25 dc 4d 70
   c2 a5 85 81 aa 72 69 dc cc 81 6d f0 7e 79 01 18
   87 eb 1f 9c b8 5c f0 b5 d1 f3 91 73 8a d0 b3 44
   f5 3a 3b f4 e3 44 72 27 95 89 00 fb 31 a5 51 60
   d0 34 8d 6f 56 30 89 66 70 fa 9c cc e8 dd 64 64
   55 c7 fb 16 db 5b 94 38 89 a8 ee ed bf eb 34 32
   cc 0f ed f8 c7 e4 bf d0 56 db bb cb ec 6a cf c8
   83 ed fc 7c d0 17 85 db af 3c fe 7c 97 46 e3 3a
   07 1b b4 34 9f 81 ca d6 3e fe 4b b6 9d a8 09 51
   96 2f bb 70 a2 83 67 8e d9 be 8f 42 bf 59 e3 ba
   ea 80 5c 5e 71 2b 43 01 3a 0e d5 fd 6e fd c8 dc
   1b 13 5f b4 e9 30 fb 9d 19 86 d1 f3 e7 31
     - TLS record 6 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'\x95\xa6\x03\x1c\x9c\xdd\xfc\xfe\xe1\x89w\x97Wr\x9e5'... (truncated, total 281)
     - fragment (encrypted) [281 bytes]:
   95 a6 03 1c 9c dd fc fe e1 89 77 97 57 72 9e 35
   eb a7 3b dd bd f7 83 58 f4 4b da 6f d7 09 84 6c
   d2 c2 13 62 72 b2 77 a5 ab f6 88 2c d3 03 cf 0f
   87 e3 2c 97 07 5e c7 87 ca af 1c 0f 1d 4f 01 57
   60 08 a7 34 d4 3c 9e bd 54 7b 3a 1f a9 9c ca 0c
   aa 7e 55 dc 51 42 62 bb e5 38 1f 5e 11 ec 04 4d
   4e 01 1b e5 e1 fa 49 25 dc 4d 70 c2 a5 85 81 aa
   72 69 dc cc 81 6d f0 7e 79 01 18 87 eb 1f 9c b8
   5c f0 b5 d1 f3 91 73 8a d0 b3 44 f5 3a 3b f4 e3
   44 72 27 95 89 00 fb 31 a5 51 60 d0 34 8d 6f 56
   30 89 66 70 fa 9c cc e8 dd 64 64 55 c7 fb 16 db
   5b 94 38 89 a8 ee ed bf eb 34 32 cc 0f ed f8 c7
   e4 bf d0 56 db bb cb ec 6a cf c8 83 ed fc 7c d0
   17 85 db af 3c fe 7c 97 46 e3 3a 07 1b b4 34 9f
   81 ca d6 3e fe 4b b6 9d a8 09 51 96 2f bb 70 a2
   83 67 8e d9 be 8f 42 bf 59 e3 ba ea 80 5c 5e 71
   2b 43 01 3a 0e d5 fd 6e fd c8 dc 1b 13 5f b4 e9
   30 fb 9d 19 86 d1 f3 e7 31
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
   65 40 76 5d bd 1c 25 f6 9e 4f db b6 91 96 92 86
   16 13 b4 11 2f 20 ec 1f 67 2e 69 7c 73 9f 1f 7d
   7c eb 5b a6 41 e4 7b c9 67 8d 15 79 3e 8d b4 f4
   6d db b2 af 9b a5 4b c9 2d 54 2a 38 89 e6 ec 6b
   26 be d3 6f 8c ba 32 71 89 7f 43 09 14 05 a0 03
   a5 49 07 83 f2 6d d6 60 27 bd 88 7d b0 ee 07 be
   13 c0 a1 36 d1 26 33 fb 99 1a 13 dd 4b 06 44 cc
   0b 46 1a 87 dc de 24 b1 08 c4 0b 47 68 18 d2 a6
   d1 8b 1c 9f 75 90 d0 94 c6 10 2f 1c af 2f cc 5e
   12 fe a3 52 cc 1f 41 85 d5 30 c8 86 24 42 3c 1c
   00 a4 33 19 84 cd 05 45 10 fc 7c f6 23 8a 64 1e
   3e ff f2 9c b9 b7 00 93 0c ac 0f 51 bb a9 04 b3
   bd 81 d0 ca 87 84 af b6 45 da 30 51 c1 d5 46 0c
   c1 df b2 60 ab 05 0e ad 83 f6 35 f1 e2 34 88 ee
   c4 78 45 3c 02 34 49 ec c4 91 1c 9c dc 38 dc f9
   84 fd cc b1 07 95 b6 02 16
     - Inner TLS message 6 server_fragment_bytes_(decrypted): Container: 
       content = b'\x0f\x00\x01\x04\x08\x04\x01\x00g\xca\x9f\xf5\xb9\xe5\xe6V'... (truncated, total 264)
       type = (enum) handshake 22
       zeros = None
     - handshake_message: [264 bytes]:
   0f 00 01 04 08 04 01 00 67 ca 9f f5 b9 e5 e6 56
   65 40 76 5d bd 1c 25 f6 9e 4f db b6 91 96 92 86
   16 13 b4 11 2f 20 ec 1f 67 2e 69 7c 73 9f 1f 7d
   7c eb 5b a6 41 e4 7b c9 67 8d 15 79 3e 8d b4 f4
   6d db b2 af 9b a5 4b c9 2d 54 2a 38 89 e6 ec 6b
   26 be d3 6f 8c ba 32 71 89 7f 43 09 14 05 a0 03
   a5 49 07 83 f2 6d d6 60 27 bd 88 7d b0 ee 07 be
   13 c0 a1 36 d1 26 33 fb 99 1a 13 dd 4b 06 44 cc
   0b 46 1a 87 dc de 24 b1 08 c4 0b 47 68 18 d2 a6
   d1 8b 1c 9f 75 90 d0 94 c6 10 2f 1c af 2f cc 5e
   12 fe a3 52 cc 1f 41 85 d5 30 c8 86 24 42 3c 1c
   00 a4 33 19 84 cd 05 45 10 fc 7c f6 23 8a 64 1e
   3e ff f2 9c b9 b7 00 93 0c ac 0f 51 bb a9 04 b3
   bd 81 d0 ca 87 84 af b6 45 da 30 51 c1 d5 46 0c
   c1 df b2 60 ab 05 0e ad 83 f6 35 f1 e2 34 88 ee
   c4 78 45 3c 02 34 49 ec c4 91 1c 9c dc 38 dc f9
   84 fd cc b1 07 95 b6 02
   handshake_message: Container: 
       msg_type = (enum) certificate_verify 15
       data = Container: 
           algorithm = (enum) rsa_pss_rsae_sha256 b'\x08\x04'
           signature = b'g\xca\x9f\xf5\xb9\xe5\xe6Ve@v]\xbd\x1c%\xf6'... (truncated, total 256)
   :: certificate_verify received

     - TLS message 6 server_certificate_verify [264 bytes]:
   0f 00 01 04 08 04 01 00 67 ca 9f f5 b9 e5 e6 56
   65 40 76 5d bd 1c 25 f6 9e 4f db b6 91 96 92 86
   16 13 b4 11 2f 20 ec 1f 67 2e 69 7c 73 9f 1f 7d
   7c eb 5b a6 41 e4 7b c9 67 8d 15 79 3e 8d b4 f4
   6d db b2 af 9b a5 4b c9 2d 54 2a 38 89 e6 ec 6b
   26 be d3 6f 8c ba 32 71 89 7f 43 09 14 05 a0 03
   a5 49 07 83 f2 6d d6 60 27 bd 88 7d b0 ee 07 be
   13 c0 a1 36 d1 26 33 fb 99 1a 13 dd 4b 06 44 cc
   0b 46 1a 87 dc de 24 b1 08 c4 0b 47 68 18 d2 a6
   d1 8b 1c 9f 75 90 d0 94 c6 10 2f 1c af 2f cc 5e
   12 fe a3 52 cc 1f 41 85 d5 30 c8 86 24 42 3c 1c
   00 a4 33 19 84 cd 05 45 10 fc 7c f6 23 8a 64 1e
   3e ff f2 9c b9 b7 00 93 0c ac 0f 51 bb a9 04 b3
   bd 81 d0 ca 87 84 af b6 45 da 30 51 c1 d5 46 0c
   c1 df b2 60 ab 05 0e ad 83 f6 35 f1 e2 34 88 ee
   c4 78 45 3c 02 34 49 ec c4 91 1c 9c dc 38 dc f9
   84 fd cc b1 07 95 b6 02
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
   24 4e bf c5 f6 8b 4f da 0d 08 33 c8 5c 09 c8 0f
   25 60 0a 40 c2 17 2e 61 28 84 03 74 dd 91 c3 31
   18 48 5c 4e 58 d0 52 de 15 40 94 ef 78 2b e6 10
   1e bb b9 58 1a 75 bc 75 04 b1 7e b7 32 9e a9 11
   bc f7 68 7a 47 79 c2 2d 85 f2 ca 61 6b 6a f1 99
   31 75 3d 8b a4 c1 62 ac 90 af b0 e3 7d 26 2e 34
   12 7f ec 02 82 14 08 9a 16 a4 b4 d4 23 ab d3 1b
   38 8b 01 e1 0e 39 b8 9d 2a 20 6c f5 1a d3 3e c1
   c9 90 57 8c a2 b8 07 51 92 b8 5b ac 8a ec ed fd
   6f b6 06 f7 60 b9 7b 3f e9 6a ff 22 bd 7d 02 b7
   e4 e9 60 37 30 ce f1 ab 19 cd 64 54 b9 2a b3 56
   91 c0 80 d8 b3 b6 cd 47 0c 83 21 5b d8 80 6e ea
   9b 8e 6c eb 87 ce e0 58 f9 de e2 ec 75 0b 50 02
   0c 67 2b 82 cb 14 4a 8d a2 40 c2 f5 e8 bf 51 7c
   1d 1f 62 18 f2 b9 79 f0 2b 5b 00 a8 ba e1 d2 24
   7c 67 18 b8 c0 46 b4 9b e2 a7 3b 35 a5 27 17 50
   4a e4 97 6a c7 1e 00 96 dc 8f 80 9d 82 74 a0 bd
   b0 ad f6 6e c8 04 39 a2 b1 ca b8 a7 78 23 60 71
   cf 8e e7 38 db 9a a7 a9 d2 b9 6c 81 fc c3 40 39
   cd 08 f5 62 58 9f 87 85 45 a4 0d d3 a3 48 d9 9b
   02 5a bf 41 6a b8 21 3e e9 9a e4 87 4d fe a2 50
   c3 c8 03 1f 02 08 aa 13 01 83 23 44 88 92 85 07
   1a 6f 61 9d 03 70 03 72 e6 80 9c 45 0d 4c 0d 60
   17 74 9b 4e 19 84 13 67 00 ef 10 07 7a d3 83 f9
   3d d8 e1 89 07 17 85 fc 08 39 0d 62 d6 90 05 81
   a8 66 58 ff 2e 0a 2b a2 f5 88 a0 43 b3 bd e4 c6
   94 d6 ae e0 0a 3e 84 5b d1 28 3a f3 4f ff 91 69
   61 62 b9 e1 8f 2f 70 64 a3 cd 39 6d 56 4f 01 8b
   07 c1 2b 8d 10 4f 50 15 fc d1 1d 87 0c 66 89 9e
   7f 87 46 3b 06 e6 92 e8 8a bd ce 82 db 6b d9 07
   f2 9e dc a0 89 32 a7 32 ef dd 4b b8 c8 92 1c ba
   39 e0 de f8 68 d0 c9 b5 96 be f2 70 ab 95 79 e5
   e2 4e d3 92 61 3e 58 35 85 5e d7 bb df b9 c2 23
   a4 ea de d0 e4 88 46 09 de fd 3c 43 6e 34 e6
     - TLS record 8 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b';\xab\xab\x8d\x85\xeaW\x07\x95}\x84$N\xbf\xc5\xf6'... (truncated, total 554)
     - fragment (encrypted) [554 bytes]:
   3b ab ab 8d 85 ea 57 07 95 7d 84 24 4e bf c5 f6
   8b 4f da 0d 08 33 c8 5c 09 c8 0f 25 60 0a 40 c2
   17 2e 61 28 84 03 74 dd 91 c3 31 18 48 5c 4e 58
   d0 52 de 15 40 94 ef 78 2b e6 10 1e bb b9 58 1a
   75 bc 75 04 b1 7e b7 32 9e a9 11 bc f7 68 7a 47
   79 c2 2d 85 f2 ca 61 6b 6a f1 99 31 75 3d 8b a4
   c1 62 ac 90 af b0 e3 7d 26 2e 34 12 7f ec 02 82
   14 08 9a 16 a4 b4 d4 23 ab d3 1b 38 8b 01 e1 0e
   39 b8 9d 2a 20 6c f5 1a d3 3e c1 c9 90 57 8c a2
   b8 07 51 92 b8 5b ac 8a ec ed fd 6f b6 06 f7 60
   b9 7b 3f e9 6a ff 22 bd 7d 02 b7 e4 e9 60 37 30
   ce f1 ab 19 cd 64 54 b9 2a b3 56 91 c0 80 d8 b3
   b6 cd 47 0c 83 21 5b d8 80 6e ea 9b 8e 6c eb 87
   ce e0 58 f9 de e2 ec 75 0b 50 02 0c 67 2b 82 cb
   14 4a 8d a2 40 c2 f5 e8 bf 51 7c 1d 1f 62 18 f2
   b9 79 f0 2b 5b 00 a8 ba e1 d2 24 7c 67 18 b8 c0
   46 b4 9b e2 a7 3b 35 a5 27 17 50 4a e4 97 6a c7
   1e 00 96 dc 8f 80 9d 82 74 a0 bd b0 ad f6 6e c8
   04 39 a2 b1 ca b8 a7 78 23 60 71 cf 8e e7 38 db
   9a a7 a9 d2 b9 6c 81 fc c3 40 39 cd 08 f5 62 58
   9f 87 85 45 a4 0d d3 a3 48 d9 9b 02 5a bf 41 6a
   b8 21 3e e9 9a e4 87 4d fe a2 50 c3 c8 03 1f 02
   08 aa 13 01 83 23 44 88 92 85 07 1a 6f 61 9d 03
   70 03 72 e6 80 9c 45 0d 4c 0d 60 17 74 9b 4e 19
   84 13 67 00 ef 10 07 7a d3 83 f9 3d d8 e1 89 07
   17 85 fc 08 39 0d 62 d6 90 05 81 a8 66 58 ff 2e
   0a 2b a2 f5 88 a0 43 b3 bd e4 c6 94 d6 ae e0 0a
   3e 84 5b d1 28 3a f3 4f ff 91 69 61 62 b9 e1 8f
   2f 70 64 a3 cd 39 6d 56 4f 01 8b 07 c1 2b 8d 10
   4f 50 15 fc d1 1d 87 0c 66 89 9e 7f 87 46 3b 06
   e6 92 e8 8a bd ce 82 db 6b d9 07 f2 9e dc a0 89
   32 a7 32 ef dd 4b b8 c8 92 1c ba 39 e0 de f8 68
   d0 c9 b5 96 be f2 70 ab 95 79 e5 e2 4e d3 92 61
   3e 58 35 85 5e d7 bb df b9 c2 23 a4 ea de d0 e4
   88 46 09 de fd 3c 43 6e 34 e6
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
   00 00 00 00 00 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 5d aa ba 94 60 d2 b3 1d 3c
   36 77 3c bb 18 c2 ad 07 90 84 cd 03 02 91 e2 d5
   6f 63 b5 fa 74 e0 65 d2 81 c9 f2 24 c8 e2 9a fe
   47 2a ed f2 6b 21 ac ad 7c 7c b5 22 0a 67 6a ac
   04 b7 51 5b 22 be aa b0 c6 d0 77 c8 98 03 ca 00
   ce 0f f1 f1 bf e4 c6 50 67 f2 3d 31 c1 ae bd 84
   0f 26 a1 4e 61 58 a5 db 2c 0f 29 54 5e 0a 23 e8
   5f e7 fd 67 2c 50 a7 7d b1 a4 37 56 36 6a 90 b9
   83 ef 10 0b de 0c b4 51 13 bf 31 27 21 e8 8d c4
   5e 06 70 fe 13 49 a6 9d 99 21 11 1d 52 ea 1a 31
   d2 ff a6 43 92 ee 1b 6d 8f af 20 e8 31 9a 97 95
   67 4b a3 d1 67 3e 7e 57 21 ee 44 b8 6a a6 9a 85
   5c 2e 39 4e ec e9 ac 57 58 99 e3 71 dc dc 90 94
   dd 73 fd 8f d8 63 27 bc d4 c2 39 00 02 a4 34 e8
   c1 1d 64 e5 73 b5 bc be 69 1c 28 3a 84 04 04 cb
   08 f1 0e fa 00 7d 6b a8 97 2c c2 d2 5c 76 23 4d
   ab 8d 9f 79 e1 05 65 be 31 8d 42 56 ae 36 5a a8
   e1 03 0f 27 28 6c 51 16 d0 c9 92 08 b2 97 64 d9
   58 4a 73 22 93 79 1c d1 36 07 5c ad b4 60 49 a2
   33 6f d2 ac fe e5 78 59 e7 f6 86 83 cf f4 cd c7
   44 2d 47 2e 4f fc 69 a4 78 9c ea 67 55 0d 9f a2
   e4 2d 55 1d fd 12 2a 2d a7 94 71 29 82 53 42 a9
   c4 f4 9f ac 8c 21 af 28 2a 8d 48 09 e6 db 44 59
   52 af bf e5 fe 4a f3 c4 87 b3 75 2e a2 0c 9d e4
   2f d9 89 f1 39 56 f1 33 11 35 27 ae 43 f0 7d c3
   8a 0b 7d f0 5c 18 36 ef b4 e4 c0 27 0a 23 b7 33
   0a af 4b 23 7c cf 40 e9 f4 3b 0c ce 73 ff 1e 84
   a0 93 27 a3 de ff d4 59 63 24 ee 8c f6 28 54 d5
   f0 65 a5 75 96 7b b8 97 6b b4 15 06 b7 d6 a6 ef
   74 4a ef 64 71 5a 57 0b c6 f3 94 56 4e 19 8c a3
   18 91 e3 14 86 a3 ca ab f3 d2 c8 dc 56 66 7b 6a
   a5 70 39 cb 31 2e 60 00 00 16
     - Inner TLS message 8 server_fragment_bytes_(decrypted): Container: 
       content = b'\x04\x00\x02\x15\x00\x00\x1c 5\x08\x0f\xf4\x08\x00\x00\x00'... (truncated, total 537)
       type = (enum) handshake 22
       zeros = None
     - handshake_message: [537 bytes]:
   04 00 02 15 00 00 1c 20 35 08 0f f4 08 00 00 00
   00 00 00 00 00 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 5d aa ba 94 60 d2 b3 1d 3c
   36 77 3c bb 18 c2 ad 07 90 84 cd 03 02 91 e2 d5
   6f 63 b5 fa 74 e0 65 d2 81 c9 f2 24 c8 e2 9a fe
   47 2a ed f2 6b 21 ac ad 7c 7c b5 22 0a 67 6a ac
   04 b7 51 5b 22 be aa b0 c6 d0 77 c8 98 03 ca 00
   ce 0f f1 f1 bf e4 c6 50 67 f2 3d 31 c1 ae bd 84
   0f 26 a1 4e 61 58 a5 db 2c 0f 29 54 5e 0a 23 e8
   5f e7 fd 67 2c 50 a7 7d b1 a4 37 56 36 6a 90 b9
   83 ef 10 0b de 0c b4 51 13 bf 31 27 21 e8 8d c4
   5e 06 70 fe 13 49 a6 9d 99 21 11 1d 52 ea 1a 31
   d2 ff a6 43 92 ee 1b 6d 8f af 20 e8 31 9a 97 95
   67 4b a3 d1 67 3e 7e 57 21 ee 44 b8 6a a6 9a 85
   5c 2e 39 4e ec e9 ac 57 58 99 e3 71 dc dc 90 94
   dd 73 fd 8f d8 63 27 bc d4 c2 39 00 02 a4 34 e8
   c1 1d 64 e5 73 b5 bc be 69 1c 28 3a 84 04 04 cb
   08 f1 0e fa 00 7d 6b a8 97 2c c2 d2 5c 76 23 4d
   ab 8d 9f 79 e1 05 65 be 31 8d 42 56 ae 36 5a a8
   e1 03 0f 27 28 6c 51 16 d0 c9 92 08 b2 97 64 d9
   58 4a 73 22 93 79 1c d1 36 07 5c ad b4 60 49 a2
   33 6f d2 ac fe e5 78 59 e7 f6 86 83 cf f4 cd c7
   44 2d 47 2e 4f fc 69 a4 78 9c ea 67 55 0d 9f a2
   e4 2d 55 1d fd 12 2a 2d a7 94 71 29 82 53 42 a9
   c4 f4 9f ac 8c 21 af 28 2a 8d 48 09 e6 db 44 59
   52 af bf e5 fe 4a f3 c4 87 b3 75 2e a2 0c 9d e4
   2f d9 89 f1 39 56 f1 33 11 35 27 ae 43 f0 7d c3
   8a 0b 7d f0 5c 18 36 ef b4 e4 c0 27 0a 23 b7 33
   0a af 4b 23 7c cf 40 e9 f4 3b 0c ce 73 ff 1e 84
   a0 93 27 a3 de ff d4 59 63 24 ee 8c f6 28 54 d5
   f0 65 a5 75 96 7b b8 97 6b b4 15 06 b7 d6 a6 ef
   74 4a ef 64 71 5a 57 0b c6 f3 94 56 4e 19 8c a3
   18 91 e3 14 86 a3 ca ab f3 d2 c8 dc 56 66 7b 6a
   a5 70 39 cb 31 2e 60 00 00
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
   00 00 00 00 00 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 5d aa ba 94 60 d2 b3 1d 3c
   36 77 3c bb 18 c2 ad 07 90 84 cd 03 02 91 e2 d5
   6f 63 b5 fa 74 e0 65 d2 81 c9 f2 24 c8 e2 9a fe
   47 2a ed f2 6b 21 ac ad 7c 7c b5 22 0a 67 6a ac
   04 b7 51 5b 22 be aa b0 c6 d0 77 c8 98 03 ca 00
   ce 0f f1 f1 bf e4 c6 50 67 f2 3d 31 c1 ae bd 84
   0f 26 a1 4e 61 58 a5 db 2c 0f 29 54 5e 0a 23 e8
   5f e7 fd 67 2c 50 a7 7d b1 a4 37 56 36 6a 90 b9
   83 ef 10 0b de 0c b4 51 13 bf 31 27 21 e8 8d c4
   5e 06 70 fe 13 49 a6 9d 99 21 11 1d 52 ea 1a 31
   d2 ff a6 43 92 ee 1b 6d 8f af 20 e8 31 9a 97 95
   67 4b a3 d1 67 3e 7e 57 21 ee 44 b8 6a a6 9a 85
   5c 2e 39 4e ec e9 ac 57 58 99 e3 71 dc dc 90 94
   dd 73 fd 8f d8 63 27 bc d4 c2 39 00 02 a4 34 e8
   c1 1d 64 e5 73 b5 bc be 69 1c 28 3a 84 04 04 cb
   08 f1 0e fa 00 7d 6b a8 97 2c c2 d2 5c 76 23 4d
   ab 8d 9f 79 e1 05 65 be 31 8d 42 56 ae 36 5a a8
   e1 03 0f 27 28 6c 51 16 d0 c9 92 08 b2 97 64 d9
   58 4a 73 22 93 79 1c d1 36 07 5c ad b4 60 49 a2
   33 6f d2 ac fe e5 78 59 e7 f6 86 83 cf f4 cd c7
   44 2d 47 2e 4f fc 69 a4 78 9c ea 67 55 0d 9f a2
   e4 2d 55 1d fd 12 2a 2d a7 94 71 29 82 53 42 a9
   c4 f4 9f ac 8c 21 af 28 2a 8d 48 09 e6 db 44 59
   52 af bf e5 fe 4a f3 c4 87 b3 75 2e a2 0c 9d e4
   2f d9 89 f1 39 56 f1 33 11 35 27 ae 43 f0 7d c3
   8a 0b 7d f0 5c 18 36 ef b4 e4 c0 27 0a 23 b7 33
   0a af 4b 23 7c cf 40 e9 f4 3b 0c ce 73 ff 1e 84
   a0 93 27 a3 de ff d4 59 63 24 ee 8c f6 28 54 d5
   f0 65 a5 75 96 7b b8 97 6b b4 15 06 b7 d6 a6 ef
   74 4a ef 64 71 5a 57 0b c6 f3 94 56 4e 19 8c a3
   18 91 e3 14 86 a3 ca ab f3 d2 c8 dc 56 66 7b 6a
   a5 70 39 cb 31 2e 60 00 00
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
   bc 6d b2 ff f2 e5 2a 11 2d d5 7f e5 f0 0f b6 5f
   74 cd a6 48 8d 53 55 5a e9 5d 4b 81 e4 ff 38 ff
   d0 c2 56 df 29 0e 08 16 1f 9d 05 b9 66 ea 92 3f
   72 79 a6 85 5c 18 d1 bc c7 a3 3b 6c 8d 99 32 46
   1d 99 ae 37 2e 29 51 39 4c fa eb 46 11 48 88 da
   d6 f2 05 a2 b4 3f 51 ba ce 45 bc 38 7f 40 39 75
   d7 55 2c 75 c6 92 a1 14 26 b8 ed 9e 07 5b 28 5a
   a2 ab a3 03 88 95 b7 80 a1 7c 6d 80 53 f9 30 33
   c6 80 58 3f 83 a1 ae 22 ee 7c fa f3 d0 44 36 ba
   19 df 79 41 a1 6b c7 35 21 5b b5 30 d8 23 85 dc
   cf c7 55 c0 81 89 6e 0a 50 13 3c 0c 77 16 ac c0
   6f e7 06 91 94 bd 51 03 73 ad b6 a5 7d 6b 56 11
   21 09 05 5e f4 cf 12 f5 88 b2 43 a7 1a 5f 84 ad
   f4 2c 45 ce eb 8a b6 e6 a5 02 30 2a 50 8c 9a c8
   0f b7 05 02 81 3a 78 3c 06 65 67 a6 5a 27 15 ca
   98 99 27 76 d7 0c a2 53 9c 76 aa 09 38 03 63 ba
   f2 99 57 ec df 1c 2f bb da 20 60 bb cc dc fb 2b
   5d 14 2a b4 db be 43 2c 89 93 19 2b 4f a7 e0 22
   0e ce 51 ad f9 b2 9b 25 f0 21 07 e1 1d 63 6b 13
   f4 39 19 33 36 48 46 62 3d ba 4a 3a a3 a7 27 9b
   80 c8 cc 23 00 5a b7 93 56 08 2d 8b c2 e7 5f 7b
   c6 49 2f 53 25 05 e6 00 73 e2 99 0c e4 59 a8 9c
   77 32 0f 5e 5d 63 4f 2b 85 7d 8f de 73 b4 d8 0c
   7d 84 72 31 d3 a0 56 34 ff dd 6a 2e 64 55 cb 83
   87 98 cc 1c 21 5c 4b 3b fc c3 7a 8c 44 1d 88 eb
   74 58 36 b2 7e 6c b9 4a 76 88 4f 75 14 e7 b9 90
   52 9a b6 f2 22 61 c4 25 9f 67 72 f4 5f aa 65 d5
   38 7c da 3d 58 4f d8 b7 55 61 1d aa 05 16 44 f5
   62 69 6c 98 9a d4 8f 36 63 9a 98 e3 59 f2 76 b1
   be da 23 d8 29 9c 06 a2 bf 33 dd a0 56 3c f4 14
   85 07 e5 52 19 bb 0b 51 3a 60 2b f3 2f cd f7 c6
   1e 50 fb 9d e2 0f dc de b0 74 ae 49 a4 09 e4 d1
   09 04 de 22 68 34 0a 4e d6 32 09 50 2e 77 90 91
   c3 5b 29 99 36 b7 1b 79 53 67 ab 18 b3 92 47
     - TLS record 9 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'q\xd9@\x82\x0bw\x8fg\xc1\xaf}\xbcm\xb2\xff\xf2'... (truncated, total 554)
     - fragment (encrypted) [554 bytes]:
   71 d9 40 82 0b 77 8f 67 c1 af 7d bc 6d b2 ff f2
   e5 2a 11 2d d5 7f e5 f0 0f b6 5f 74 cd a6 48 8d
   53 55 5a e9 5d 4b 81 e4 ff 38 ff d0 c2 56 df 29
   0e 08 16 1f 9d 05 b9 66 ea 92 3f 72 79 a6 85 5c
   18 d1 bc c7 a3 3b 6c 8d 99 32 46 1d 99 ae 37 2e
   29 51 39 4c fa eb 46 11 48 88 da d6 f2 05 a2 b4
   3f 51 ba ce 45 bc 38 7f 40 39 75 d7 55 2c 75 c6
   92 a1 14 26 b8 ed 9e 07 5b 28 5a a2 ab a3 03 88
   95 b7 80 a1 7c 6d 80 53 f9 30 33 c6 80 58 3f 83
   a1 ae 22 ee 7c fa f3 d0 44 36 ba 19 df 79 41 a1
   6b c7 35 21 5b b5 30 d8 23 85 dc cf c7 55 c0 81
   89 6e 0a 50 13 3c 0c 77 16 ac c0 6f e7 06 91 94
   bd 51 03 73 ad b6 a5 7d 6b 56 11 21 09 05 5e f4
   cf 12 f5 88 b2 43 a7 1a 5f 84 ad f4 2c 45 ce eb
   8a b6 e6 a5 02 30 2a 50 8c 9a c8 0f b7 05 02 81
   3a 78 3c 06 65 67 a6 5a 27 15 ca 98 99 27 76 d7
   0c a2 53 9c 76 aa 09 38 03 63 ba f2 99 57 ec df
   1c 2f bb da 20 60 bb cc dc fb 2b 5d 14 2a b4 db
   be 43 2c 89 93 19 2b 4f a7 e0 22 0e ce 51 ad f9
   b2 9b 25 f0 21 07 e1 1d 63 6b 13 f4 39 19 33 36
   48 46 62 3d ba 4a 3a a3 a7 27 9b 80 c8 cc 23 00
   5a b7 93 56 08 2d 8b c2 e7 5f 7b c6 49 2f 53 25
   05 e6 00 73 e2 99 0c e4 59 a8 9c 77 32 0f 5e 5d
   63 4f 2b 85 7d 8f de 73 b4 d8 0c 7d 84 72 31 d3
   a0 56 34 ff dd 6a 2e 64 55 cb 83 87 98 cc 1c 21
   5c 4b 3b fc c3 7a 8c 44 1d 88 eb 74 58 36 b2 7e
   6c b9 4a 76 88 4f 75 14 e7 b9 90 52 9a b6 f2 22
   61 c4 25 9f 67 72 f4 5f aa 65 d5 38 7c da 3d 58
   4f d8 b7 55 61 1d aa 05 16 44 f5 62 69 6c 98 9a
   d4 8f 36 63 9a 98 e3 59 f2 76 b1 be da 23 d8 29
   9c 06 a2 bf 33 dd a0 56 3c f4 14 85 07 e5 52 19
   bb 0b 51 3a 60 2b f3 2f cd f7 c6 1e 50 fb 9d e2
   0f dc de b0 74 ae 49 a4 09 e4 d1 09 04 de 22 68
   34 0a 4e d6 32 09 50 2e 77 90 91 c3 5b 29 99 36
   b7 1b 79 53 67 ab 18 b3 92 47
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
   00 00 00 00 01 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 ca 62 30 97 3c ff a2 bc ca
   44 73 ff 08 94 7a c0 40 27 f8 f6 02 f9 e1 5a 5f
   11 33 00 cf 6e 84 e6 7f a2 03 76 eb d3 dd 63 7f
   63 0a bb 24 8d 4f 20 31 2f f0 1b 63 45 85 e7 14
   b7 77 ac c9 2e 20 bc 75 ad 06 13 aa 4c b2 cd 19
   b3 93 7c bd 8c 1c 0e 26 33 6a a1 36 da d7 8b 60
   a3 0e a2 93 47 d4 28 b6 f0 c8 3c c4 d8 31 b2 3a
   a7 65 75 ff f1 26 b2 50 12 47 8c df 5d 6c 68 51
   d9 c1 57 32 7c 78 c8 07 a7 a2 46 26 1e 3c a1 4e
   4e 34 fb 24 d4 ac 56 7e 0b 65 c6 f6 58 99 70 70
   76 64 67 04 3c a8 36 ab 5b ba e7 3b 56 18 e0 3e
   bb 2a c1 a5 8f ce 19 b0 15 56 7b 12 db 61 1f f9
   7a e7 46 e3 40 6f ed 02 b7 4a c3 58 d6 7b 0f b7
   ea 2b 74 36 5f 80 64 34 e4 02 19 74 41 7d 57 5f
   c0 81 c3 0b 78 8c b3 02 43 e8 7a a5 2e 48 07 76
   e4 77 bc 6d 58 1a 4e cb 02 e0 5b 5d 98 55 ea bf
   33 e0 61 83 12 28 d9 eb 29 72 da 60 b2 ce d2 61
   17 2a 91 8d 88 b1 63 86 a5 67 65 64 50 9f 39 ee
   47 03 1a 3d 54 c3 76 f3 e0 8c a2 f9 85 85 b1 7a
   0b e7 31 63 48 a1 5f fa fd 71 41 52 82 44 04 ab
   4f a0 cf cb 35 0f 7d 4d 1b 7e a5 80 47 04 d4 b5
   8c 3d 71 79 bc ac d1 d4 9c c7 ec 00 8a 84 b5 2e
   55 7e 89 5b 65 18 6e df bb 0f 5c 67 34 a2 e6 b9
   8b 4e e8 71 d3 e4 eb 20 a7 ce 15 61 68 56 0e 9e
   b4 db d6 c4 29 62 2c 21 47 37 02 61 d8 cf 47 71
   d7 bc ee ad 0c 06 92 a1 ea f4 3d 21 fd 15 1d 68
   a9 57 f5 9a 4b 52 9a 8a 7e 17 06 13 c2 11 94 d3
   0a ad 1f 90 81 db 7e 41 a1 8d b8 83 f7 35 fb 2b
   bb 25 b0 09 89 b4 5d 94 3f 28 db 9f d4 93 f3 c0
   f8 bd 65 99 2f 0b c1 dd 98 ff ef 37 26 eb 62 43
   97 84 23 e8 63 ff 80 36 0d 9e 0f 32 1b e0 97 7c
   b4 5d d4 3e 99 f5 a2 00 00 16
     - Inner TLS message 9 server_fragment_bytes_(decrypted): Container: 
       content = b'\x04\x00\x02\x15\x00\x00\x1c \x15\xfcTS\x08\x00\x00\x00'... (truncated, total 537)
       type = (enum) handshake 22
       zeros = None
     - handshake_message: [537 bytes]:
   04 00 02 15 00 00 1c 20 15 fc 54 53 08 00 00 00
   00 00 00 00 01 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 ca 62 30 97 3c ff a2 bc ca
   44 73 ff 08 94 7a c0 40 27 f8 f6 02 f9 e1 5a 5f
   11 33 00 cf 6e 84 e6 7f a2 03 76 eb d3 dd 63 7f
   63 0a bb 24 8d 4f 20 31 2f f0 1b 63 45 85 e7 14
   b7 77 ac c9 2e 20 bc 75 ad 06 13 aa 4c b2 cd 19
   b3 93 7c bd 8c 1c 0e 26 33 6a a1 36 da d7 8b 60
   a3 0e a2 93 47 d4 28 b6 f0 c8 3c c4 d8 31 b2 3a
   a7 65 75 ff f1 26 b2 50 12 47 8c df 5d 6c 68 51
   d9 c1 57 32 7c 78 c8 07 a7 a2 46 26 1e 3c a1 4e
   4e 34 fb 24 d4 ac 56 7e 0b 65 c6 f6 58 99 70 70
   76 64 67 04 3c a8 36 ab 5b ba e7 3b 56 18 e0 3e
   bb 2a c1 a5 8f ce 19 b0 15 56 7b 12 db 61 1f f9
   7a e7 46 e3 40 6f ed 02 b7 4a c3 58 d6 7b 0f b7
   ea 2b 74 36 5f 80 64 34 e4 02 19 74 41 7d 57 5f
   c0 81 c3 0b 78 8c b3 02 43 e8 7a a5 2e 48 07 76
   e4 77 bc 6d 58 1a 4e cb 02 e0 5b 5d 98 55 ea bf
   33 e0 61 83 12 28 d9 eb 29 72 da 60 b2 ce d2 61
   17 2a 91 8d 88 b1 63 86 a5 67 65 64 50 9f 39 ee
   47 03 1a 3d 54 c3 76 f3 e0 8c a2 f9 85 85 b1 7a
   0b e7 31 63 48 a1 5f fa fd 71 41 52 82 44 04 ab
   4f a0 cf cb 35 0f 7d 4d 1b 7e a5 80 47 04 d4 b5
   8c 3d 71 79 bc ac d1 d4 9c c7 ec 00 8a 84 b5 2e
   55 7e 89 5b 65 18 6e df bb 0f 5c 67 34 a2 e6 b9
   8b 4e e8 71 d3 e4 eb 20 a7 ce 15 61 68 56 0e 9e
   b4 db d6 c4 29 62 2c 21 47 37 02 61 d8 cf 47 71
   d7 bc ee ad 0c 06 92 a1 ea f4 3d 21 fd 15 1d 68
   a9 57 f5 9a 4b 52 9a 8a 7e 17 06 13 c2 11 94 d3
   0a ad 1f 90 81 db 7e 41 a1 8d b8 83 f7 35 fb 2b
   bb 25 b0 09 89 b4 5d 94 3f 28 db 9f d4 93 f3 c0
   f8 bd 65 99 2f 0b c1 dd 98 ff ef 37 26 eb 62 43
   97 84 23 e8 63 ff 80 36 0d 9e 0f 32 1b e0 97 7c
   b4 5d d4 3e 99 f5 a2 00 00
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
   00 00 00 00 01 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 ca 62 30 97 3c ff a2 bc ca
   44 73 ff 08 94 7a c0 40 27 f8 f6 02 f9 e1 5a 5f
   11 33 00 cf 6e 84 e6 7f a2 03 76 eb d3 dd 63 7f
   63 0a bb 24 8d 4f 20 31 2f f0 1b 63 45 85 e7 14
   b7 77 ac c9 2e 20 bc 75 ad 06 13 aa 4c b2 cd 19
   b3 93 7c bd 8c 1c 0e 26 33 6a a1 36 da d7 8b 60
   a3 0e a2 93 47 d4 28 b6 f0 c8 3c c4 d8 31 b2 3a
   a7 65 75 ff f1 26 b2 50 12 47 8c df 5d 6c 68 51
   d9 c1 57 32 7c 78 c8 07 a7 a2 46 26 1e 3c a1 4e
   4e 34 fb 24 d4 ac 56 7e 0b 65 c6 f6 58 99 70 70
   76 64 67 04 3c a8 36 ab 5b ba e7 3b 56 18 e0 3e
   bb 2a c1 a5 8f ce 19 b0 15 56 7b 12 db 61 1f f9
   7a e7 46 e3 40 6f ed 02 b7 4a c3 58 d6 7b 0f b7
   ea 2b 74 36 5f 80 64 34 e4 02 19 74 41 7d 57 5f
   c0 81 c3 0b 78 8c b3 02 43 e8 7a a5 2e 48 07 76
   e4 77 bc 6d 58 1a 4e cb 02 e0 5b 5d 98 55 ea bf
   33 e0 61 83 12 28 d9 eb 29 72 da 60 b2 ce d2 61
   17 2a 91 8d 88 b1 63 86 a5 67 65 64 50 9f 39 ee
   47 03 1a 3d 54 c3 76 f3 e0 8c a2 f9 85 85 b1 7a
   0b e7 31 63 48 a1 5f fa fd 71 41 52 82 44 04 ab
   4f a0 cf cb 35 0f 7d 4d 1b 7e a5 80 47 04 d4 b5
   8c 3d 71 79 bc ac d1 d4 9c c7 ec 00 8a 84 b5 2e
   55 7e 89 5b 65 18 6e df bb 0f 5c 67 34 a2 e6 b9
   8b 4e e8 71 d3 e4 eb 20 a7 ce 15 61 68 56 0e 9e
   b4 db d6 c4 29 62 2c 21 47 37 02 61 d8 cf 47 71
   d7 bc ee ad 0c 06 92 a1 ea f4 3d 21 fd 15 1d 68
   a9 57 f5 9a 4b 52 9a 8a 7e 17 06 13 c2 11 94 d3
   0a ad 1f 90 81 db 7e 41 a1 8d b8 83 f7 35 fb 2b
   bb 25 b0 09 89 b4 5d 94 3f 28 db 9f d4 93 f3 c0
   f8 bd 65 99 2f 0b c1 dd 98 ff ef 37 26 eb 62 43
   97 84 23 e8 63 ff 80 36 0d 9e 0f 32 1b e0 97 7c
   b4 5d d4 3e 99 f5 a2 00 00
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
   7f ad 74 8d a6 a6 08 3a fe f4 c7 d7 3d 0c d8 4a
   b1 a6 3a 1e 7d f3 1f 46 7a 34 8f 33 42 95 16 39
   c5 c7 2a 2d 37 71 7a ac 46 af 13 da c8 51 a4 3f
   0e ad c4 b4 ad fe 37 22 6f 93 02 1f 09 2a 20 d9
   ce b8 64 d8 9b 7e c8 d4 40 fc 5a ea 7e 43 52 ed
   6f 75 80 8b 7d bc b5 7b 8f 19 84 45 d4 cd a0 36
   21 b4 eb d0 68 91 62 9c be 08 3e 1e f8 61 47 eb
   c7 6b f3 9f b7 5b 81 58 da 97 ac 01 1e 8a 92 74
   4d 84 f2 47 f7 26 eb 87 77 2e 5d ff 08 6e a9 67
   13 8b 17 2e af 6c 72 e3 7f 85 21 d5 c6 cd 6f d3
   61 07 52 bb 83 c5 44 42 be 53 3d 88 31 36 c1 65
   5a b3 70 41 7b d9 28 aa 98 00 b9 b7 e4 41 be 6d
   7d 36 a2 31 c7 26 45 8b d5 3d 1a ba d4 49 3a 6e
   00 87 c4 db e8 e9 2b 2a 90 d5 64 30 33 3a 03 eb
   fc 9b d1 e1 1b 7e 9f 13 85 a1 97 a2 4d 58 32 3a
   9b a8 56 f0 b1 d9 13 71 d3 67 95 c1 10 0e 7d e9
   5a 6b 5b 7b 52 57 ef a9 69 29 70 89 34 93 9f 9d
   06 f6 a1 e6 ea dd 2b 98 cb 02 64 75 55 09 5d 51
   1e b3 d7 28 e3 e2 cc 3b 26 19 cf c5 a5 63 27 21
   90 9a b3 25 a9 26 65 c3 70 d5 ff f7 28 c6 9c ad
   bc ed 17 f0 68 ae aa 09 2f 00 53 51 8b 2c cb a8
   8b c1 56 1a 58 82 f8 bb 9a 69 fb 47 ad 64 94 9c
   e6 41 6d 6e 54 87 1c ff 85 31 c0 fa 6a 77 83 68
   ce 4b 80 8f 6f f7 21 fe 75 a9 20 d3 bd d5 07 b4
   59 3e ee 1a a7 0f 90 f8 6f af 48 bb 76 66 bc 40
   56 a9 39 79 90 25 6e 24 3a 1d 64 25 35 ef a7 b7
   4e 4b 4f 90 d6 5e 61 06 7f b6 82 4b 1e a1 d0 7b
   bf d1 6d 65 75 6a 94 b2 42 34 df 00 54 a7 ea ba
   dd fd d6 f3 f7 41 8d 78 0e 70 a4 df 84 a3 eb 7b
   40 c1 f2 8b 75 41 39 a3 7f a7 0c b4 92 f8 a7 fb
   bd 2a 34 c8 d9 75 80 44 1b 74 8f 5f 81 d5 fe b3
   7f f9 eb 5f a0 cd 47 d0 f2 26 ff 98 74 13 f6 e8
   02 8d 82 dd eb c3 a4 e3 af 67 e6 a9 c0 2e 5c d4
   23 a1 52 db c1 ed b3 e1 bb 48 03 0b 9a 25 c4 2c
   8f 86 37 13 33 fb 4b 6d b2 d1 16 a5 a3 91 56 cc
   8b 80 8c d2 75 7d 45 93 05 41 72 c2 31 e3 23 2a
   d2 00 09 00 f8 07 98 b4 41 ec 1f e4 dd ab b0 89
   ec a8 50 de ae cc e4 6f b8 28 94 b9 8f 64 9f 30
   db ff 0c 9a 9c 91 37 ea 6c 2d 46 6a 29 5d 4f 50
   40 02 94 f3 4c 85 16 fc d4 3f 3b e5 be 2f f1 a8
   0d ba ab fe 2d 5b 95 a3 69 09 3a e8 86 44 6e 23
   1a 63 b3 e2 fb 98 d5 21 36 38 4d d6 96 1b f3 42
   b4 01 ee e5 cb 76 b6 fb 5f 1a ff 89 a2 21 3c b2
   33 c8 2d cb eb a2 b6 ec d3 d2 33 c1 ce 88 0d 9c
   07 fc eb 21 7b 50 38 6b b3 e8 18 94 79 3d 6e 14
   cf 87 fe 2a d7 64 62 2d 89 ee 38 b6 27 03 f8 fb
   4d bd f3 b0 7a 22 8b dc ef 5f 46 b0 55 4b 7a 28
   48 bd 8c 25 96 c1 4e ad 92 59 84 35 40 71 e3 2d
   f0 5d 40 db f5 48 af de 31 be c9 e8 39 ff 2d 13
   15 5f 07 4b 7d b3 f3 8f 36 55 b6 2e 2c 32 30 37
   8e 5b 60 26 10 16 78 c2 1d 9c 66 1c a9 66 ea d2
   69 25 85 72 12 c9 df 3f ad ef 3e 81 4d 09 41 94
   98 35 3d e2 0c 0f 42 97 3a dc 10 6d ac 04 22 9c
   06 c0 d2 3c 4f 65 43 d2 06 33 d8 41 bd 36 98 9d
   b4 30 3f 8d 67 13 94 5e 00 d1 ca 25 4d 0f a7 c5
   47 10 de eb cb 80 4f 16 a0 d6 87 61 f9 02 93 47
   d2 ae 4c af 5d 83 ff b4 3b e3 ff 65 31 6d 63 b1
   83 9a da 37 aa 81 b6 30 ac 27 8b ac 7a f4 e5 63
   21 fd 8a ad 1e 65 4f 80 d7 b4 39 d4 ec 52 b8 7e
   ca 70 62 29 fc e5 b6 03 25 68 a9 9d f5 54 1c 1d
   7b e5 27 65 eb 1e 3a 94 58 58 10 af 09 84 2e 29
   ba e3 d4 9f 56 e8 a6 68 7c 7a 5a 9d 94 b7 49 a0
   77 58 8e 39 48 aa 62 e6 56 2e bc 61 50 62 0a 21
   c3 f3 91 cd f6 9e ae e6 5a 0d a5 f2 41 37 aa 71
   eb 6d 11 49 1a ad 7e f4 d3 4e f7 0c da 7a 42 8e
   0b 14 ef 2e a9 f8 84 cb b7 70 64 13 64 31 09 d9
   1e 2d 1f 75 18 4f 66 f8 31 b4 bb 9a 2c 65 de 22
   9a 50 c0 52 5a c5 04 f1 9b 34 3f ae 2f 25 81 ed
   89 3f 7c c3 92 cf 7a ea 6f bd 9e e3 c9 39 b3 de
   27 36 ac de d2 9c 81 30 21 fb 5b 9d 78 d0 a1 46
   f7 73 87 dd dc b9 c3 ec ad 82 f1 51 f2 fe 5f 6d
   7a e2 bb a9 33 92 3e 1e 4f 0c ea c4 b2 94 96 62
   44 b5 5e ff 0b bf 94 a6 9a d7 9a 58 a6 5c b3 eb
   38 3d a0 8a 63 ba b5 bc 6a 8d 93 7c 87 aa 82 41
   ee 03 27 78 a3 18 5f c3 d3 3d 8d 42 ce c1 8e 3f
   13 5a f5 10 19 29 16 0c f2 c8 62 58 28 37 39 75
   1b 82 65 ce 92 1e 8b 5d 88 b8 a5 4c d8 65 ef a6
   17 81 63 9f 76 07 cf 86 26 dd 72 7c 62 bc 7d ab
   76 b5 5c 5c ca 7c 27 d1 27 63 42 41 ee 54 30 b3
   c3 83 83 be 25 2d 49 48 ae de f7 2d ee 13 4c 0a
   16 47 1c bf d5 33 63 66 93 fa d6 e0 ac c9 7e a8
   1d d2 7a 56 5b 3c 4e f5 c7 92 19 e4 f2 94 e6 1f
   71 53 d2 4a 40 db 6f 11 f9 bf a5 d9 dd cf 80 56
   48 51 c0 10 9a b3 b8 39 ef f5 bd ca 67 36 ef 90
   5a 51 bd 73 b5 4c de d5 40 ca 8b 79 7e 0d 04 e4
   2f b0 08 65 e4 2e 09 08 e9 3b 10 dc 24 97 69 b1
   a3 71 b1 fb 88 f8 7d ce 8d 7e 3b c3 30 7f 50 38
   c9 75 36 a3 dd ce 71 60 7f a3 cf 2d 7b 43 33 0e
   d1 98 02 78 e0 2c 30 7f 8c 85 d7 2b 4d f4 22 e6
   1b 7d b7 78 8e 40 15 10 5c aa 66 7b 70 5a a2 8a
   b3 27 45 38 b9 52 8f 22 6c d7 4c 7a d0 a2 6d d7
   5f f4 ad be cf 6c 18 90 8c 7f e0 b8 2c 69 54 90
   60 ff 56 43 1e 7a 51 67 20 2c 2f e1 62 ac 20 d6
   85 8c 96 58 aa 26 68 74 ac 05 c7 ff 77 e4 72 67
   dd 21 d1 fd 2a bd 7b 30 c5 df d2 40 5a c1 e0 a9
   c8 18 64 ef 98 09 49 fd 6d f1 08 a2 16 c0 f0 32
   0e 5c 55 ec 31 d2 e1 d3 bd 2f 1f 01 39 79 f0 8b
   0c e2 c7 d1 d8 c6 5a c9 32 37 50 68 fb d5 84 2b
   cc 25 c9 5f c3 34 cb 20 7d c1 52 b6 1c ad 18 51
   40 c4 84 c6 e2 66 7b 50 4b 15 12 ab db 2f 32 9f
   0b 17 c9 3e ce 0d 1d b8 7d 63 e7 0e ff ea 89 e6
   da a3 77 c2 3f 66 a7 68 cd 05 95 24 89 e9 44 af
   3f eb 2a 88 9d 1d 5e 50 f3 00 de 38 73 63 d8 f2
   df 11 55 ce c1 8f 61 15 c5 a1 4a 84 fb 4b e3 24
   6c 4f 46 a0 70 53 23 f0 03 38 4a 96 0e 27 ea f2
   b8 50 c9 d2 c1 64 67 ea d5 db b9 62 5a c1 79 e5
   c9 fe 82 32 dd a2 dd 73 17 a9 8c 6b ae d7 2e 53
   c2 71 8d 98 74 7f 64 73 b6 d2 25 8b 5a e2 b1 a1
   de 67 68 72 a4 26 43 61 a2 67 0e a6 95 53 10 a0
   5e 91 e7 12 c7 e1 cd 0b 87 1a af d5 1a 5f 00 24
   0a 61 d3 b7 4d c5 fc f6 ad 67 f7 a6 2e 02 54 bb
   59 35 a7 74 a3 e9 d5 b9 5a dd b4 85 78 41 ec 5d
   67 db bf e3 70 37 29 0c 63 86 9c 23 b9 bb 36 fc
   49 c0 e1 90 f6 48 5c a0 e1 88 ed 2b f9 3a c6 db
   70 97 eb 1b 83 c1 99 69 37 36 e0 50 60 b9 3c 77
   8c 18 e2 9f cf 16 d9 4f 39 f7 56 41 bb 68 a1 ff
   f7 eb 0c 91 59 58 cb 7e a7 93 3a 22 9a 31 97 73
   f6 cf 87 0f 68 91 35 61 8d bc b2 81 f3 09 2b ee
   1b 14 65 97 31 2b ce 06 bb fb aa 09 98 b8 81 00
   c4 1e 25 a8 02 dc 72 a5 86 f9 d4 55 f6 c5 5e 7a
   80 b6 09 ea 90 4f 82 71 fb 12 f4 5a c2 53 3a 64
   ef b8 3b 1b 1a 45 eb 1b 2f 00 f1 03 f7 62 f5 3d
   c4 53 2e d7 8d 32 2c e2 f3 ea 2e 8d 2a 56 13 b7
   6f 59 a5 8f 4f 50 50 ed dc 7b 9e 90 32 75 83 a3
   09 cc 3f df 2c 3e 87 a3 a9 0e 09 2a ab c4 3d 56
   8f 18 da 79 af 2a 2b 89 bb 0f e0 01 4f a6 86 48
   8b c9 12 fc c2 53 d5 0e 54 76 2e 19 42 92 8a ff
   6d c8 29 4e c9 ca 8c be 93 ca dd a4 a1 9f d4 fb
   2c a1 a5 25 2b 02 88 9b c5 2b a1 57 8d e6 78 f0
   0f ff 34 84 d8 04 84 f9 d4 ab 56 a2 9b 78 6e b9
   8e 23 80 65 2b 56 12 3a 74 14 e5 cc cf 73 84 43
   1f 35 e0 ae 01 35 f4 24 54 0e ba a9 00 59 f7 ad
   6a 2a 70 6c ca 48 62 5f 4f 17 d1 84 50 d6 ec f7
   96 e5 55 62 5d 01 c5 51 c1 21 15 fb 9f 87 9e c9
   a8 ce 9e 89 53 dd f8 76 89 50 8c 74 7a 04 78 18
   9e d9 cf c7 a3 e9 b7 79 24 6b 87 8d 05 87 5a a0
   c9 e7 d7 e6 7b 6b 1c 54 5a 2d ce 02 d4 fb b4 48
   ab 64 b6 1a 03 ae bc 10 62 ad 19 f3 39 c4 5e a4
   ba d3 2b 93 11 fc bd f4 31 56 ef 76 1b 59 2c 93
   c5 6c de 8b 82 bc 97 bb 77 a6 2e e8 95 aa 02 19
   93 98 eb bc b1 76 24 da a4 92 76 bb 62 4e e9 38
   02 ce 27 63 5e a3 9b 36 ae 86 92 c7 63 fe 6d 8f
   f4 35 a0 3c e5 f4 db 2a f1 86 3a 60 51 a2 84 61
   80 0f a8 64 b3 f9 15 2e 67 b0 c1 49 c7 64 b1 0b
   38 e0 28 dc b5 1a 3f f4 5e 88 a0 fc 8a 74 92 40
   c9 fe 16 e1 37 2e 75 a4 63 0e bd 07 f3 35 d1 69
   45 57 dd c3 0b 15 a3 c2 ea 8e 04 ac 8d 51 d8 e4
   b0 3e 88 eb b6 a8 88 e2 59 1f 9d c4 a6 90 b2 54
   ab d6 5a 9f 25 33 d3 f1 c8 8c 1b c3 cd 7a d2 ad
   00 1f d9 0a 3b f5 83 98 29 9f dd aa 1c ae b0 60
   10 70 09 f1 3e 8a 89 9c 03 09 1e ae f4 3b b8 eb
   e5 70 d8 a3 86 54 4c ef 6c ba 03 0a 54 70 4d ca
   31 89 e5 33 e6 de 0b 7e 28 8d 9f ad ed 98 d8 9f
   24 2c 64 a9 bc 5e ec 52 cf c1 1d c8 ef 3f 19 97
   8e 40 d9 3f 23 ff 72 dd 9a 55 f9 e4 40 ce 8e ce
   88 e7 71 16 28 87 5a 42 77 b5 a0 ab 3b 95 8c 9c
   75 1e bf 07 b5 8f 56 dc 77 bd c2 33 df bb 87 d9
   d4 e2 60 03 2c 2a af d8 c2 3b 4f f2 b2 87 73 81
   10 a5 97 8b ef 6f d4 82 8a 11 be c0 76 39 cd 70
   60 28 1e 91 71 34 7e 25 5e 4b 69 7d 3f 4e 5e db
   12 cc 7c 31 8f d4 28 9d 01 61 de 80 b7 b1 b8 10
   a0 00 a5 1d 54 1d 2c ce 05 5b e4 81 59 d0 86 76
   50 b1 d6 1b 71 22 9c 30 95 98 63 7c cb a3 1c 1a
   9f cb 2a a8 8c c1 a2 42 e7 f9 83 eb 80 90 79 19
   91 f6 da 16 6e d9 3c 36 d7 c6 8f 54 fc ad a7 4d
   52 41 28 f8 fc e0 fc b7 eb a6 aa 64 82 e4 a6 41
   82 8b df 01 e4 eb de 6e 75 25 58 e5 40 73 24 f5
   6a e9 5f 23 36 c6 5d ee 90 92 49 20 f3 d5 ac 64
   b2 f5 ce fd 4b 9c 2d 8f d8 f9 ef d6 5b c3 7f 53
   fd 06 36 10 49 92 88 a7 eb f0 b8 41 68 cd 5b 82
   85 34 0b 89 2a 9d d5 3b 6a 08 41 c4 21 64 ed 2d
   49 f0 a8 c9 4b 99 c3 2f 0d 8f d7 a7 01 c8 c4 54
   bf 26 56 41 12 1a d6 c9 04 fb 8b 62 92 46 8d bc
   11 15 4f f6 d0 8c c4 ff 25 03 1f 40 d7 9d 81 c2
   40 b3 d9 f9 73 20 90 7d d7 a4 c6 10 03 40 71 bc
   24 d6 fe 3e d3 bb ff 46 34 16 e6 95 22 05 f1 04
   2e 6d a0 b3 61 34 48 35 66 a7 35 6b 37 39 c2 37
   ec 3c b9 2e 36 fe b0 c5 e6 88 6d ff 24 37 76 cc
   f0 2a e7 3e cc 30 cd 38 ae d2 9c af 49 91 b8 b6
   af af 1f be ec 87 c5 95 ac a3 75 6b c3 5d 27 dc
   71 10 f3 2c 9d ca fc c3 3b 90 2c cf b6 c6 e6 d9
   4b dd a6 b6 04 48 35 4a a1 4d da bc 04 e0 4c c5
   a9 94 f2 0f 3e b7 ec 83 56 89 e9 61 3b 1b a7 c0
   d2 1a 1d 4a 4d f0 1e 06 72 12 c4 06 7a fb ba 6f
   e4 a2 bb 01 ef 04 97 37 be 04 79 3f ea b2 cf 79
   81 0c 38 bd 75 ed 5c 12 a5 5d a3 4b 01 74 c9 64
   d7 d7 f0 91 2f 0c 89 40 fc af 32 78 e8 b5 1d 0d
   64 ce 34 58 01 46 de 1d a0 d2 f2 48 a6 03 d1 ec
   75 bb 79 e1 a7 5c 08 18 dd 79 19 08 c2 41 7a 84
   7a fe b8 36 36 04 a7 3e 3c 71 6c ee fb 93 fe a5
   11 83 44 2b 55 1d 36 f4 77 89 38 83 dc 4f 11 67
   35 24 ef 16 02 2b 83 e7 aa ac c6 0c 36 a0 87 7e
   71 85 99 c7 ce e4 cb 72 df 0a f7 63 72 d4 7b 32
   ea 4b 0b c5 6a aa fb 6d 3f 5b 59 58 2a 0a 98 03
   5b 4b 11 6d 49 3a 2e 37 83 4c c2 2e 5f 9f 22 cc
   39 e5 f4 91 24 1e 77 35 23 16 1d eb 8e e3 45 be
   e7 d7 e0 53 7a 99 5d db 42 1c a4 1d f2 f5 f2 ca
   58 07 a6 4f a9 df 62 98 99 bc 82 3e 8b f2 8d 0b
   e2 12 07 c6 6f 96 f8 ec 72 00 b2 4e 21 22 9b da
   f5 f2 70 85 47 03 5c d9 8b f6 8f 2c c9 b5 fc 18
   a9 3e 9f c5 a7 99 76 a4 4c 88 76 a0 7b 27 bf 40
   cd c0 30 7a 46 06 9d 74 6f 93 98 04 68 d2 28 9a
   40 2e 26 b6 f4 d1 19 c1 55 01 ba 7a 6f 0c c0 90
   a7 b1 e9 b1 4b 83 fe 8f 45 b1 01 d0 f9 8b 3d da
   fa b2 08 a4 4d 85 82 d4 d0 89 bd 3d 8b 99 46 9f
   3e 34 92 ce 29 5e fd 3a ac af 7f b6 45 f3 ae e2
   64 9f df d3 c2 86 0d af 75 3b 29 96 2a 04 05 dd
   d5 25 63 63 2a 45 a7 c8 8e 72 fd b5 f5 04 d3 74
   8d 72 57 b7 19 89 4c b0 15 78 cd c8 f6 05 8e b1
   5a 8a 2a 96 0a e4 e5 3f e1 da 21 63 28 8e 2a 21
   61 98 a6 56 50 de 39 63 e0 80 cd 9d 52 34 5e ff
   b3 d9 44 f1 45 10 d7 26 8e fe fb 3b 1d 3f a2 b2
   46 2b ce 50 08 2b 49 fa 0e 19 1f 8e 3b b9 fb 6a
   17 a7 29 fc 06 ce 72 48 5c 71 56 f8 8f d0 46 1b
   95 6b 78 ed ac ed 99 12 6c 64 d8 5f 1b 46 3f 44
   f7 6b 18 f1 af f8 23 92 2b fb 6c 70 6f 37 ee b3
   c3 1c 73 78 9b b8 0a ab 92 5d 40 a3 1a 00 0f d3
   9b 86 3a e1 7c 70 eb 68 88 ec d5 a0 f9 50 40 ba
   c3 67 5d 84 80 aa a2 ea f4 50 6b 88 69 b8 79 1f
   42 23 f7 97 ee 9e 74 95 23 e9 26 dc 38 d4 7a 05
   5e 5a 9d 63 fd 79 a2 f1 9f f8 d6 28 d5 9a ec 4e
   ec dc 57 56 1c b1 30 76 e8 ac 3f eb 19 bd 36 45
   e0 00 ab 99 68 4b da d5 2d 00 76 49 ab 79 c0 11
   8f 1f f0 47 a5 8f c2 d7 51 e7 9f 66 d6 d0 cf f2
   11 f4 0a 27 7f f0 36 1a 5f 2d 93 2b 89 39 0b 01
   48 9d 12 ff 67 db db 21 bd 5e a6 1f a0 91 74 27
   d4 be cd be eb 41 ea 83 60 aa 4e 66 55 6c 5a 54
   1c df e2 67 73 b4 ea 3a 73 9c 32 fb 6c 2f 46 b2
   9e cf 1b 58 2a 91 8c 97 e7 e4 c7 4b 6a 92 be 9b
   e5 ec 02 c2 89 72 1c 82 cf 74 4c f4 b2 d8 fb 4d
   21 24 27 1a 7e 41 2a 96 5d 65 26 79 c6 ac 80 04
   ff 51 57 ec 44 25 02 9a 83 9a 64 cb df 6b a0 2d
   48 d2 bd 29 db f8 dd bd 5a 35 70 dd 59 1c 57 de
   a4 eb 15 26 61 74 06 6c c9 9d 80 84 8f 38 ec 74
   2b b1 77 e2 9c 32 b0 ca 73 47 7b 93 76 d1 b0 73
   f3 fa d3 b8 f3 73 2e e5 30 52 fd 9a 35 42 67 05
   86 02 8e 5f bc 4e aa ea 49 43 88 4e 50 43 69 c8
   12 7d b7 43 d4 c8 f5 bd 08 cf 58 d2 95 50 a3 cb
   51 7c 06 0d 0e 82 7e 6b f7 f5 28 fb 5d fb ab c5
   9d 69 2f 26 b5 6d 53 e1 3a 9d 07 7e ef 28 cd 77
   42 f5 f4 fb b2 b4 69 c2 f4 b8 eb 11 82 9e 7b ab
   06 e2 d7 eb ef ba 58 7c 9c de 98 78 f3 b9 9e eb
   c4 f8 97 fd 85 a8 de a4 4a 6f 0b 8d 4d f0 11 e7
   8f 61 ce e3 d0 31 77 97 83 34 5e 85 c6 19 9b 28
   b9 7e f1 01 a7 9d 0c 0c 2b a4 95 8b 1a e5 e1 d6
   2a a9 f6 7d 68 fd 0f a7 70 d9 0c 6f 54 f4 0b 5b
   b4 e2 b7 0b 99 5a c4 ee 69 77 62 c5 05 24 b5 e1
   f2 ed 4c 20 98 e5 73 b7 08 76 11 a9 af e2 71 50
   4f 41 63 62 4c 1e db e5 55 00 c7 70 c7 89 1f 63
   5e 94 39 8a f0 3b 47 e0 c3 ee c7 24 49 1c 9e 24
   99 13 91 04 a8 c0 c5 86 c2 68 ec 87 70 80 b4 45
   28 ca e0 79 ac 65 a0 af fc 21 1b f8 1d 37 87 4d
   ec 11 49 f6 f3 3f 75 6b 26 a1 26 4e 1e 85 6a 10
   17 37 0a e1 fa 13 44 c9 e4 02 a3 06 fd 10 b9 95
   69 d5 80 78 bc 2b 8d aa e6 21 c0 f2 c6 17 a6 cf
   7c 99 c8 93 47 31 20 d5 c2 55 4a 1a 86 3e 6d 17
   03 d3 9d ec f1 a3 6d 13 63 e6 b0 9e 43 65 12 30
   7a 3e 30 92 b2 a1 4f be 62 18 5d 8a 86 5a 35 5e
   e1 41 36 d1 30 86 04 3e 57 d9 b7 cb e0 e7 e4 ff
   e3 56 fb 39 cb ca 07 35 92 18 38 da 01 4b 4e ee
   6f 53 11 77 7b 78 b5 3d 69 d7 a7 89 73 24 b6 6e
   3e 62 77 90 98 db d6 2a 0a 80 3f ff 7c 27 be bb
   87 5d 36 f5 8c 42 c4 7f b3 20 1b 47 9b 3d e5 c6
   1e 43 6d e8 31 e7 f5 f9 e9 1a 76 39 8e 28 9f 73
   36 0c 30 ab 33 75 12 3b 59 5c c9 9a ef 62 f4 a3
   70 5b 53 89 60 31 d2 8b 65 9d 21 68 f9 89 93 d5
   ab 22 4b 39 1b 6e 71 7b 92 71 bf f9 7e 22 1d 8f
   aa 0e 01 43 a1 71 8a ba 1c cb 0b 1f d1 4a 6a 10
   fd 28 18 a9 d5 40 1c a4 8d 52 f9 94 ac 8a 5f 13
   48 e9 a9 4e 5e 9e ae e0 41 9f 81 d1 e9 89 61 ca
   e8 5f 25 df df 9a ad e3 f7 d0 82 08 9e c5 6d 5c
   b0 53 d8 90 74 88 3f 6c 2c a7 d8 c7 00 b2 30 f8
   6b 5e 2f c2 84 f0 67 66 b5 ec cc 1a 82 65 7e 05
   4e 99 1a f0 75 5f 57 c2 cf c2 9d f6 3c 80 d9 31
   8d 1b 76 e8 b7 f8 2f 54 50 d9 f6 f9 dc 7a 16 9e
   3b 8b 60 6a dd a9 82 38 58 50 1b 30 a8 42 33 05
   94 da a4 29 11 cf 11 5b a1 86 66 69 f9 cb 70 be
   77 a3 2b f5 89 d3 e0 0c 58 e8 ba e9 80 f3 bf 7a
   55 06 b4 da 31 1e 6a d5 14 1e 14 ef ea 06 02 5d
   10 fb 30 5a 21 e6 db c1 a9 a6 54 52 06 4b cb a3
   0d 65 26 2e 5a a8 df 9f 04 25 b2 8b 2f 35 0e 73
   d8 08 e3 3b 4d 03 44 4b 96 97 cb 85 51 af cb af
   63 2a 54 31 fe 1b ad 6f bb 2d c9 0b 4d d4 ef b4
   f4 53 a6 60 b1 ab d7 81 39 04 62 10 a5 9e ec 57
   21 9d 86 5a a0 b3 60 5f 4b 32 2b 5f 39 8e 76 6f
   c6 9b e4 01 a1 70 0d 9c 64 39 a9 02 e0 2b 9c ff
   1e 2e 89 a3 45 4a dc c0 ec 9c b1 40 09 25 14 12
   b0 4c 1a c4 27 92 e9 af da 94 ff d8 4e 03 51 37
   60 0f c0 d0 fc 05 38 40 0d ea 5a f6 f5 b8 15 2a
   62 cb 21 37 24 6b a9 cf 0b 38 51 34 36 86 42 ab
   ca 96 15 2d 83 5a 3b bd 58 27 b7 ed d5 d0 c2 36
   78 20 3d 14 82 2e d0 db a3 09 6f 1c 0c 2a fe 92
   63 86 60 20 c4 55 7f 1c 95 ae b0 b6 11 85 b2 d1
   6d 1a 2e c1 82 86 b5 5b d6 1d b0 09 92 aa 1b b0
   94 93 37 20 9b 8a f1 96 6c 87 6c 4c 22 70 bf e1
   1d 48 4c 53 f5 27 85 6d f4 2a 0d 79 49 b3 e9 ad
   1e d4 83 db e8 65 15 53 dd bf 0a 26 29 b5 7f 12
   cd 61 d0 13 2f 2a 5e ee d2 b0 aa 64 8b 09 c6 66
   ba 09 0b 87 e7 0a e1 80 3c 3e ab 90 93 95 b4 4a
   54 b9 35 56 23 a7 f0 f5 20 c8 40 2e 2f b0 c1 c3
   77 c5 ee c9 9e 1e fb 2a 5d c3 f3 7e 18 0e 0a 94
   47 ed 54 9b 1b c1 60 f6 a4 f5 05 bc 3a 69 9d ac
   13 d5 09 e9 1f a3 82 33 b2 35 6f 34 9b 5e cf 17
   16 51 cb 53 97 03 63 1f 14 da 45 5c b0 64 36 ce
   b8 6e 84 f4 1d f3 86 2c b1 f4 9d 12 53 5f d2 68
   71 f6 9b e4 48 86 d2 2e e8 4f 58 06 6d 40 a0 0d
   f6 0f 08 52 ef 42 93 b6 ee a7 ed 7a 0e e6 c4 72
   67 76 a7 82 77 a7 09 54 3f d4 3c fd 82 f8 81 b3
   97 81 fa 83 41 27 d8 c4 7b 82 7e 01 1e 24 f4 c6
   ba e0 33 a6 e5 4b 85 01 b0 30 fe d1 2b 0c 58 47
   35 a5 7b 80 9c 4a c8 87 15 bb d4 f6 04 01 3b e5
   0e 16 4f e0 cf ff c4 3d 71 3c c7 32 e8 e4 af ec
   6a 75 e2 56 21 d5 97 63 c2 5d d6 5c 24 4d 6f bf
   6b b6 88 d7 0e 27 70 fe b8 59 2b e0 a1 d9 cd ed
   95 5c 71 cb 4c a7 c9 7c e5 fe cb 4f 8e 10 f9 7a
   6e ec 39 f9 c4 1e 6d b9 31 71 17 f8 f4 dd 43 ee
   1e e1 80 34 8e fd e9 cf d8 73 5c e2 9d 13 22 5e
   2a b5 2f fd 4b 47 61 98 5c 4e 4e b9 70 92 47 d6
   fe 6a aa 15 1f 42 20 75 79 72 c9 2a 7f 8b b1 79
   38 ff e7 a5 56 2d 2d 99 fa 9c 46 4c 12 b6 46 4a
   d4 39 8e 68 2a c7 91 56 20 85 26 d9 02 f8 47 56
   bd 06 c2 15 6f 5b 20 2a 31 cf ec 12 29 db 49 d5
   63 6f ac 28 67 01 71 ff eb 08 ce 37 bc 29 c1 96
   41 67 86 52 a5 86 97 e0 eb 2d 44 80 63 74 5c 64
   76 3d c8 a3 e4 c1 b5 71 c7 7a 0a 2b 72 66 07 44
   4a 30 1b d5 5d c4 ff 39 bc 06 59 db 98 68 9c 28
   25 e7 f3 d9 ba db 34 62 f2 3d 56 e4 34 6b 25 33
   d2 2e 49 ed 18 42 e4 6d 25 c7 e7 b8 3f 15 bd d6
   12 e1 e1 d5 70 e9 e6 62 02 d4 19 f1 f9 67 33 d2
   67 16 ef fa f1 36 eb c6 5e 25 a5 ce 53 6e f7 c1
   bb 00 c0 13 68 88 c0 b9 aa a7 29 0a 6e 21 e3 ab
   ed b9 d4 cb 2d 8c 0d 78 4a bc 0f b0 5d 38 2b 71
   07 1d e0 95 ed aa 62 ab 4b 61 9d bc d1 e5 d2 65
   aa 16 a6 13 cd 99 92 be 40 14 ad 90 e7 c9 f1 21
   d2 f3 e5 85 17 f5 1f d9 86 99 36 2c df d0 df 45
   ee 71 7e 52 77 02 dd 5c 22 81 12 ac a2 25 ee 1e
   f4 45 f5 f3 c5 58 fb b1 30 c2 db 54 68 2c a8 8c
   c1 0a 1a 0f 8f 32 90 ca 35 46 5c 00 9d 4c a4 2f
   5e d6 c9 cd 43 bd 92 46 c3 2e 6b ca 11 45 d3 88
   1f 3f b1 50 85 48 63 b2 e2 3d 2d 03 f8 18 5b 5f
   5a 2d 01 88 4f 31 4e 41 aa 26 85 fc 47 0d ee 07
   f6 59 b8 fb 69 36 a5 41 28 63 44 61 1d c3 22 9b
   4e 08 51 8e e4 5e 51 77 96 8c 0d 40 d8 d8 2c 1c
   8f 4a 43 1e a2 c9 e0 86 40 b4 31 b9 f5 20 8f 3f
   aa 5e 16 cb 6f ec 3c af d9 cd 6d 6a 5c 1a 4e 56
   81 67 fa 76 dc 0b 47 3b 2f bd cf 73 4f 18 28 56
   11 8a fe f8 53 60 0d 12 21 7c 37 45 2b 03 f0 27
   fb 78 7c 05 8d ca 2f aa 0d 87 f0 f9 22 69 a8 6f
   cc ae db c8 2f 58 eb af 0e 6a 7e 31 65 f1 03 27
   97 2c 19 bf 71 f3 3e 6a ad 66 fc 42 91 36 c7 82
   f6 da 9a af 3c ff d1 14 95 a7 c2 96 a1 0e 72 a5
   e3 ad 4b 16 af a2 c5 4a 74 27 78 fe ba ff be 2c
   ca 44 b2 e9 f1 af f1 d3 b7 94 95 6a 22 81 36 ce
   32 95 73 f8 1f a5 c7 d8 ce 55 f2 32 23 d2 21 c0
   d2 dc 4b a4 7b 4e 5e 3d d8 22 d4 75 93 fc 94 c6
   4f e5 64 6d 36 6b 32 47 d0 39 6d 8e e6 3c ab 20
   da d4 f6 bf c6 f6 da 8e 72 f7 cb da 13 c2 37 b9
   ed 0e 1c 0b a2 fe b8 82 ba be b0 04 eb 9d 94 74
   78 00 6d 97 fb b1 c4 9d 40 69 90 76 1b af 18 ad
   fd c6 57 21 43 eb 94 42 08 04 5d 46 c0 f6 8b c2
   92 4a 21 20 0d 9c 93 0a dd 0e 87 26 73 92 a0 d0
   d2 80 ff 5f b7 26 1d b9 27 28 5c 37 82 2f a3 7c
   5f 85 f2 60 97 f6 89 de ca 45 db ec a3 d7 f9 12
   f4 1d 85 07 65 b5 43 80 b1 7b d0 8c 49 d2 e4 95
   8c 11 49 8d 66 02 37 9e 64 a6 66 86 17 f9 86 f0
   ea 25 bf b3 16 38 5d 96 a7 5a 0c 7b 4b a3 9d 37
   3f 03 b6 33 26 31 5d 6d 7e 23 74 53 9d 44 70 c3
   40 90 46 c7 49 53 e4 57 75 d5 fb 80 1a cf 3e aa
   4f 82 c9 56 6a 47 cf 52 51 02 72 8e 40 be 6f 43
   13 2e e0 2c d5 1a a1 a1
     - TLS record 10 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b's3F\x8cD\xf1\xbb\xf3}\x11\x98\x7f\xadt\x8d\xa6'... (truncated, total 5923)
     - fragment (encrypted) [5923 bytes]:
   73 33 46 8c 44 f1 bb f3 7d 11 98 7f ad 74 8d a6
   a6 08 3a fe f4 c7 d7 3d 0c d8 4a b1 a6 3a 1e 7d
   f3 1f 46 7a 34 8f 33 42 95 16 39 c5 c7 2a 2d 37
   71 7a ac 46 af 13 da c8 51 a4 3f 0e ad c4 b4 ad
   fe 37 22 6f 93 02 1f 09 2a 20 d9 ce b8 64 d8 9b
   7e c8 d4 40 fc 5a ea 7e 43 52 ed 6f 75 80 8b 7d
   bc b5 7b 8f 19 84 45 d4 cd a0 36 21 b4 eb d0 68
   91 62 9c be 08 3e 1e f8 61 47 eb c7 6b f3 9f b7
   5b 81 58 da 97 ac 01 1e 8a 92 74 4d 84 f2 47 f7
   26 eb 87 77 2e 5d ff 08 6e a9 67 13 8b 17 2e af
   6c 72 e3 7f 85 21 d5 c6 cd 6f d3 61 07 52 bb 83
   c5 44 42 be 53 3d 88 31 36 c1 65 5a b3 70 41 7b
   d9 28 aa 98 00 b9 b7 e4 41 be 6d 7d 36 a2 31 c7
   26 45 8b d5 3d 1a ba d4 49 3a 6e 00 87 c4 db e8
   e9 2b 2a 90 d5 64 30 33 3a 03 eb fc 9b d1 e1 1b
   7e 9f 13 85 a1 97 a2 4d 58 32 3a 9b a8 56 f0 b1
   d9 13 71 d3 67 95 c1 10 0e 7d e9 5a 6b 5b 7b 52
   57 ef a9 69 29 70 89 34 93 9f 9d 06 f6 a1 e6 ea
   dd 2b 98 cb 02 64 75 55 09 5d 51 1e b3 d7 28 e3
   e2 cc 3b 26 19 cf c5 a5 63 27 21 90 9a b3 25 a9
   26 65 c3 70 d5 ff f7 28 c6 9c ad bc ed 17 f0 68
   ae aa 09 2f 00 53 51 8b 2c cb a8 8b c1 56 1a 58
   82 f8 bb 9a 69 fb 47 ad 64 94 9c e6 41 6d 6e 54
   87 1c ff 85 31 c0 fa 6a 77 83 68 ce 4b 80 8f 6f
   f7 21 fe 75 a9 20 d3 bd d5 07 b4 59 3e ee 1a a7
   0f 90 f8 6f af 48 bb 76 66 bc 40 56 a9 39 79 90
   25 6e 24 3a 1d 64 25 35 ef a7 b7 4e 4b 4f 90 d6
   5e 61 06 7f b6 82 4b 1e a1 d0 7b bf d1 6d 65 75
   6a 94 b2 42 34 df 00 54 a7 ea ba dd fd d6 f3 f7
   41 8d 78 0e 70 a4 df 84 a3 eb 7b 40 c1 f2 8b 75
   41 39 a3 7f a7 0c b4 92 f8 a7 fb bd 2a 34 c8 d9
   75 80 44 1b 74 8f 5f 81 d5 fe b3 7f f9 eb 5f a0
   cd 47 d0 f2 26 ff 98 74 13 f6 e8 02 8d 82 dd eb
   c3 a4 e3 af 67 e6 a9 c0 2e 5c d4 23 a1 52 db c1
   ed b3 e1 bb 48 03 0b 9a 25 c4 2c 8f 86 37 13 33
   fb 4b 6d b2 d1 16 a5 a3 91 56 cc 8b 80 8c d2 75
   7d 45 93 05 41 72 c2 31 e3 23 2a d2 00 09 00 f8
   07 98 b4 41 ec 1f e4 dd ab b0 89 ec a8 50 de ae
   cc e4 6f b8 28 94 b9 8f 64 9f 30 db ff 0c 9a 9c
   91 37 ea 6c 2d 46 6a 29 5d 4f 50 40 02 94 f3 4c
   85 16 fc d4 3f 3b e5 be 2f f1 a8 0d ba ab fe 2d
   5b 95 a3 69 09 3a e8 86 44 6e 23 1a 63 b3 e2 fb
   98 d5 21 36 38 4d d6 96 1b f3 42 b4 01 ee e5 cb
   76 b6 fb 5f 1a ff 89 a2 21 3c b2 33 c8 2d cb eb
   a2 b6 ec d3 d2 33 c1 ce 88 0d 9c 07 fc eb 21 7b
   50 38 6b b3 e8 18 94 79 3d 6e 14 cf 87 fe 2a d7
   64 62 2d 89 ee 38 b6 27 03 f8 fb 4d bd f3 b0 7a
   22 8b dc ef 5f 46 b0 55 4b 7a 28 48 bd 8c 25 96
   c1 4e ad 92 59 84 35 40 71 e3 2d f0 5d 40 db f5
   48 af de 31 be c9 e8 39 ff 2d 13 15 5f 07 4b 7d
   b3 f3 8f 36 55 b6 2e 2c 32 30 37 8e 5b 60 26 10
   16 78 c2 1d 9c 66 1c a9 66 ea d2 69 25 85 72 12
   c9 df 3f ad ef 3e 81 4d 09 41 94 98 35 3d e2 0c
   0f 42 97 3a dc 10 6d ac 04 22 9c 06 c0 d2 3c 4f
   65 43 d2 06 33 d8 41 bd 36 98 9d b4 30 3f 8d 67
   13 94 5e 00 d1 ca 25 4d 0f a7 c5 47 10 de eb cb
   80 4f 16 a0 d6 87 61 f9 02 93 47 d2 ae 4c af 5d
   83 ff b4 3b e3 ff 65 31 6d 63 b1 83 9a da 37 aa
   81 b6 30 ac 27 8b ac 7a f4 e5 63 21 fd 8a ad 1e
   65 4f 80 d7 b4 39 d4 ec 52 b8 7e ca 70 62 29 fc
   e5 b6 03 25 68 a9 9d f5 54 1c 1d 7b e5 27 65 eb
   1e 3a 94 58 58 10 af 09 84 2e 29 ba e3 d4 9f 56
   e8 a6 68 7c 7a 5a 9d 94 b7 49 a0 77 58 8e 39 48
   aa 62 e6 56 2e bc 61 50 62 0a 21 c3 f3 91 cd f6
   9e ae e6 5a 0d a5 f2 41 37 aa 71 eb 6d 11 49 1a
   ad 7e f4 d3 4e f7 0c da 7a 42 8e 0b 14 ef 2e a9
   f8 84 cb b7 70 64 13 64 31 09 d9 1e 2d 1f 75 18
   4f 66 f8 31 b4 bb 9a 2c 65 de 22 9a 50 c0 52 5a
   c5 04 f1 9b 34 3f ae 2f 25 81 ed 89 3f 7c c3 92
   cf 7a ea 6f bd 9e e3 c9 39 b3 de 27 36 ac de d2
   9c 81 30 21 fb 5b 9d 78 d0 a1 46 f7 73 87 dd dc
   b9 c3 ec ad 82 f1 51 f2 fe 5f 6d 7a e2 bb a9 33
   92 3e 1e 4f 0c ea c4 b2 94 96 62 44 b5 5e ff 0b
   bf 94 a6 9a d7 9a 58 a6 5c b3 eb 38 3d a0 8a 63
   ba b5 bc 6a 8d 93 7c 87 aa 82 41 ee 03 27 78 a3
   18 5f c3 d3 3d 8d 42 ce c1 8e 3f 13 5a f5 10 19
   29 16 0c f2 c8 62 58 28 37 39 75 1b 82 65 ce 92
   1e 8b 5d 88 b8 a5 4c d8 65 ef a6 17 81 63 9f 76
   07 cf 86 26 dd 72 7c 62 bc 7d ab 76 b5 5c 5c ca
   7c 27 d1 27 63 42 41 ee 54 30 b3 c3 83 83 be 25
   2d 49 48 ae de f7 2d ee 13 4c 0a 16 47 1c bf d5
   33 63 66 93 fa d6 e0 ac c9 7e a8 1d d2 7a 56 5b
   3c 4e f5 c7 92 19 e4 f2 94 e6 1f 71 53 d2 4a 40
   db 6f 11 f9 bf a5 d9 dd cf 80 56 48 51 c0 10 9a
   b3 b8 39 ef f5 bd ca 67 36 ef 90 5a 51 bd 73 b5
   4c de d5 40 ca 8b 79 7e 0d 04 e4 2f b0 08 65 e4
   2e 09 08 e9 3b 10 dc 24 97 69 b1 a3 71 b1 fb 88
   f8 7d ce 8d 7e 3b c3 30 7f 50 38 c9 75 36 a3 dd
   ce 71 60 7f a3 cf 2d 7b 43 33 0e d1 98 02 78 e0
   2c 30 7f 8c 85 d7 2b 4d f4 22 e6 1b 7d b7 78 8e
   40 15 10 5c aa 66 7b 70 5a a2 8a b3 27 45 38 b9
   52 8f 22 6c d7 4c 7a d0 a2 6d d7 5f f4 ad be cf
   6c 18 90 8c 7f e0 b8 2c 69 54 90 60 ff 56 43 1e
   7a 51 67 20 2c 2f e1 62 ac 20 d6 85 8c 96 58 aa
   26 68 74 ac 05 c7 ff 77 e4 72 67 dd 21 d1 fd 2a
   bd 7b 30 c5 df d2 40 5a c1 e0 a9 c8 18 64 ef 98
   09 49 fd 6d f1 08 a2 16 c0 f0 32 0e 5c 55 ec 31
   d2 e1 d3 bd 2f 1f 01 39 79 f0 8b 0c e2 c7 d1 d8
   c6 5a c9 32 37 50 68 fb d5 84 2b cc 25 c9 5f c3
   34 cb 20 7d c1 52 b6 1c ad 18 51 40 c4 84 c6 e2
   66 7b 50 4b 15 12 ab db 2f 32 9f 0b 17 c9 3e ce
   0d 1d b8 7d 63 e7 0e ff ea 89 e6 da a3 77 c2 3f
   66 a7 68 cd 05 95 24 89 e9 44 af 3f eb 2a 88 9d
   1d 5e 50 f3 00 de 38 73 63 d8 f2 df 11 55 ce c1
   8f 61 15 c5 a1 4a 84 fb 4b e3 24 6c 4f 46 a0 70
   53 23 f0 03 38 4a 96 0e 27 ea f2 b8 50 c9 d2 c1
   64 67 ea d5 db b9 62 5a c1 79 e5 c9 fe 82 32 dd
   a2 dd 73 17 a9 8c 6b ae d7 2e 53 c2 71 8d 98 74
   7f 64 73 b6 d2 25 8b 5a e2 b1 a1 de 67 68 72 a4
   26 43 61 a2 67 0e a6 95 53 10 a0 5e 91 e7 12 c7
   e1 cd 0b 87 1a af d5 1a 5f 00 24 0a 61 d3 b7 4d
   c5 fc f6 ad 67 f7 a6 2e 02 54 bb 59 35 a7 74 a3
   e9 d5 b9 5a dd b4 85 78 41 ec 5d 67 db bf e3 70
   37 29 0c 63 86 9c 23 b9 bb 36 fc 49 c0 e1 90 f6
   48 5c a0 e1 88 ed 2b f9 3a c6 db 70 97 eb 1b 83
   c1 99 69 37 36 e0 50 60 b9 3c 77 8c 18 e2 9f cf
   16 d9 4f 39 f7 56 41 bb 68 a1 ff f7 eb 0c 91 59
   58 cb 7e a7 93 3a 22 9a 31 97 73 f6 cf 87 0f 68
   91 35 61 8d bc b2 81 f3 09 2b ee 1b 14 65 97 31
   2b ce 06 bb fb aa 09 98 b8 81 00 c4 1e 25 a8 02
   dc 72 a5 86 f9 d4 55 f6 c5 5e 7a 80 b6 09 ea 90
   4f 82 71 fb 12 f4 5a c2 53 3a 64 ef b8 3b 1b 1a
   45 eb 1b 2f 00 f1 03 f7 62 f5 3d c4 53 2e d7 8d
   32 2c e2 f3 ea 2e 8d 2a 56 13 b7 6f 59 a5 8f 4f
   50 50 ed dc 7b 9e 90 32 75 83 a3 09 cc 3f df 2c
   3e 87 a3 a9 0e 09 2a ab c4 3d 56 8f 18 da 79 af
   2a 2b 89 bb 0f e0 01 4f a6 86 48 8b c9 12 fc c2
   53 d5 0e 54 76 2e 19 42 92 8a ff 6d c8 29 4e c9
   ca 8c be 93 ca dd a4 a1 9f d4 fb 2c a1 a5 25 2b
   02 88 9b c5 2b a1 57 8d e6 78 f0 0f ff 34 84 d8
   04 84 f9 d4 ab 56 a2 9b 78 6e b9 8e 23 80 65 2b
   56 12 3a 74 14 e5 cc cf 73 84 43 1f 35 e0 ae 01
   35 f4 24 54 0e ba a9 00 59 f7 ad 6a 2a 70 6c ca
   48 62 5f 4f 17 d1 84 50 d6 ec f7 96 e5 55 62 5d
   01 c5 51 c1 21 15 fb 9f 87 9e c9 a8 ce 9e 89 53
   dd f8 76 89 50 8c 74 7a 04 78 18 9e d9 cf c7 a3
   e9 b7 79 24 6b 87 8d 05 87 5a a0 c9 e7 d7 e6 7b
   6b 1c 54 5a 2d ce 02 d4 fb b4 48 ab 64 b6 1a 03
   ae bc 10 62 ad 19 f3 39 c4 5e a4 ba d3 2b 93 11
   fc bd f4 31 56 ef 76 1b 59 2c 93 c5 6c de 8b 82
   bc 97 bb 77 a6 2e e8 95 aa 02 19 93 98 eb bc b1
   76 24 da a4 92 76 bb 62 4e e9 38 02 ce 27 63 5e
   a3 9b 36 ae 86 92 c7 63 fe 6d 8f f4 35 a0 3c e5
   f4 db 2a f1 86 3a 60 51 a2 84 61 80 0f a8 64 b3
   f9 15 2e 67 b0 c1 49 c7 64 b1 0b 38 e0 28 dc b5
   1a 3f f4 5e 88 a0 fc 8a 74 92 40 c9 fe 16 e1 37
   2e 75 a4 63 0e bd 07 f3 35 d1 69 45 57 dd c3 0b
   15 a3 c2 ea 8e 04 ac 8d 51 d8 e4 b0 3e 88 eb b6
   a8 88 e2 59 1f 9d c4 a6 90 b2 54 ab d6 5a 9f 25
   33 d3 f1 c8 8c 1b c3 cd 7a d2 ad 00 1f d9 0a 3b
   f5 83 98 29 9f dd aa 1c ae b0 60 10 70 09 f1 3e
   8a 89 9c 03 09 1e ae f4 3b b8 eb e5 70 d8 a3 86
   54 4c ef 6c ba 03 0a 54 70 4d ca 31 89 e5 33 e6
   de 0b 7e 28 8d 9f ad ed 98 d8 9f 24 2c 64 a9 bc
   5e ec 52 cf c1 1d c8 ef 3f 19 97 8e 40 d9 3f 23
   ff 72 dd 9a 55 f9 e4 40 ce 8e ce 88 e7 71 16 28
   87 5a 42 77 b5 a0 ab 3b 95 8c 9c 75 1e bf 07 b5
   8f 56 dc 77 bd c2 33 df bb 87 d9 d4 e2 60 03 2c
   2a af d8 c2 3b 4f f2 b2 87 73 81 10 a5 97 8b ef
   6f d4 82 8a 11 be c0 76 39 cd 70 60 28 1e 91 71
   34 7e 25 5e 4b 69 7d 3f 4e 5e db 12 cc 7c 31 8f
   d4 28 9d 01 61 de 80 b7 b1 b8 10 a0 00 a5 1d 54
   1d 2c ce 05 5b e4 81 59 d0 86 76 50 b1 d6 1b 71
   22 9c 30 95 98 63 7c cb a3 1c 1a 9f cb 2a a8 8c
   c1 a2 42 e7 f9 83 eb 80 90 79 19 91 f6 da 16 6e
   d9 3c 36 d7 c6 8f 54 fc ad a7 4d 52 41 28 f8 fc
   e0 fc b7 eb a6 aa 64 82 e4 a6 41 82 8b df 01 e4
   eb de 6e 75 25 58 e5 40 73 24 f5 6a e9 5f 23 36
   c6 5d ee 90 92 49 20 f3 d5 ac 64 b2 f5 ce fd 4b
   9c 2d 8f d8 f9 ef d6 5b c3 7f 53 fd 06 36 10 49
   92 88 a7 eb f0 b8 41 68 cd 5b 82 85 34 0b 89 2a
   9d d5 3b 6a 08 41 c4 21 64 ed 2d 49 f0 a8 c9 4b
   99 c3 2f 0d 8f d7 a7 01 c8 c4 54 bf 26 56 41 12
   1a d6 c9 04 fb 8b 62 92 46 8d bc 11 15 4f f6 d0
   8c c4 ff 25 03 1f 40 d7 9d 81 c2 40 b3 d9 f9 73
   20 90 7d d7 a4 c6 10 03 40 71 bc 24 d6 fe 3e d3
   bb ff 46 34 16 e6 95 22 05 f1 04 2e 6d a0 b3 61
   34 48 35 66 a7 35 6b 37 39 c2 37 ec 3c b9 2e 36
   fe b0 c5 e6 88 6d ff 24 37 76 cc f0 2a e7 3e cc
   30 cd 38 ae d2 9c af 49 91 b8 b6 af af 1f be ec
   87 c5 95 ac a3 75 6b c3 5d 27 dc 71 10 f3 2c 9d
   ca fc c3 3b 90 2c cf b6 c6 e6 d9 4b dd a6 b6 04
   48 35 4a a1 4d da bc 04 e0 4c c5 a9 94 f2 0f 3e
   b7 ec 83 56 89 e9 61 3b 1b a7 c0 d2 1a 1d 4a 4d
   f0 1e 06 72 12 c4 06 7a fb ba 6f e4 a2 bb 01 ef
   04 97 37 be 04 79 3f ea b2 cf 79 81 0c 38 bd 75
   ed 5c 12 a5 5d a3 4b 01 74 c9 64 d7 d7 f0 91 2f
   0c 89 40 fc af 32 78 e8 b5 1d 0d 64 ce 34 58 01
   46 de 1d a0 d2 f2 48 a6 03 d1 ec 75 bb 79 e1 a7
   5c 08 18 dd 79 19 08 c2 41 7a 84 7a fe b8 36 36
   04 a7 3e 3c 71 6c ee fb 93 fe a5 11 83 44 2b 55
   1d 36 f4 77 89 38 83 dc 4f 11 67 35 24 ef 16 02
   2b 83 e7 aa ac c6 0c 36 a0 87 7e 71 85 99 c7 ce
   e4 cb 72 df 0a f7 63 72 d4 7b 32 ea 4b 0b c5 6a
   aa fb 6d 3f 5b 59 58 2a 0a 98 03 5b 4b 11 6d 49
   3a 2e 37 83 4c c2 2e 5f 9f 22 cc 39 e5 f4 91 24
   1e 77 35 23 16 1d eb 8e e3 45 be e7 d7 e0 53 7a
   99 5d db 42 1c a4 1d f2 f5 f2 ca 58 07 a6 4f a9
   df 62 98 99 bc 82 3e 8b f2 8d 0b e2 12 07 c6 6f
   96 f8 ec 72 00 b2 4e 21 22 9b da f5 f2 70 85 47
   03 5c d9 8b f6 8f 2c c9 b5 fc 18 a9 3e 9f c5 a7
   99 76 a4 4c 88 76 a0 7b 27 bf 40 cd c0 30 7a 46
   06 9d 74 6f 93 98 04 68 d2 28 9a 40 2e 26 b6 f4
   d1 19 c1 55 01 ba 7a 6f 0c c0 90 a7 b1 e9 b1 4b
   83 fe 8f 45 b1 01 d0 f9 8b 3d da fa b2 08 a4 4d
   85 82 d4 d0 89 bd 3d 8b 99 46 9f 3e 34 92 ce 29
   5e fd 3a ac af 7f b6 45 f3 ae e2 64 9f df d3 c2
   86 0d af 75 3b 29 96 2a 04 05 dd d5 25 63 63 2a
   45 a7 c8 8e 72 fd b5 f5 04 d3 74 8d 72 57 b7 19
   89 4c b0 15 78 cd c8 f6 05 8e b1 5a 8a 2a 96 0a
   e4 e5 3f e1 da 21 63 28 8e 2a 21 61 98 a6 56 50
   de 39 63 e0 80 cd 9d 52 34 5e ff b3 d9 44 f1 45
   10 d7 26 8e fe fb 3b 1d 3f a2 b2 46 2b ce 50 08
   2b 49 fa 0e 19 1f 8e 3b b9 fb 6a 17 a7 29 fc 06
   ce 72 48 5c 71 56 f8 8f d0 46 1b 95 6b 78 ed ac
   ed 99 12 6c 64 d8 5f 1b 46 3f 44 f7 6b 18 f1 af
   f8 23 92 2b fb 6c 70 6f 37 ee b3 c3 1c 73 78 9b
   b8 0a ab 92 5d 40 a3 1a 00 0f d3 9b 86 3a e1 7c
   70 eb 68 88 ec d5 a0 f9 50 40 ba c3 67 5d 84 80
   aa a2 ea f4 50 6b 88 69 b8 79 1f 42 23 f7 97 ee
   9e 74 95 23 e9 26 dc 38 d4 7a 05 5e 5a 9d 63 fd
   79 a2 f1 9f f8 d6 28 d5 9a ec 4e ec dc 57 56 1c
   b1 30 76 e8 ac 3f eb 19 bd 36 45 e0 00 ab 99 68
   4b da d5 2d 00 76 49 ab 79 c0 11 8f 1f f0 47 a5
   8f c2 d7 51 e7 9f 66 d6 d0 cf f2 11 f4 0a 27 7f
   f0 36 1a 5f 2d 93 2b 89 39 0b 01 48 9d 12 ff 67
   db db 21 bd 5e a6 1f a0 91 74 27 d4 be cd be eb
   41 ea 83 60 aa 4e 66 55 6c 5a 54 1c df e2 67 73
   b4 ea 3a 73 9c 32 fb 6c 2f 46 b2 9e cf 1b 58 2a
   91 8c 97 e7 e4 c7 4b 6a 92 be 9b e5 ec 02 c2 89
   72 1c 82 cf 74 4c f4 b2 d8 fb 4d 21 24 27 1a 7e
   41 2a 96 5d 65 26 79 c6 ac 80 04 ff 51 57 ec 44
   25 02 9a 83 9a 64 cb df 6b a0 2d 48 d2 bd 29 db
   f8 dd bd 5a 35 70 dd 59 1c 57 de a4 eb 15 26 61
   74 06 6c c9 9d 80 84 8f 38 ec 74 2b b1 77 e2 9c
   32 b0 ca 73 47 7b 93 76 d1 b0 73 f3 fa d3 b8 f3
   73 2e e5 30 52 fd 9a 35 42 67 05 86 02 8e 5f bc
   4e aa ea 49 43 88 4e 50 43 69 c8 12 7d b7 43 d4
   c8 f5 bd 08 cf 58 d2 95 50 a3 cb 51 7c 06 0d 0e
   82 7e 6b f7 f5 28 fb 5d fb ab c5 9d 69 2f 26 b5
   6d 53 e1 3a 9d 07 7e ef 28 cd 77 42 f5 f4 fb b2
   b4 69 c2 f4 b8 eb 11 82 9e 7b ab 06 e2 d7 eb ef
   ba 58 7c 9c de 98 78 f3 b9 9e eb c4 f8 97 fd 85
   a8 de a4 4a 6f 0b 8d 4d f0 11 e7 8f 61 ce e3 d0
   31 77 97 83 34 5e 85 c6 19 9b 28 b9 7e f1 01 a7
   9d 0c 0c 2b a4 95 8b 1a e5 e1 d6 2a a9 f6 7d 68
   fd 0f a7 70 d9 0c 6f 54 f4 0b 5b b4 e2 b7 0b 99
   5a c4 ee 69 77 62 c5 05 24 b5 e1 f2 ed 4c 20 98
   e5 73 b7 08 76 11 a9 af e2 71 50 4f 41 63 62 4c
   1e db e5 55 00 c7 70 c7 89 1f 63 5e 94 39 8a f0
   3b 47 e0 c3 ee c7 24 49 1c 9e 24 99 13 91 04 a8
   c0 c5 86 c2 68 ec 87 70 80 b4 45 28 ca e0 79 ac
   65 a0 af fc 21 1b f8 1d 37 87 4d ec 11 49 f6 f3
   3f 75 6b 26 a1 26 4e 1e 85 6a 10 17 37 0a e1 fa
   13 44 c9 e4 02 a3 06 fd 10 b9 95 69 d5 80 78 bc
   2b 8d aa e6 21 c0 f2 c6 17 a6 cf 7c 99 c8 93 47
   31 20 d5 c2 55 4a 1a 86 3e 6d 17 03 d3 9d ec f1
   a3 6d 13 63 e6 b0 9e 43 65 12 30 7a 3e 30 92 b2
   a1 4f be 62 18 5d 8a 86 5a 35 5e e1 41 36 d1 30
   86 04 3e 57 d9 b7 cb e0 e7 e4 ff e3 56 fb 39 cb
   ca 07 35 92 18 38 da 01 4b 4e ee 6f 53 11 77 7b
   78 b5 3d 69 d7 a7 89 73 24 b6 6e 3e 62 77 90 98
   db d6 2a 0a 80 3f ff 7c 27 be bb 87 5d 36 f5 8c
   42 c4 7f b3 20 1b 47 9b 3d e5 c6 1e 43 6d e8 31
   e7 f5 f9 e9 1a 76 39 8e 28 9f 73 36 0c 30 ab 33
   75 12 3b 59 5c c9 9a ef 62 f4 a3 70 5b 53 89 60
   31 d2 8b 65 9d 21 68 f9 89 93 d5 ab 22 4b 39 1b
   6e 71 7b 92 71 bf f9 7e 22 1d 8f aa 0e 01 43 a1
   71 8a ba 1c cb 0b 1f d1 4a 6a 10 fd 28 18 a9 d5
   40 1c a4 8d 52 f9 94 ac 8a 5f 13 48 e9 a9 4e 5e
   9e ae e0 41 9f 81 d1 e9 89 61 ca e8 5f 25 df df
   9a ad e3 f7 d0 82 08 9e c5 6d 5c b0 53 d8 90 74
   88 3f 6c 2c a7 d8 c7 00 b2 30 f8 6b 5e 2f c2 84
   f0 67 66 b5 ec cc 1a 82 65 7e 05 4e 99 1a f0 75
   5f 57 c2 cf c2 9d f6 3c 80 d9 31 8d 1b 76 e8 b7
   f8 2f 54 50 d9 f6 f9 dc 7a 16 9e 3b 8b 60 6a dd
   a9 82 38 58 50 1b 30 a8 42 33 05 94 da a4 29 11
   cf 11 5b a1 86 66 69 f9 cb 70 be 77 a3 2b f5 89
   d3 e0 0c 58 e8 ba e9 80 f3 bf 7a 55 06 b4 da 31
   1e 6a d5 14 1e 14 ef ea 06 02 5d 10 fb 30 5a 21
   e6 db c1 a9 a6 54 52 06 4b cb a3 0d 65 26 2e 5a
   a8 df 9f 04 25 b2 8b 2f 35 0e 73 d8 08 e3 3b 4d
   03 44 4b 96 97 cb 85 51 af cb af 63 2a 54 31 fe
   1b ad 6f bb 2d c9 0b 4d d4 ef b4 f4 53 a6 60 b1
   ab d7 81 39 04 62 10 a5 9e ec 57 21 9d 86 5a a0
   b3 60 5f 4b 32 2b 5f 39 8e 76 6f c6 9b e4 01 a1
   70 0d 9c 64 39 a9 02 e0 2b 9c ff 1e 2e 89 a3 45
   4a dc c0 ec 9c b1 40 09 25 14 12 b0 4c 1a c4 27
   92 e9 af da 94 ff d8 4e 03 51 37 60 0f c0 d0 fc
   05 38 40 0d ea 5a f6 f5 b8 15 2a 62 cb 21 37 24
   6b a9 cf 0b 38 51 34 36 86 42 ab ca 96 15 2d 83
   5a 3b bd 58 27 b7 ed d5 d0 c2 36 78 20 3d 14 82
   2e d0 db a3 09 6f 1c 0c 2a fe 92 63 86 60 20 c4
   55 7f 1c 95 ae b0 b6 11 85 b2 d1 6d 1a 2e c1 82
   86 b5 5b d6 1d b0 09 92 aa 1b b0 94 93 37 20 9b
   8a f1 96 6c 87 6c 4c 22 70 bf e1 1d 48 4c 53 f5
   27 85 6d f4 2a 0d 79 49 b3 e9 ad 1e d4 83 db e8
   65 15 53 dd bf 0a 26 29 b5 7f 12 cd 61 d0 13 2f
   2a 5e ee d2 b0 aa 64 8b 09 c6 66 ba 09 0b 87 e7
   0a e1 80 3c 3e ab 90 93 95 b4 4a 54 b9 35 56 23
   a7 f0 f5 20 c8 40 2e 2f b0 c1 c3 77 c5 ee c9 9e
   1e fb 2a 5d c3 f3 7e 18 0e 0a 94 47 ed 54 9b 1b
   c1 60 f6 a4 f5 05 bc 3a 69 9d ac 13 d5 09 e9 1f
   a3 82 33 b2 35 6f 34 9b 5e cf 17 16 51 cb 53 97
   03 63 1f 14 da 45 5c b0 64 36 ce b8 6e 84 f4 1d
   f3 86 2c b1 f4 9d 12 53 5f d2 68 71 f6 9b e4 48
   86 d2 2e e8 4f 58 06 6d 40 a0 0d f6 0f 08 52 ef
   42 93 b6 ee a7 ed 7a 0e e6 c4 72 67 76 a7 82 77
   a7 09 54 3f d4 3c fd 82 f8 81 b3 97 81 fa 83 41
   27 d8 c4 7b 82 7e 01 1e 24 f4 c6 ba e0 33 a6 e5
   4b 85 01 b0 30 fe d1 2b 0c 58 47 35 a5 7b 80 9c
   4a c8 87 15 bb d4 f6 04 01 3b e5 0e 16 4f e0 cf
   ff c4 3d 71 3c c7 32 e8 e4 af ec 6a 75 e2 56 21
   d5 97 63 c2 5d d6 5c 24 4d 6f bf 6b b6 88 d7 0e
   27 70 fe b8 59 2b e0 a1 d9 cd ed 95 5c 71 cb 4c
   a7 c9 7c e5 fe cb 4f 8e 10 f9 7a 6e ec 39 f9 c4
   1e 6d b9 31 71 17 f8 f4 dd 43 ee 1e e1 80 34 8e
   fd e9 cf d8 73 5c e2 9d 13 22 5e 2a b5 2f fd 4b
   47 61 98 5c 4e 4e b9 70 92 47 d6 fe 6a aa 15 1f
   42 20 75 79 72 c9 2a 7f 8b b1 79 38 ff e7 a5 56
   2d 2d 99 fa 9c 46 4c 12 b6 46 4a d4 39 8e 68 2a
   c7 91 56 20 85 26 d9 02 f8 47 56 bd 06 c2 15 6f
   5b 20 2a 31 cf ec 12 29 db 49 d5 63 6f ac 28 67
   01 71 ff eb 08 ce 37 bc 29 c1 96 41 67 86 52 a5
   86 97 e0 eb 2d 44 80 63 74 5c 64 76 3d c8 a3 e4
   c1 b5 71 c7 7a 0a 2b 72 66 07 44 4a 30 1b d5 5d
   c4 ff 39 bc 06 59 db 98 68 9c 28 25 e7 f3 d9 ba
   db 34 62 f2 3d 56 e4 34 6b 25 33 d2 2e 49 ed 18
   42 e4 6d 25 c7 e7 b8 3f 15 bd d6 12 e1 e1 d5 70
   e9 e6 62 02 d4 19 f1 f9 67 33 d2 67 16 ef fa f1
   36 eb c6 5e 25 a5 ce 53 6e f7 c1 bb 00 c0 13 68
   88 c0 b9 aa a7 29 0a 6e 21 e3 ab ed b9 d4 cb 2d
   8c 0d 78 4a bc 0f b0 5d 38 2b 71 07 1d e0 95 ed
   aa 62 ab 4b 61 9d bc d1 e5 d2 65 aa 16 a6 13 cd
   99 92 be 40 14 ad 90 e7 c9 f1 21 d2 f3 e5 85 17
   f5 1f d9 86 99 36 2c df d0 df 45 ee 71 7e 52 77
   02 dd 5c 22 81 12 ac a2 25 ee 1e f4 45 f5 f3 c5
   58 fb b1 30 c2 db 54 68 2c a8 8c c1 0a 1a 0f 8f
   32 90 ca 35 46 5c 00 9d 4c a4 2f 5e d6 c9 cd 43
   bd 92 46 c3 2e 6b ca 11 45 d3 88 1f 3f b1 50 85
   48 63 b2 e2 3d 2d 03 f8 18 5b 5f 5a 2d 01 88 4f
   31 4e 41 aa 26 85 fc 47 0d ee 07 f6 59 b8 fb 69
   36 a5 41 28 63 44 61 1d c3 22 9b 4e 08 51 8e e4
   5e 51 77 96 8c 0d 40 d8 d8 2c 1c 8f 4a 43 1e a2
   c9 e0 86 40 b4 31 b9 f5 20 8f 3f aa 5e 16 cb 6f
   ec 3c af d9 cd 6d 6a 5c 1a 4e 56 81 67 fa 76 dc
   0b 47 3b 2f bd cf 73 4f 18 28 56 11 8a fe f8 53
   60 0d 12 21 7c 37 45 2b 03 f0 27 fb 78 7c 05 8d
   ca 2f aa 0d 87 f0 f9 22 69 a8 6f cc ae db c8 2f
   58 eb af 0e 6a 7e 31 65 f1 03 27 97 2c 19 bf 71
   f3 3e 6a ad 66 fc 42 91 36 c7 82 f6 da 9a af 3c
   ff d1 14 95 a7 c2 96 a1 0e 72 a5 e3 ad 4b 16 af
   a2 c5 4a 74 27 78 fe ba ff be 2c ca 44 b2 e9 f1
   af f1 d3 b7 94 95 6a 22 81 36 ce 32 95 73 f8 1f
   a5 c7 d8 ce 55 f2 32 23 d2 21 c0 d2 dc 4b a4 7b
   4e 5e 3d d8 22 d4 75 93 fc 94 c6 4f e5 64 6d 36
   6b 32 47 d0 39 6d 8e e6 3c ab 20 da d4 f6 bf c6
   f6 da 8e 72 f7 cb da 13 c2 37 b9 ed 0e 1c 0b a2
   fe b8 82 ba be b0 04 eb 9d 94 74 78 00 6d 97 fb
   b1 c4 9d 40 69 90 76 1b af 18 ad fd c6 57 21 43
   eb 94 42 08 04 5d 46 c0 f6 8b c2 92 4a 21 20 0d
   9c 93 0a dd 0e 87 26 73 92 a0 d0 d2 80 ff 5f b7
   26 1d b9 27 28 5c 37 82 2f a3 7c 5f 85 f2 60 97
   f6 89 de ca 45 db ec a3 d7 f9 12 f4 1d 85 07 65
   b5 43 80 b1 7b d0 8c 49 d2 e4 95 8c 11 49 8d 66
   02 37 9e 64 a6 66 86 17 f9 86 f0 ea 25 bf b3 16
   38 5d 96 a7 5a 0c 7b 4b a3 9d 37 3f 03 b6 33 26
   31 5d 6d 7e 23 74 53 9d 44 70 c3 40 90 46 c7 49
   53 e4 57 75 d5 fb 80 1a cf 3e aa 4f 82 c9 56 6a
   47 cf 52 51 02 72 8e 40 be 6f 43 13 2e e0 2c d5
   1a a1 a1
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
   0a 43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 74
   65 78 74 2f 68 74 6d 6c 0d 0a 0d 0a 3c 48 54 4d
   4c 3e 3c 42 4f 44 59 20 42 47 43 4f 4c 4f 52 3d
   22 23 66 66 66 66 66 66 22 3e 0a 3c 70 72 65 3e
   0a 0a 73 5f 73 65 72 76 65 72 20 2d 63 65 72 74
   20 73 65 72 76 65 72 2e 63 72 74 20 2d 6b 65 79
   20 73 65 72 76 65 72 2e 6b 65 79 20 2d 77 77 77
   20 2d 70 6f 72 74 20 38 34 30 33 20 2d 43 41 66
   69 6c 65 20 63 6c 69 65 6e 74 2e 63 72 74 20 2d
   64 65 62 75 67 20 2d 6b 65 79 6c 6f 67 66 69 6c
   65 20 6b 65 79 2e 74 78 74 20 2d 6d 73 67 20 2d
   73 74 61 74 65 20 2d 74 6c 73 65 78 74 64 65 62
   75 67 20 2d 56 65 72 69 66 79 20 31 20 0a 53 65
   63 75 72 65 20 52 65 6e 65 67 6f 74 69 61 74 69
   6f 6e 20 49 53 20 4e 4f 54 20 73 75 70 70 6f 72
   74 65 64 0a 43 69 70 68 65 72 73 20 73 75 70 70
   6f 72 74 65 64 20 69 6e 20 73 5f 73 65 72 76 65
   72 20 62 69 6e 61 72 79 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 32 35 36
   5f 47 43 4d 5f 53 48 41 33 38 34 20 20 20 20 54
   4c 53 76 31 2e 33 20 20 20 20 3a 54 4c 53 5f 43
   48 41 43 48 41 32 30 5f 50 4f 4c 59 31 33 30 35
   5f 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 31 32 38
   5f 47 43 4d 5f 53 48 41 32 35 36 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 32 35 36 2d 47 43
   4d 2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d
   41 45 53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48
   45 2d 52 53 41 2d 41 45 53 32 35 36 2d 47 43 4d
   2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 45 43 44 48 45 2d 45 43 44 53 41
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45
   43 44 48 45 2d 52 53 41 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33 30
   35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 45 43 44 53 41 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20 20
   3a 44 48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 45 43
   44 53 41 2d 41 45 53 32 35 36 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 52 53 41 2d 41 45 53 32 35 36 2d 53
   48 41 33 38 34 20 20 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 44 48 45 2d 52 53 41 2d 41 45 53
   32 35 36 2d 53 48 41 32 35 36 20 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 32 35 36 20 0a 54 4c 53 76 31 2e 32 20 20 20
   20 3a 45 43 44 48 45 2d 52 53 41 2d 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   41 45 53 31 32 38 2d 53 48 41 32 35 36 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 45
   43 44 48 45 2d 45 43 44 53 41 2d 41 45 53 32 35
   36 2d 53 48 41 20 20 20 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d 41
   45 53 32 35 36 2d 53 48 41 20 20 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   52 53 41 2d 41 45 53 32 35 36 2d 53 48 41 20 20
   20 20 20 20 20 20 54 4c 53 76 31 2e 30 20 20 20
   20 3a 45 43 44 48 45 2d 45 43 44 53 41 2d 41 45
   53 31 32 38 2d 53 48 41 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 53 48 41 20 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 44
   48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45
   53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38 34 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53
   48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32 20 20
   20 20 3a 52 53 41 2d 50 53 4b 2d 43 48 41 43 48
   41 32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53
   76 31 2e 32 20 20 20 20 3a 44 48 45 2d 50 53 4b
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a
   45 43 44 48 45 2d 50 53 4b 2d 43 48 41 43 48 41
   32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 41 45 53 32 35 36 2d 47
   43 4d 2d 53 48 41 33 38 34 20 20 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53 48
   41 33 38 34 20 20 20 20 20 54 4c 53 76 31 2e 32
   20 20 20 20 3a 50 53 4b 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 20 20 20 20 0a
   54 4c 53 76 31 2e 32 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53
   48 41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 41 45 53 32 35 36 2d 53 48 41
   32 35 36 20 20 20 20 20 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 20 20 20 20
   20 20 20 20 20 20 0a 54 4c 53 76 31 2e 30 20 20
   20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 54
   4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48 45
   2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d
   53 48 41 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 52 53 41 2d 41 45 53 2d 32 35
   36 2d 43 42 43 2d 53 48 41 20 20 20 53 53 4c 76
   33 20 20 20 20 20 20 3a 53 52 50 2d 41 45 53 2d
   32 35 36 2d 43 42 43 2d 53 48 41 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 52
   53 41 2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42
   43 2d 53 48 41 33 38 34 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 0a 53 53 4c
   76 33 20 20 20 20 20 20 3a 41 45 53 32 35 36 2d
   53 48 41 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 30 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53 48
   41 33 38 34 20 20 20 20 20 0a 53 53 4c 76 33 20
   20 20 20 20 20 3a 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48
   45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43
   2d 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41
   45 53 31 32 38 2d 43 42 43 2d 53 48 41 20 20 53
   53 4c 76 33 20 20 20 20 20 20 3a 53 52 50 2d 52
   53 41 2d 41 45 53 2d 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 41 45 53 2d 31 32 38 2d 43 42
   43 2d 53 48 41 20 20 20 20 20 20 20 54 4c 53 76
   31 2e 30 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d
   41 45 53 31 32 38 2d 43 42 43 2d 53 48 41 32 35
   36 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 44
   48 45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42
   43 2d 53 48 41 32 35 36 20 53 53 4c 76 33 20 20
   20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 41 45 53 31 32 38 2d 53 48 41 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 32 35 36 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 2d 2d 2d 0a 43 69
   70 68 65 72 73 20 63 6f 6d 6d 6f 6e 20 62 65 74
   77 65 65 6e 20 62 6f 74 68 20 53 53 4c 20 65 6e
   64 20 70 6f 69 6e 74 73 3a 0a 54 4c 53 5f 41 45
   53 5f 31 32 38 5f 47 43 4d 5f 53 48 41 32 35 36
   20 20 20 20 20 54 4c 53 5f 43 48 41 43 48 41 32
   30 5f 50 4f 4c 59 31 33 30 35 5f 53 48 41 32 35
   36 0a 53 69 67 6e 61 74 75 72 65 20 41 6c 67 6f
   72 69 74 68 6d 73 3a 20 52 53 41 2b 53 48 41 32
   35 36 3a 52 53 41 2b 53 48 41 33 38 34 3a 52 53
   41 2b 53 48 41 35 31 32 3a 45 43 44 53 41 2b 53
   48 41 32 35 36 3a 45 43 44 53 41 2b 53 48 41 33
   38 34 3a 45 43 44 53 41 2b 53 48 41 35 31 32 3a
   52 53 41 2d 50 53 53 2b 53 48 41 32 35 36 3a 52
   53 41 2d 50 53 53 2b 53 48 41 33 38 34 3a 52 53
   41 2d 50 53 53 2b 53 48 41 32 35 36 3a 52 53 41
   2d 50 53 53 2b 53 48 41 33 38 34 3a 52 53 41 2d
   50 53 53 2b 53 48 41 32 35 36 3a 45 64 32 35 35
   31 39 3a 45 64 34 34 38 3a 52 53 41 2b 53 48 41
   31 0a 53 68 61 72 65 64 20 53 69 67 6e 61 74 75
   72 65 20 41 6c 67 6f 72 69 74 68 6d 73 3a 20 52
   53 41 2b 53 48 41 32 35 36 3a 52 53 41 2b 53 48
   41 33 38 34 3a 52 53 41 2b 53 48 41 35 31 32 3a
   45 43 44 53 41 2b 53 48 41 32 35 36 3a 45 43 44
   53 41 2b 53 48 41 33 38 34 3a 45 43 44 53 41 2b
   53 48 41 35 31 32 3a 52 53 41 2d 50 53 53 2b 53
   48 41 32 35 36 3a 52 53 41 2d 50 53 53 2b 53 48
   41 33 38 34 3a 52 53 41 2d 50 53 53 2b 53 48 41
   32 35 36 3a 52 53 41 2d 50 53 53 2b 53 48 41 33
   38 34 3a 52 53 41 2d 50 53 53 2b 53 48 41 32 35
   36 3a 45 64 32 35 35 31 39 3a 45 64 34 34 38 0a
   50 65 65 72 20 73 69 67 6e 61 74 75 72 65 20 74
   79 70 65 3a 20 45 64 32 35 35 31 39 0a 53 75 70
   70 6f 72 74 65 64 20 67 72 6f 75 70 73 3a 20 78
   32 35 35 31 39 0a 53 68 61 72 65 64 20 67 72 6f
   75 70 73 3a 20 78 32 35 35 31 39 0a 2d 2d 2d 0a
   4e 65 77 2c 20 54 4c 53 76 31 2e 33 2c 20 43 69
   70 68 65 72 20 69 73 20 54 4c 53 5f 41 45 53 5f
   31 32 38 5f 47 43 4d 5f 53 48 41 32 35 36 0a 53
   53 4c 2d 53 65 73 73 69 6f 6e 3a 0a 20 20 20 20
   50 72 6f 74 6f 63 6f 6c 20 20 3a 20 54 4c 53 76
   31 2e 33 0a 20 20 20 20 43 69 70 68 65 72 20 20
   20 20 3a 20 54 4c 53 5f 41 45 53 5f 31 32 38 5f
   47 43 4d 5f 53 48 41 32 35 36 0a 20 20 20 20 53
   65 73 73 69 6f 6e 2d 49 44 3a 20 45 38 41 38 38
   37 44 36 44 41 32 33 30 32 31 39 31 36 42 35 37
   46 37 35 31 46 32 37 36 36 33 42 34 35 41 43 33
   45 45 38 44 37 45 44 31 38 30 36 31 30 44 36 38
   41 35 32 45 38 36 31 32 36 39 36 0a 20 20 20 20
   53 65 73 73 69 6f 6e 2d 49 44 2d 63 74 78 3a 20
   30 31 30 30 30 30 30 30 0a 20 20 20 20 52 65 73
   75 6d 70 74 69 6f 6e 20 50 53 4b 3a 20 38 46 46
   37 45 46 43 36 45 39 35 32 45 46 36 45 38 36 43
   30 44 39 45 42 31 32 46 46 39 43 36 32 30 39 33
   42 44 45 34 43 37 35 39 42 39 46 43 32 31 42 46
   39 35 46 37 45 46 36 30 44 43 41 36 39 0a 20 20
   20 20 50 53 4b 20 69 64 65 6e 74 69 74 79 3a 20
   4e 6f 6e 65 0a 20 20 20 20 50 53 4b 20 69 64 65
   6e 74 69 74 79 20 68 69 6e 74 3a 20 4e 6f 6e 65
   0a 20 20 20 20 53 52 50 20 75 73 65 72 6e 61 6d
   65 3a 20 4e 6f 6e 65 0a 20 20 20 20 53 74 61 72
   74 20 54 69 6d 65 3a 20 31 36 38 30 36 32 35 38
   31 37 0a 20 20 20 20 54 69 6d 65 6f 75 74 20 20
   20 3a 20 37 32 30 30 20 28 73 65 63 29 0a 20 20
   20 20 56 65 72 69 66 79 20 72 65 74 75 72 6e 20
   63 6f 64 65 3a 20 31 38 20 28 73 65 6c 66 2d 73
   69 67 6e 65 64 20 63 65 72 74 69 66 69 63 61 74
   65 29 0a 20 20 20 20 45 78 74 65 6e 64 65 64 20
   6d 61 73 74 65 72 20 73 65 63 72 65 74 3a 20 6e
   6f 0a 20 20 20 20 4d 61 78 20 45 61 72 6c 79 20
   44 61 74 61 3a 20 30 0a 2d 2d 2d 0a 20 20 20 30
   20 69 74 65 6d 73 20 69 6e 20 74 68 65 20 73 65
   73 73 69 6f 6e 20 63 61 63 68 65 0a 20 20 20 30
   20 63 6c 69 65 6e 74 20 63 6f 6e 6e 65 63 74 73
   20 28 53 53 4c 5f 63 6f 6e 6e 65 63 74 28 29 29
   0a 20 20 20 30 20 63 6c 69 65 6e 74 20 72 65 6e
   65 67 6f 74 69 61 74 65 73 20 28 53 53 4c 5f 63
   6f 6e 6e 65 63 74 28 29 29 0a 20 20 20 30 20 63
   6c 69 65 6e 74 20 63 6f 6e 6e 65 63 74 73 20 74
   68 61 74 20 66 69 6e 69 73 68 65 64 0a 20 20 20
   36 20 73 65 72 76 65 72 20 61 63 63 65 70 74 73
   20 28 53 53 4c 5f 61 63 63 65 70 74 28 29 29 0a
   20 20 20 30 20 73 65 72 76 65 72 20 72 65 6e 65
   67 6f 74 69 61 74 65 73 20 28 53 53 4c 5f 61 63
   63 65 70 74 28 29 29 0a 20 20 20 36 20 73 65 72
   76 65 72 20 61 63 63 65 70 74 73 20 74 68 61 74
   20 66 69 6e 69 73 68 65 64 0a 20 20 20 32 20 73
   65 73 73 69 6f 6e 20 63 61 63 68 65 20 68 69 74
   73 0a 20 20 20 30 20 73 65 73 73 69 6f 6e 20 63
   61 63 68 65 20 6d 69 73 73 65 73 0a 20 20 20 30
   20 73 65 73 73 69 6f 6e 20 63 61 63 68 65 20 74
   69 6d 65 6f 75 74 73 0a 20 20 20 30 20 63 61 6c
   6c 62 61 63 6b 20 63 61 63 68 65 20 68 69 74 73
   0a 20 20 20 30 20 63 61 63 68 65 20 66 75 6c 6c
   20 6f 76 65 72 66 6c 6f 77 73 20 28 31 32 38 20
   61 6c 6c 6f 77 65 64 29 0a 2d 2d 2d 0a 43 6c 69
   65 6e 74 20 63 65 72 74 69 66 69 63 61 74 65 0a
   43 65 72 74 69 66 69 63 61 74 65 3a 0a 20 20 20
   20 44 61 74 61 3a 0a 20 20 20 20 20 20 20 20 56
   65 72 73 69 6f 6e 3a 20 33 20 28 30 78 32 29 0a
   20 20 20 20 20 20 20 20 53 65 72 69 61 6c 20 4e
   75 6d 62 65 72 3a 0a 20 20 20 20 20 20 20 20 20
   20 20 20 32 36 3a 33 66 3a 35 36 3a 63 35 3a 37
   33 3a 66 36 3a 36 62 3a 33 36 3a 64 38 3a 39 61
   3a 30 66 3a 63 37 3a 64 62 3a 61 66 3a 34 61 3a
   63 66 3a 66 37 3a 61 33 3a 37 32 3a 30 66 0a 20
   20 20 20 20 20 20 20 53 69 67 6e 61 74 75 72 65
   20 41 6c 67 6f 72 69 74 68 6d 3a 20 45 44 32 35
   35 31 39 0a 20 20 20 20 20 20 20 20 49 73 73 75
   65 72 3a 20 43 4e 3d 63 72 79 70 74 6f 67 72 61
   70 68 79 2e 69 6f 0a 20 20 20 20 20 20 20 20 56
   61 6c 69 64 69 74 79 0a 20 20 20 20 20 20 20 20
   20 20 20 20 4e 6f 74 20 42 65 66 6f 72 65 3a 20
   4d 61 72 20 32 33 20 32 30 3a 31 35 3a 31 34 20
   32 30 32 33 20 47 4d 54 0a 20 20 20 20 20 20 20
   20 20 20 20 20 4e 6f 74 20 41 66 74 65 72 20 3a
   20 41 70 72 20 32 33 20 32 30 3a 31 35 3a 31 34
   20 32 30 32 33 20 47 4d 54 0a 20 20 20 20 20 20
   20 20 53 75 62 6a 65 63 74 3a 20 43 4e 3d 63 72
   79 70 74 6f 67 72 61 70 68 79 2e 69 6f 0a 20 20
   20 20 20 20 20 20 53 75 62 6a 65 63 74 20 50 75
   62 6c 69 63 20 4b 65 79 20 49 6e 66 6f 3a 0a 20
   20 20 20 20 20 20 20 20 20 20 20 50 75 62 6c 69
   63 20 4b 65 79 20 41 6c 67 6f 72 69 74 68 6d 3a
   20 45 44 32 35 35 31 39 0a 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 45 44 32 35 35 31 39
   20 50 75 62 6c 69 63 2d 4b 65 79 3a 0a 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 70 75 62
   3a 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 20 36 66 3a 37 65 3a 62 38 3a 66
   35 3a 61 33 3a 32 38 3a 61 34 3a 62 39 3a 63 35
   3a 35 36 3a 66 63 3a 33 33 3a 38 38 3a 39 34 3a
   39 36 3a 0a 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 35 31 3a 34 62 3a 61 33
   3a 31 34 3a 61 36 3a 63 63 3a 61 66 3a 38 36 3a
   37 34 3a 35 38 3a 37 63 3a 32 34 3a 39 33 3a 61
   64 3a 35 63 3a 0a 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 61 36 3a 64 38 0a
   20 20 20 20 20 20 20 20 58 35 30 39 76 33 20 65
   78 74 65 6e 73 69 6f 6e 73 3a 0a 20 20 20 20 20
   20 20 20 20 20 20 20 58 35 30 39 76 33 20 53 75
   62 6a 65 63 74 20 41 6c 74 65 72 6e 61 74 69 76
   65 20 4e 61 6d 65 3a 20 0a 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 44 4e 53 3a 63 72 79
   70 74 6f 67 72 61 70 68 79 2e 69 6f 0a 20 20 20
   20 20 20 20 20 20 20 20 20 58 35 30 39 76 33 20
   4b 65 79 20 55 73 61 67 65 3a 20 0a 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 44 69 67 69
   74 61 6c 20 53 69 67 6e 61 74 75 72 65 2c 20 4e
   6f 6e 20 52 65 70 75 64 69 61 74 69 6f 6e 2c 20
   44 61 74 61 20 45 6e 63 69 70 68 65 72 6d 65 6e
   74 2c 20 43 65 72 74 69 66 69 63 61 74 65 20 53
   69 67 6e 0a 20 20 20 20 20 20 20 20 20 20 20 20
   58 35 30 39 76 33 20 42 61 73 69 63 20 43 6f 6e
   73 74 72 61 69 6e 74 73 3a 20 63 72 69 74 69 63
   61 6c 0a 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 43 41 3a 46 41 4c 53 45 0a 20 20 20 20
   53 69 67 6e 61 74 75 72 65 20 41 6c 67 6f 72 69
   74 68 6d 3a 20 45 44 32 35 35 31 39 0a 20 20 20
   20 53 69 67 6e 61 74 75 72 65 20 56 61 6c 75 65
   3a 0a 20 20 20 20 20 20 20 20 34 39 3a 64 32 3a
   34 63 3a 30 37 3a 35 63 3a 39 33 3a 61 65 3a 61
   61 3a 39 38 3a 30 33 3a 36 61 3a 64 36 3a 65 34
   3a 32 35 3a 36 35 3a 37 34 3a 34 35 3a 62 64 3a
   0a 20 20 20 20 20 20 20 20 34 65 3a 31 35 3a 66
   62 3a 31 34 3a 66 64 3a 38 64 3a 35 37 3a 39 62
   3a 38 30 3a 63 35 3a 66 35 3a 38 31 3a 39 35 3a
   39 66 3a 61 30 3a 61 61 3a 37 35 3a 30 34 3a 0a
   20 20 20 20 20 20 20 20 66 31 3a 66 38 3a 36 63
   3a 66 61 3a 66 63 3a 30 65 3a 62 64 3a 65 65 3a
   33 61 3a 66 37 3a 66 61 3a 65 63 3a 64 33 3a 36
   34 3a 66 66 3a 38 36 3a 32 37 3a 61 36 3a 0a 20
   20 20 20 20 20 20 20 30 64 3a 34 38 3a 64 64 3a
   37 63 3a 63 35 3a 37 32 3a 36 62 3a 36 34 3a 38
   66 3a 30 39 0a 2d 2d 2d 2d 2d 42 45 47 49 4e 20
   43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d
   0a 4d 49 49 42 4c 6a 43 42 34 61 41 44 41 67 45
   43 41 68 51 6d 50 31 62 46 63 2f 5a 72 4e 74 69
   61 44 38 66 62 72 30 72 50 39 36 4e 79 44 7a 41
   46 42 67 4d 72 5a 58 41 77 47 6a 45 59 4d 42 59
   47 0a 41 31 55 45 41 77 77 50 59 33 4a 35 63 48
   52 76 5a 33 4a 68 63 47 68 35 4c 6d 6c 76 4d 42
   34 58 44 54 49 7a 4d 44 4d 79 4d 7a 49 77 4d 54
   55 78 4e 46 6f 58 44 54 49 7a 4d 44 51 79 4d 7a
   49 77 0a 4d 54 55 78 4e 46 6f 77 47 6a 45 59 4d
   42 59 47 41 31 55 45 41 77 77 50 59 33 4a 35 63
   48 52 76 5a 33 4a 68 63 47 68 35 4c 6d 6c 76 4d
   43 6f 77 42 51 59 44 4b 32 56 77 41 79 45 41 62
   33 36 34 0a 39 61 4d 6f 70 4c 6e 46 56 76 77 7a
   69 4a 53 57 55 55 75 6a 46 4b 62 4d 72 34 5a 30
   57 48 77 6b 6b 36 31 63 70 74 69 6a 4f 54 41 33
   4d 42 6f 47 41 31 55 64 45 51 51 54 4d 42 47 43
   44 32 4e 79 0a 65 58 42 30 62 32 64 79 59 58 42
   6f 65 53 35 70 62 7a 41 4c 42 67 4e 56 48 51 38
   45 42 41 4d 43 41 74 51 77 44 41 59 44 56 52 30
   54 41 51 48 2f 42 41 49 77 41 44 41 46 42 67 4d
   72 5a 58 41 44 0a 51 51 42 4a 30 6b 77 48 58 4a
   4f 75 71 70 67 44 61 74 62 6b 4a 57 56 30 52 62
   31 4f 46 66 73 55 2f 59 31 58 6d 34 44 46 39 59
   47 56 6e 36 43 71 64 51 54 78 2b 47 7a 36 2f 41
   36 39 37 6a 72 33 0a 2b 75 7a 54 5a 50 2b 47 4a
   36 59 4e 53 4e 31 38 78 58 4a 72 5a 49 38 4a 0a
   2d 2d 2d 2d 2d 45 4e 44 20 43 45 52 54 49 46 49
   43 41 54 45 2d 2d 2d 2d 2d 0a 3c 2f 70 72 65 3e
   3c 2f 42 4f 44 59 3e 3c 2f 48 54 4d 4c 3e 0d 0a
   0d 0a 17
     - Inner TLS message 10 server_application_data_(decrypted): Container: 
       content = b'HTTP/1.0 200 ok\r'... (truncated, total 5906)
       type = (enum) application_data 23
       zeros = None
     - TLS message 10 server_application_data [5906 bytes]:
   48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d
   0a 43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 74
   65 78 74 2f 68 74 6d 6c 0d 0a 0d 0a 3c 48 54 4d
   4c 3e 3c 42 4f 44 59 20 42 47 43 4f 4c 4f 52 3d
   22 23 66 66 66 66 66 66 22 3e 0a 3c 70 72 65 3e
   0a 0a 73 5f 73 65 72 76 65 72 20 2d 63 65 72 74
   20 73 65 72 76 65 72 2e 63 72 74 20 2d 6b 65 79
   20 73 65 72 76 65 72 2e 6b 65 79 20 2d 77 77 77
   20 2d 70 6f 72 74 20 38 34 30 33 20 2d 43 41 66
   69 6c 65 20 63 6c 69 65 6e 74 2e 63 72 74 20 2d
   64 65 62 75 67 20 2d 6b 65 79 6c 6f 67 66 69 6c
   65 20 6b 65 79 2e 74 78 74 20 2d 6d 73 67 20 2d
   73 74 61 74 65 20 2d 74 6c 73 65 78 74 64 65 62
   75 67 20 2d 56 65 72 69 66 79 20 31 20 0a 53 65
   63 75 72 65 20 52 65 6e 65 67 6f 74 69 61 74 69
   6f 6e 20 49 53 20 4e 4f 54 20 73 75 70 70 6f 72
   74 65 64 0a 43 69 70 68 65 72 73 20 73 75 70 70
   6f 72 74 65 64 20 69 6e 20 73 5f 73 65 72 76 65
   72 20 62 69 6e 61 72 79 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 32 35 36
   5f 47 43 4d 5f 53 48 41 33 38 34 20 20 20 20 54
   4c 53 76 31 2e 33 20 20 20 20 3a 54 4c 53 5f 43
   48 41 43 48 41 32 30 5f 50 4f 4c 59 31 33 30 35
   5f 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 31 32 38
   5f 47 43 4d 5f 53 48 41 32 35 36 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 32 35 36 2d 47 43
   4d 2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d
   41 45 53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48
   45 2d 52 53 41 2d 41 45 53 32 35 36 2d 47 43 4d
   2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 45 43 44 48 45 2d 45 43 44 53 41
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45
   43 44 48 45 2d 52 53 41 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33 30
   35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 45 43 44 53 41 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20 20
   3a 44 48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 45 43
   44 53 41 2d 41 45 53 32 35 36 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 52 53 41 2d 41 45 53 32 35 36 2d 53
   48 41 33 38 34 20 20 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 44 48 45 2d 52 53 41 2d 41 45 53
   32 35 36 2d 53 48 41 32 35 36 20 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 32 35 36 20 0a 54 4c 53 76 31 2e 32 20 20 20
   20 3a 45 43 44 48 45 2d 52 53 41 2d 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   41 45 53 31 32 38 2d 53 48 41 32 35 36 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 45
   43 44 48 45 2d 45 43 44 53 41 2d 41 45 53 32 35
   36 2d 53 48 41 20 20 20 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d 41
   45 53 32 35 36 2d 53 48 41 20 20 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   52 53 41 2d 41 45 53 32 35 36 2d 53 48 41 20 20
   20 20 20 20 20 20 54 4c 53 76 31 2e 30 20 20 20
   20 3a 45 43 44 48 45 2d 45 43 44 53 41 2d 41 45
   53 31 32 38 2d 53 48 41 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 53 48 41 20 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 44
   48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45
   53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38 34 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53
   48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32 20 20
   20 20 3a 52 53 41 2d 50 53 4b 2d 43 48 41 43 48
   41 32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53
   76 31 2e 32 20 20 20 20 3a 44 48 45 2d 50 53 4b
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a
   45 43 44 48 45 2d 50 53 4b 2d 43 48 41 43 48 41
   32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 41 45 53 32 35 36 2d 47
   43 4d 2d 53 48 41 33 38 34 20 20 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53 48
   41 33 38 34 20 20 20 20 20 54 4c 53 76 31 2e 32
   20 20 20 20 3a 50 53 4b 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 20 20 20 20 0a
   54 4c 53 76 31 2e 32 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53
   48 41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 41 45 53 32 35 36 2d 53 48 41
   32 35 36 20 20 20 20 20 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 20 20 20 20
   20 20 20 20 20 20 0a 54 4c 53 76 31 2e 30 20 20
   20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 54
   4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48 45
   2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d
   53 48 41 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 52 53 41 2d 41 45 53 2d 32 35
   36 2d 43 42 43 2d 53 48 41 20 20 20 53 53 4c 76
   33 20 20 20 20 20 20 3a 53 52 50 2d 41 45 53 2d
   32 35 36 2d 43 42 43 2d 53 48 41 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 52
   53 41 2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42
   43 2d 53 48 41 33 38 34 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 0a 53 53 4c
   76 33 20 20 20 20 20 20 3a 41 45 53 32 35 36 2d
   53 48 41 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 30 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53 48
   41 33 38 34 20 20 20 20 20 0a 53 53 4c 76 33 20
   20 20 20 20 20 3a 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48
   45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43
   2d 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41
   45 53 31 32 38 2d 43 42 43 2d 53 48 41 20 20 53
   53 4c 76 33 20 20 20 20 20 20 3a 53 52 50 2d 52
   53 41 2d 41 45 53 2d 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 41 45 53 2d 31 32 38 2d 43 42
   43 2d 53 48 41 20 20 20 20 20 20 20 54 4c 53 76
   31 2e 30 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d
   41 45 53 31 32 38 2d 43 42 43 2d 53 48 41 32 35
   36 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 44
   48 45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42
   43 2d 53 48 41 32 35 36 20 53 53 4c 76 33 20 20
   20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 41 45 53 31 32 38 2d 53 48 41 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 32 35 36 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 2d 2d 2d 0a 43 69
   70 68 65 72 73 20 63 6f 6d 6d 6f 6e 20 62 65 74
   77 65 65 6e 20 62 6f 74 68 20 53 53 4c 20 65 6e
   64 20 70 6f 69 6e 74 73 3a 0a 54 4c 53 5f 41 45
   53 5f 31 32 38 5f 47 43 4d 5f 53 48 41 32 35 36
   20 20 20 20 20 54 4c 53 5f 43 48 41 43 48 41 32
   30 5f 50 4f 4c 59 31 33 30 35 5f 53 48 41 32 35
   36 0a 53 69 67 6e 61 74 75 72 65 20 41 6c 67 6f
   72 69 74 68 6d 73 3a 20 52 53 41 2b 53 48 41 32
   35 36 3a 52 53 41 2b 53 48 41 33 38 34 3a 52 53
   41 2b 53 48 41 35 31 32 3a 45 43 44 53 41 2b 53
   48 41 32 35 36 3a 45 43 44 53 41 2b 53 48 41 33
   38 34 3a 45 43 44 53 41 2b 53 48 41 35 31 32 3a
   52 53 41 2d 50 53 53 2b 53 48 41 32 35 36 3a 52
   53 41 2d 50 53 53 2b 53 48 41 33 38 34 3a 52 53
   41 2d 50 53 53 2b 53 48 41 32 35 36 3a 52 53 41
   2d 50 53 53 2b 53 48 41 33 38 34 3a 52 53 41 2d
   50 53 53 2b 53 48 41 32 35 36 3a 45 64 32 35 35
   31 39 3a 45 64 34 34 38 3a 52 53 41 2b 53 48 41
   31 0a 53 68 61 72 65 64 20 53 69 67 6e 61 74 75
   72 65 20 41 6c 67 6f 72 69 74 68 6d 73 3a 20 52
   53 41 2b 53 48 41 32 35 36 3a 52 53 41 2b 53 48
   41 33 38 34 3a 52 53 41 2b 53 48 41 35 31 32 3a
   45 43 44 53 41 2b 53 48 41 32 35 36 3a 45 43 44
   53 41 2b 53 48 41 33 38 34 3a 45 43 44 53 41 2b
   53 48 41 35 31 32 3a 52 53 41 2d 50 53 53 2b 53
   48 41 32 35 36 3a 52 53 41 2d 50 53 53 2b 53 48
   41 33 38 34 3a 52 53 41 2d 50 53 53 2b 53 48 41
   32 35 36 3a 52 53 41 2d 50 53 53 2b 53 48 41 33
   38 34 3a 52 53 41 2d 50 53 53 2b 53 48 41 32 35
   36 3a 45 64 32 35 35 31 39 3a 45 64 34 34 38 0a
   50 65 65 72 20 73 69 67 6e 61 74 75 72 65 20 74
   79 70 65 3a 20 45 64 32 35 35 31 39 0a 53 75 70
   70 6f 72 74 65 64 20 67 72 6f 75 70 73 3a 20 78
   32 35 35 31 39 0a 53 68 61 72 65 64 20 67 72 6f
   75 70 73 3a 20 78 32 35 35 31 39 0a 2d 2d 2d 0a
   4e 65 77 2c 20 54 4c 53 76 31 2e 33 2c 20 43 69
   70 68 65 72 20 69 73 20 54 4c 53 5f 41 45 53 5f
   31 32 38 5f 47 43 4d 5f 53 48 41 32 35 36 0a 53
   53 4c 2d 53 65 73 73 69 6f 6e 3a 0a 20 20 20 20
   50 72 6f 74 6f 63 6f 6c 20 20 3a 20 54 4c 53 76
   31 2e 33 0a 20 20 20 20 43 69 70 68 65 72 20 20
   20 20 3a 20 54 4c 53 5f 41 45 53 5f 31 32 38 5f
   47 43 4d 5f 53 48 41 32 35 36 0a 20 20 20 20 53
   65 73 73 69 6f 6e 2d 49 44 3a 20 45 38 41 38 38
   37 44 36 44 41 32 33 30 32 31 39 31 36 42 35 37
   46 37 35 31 46 32 37 36 36 33 42 34 35 41 43 33
   45 45 38 44 37 45 44 31 38 30 36 31 30 44 36 38
   41 35 32 45 38 36 31 32 36 39 36 0a 20 20 20 20
   53 65 73 73 69 6f 6e 2d 49 44 2d 63 74 78 3a 20
   30 31 30 30 30 30 30 30 0a 20 20 20 20 52 65 73
   75 6d 70 74 69 6f 6e 20 50 53 4b 3a 20 38 46 46
   37 45 46 43 36 45 39 35 32 45 46 36 45 38 36 43
   30 44 39 45 42 31 32 46 46 39 43 36 32 30 39 33
   42 44 45 34 43 37 35 39 42 39 46 43 32 31 42 46
   39 35 46 37 45 46 36 30 44 43 41 36 39 0a 20 20
   20 20 50 53 4b 20 69 64 65 6e 74 69 74 79 3a 20
   4e 6f 6e 65 0a 20 20 20 20 50 53 4b 20 69 64 65
   6e 74 69 74 79 20 68 69 6e 74 3a 20 4e 6f 6e 65
   0a 20 20 20 20 53 52 50 20 75 73 65 72 6e 61 6d
   65 3a 20 4e 6f 6e 65 0a 20 20 20 20 53 74 61 72
   74 20 54 69 6d 65 3a 20 31 36 38 30 36 32 35 38
   31 37 0a 20 20 20 20 54 69 6d 65 6f 75 74 20 20
   20 3a 20 37 32 30 30 20 28 73 65 63 29 0a 20 20
   20 20 56 65 72 69 66 79 20 72 65 74 75 72 6e 20
   63 6f 64 65 3a 20 31 38 20 28 73 65 6c 66 2d 73
   69 67 6e 65 64 20 63 65 72 74 69 66 69 63 61 74
   65 29 0a 20 20 20 20 45 78 74 65 6e 64 65 64 20
   6d 61 73 74 65 72 20 73 65 63 72 65 74 3a 20 6e
   6f 0a 20 20 20 20 4d 61 78 20 45 61 72 6c 79 20
   44 61 74 61 3a 20 30 0a 2d 2d 2d 0a 20 20 20 30
   20 69 74 65 6d 73 20 69 6e 20 74 68 65 20 73 65
   73 73 69 6f 6e 20 63 61 63 68 65 0a 20 20 20 30
   20 63 6c 69 65 6e 74 20 63 6f 6e 6e 65 63 74 73
   20 28 53 53 4c 5f 63 6f 6e 6e 65 63 74 28 29 29
   0a 20 20 20 30 20 63 6c 69 65 6e 74 20 72 65 6e
   65 67 6f 74 69 61 74 65 73 20 28 53 53 4c 5f 63
   6f 6e 6e 65 63 74 28 29 29 0a 20 20 20 30 20 63
   6c 69 65 6e 74 20 63 6f 6e 6e 65 63 74 73 20 74
   68 61 74 20 66 69 6e 69 73 68 65 64 0a 20 20 20
   36 20 73 65 72 76 65 72 20 61 63 63 65 70 74 73
   20 28 53 53 4c 5f 61 63 63 65 70 74 28 29 29 0a
   20 20 20 30 20 73 65 72 76 65 72 20 72 65 6e 65
   67 6f 74 69 61 74 65 73 20 28 53 53 4c 5f 61 63
   63 65 70 74 28 29 29 0a 20 20 20 36 20 73 65 72
   76 65 72 20 61 63 63 65 70 74 73 20 74 68 61 74
   20 66 69 6e 69 73 68 65 64 0a 20 20 20 32 20 73
   65 73 73 69 6f 6e 20 63 61 63 68 65 20 68 69 74
   73 0a 20 20 20 30 20 73 65 73 73 69 6f 6e 20 63
   61 63 68 65 20 6d 69 73 73 65 73 0a 20 20 20 30
   20 73 65 73 73 69 6f 6e 20 63 61 63 68 65 20 74
   69 6d 65 6f 75 74 73 0a 20 20 20 30 20 63 61 6c
   6c 62 61 63 6b 20 63 61 63 68 65 20 68 69 74 73
   0a 20 20 20 30 20 63 61 63 68 65 20 66 75 6c 6c
   20 6f 76 65 72 66 6c 6f 77 73 20 28 31 32 38 20
   61 6c 6c 6f 77 65 64 29 0a 2d 2d 2d 0a 43 6c 69
   65 6e 74 20 63 65 72 74 69 66 69 63 61 74 65 0a
   43 65 72 74 69 66 69 63 61 74 65 3a 0a 20 20 20
   20 44 61 74 61 3a 0a 20 20 20 20 20 20 20 20 56
   65 72 73 69 6f 6e 3a 20 33 20 28 30 78 32 29 0a
   20 20 20 20 20 20 20 20 53 65 72 69 61 6c 20 4e
   75 6d 62 65 72 3a 0a 20 20 20 20 20 20 20 20 20
   20 20 20 32 36 3a 33 66 3a 35 36 3a 63 35 3a 37
   33 3a 66 36 3a 36 62 3a 33 36 3a 64 38 3a 39 61
   3a 30 66 3a 63 37 3a 64 62 3a 61 66 3a 34 61 3a
   63 66 3a 66 37 3a 61 33 3a 37 32 3a 30 66 0a 20
   20 20 20 20 20 20 20 53 69 67 6e 61 74 75 72 65
   20 41 6c 67 6f 72 69 74 68 6d 3a 20 45 44 32 35
   35 31 39 0a 20 20 20 20 20 20 20 20 49 73 73 75
   65 72 3a 20 43 4e 3d 63 72 79 70 74 6f 67 72 61
   70 68 79 2e 69 6f 0a 20 20 20 20 20 20 20 20 56
   61 6c 69 64 69 74 79 0a 20 20 20 20 20 20 20 20
   20 20 20 20 4e 6f 74 20 42 65 66 6f 72 65 3a 20
   4d 61 72 20 32 33 20 32 30 3a 31 35 3a 31 34 20
   32 30 32 33 20 47 4d 54 0a 20 20 20 20 20 20 20
   20 20 20 20 20 4e 6f 74 20 41 66 74 65 72 20 3a
   20 41 70 72 20 32 33 20 32 30 3a 31 35 3a 31 34
   20 32 30 32 33 20 47 4d 54 0a 20 20 20 20 20 20
   20 20 53 75 62 6a 65 63 74 3a 20 43 4e 3d 63 72
   79 70 74 6f 67 72 61 70 68 79 2e 69 6f 0a 20 20
   20 20 20 20 20 20 53 75 62 6a 65 63 74 20 50 75
   62 6c 69 63 20 4b 65 79 20 49 6e 66 6f 3a 0a 20
   20 20 20 20 20 20 20 20 20 20 20 50 75 62 6c 69
   63 20 4b 65 79 20 41 6c 67 6f 72 69 74 68 6d 3a
   20 45 44 32 35 35 31 39 0a 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 45 44 32 35 35 31 39
   20 50 75 62 6c 69 63 2d 4b 65 79 3a 0a 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 70 75 62
   3a 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 20 36 66 3a 37 65 3a 62 38 3a 66
   35 3a 61 33 3a 32 38 3a 61 34 3a 62 39 3a 63 35
   3a 35 36 3a 66 63 3a 33 33 3a 38 38 3a 39 34 3a
   39 36 3a 0a 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 35 31 3a 34 62 3a 61 33
   3a 31 34 3a 61 36 3a 63 63 3a 61 66 3a 38 36 3a
   37 34 3a 35 38 3a 37 63 3a 32 34 3a 39 33 3a 61
   64 3a 35 63 3a 0a 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 61 36 3a 64 38 0a
   20 20 20 20 20 20 20 20 58 35 30 39 76 33 20 65
   78 74 65 6e 73 69 6f 6e 73 3a 0a 20 20 20 20 20
   20 20 20 20 20 20 20 58 35 30 39 76 33 20 53 75
   62 6a 65 63 74 20 41 6c 74 65 72 6e 61 74 69 76
   65 20 4e 61 6d 65 3a 20 0a 20 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 44 4e 53 3a 63 72 79
   70 74 6f 67 72 61 70 68 79 2e 69 6f 0a 20 20 20
   20 20 20 20 20 20 20 20 20 58 35 30 39 76 33 20
   4b 65 79 20 55 73 61 67 65 3a 20 0a 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 44 69 67 69
   74 61 6c 20 53 69 67 6e 61 74 75 72 65 2c 20 4e
   6f 6e 20 52 65 70 75 64 69 61 74 69 6f 6e 2c 20
   44 61 74 61 20 45 6e 63 69 70 68 65 72 6d 65 6e
   74 2c 20 43 65 72 74 69 66 69 63 61 74 65 20 53
   69 67 6e 0a 20 20 20 20 20 20 20 20 20 20 20 20
   58 35 30 39 76 33 20 42 61 73 69 63 20 43 6f 6e
   73 74 72 61 69 6e 74 73 3a 20 63 72 69 74 69 63
   61 6c 0a 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 43 41 3a 46 41 4c 53 45 0a 20 20 20 20
   53 69 67 6e 61 74 75 72 65 20 41 6c 67 6f 72 69
   74 68 6d 3a 20 45 44 32 35 35 31 39 0a 20 20 20
   20 53 69 67 6e 61 74 75 72 65 20 56 61 6c 75 65
   3a 0a 20 20 20 20 20 20 20 20 34 39 3a 64 32 3a
   34 63 3a 30 37 3a 35 63 3a 39 33 3a 61 65 3a 61
   61 3a 39 38 3a 30 33 3a 36 61 3a 64 36 3a 65 34
   3a 32 35 3a 36 35 3a 37 34 3a 34 35 3a 62 64 3a
   0a 20 20 20 20 20 20 20 20 34 65 3a 31 35 3a 66
   62 3a 31 34 3a 66 64 3a 38 64 3a 35 37 3a 39 62
   3a 38 30 3a 63 35 3a 66 35 3a 38 31 3a 39 35 3a
   39 66 3a 61 30 3a 61 61 3a 37 35 3a 30 34 3a 0a
   20 20 20 20 20 20 20 20 66 31 3a 66 38 3a 36 63
   3a 66 61 3a 66 63 3a 30 65 3a 62 64 3a 65 65 3a
   33 61 3a 66 37 3a 66 61 3a 65 63 3a 64 33 3a 36
   34 3a 66 66 3a 38 36 3a 32 37 3a 61 36 3a 0a 20
   20 20 20 20 20 20 20 30 64 3a 34 38 3a 64 64 3a
   37 63 3a 63 35 3a 37 32 3a 36 62 3a 36 34 3a 38
   66 3a 30 39 0a 2d 2d 2d 2d 2d 42 45 47 49 4e 20
   43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d
   0a 4d 49 49 42 4c 6a 43 42 34 61 41 44 41 67 45
   43 41 68 51 6d 50 31 62 46 63 2f 5a 72 4e 74 69
   61 44 38 66 62 72 30 72 50 39 36 4e 79 44 7a 41
   46 42 67 4d 72 5a 58 41 77 47 6a 45 59 4d 42 59
   47 0a 41 31 55 45 41 77 77 50 59 33 4a 35 63 48
   52 76 5a 33 4a 68 63 47 68 35 4c 6d 6c 76 4d 42
   34 58 44 54 49 7a 4d 44 4d 79 4d 7a 49 77 4d 54
   55 78 4e 46 6f 58 44 54 49 7a 4d 44 51 79 4d 7a
   49 77 0a 4d 54 55 78 4e 46 6f 77 47 6a 45 59 4d
   42 59 47 41 31 55 45 41 77 77 50 59 33 4a 35 63
   48 52 76 5a 33 4a 68 63 47 68 35 4c 6d 6c 76 4d
   43 6f 77 42 51 59 44 4b 32 56 77 41 79 45 41 62
   33 36 34 0a 39 61 4d 6f 70 4c 6e 46 56 76 77 7a
   69 4a 53 57 55 55 75 6a 46 4b 62 4d 72 34 5a 30
   57 48 77 6b 6b 36 31 63 70 74 69 6a 4f 54 41 33
   4d 42 6f 47 41 31 55 64 45 51 51 54 4d 42 47 43
   44 32 4e 79 0a 65 58 42 30 62 32 64 79 59 58 42
   6f 65 53 35 70 62 7a 41 4c 42 67 4e 56 48 51 38
   45 42 41 4d 43 41 74 51 77 44 41 59 44 56 52 30
   54 41 51 48 2f 42 41 49 77 41 44 41 46 42 67 4d
   72 5a 58 41 44 0a 51 51 42 4a 30 6b 77 48 58 4a
   4f 75 71 70 67 44 61 74 62 6b 4a 57 56 30 52 62
   31 4f 46 66 73 55 2f 59 31 58 6d 34 44 46 39 59
   47 56 6e 36 43 71 64 51 54 78 2b 47 7a 36 2f 41
   36 39 37 6a 72 33 0a 2b 75 7a 54 5a 50 2b 47 4a
   36 59 4e 53 4e 31 38 78 58 4a 72 5a 49 38 4a 0a
   2d 2d 2d 2d 2d 45 4e 44 20 43 45 52 54 49 46 49
   43 41 54 45 2d 2d 2d 2d 2d 0a 3c 2f 70 72 65 3e
   3c 2f 42 4f 44 59 3e 3c 2f 48 54 4d 4c 3e 0d 0a
   0d 0a
     - TLS message 10 server_application_data [5906 bytes]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n<pre>\n\ns_server -cert server.crt -key server.key -www -port 8403 -CAfile client.crt -debug -keylogfile key.txt -msg -state -tlsextdebug -Verify 1 \nSecure Renegotiation IS NOT supported\nCiphers supported in s_server binary\nTLSv1.3    :TLS_AES_256_GCM_SHA384    TLSv1.3    :TLS_CHACHA20_POLY1305_SHA256 \nTLSv1.3    :TLS_AES_128_GCM_SHA256    TLSv1.2    :ECDHE-ECDSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2    :DHE-RSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-ECDSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-RSA-CHACHA20-POLY1305 \nTLSv1.2    :DHE-RSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-ECDSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2    :DHE-RSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-ECDSA-AES256-SHA384 TLSv1.2    :ECDHE-RSA-AES256-SHA384   \nTLSv1.2    :DHE-RSA-AES256-SHA256     TLSv1.2    :ECDHE-ECDSA-AES128-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-SHA256   TLSv1.2    :DHE-RSA-AES128-SHA256     \nTLSv1.0    :ECDHE-ECDSA-AES256-SHA    TLSv1.0    :ECDHE-RSA-AES256-SHA      \nSSLv3      :DHE-RSA-AES256-SHA        TLSv1.0    :ECDHE-ECDSA-AES128-SHA    \nTLSv1.0    :ECDHE-RSA-AES128-SHA      SSLv3      :DHE-RSA-AES128-SHA        \nTLSv1.2    :RSA-PSK-AES256-GCM-SHA384 TLSv1.2    :DHE-PSK-AES256-GCM-SHA384 \nTLSv1.2    :RSA-PSK-CHACHA20-POLY1305 TLSv1.2    :DHE-PSK-CHACHA20-POLY1305 \nTLSv1.2    :ECDHE-PSK-CHACHA20-POLY1305 TLSv1.2    :AES256-GCM-SHA384         \nTLSv1.2    :PSK-AES256-GCM-SHA384     TLSv1.2    :PSK-CHACHA20-POLY1305     \nTLSv1.2    :RSA-PSK-AES128-GCM-SHA256 TLSv1.2    :DHE-PSK-AES128-GCM-SHA256 \nTLSv1.2    :AES128-GCM-SHA256         TLSv1.2    :PSK-AES128-GCM-SHA256     \nTLSv1.2    :AES256-SHA256             TLSv1.2    :AES128-SHA256             \nTLSv1.0    :ECDHE-PSK-AES256-CBC-SHA384 TLSv1.0    :ECDHE-PSK-AES256-CBC-SHA  \nSSLv3      :SRP-RSA-AES-256-CBC-SHA   SSLv3      :SRP-AES-256-CBC-SHA       \nTLSv1.0    :RSA-PSK-AES256-CBC-SHA384 TLSv1.0    :DHE-PSK-AES256-CBC-SHA384 \nSSLv3      :RSA-PSK-AES256-CBC-SHA    SSLv3      :DHE-PSK-AES256-CBC-SHA    \nSSLv3      :AES256-SHA                TLSv1.0    :PSK-AES256-CBC-SHA384     \nSSLv3      :PSK-AES256-CBC-SHA        TLSv1.0    :ECDHE-PSK-AES128-CBC-SHA256 \nTLSv1.0    :ECDHE-PSK-AES128-CBC-SHA  SSLv3      :SRP-RSA-AES-128-CBC-SHA   \nSSLv3      :SRP-AES-128-CBC-SHA       TLSv1.0    :RSA-PSK-AES128-CBC-SHA256 \nTLSv1.0    :DHE-PSK-AES128-CBC-SHA256 SSLv3      :RSA-PSK-AES128-CBC-SHA    \nSSLv3      :DHE-PSK-AES128-CBC-SHA    SSLv3      :AES128-SHA                \nTLSv1.0    :PSK-AES128-CBC-SHA256     SSLv3      :PSK-AES128-CBC-SHA        \n---\nCiphers common between both SSL end points:\nTLS_AES_128_GCM_SHA256     TLS_CHACHA20_POLY1305_SHA256\nSignature Algorithms: RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:Ed25519:Ed448:RSA+SHA1\nShared Signature Algorithms: RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:Ed25519:Ed448\nPeer signature type: Ed25519\nSupported groups: x25519\nShared groups: x25519\n---\nNew, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\nSSL-Session:\n    Protocol  : TLSv1.3\n    Cipher    : TLS_AES_128_GCM_SHA256\n    Session-ID: E8A887D6DA23021916B57F751F27663B45AC3EE8D7ED180610D68A52E8612696\n    Session-ID-ctx: 01000000\n    Resumption PSK: 8FF7EFC6E952EF6E86C0D9EB12FF9C62093BDE4C759B9FC21BF95F7EF60DCA69\n    PSK identity: None\n    PSK identity hint: None\n    SRP username: None\n    Start Time: 1680625817\n    Timeout   : 7200 (sec)\n    Verify return code: 18 (self-signed certificate)\n    Extended master secret: no\n    Max Early Data: 0\n---\n   0 items in the session cache\n   0 client connects (SSL_connect())\n   0 client renegotiates (SSL_connect())\n   0 client connects that finished\n   6 server accepts (SSL_accept())\n   0 server renegotiates (SSL_accept())\n   6 server accepts that finished\n   2 session cache hits\n   0 session cache misses\n   0 session cache timeouts\n   0 callback cache hits\n   0 cache full overflows (128 allowed)\n---\nClient certificate\nCertificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number:\n            26:3f:56:c5:73:f6:6b:36:d8:9a:0f:c7:db:af:4a:cf:f7:a3:72:0f\n        Signature Algorithm: ED25519\n        Issuer: CN=cryptography.io\n        Validity\n            Not Before: Mar 23 20:15:14 2023 GMT\n            Not After : Apr 23 20:15:14 2023 GMT\n        Subject: CN=cryptography.io\n        Subject Public Key Info:\n            Public Key Algorithm: ED25519\n                ED25519 Public-Key:\n                pub:\n                    6f:7e:b8:f5:a3:28:a4:b9:c5:56:fc:33:88:94:96:\n                    51:4b:a3:14:a6:cc:af:86:74:58:7c:24:93:ad:5c:\n                    a6:d8\n        X509v3 extensions:\n            X509v3 Subject Alternative Name: \n                DNS:cryptography.io\n            X509v3 Key Usage: \n                Digital Signature, Non Repudiation, Data Encipherment, Certificate Sign\n            X509v3 Basic Constraints: critical\n                CA:FALSE\n    Signature Algorithm: ED25519\n    Signature Value:\n        49:d2:4c:07:5c:93:ae:aa:98:03:6a:d6:e4:25:65:74:45:bd:\n        4e:15:fb:14:fd:8d:57:9b:80:c5:f5:81:95:9f:a0:aa:75:04:\n        f1:f8:6c:fa:fc:0e:bd:ee:3a:f7:fa:ec:d3:64:ff:86:27:a6:\n        0d:48:dd:7c:c5:72:6b:64:8f:09\n-----BEGIN CERTIFICATE-----\nMIIBLjCB4aADAgECAhQmP1bFc/ZrNtiaD8fbr0rP96NyDzAFBgMrZXAwGjEYMBYG\nA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMB4XDTIzMDMyMzIwMTUxNFoXDTIzMDQyMzIw\nMTUxNFowGjEYMBYGA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMCowBQYDK2VwAyEAb364\n9aMopLnFVvwziJSWUUujFKbMr4Z0WHwkk61cptijOTA3MBoGA1UdEQQTMBGCD2Ny\neXB0b2dyYXBoeS5pbzALBgNVHQ8EBAMCAtQwDAYDVR0TAQH/BAIwADAFBgMrZXAD\nQQBJ0kwHXJOuqpgDatbkJWV0Rb1OFfsU/Y1Xm4DF9YGVn6CqdQTx+Gz6/A697jr3\n+uzTZP+GJ6YNSN18xXJrZI8J\n-----END CERTIFICATE-----\n</pre></BODY></HTML>\r\n\r\n'
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

   APPLICATION DATA - [cert]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n<pre>\n\ns_server -cert server.crt -key server.key -www -port 8403 -CAfile client.crt -debug -keylogfile key.txt -msg -state -tlsextdebug -Verify 1 \nSecure Renegotiation IS NOT supported\nCiphers supported in s_server binary\nTLSv1.3    :TLS_AES_256_GCM_SHA384    TLSv1.3    :TLS_CHACHA20_POLY1305_SHA256 \nTLSv1.3    :TLS_AES_128_GCM_SHA256    TLSv1.2    :ECDHE-ECDSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2    :DHE-RSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-ECDSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-RSA-CHACHA20-POLY1305 \nTLSv1.2    :DHE-RSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-ECDSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2    :DHE-RSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-ECDSA-AES256-SHA384 TLSv1.2    :ECDHE-RSA-AES256-SHA384   \nTLSv1.2    :DHE-RSA-AES256-SHA256     TLSv1.2    :ECDHE-ECDSA-AES128-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-SHA256   TLSv1.2    :DHE-RSA-AES128-SHA256     \nTLSv1.0    :ECDHE-ECDSA-AES256-SHA    TLSv1.0    :ECDHE-RSA-AES256-SHA      \nSSLv3      :DHE-RSA-AES256-SHA        TLSv1.0    :ECDHE-ECDSA-AES128-SHA    \nTLSv1.0    :ECDHE-RSA-AES128-SHA      SSLv3      :DHE-RSA-AES128-SHA        \nTLSv1.2    :RSA-PSK-AES256-GCM-SHA384 TLSv1.2    :DHE-PSK-AES256-GCM-SHA384 \nTLSv1.2    :RSA-PSK-CHACHA20-POLY1305 TLSv1.2    :DHE-PSK-CHACHA20-POLY1305 \nTLSv1.2    :ECDHE-PSK-CHACHA20-POLY1305 TLSv1.2    :AES256-GCM-SHA384         \nTLSv1.2    :PSK-AES256-GCM-SHA384     TLSv1.2    :PSK-CHACHA20-POLY1305     \nTLSv1.2    :RSA-PSK-AES128-GCM-SHA256 TLSv1.2    :DHE-PSK-AES128-GCM-SHA256 \nTLSv1.2    :AES128-GCM-SHA256         TLSv1.2    :PSK-AES128-GCM-SHA256     \nTLSv1.2    :AES256-SHA256             TLSv1.2    :AES128-SHA256             \nTLSv1.0    :ECDHE-PSK-AES256-CBC-SHA384 TLSv1.0    :ECDHE-PSK-AES256-CBC-SHA  \nSSLv3      :SRP-RSA-AES-256-CBC-SHA   SSLv3      :SRP-AES-256-CBC-SHA       \nTLSv1.0    :RSA-PSK-AES256-CBC-SHA384 TLSv1.0    :DHE-PSK-AES256-CBC-SHA384 \nSSLv3      :RSA-PSK-AES256-CBC-SHA    SSLv3      :DHE-PSK-AES256-CBC-SHA    \nSSLv3      :AES256-SHA                TLSv1.0    :PSK-AES256-CBC-SHA384     \nSSLv3      :PSK-AES256-CBC-SHA        TLSv1.0    :ECDHE-PSK-AES128-CBC-SHA256 \nTLSv1.0    :ECDHE-PSK-AES128-CBC-SHA  SSLv3      :SRP-RSA-AES-128-CBC-SHA   \nSSLv3      :SRP-AES-128-CBC-SHA       TLSv1.0    :RSA-PSK-AES128-CBC-SHA256 \nTLSv1.0    :DHE-PSK-AES128-CBC-SHA256 SSLv3      :RSA-PSK-AES128-CBC-SHA    \nSSLv3      :DHE-PSK-AES128-CBC-SHA    SSLv3      :AES128-SHA                \nTLSv1.0    :PSK-AES128-CBC-SHA256     SSLv3      :PSK-AES128-CBC-SHA        \n---\nCiphers common between both SSL end points:\nTLS_AES_128_GCM_SHA256     TLS_CHACHA20_POLY1305_SHA256\nSignature Algorithms: RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:Ed25519:Ed448:RSA+SHA1\nShared Signature Algorithms: RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA256:Ed25519:Ed448\nPeer signature type: Ed25519\nSupported groups: x25519\nShared groups: x25519\n---\nNew, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\nSSL-Session:\n    Protocol  : TLSv1.3\n    Cipher    : TLS_AES_128_GCM_SHA256\n    Session-ID: E8A887D6DA23021916B57F751F27663B45AC3EE8D7ED180610D68A52E8612696\n    Session-ID-ctx: 01000000\n    Resumption PSK: 8FF7EFC6E952EF6E86C0D9EB12FF9C62093BDE4C759B9FC21BF95F7EF60DCA69\n    PSK identity: None\n    PSK identity hint: None\n    SRP username: None\n    Start Time: 1680625817\n    Timeout   : 7200 (sec)\n    Verify return code: 18 (self-signed certificate)\n    Extended master secret: no\n    Max Early Data: 0\n---\n   0 items in the session cache\n   0 client connects (SSL_connect())\n   0 client renegotiates (SSL_connect())\n   0 client connects that finished\n   6 server accepts (SSL_accept())\n   0 server renegotiates (SSL_accept())\n   6 server accepts that finished\n   2 session cache hits\n   0 session cache misses\n   0 session cache timeouts\n   0 callback cache hits\n   0 cache full overflows (128 allowed)\n---\nClient certificate\nCertificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number:\n            26:3f:56:c5:73:f6:6b:36:d8:9a:0f:c7:db:af:4a:cf:f7:a3:72:0f\n        Signature Algorithm: ED25519\n        Issuer: CN=cryptography.io\n        Validity\n            Not Before: Mar 23 20:15:14 2023 GMT\n            Not After : Apr 23 20:15:14 2023 GMT\n        Subject: CN=cryptography.io\n        Subject Public Key Info:\n            Public Key Algorithm: ED25519\n                ED25519 Public-Key:\n                pub:\n                    6f:7e:b8:f5:a3:28:a4:b9:c5:56:fc:33:88:94:96:\n                    51:4b:a3:14:a6:cc:af:86:74:58:7c:24:93:ad:5c:\n                    a6:d8\n        X509v3 extensions:\n            X509v3 Subject Alternative Name: \n                DNS:cryptography.io\n            X509v3 Key Usage: \n                Digital Signature, Non Repudiation, Data Encipherment, Certificate Sign\n            X509v3 Basic Constraints: critical\n                CA:FALSE\n    Signature Algorithm: ED25519\n    Signature Value:\n        49:d2:4c:07:5c:93:ae:aa:98:03:6a:d6:e4:25:65:74:45:bd:\n        4e:15:fb:14:fd:8d:57:9b:80:c5:f5:81:95:9f:a0:aa:75:04:\n        f1:f8:6c:fa:fc:0e:bd:ee:3a:f7:fa:ec:d3:64:ff:86:27:a6:\n        0d:48:dd:7c:c5:72:6b:64:8f:09\n-----BEGIN CERTIFICATE-----\nMIIBLjCB4aADAgECAhQmP1bFc/ZrNtiaD8fbr0rP96NyDzAFBgMrZXAwGjEYMBYG\nA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMB4XDTIzMDMyMzIwMTUxNFoXDTIzMDQyMzIw\nMTUxNFowGjEYMBYGA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMCowBQYDK2VwAyEAb364\n9aMopLnFVvwziJSWUUujFKbMr4Z0WHwkk61cptijOTA3MBoGA1UdEQQTMBGCD2Ny\neXB0b2dyYXBoeS5pbzALBgNVHQ8EBAMCAtQwDAYDVR0TAQH/BAIwADAFBgMrZXAD\nQQBJ0kwHXJOuqpgDatbkJWV0Rb1OFfsU/Y1Xm4DF9YGVn6CqdQTx+Gz6/A697jr3\n+uzTZP+GJ6YNSN18xXJrZI8J\n-----END CERTIFICATE-----\n</pre></BODY></HTML>\r\n\r\n'
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
   c3 00 b1 0d c3 06 36 0c e5 d6 41 42 4f e1 5d 99
   5c 2f 0a 01 43 dc 20 de e1 e5 8b cc 84 77 6d 91
   60 c2 91 1c 4c 02 52 55 55 06 df e1 4f c0 76 4a
   87 c0 80 f8 6b 90 8c 00 04 13 01 13 03 01 00 04
   b7 00 2b 00 03 02 03 04 00 0d 00 1e 00 1c 04 01
   05 01 06 01 04 03 05 03 06 03 08 04 08 05 08 09
   08 0a 08 09 08 07 08 08 02 01 00 0a 00 04 00 02
   00 1d 00 33 00 26 00 24 00 1d 00 20 3d 40 0c e9
   53 a4 6a d1 d4 0f 4b 2c 00 7f f7 b9 d6 57 bc 29
   82 ff 19 ef f9 0d 25 24 75 a1 04 1d 00 2d 00 02
   01 01 00 29 04 52 04 0c 02 00 43 08 3d ec 3a 25
   bf 2d 1a a5 0b f9 6b 6e 5a 89 5d aa ba 94 60 d2
   b3 1d 3c 36 77 3c bb 18 c2 ad 07 90 84 cd 03 02
   91 e2 d5 6f 63 b5 fa 74 e0 65 d2 81 c9 f2 24 c8
   e2 9a fe 47 2a ed f2 6b 21 ac ad 7c 7c b5 22 0a
   67 6a ac 04 b7 51 5b 22 be aa b0 c6 d0 77 c8 98
   03 ca 00 ce 0f f1 f1 bf e4 c6 50 67 f2 3d 31 c1
   ae bd 84 0f 26 a1 4e 61 58 a5 db 2c 0f 29 54 5e
   0a 23 e8 5f e7 fd 67 2c 50 a7 7d b1 a4 37 56 36
   6a 90 b9 83 ef 10 0b de 0c b4 51 13 bf 31 27 21
   e8 8d c4 5e 06 70 fe 13 49 a6 9d 99 21 11 1d 52
   ea 1a 31 d2 ff a6 43 92 ee 1b 6d 8f af 20 e8 31
   9a 97 95 67 4b a3 d1 67 3e 7e 57 21 ee 44 b8 6a
   a6 9a 85 5c 2e 39 4e ec e9 ac 57 58 99 e3 71 dc
   dc 90 94 dd 73 fd 8f d8 63 27 bc d4 c2 39 00 02
   a4 34 e8 c1 1d 64 e5 73 b5 bc be 69 1c 28 3a 84
   04 04 cb 08 f1 0e fa 00 7d 6b a8 97 2c c2 d2 5c
   76 23 4d ab 8d 9f 79 e1 05 65 be 31 8d 42 56 ae
   36 5a a8 e1 03 0f 27 28 6c 51 16 d0 c9 92 08 b2
   97 64 d9 58 4a 73 22 93 79 1c d1 36 07 5c ad b4
   60 49 a2 33 6f d2 ac fe e5 78 59 e7 f6 86 83 cf
   f4 cd c7 44 2d 47 2e 4f fc 69 a4 78 9c ea 67 55
   0d 9f a2 e4 2d 55 1d fd 12 2a 2d a7 94 71 29 82
   53 42 a9 c4 f4 9f ac 8c 21 af 28 2a 8d 48 09 e6
   db 44 59 52 af bf e5 fe 4a f3 c4 87 b3 75 2e a2
   0c 9d e4 2f d9 89 f1 39 56 f1 33 11 35 27 ae 43
   f0 7d c3 8a 0b 7d f0 5c 18 36 ef b4 e4 c0 27 0a
   23 b7 33 0a af 4b 23 7c cf 40 e9 f4 3b 0c ce 73
   ff 1e 84 a0 93 27 a3 de ff d4 59 63 24 ee 8c f6
   28 54 d5 f0 65 a5 75 96 7b b8 97 6b b4 15 06 b7
   d6 a6 ef 74 4a ef 64 71 5a 57 0b c6 f3 94 56 4e
   19 8c a3 18 91 e3 14 86 a3 ca ab f3 d2 c8 dc 56
   66 7b 6a a5 70 39 cb 31 2e 60 35 08 10 0e 02 00
   43 08 3d ec 3a 25 bf 2d 1a a5 0b f9 6b 6e 5a 89
   ca 62 30 97 3c ff a2 bc ca 44 73 ff 08 94 7a c0
   40 27 f8 f6 02 f9 e1 5a 5f 11 33 00 cf 6e 84 e6
   7f a2 03 76 eb d3 dd 63 7f 63 0a bb 24 8d 4f 20
   31 2f f0 1b 63 45 85 e7 14 b7 77 ac c9 2e 20 bc
   75 ad 06 13 aa 4c b2 cd 19 b3 93 7c bd 8c 1c 0e
   26 33 6a a1 36 da d7 8b 60 a3 0e a2 93 47 d4 28
   b6 f0 c8 3c c4 d8 31 b2 3a a7 65 75 ff f1 26 b2
   50 12 47 8c df 5d 6c 68 51 d9 c1 57 32 7c 78 c8
   07 a7 a2 46 26 1e 3c a1 4e 4e 34 fb 24 d4 ac 56
   7e 0b 65 c6 f6 58 99 70 70 76 64 67 04 3c a8 36
   ab 5b ba e7 3b 56 18 e0 3e bb 2a c1 a5 8f ce 19
   b0 15 56 7b 12 db 61 1f f9 7a e7 46 e3 40 6f ed
   02 b7 4a c3 58 d6 7b 0f b7 ea 2b 74 36 5f 80 64
   34 e4 02 19 74 41 7d 57 5f c0 81 c3 0b 78 8c b3
   02 43 e8 7a a5 2e 48 07 76 e4 77 bc 6d 58 1a 4e
   cb 02 e0 5b 5d 98 55 ea bf 33 e0 61 83 12 28 d9
   eb 29 72 da 60 b2 ce d2 61 17 2a 91 8d 88 b1 63
   86 a5 67 65 64 50 9f 39 ee 47 03 1a 3d 54 c3 76
   f3 e0 8c a2 f9 85 85 b1 7a 0b e7 31 63 48 a1 5f
   fa fd 71 41 52 82 44 04 ab 4f a0 cf cb 35 0f 7d
   4d 1b 7e a5 80 47 04 d4 b5 8c 3d 71 79 bc ac d1
   d4 9c c7 ec 00 8a 84 b5 2e 55 7e 89 5b 65 18 6e
   df bb 0f 5c 67 34 a2 e6 b9 8b 4e e8 71 d3 e4 eb
   20 a7 ce 15 61 68 56 0e 9e b4 db d6 c4 29 62 2c
   21 47 37 02 61 d8 cf 47 71 d7 bc ee ad 0c 06 92
   a1 ea f4 3d 21 fd 15 1d 68 a9 57 f5 9a 4b 52 9a
   8a 7e 17 06 13 c2 11 94 d3 0a ad 1f 90 81 db 7e
   41 a1 8d b8 83 f7 35 fb 2b bb 25 b0 09 89 b4 5d
   94 3f 28 db 9f d4 93 f3 c0 f8 bd 65 99 2f 0b c1
   dd 98 ff ef 37 26 eb 62 43 97 84 23 e8 63 ff 80
   36 0d 9e 0f 32 1b e0 97 7c b4 5d d4 3e 99 f5 a2
   15 fc 54 66
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
   1d c1 a3 41 29 c3 00 b1 0d c3 06 36 0c e5 d6 41
   42 4f e1 5d 99 5c 2f 0a 01 43 dc 20 de e1 e5 8b
   cc 84 77 6d 91 60 c2 91 1c 4c 02 52 55 55 06 df
   e1 4f c0 76 4a 87 c0 80 f8 6b 90 8c 00 04 13 01
   13 03 01 00 04 b7 00 2b 00 03 02 03 04 00 0d 00
   1e 00 1c 04 01 05 01 06 01 04 03 05 03 06 03 08
   04 08 05 08 09 08 0a 08 09 08 07 08 08 02 01 00
   0a 00 04 00 02 00 1d 00 33 00 26 00 24 00 1d 00
   20 3d 40 0c e9 53 a4 6a d1 d4 0f 4b 2c 00 7f f7
   b9 d6 57 bc 29 82 ff 19 ef f9 0d 25 24 75 a1 04
   1d 00 2d 00 02 01 01 00 29 04 52 04 0c 02 00 43
   08 3d ec 3a 25 bf 2d 1a a5 0b f9 6b 6e 5a 89 5d
   aa ba 94 60 d2 b3 1d 3c 36 77 3c bb 18 c2 ad 07
   90 84 cd 03 02 91 e2 d5 6f 63 b5 fa 74 e0 65 d2
   81 c9 f2 24 c8 e2 9a fe 47 2a ed f2 6b 21 ac ad
   7c 7c b5 22 0a 67 6a ac 04 b7 51 5b 22 be aa b0
   c6 d0 77 c8 98 03 ca 00 ce 0f f1 f1 bf e4 c6 50
   67 f2 3d 31 c1 ae bd 84 0f 26 a1 4e 61 58 a5 db
   2c 0f 29 54 5e 0a 23 e8 5f e7 fd 67 2c 50 a7 7d
   b1 a4 37 56 36 6a 90 b9 83 ef 10 0b de 0c b4 51
   13 bf 31 27 21 e8 8d c4 5e 06 70 fe 13 49 a6 9d
   99 21 11 1d 52 ea 1a 31 d2 ff a6 43 92 ee 1b 6d
   8f af 20 e8 31 9a 97 95 67 4b a3 d1 67 3e 7e 57
   21 ee 44 b8 6a a6 9a 85 5c 2e 39 4e ec e9 ac 57
   58 99 e3 71 dc dc 90 94 dd 73 fd 8f d8 63 27 bc
   d4 c2 39 00 02 a4 34 e8 c1 1d 64 e5 73 b5 bc be
   69 1c 28 3a 84 04 04 cb 08 f1 0e fa 00 7d 6b a8
   97 2c c2 d2 5c 76 23 4d ab 8d 9f 79 e1 05 65 be
   31 8d 42 56 ae 36 5a a8 e1 03 0f 27 28 6c 51 16
   d0 c9 92 08 b2 97 64 d9 58 4a 73 22 93 79 1c d1
   36 07 5c ad b4 60 49 a2 33 6f d2 ac fe e5 78 59
   e7 f6 86 83 cf f4 cd c7 44 2d 47 2e 4f fc 69 a4
   78 9c ea 67 55 0d 9f a2 e4 2d 55 1d fd 12 2a 2d
   a7 94 71 29 82 53 42 a9 c4 f4 9f ac 8c 21 af 28
   2a 8d 48 09 e6 db 44 59 52 af bf e5 fe 4a f3 c4
   87 b3 75 2e a2 0c 9d e4 2f d9 89 f1 39 56 f1 33
   11 35 27 ae 43 f0 7d c3 8a 0b 7d f0 5c 18 36 ef
   b4 e4 c0 27 0a 23 b7 33 0a af 4b 23 7c cf 40 e9
   f4 3b 0c ce 73 ff 1e 84 a0 93 27 a3 de ff d4 59
   63 24 ee 8c f6 28 54 d5 f0 65 a5 75 96 7b b8 97
   6b b4 15 06 b7 d6 a6 ef 74 4a ef 64 71 5a 57 0b
   c6 f3 94 56 4e 19 8c a3 18 91 e3 14 86 a3 ca ab
   f3 d2 c8 dc 56 66 7b 6a a5 70 39 cb 31 2e 60 35
   08 10 0e 02 00 43 08 3d ec 3a 25 bf 2d 1a a5 0b
   f9 6b 6e 5a 89 ca 62 30 97 3c ff a2 bc ca 44 73
   ff 08 94 7a c0 40 27 f8 f6 02 f9 e1 5a 5f 11 33
   00 cf 6e 84 e6 7f a2 03 76 eb d3 dd 63 7f 63 0a
   bb 24 8d 4f 20 31 2f f0 1b 63 45 85 e7 14 b7 77
   ac c9 2e 20 bc 75 ad 06 13 aa 4c b2 cd 19 b3 93
   7c bd 8c 1c 0e 26 33 6a a1 36 da d7 8b 60 a3 0e
   a2 93 47 d4 28 b6 f0 c8 3c c4 d8 31 b2 3a a7 65
   75 ff f1 26 b2 50 12 47 8c df 5d 6c 68 51 d9 c1
   57 32 7c 78 c8 07 a7 a2 46 26 1e 3c a1 4e 4e 34
   fb 24 d4 ac 56 7e 0b 65 c6 f6 58 99 70 70 76 64
   67 04 3c a8 36 ab 5b ba e7 3b 56 18 e0 3e bb 2a
   c1 a5 8f ce 19 b0 15 56 7b 12 db 61 1f f9 7a e7
   46 e3 40 6f ed 02 b7 4a c3 58 d6 7b 0f b7 ea 2b
   74 36 5f 80 64 34 e4 02 19 74 41 7d 57 5f c0 81
   c3 0b 78 8c b3 02 43 e8 7a a5 2e 48 07 76 e4 77
   bc 6d 58 1a 4e cb 02 e0 5b 5d 98 55 ea bf 33 e0
   61 83 12 28 d9 eb 29 72 da 60 b2 ce d2 61 17 2a
   91 8d 88 b1 63 86 a5 67 65 64 50 9f 39 ee 47 03
   1a 3d 54 c3 76 f3 e0 8c a2 f9 85 85 b1 7a 0b e7
   31 63 48 a1 5f fa fd 71 41 52 82 44 04 ab 4f a0
   cf cb 35 0f 7d 4d 1b 7e a5 80 47 04 d4 b5 8c 3d
   71 79 bc ac d1 d4 9c c7 ec 00 8a 84 b5 2e 55 7e
   89 5b 65 18 6e df bb 0f 5c 67 34 a2 e6 b9 8b 4e
   e8 71 d3 e4 eb 20 a7 ce 15 61 68 56 0e 9e b4 db
   d6 c4 29 62 2c 21 47 37 02 61 d8 cf 47 71 d7 bc
   ee ad 0c 06 92 a1 ea f4 3d 21 fd 15 1d 68 a9 57
   f5 9a 4b 52 9a 8a 7e 17 06 13 c2 11 94 d3 0a ad
   1f 90 81 db 7e 41 a1 8d b8 83 f7 35 fb 2b bb 25
   b0 09 89 b4 5d 94 3f 28 db 9f d4 93 f3 c0 f8 bd
   65 99 2f 0b c1 dd 98 ff ef 37 26 eb 62 43 97 84
   23 e8 63 ff 80 36 0d 9e 0f 32 1b e0 97 7c b4 5d
   d4 3e 99 f5 a2 15 fc 54 66 00 42 20 b2 04 89 fc
   8d 85 d2 45 a7 09 c7 e9 59 8f a1 1d 1a 6b 8e e3
   9f 52 13 2e 61 ea 0a 41 b7 96 61 d1 20 14 89 7f
   5b f9 50 5b 0d 59 33 43 24 bd f4 7c 7f 31 b9 98
   31 79 e2 3a 0f af 58 26 d3 02 4c 1f b1
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
   8c 31 76 0b 8c 86 39 c4 0f 42 5b 12 c5 bb fb bd
   48 00 12 55 cc 6b b1 0c 16 cd 85 8a 3b 08 94 10
   1b ce 33 fa 22 e7 9e e8 b4 78 9a 32 b4 21 dc 63
   17 f6 bf f1 c4 57 a1 b8 2d a0 ec 02 a5 52 57 ec
   bd 71 1d ab c3 a0 4c 0e a0 34 25 ac 00 15 53 06
   4f 14 93 23 17 d3 e2 ee ee b2 1b 80 eb 82 d7 a0
   1f 6b b4 46 10 ee 52 58 f1 1d 32 ea 1b c0 eb 1a
   21 3f a3 c5 dc 80 ab ce d4 6d d8 5e 71 00 4a a5
   e4 c1 5a f8 b9 0b 91 0e 92 ca 5e 17 c9 2c 1a f2
   8e bb 2c 0b 64 9b 94 05 60 d4 46 84 52 62 91 a8
   a1 6e 09 22 96 9f b6 51 8c 40 a0 e2 ec 98 21 b2
   cf 73 f5 32 c1 a8 df a7 09 40 0b 3f c5 cb dc 8a
   24 6b be 22 37 08 7a e6 f0 33 e8 ac 30 af 93 83
   46 4c b4 b2 a5 84 26 f4 69 4a d4 1f a9 e8 82 cd
   3d 58 bd 0e 9d d0 a2 99 83 0c 17 96 66 6f ea f5
   a7 9e 05 0c 76 3a 99 ba a8 c1 2c 49 73 b4 67 e6
   1f 4b b8 6e 5f ec 96 fb 96 cc 27 ef c6 e9 11 a3
   a1 fe e4 77 31 3f fc e3 31 e2 89 33 c9 d6 1e 69
   ba cb 0f 6c f1 cc 71 33 b9 2b 01 06 bb f5 db bc
   7f 95 9c 03 83 48 b9 87 fc 16 18 08 a1 aa 7a c4
   6d 77 08 1c 94 5d 35 40 f0 dd c6 b0 34 0f 94 d7
   08 70 c5 85 e5 86 44 14 d6 a9 cc cb a9 23 86 da
   27 47 ad fe 01 d1 a3 73 12 fd 43 ff 15 7f 01 f6
   22 06 d6 39 d1 a4 27 8b a0 5e e4 1c 23 20 3c 43
   8e 60 1b f6 a9 2e 21 68 ac 8f 04 b0 f6 9c 82 69
   96 4f 4a f8 c0 da fa db 26 41 ee aa e8 e8 22 84
   a0 0f af 75 b0 14 4e 21 81 c5 fe 0d 10 e4 42 2c
   07 ff 6c 18 56 36 ab f1 9a 55 d9 d4 55 ff 12 13
   56 57 6e 5f 50 73 f8 a4 b5 b5 ec 85 03 00 94 e8
   70 cc 2b 5b d7 92 b4 86 51 16 53 dd 4f c0 58 ea
   72 84 c1 e0 f0 e6 c1 cc 55 74 b0 b1 2b 2a 20 7e
   d5 dc e6 76 10 0b 32 5c 9d 97 29 6d a3 96 5d 9b
   29 7f a5 c5 ed 21 cf c8 2c a0 12 29 57 49 4b c1
   91 94 a8 d6 56 8c 78 6e 69 94 e6 bc 93 b3 02
     - TLS record 5 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'\xeb\x0c\xa4\x06\xda\xe5I\xb7\xa3\x19\xd9\x8c1v\x0b\x8c'... (truncated, total 554)
     - fragment (encrypted) [554 bytes]:
   eb 0c a4 06 da e5 49 b7 a3 19 d9 8c 31 76 0b 8c
   86 39 c4 0f 42 5b 12 c5 bb fb bd 48 00 12 55 cc
   6b b1 0c 16 cd 85 8a 3b 08 94 10 1b ce 33 fa 22
   e7 9e e8 b4 78 9a 32 b4 21 dc 63 17 f6 bf f1 c4
   57 a1 b8 2d a0 ec 02 a5 52 57 ec bd 71 1d ab c3
   a0 4c 0e a0 34 25 ac 00 15 53 06 4f 14 93 23 17
   d3 e2 ee ee b2 1b 80 eb 82 d7 a0 1f 6b b4 46 10
   ee 52 58 f1 1d 32 ea 1b c0 eb 1a 21 3f a3 c5 dc
   80 ab ce d4 6d d8 5e 71 00 4a a5 e4 c1 5a f8 b9
   0b 91 0e 92 ca 5e 17 c9 2c 1a f2 8e bb 2c 0b 64
   9b 94 05 60 d4 46 84 52 62 91 a8 a1 6e 09 22 96
   9f b6 51 8c 40 a0 e2 ec 98 21 b2 cf 73 f5 32 c1
   a8 df a7 09 40 0b 3f c5 cb dc 8a 24 6b be 22 37
   08 7a e6 f0 33 e8 ac 30 af 93 83 46 4c b4 b2 a5
   84 26 f4 69 4a d4 1f a9 e8 82 cd 3d 58 bd 0e 9d
   d0 a2 99 83 0c 17 96 66 6f ea f5 a7 9e 05 0c 76
   3a 99 ba a8 c1 2c 49 73 b4 67 e6 1f 4b b8 6e 5f
   ec 96 fb 96 cc 27 ef c6 e9 11 a3 a1 fe e4 77 31
   3f fc e3 31 e2 89 33 c9 d6 1e 69 ba cb 0f 6c f1
   cc 71 33 b9 2b 01 06 bb f5 db bc 7f 95 9c 03 83
   48 b9 87 fc 16 18 08 a1 aa 7a c4 6d 77 08 1c 94
   5d 35 40 f0 dd c6 b0 34 0f 94 d7 08 70 c5 85 e5
   86 44 14 d6 a9 cc cb a9 23 86 da 27 47 ad fe 01
   d1 a3 73 12 fd 43 ff 15 7f 01 f6 22 06 d6 39 d1
   a4 27 8b a0 5e e4 1c 23 20 3c 43 8e 60 1b f6 a9
   2e 21 68 ac 8f 04 b0 f6 9c 82 69 96 4f 4a f8 c0
   da fa db 26 41 ee aa e8 e8 22 84 a0 0f af 75 b0
   14 4e 21 81 c5 fe 0d 10 e4 42 2c 07 ff 6c 18 56
   36 ab f1 9a 55 d9 d4 55 ff 12 13 56 57 6e 5f 50
   73 f8 a4 b5 b5 ec 85 03 00 94 e8 70 cc 2b 5b d7
   92 b4 86 51 16 53 dd 4f c0 58 ea 72 84 c1 e0 f0
   e6 c1 cc 55 74 b0 b1 2b 2a 20 7e d5 dc e6 76 10
   0b 32 5c 9d 97 29 6d a3 96 5d 9b 29 7f a5 c5 ed
   21 cf c8 2c a0 12 29 57 49 4b c1 91 94 a8 d6 56
   8c 78 6e 69 94 e6 bc 93 b3 02
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
   00 00 00 00 00 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 63 fe 26 8b 0c ab f9 7b f3
   0a 07 55 3f ad bd 9d 0b 18 e2 52 95 6d 10 a0 12
   e8 24 49 0f d4 43 6c 58 95 75 df f2 fa d1 60 6f
   56 a5 dd c6 5d 2c ce 3d 98 e3 a2 03 6a b1 d4 ae
   70 46 4b b2 95 99 68 a9 3d 7e b9 b1 99 a8 7e f2
   cf 7f 40 19 47 4c 10 15 f0 7b a0 a9 44 fb 1b ae
   07 24 39 8f d9 10 f8 b7 d4 bb 7f 8a 7d 2d fd 38
   ac 20 ce c0 48 73 24 9f 7b 89 b8 fe 32 b6 2d 45
   a9 63 4d 82 40 15 a6 8e fe 9b ce cd ba 69 e4 5b
   9d 66 22 e8 a0 4c a9 14 36 bf 78 58 7b 2d 10 e7
   f2 af c4 a7 df 99 9d f3 29 ba 7d 35 0c 67 09 4f
   7a 53 a8 be f1 10 bd 91 85 c6 87 d9 b4 88 84 bd
   84 bc 4d f2 a5 6e e0 e6 ed db 5f 80 d9 2c 4e f3
   8e cc 67 01 7a 95 e9 0f 6e 39 b3 36 f1 84 45 08
   1a 56 54 2c 88 c9 68 c0 b9 1b 29 8f 93 10 94 5e
   f0 1f 6a 9f 5e 7f 44 0e 33 67 e2 7b c3 be 9c f0
   65 e0 e1 e1 4d 56 f3 e3 55 72 b7 bd 2e 23 43 21
   68 fe b8 de f0 92 0e db 30 5d 81 d6 d1 16 8f 7e
   77 dd 84 99 05 a1 d1 16 26 70 c5 8f a4 fa c4 bd
   61 b6 0d 4d cb 7b 45 b8 c0 dc 67 49 f8 66 a4 be
   8f d0 9e d6 24 33 95 33 6d 41 f8 e1 92 e5 d1 ba
   c4 72 6b 7a a8 27 cf 5b ca 51 ff 3f dc 3f cd 32
   42 9a 64 fa 67 33 59 09 db b7 ae af 5d 16 4b 62
   14 fa 07 eb ba 01 44 33 ca bb b2 fb 59 7e 23 58
   83 a4 b6 94 1f d3 9a 3b fa 17 09 f1 e0 1e 1a f9
   06 7c 39 67 ab 17 62 36 d4 a7 df a9 24 d0 98 3b
   90 72 23 fe a1 8f 05 c8 f6 81 a8 f5 64 4f 9f 29
   b1 57 2c 9a b9 07 84 81 1b 0c 20 4b 3e 8c 3a d1
   21 c1 76 4e b8 c0 56 16 f4 45 8b 7b 5f c6 33 41
   20 46 25 2f 97 eb 8d af 53 e1 8b 31 09 a4 94 d3
   de 94 63 15 de 0b a2 38 2a d0 de 89 94 68 b6 8d
   07 31 b3 79 66 55 53 00 00 16
     - Inner TLS message 5 server_fragment_bytes_(decrypted): Container: 
       content = b'\x04\x00\x02\x15\x00\x00\x1c \r)\x16b\x08\x00\x00\x00'... (truncated, total 537)
       type = (enum) handshake 22
       zeros = None
     - handshake_message: [537 bytes]:
   04 00 02 15 00 00 1c 20 0d 29 16 62 08 00 00 00
   00 00 00 00 00 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 63 fe 26 8b 0c ab f9 7b f3
   0a 07 55 3f ad bd 9d 0b 18 e2 52 95 6d 10 a0 12
   e8 24 49 0f d4 43 6c 58 95 75 df f2 fa d1 60 6f
   56 a5 dd c6 5d 2c ce 3d 98 e3 a2 03 6a b1 d4 ae
   70 46 4b b2 95 99 68 a9 3d 7e b9 b1 99 a8 7e f2
   cf 7f 40 19 47 4c 10 15 f0 7b a0 a9 44 fb 1b ae
   07 24 39 8f d9 10 f8 b7 d4 bb 7f 8a 7d 2d fd 38
   ac 20 ce c0 48 73 24 9f 7b 89 b8 fe 32 b6 2d 45
   a9 63 4d 82 40 15 a6 8e fe 9b ce cd ba 69 e4 5b
   9d 66 22 e8 a0 4c a9 14 36 bf 78 58 7b 2d 10 e7
   f2 af c4 a7 df 99 9d f3 29 ba 7d 35 0c 67 09 4f
   7a 53 a8 be f1 10 bd 91 85 c6 87 d9 b4 88 84 bd
   84 bc 4d f2 a5 6e e0 e6 ed db 5f 80 d9 2c 4e f3
   8e cc 67 01 7a 95 e9 0f 6e 39 b3 36 f1 84 45 08
   1a 56 54 2c 88 c9 68 c0 b9 1b 29 8f 93 10 94 5e
   f0 1f 6a 9f 5e 7f 44 0e 33 67 e2 7b c3 be 9c f0
   65 e0 e1 e1 4d 56 f3 e3 55 72 b7 bd 2e 23 43 21
   68 fe b8 de f0 92 0e db 30 5d 81 d6 d1 16 8f 7e
   77 dd 84 99 05 a1 d1 16 26 70 c5 8f a4 fa c4 bd
   61 b6 0d 4d cb 7b 45 b8 c0 dc 67 49 f8 66 a4 be
   8f d0 9e d6 24 33 95 33 6d 41 f8 e1 92 e5 d1 ba
   c4 72 6b 7a a8 27 cf 5b ca 51 ff 3f dc 3f cd 32
   42 9a 64 fa 67 33 59 09 db b7 ae af 5d 16 4b 62
   14 fa 07 eb ba 01 44 33 ca bb b2 fb 59 7e 23 58
   83 a4 b6 94 1f d3 9a 3b fa 17 09 f1 e0 1e 1a f9
   06 7c 39 67 ab 17 62 36 d4 a7 df a9 24 d0 98 3b
   90 72 23 fe a1 8f 05 c8 f6 81 a8 f5 64 4f 9f 29
   b1 57 2c 9a b9 07 84 81 1b 0c 20 4b 3e 8c 3a d1
   21 c1 76 4e b8 c0 56 16 f4 45 8b 7b 5f c6 33 41
   20 46 25 2f 97 eb 8d af 53 e1 8b 31 09 a4 94 d3
   de 94 63 15 de 0b a2 38 2a d0 de 89 94 68 b6 8d
   07 31 b3 79 66 55 53 00 00
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
   00 00 00 00 00 02 00 43 08 3d ec 3a 25 bf 2d 1a
   a5 0b f9 6b 6e 5a 89 63 fe 26 8b 0c ab f9 7b f3
   0a 07 55 3f ad bd 9d 0b 18 e2 52 95 6d 10 a0 12
   e8 24 49 0f d4 43 6c 58 95 75 df f2 fa d1 60 6f
   56 a5 dd c6 5d 2c ce 3d 98 e3 a2 03 6a b1 d4 ae
   70 46 4b b2 95 99 68 a9 3d 7e b9 b1 99 a8 7e f2
   cf 7f 40 19 47 4c 10 15 f0 7b a0 a9 44 fb 1b ae
   07 24 39 8f d9 10 f8 b7 d4 bb 7f 8a 7d 2d fd 38
   ac 20 ce c0 48 73 24 9f 7b 89 b8 fe 32 b6 2d 45
   a9 63 4d 82 40 15 a6 8e fe 9b ce cd ba 69 e4 5b
   9d 66 22 e8 a0 4c a9 14 36 bf 78 58 7b 2d 10 e7
   f2 af c4 a7 df 99 9d f3 29 ba 7d 35 0c 67 09 4f
   7a 53 a8 be f1 10 bd 91 85 c6 87 d9 b4 88 84 bd
   84 bc 4d f2 a5 6e e0 e6 ed db 5f 80 d9 2c 4e f3
   8e cc 67 01 7a 95 e9 0f 6e 39 b3 36 f1 84 45 08
   1a 56 54 2c 88 c9 68 c0 b9 1b 29 8f 93 10 94 5e
   f0 1f 6a 9f 5e 7f 44 0e 33 67 e2 7b c3 be 9c f0
   65 e0 e1 e1 4d 56 f3 e3 55 72 b7 bd 2e 23 43 21
   68 fe b8 de f0 92 0e db 30 5d 81 d6 d1 16 8f 7e
   77 dd 84 99 05 a1 d1 16 26 70 c5 8f a4 fa c4 bd
   61 b6 0d 4d cb 7b 45 b8 c0 dc 67 49 f8 66 a4 be
   8f d0 9e d6 24 33 95 33 6d 41 f8 e1 92 e5 d1 ba
   c4 72 6b 7a a8 27 cf 5b ca 51 ff 3f dc 3f cd 32
   42 9a 64 fa 67 33 59 09 db b7 ae af 5d 16 4b 62
   14 fa 07 eb ba 01 44 33 ca bb b2 fb 59 7e 23 58
   83 a4 b6 94 1f d3 9a 3b fa 17 09 f1 e0 1e 1a f9
   06 7c 39 67 ab 17 62 36 d4 a7 df a9 24 d0 98 3b
   90 72 23 fe a1 8f 05 c8 f6 81 a8 f5 64 4f 9f 29
   b1 57 2c 9a b9 07 84 81 1b 0c 20 4b 3e 8c 3a d1
   21 c1 76 4e b8 c0 56 16 f4 45 8b 7b 5f c6 33 41
   20 46 25 2f 97 eb 8d af 53 e1 8b 31 09 a4 94 d3
   de 94 63 15 de 0b a2 38 2a d0 de 89 94 68 b6 8d
   07 31 b3 79 66 55 53 00 00
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
   17 03 03 15 8b 75 b1 26 cd 12 02 09 a8 cb 39 a1
   96 71 6f 76 f7 cc af 2e 0c 2a 14 a6 4d da b9 cf
   53 4d 74 9c 76 a4 84 83 7b a6 37 c9 ca 5d 1e 45
   05 96 33 75 90 02 5c 1b 7f fa 13 18 01 71 63 af
   b7 05 16 1f 5e d3 dc 9b ea d1 2c 1c bd 20 c4 f8
   64 c8 46 52 23 17 24 87 1f e8 08 ed 7a 61 95 74
   24 ed 79 bb 64 93 28 aa 7b c4 f5 f4 9e ff 26 ff
   2c 3e 0e dd 25 94 47 21 75 fd 13 61 83 b8 a3 ed
   65 15 18 08 96 f4 cd ae 95 60 f0 03 5f 52 bd 48
   58 a8 ca b9 ab 28 96 77 ad 8d 89 1c f6 79 54 a9
   cf 97 de 81 1c e1 de 39 2b 03 8a 29 30 98 45 cc
   50 29 f3 73 15 2b 91 c8 56 4d f4 e6 b5 75 19 67
   f1 28 4c 86 e9 34 cf cd 26 02 55 24 77 c3 c7 bf
   9a 74 6c 84 4e 4b 82 80 c8 34 40 9d 0f e6 65 d0
   95 56 4c 5e 71 4a b9 5d cf d0 b1 c5 de a1 99 ae
   8c 1e 20 67 d6 0d 81 97 d9 d9 c4 4f 63 b9 1d a4
   1d 7a ee b8 cd 5d 1c ce 00 79 eb 6e 8f 0f f1 68
   bb 61 d8 8a 27 38 1d af 31 76 5d 86 da a8 f4 bc
   8b 3a bf 65 16 7e c3 c5 ac be 02 5a 5a 93 2c b9
   37 0e 81 0a 3b f7 1f 3c 1a 4d 5a f9 01 53 07 32
   77 db 86 fc 94 6a b3 e0 20 51 31 fc 6d 08 f8 13
   0d e3 3a 1b 5d 2d d9 ac 7a fc 0e 9b 65 cb 98 fa
   3c b8 68 24 ea 84 53 da e3 9f ba 5a 18 8d 51 93
   7d 50 c4 69 37 14 6a 61 1b 99 79 d3 a5 da 89 ff
   f9 65 d1 fd 3a 42 f4 d6 bd 27 d4 34 f9 1f a6 5c
   90 f9 51 74 ad 03 c7 d9 d8 ec fb 6d 5c 90 e8 8f
   3d 70 60 8d c6 8f ef f1 75 f6 6b 31 05 08 8a dc
   4f 3a 78 d0 73 f1 8c 7b a8 6b fa c9 85 43 88 ce
   6f 46 14 c6 ad 1b de 9a 42 a8 23 c3 3e 5c 41 5b
   4e d6 fb 54 59 a3 10 c7 07 89 47 3a 53 09 fe 81
   7a 7a 7e 4f 4a 1a 32 91 ce aa 96 24 68 10 a4 e3
   45 d6 ac 10 ce e0 6e c1 b8 ea 89 0d af 5f 0e bc
   ab 39 03 6d b5 a8 8f 05 e9 dc 2a d0 11 9f 93 18
   b9 ac 6b 90 3a 40 66 d1 77 43 dc 37 b3 08 eb ec
   bd 8f f9 f5 bf b0 4f e7 88 89 d6 c3 42 d7 16 4d
   33 a1 3e 79 6b 75 93 9a 21 87 b5 2b af f4 f3 0a
   21 1f 39 7c 1f 54 51 4a 8e ab 3e 65 6b 4f f0 3b
   d6 26 ba df f4 57 76 00 56 e3 9c 35 67 cd ed b4
   a7 12 ee 82 63 3f 8d 17 d9 4e 02 15 a1 6e ce 4b
   78 76 24 23 04 18 69 35 49 ce 8e ea 88 01 d0 3b
   cc 92 74 79 ad e5 4c 54 4e 8d 51 b6 2f 72 60 ed
   8b 99 a9 3c 4c 4d 4f e6 b0 a8 83 64 f6 de 22 25
   64 2d 8b 17 36 c8 aa 4b 79 92 ac 51 93 ee e3 a9
   ee fd e9 6a f8 c7 eb 72 22 6d 7a ca b8 98 7c 3e
   9f ad 8c 81 fa 46 17 9a 45 50 d9 9b 37 64 77 28
   d4 52 64 4f 5c cc 9a bf 15 73 2c 79 c8 95 c8 bd
   05 36 fb 1f 49 b5 92 94 6a bf 11 4a 8d 7d eb 91
   84 96 28 50 0c 90 94 b0 ec c0 02 5b 73 ae 6b a7
   ce 1f ac 1d a0 5a 8c 34 f6 05 f3 f4 db c6 fd d0
   4a 9a 13 70 85 ba fc b5 4d 29 88 c5 9c dd 35 c5
   b1 de 9c 65 db bb 81 15 8e 18 bc c6 30 e0 11 4d
   d5 a0 11 ff c0 75 e1 b8 e9 b7 73 8d cc f0 54 bd
   d3 49 f3 4a 27 e4 9e 12 2c 1c c6 74 a6 a1 b8 9b
   a1 1f 26 11 ca 8d 8f 49 f9 36 42 4d 8e a8 67 48
   ae de 7d f5 f6 a9 68 fb 4e fc c7 5f 30 a7 29 89
   c2 06 d8 86 b9 c8 7e bd 98 53 86 20 73 2f 96 c3
   c9 23 ac 9d 3a f9 f4 2b 4c 12 ba c8 8f 21 59 67
   39 1c d8 a9 d5 07 14 2b dc 22 34 3e dc d0 47 ac
   c9 f5 a9 89 f2 cb 56 d6 20 40 9d ce ec ce 66 84
   68 54 66 58 cf 3d e4 85 7a 0f c5 d9 58 33 5f 0e
   e0 58 7f 2e c0 07 3b 66 43 90 7f 89 62 52 55 27
   fe 73 a8 b6 a3 06 61 9a a0 fd 55 c9 c4 2e da ff
   f0 fc 0d 33 f5 cd e7 15 dc ab 42 a7 12 10 8a a1
   50 82 6f f5 e5 07 f1 6b b2 e9 f3 bf 4b b0 86 97
   ba b3 2a 6e ce 40 b9 7e c4 c3 42 9c e1 1a 65 c2
   68 08 98 59 7b 99 68 d9 f8 1f 1e a1 e1 73 d9 b6
   2e 9a 9e 0c a0 e9 d7 79 d6 60 32 0f 3d 91 79 48
   19 03 c7 a7 63 e9 4e 86 87 1c 7b 95 9e d1 37 00
   68 8e 1c d7 de aa e1 97 3c ff 88 38 30 cc 1d 99
   0f c4 aa d4 f8 b8 08 8f 74 c9 64 4e 2f 06 51 50
   04 6e ee 8d 58 9c 76 94 67 34 e1 9a b7 75 cd 4e
   36 b5 b9 61 e0 4f 03 f4 f4 01 e3 56 73 18 c5 c3
   4f 38 19 8b da 67 6b da 36 ce cd 9d 2a 22 0c ad
   25 d0 44 78 d5 20 1d d1 76 26 8f f4 4f e0 65 67
   9a 4e 84 03 c3 eb 6f ce ec 74 e1 f7 7f 3c 34 24
   70 f1 22 02 60 22 ef 6f 9b 87 e4 e8 dd e5 ce 40
   e2 3c 54 78 46 a0 e7 1b ca bc 8a b3 a0 20 6d c9
   5f ec b3 0f ff 3d 68 68 26 46 48 46 b1 30 56 7e
   82 27 fc 20 4b 72 df 90 d5 9e b3 22 bb d3 3b e7
   37 65 ab ea d1 5a 76 db f8 e6 5a f1 cf 78 b2 b7
   d4 8b ca 96 87 9e 31 52 05 ae 9c 93 6b 96 2d 50
   4f 44 c5 55 79 d9 7c 52 39 bf 08 35 0e 80 cb 29
   8c 00 9d f2 13 af e6 bd e7 1b 9c 70 c5 e0 2f 4a
   92 48 f4 80 00 5a 22 da 02 72 5b a7 21 aa 4a b0
   03 d9 a2 39 45 6b 94 73 01 75 62 e7 81 8c e4 ad
   0a 12 be 05 03 74 bd 58 2c f9 4a 5c e8 2d b8 af
   df 5b a0 7b 72 6e 0a e7 fd 35 fb b0 65 bc c2 2d
   34 98 7c 64 fe 5e f3 8c ec 00 5a 1f 1a 2c c2 14
   5b df 45 2b 7c 0f 79 5c d9 7d b8 74 3d 34 e4 a1
   f1 5a 2a 48 84 be fa 12 3f 61 2c 20 31 10 3a db
   0f f0 28 e4 90 02 f1 de cd 8a 7a e8 db 1f bd 53
   d8 02 fc 81 cd ab 12 e9 c1 a7 b7 1a a3 52 e0 af
   a9 53 4a cb f2 61 30 dd 70 5f 08 45 c9 59 24 bb
   ae 03 e5 a8 50 30 b0 65 12 bb 50 0f 42 b5 1a c3
   26 5a 11 73 73 1f 12 ae 3f 79 ba d8 34 5b 9d 35
   cb fe af 4d ea 86 4b 56 5e c0 7e 7b ed 1c df d2
   29 86 2a 2d 3e aa c9 24 43 35 68 92 57 a1 b9 7e
   58 1c 9b 51 c7 57 2d 43 3e 93 cf 43 e4 6c 3a 01
   61 e0 6f c6 6f 20 d4 f1 af 8f 9e 03 9c cc e7 ab
   d3 36 38 b1 34 f8 de 1b 41 3b b4 2f 34 34 04 80
   62 4f c8 05 72 df 61 db 6b 21 41 f3 65 05 5b cb
   6e 08 bf d2 60 dd d6 ae 00 c8 8d df dd 00 55 e0
   12 ce c3 04 9a 34 1a c7 53 46 c8 68 dc ee eb 2d
   48 f1 34 c3 d2 37 42 81 c4 db 55 71 cc db 27 97
   db bb 76 55 89 30 63 4b 65 fd aa 16 c7 82 6c a2
   2f f9 7a 0c 69 6d 33 f1 08 df 15 c4 62 6e 30 5b
   3e b4 00 55 63 3d f8 ce 40 b2 0b 84 78 ef c0 af
   f5 ca 6e a2 e1 37 00 16 b6 c0 92 10 77 76 00 28
   4f 08 c7 6d 36 7d 2e 94 ea 06 de a6 c9 14 d7 26
   db 8e bb 46 61 ee 9b db 7f 90 18 9a c2 9e d5 f9
   f7 f4 32 47 86 2a e8 db 0f aa 0f 39 c1 47 46 28
   7f 71 6c bc fe f5 6e f6 93 1a ad da a9 83 e5 d3
   76 e8 e6 6d b2 fc 6a 1b f2 30 dd b7 89 34 4c 11
   33 c0 0b d9 ab 68 9b 34 35 8b d1 fc 99 e9 85 51
   ca 5f 53 44 42 60 04 0c 3e c0 5d 94 97 4f 41 d8
   58 86 e6 88 49 ed 2b 4f 25 c4 7c 83 4b cf e1 98
   a1 38 6f 54 02 7d 77 75 42 f4 d3 f7 b8 3d ea cd
   81 69 c8 79 f1 e9 93 63 c4 24 37 d1 20 5e 22 3f
   69 2a 46 27 bd fe 1f 2a d7 b2 d2 df 7e 1f a6 c0
   71 4a 4d 5a b8 16 8d 91 ee b7 e2 e2 c2 db 35 e5
   00 f4 46 3f c8 da 36 d7 28 3e 24 7d 4b 71 d0 c7
   1d a1 fe a9 80 ca d3 8a 30 9b 92 b6 e1 23 7e 11
   17 13 73 c9 a1 e9 16 0e ed 40 fc 83 33 49 4a af
   6d d0 20 9f ad 64 3b b7 f6 d3 ab 45 36 a9 04 b1
   02 01 ba ae bb 94 68 67 68 ba cf 77 19 1d c1 73
   d2 25 a3 c0 32 08 c2 d6 8b ea 5c 50 87 ae ea 42
   46 3c 9a 0d c5 85 60 bc ad 8b f4 50 71 2d ea ef
   2c 44 e5 9d 6d b4 d4 44 ef db a9 41 1b 1d 4e 44
   a8 7f a2 04 5d 2b 93 c6 30 3b 66 45 99 9e b6 e2
   28 2d 8d 90 e0 39 ca 8e 23 22 88 79 fc e4 5a 9c
   b7 01 b9 94 f6 16 12 f5 ed 00 16 10 20 5d b0 ed
   7b cb 29 dc 01 6e d4 dd 8f 0a 0e 8f 65 a8 2a 28
   c8 cd e4 cc 58 5d 5e 91 54 f0 67 8a 5c 54 75 4c
   1f ea d7 3c 07 b8 7d 32 d7 56 d6 13 1e 72 c2 d3
   a7 c5 07 a7 a1 82 8a 7e 5e ab 53 b2 90 76 0d 10
   50 1d fe d5 66 42 e6 bf 0a 3a 31 b6 c3 28 b2 83
   63 cc ff ba e9 de c1 e7 4b b6 76 b2 88 ae 43 97
   c4 9e 45 eb 19 29 dc ea 6e 4e 03 bf 28 78 27 99
   7c d8 d8 20 c3 e3 69 eb 52 16 a9 21 b1 23 63 81
   37 d1 d2 27 28 eb 96 45 ce e0 00 91 6b 30 e4 2c
   d5 d9 16 a8 3a 4f bd 38 29 92 4e 1e 16 24 0b 8b
   b1 20 63 f4 30 76 28 32 93 46 e0 b7 3a 57 38 5d
   2e 90 b9 e1 b6 15 bf 9f 1b 6b 75 95 8f 4a 3d 26
   42 62 b2 87 a0 48 39 69 74 94 36 f4 6e 43 f6 a1
   3f 39 40 25 78 37 03 7f 24 f8 6c 9a 0f 5d b8 13
   26 64 8b d7 9e 34 7e 86 37 28 29 e3 6e 64 51 5e
   8f 04 5a a9 3c 90 92 db 25 72 b5 19 86 27 57 5b
   a9 07 8f be c2 cb 84 cf 45 1d 0b d2 79 f5 17 52
   4d 10 19 64 89 c6 5b 64 66 f6 4e b5 6c a7 51 b0
   2a 3e 7f 9f a4 31 bb 67 d8 74 a0 3a d4 f3 6c 00
   1e 62 ba 70 89 4c 13 52 5c 90 db bc ae 46 ca fd
   2f 17 ed 2b 62 d7 c1 3f ff 8c 46 52 46 40 17 a7
   57 af b3 5b 31 83 a0 7e 15 89 86 87 c3 41 c4 a9
   8a 3b 91 f6 9c 17 8a 1b e6 32 b1 1b c3 0e 5c 61
   dd 3e 09 be eb d7 7f 96 d8 bd c2 d4 06 78 d6 cd
   2a 75 50 c2 6f 90 7d d3 15 53 8c aa 59 f8 b0 96
   db 68 03 7a 46 66 bc 73 58 4a ee 25 c1 1b 77 d0
   47 02 6e a2 db 36 7b 30 1a e4 aa 7f b5 ca 7c f7
   5d 1c d7 ac ee 32 37 fd 94 67 09 7b d1 d9 66 0f
   4c 2e 17 2a 47 34 54 d1 3e 28 0d e9 36 80 19 04
   88 1a 05 bc a1 10 8c eb db 2a bd f8 c5 d6 32 b0
   02 b1 48 c4 3d 06 5b 42 ff 0b 80 2d d2 ab 07 1a
   76 6a ef 31 6b 33 0a 9e f6 06 aa f6 a6 d6 df e0
   af 14 75 5b 4c 56 8e 37 3c 6e 42 59 f7 d1 b7 e9
   04 a0 e6 22 7f 58 80 ba 22 c2 81 05 d1 42 46 31
   fd 2a ea c3 bd ce fc 89 38 72 04 43 dd 34 bd 2e
   66 c7 bd d9 56 59 99 8a 9a 72 ee eb 7b 15 fb 83
   bd 2c f6 5c ce af 6a c8 df bb 09 d3 78 25 d6 34
   4e e7 d9 ea ca 1a 75 98 74 95 87 88 2c 7e 55 89
   cb 09 0a 09 1f 6c 24 f2 1a d2 d4 61 36 77 0b ef
   86 5d 2e a3 1d b9 8e 14 4e 9c 39 5f 66 95 df 9a
   db 20 e5 17 4a 77 a6 db 06 97 4a cf ca 96 1c 25
   a2 09 62 8f 1d 85 78 1a 0a c4 50 a8 8c 24 f0 77
   7f 17 68 93 b4 b2 aa 20 3b 9d ba d2 2c 92 0a 3e
   e1 f3 43 5f 67 25 34 1c cc c0 13 12 21 76 44 ab
   88 12 e0 e8 e0 b4 73 03 d8 9b c2 4b 2a f6 f3 6e
   9a f2 53 4b e3 20 69 ca e5 91 0f e9 af 17 c9 46
   da ec 13 66 44 04 8c 97 4a 6f 09 db b9 18 84 9a
   fe 8c 2a f6 9c e9 ba 45 68 79 cb 8b 75 01 9b cd
   fe 8f d1 59 8a 0b 74 1b 40 75 a4 1a b6 42 bb 2b
   03 35 bb 8f 97 d4 24 45 d3 8d 9b a2 83 7d 9a e9
   98 8c ad 3d dd 88 38 1c 0b 31 eb 35 c8 c1 2f 9e
   c5 3a b5 aa 6d 4b f0 46 fd ad 57 42 76 38 ef 37
   38 df 4e aa b6 8f 44 a7 30 5e 93 25 60 1c fc 05
   b6 69 72 51 a0 b3 8d d6 2f de 83 70 f3 b3 6c 33
   63 8f 4e 5a 0b b8 76 08 4d 49 9a b7 64 3d c3 fb
   4a 10 0a 76 62 20 1e f3 19 83 8f 8f 23 8f 8c 00
   b7 09 a9 f5 12 73 78 60 9a 21 64 d0 52 77 1c 31
   3b b6 77 50 44 3d 2f a4 98 af 07 6b b4 10 9a 45
   34 01 32 55 e8 64 af c3 47 a1 ac 92 1d 8d b8 89
   af 11 22 32 56 ad 64 42 a9 c4 8f 1e 70 ea 76 78
   08 e2 60 8f fe d4 e6 7c 3e 7d 2d 44 fa 02 17 ab
   27 c6 bb fa db 06 69 91 ed 9d 1e 54 28 6b 6c 57
   f8 8a 84 5c 19 07 e1 ad 3e 12 ba fc ad 75 30 47
   79 ac f7 00 3d 37 53 45 2f 89 44 c0 bd fd 79 32
   3c 42 fc f0 46 d7 75 21 fe d0 71 a5 59 3d 8b f4
   8e dc 7f 5e 63 70 4f dd 72 f2 d5 d8 4b 57 e6 4c
   68 1d c1 ef a4 d7 73 51 c4 5d ce c1 59 c6 b0 61
   a4 e2 76 3c 63 da 3d fb 5e 5a 5f 35 d6 41 f0 30
   2e 6b 96 11 9a cb 33 f5 bb d2 f5 e9 dc d6 8b 65
   32 4a bf 0c d1 1c 98 4a 20 e1 80 0b a3 d6 4e 5e
   3f 72 27 b9 57 d9 0c 1c 06 e1 99 61 4f 56 5a 42
   45 cd a0 44 2f ed 0a 38 99 d5 b3 86 6e ab 92 e0
   27 83 31 5c 87 f3 60 a6 ce a9 4d 71 e3 65 1e 2d
   38 00 0b 48 a4 7d e3 da 31 90 d6 91 b0 22 83 71
   40 35 8f 86 18 6d 9b 7f 14 34 ef cc bb 02 9b 98
   4b 58 cf 3e 74 ea 98 70 92 a4 40 3f 61 5e ef fc
   e5 3b bd ba 06 44 03 b2 d0 70 76 ee 27 3f 1a d5
   d6 b7 9e 33 37 78 c2 50 4c 57 15 55 ea e3 11 13
   e4 c9 04 3f ab 42 49 73 a0 f0 e2 83 5a 01 e2 db
   86 64 64 5c a6 39 66 66 56 bc fa fd d5 6c 76 82
   89 2e 78 ae 38 d6 bf 8d e7 53 fd e7 8c 39 eb 03
   a1 bb d8 87 72 84 34 54 85 0c 0b 89 17 f0 cb 41
   0e e8 f4 73 6e ed d8 03 42 7d 0d a7 ae cd e7 e8
   db 31 0d 28 cb ad 7b 28 3d 4f 41 41 89 1f 96 f4
   b0 55 0b ec 83 4d ee d1 56 83 86 29 52 df 8f 8d
   c3 00 dc 44 33 b1 3e 04 e1 69 25 be 36 e6 92 ce
   9f 13 6d dd c0 3a d9 d1 bb fa 0d 61 59 51 30 4f
   39 6b 26 48 11 a4 46 a9 bf 69 0f 8a 49 c6 17 ac
   86 a4 26 d0 3a 47 3c 48 48 d1 c6 a7 66 cb ac 6d
   22 e4 24 46 79 fc 5e a1 e8 ee 80 ff 48 d1 40 5e
   16 39 2d e3 8e 81 74 5b c7 ef 46 70 85 84 9a 6c
   70 66 0f 5b 9e eb bf 2e 97 42 c2 ca 49 bf 8e 6d
   52 81 21 f3 d8 2c 76 86 7f f4 1f 23 27 2e 37 37
   02 51 32 18 04 88 2c d6 b6 65 dd 2e 25 0a 82 f1
   1b 78 3d 73 90 69 33 5a 5c c4 1c 95 45 b5 f2 4b
   5a 37 87 e2 39 df 73 ce 40 0b 43 30 79 fd 9b eb
   5b 14 8d 25 ac f8 e1 e8 1e b0 d4 cb 71 17 d5 b3
   b6 16 17 b1 91 87 5e 1e 90 eb c0 54 2e 73 38 47
   14 48 54 a7 14 c7 bb fc f7 5e 18 4b 08 82 ef 29
   7e 4f 1c 0d ce b6 b5 c8 8e e3 9e 6a c5 ee 10 ad
   91 df 8c d9 4a ca f7 f2 88 9f 33 0b f5 74 9f 7f
   88 81 13 67 b2 c7 ae cc d5 51 be 18 92 61 02 4b
   a2 48 03 49 da 4c 5c 3f 18 b7 97 31 07 76 13 2b
   71 c4 ab a3 8d ac 49 b3 61 10 74 ea 41 77 62 47
   6d 9e 82 68 28 b0 dc a2 f5 04 7a d7 02 a0 de 60
   dd 91 47 2a ff 47 42 bf 0e 07 fa 48 ed 22 6f 1f
   4a ab e7 87 f6 7f 31 13 a3 c9 dc c5 97 fe 18 c9
   b8 38 3b a6 3a 29 08 bd 87 57 ce 30 bc 37 62 ae
   2a 45 f0 72 b4 51 77 a0 16 db da 3b bc 6e 9d 8f
   d5 99 f5 7d ec f9 df 1d d4 1d 75 a0 57 74 81 7d
   d3 c8 02 6a 31 10 f3 fc 2e 7e 77 e2 9a 7d 2d a9
   c4 c8 21 bb 69 77 d8 12 eb f0 9b 85 c5 1f 52 2e
   e2 23 a3 66 d4 66 bb b9 cd 39 86 9f 07 d8 a5 e7
   da e0 41 3c 56 dd b6 a6 fb 01 65 a6 d1 bb 18 de
   16 66 82 29 86 1f 8e 03 c2 26 d6 7c 32 a2 05 cf
   20 0e ce cf 9b df 47 40 31 7d 6d 2b 3a fd 23 7e
   d1 bd 73 0d 3b fa f6 f6 7c b6 84 3e 73 dd 7d ca
   0e 01 76 50 af 7f e7 f6 51 19 b5 42 41 c2 d4 1a
   f4 6a 16 60 02 c9 1b f2 73 6d 17 4c 70 d7 b1 d7
   8c 41 0e 20 21 11 c4 61 52 f8 b6 93 d6 f2 2e 1d
   59 ff aa a4 03 ae 1c 87 55 34 e8 bc 98 f2 3a 0c
   76 5a 0a f5 1f 2b ed 5e 74 31 86 e8 df b2 a5 86
   f1 1d e6 d9 23 18 9d fe 84 f8 fd f7 64 43 d3 ed
   a6 84 58 35 84 79 81 e6 a2 37 31 cd a9 20 2d bc
   e4 1f 09 db c7 c5 c6 a9 18 33 b3 ea 8c 2b 50 a7
   f0 95 86 6d c1 9b 99 7a 8c 91 8c 57 f2 30 42 79
   92 9e 0a cd 5e 5c 15 a4 f5 b6 fb 87 5d 2e 4b 3d
   3b fc 5a d3 af a1 31 21 8e 38 fa 75 e8 27 2f 22
   5d 63 98 fd 41 6f b8 15 68 5a 0f 4e 19 c4 ff cf
   1f bf 97 0c 42 42 9b 75 ef 11 e4 db 25 54 dc 95
   77 14 6b 9e 15 7b b8 fb d5 58 f1 68 1a e2 c9 bc
   8d 19 27 51 70 82 8c 49 12 c9 d4 ac 91 21 f9 da
   5b f6 00 33 bd e6 c2 6e 0b 71 f4 ad 8e c4 d6 c2
   dc 35 52 b7 1e ed 97 1e 4a 09 53 eb 30 9e 99 73
   55 3d 8c 70 52 6d 3a 9d ca 9d 3d 73 c8 b1 b0 7e
   80 a7 3c 2c 40 15 0f 99 f0 5b 47 4f 96 4a d7 c8
   93 2d 45 d9 8a 68 68 fc a8 62 25 a6 f8 50 41 7b
   3f eb 10 46 5f f9 cd 31 99 e7 ee f0 cb 78 26 3f
   05 6d 50 c8 f1 69 fd 0c e0 31 cd eb 96 e9 62 b4
   91 6d 7b 42 60 16 bb 3a da 8a f8 00 21 e4 a7 7d
   8b f9 23 ce 7a ab 57 f6 c0 88 00 4a 8d 69 76 64
   9e 30 8d c6 54 88 8c 87 59 be 77 2b 65 08 39 ab
   f0 1d 6a d4 e6 74 e9 ff 2b 79 b8 a2 ca 75 6c 06
   f0 dd 10 82 78 34 85 7d 2b 49 f4 a1 e6 7a 86 32
   4e 52 a1 e1 bf 3c f9 e8 8a 5c 43 fd 82 d3 19 fa
   c7 eb 28 49 0a 30 5a 14 94 41 78 fa 4f 84 bc 19
   ef 64 f6 2b 30 77 b5 e1 65 4f 33 47 4e 3d 85 7c
   66 3d 44 82 a4 3f 3e 10 93 b4 84 5e 77 ab 8d 89
   71 f3 56 83 15 15 06 1f ba 1c 09 01 eb 92 2c e3
   25 bb 25 2c 6b 32 e2 3a 3c ce 16 63 e5 d0 bc 05
   ce b0 b2 ef 8e 34 04 1c 39 9e 19 71 43 85 9e 4c
   d9 59 cd e7 6d 89 c7 17 c8 39 71 de df 32 e7 fa
   4b 93 0c ae e1 27 8a 16 a2 d3 7b 4b 17 b7 39 7e
   98 88 86 7a b2 b6 e3 65 25 3e 19 de 92 c1 9c d9
   b2 44 4c a2 4a 8a 18 e1 41 c4 78 87 98 c4 a8 ed
   a1 67 ce b3 c2 6a cb a5 f8 b4 6c df 01 3f 6d 79
   1e 9e cb b8 84 b5 b8 0b 5d a4 3e e0 17 b0 4e c8
   e2 2f 7a 6b 4b 74 9f 45 f0 b6 06 d5 63 92 72 8f
   18 e6 e9 68 22 c2 07 35 ca df a6 d2 1c 4d f6 c7
   fa 0c f4 26 42 1f a2 84 ef 22 d5 eb ab 7b d8 5c
   b5 e5 62 ef 92 ce bf ac 18 ac 51 f5 d1 7f cb c4
   01 44 e0 b4 6b 33 28 07 2d 82 14 03 0b 88 af 66
   8b 03 7b b4 c9 08 6b 96 cb 77 66 54 3f 81 8a 57
   4c 9b b4 98 f2 cc c6 b2 1e ff 79 dc 39 56 47 d5
   51 79 ec 92 6f 25 34 02 87 1b d5 c5 96 08 28 81
   8f 47 82 39 cc 37 dd 62 c4 2d 82 89 f4 a9 7a 3a
   53 28 fe ea ba 82 a3 86 7f b6 bc 93 fe b1 6e 21
   c3 07 66 e6 86 ac f0 c7 d8 b6 31 23 4f 86 32 be
   57 09 75 94 28 59 4e 4c 7e 2b 5e 06 37 1e ff b8
   fd b5 52 08 13 61 b1 51 fd 0c 46 b8 9b 22 85 ff
   2e f6 6b b6 f0 b1 b9 3b ac 61 f7 69 80 3f ab 86
   4a d4 f6 40 63 90 e8 8d 75 72 ee 56 29 8b be c3
   33 d3 8a 2d 2a 98 2a 65 cc 58 f4 b6 75 26 26 e3
   3e f2 2f 6d 90 49 90 a4 ca 8a 9d 3a f7 03 e9 91
   68 10 8d 36 5d 88 1a a7 b4 d2 49 5b 19 63 2b 9d
   a2 16 30 8a 35 01 24 80 be 49 04 9a a1 d9 cc 01
   22 d6 90 27 5f 84 6c fb 90 56 42 eb be 68 ea b7
   ab 51 45 a5 1e 88 1a af 5b 69 80 2c 44 d3 f8 8b
   41 ce fe 57 84 87 14 08 c7 20 77 d0 ee d7 48 1f
   ff 80 2e b2 d1 88 a0 62 54 ef f1 d5 7e 16 c8 fb
   55 34 45 a0 c3 cc 70 2b 5a d9 50 1e ad 04 e2 34
   2e 73 ab d3 b8 99 4c 87 fa 3e 3c 4b 55 e4 7f 75
   ac 84 e3 ce a8 c6 2e a3 d6 15 4c 2f 6f 58 7f de
   a4 6f 6f 36 63 e0 31 9d 76 1a 9d 85 e0 cd d0 81
   02 c1 49 17 f3 c8 58 fd d3 8b ba b8 d6 5e 32 50
   ff b4 57 d3 f4 ca 93 08 d4 3b 84 35 91 73 05 9e
   ab fc bf 0f ea 76 e7 9f b9 45 ad dd 7d de 37 ba
   89 d5 ec 02 65 84 69 64 90 b4 e8 66 9a 8d 89 9e
   c0 80 9e 09 42 bc cb c9 6f 15 d2 24 09 de 75 14
   de d0 9e 43 8d 0c 78 f7 d7 27 72 08 a4 55 21 2c
   30 ec 47 f7 4f 4f 79 05 da 96 44 0a 8a 14 dd c3
   a9 8f 57 83 d7 6f 1b bb ac c5 33 01 63 3c 42 e0
   02 15 89 8b a6 18 fa 85 8b d0 ec 18 39 a5 cb 09
   30 c7 8f 0d 13 19 40 75 f8 26 45 67 da 2e d8 12
   d8 b1 41 e5 1a 55 35 40 33 24 95 6d 33 57 4b ba
   3f ea 1d cd ba 86 d9 0b d2 99 b3 2a 0a ae 83 7a
   79 d5 7d 90 c0 72 ef 8b 64 bf 03 4d 33 74 78 e1
   72 2b a4 64 66 78 c1 b4 36 0a 31 cc fa 4f 23 db
   a3 c6 40 4f 33 34 15 f2 07 9a 10 f8 47 79 9e 65
   51 b0 d7 ca 09 61 72 a2 9d 0a 92 73 d6 1b 27 80
   31 b5 dd d1 b2 c5 04 2e 99 e7 8f 91 a7 dd cb 5a
   4f 65 42 95 ca 75 15 f2 da be f3 36 70 ec 91 23
   fa 3c b4 69 2e 54 15 8e b8 52 e4 3c 61 a1 d1 31
   fd dc c2 a5 89 7a c3 e1 aa bd 5f f4 d1 bc 82 4d
   aa e6 0b 5a a4 6c 0a 6e a1 02 58 00 8d 85 a5 2b
   17 b5 04 f1 e4 98 b1 4c f1 6f 0d c8 e7 ac 3c 40
   65 1d b1 7f 49 54 3d 9c f6 25 eb 7d 36 75 a6 cd
   e3 42 a6 2d 20 ef df 5c 42 e3 82 bf 5f e7 3f cd
   73 ea e4 fb c1 1a 90 7c 57 c3 2d de de d2 73 72
   b5 aa 1f 47 c6 9a 7a cf 4f 06 93 70 64 2f 56 ce
   0b 9b f7 8f 91 2c c4 58 7c 8d 89 b2 c0 80 bb 39
   78 da 5d 04 14 b2 5f 54 91 b1 29 42 14 9f c6 b7
   f6 19 e6 2d f0 6f f0 14 6e 62 c2 9b 67 e3 88 bd
   6b d3 51 ea dd ad 65 42 54 de 3f ed 6c ba fc 71
     - TLS record 6 server_application_data: Container: 
       type = (enum) application_data 23
       legacy_record_version = b'\x03\x03' (total 2)
       fragment = b'u\xb1&\xcd\x12\x02\t\xa8\xcb9\xa1\x96qov\xf7'... (truncated, total 5515)
     - fragment (encrypted) [5515 bytes]:
   75 b1 26 cd 12 02 09 a8 cb 39 a1 96 71 6f 76 f7
   cc af 2e 0c 2a 14 a6 4d da b9 cf 53 4d 74 9c 76
   a4 84 83 7b a6 37 c9 ca 5d 1e 45 05 96 33 75 90
   02 5c 1b 7f fa 13 18 01 71 63 af b7 05 16 1f 5e
   d3 dc 9b ea d1 2c 1c bd 20 c4 f8 64 c8 46 52 23
   17 24 87 1f e8 08 ed 7a 61 95 74 24 ed 79 bb 64
   93 28 aa 7b c4 f5 f4 9e ff 26 ff 2c 3e 0e dd 25
   94 47 21 75 fd 13 61 83 b8 a3 ed 65 15 18 08 96
   f4 cd ae 95 60 f0 03 5f 52 bd 48 58 a8 ca b9 ab
   28 96 77 ad 8d 89 1c f6 79 54 a9 cf 97 de 81 1c
   e1 de 39 2b 03 8a 29 30 98 45 cc 50 29 f3 73 15
   2b 91 c8 56 4d f4 e6 b5 75 19 67 f1 28 4c 86 e9
   34 cf cd 26 02 55 24 77 c3 c7 bf 9a 74 6c 84 4e
   4b 82 80 c8 34 40 9d 0f e6 65 d0 95 56 4c 5e 71
   4a b9 5d cf d0 b1 c5 de a1 99 ae 8c 1e 20 67 d6
   0d 81 97 d9 d9 c4 4f 63 b9 1d a4 1d 7a ee b8 cd
   5d 1c ce 00 79 eb 6e 8f 0f f1 68 bb 61 d8 8a 27
   38 1d af 31 76 5d 86 da a8 f4 bc 8b 3a bf 65 16
   7e c3 c5 ac be 02 5a 5a 93 2c b9 37 0e 81 0a 3b
   f7 1f 3c 1a 4d 5a f9 01 53 07 32 77 db 86 fc 94
   6a b3 e0 20 51 31 fc 6d 08 f8 13 0d e3 3a 1b 5d
   2d d9 ac 7a fc 0e 9b 65 cb 98 fa 3c b8 68 24 ea
   84 53 da e3 9f ba 5a 18 8d 51 93 7d 50 c4 69 37
   14 6a 61 1b 99 79 d3 a5 da 89 ff f9 65 d1 fd 3a
   42 f4 d6 bd 27 d4 34 f9 1f a6 5c 90 f9 51 74 ad
   03 c7 d9 d8 ec fb 6d 5c 90 e8 8f 3d 70 60 8d c6
   8f ef f1 75 f6 6b 31 05 08 8a dc 4f 3a 78 d0 73
   f1 8c 7b a8 6b fa c9 85 43 88 ce 6f 46 14 c6 ad
   1b de 9a 42 a8 23 c3 3e 5c 41 5b 4e d6 fb 54 59
   a3 10 c7 07 89 47 3a 53 09 fe 81 7a 7a 7e 4f 4a
   1a 32 91 ce aa 96 24 68 10 a4 e3 45 d6 ac 10 ce
   e0 6e c1 b8 ea 89 0d af 5f 0e bc ab 39 03 6d b5
   a8 8f 05 e9 dc 2a d0 11 9f 93 18 b9 ac 6b 90 3a
   40 66 d1 77 43 dc 37 b3 08 eb ec bd 8f f9 f5 bf
   b0 4f e7 88 89 d6 c3 42 d7 16 4d 33 a1 3e 79 6b
   75 93 9a 21 87 b5 2b af f4 f3 0a 21 1f 39 7c 1f
   54 51 4a 8e ab 3e 65 6b 4f f0 3b d6 26 ba df f4
   57 76 00 56 e3 9c 35 67 cd ed b4 a7 12 ee 82 63
   3f 8d 17 d9 4e 02 15 a1 6e ce 4b 78 76 24 23 04
   18 69 35 49 ce 8e ea 88 01 d0 3b cc 92 74 79 ad
   e5 4c 54 4e 8d 51 b6 2f 72 60 ed 8b 99 a9 3c 4c
   4d 4f e6 b0 a8 83 64 f6 de 22 25 64 2d 8b 17 36
   c8 aa 4b 79 92 ac 51 93 ee e3 a9 ee fd e9 6a f8
   c7 eb 72 22 6d 7a ca b8 98 7c 3e 9f ad 8c 81 fa
   46 17 9a 45 50 d9 9b 37 64 77 28 d4 52 64 4f 5c
   cc 9a bf 15 73 2c 79 c8 95 c8 bd 05 36 fb 1f 49
   b5 92 94 6a bf 11 4a 8d 7d eb 91 84 96 28 50 0c
   90 94 b0 ec c0 02 5b 73 ae 6b a7 ce 1f ac 1d a0
   5a 8c 34 f6 05 f3 f4 db c6 fd d0 4a 9a 13 70 85
   ba fc b5 4d 29 88 c5 9c dd 35 c5 b1 de 9c 65 db
   bb 81 15 8e 18 bc c6 30 e0 11 4d d5 a0 11 ff c0
   75 e1 b8 e9 b7 73 8d cc f0 54 bd d3 49 f3 4a 27
   e4 9e 12 2c 1c c6 74 a6 a1 b8 9b a1 1f 26 11 ca
   8d 8f 49 f9 36 42 4d 8e a8 67 48 ae de 7d f5 f6
   a9 68 fb 4e fc c7 5f 30 a7 29 89 c2 06 d8 86 b9
   c8 7e bd 98 53 86 20 73 2f 96 c3 c9 23 ac 9d 3a
   f9 f4 2b 4c 12 ba c8 8f 21 59 67 39 1c d8 a9 d5
   07 14 2b dc 22 34 3e dc d0 47 ac c9 f5 a9 89 f2
   cb 56 d6 20 40 9d ce ec ce 66 84 68 54 66 58 cf
   3d e4 85 7a 0f c5 d9 58 33 5f 0e e0 58 7f 2e c0
   07 3b 66 43 90 7f 89 62 52 55 27 fe 73 a8 b6 a3
   06 61 9a a0 fd 55 c9 c4 2e da ff f0 fc 0d 33 f5
   cd e7 15 dc ab 42 a7 12 10 8a a1 50 82 6f f5 e5
   07 f1 6b b2 e9 f3 bf 4b b0 86 97 ba b3 2a 6e ce
   40 b9 7e c4 c3 42 9c e1 1a 65 c2 68 08 98 59 7b
   99 68 d9 f8 1f 1e a1 e1 73 d9 b6 2e 9a 9e 0c a0
   e9 d7 79 d6 60 32 0f 3d 91 79 48 19 03 c7 a7 63
   e9 4e 86 87 1c 7b 95 9e d1 37 00 68 8e 1c d7 de
   aa e1 97 3c ff 88 38 30 cc 1d 99 0f c4 aa d4 f8
   b8 08 8f 74 c9 64 4e 2f 06 51 50 04 6e ee 8d 58
   9c 76 94 67 34 e1 9a b7 75 cd 4e 36 b5 b9 61 e0
   4f 03 f4 f4 01 e3 56 73 18 c5 c3 4f 38 19 8b da
   67 6b da 36 ce cd 9d 2a 22 0c ad 25 d0 44 78 d5
   20 1d d1 76 26 8f f4 4f e0 65 67 9a 4e 84 03 c3
   eb 6f ce ec 74 e1 f7 7f 3c 34 24 70 f1 22 02 60
   22 ef 6f 9b 87 e4 e8 dd e5 ce 40 e2 3c 54 78 46
   a0 e7 1b ca bc 8a b3 a0 20 6d c9 5f ec b3 0f ff
   3d 68 68 26 46 48 46 b1 30 56 7e 82 27 fc 20 4b
   72 df 90 d5 9e b3 22 bb d3 3b e7 37 65 ab ea d1
   5a 76 db f8 e6 5a f1 cf 78 b2 b7 d4 8b ca 96 87
   9e 31 52 05 ae 9c 93 6b 96 2d 50 4f 44 c5 55 79
   d9 7c 52 39 bf 08 35 0e 80 cb 29 8c 00 9d f2 13
   af e6 bd e7 1b 9c 70 c5 e0 2f 4a 92 48 f4 80 00
   5a 22 da 02 72 5b a7 21 aa 4a b0 03 d9 a2 39 45
   6b 94 73 01 75 62 e7 81 8c e4 ad 0a 12 be 05 03
   74 bd 58 2c f9 4a 5c e8 2d b8 af df 5b a0 7b 72
   6e 0a e7 fd 35 fb b0 65 bc c2 2d 34 98 7c 64 fe
   5e f3 8c ec 00 5a 1f 1a 2c c2 14 5b df 45 2b 7c
   0f 79 5c d9 7d b8 74 3d 34 e4 a1 f1 5a 2a 48 84
   be fa 12 3f 61 2c 20 31 10 3a db 0f f0 28 e4 90
   02 f1 de cd 8a 7a e8 db 1f bd 53 d8 02 fc 81 cd
   ab 12 e9 c1 a7 b7 1a a3 52 e0 af a9 53 4a cb f2
   61 30 dd 70 5f 08 45 c9 59 24 bb ae 03 e5 a8 50
   30 b0 65 12 bb 50 0f 42 b5 1a c3 26 5a 11 73 73
   1f 12 ae 3f 79 ba d8 34 5b 9d 35 cb fe af 4d ea
   86 4b 56 5e c0 7e 7b ed 1c df d2 29 86 2a 2d 3e
   aa c9 24 43 35 68 92 57 a1 b9 7e 58 1c 9b 51 c7
   57 2d 43 3e 93 cf 43 e4 6c 3a 01 61 e0 6f c6 6f
   20 d4 f1 af 8f 9e 03 9c cc e7 ab d3 36 38 b1 34
   f8 de 1b 41 3b b4 2f 34 34 04 80 62 4f c8 05 72
   df 61 db 6b 21 41 f3 65 05 5b cb 6e 08 bf d2 60
   dd d6 ae 00 c8 8d df dd 00 55 e0 12 ce c3 04 9a
   34 1a c7 53 46 c8 68 dc ee eb 2d 48 f1 34 c3 d2
   37 42 81 c4 db 55 71 cc db 27 97 db bb 76 55 89
   30 63 4b 65 fd aa 16 c7 82 6c a2 2f f9 7a 0c 69
   6d 33 f1 08 df 15 c4 62 6e 30 5b 3e b4 00 55 63
   3d f8 ce 40 b2 0b 84 78 ef c0 af f5 ca 6e a2 e1
   37 00 16 b6 c0 92 10 77 76 00 28 4f 08 c7 6d 36
   7d 2e 94 ea 06 de a6 c9 14 d7 26 db 8e bb 46 61
   ee 9b db 7f 90 18 9a c2 9e d5 f9 f7 f4 32 47 86
   2a e8 db 0f aa 0f 39 c1 47 46 28 7f 71 6c bc fe
   f5 6e f6 93 1a ad da a9 83 e5 d3 76 e8 e6 6d b2
   fc 6a 1b f2 30 dd b7 89 34 4c 11 33 c0 0b d9 ab
   68 9b 34 35 8b d1 fc 99 e9 85 51 ca 5f 53 44 42
   60 04 0c 3e c0 5d 94 97 4f 41 d8 58 86 e6 88 49
   ed 2b 4f 25 c4 7c 83 4b cf e1 98 a1 38 6f 54 02
   7d 77 75 42 f4 d3 f7 b8 3d ea cd 81 69 c8 79 f1
   e9 93 63 c4 24 37 d1 20 5e 22 3f 69 2a 46 27 bd
   fe 1f 2a d7 b2 d2 df 7e 1f a6 c0 71 4a 4d 5a b8
   16 8d 91 ee b7 e2 e2 c2 db 35 e5 00 f4 46 3f c8
   da 36 d7 28 3e 24 7d 4b 71 d0 c7 1d a1 fe a9 80
   ca d3 8a 30 9b 92 b6 e1 23 7e 11 17 13 73 c9 a1
   e9 16 0e ed 40 fc 83 33 49 4a af 6d d0 20 9f ad
   64 3b b7 f6 d3 ab 45 36 a9 04 b1 02 01 ba ae bb
   94 68 67 68 ba cf 77 19 1d c1 73 d2 25 a3 c0 32
   08 c2 d6 8b ea 5c 50 87 ae ea 42 46 3c 9a 0d c5
   85 60 bc ad 8b f4 50 71 2d ea ef 2c 44 e5 9d 6d
   b4 d4 44 ef db a9 41 1b 1d 4e 44 a8 7f a2 04 5d
   2b 93 c6 30 3b 66 45 99 9e b6 e2 28 2d 8d 90 e0
   39 ca 8e 23 22 88 79 fc e4 5a 9c b7 01 b9 94 f6
   16 12 f5 ed 00 16 10 20 5d b0 ed 7b cb 29 dc 01
   6e d4 dd 8f 0a 0e 8f 65 a8 2a 28 c8 cd e4 cc 58
   5d 5e 91 54 f0 67 8a 5c 54 75 4c 1f ea d7 3c 07
   b8 7d 32 d7 56 d6 13 1e 72 c2 d3 a7 c5 07 a7 a1
   82 8a 7e 5e ab 53 b2 90 76 0d 10 50 1d fe d5 66
   42 e6 bf 0a 3a 31 b6 c3 28 b2 83 63 cc ff ba e9
   de c1 e7 4b b6 76 b2 88 ae 43 97 c4 9e 45 eb 19
   29 dc ea 6e 4e 03 bf 28 78 27 99 7c d8 d8 20 c3
   e3 69 eb 52 16 a9 21 b1 23 63 81 37 d1 d2 27 28
   eb 96 45 ce e0 00 91 6b 30 e4 2c d5 d9 16 a8 3a
   4f bd 38 29 92 4e 1e 16 24 0b 8b b1 20 63 f4 30
   76 28 32 93 46 e0 b7 3a 57 38 5d 2e 90 b9 e1 b6
   15 bf 9f 1b 6b 75 95 8f 4a 3d 26 42 62 b2 87 a0
   48 39 69 74 94 36 f4 6e 43 f6 a1 3f 39 40 25 78
   37 03 7f 24 f8 6c 9a 0f 5d b8 13 26 64 8b d7 9e
   34 7e 86 37 28 29 e3 6e 64 51 5e 8f 04 5a a9 3c
   90 92 db 25 72 b5 19 86 27 57 5b a9 07 8f be c2
   cb 84 cf 45 1d 0b d2 79 f5 17 52 4d 10 19 64 89
   c6 5b 64 66 f6 4e b5 6c a7 51 b0 2a 3e 7f 9f a4
   31 bb 67 d8 74 a0 3a d4 f3 6c 00 1e 62 ba 70 89
   4c 13 52 5c 90 db bc ae 46 ca fd 2f 17 ed 2b 62
   d7 c1 3f ff 8c 46 52 46 40 17 a7 57 af b3 5b 31
   83 a0 7e 15 89 86 87 c3 41 c4 a9 8a 3b 91 f6 9c
   17 8a 1b e6 32 b1 1b c3 0e 5c 61 dd 3e 09 be eb
   d7 7f 96 d8 bd c2 d4 06 78 d6 cd 2a 75 50 c2 6f
   90 7d d3 15 53 8c aa 59 f8 b0 96 db 68 03 7a 46
   66 bc 73 58 4a ee 25 c1 1b 77 d0 47 02 6e a2 db
   36 7b 30 1a e4 aa 7f b5 ca 7c f7 5d 1c d7 ac ee
   32 37 fd 94 67 09 7b d1 d9 66 0f 4c 2e 17 2a 47
   34 54 d1 3e 28 0d e9 36 80 19 04 88 1a 05 bc a1
   10 8c eb db 2a bd f8 c5 d6 32 b0 02 b1 48 c4 3d
   06 5b 42 ff 0b 80 2d d2 ab 07 1a 76 6a ef 31 6b
   33 0a 9e f6 06 aa f6 a6 d6 df e0 af 14 75 5b 4c
   56 8e 37 3c 6e 42 59 f7 d1 b7 e9 04 a0 e6 22 7f
   58 80 ba 22 c2 81 05 d1 42 46 31 fd 2a ea c3 bd
   ce fc 89 38 72 04 43 dd 34 bd 2e 66 c7 bd d9 56
   59 99 8a 9a 72 ee eb 7b 15 fb 83 bd 2c f6 5c ce
   af 6a c8 df bb 09 d3 78 25 d6 34 4e e7 d9 ea ca
   1a 75 98 74 95 87 88 2c 7e 55 89 cb 09 0a 09 1f
   6c 24 f2 1a d2 d4 61 36 77 0b ef 86 5d 2e a3 1d
   b9 8e 14 4e 9c 39 5f 66 95 df 9a db 20 e5 17 4a
   77 a6 db 06 97 4a cf ca 96 1c 25 a2 09 62 8f 1d
   85 78 1a 0a c4 50 a8 8c 24 f0 77 7f 17 68 93 b4
   b2 aa 20 3b 9d ba d2 2c 92 0a 3e e1 f3 43 5f 67
   25 34 1c cc c0 13 12 21 76 44 ab 88 12 e0 e8 e0
   b4 73 03 d8 9b c2 4b 2a f6 f3 6e 9a f2 53 4b e3
   20 69 ca e5 91 0f e9 af 17 c9 46 da ec 13 66 44
   04 8c 97 4a 6f 09 db b9 18 84 9a fe 8c 2a f6 9c
   e9 ba 45 68 79 cb 8b 75 01 9b cd fe 8f d1 59 8a
   0b 74 1b 40 75 a4 1a b6 42 bb 2b 03 35 bb 8f 97
   d4 24 45 d3 8d 9b a2 83 7d 9a e9 98 8c ad 3d dd
   88 38 1c 0b 31 eb 35 c8 c1 2f 9e c5 3a b5 aa 6d
   4b f0 46 fd ad 57 42 76 38 ef 37 38 df 4e aa b6
   8f 44 a7 30 5e 93 25 60 1c fc 05 b6 69 72 51 a0
   b3 8d d6 2f de 83 70 f3 b3 6c 33 63 8f 4e 5a 0b
   b8 76 08 4d 49 9a b7 64 3d c3 fb 4a 10 0a 76 62
   20 1e f3 19 83 8f 8f 23 8f 8c 00 b7 09 a9 f5 12
   73 78 60 9a 21 64 d0 52 77 1c 31 3b b6 77 50 44
   3d 2f a4 98 af 07 6b b4 10 9a 45 34 01 32 55 e8
   64 af c3 47 a1 ac 92 1d 8d b8 89 af 11 22 32 56
   ad 64 42 a9 c4 8f 1e 70 ea 76 78 08 e2 60 8f fe
   d4 e6 7c 3e 7d 2d 44 fa 02 17 ab 27 c6 bb fa db
   06 69 91 ed 9d 1e 54 28 6b 6c 57 f8 8a 84 5c 19
   07 e1 ad 3e 12 ba fc ad 75 30 47 79 ac f7 00 3d
   37 53 45 2f 89 44 c0 bd fd 79 32 3c 42 fc f0 46
   d7 75 21 fe d0 71 a5 59 3d 8b f4 8e dc 7f 5e 63
   70 4f dd 72 f2 d5 d8 4b 57 e6 4c 68 1d c1 ef a4
   d7 73 51 c4 5d ce c1 59 c6 b0 61 a4 e2 76 3c 63
   da 3d fb 5e 5a 5f 35 d6 41 f0 30 2e 6b 96 11 9a
   cb 33 f5 bb d2 f5 e9 dc d6 8b 65 32 4a bf 0c d1
   1c 98 4a 20 e1 80 0b a3 d6 4e 5e 3f 72 27 b9 57
   d9 0c 1c 06 e1 99 61 4f 56 5a 42 45 cd a0 44 2f
   ed 0a 38 99 d5 b3 86 6e ab 92 e0 27 83 31 5c 87
   f3 60 a6 ce a9 4d 71 e3 65 1e 2d 38 00 0b 48 a4
   7d e3 da 31 90 d6 91 b0 22 83 71 40 35 8f 86 18
   6d 9b 7f 14 34 ef cc bb 02 9b 98 4b 58 cf 3e 74
   ea 98 70 92 a4 40 3f 61 5e ef fc e5 3b bd ba 06
   44 03 b2 d0 70 76 ee 27 3f 1a d5 d6 b7 9e 33 37
   78 c2 50 4c 57 15 55 ea e3 11 13 e4 c9 04 3f ab
   42 49 73 a0 f0 e2 83 5a 01 e2 db 86 64 64 5c a6
   39 66 66 56 bc fa fd d5 6c 76 82 89 2e 78 ae 38
   d6 bf 8d e7 53 fd e7 8c 39 eb 03 a1 bb d8 87 72
   84 34 54 85 0c 0b 89 17 f0 cb 41 0e e8 f4 73 6e
   ed d8 03 42 7d 0d a7 ae cd e7 e8 db 31 0d 28 cb
   ad 7b 28 3d 4f 41 41 89 1f 96 f4 b0 55 0b ec 83
   4d ee d1 56 83 86 29 52 df 8f 8d c3 00 dc 44 33
   b1 3e 04 e1 69 25 be 36 e6 92 ce 9f 13 6d dd c0
   3a d9 d1 bb fa 0d 61 59 51 30 4f 39 6b 26 48 11
   a4 46 a9 bf 69 0f 8a 49 c6 17 ac 86 a4 26 d0 3a
   47 3c 48 48 d1 c6 a7 66 cb ac 6d 22 e4 24 46 79
   fc 5e a1 e8 ee 80 ff 48 d1 40 5e 16 39 2d e3 8e
   81 74 5b c7 ef 46 70 85 84 9a 6c 70 66 0f 5b 9e
   eb bf 2e 97 42 c2 ca 49 bf 8e 6d 52 81 21 f3 d8
   2c 76 86 7f f4 1f 23 27 2e 37 37 02 51 32 18 04
   88 2c d6 b6 65 dd 2e 25 0a 82 f1 1b 78 3d 73 90
   69 33 5a 5c c4 1c 95 45 b5 f2 4b 5a 37 87 e2 39
   df 73 ce 40 0b 43 30 79 fd 9b eb 5b 14 8d 25 ac
   f8 e1 e8 1e b0 d4 cb 71 17 d5 b3 b6 16 17 b1 91
   87 5e 1e 90 eb c0 54 2e 73 38 47 14 48 54 a7 14
   c7 bb fc f7 5e 18 4b 08 82 ef 29 7e 4f 1c 0d ce
   b6 b5 c8 8e e3 9e 6a c5 ee 10 ad 91 df 8c d9 4a
   ca f7 f2 88 9f 33 0b f5 74 9f 7f 88 81 13 67 b2
   c7 ae cc d5 51 be 18 92 61 02 4b a2 48 03 49 da
   4c 5c 3f 18 b7 97 31 07 76 13 2b 71 c4 ab a3 8d
   ac 49 b3 61 10 74 ea 41 77 62 47 6d 9e 82 68 28
   b0 dc a2 f5 04 7a d7 02 a0 de 60 dd 91 47 2a ff
   47 42 bf 0e 07 fa 48 ed 22 6f 1f 4a ab e7 87 f6
   7f 31 13 a3 c9 dc c5 97 fe 18 c9 b8 38 3b a6 3a
   29 08 bd 87 57 ce 30 bc 37 62 ae 2a 45 f0 72 b4
   51 77 a0 16 db da 3b bc 6e 9d 8f d5 99 f5 7d ec
   f9 df 1d d4 1d 75 a0 57 74 81 7d d3 c8 02 6a 31
   10 f3 fc 2e 7e 77 e2 9a 7d 2d a9 c4 c8 21 bb 69
   77 d8 12 eb f0 9b 85 c5 1f 52 2e e2 23 a3 66 d4
   66 bb b9 cd 39 86 9f 07 d8 a5 e7 da e0 41 3c 56
   dd b6 a6 fb 01 65 a6 d1 bb 18 de 16 66 82 29 86
   1f 8e 03 c2 26 d6 7c 32 a2 05 cf 20 0e ce cf 9b
   df 47 40 31 7d 6d 2b 3a fd 23 7e d1 bd 73 0d 3b
   fa f6 f6 7c b6 84 3e 73 dd 7d ca 0e 01 76 50 af
   7f e7 f6 51 19 b5 42 41 c2 d4 1a f4 6a 16 60 02
   c9 1b f2 73 6d 17 4c 70 d7 b1 d7 8c 41 0e 20 21
   11 c4 61 52 f8 b6 93 d6 f2 2e 1d 59 ff aa a4 03
   ae 1c 87 55 34 e8 bc 98 f2 3a 0c 76 5a 0a f5 1f
   2b ed 5e 74 31 86 e8 df b2 a5 86 f1 1d e6 d9 23
   18 9d fe 84 f8 fd f7 64 43 d3 ed a6 84 58 35 84
   79 81 e6 a2 37 31 cd a9 20 2d bc e4 1f 09 db c7
   c5 c6 a9 18 33 b3 ea 8c 2b 50 a7 f0 95 86 6d c1
   9b 99 7a 8c 91 8c 57 f2 30 42 79 92 9e 0a cd 5e
   5c 15 a4 f5 b6 fb 87 5d 2e 4b 3d 3b fc 5a d3 af
   a1 31 21 8e 38 fa 75 e8 27 2f 22 5d 63 98 fd 41
   6f b8 15 68 5a 0f 4e 19 c4 ff cf 1f bf 97 0c 42
   42 9b 75 ef 11 e4 db 25 54 dc 95 77 14 6b 9e 15
   7b b8 fb d5 58 f1 68 1a e2 c9 bc 8d 19 27 51 70
   82 8c 49 12 c9 d4 ac 91 21 f9 da 5b f6 00 33 bd
   e6 c2 6e 0b 71 f4 ad 8e c4 d6 c2 dc 35 52 b7 1e
   ed 97 1e 4a 09 53 eb 30 9e 99 73 55 3d 8c 70 52
   6d 3a 9d ca 9d 3d 73 c8 b1 b0 7e 80 a7 3c 2c 40
   15 0f 99 f0 5b 47 4f 96 4a d7 c8 93 2d 45 d9 8a
   68 68 fc a8 62 25 a6 f8 50 41 7b 3f eb 10 46 5f
   f9 cd 31 99 e7 ee f0 cb 78 26 3f 05 6d 50 c8 f1
   69 fd 0c e0 31 cd eb 96 e9 62 b4 91 6d 7b 42 60
   16 bb 3a da 8a f8 00 21 e4 a7 7d 8b f9 23 ce 7a
   ab 57 f6 c0 88 00 4a 8d 69 76 64 9e 30 8d c6 54
   88 8c 87 59 be 77 2b 65 08 39 ab f0 1d 6a d4 e6
   74 e9 ff 2b 79 b8 a2 ca 75 6c 06 f0 dd 10 82 78
   34 85 7d 2b 49 f4 a1 e6 7a 86 32 4e 52 a1 e1 bf
   3c f9 e8 8a 5c 43 fd 82 d3 19 fa c7 eb 28 49 0a
   30 5a 14 94 41 78 fa 4f 84 bc 19 ef 64 f6 2b 30
   77 b5 e1 65 4f 33 47 4e 3d 85 7c 66 3d 44 82 a4
   3f 3e 10 93 b4 84 5e 77 ab 8d 89 71 f3 56 83 15
   15 06 1f ba 1c 09 01 eb 92 2c e3 25 bb 25 2c 6b
   32 e2 3a 3c ce 16 63 e5 d0 bc 05 ce b0 b2 ef 8e
   34 04 1c 39 9e 19 71 43 85 9e 4c d9 59 cd e7 6d
   89 c7 17 c8 39 71 de df 32 e7 fa 4b 93 0c ae e1
   27 8a 16 a2 d3 7b 4b 17 b7 39 7e 98 88 86 7a b2
   b6 e3 65 25 3e 19 de 92 c1 9c d9 b2 44 4c a2 4a
   8a 18 e1 41 c4 78 87 98 c4 a8 ed a1 67 ce b3 c2
   6a cb a5 f8 b4 6c df 01 3f 6d 79 1e 9e cb b8 84
   b5 b8 0b 5d a4 3e e0 17 b0 4e c8 e2 2f 7a 6b 4b
   74 9f 45 f0 b6 06 d5 63 92 72 8f 18 e6 e9 68 22
   c2 07 35 ca df a6 d2 1c 4d f6 c7 fa 0c f4 26 42
   1f a2 84 ef 22 d5 eb ab 7b d8 5c b5 e5 62 ef 92
   ce bf ac 18 ac 51 f5 d1 7f cb c4 01 44 e0 b4 6b
   33 28 07 2d 82 14 03 0b 88 af 66 8b 03 7b b4 c9
   08 6b 96 cb 77 66 54 3f 81 8a 57 4c 9b b4 98 f2
   cc c6 b2 1e ff 79 dc 39 56 47 d5 51 79 ec 92 6f
   25 34 02 87 1b d5 c5 96 08 28 81 8f 47 82 39 cc
   37 dd 62 c4 2d 82 89 f4 a9 7a 3a 53 28 fe ea ba
   82 a3 86 7f b6 bc 93 fe b1 6e 21 c3 07 66 e6 86
   ac f0 c7 d8 b6 31 23 4f 86 32 be 57 09 75 94 28
   59 4e 4c 7e 2b 5e 06 37 1e ff b8 fd b5 52 08 13
   61 b1 51 fd 0c 46 b8 9b 22 85 ff 2e f6 6b b6 f0
   b1 b9 3b ac 61 f7 69 80 3f ab 86 4a d4 f6 40 63
   90 e8 8d 75 72 ee 56 29 8b be c3 33 d3 8a 2d 2a
   98 2a 65 cc 58 f4 b6 75 26 26 e3 3e f2 2f 6d 90
   49 90 a4 ca 8a 9d 3a f7 03 e9 91 68 10 8d 36 5d
   88 1a a7 b4 d2 49 5b 19 63 2b 9d a2 16 30 8a 35
   01 24 80 be 49 04 9a a1 d9 cc 01 22 d6 90 27 5f
   84 6c fb 90 56 42 eb be 68 ea b7 ab 51 45 a5 1e
   88 1a af 5b 69 80 2c 44 d3 f8 8b 41 ce fe 57 84
   87 14 08 c7 20 77 d0 ee d7 48 1f ff 80 2e b2 d1
   88 a0 62 54 ef f1 d5 7e 16 c8 fb 55 34 45 a0 c3
   cc 70 2b 5a d9 50 1e ad 04 e2 34 2e 73 ab d3 b8
   99 4c 87 fa 3e 3c 4b 55 e4 7f 75 ac 84 e3 ce a8
   c6 2e a3 d6 15 4c 2f 6f 58 7f de a4 6f 6f 36 63
   e0 31 9d 76 1a 9d 85 e0 cd d0 81 02 c1 49 17 f3
   c8 58 fd d3 8b ba b8 d6 5e 32 50 ff b4 57 d3 f4
   ca 93 08 d4 3b 84 35 91 73 05 9e ab fc bf 0f ea
   76 e7 9f b9 45 ad dd 7d de 37 ba 89 d5 ec 02 65
   84 69 64 90 b4 e8 66 9a 8d 89 9e c0 80 9e 09 42
   bc cb c9 6f 15 d2 24 09 de 75 14 de d0 9e 43 8d
   0c 78 f7 d7 27 72 08 a4 55 21 2c 30 ec 47 f7 4f
   4f 79 05 da 96 44 0a 8a 14 dd c3 a9 8f 57 83 d7
   6f 1b bb ac c5 33 01 63 3c 42 e0 02 15 89 8b a6
   18 fa 85 8b d0 ec 18 39 a5 cb 09 30 c7 8f 0d 13
   19 40 75 f8 26 45 67 da 2e d8 12 d8 b1 41 e5 1a
   55 35 40 33 24 95 6d 33 57 4b ba 3f ea 1d cd ba
   86 d9 0b d2 99 b3 2a 0a ae 83 7a 79 d5 7d 90 c0
   72 ef 8b 64 bf 03 4d 33 74 78 e1 72 2b a4 64 66
   78 c1 b4 36 0a 31 cc fa 4f 23 db a3 c6 40 4f 33
   34 15 f2 07 9a 10 f8 47 79 9e 65 51 b0 d7 ca 09
   61 72 a2 9d 0a 92 73 d6 1b 27 80 31 b5 dd d1 b2
   c5 04 2e 99 e7 8f 91 a7 dd cb 5a 4f 65 42 95 ca
   75 15 f2 da be f3 36 70 ec 91 23 fa 3c b4 69 2e
   54 15 8e b8 52 e4 3c 61 a1 d1 31 fd dc c2 a5 89
   7a c3 e1 aa bd 5f f4 d1 bc 82 4d aa e6 0b 5a a4
   6c 0a 6e a1 02 58 00 8d 85 a5 2b 17 b5 04 f1 e4
   98 b1 4c f1 6f 0d c8 e7 ac 3c 40 65 1d b1 7f 49
   54 3d 9c f6 25 eb 7d 36 75 a6 cd e3 42 a6 2d 20
   ef df 5c 42 e3 82 bf 5f e7 3f cd 73 ea e4 fb c1
   1a 90 7c 57 c3 2d de de d2 73 72 b5 aa 1f 47 c6
   9a 7a cf 4f 06 93 70 64 2f 56 ce 0b 9b f7 8f 91
   2c c4 58 7c 8d 89 b2 c0 80 bb 39 78 da 5d 04 14
   b2 5f 54 91 b1 29 42 14 9f c6 b7 f6 19 e6 2d f0
   6f f0 14 6e 62 c2 9b 67 e3 88 bd 6b d3 51 ea dd
   ad 65 42 54 de 3f ed 6c ba fc 71
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
   0a 43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 74
   65 78 74 2f 68 74 6d 6c 0d 0a 0d 0a 3c 48 54 4d
   4c 3e 3c 42 4f 44 59 20 42 47 43 4f 4c 4f 52 3d
   22 23 66 66 66 66 66 66 22 3e 0a 3c 70 72 65 3e
   0a 0a 73 5f 73 65 72 76 65 72 20 2d 63 65 72 74
   20 73 65 72 76 65 72 2e 63 72 74 20 2d 6b 65 79
   20 73 65 72 76 65 72 2e 6b 65 79 20 2d 77 77 77
   20 2d 70 6f 72 74 20 38 34 30 33 20 2d 43 41 66
   69 6c 65 20 63 6c 69 65 6e 74 2e 63 72 74 20 2d
   64 65 62 75 67 20 2d 6b 65 79 6c 6f 67 66 69 6c
   65 20 6b 65 79 2e 74 78 74 20 2d 6d 73 67 20 2d
   73 74 61 74 65 20 2d 74 6c 73 65 78 74 64 65 62
   75 67 20 2d 56 65 72 69 66 79 20 31 20 0a 53 65
   63 75 72 65 20 52 65 6e 65 67 6f 74 69 61 74 69
   6f 6e 20 49 53 20 4e 4f 54 20 73 75 70 70 6f 72
   74 65 64 0a 43 69 70 68 65 72 73 20 73 75 70 70
   6f 72 74 65 64 20 69 6e 20 73 5f 73 65 72 76 65
   72 20 62 69 6e 61 72 79 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 32 35 36
   5f 47 43 4d 5f 53 48 41 33 38 34 20 20 20 20 54
   4c 53 76 31 2e 33 20 20 20 20 3a 54 4c 53 5f 43
   48 41 43 48 41 32 30 5f 50 4f 4c 59 31 33 30 35
   5f 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 31 32 38
   5f 47 43 4d 5f 53 48 41 32 35 36 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 32 35 36 2d 47 43
   4d 2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d
   41 45 53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48
   45 2d 52 53 41 2d 41 45 53 32 35 36 2d 47 43 4d
   2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 45 43 44 48 45 2d 45 43 44 53 41
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45
   43 44 48 45 2d 52 53 41 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33 30
   35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 45 43 44 53 41 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20 20
   3a 44 48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 45 43
   44 53 41 2d 41 45 53 32 35 36 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 52 53 41 2d 41 45 53 32 35 36 2d 53
   48 41 33 38 34 20 20 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 44 48 45 2d 52 53 41 2d 41 45 53
   32 35 36 2d 53 48 41 32 35 36 20 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 32 35 36 20 0a 54 4c 53 76 31 2e 32 20 20 20
   20 3a 45 43 44 48 45 2d 52 53 41 2d 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   41 45 53 31 32 38 2d 53 48 41 32 35 36 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 45
   43 44 48 45 2d 45 43 44 53 41 2d 41 45 53 32 35
   36 2d 53 48 41 20 20 20 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d 41
   45 53 32 35 36 2d 53 48 41 20 20 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   52 53 41 2d 41 45 53 32 35 36 2d 53 48 41 20 20
   20 20 20 20 20 20 54 4c 53 76 31 2e 30 20 20 20
   20 3a 45 43 44 48 45 2d 45 43 44 53 41 2d 41 45
   53 31 32 38 2d 53 48 41 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 53 48 41 20 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 44
   48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45
   53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38 34 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53
   48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32 20 20
   20 20 3a 52 53 41 2d 50 53 4b 2d 43 48 41 43 48
   41 32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53
   76 31 2e 32 20 20 20 20 3a 44 48 45 2d 50 53 4b
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a
   45 43 44 48 45 2d 50 53 4b 2d 43 48 41 43 48 41
   32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 41 45 53 32 35 36 2d 47
   43 4d 2d 53 48 41 33 38 34 20 20 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53 48
   41 33 38 34 20 20 20 20 20 54 4c 53 76 31 2e 32
   20 20 20 20 3a 50 53 4b 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 20 20 20 20 0a
   54 4c 53 76 31 2e 32 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53
   48 41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 41 45 53 32 35 36 2d 53 48 41
   32 35 36 20 20 20 20 20 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 20 20 20 20
   20 20 20 20 20 20 0a 54 4c 53 76 31 2e 30 20 20
   20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 54
   4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48 45
   2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d
   53 48 41 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 52 53 41 2d 41 45 53 2d 32 35
   36 2d 43 42 43 2d 53 48 41 20 20 20 53 53 4c 76
   33 20 20 20 20 20 20 3a 53 52 50 2d 41 45 53 2d
   32 35 36 2d 43 42 43 2d 53 48 41 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 52
   53 41 2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42
   43 2d 53 48 41 33 38 34 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 0a 53 53 4c
   76 33 20 20 20 20 20 20 3a 41 45 53 32 35 36 2d
   53 48 41 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 30 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53 48
   41 33 38 34 20 20 20 20 20 0a 53 53 4c 76 33 20
   20 20 20 20 20 3a 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48
   45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43
   2d 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41
   45 53 31 32 38 2d 43 42 43 2d 53 48 41 20 20 53
   53 4c 76 33 20 20 20 20 20 20 3a 53 52 50 2d 52
   53 41 2d 41 45 53 2d 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 41 45 53 2d 31 32 38 2d 43 42
   43 2d 53 48 41 20 20 20 20 20 20 20 54 4c 53 76
   31 2e 30 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d
   41 45 53 31 32 38 2d 43 42 43 2d 53 48 41 32 35
   36 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 44
   48 45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42
   43 2d 53 48 41 32 35 36 20 53 53 4c 76 33 20 20
   20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 41 45 53 31 32 38 2d 53 48 41 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 32 35 36 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 2d 2d 2d 0a 43 69
   70 68 65 72 73 20 63 6f 6d 6d 6f 6e 20 62 65 74
   77 65 65 6e 20 62 6f 74 68 20 53 53 4c 20 65 6e
   64 20 70 6f 69 6e 74 73 3a 0a 54 4c 53 5f 41 45
   53 5f 31 32 38 5f 47 43 4d 5f 53 48 41 32 35 36
   20 20 20 20 20 54 4c 53 5f 43 48 41 43 48 41 32
   30 5f 50 4f 4c 59 31 33 30 35 5f 53 48 41 32 35
   36 0a 53 75 70 70 6f 72 74 65 64 20 67 72 6f 75
   70 73 3a 20 78 32 35 35 31 39 0a 53 68 61 72 65
   64 20 67 72 6f 75 70 73 3a 20 78 32 35 35 31 39
   0a 2d 2d 2d 0a 52 65 75 73 65 64 2c 20 54 4c 53
   76 31 2e 33 2c 20 43 69 70 68 65 72 20 69 73 20
   54 4c 53 5f 41 45 53 5f 31 32 38 5f 47 43 4d 5f
   53 48 41 32 35 36 0a 53 53 4c 2d 53 65 73 73 69
   6f 6e 3a 0a 20 20 20 20 50 72 6f 74 6f 63 6f 6c
   20 20 3a 20 54 4c 53 76 31 2e 33 0a 20 20 20 20
   43 69 70 68 65 72 20 20 20 20 3a 20 54 4c 53 5f
   41 45 53 5f 31 32 38 5f 47 43 4d 5f 53 48 41 32
   35 36 0a 20 20 20 20 53 65 73 73 69 6f 6e 2d 49
   44 3a 20 38 45 38 39 41 32 39 31 33 37 43 30 43
   34 33 30 39 42 32 37 37 38 32 41 31 44 45 35 41
   33 46 34 30 36 39 46 41 41 41 30 44 44 33 36 41
   38 34 41 37 35 32 39 42 37 35 46 43 45 33 42 45
   38 41 38 0a 20 20 20 20 53 65 73 73 69 6f 6e 2d
   49 44 2d 63 74 78 3a 20 30 31 30 30 30 30 30 30
   0a 20 20 20 20 52 65 73 75 6d 70 74 69 6f 6e 20
   50 53 4b 3a 20 36 32 45 34 35 33 41 30 42 41 41
   38 33 32 42 36 33 43 41 36 36 34 30 44 31 39 30
   35 33 34 46 35 46 34 30 44 35 34 34 39 30 32 42
   31 33 43 30 45 44 37 32 43 31 37 41 42 36 43 42
   32 34 34 39 45 0a 20 20 20 20 50 53 4b 20 69 64
   65 6e 74 69 74 79 3a 20 4e 6f 6e 65 0a 20 20 20
   20 50 53 4b 20 69 64 65 6e 74 69 74 79 20 68 69
   6e 74 3a 20 4e 6f 6e 65 0a 20 20 20 20 53 52 50
   20 75 73 65 72 6e 61 6d 65 3a 20 4e 6f 6e 65 0a
   20 20 20 20 53 74 61 72 74 20 54 69 6d 65 3a 20
   31 36 38 30 36 32 35 38 31 38 0a 20 20 20 20 54
   69 6d 65 6f 75 74 20 20 20 3a 20 37 32 30 30 20
   28 73 65 63 29 0a 20 20 20 20 56 65 72 69 66 79
   20 72 65 74 75 72 6e 20 63 6f 64 65 3a 20 31 38
   20 28 73 65 6c 66 2d 73 69 67 6e 65 64 20 63 65
   72 74 69 66 69 63 61 74 65 29 0a 20 20 20 20 45
   78 74 65 6e 64 65 64 20 6d 61 73 74 65 72 20 73
   65 63 72 65 74 3a 20 6e 6f 0a 20 20 20 20 4d 61
   78 20 45 61 72 6c 79 20 44 61 74 61 3a 20 30 0a
   2d 2d 2d 0a 20 20 20 30 20 69 74 65 6d 73 20 69
   6e 20 74 68 65 20 73 65 73 73 69 6f 6e 20 63 61
   63 68 65 0a 20 20 20 30 20 63 6c 69 65 6e 74 20
   63 6f 6e 6e 65 63 74 73 20 28 53 53 4c 5f 63 6f
   6e 6e 65 63 74 28 29 29 0a 20 20 20 30 20 63 6c
   69 65 6e 74 20 72 65 6e 65 67 6f 74 69 61 74 65
   73 20 28 53 53 4c 5f 63 6f 6e 6e 65 63 74 28 29
   29 0a 20 20 20 30 20 63 6c 69 65 6e 74 20 63 6f
   6e 6e 65 63 74 73 20 74 68 61 74 20 66 69 6e 69
   73 68 65 64 0a 20 20 20 37 20 73 65 72 76 65 72
   20 61 63 63 65 70 74 73 20 28 53 53 4c 5f 61 63
   63 65 70 74 28 29 29 0a 20 20 20 30 20 73 65 72
   76 65 72 20 72 65 6e 65 67 6f 74 69 61 74 65 73
   20 28 53 53 4c 5f 61 63 63 65 70 74 28 29 29 0a
   20 20 20 37 20 73 65 72 76 65 72 20 61 63 63 65
   70 74 73 20 74 68 61 74 20 66 69 6e 69 73 68 65
   64 0a 20 20 20 33 20 73 65 73 73 69 6f 6e 20 63
   61 63 68 65 20 68 69 74 73 0a 20 20 20 30 20 73
   65 73 73 69 6f 6e 20 63 61 63 68 65 20 6d 69 73
   73 65 73 0a 20 20 20 30 20 73 65 73 73 69 6f 6e
   20 63 61 63 68 65 20 74 69 6d 65 6f 75 74 73 0a
   20 20 20 30 20 63 61 6c 6c 62 61 63 6b 20 63 61
   63 68 65 20 68 69 74 73 0a 20 20 20 30 20 63 61
   63 68 65 20 66 75 6c 6c 20 6f 76 65 72 66 6c 6f
   77 73 20 28 31 32 38 20 61 6c 6c 6f 77 65 64 29
   0a 2d 2d 2d 0a 43 6c 69 65 6e 74 20 63 65 72 74
   69 66 69 63 61 74 65 0a 43 65 72 74 69 66 69 63
   61 74 65 3a 0a 20 20 20 20 44 61 74 61 3a 0a 20
   20 20 20 20 20 20 20 56 65 72 73 69 6f 6e 3a 20
   33 20 28 30 78 32 29 0a 20 20 20 20 20 20 20 20
   53 65 72 69 61 6c 20 4e 75 6d 62 65 72 3a 0a 20
   20 20 20 20 20 20 20 20 20 20 20 32 36 3a 33 66
   3a 35 36 3a 63 35 3a 37 33 3a 66 36 3a 36 62 3a
   33 36 3a 64 38 3a 39 61 3a 30 66 3a 63 37 3a 64
   62 3a 61 66 3a 34 61 3a 63 66 3a 66 37 3a 61 33
   3a 37 32 3a 30 66 0a 20 20 20 20 20 20 20 20 53
   69 67 6e 61 74 75 72 65 20 41 6c 67 6f 72 69 74
   68 6d 3a 20 45 44 32 35 35 31 39 0a 20 20 20 20
   20 20 20 20 49 73 73 75 65 72 3a 20 43 4e 3d 63
   72 79 70 74 6f 67 72 61 70 68 79 2e 69 6f 0a 20
   20 20 20 20 20 20 20 56 61 6c 69 64 69 74 79 0a
   20 20 20 20 20 20 20 20 20 20 20 20 4e 6f 74 20
   42 65 66 6f 72 65 3a 20 4d 61 72 20 32 33 20 32
   30 3a 31 35 3a 31 34 20 32 30 32 33 20 47 4d 54
   0a 20 20 20 20 20 20 20 20 20 20 20 20 4e 6f 74
   20 41 66 74 65 72 20 3a 20 41 70 72 20 32 33 20
   32 30 3a 31 35 3a 31 34 20 32 30 32 33 20 47 4d
   54 0a 20 20 20 20 20 20 20 20 53 75 62 6a 65 63
   74 3a 20 43 4e 3d 63 72 79 70 74 6f 67 72 61 70
   68 79 2e 69 6f 0a 20 20 20 20 20 20 20 20 53 75
   62 6a 65 63 74 20 50 75 62 6c 69 63 20 4b 65 79
   20 49 6e 66 6f 3a 0a 20 20 20 20 20 20 20 20 20
   20 20 20 50 75 62 6c 69 63 20 4b 65 79 20 41 6c
   67 6f 72 69 74 68 6d 3a 20 45 44 32 35 35 31 39
   0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 45 44 32 35 35 31 39 20 50 75 62 6c 69 63 2d
   4b 65 79 3a 0a 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 70 75 62 3a 0a 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 20 36 66
   3a 37 65 3a 62 38 3a 66 35 3a 61 33 3a 32 38 3a
   61 34 3a 62 39 3a 63 35 3a 35 36 3a 66 63 3a 33
   33 3a 38 38 3a 39 34 3a 39 36 3a 0a 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   35 31 3a 34 62 3a 61 33 3a 31 34 3a 61 36 3a 63
   63 3a 61 66 3a 38 36 3a 37 34 3a 35 38 3a 37 63
   3a 32 34 3a 39 33 3a 61 64 3a 35 63 3a 0a 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 61 36 3a 64 38 0a 20 20 20 20 20 20 20 20
   58 35 30 39 76 33 20 65 78 74 65 6e 73 69 6f 6e
   73 3a 0a 20 20 20 20 20 20 20 20 20 20 20 20 58
   35 30 39 76 33 20 53 75 62 6a 65 63 74 20 41 6c
   74 65 72 6e 61 74 69 76 65 20 4e 61 6d 65 3a 20
   0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 44 4e 53 3a 63 72 79 70 74 6f 67 72 61 70 68
   79 2e 69 6f 0a 20 20 20 20 20 20 20 20 20 20 20
   20 58 35 30 39 76 33 20 4b 65 79 20 55 73 61 67
   65 3a 20 0a 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 44 69 67 69 74 61 6c 20 53 69 67 6e
   61 74 75 72 65 2c 20 4e 6f 6e 20 52 65 70 75 64
   69 61 74 69 6f 6e 2c 20 44 61 74 61 20 45 6e 63
   69 70 68 65 72 6d 65 6e 74 2c 20 43 65 72 74 69
   66 69 63 61 74 65 20 53 69 67 6e 0a 20 20 20 20
   20 20 20 20 20 20 20 20 58 35 30 39 76 33 20 42
   61 73 69 63 20 43 6f 6e 73 74 72 61 69 6e 74 73
   3a 20 63 72 69 74 69 63 61 6c 0a 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 43 41 3a 46 41
   4c 53 45 0a 20 20 20 20 53 69 67 6e 61 74 75 72
   65 20 41 6c 67 6f 72 69 74 68 6d 3a 20 45 44 32
   35 35 31 39 0a 20 20 20 20 53 69 67 6e 61 74 75
   72 65 20 56 61 6c 75 65 3a 0a 20 20 20 20 20 20
   20 20 34 39 3a 64 32 3a 34 63 3a 30 37 3a 35 63
   3a 39 33 3a 61 65 3a 61 61 3a 39 38 3a 30 33 3a
   36 61 3a 64 36 3a 65 34 3a 32 35 3a 36 35 3a 37
   34 3a 34 35 3a 62 64 3a 0a 20 20 20 20 20 20 20
   20 34 65 3a 31 35 3a 66 62 3a 31 34 3a 66 64 3a
   38 64 3a 35 37 3a 39 62 3a 38 30 3a 63 35 3a 66
   35 3a 38 31 3a 39 35 3a 39 66 3a 61 30 3a 61 61
   3a 37 35 3a 30 34 3a 0a 20 20 20 20 20 20 20 20
   66 31 3a 66 38 3a 36 63 3a 66 61 3a 66 63 3a 30
   65 3a 62 64 3a 65 65 3a 33 61 3a 66 37 3a 66 61
   3a 65 63 3a 64 33 3a 36 34 3a 66 66 3a 38 36 3a
   32 37 3a 61 36 3a 0a 20 20 20 20 20 20 20 20 30
   64 3a 34 38 3a 64 64 3a 37 63 3a 63 35 3a 37 32
   3a 36 62 3a 36 34 3a 38 66 3a 30 39 0a 2d 2d 2d
   2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43
   41 54 45 2d 2d 2d 2d 2d 0a 4d 49 49 42 4c 6a 43
   42 34 61 41 44 41 67 45 43 41 68 51 6d 50 31 62
   46 63 2f 5a 72 4e 74 69 61 44 38 66 62 72 30 72
   50 39 36 4e 79 44 7a 41 46 42 67 4d 72 5a 58 41
   77 47 6a 45 59 4d 42 59 47 0a 41 31 55 45 41 77
   77 50 59 33 4a 35 63 48 52 76 5a 33 4a 68 63 47
   68 35 4c 6d 6c 76 4d 42 34 58 44 54 49 7a 4d 44
   4d 79 4d 7a 49 77 4d 54 55 78 4e 46 6f 58 44 54
   49 7a 4d 44 51 79 4d 7a 49 77 0a 4d 54 55 78 4e
   46 6f 77 47 6a 45 59 4d 42 59 47 41 31 55 45 41
   77 77 50 59 33 4a 35 63 48 52 76 5a 33 4a 68 63
   47 68 35 4c 6d 6c 76 4d 43 6f 77 42 51 59 44 4b
   32 56 77 41 79 45 41 62 33 36 34 0a 39 61 4d 6f
   70 4c 6e 46 56 76 77 7a 69 4a 53 57 55 55 75 6a
   46 4b 62 4d 72 34 5a 30 57 48 77 6b 6b 36 31 63
   70 74 69 6a 4f 54 41 33 4d 42 6f 47 41 31 55 64
   45 51 51 54 4d 42 47 43 44 32 4e 79 0a 65 58 42
   30 62 32 64 79 59 58 42 6f 65 53 35 70 62 7a 41
   4c 42 67 4e 56 48 51 38 45 42 41 4d 43 41 74 51
   77 44 41 59 44 56 52 30 54 41 51 48 2f 42 41 49
   77 41 44 41 46 42 67 4d 72 5a 58 41 44 0a 51 51
   42 4a 30 6b 77 48 58 4a 4f 75 71 70 67 44 61 74
   62 6b 4a 57 56 30 52 62 31 4f 46 66 73 55 2f 59
   31 58 6d 34 44 46 39 59 47 56 6e 36 43 71 64 51
   54 78 2b 47 7a 36 2f 41 36 39 37 6a 72 33 0a 2b
   75 7a 54 5a 50 2b 47 4a 36 59 4e 53 4e 31 38 78
   58 4a 72 5a 49 38 4a 0a 2d 2d 2d 2d 2d 45 4e 44
   20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d
   2d 0a 3c 2f 70 72 65 3e 3c 2f 42 4f 44 59 3e 3c
   2f 48 54 4d 4c 3e 0d 0a 0d 0a 17
     - Inner TLS message 6 server_application_data_(decrypted): Container: 
       content = b'HTTP/1.0 200 ok\r'... (truncated, total 5498)
       type = (enum) application_data 23
       zeros = None
     - TLS message 6 server_application_data [5498 bytes]:
   48 54 54 50 2f 31 2e 30 20 32 30 30 20 6f 6b 0d
   0a 43 6f 6e 74 65 6e 74 2d 74 79 70 65 3a 20 74
   65 78 74 2f 68 74 6d 6c 0d 0a 0d 0a 3c 48 54 4d
   4c 3e 3c 42 4f 44 59 20 42 47 43 4f 4c 4f 52 3d
   22 23 66 66 66 66 66 66 22 3e 0a 3c 70 72 65 3e
   0a 0a 73 5f 73 65 72 76 65 72 20 2d 63 65 72 74
   20 73 65 72 76 65 72 2e 63 72 74 20 2d 6b 65 79
   20 73 65 72 76 65 72 2e 6b 65 79 20 2d 77 77 77
   20 2d 70 6f 72 74 20 38 34 30 33 20 2d 43 41 66
   69 6c 65 20 63 6c 69 65 6e 74 2e 63 72 74 20 2d
   64 65 62 75 67 20 2d 6b 65 79 6c 6f 67 66 69 6c
   65 20 6b 65 79 2e 74 78 74 20 2d 6d 73 67 20 2d
   73 74 61 74 65 20 2d 74 6c 73 65 78 74 64 65 62
   75 67 20 2d 56 65 72 69 66 79 20 31 20 0a 53 65
   63 75 72 65 20 52 65 6e 65 67 6f 74 69 61 74 69
   6f 6e 20 49 53 20 4e 4f 54 20 73 75 70 70 6f 72
   74 65 64 0a 43 69 70 68 65 72 73 20 73 75 70 70
   6f 72 74 65 64 20 69 6e 20 73 5f 73 65 72 76 65
   72 20 62 69 6e 61 72 79 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 32 35 36
   5f 47 43 4d 5f 53 48 41 33 38 34 20 20 20 20 54
   4c 53 76 31 2e 33 20 20 20 20 3a 54 4c 53 5f 43
   48 41 43 48 41 32 30 5f 50 4f 4c 59 31 33 30 35
   5f 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 33
   20 20 20 20 3a 54 4c 53 5f 41 45 53 5f 31 32 38
   5f 47 43 4d 5f 53 48 41 32 35 36 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 32 35 36 2d 47 43
   4d 2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d
   41 45 53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48
   45 2d 52 53 41 2d 41 45 53 32 35 36 2d 47 43 4d
   2d 53 48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 45 43 44 48 45 2d 45 43 44 53 41
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45
   43 44 48 45 2d 52 53 41 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33 30
   35 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 45 43 44 53 41 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20 20
   3a 44 48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53 76
   31 2e 32 20 20 20 20 3a 45 43 44 48 45 2d 45 43
   44 53 41 2d 41 45 53 32 35 36 2d 53 48 41 33 38
   34 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 45 43
   44 48 45 2d 52 53 41 2d 41 45 53 32 35 36 2d 53
   48 41 33 38 34 20 20 20 0a 54 4c 53 76 31 2e 32
   20 20 20 20 3a 44 48 45 2d 52 53 41 2d 41 45 53
   32 35 36 2d 53 48 41 32 35 36 20 20 20 20 20 54
   4c 53 76 31 2e 32 20 20 20 20 3a 45 43 44 48 45
   2d 45 43 44 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 32 35 36 20 0a 54 4c 53 76 31 2e 32 20 20 20
   20 3a 45 43 44 48 45 2d 52 53 41 2d 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 44 48 45 2d 52 53 41 2d
   41 45 53 31 32 38 2d 53 48 41 32 35 36 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 45
   43 44 48 45 2d 45 43 44 53 41 2d 41 45 53 32 35
   36 2d 53 48 41 20 20 20 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 52 53 41 2d 41
   45 53 32 35 36 2d 53 48 41 20 20 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   52 53 41 2d 41 45 53 32 35 36 2d 53 48 41 20 20
   20 20 20 20 20 20 54 4c 53 76 31 2e 30 20 20 20
   20 3a 45 43 44 48 45 2d 45 43 44 53 41 2d 41 45
   53 31 32 38 2d 53 48 41 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 45 43 44 48 45 2d 52
   53 41 2d 41 45 53 31 32 38 2d 53 48 41 20 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 44
   48 45 2d 52 53 41 2d 41 45 53 31 32 38 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45
   53 32 35 36 2d 47 43 4d 2d 53 48 41 33 38 34 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53
   48 41 33 38 34 20 0a 54 4c 53 76 31 2e 32 20 20
   20 20 3a 52 53 41 2d 50 53 4b 2d 43 48 41 43 48
   41 32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53
   76 31 2e 32 20 20 20 20 3a 44 48 45 2d 50 53 4b
   2d 43 48 41 43 48 41 32 30 2d 50 4f 4c 59 31 33
   30 35 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a
   45 43 44 48 45 2d 50 53 4b 2d 43 48 41 43 48 41
   32 30 2d 50 4f 4c 59 31 33 30 35 20 54 4c 53 76
   31 2e 32 20 20 20 20 3a 41 45 53 32 35 36 2d 47
   43 4d 2d 53 48 41 33 38 34 20 20 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 47 43 4d 2d 53 48
   41 33 38 34 20 20 20 20 20 54 4c 53 76 31 2e 32
   20 20 20 20 3a 50 53 4b 2d 43 48 41 43 48 41 32
   30 2d 50 4f 4c 59 31 33 30 35 20 20 20 20 20 0a
   54 4c 53 76 31 2e 32 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53
   48 41 32 35 36 20 54 4c 53 76 31 2e 32 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 31 32 38
   2d 47 43 4d 2d 53 48 41 32 35 36 20 0a 54 4c 53
   76 31 2e 32 20 20 20 20 3a 41 45 53 31 32 38 2d
   47 43 4d 2d 53 48 41 32 35 36 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 32 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 47 43 4d 2d 53 48
   41 32 35 36 20 20 20 20 20 0a 54 4c 53 76 31 2e
   32 20 20 20 20 3a 41 45 53 32 35 36 2d 53 48 41
   32 35 36 20 20 20 20 20 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 32 20 20 20 20 3a 41 45 53 31
   32 38 2d 53 48 41 32 35 36 20 20 20 20 20 20 20
   20 20 20 20 20 20 0a 54 4c 53 76 31 2e 30 20 20
   20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 54
   4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48 45
   2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d
   53 48 41 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 52 53 41 2d 41 45 53 2d 32 35
   36 2d 43 42 43 2d 53 48 41 20 20 20 53 53 4c 76
   33 20 20 20 20 20 20 3a 53 52 50 2d 41 45 53 2d
   32 35 36 2d 43 42 43 2d 53 48 41 20 20 20 20 20
   20 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 52
   53 41 2d 50 53 4b 2d 41 45 53 32 35 36 2d 43 42
   43 2d 53 48 41 33 38 34 20 54 4c 53 76 31 2e 30
   20 20 20 20 3a 44 48 45 2d 50 53 4b 2d 41 45 53
   32 35 36 2d 43 42 43 2d 53 48 41 33 38 34 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 52 53 41 2d
   50 53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 44 48 45 2d 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 0a 53 53 4c
   76 33 20 20 20 20 20 20 3a 41 45 53 32 35 36 2d
   53 48 41 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 54 4c 53 76 31 2e 30 20 20 20 20 3a 50
   53 4b 2d 41 45 53 32 35 36 2d 43 42 43 2d 53 48
   41 33 38 34 20 20 20 20 20 0a 53 53 4c 76 33 20
   20 20 20 20 20 3a 50 53 4b 2d 41 45 53 32 35 36
   2d 43 42 43 2d 53 48 41 20 20 20 20 20 20 20 20
   54 4c 53 76 31 2e 30 20 20 20 20 3a 45 43 44 48
   45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43
   2d 53 48 41 32 35 36 20 0a 54 4c 53 76 31 2e 30
   20 20 20 20 3a 45 43 44 48 45 2d 50 53 4b 2d 41
   45 53 31 32 38 2d 43 42 43 2d 53 48 41 20 20 53
   53 4c 76 33 20 20 20 20 20 20 3a 53 52 50 2d 52
   53 41 2d 41 45 53 2d 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 0a 53 53 4c 76 33 20 20 20 20 20
   20 3a 53 52 50 2d 41 45 53 2d 31 32 38 2d 43 42
   43 2d 53 48 41 20 20 20 20 20 20 20 54 4c 53 76
   31 2e 30 20 20 20 20 3a 52 53 41 2d 50 53 4b 2d
   41 45 53 31 32 38 2d 43 42 43 2d 53 48 41 32 35
   36 20 0a 54 4c 53 76 31 2e 30 20 20 20 20 3a 44
   48 45 2d 50 53 4b 2d 41 45 53 31 32 38 2d 43 42
   43 2d 53 48 41 32 35 36 20 53 53 4c 76 33 20 20
   20 20 20 20 3a 52 53 41 2d 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 20 20 20 20 0a
   53 53 4c 76 33 20 20 20 20 20 20 3a 44 48 45 2d
   50 53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53
   48 41 20 20 20 20 53 53 4c 76 33 20 20 20 20 20
   20 3a 41 45 53 31 32 38 2d 53 48 41 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 0a 54 4c 53
   76 31 2e 30 20 20 20 20 3a 50 53 4b 2d 41 45 53
   31 32 38 2d 43 42 43 2d 53 48 41 32 35 36 20 20
   20 20 20 53 53 4c 76 33 20 20 20 20 20 20 3a 50
   53 4b 2d 41 45 53 31 32 38 2d 43 42 43 2d 53 48
   41 20 20 20 20 20 20 20 20 0a 2d 2d 2d 0a 43 69
   70 68 65 72 73 20 63 6f 6d 6d 6f 6e 20 62 65 74
   77 65 65 6e 20 62 6f 74 68 20 53 53 4c 20 65 6e
   64 20 70 6f 69 6e 74 73 3a 0a 54 4c 53 5f 41 45
   53 5f 31 32 38 5f 47 43 4d 5f 53 48 41 32 35 36
   20 20 20 20 20 54 4c 53 5f 43 48 41 43 48 41 32
   30 5f 50 4f 4c 59 31 33 30 35 5f 53 48 41 32 35
   36 0a 53 75 70 70 6f 72 74 65 64 20 67 72 6f 75
   70 73 3a 20 78 32 35 35 31 39 0a 53 68 61 72 65
   64 20 67 72 6f 75 70 73 3a 20 78 32 35 35 31 39
   0a 2d 2d 2d 0a 52 65 75 73 65 64 2c 20 54 4c 53
   76 31 2e 33 2c 20 43 69 70 68 65 72 20 69 73 20
   54 4c 53 5f 41 45 53 5f 31 32 38 5f 47 43 4d 5f
   53 48 41 32 35 36 0a 53 53 4c 2d 53 65 73 73 69
   6f 6e 3a 0a 20 20 20 20 50 72 6f 74 6f 63 6f 6c
   20 20 3a 20 54 4c 53 76 31 2e 33 0a 20 20 20 20
   43 69 70 68 65 72 20 20 20 20 3a 20 54 4c 53 5f
   41 45 53 5f 31 32 38 5f 47 43 4d 5f 53 48 41 32
   35 36 0a 20 20 20 20 53 65 73 73 69 6f 6e 2d 49
   44 3a 20 38 45 38 39 41 32 39 31 33 37 43 30 43
   34 33 30 39 42 32 37 37 38 32 41 31 44 45 35 41
   33 46 34 30 36 39 46 41 41 41 30 44 44 33 36 41
   38 34 41 37 35 32 39 42 37 35 46 43 45 33 42 45
   38 41 38 0a 20 20 20 20 53 65 73 73 69 6f 6e 2d
   49 44 2d 63 74 78 3a 20 30 31 30 30 30 30 30 30
   0a 20 20 20 20 52 65 73 75 6d 70 74 69 6f 6e 20
   50 53 4b 3a 20 36 32 45 34 35 33 41 30 42 41 41
   38 33 32 42 36 33 43 41 36 36 34 30 44 31 39 30
   35 33 34 46 35 46 34 30 44 35 34 34 39 30 32 42
   31 33 43 30 45 44 37 32 43 31 37 41 42 36 43 42
   32 34 34 39 45 0a 20 20 20 20 50 53 4b 20 69 64
   65 6e 74 69 74 79 3a 20 4e 6f 6e 65 0a 20 20 20
   20 50 53 4b 20 69 64 65 6e 74 69 74 79 20 68 69
   6e 74 3a 20 4e 6f 6e 65 0a 20 20 20 20 53 52 50
   20 75 73 65 72 6e 61 6d 65 3a 20 4e 6f 6e 65 0a
   20 20 20 20 53 74 61 72 74 20 54 69 6d 65 3a 20
   31 36 38 30 36 32 35 38 31 38 0a 20 20 20 20 54
   69 6d 65 6f 75 74 20 20 20 3a 20 37 32 30 30 20
   28 73 65 63 29 0a 20 20 20 20 56 65 72 69 66 79
   20 72 65 74 75 72 6e 20 63 6f 64 65 3a 20 31 38
   20 28 73 65 6c 66 2d 73 69 67 6e 65 64 20 63 65
   72 74 69 66 69 63 61 74 65 29 0a 20 20 20 20 45
   78 74 65 6e 64 65 64 20 6d 61 73 74 65 72 20 73
   65 63 72 65 74 3a 20 6e 6f 0a 20 20 20 20 4d 61
   78 20 45 61 72 6c 79 20 44 61 74 61 3a 20 30 0a
   2d 2d 2d 0a 20 20 20 30 20 69 74 65 6d 73 20 69
   6e 20 74 68 65 20 73 65 73 73 69 6f 6e 20 63 61
   63 68 65 0a 20 20 20 30 20 63 6c 69 65 6e 74 20
   63 6f 6e 6e 65 63 74 73 20 28 53 53 4c 5f 63 6f
   6e 6e 65 63 74 28 29 29 0a 20 20 20 30 20 63 6c
   69 65 6e 74 20 72 65 6e 65 67 6f 74 69 61 74 65
   73 20 28 53 53 4c 5f 63 6f 6e 6e 65 63 74 28 29
   29 0a 20 20 20 30 20 63 6c 69 65 6e 74 20 63 6f
   6e 6e 65 63 74 73 20 74 68 61 74 20 66 69 6e 69
   73 68 65 64 0a 20 20 20 37 20 73 65 72 76 65 72
   20 61 63 63 65 70 74 73 20 28 53 53 4c 5f 61 63
   63 65 70 74 28 29 29 0a 20 20 20 30 20 73 65 72
   76 65 72 20 72 65 6e 65 67 6f 74 69 61 74 65 73
   20 28 53 53 4c 5f 61 63 63 65 70 74 28 29 29 0a
   20 20 20 37 20 73 65 72 76 65 72 20 61 63 63 65
   70 74 73 20 74 68 61 74 20 66 69 6e 69 73 68 65
   64 0a 20 20 20 33 20 73 65 73 73 69 6f 6e 20 63
   61 63 68 65 20 68 69 74 73 0a 20 20 20 30 20 73
   65 73 73 69 6f 6e 20 63 61 63 68 65 20 6d 69 73
   73 65 73 0a 20 20 20 30 20 73 65 73 73 69 6f 6e
   20 63 61 63 68 65 20 74 69 6d 65 6f 75 74 73 0a
   20 20 20 30 20 63 61 6c 6c 62 61 63 6b 20 63 61
   63 68 65 20 68 69 74 73 0a 20 20 20 30 20 63 61
   63 68 65 20 66 75 6c 6c 20 6f 76 65 72 66 6c 6f
   77 73 20 28 31 32 38 20 61 6c 6c 6f 77 65 64 29
   0a 2d 2d 2d 0a 43 6c 69 65 6e 74 20 63 65 72 74
   69 66 69 63 61 74 65 0a 43 65 72 74 69 66 69 63
   61 74 65 3a 0a 20 20 20 20 44 61 74 61 3a 0a 20
   20 20 20 20 20 20 20 56 65 72 73 69 6f 6e 3a 20
   33 20 28 30 78 32 29 0a 20 20 20 20 20 20 20 20
   53 65 72 69 61 6c 20 4e 75 6d 62 65 72 3a 0a 20
   20 20 20 20 20 20 20 20 20 20 20 32 36 3a 33 66
   3a 35 36 3a 63 35 3a 37 33 3a 66 36 3a 36 62 3a
   33 36 3a 64 38 3a 39 61 3a 30 66 3a 63 37 3a 64
   62 3a 61 66 3a 34 61 3a 63 66 3a 66 37 3a 61 33
   3a 37 32 3a 30 66 0a 20 20 20 20 20 20 20 20 53
   69 67 6e 61 74 75 72 65 20 41 6c 67 6f 72 69 74
   68 6d 3a 20 45 44 32 35 35 31 39 0a 20 20 20 20
   20 20 20 20 49 73 73 75 65 72 3a 20 43 4e 3d 63
   72 79 70 74 6f 67 72 61 70 68 79 2e 69 6f 0a 20
   20 20 20 20 20 20 20 56 61 6c 69 64 69 74 79 0a
   20 20 20 20 20 20 20 20 20 20 20 20 4e 6f 74 20
   42 65 66 6f 72 65 3a 20 4d 61 72 20 32 33 20 32
   30 3a 31 35 3a 31 34 20 32 30 32 33 20 47 4d 54
   0a 20 20 20 20 20 20 20 20 20 20 20 20 4e 6f 74
   20 41 66 74 65 72 20 3a 20 41 70 72 20 32 33 20
   32 30 3a 31 35 3a 31 34 20 32 30 32 33 20 47 4d
   54 0a 20 20 20 20 20 20 20 20 53 75 62 6a 65 63
   74 3a 20 43 4e 3d 63 72 79 70 74 6f 67 72 61 70
   68 79 2e 69 6f 0a 20 20 20 20 20 20 20 20 53 75
   62 6a 65 63 74 20 50 75 62 6c 69 63 20 4b 65 79
   20 49 6e 66 6f 3a 0a 20 20 20 20 20 20 20 20 20
   20 20 20 50 75 62 6c 69 63 20 4b 65 79 20 41 6c
   67 6f 72 69 74 68 6d 3a 20 45 44 32 35 35 31 39
   0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 45 44 32 35 35 31 39 20 50 75 62 6c 69 63 2d
   4b 65 79 3a 0a 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 20 70 75 62 3a 0a 20 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 20 36 66
   3a 37 65 3a 62 38 3a 66 35 3a 61 33 3a 32 38 3a
   61 34 3a 62 39 3a 63 35 3a 35 36 3a 66 63 3a 33
   33 3a 38 38 3a 39 34 3a 39 36 3a 0a 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   35 31 3a 34 62 3a 61 33 3a 31 34 3a 61 36 3a 63
   63 3a 61 66 3a 38 36 3a 37 34 3a 35 38 3a 37 63
   3a 32 34 3a 39 33 3a 61 64 3a 35 63 3a 0a 20 20
   20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 61 36 3a 64 38 0a 20 20 20 20 20 20 20 20
   58 35 30 39 76 33 20 65 78 74 65 6e 73 69 6f 6e
   73 3a 0a 20 20 20 20 20 20 20 20 20 20 20 20 58
   35 30 39 76 33 20 53 75 62 6a 65 63 74 20 41 6c
   74 65 72 6e 61 74 69 76 65 20 4e 61 6d 65 3a 20
   0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20
   20 44 4e 53 3a 63 72 79 70 74 6f 67 72 61 70 68
   79 2e 69 6f 0a 20 20 20 20 20 20 20 20 20 20 20
   20 58 35 30 39 76 33 20 4b 65 79 20 55 73 61 67
   65 3a 20 0a 20 20 20 20 20 20 20 20 20 20 20 20
   20 20 20 20 44 69 67 69 74 61 6c 20 53 69 67 6e
   61 74 75 72 65 2c 20 4e 6f 6e 20 52 65 70 75 64
   69 61 74 69 6f 6e 2c 20 44 61 74 61 20 45 6e 63
   69 70 68 65 72 6d 65 6e 74 2c 20 43 65 72 74 69
   66 69 63 61 74 65 20 53 69 67 6e 0a 20 20 20 20
   20 20 20 20 20 20 20 20 58 35 30 39 76 33 20 42
   61 73 69 63 20 43 6f 6e 73 74 72 61 69 6e 74 73
   3a 20 63 72 69 74 69 63 61 6c 0a 20 20 20 20 20
   20 20 20 20 20 20 20 20 20 20 20 43 41 3a 46 41
   4c 53 45 0a 20 20 20 20 53 69 67 6e 61 74 75 72
   65 20 41 6c 67 6f 72 69 74 68 6d 3a 20 45 44 32
   35 35 31 39 0a 20 20 20 20 53 69 67 6e 61 74 75
   72 65 20 56 61 6c 75 65 3a 0a 20 20 20 20 20 20
   20 20 34 39 3a 64 32 3a 34 63 3a 30 37 3a 35 63
   3a 39 33 3a 61 65 3a 61 61 3a 39 38 3a 30 33 3a
   36 61 3a 64 36 3a 65 34 3a 32 35 3a 36 35 3a 37
   34 3a 34 35 3a 62 64 3a 0a 20 20 20 20 20 20 20
   20 34 65 3a 31 35 3a 66 62 3a 31 34 3a 66 64 3a
   38 64 3a 35 37 3a 39 62 3a 38 30 3a 63 35 3a 66
   35 3a 38 31 3a 39 35 3a 39 66 3a 61 30 3a 61 61
   3a 37 35 3a 30 34 3a 0a 20 20 20 20 20 20 20 20
   66 31 3a 66 38 3a 36 63 3a 66 61 3a 66 63 3a 30
   65 3a 62 64 3a 65 65 3a 33 61 3a 66 37 3a 66 61
   3a 65 63 3a 64 33 3a 36 34 3a 66 66 3a 38 36 3a
   32 37 3a 61 36 3a 0a 20 20 20 20 20 20 20 20 30
   64 3a 34 38 3a 64 64 3a 37 63 3a 63 35 3a 37 32
   3a 36 62 3a 36 34 3a 38 66 3a 30 39 0a 2d 2d 2d
   2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43
   41 54 45 2d 2d 2d 2d 2d 0a 4d 49 49 42 4c 6a 43
   42 34 61 41 44 41 67 45 43 41 68 51 6d 50 31 62
   46 63 2f 5a 72 4e 74 69 61 44 38 66 62 72 30 72
   50 39 36 4e 79 44 7a 41 46 42 67 4d 72 5a 58 41
   77 47 6a 45 59 4d 42 59 47 0a 41 31 55 45 41 77
   77 50 59 33 4a 35 63 48 52 76 5a 33 4a 68 63 47
   68 35 4c 6d 6c 76 4d 42 34 58 44 54 49 7a 4d 44
   4d 79 4d 7a 49 77 4d 54 55 78 4e 46 6f 58 44 54
   49 7a 4d 44 51 79 4d 7a 49 77 0a 4d 54 55 78 4e
   46 6f 77 47 6a 45 59 4d 42 59 47 41 31 55 45 41
   77 77 50 59 33 4a 35 63 48 52 76 5a 33 4a 68 63
   47 68 35 4c 6d 6c 76 4d 43 6f 77 42 51 59 44 4b
   32 56 77 41 79 45 41 62 33 36 34 0a 39 61 4d 6f
   70 4c 6e 46 56 76 77 7a 69 4a 53 57 55 55 75 6a
   46 4b 62 4d 72 34 5a 30 57 48 77 6b 6b 36 31 63
   70 74 69 6a 4f 54 41 33 4d 42 6f 47 41 31 55 64
   45 51 51 54 4d 42 47 43 44 32 4e 79 0a 65 58 42
   30 62 32 64 79 59 58 42 6f 65 53 35 70 62 7a 41
   4c 42 67 4e 56 48 51 38 45 42 41 4d 43 41 74 51
   77 44 41 59 44 56 52 30 54 41 51 48 2f 42 41 49
   77 41 44 41 46 42 67 4d 72 5a 58 41 44 0a 51 51
   42 4a 30 6b 77 48 58 4a 4f 75 71 70 67 44 61 74
   62 6b 4a 57 56 30 52 62 31 4f 46 66 73 55 2f 59
   31 58 6d 34 44 46 39 59 47 56 6e 36 43 71 64 51
   54 78 2b 47 7a 36 2f 41 36 39 37 6a 72 33 0a 2b
   75 7a 54 5a 50 2b 47 4a 36 59 4e 53 4e 31 38 78
   58 4a 72 5a 49 38 4a 0a 2d 2d 2d 2d 2d 45 4e 44
   20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d
   2d 0a 3c 2f 70 72 65 3e 3c 2f 42 4f 44 59 3e 3c
   2f 48 54 4d 4c 3e 0d 0a 0d 0a
     - TLS message 6 server_application_data [5498 bytes]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n<pre>\n\ns_server -cert server.crt -key server.key -www -port 8403 -CAfile client.crt -debug -keylogfile key.txt -msg -state -tlsextdebug -Verify 1 \nSecure Renegotiation IS NOT supported\nCiphers supported in s_server binary\nTLSv1.3    :TLS_AES_256_GCM_SHA384    TLSv1.3    :TLS_CHACHA20_POLY1305_SHA256 \nTLSv1.3    :TLS_AES_128_GCM_SHA256    TLSv1.2    :ECDHE-ECDSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2    :DHE-RSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-ECDSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-RSA-CHACHA20-POLY1305 \nTLSv1.2    :DHE-RSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-ECDSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2    :DHE-RSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-ECDSA-AES256-SHA384 TLSv1.2    :ECDHE-RSA-AES256-SHA384   \nTLSv1.2    :DHE-RSA-AES256-SHA256     TLSv1.2    :ECDHE-ECDSA-AES128-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-SHA256   TLSv1.2    :DHE-RSA-AES128-SHA256     \nTLSv1.0    :ECDHE-ECDSA-AES256-SHA    TLSv1.0    :ECDHE-RSA-AES256-SHA      \nSSLv3      :DHE-RSA-AES256-SHA        TLSv1.0    :ECDHE-ECDSA-AES128-SHA    \nTLSv1.0    :ECDHE-RSA-AES128-SHA      SSLv3      :DHE-RSA-AES128-SHA        \nTLSv1.2    :RSA-PSK-AES256-GCM-SHA384 TLSv1.2    :DHE-PSK-AES256-GCM-SHA384 \nTLSv1.2    :RSA-PSK-CHACHA20-POLY1305 TLSv1.2    :DHE-PSK-CHACHA20-POLY1305 \nTLSv1.2    :ECDHE-PSK-CHACHA20-POLY1305 TLSv1.2    :AES256-GCM-SHA384         \nTLSv1.2    :PSK-AES256-GCM-SHA384     TLSv1.2    :PSK-CHACHA20-POLY1305     \nTLSv1.2    :RSA-PSK-AES128-GCM-SHA256 TLSv1.2    :DHE-PSK-AES128-GCM-SHA256 \nTLSv1.2    :AES128-GCM-SHA256         TLSv1.2    :PSK-AES128-GCM-SHA256     \nTLSv1.2    :AES256-SHA256             TLSv1.2    :AES128-SHA256             \nTLSv1.0    :ECDHE-PSK-AES256-CBC-SHA384 TLSv1.0    :ECDHE-PSK-AES256-CBC-SHA  \nSSLv3      :SRP-RSA-AES-256-CBC-SHA   SSLv3      :SRP-AES-256-CBC-SHA       \nTLSv1.0    :RSA-PSK-AES256-CBC-SHA384 TLSv1.0    :DHE-PSK-AES256-CBC-SHA384 \nSSLv3      :RSA-PSK-AES256-CBC-SHA    SSLv3      :DHE-PSK-AES256-CBC-SHA    \nSSLv3      :AES256-SHA                TLSv1.0    :PSK-AES256-CBC-SHA384     \nSSLv3      :PSK-AES256-CBC-SHA        TLSv1.0    :ECDHE-PSK-AES128-CBC-SHA256 \nTLSv1.0    :ECDHE-PSK-AES128-CBC-SHA  SSLv3      :SRP-RSA-AES-128-CBC-SHA   \nSSLv3      :SRP-AES-128-CBC-SHA       TLSv1.0    :RSA-PSK-AES128-CBC-SHA256 \nTLSv1.0    :DHE-PSK-AES128-CBC-SHA256 SSLv3      :RSA-PSK-AES128-CBC-SHA    \nSSLv3      :DHE-PSK-AES128-CBC-SHA    SSLv3      :AES128-SHA                \nTLSv1.0    :PSK-AES128-CBC-SHA256     SSLv3      :PSK-AES128-CBC-SHA        \n---\nCiphers common between both SSL end points:\nTLS_AES_128_GCM_SHA256     TLS_CHACHA20_POLY1305_SHA256\nSupported groups: x25519\nShared groups: x25519\n---\nReused, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\nSSL-Session:\n    Protocol  : TLSv1.3\n    Cipher    : TLS_AES_128_GCM_SHA256\n    Session-ID: 8E89A29137C0C4309B27782A1DE5A3F4069FAAA0DD36A84A7529B75FCE3BE8A8\n    Session-ID-ctx: 01000000\n    Resumption PSK: 62E453A0BAA832B63CA6640D190534F5F40D544902B13C0ED72C17AB6CB2449E\n    PSK identity: None\n    PSK identity hint: None\n    SRP username: None\n    Start Time: 1680625818\n    Timeout   : 7200 (sec)\n    Verify return code: 18 (self-signed certificate)\n    Extended master secret: no\n    Max Early Data: 0\n---\n   0 items in the session cache\n   0 client connects (SSL_connect())\n   0 client renegotiates (SSL_connect())\n   0 client connects that finished\n   7 server accepts (SSL_accept())\n   0 server renegotiates (SSL_accept())\n   7 server accepts that finished\n   3 session cache hits\n   0 session cache misses\n   0 session cache timeouts\n   0 callback cache hits\n   0 cache full overflows (128 allowed)\n---\nClient certificate\nCertificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number:\n            26:3f:56:c5:73:f6:6b:36:d8:9a:0f:c7:db:af:4a:cf:f7:a3:72:0f\n        Signature Algorithm: ED25519\n        Issuer: CN=cryptography.io\n        Validity\n            Not Before: Mar 23 20:15:14 2023 GMT\n            Not After : Apr 23 20:15:14 2023 GMT\n        Subject: CN=cryptography.io\n        Subject Public Key Info:\n            Public Key Algorithm: ED25519\n                ED25519 Public-Key:\n                pub:\n                    6f:7e:b8:f5:a3:28:a4:b9:c5:56:fc:33:88:94:96:\n                    51:4b:a3:14:a6:cc:af:86:74:58:7c:24:93:ad:5c:\n                    a6:d8\n        X509v3 extensions:\n            X509v3 Subject Alternative Name: \n                DNS:cryptography.io\n            X509v3 Key Usage: \n                Digital Signature, Non Repudiation, Data Encipherment, Certificate Sign\n            X509v3 Basic Constraints: critical\n                CA:FALSE\n    Signature Algorithm: ED25519\n    Signature Value:\n        49:d2:4c:07:5c:93:ae:aa:98:03:6a:d6:e4:25:65:74:45:bd:\n        4e:15:fb:14:fd:8d:57:9b:80:c5:f5:81:95:9f:a0:aa:75:04:\n        f1:f8:6c:fa:fc:0e:bd:ee:3a:f7:fa:ec:d3:64:ff:86:27:a6:\n        0d:48:dd:7c:c5:72:6b:64:8f:09\n-----BEGIN CERTIFICATE-----\nMIIBLjCB4aADAgECAhQmP1bFc/ZrNtiaD8fbr0rP96NyDzAFBgMrZXAwGjEYMBYG\nA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMB4XDTIzMDMyMzIwMTUxNFoXDTIzMDQyMzIw\nMTUxNFowGjEYMBYGA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMCowBQYDK2VwAyEAb364\n9aMopLnFVvwziJSWUUujFKbMr4Z0WHwkk61cptijOTA3MBoGA1UdEQQTMBGCD2Ny\neXB0b2dyYXBoeS5pbzALBgNVHQ8EBAMCAtQwDAYDVR0TAQH/BAIwADAFBgMrZXAD\nQQBJ0kwHXJOuqpgDatbkJWV0Rb1OFfsU/Y1Xm4DF9YGVn6CqdQTx+Gz6/A697jr3\n+uzTZP+GJ6YNSN18xXJrZI8J\n-----END CERTIFICATE-----\n</pre></BODY></HTML>\r\n\r\n'
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

   APPLICATION DATA - [psk]: b'HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY BGCOLOR="#ffffff">\n<pre>\n\ns_server -cert server.crt -key server.key -www -port 8403 -CAfile client.crt -debug -keylogfile key.txt -msg -state -tlsextdebug -Verify 1 \nSecure Renegotiation IS NOT supported\nCiphers supported in s_server binary\nTLSv1.3    :TLS_AES_256_GCM_SHA384    TLSv1.3    :TLS_CHACHA20_POLY1305_SHA256 \nTLSv1.3    :TLS_AES_128_GCM_SHA256    TLSv1.2    :ECDHE-ECDSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2    :DHE-RSA-AES256-GCM-SHA384 \nTLSv1.2    :ECDHE-ECDSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-RSA-CHACHA20-POLY1305 \nTLSv1.2    :DHE-RSA-CHACHA20-POLY1305 TLSv1.2    :ECDHE-ECDSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2    :DHE-RSA-AES128-GCM-SHA256 \nTLSv1.2    :ECDHE-ECDSA-AES256-SHA384 TLSv1.2    :ECDHE-RSA-AES256-SHA384   \nTLSv1.2    :DHE-RSA-AES256-SHA256     TLSv1.2    :ECDHE-ECDSA-AES128-SHA256 \nTLSv1.2    :ECDHE-RSA-AES128-SHA256   TLSv1.2    :DHE-RSA-AES128-SHA256     \nTLSv1.0    :ECDHE-ECDSA-AES256-SHA    TLSv1.0    :ECDHE-RSA-AES256-SHA      \nSSLv3      :DHE-RSA-AES256-SHA        TLSv1.0    :ECDHE-ECDSA-AES128-SHA    \nTLSv1.0    :ECDHE-RSA-AES128-SHA      SSLv3      :DHE-RSA-AES128-SHA        \nTLSv1.2    :RSA-PSK-AES256-GCM-SHA384 TLSv1.2    :DHE-PSK-AES256-GCM-SHA384 \nTLSv1.2    :RSA-PSK-CHACHA20-POLY1305 TLSv1.2    :DHE-PSK-CHACHA20-POLY1305 \nTLSv1.2    :ECDHE-PSK-CHACHA20-POLY1305 TLSv1.2    :AES256-GCM-SHA384         \nTLSv1.2    :PSK-AES256-GCM-SHA384     TLSv1.2    :PSK-CHACHA20-POLY1305     \nTLSv1.2    :RSA-PSK-AES128-GCM-SHA256 TLSv1.2    :DHE-PSK-AES128-GCM-SHA256 \nTLSv1.2    :AES128-GCM-SHA256         TLSv1.2    :PSK-AES128-GCM-SHA256     \nTLSv1.2    :AES256-SHA256             TLSv1.2    :AES128-SHA256             \nTLSv1.0    :ECDHE-PSK-AES256-CBC-SHA384 TLSv1.0    :ECDHE-PSK-AES256-CBC-SHA  \nSSLv3      :SRP-RSA-AES-256-CBC-SHA   SSLv3      :SRP-AES-256-CBC-SHA       \nTLSv1.0    :RSA-PSK-AES256-CBC-SHA384 TLSv1.0    :DHE-PSK-AES256-CBC-SHA384 \nSSLv3      :RSA-PSK-AES256-CBC-SHA    SSLv3      :DHE-PSK-AES256-CBC-SHA    \nSSLv3      :AES256-SHA                TLSv1.0    :PSK-AES256-CBC-SHA384     \nSSLv3      :PSK-AES256-CBC-SHA        TLSv1.0    :ECDHE-PSK-AES128-CBC-SHA256 \nTLSv1.0    :ECDHE-PSK-AES128-CBC-SHA  SSLv3      :SRP-RSA-AES-128-CBC-SHA   \nSSLv3      :SRP-AES-128-CBC-SHA       TLSv1.0    :RSA-PSK-AES128-CBC-SHA256 \nTLSv1.0    :DHE-PSK-AES128-CBC-SHA256 SSLv3      :RSA-PSK-AES128-CBC-SHA    \nSSLv3      :DHE-PSK-AES128-CBC-SHA    SSLv3      :AES128-SHA                \nTLSv1.0    :PSK-AES128-CBC-SHA256     SSLv3      :PSK-AES128-CBC-SHA        \n---\nCiphers common between both SSL end points:\nTLS_AES_128_GCM_SHA256     TLS_CHACHA20_POLY1305_SHA256\nSupported groups: x25519\nShared groups: x25519\n---\nReused, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\nSSL-Session:\n    Protocol  : TLSv1.3\n    Cipher    : TLS_AES_128_GCM_SHA256\n    Session-ID: 8E89A29137C0C4309B27782A1DE5A3F4069FAAA0DD36A84A7529B75FCE3BE8A8\n    Session-ID-ctx: 01000000\n    Resumption PSK: 62E453A0BAA832B63CA6640D190534F5F40D544902B13C0ED72C17AB6CB2449E\n    PSK identity: None\n    PSK identity hint: None\n    SRP username: None\n    Start Time: 1680625818\n    Timeout   : 7200 (sec)\n    Verify return code: 18 (self-signed certificate)\n    Extended master secret: no\n    Max Early Data: 0\n---\n   0 items in the session cache\n   0 client connects (SSL_connect())\n   0 client renegotiates (SSL_connect())\n   0 client connects that finished\n   7 server accepts (SSL_accept())\n   0 server renegotiates (SSL_accept())\n   7 server accepts that finished\n   3 session cache hits\n   0 session cache misses\n   0 session cache timeouts\n   0 callback cache hits\n   0 cache full overflows (128 allowed)\n---\nClient certificate\nCertificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number:\n            26:3f:56:c5:73:f6:6b:36:d8:9a:0f:c7:db:af:4a:cf:f7:a3:72:0f\n        Signature Algorithm: ED25519\n        Issuer: CN=cryptography.io\n        Validity\n            Not Before: Mar 23 20:15:14 2023 GMT\n            Not After : Apr 23 20:15:14 2023 GMT\n        Subject: CN=cryptography.io\n        Subject Public Key Info:\n            Public Key Algorithm: ED25519\n                ED25519 Public-Key:\n                pub:\n                    6f:7e:b8:f5:a3:28:a4:b9:c5:56:fc:33:88:94:96:\n                    51:4b:a3:14:a6:cc:af:86:74:58:7c:24:93:ad:5c:\n                    a6:d8\n        X509v3 extensions:\n            X509v3 Subject Alternative Name: \n                DNS:cryptography.io\n            X509v3 Key Usage: \n                Digital Signature, Non Repudiation, Data Encipherment, Certificate Sign\n            X509v3 Basic Constraints: critical\n                CA:FALSE\n    Signature Algorithm: ED25519\n    Signature Value:\n        49:d2:4c:07:5c:93:ae:aa:98:03:6a:d6:e4:25:65:74:45:bd:\n        4e:15:fb:14:fd:8d:57:9b:80:c5:f5:81:95:9f:a0:aa:75:04:\n        f1:f8:6c:fa:fc:0e:bd:ee:3a:f7:fa:ec:d3:64:ff:86:27:a6:\n        0d:48:dd:7c:c5:72:6b:64:8f:09\n-----BEGIN CERTIFICATE-----\nMIIBLjCB4aADAgECAhQmP1bFc/ZrNtiaD8fbr0rP96NyDzAFBgMrZXAwGjEYMBYG\nA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMB4XDTIzMDMyMzIwMTUxNFoXDTIzMDQyMzIw\nMTUxNFowGjEYMBYGA1UEAwwPY3J5cHRvZ3JhcGh5LmlvMCowBQYDK2VwAyEAb364\n9aMopLnFVvwziJSWUUujFKbMr4Z0WHwkk61cptijOTA3MBoGA1UdEQQTMBGCD2Ny\neXB0b2dyYXBoeS5pbzALBgNVHQ8EBAMCAtQwDAYDVR0TAQH/BAIwADAFBgMrZXAD\nQQBJ0kwHXJOuqpgDatbkJWV0Rb1OFfsU/Y1Xm4DF9YGVn6CqdQTx+Gz6/A697jr3\n+uzTZP+GJ6YNSN18xXJrZI8J\n-----END CERTIFICATE-----\n</pre></BODY></HTML>\r\n\r\n'
