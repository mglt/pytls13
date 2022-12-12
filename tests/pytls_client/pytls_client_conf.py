import os.path

## Directory where the TLS client stores its cryptographic material
# conf_dir = '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/'
conf_dir = './'
#conf_dir = '/home/emigdan/gitlab/pytls13/tests/pytls_client'
key_dir = os.path.join( conf_dir, 'tls_client_keys' )


#tls_server_list = { \
engine_conf_list = { \
  'illustrated_tls13' : {
     'description' : f"  - Illustrated TLS1.3 Server\n"\
                     f"   - unauthenticated client\n",
     'destination' : {
       'ip' : '127.0.0.1',
       'port' : 8400,
     },
     'sent_data' : b'ping',
     'debug' : {
       'trace' : True,
       'test_vector' : {
         'file' :  os.path.join( conf_dir, 'illustrated_tls13.json' ),
         'mode' : 'check'
         },
       },
     'lurk_client' : {
       'freshness' : 'null'
       },
     'tls13': {
       'session_resumption' : False
     },
   },
   'openssl_uclient' : {
     'destination' : {
       'ip' : '127.0.0.1',
       'port' : 8402,
     },
     'debug' : {
        'trace' : True
     },
     'tls13' : {
       'session_resumption' : False
     },
     'description' : f"  - OpenSSL TLS1.3 Server\n"\
                     f"  - unauthenticated client\n" },
   'openssl_auth_client' : {
     'destination' : {
       'ip' : '127.0.0.1',
       'port' : 8403
     },
     'debug' : {
        'trace' : True
     },
     'description' : f"  - OpenSSL TLS1.3 Server\n"\
                     f"  - authenticated client\n" },
}


crypto_service_conf_list = {
  'lib_cs' : {
    'connectivity' : {
      'type': 'lib_cs',
      },
     'cs' : {
       ( 'tls13', 'v1' ) : {
         'public_key' : [ os.path.join( key_dir, '_Ed25519PublicKey-ed25519-X509.der' ) ],
         'private_key': os.path.join( key_dir, '_Ed25519PrivateKey-ed25519-pkcs8.der' ),
         'sig_scheme': ['ed25519']
       }
    }
  },
  'illustrated_tls13_stateless_tcp' : {
    'connectivity' : {
      'type': 'stateless_tcp',
      'ip' : '127.0.0.1',
      'port' : 9400
     }
   },
  'stateless_tcp' : {
    'connectivity' : {
      'type': 'stateless_tcp',
      'ip' : '127.0.0.1',
      'port' : 9401
     },
     'cs' : {
       ( 'tls13', 'v1' ) : {
         'public_key' : [ os.path.join( key_dir, '_Ed25519PublicKey-ed25519-X509.der' ) ],
         'sig_scheme': ['ed25519']
       }
     }
   }
}


def get_tls_client_conf( ):
  pass

def get_cs_conf( ):
  pass
