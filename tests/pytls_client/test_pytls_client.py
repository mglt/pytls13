#!/usr//bin/python3

import os.path
import pprint

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/')
import pytls13.tls_client 
import pytls_client_conf

#from pytls_client_conf import conf_dir, key_dir, tls_server_list, cs_list

### ### 
### ### ## Directory where the TLS client stores its cryptographic material
### ### # conf_dir = '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/'
### ### conf_dir = '/home/emigdan/gitlab/pytls13/tests/pytls_client/tls_client_keys'
### ### key_dir = os.path.join( conf_dir, 'tls_client_keys' )
### ### 
### ### ## THE designation is misleading. This IS NOT TLS SERVERS BUT TLS CLIENT 
### ### ## configuration. For a given TLS communication
### ### ## maybe tls_session_list
### ### 
### ### tls_server_list = { \
### ### #  'illustrated_tls13' : {
### ### #     'description' : f"  - Illustrated TLS1.3 Server\n"\
### ### #                     f"   - unauthenticated client\n", 
### ### #     'destination' : {
### ### #       'ip' : '127.0.0.1', 
### ### #       'port' : 8400,
### ### #     },
### ### #     'sent_data' : b'ping', 
### ### #     'debug' : {
### ### #       'trace' : True,
### ### #       'test_vector' : {
### ### #         'file' :  os.path.join( 'illustrated_tls13.json', 
### ### #         'mode' : 'check'
### ### #         },
### ### #       },
### ### #     'lurk_client' : {
### ### #       'freshness' : 'null'
### ### #       },
### ### #     'tls13': {
### ### #       'session_resumption' : False
### ### #     },
### ### #   }, 
### ###    'openssl_uclient' : {
### ###      'destination' : {
### ###        'ip' : '127.0.0.1', 
### ###        'port' : 8402, 
### ###      }, 
### ###      'debug' : {
### ###         'trace' : True
### ###      },
### ###      'tls13' : {
### ###        'session_resumption' : False
### ###      }, 
### ###      'description' : f"  - OpenSSL TLS1.3 Server\n"\
### ###                      f"  - unauthenticated client\n" }, 
### ###    'openssl_auth_client' : {
### ###      'destination' : {
### ###        'ip' : '127.0.0.1', 
### ###        'port' : 8403
### ###      },
### ###      'debug' : {
### ###         'trace' : True
### ###      },
### ###      'description' : f"  - OpenSSL TLS1.3 Server\n"\
### ###                      f"  - authenticated client\n" }, 
### ### }
### ### 
### ### 
### ### cs_list = {
### ###   'lib_cs' : { 
### ###     'connectivity' : {
### ###       'type': 'lib_cs', 
### ###       },
### ###      'cs' : {
### ###        ( 'tls13', 'v1' ) : {
### ###          'public_key' : [ os.path.join( conf_dir, '_Ed25519PublicKey-ed25519-X509.der' ) ],
### ###          'private_key': os.path.join( conf_dir, '_Ed25519PrivateKey-ed25519-pkcs8.der' ),
### ###          'sig_scheme': ['ed25519']
### ###        }
### ###     }
### ###   },
### ###   'illustrated_tls12_stateless_tcp' : {
### ###     'connectivity' : {
### ###       'type': 'stateless_tcp',
### ###       'ip' : '127.0.0.1', 
### ###       'port' : 9400
### ###      }
### ###    },
### ###   'stateless_tcp' : {
### ###     'connectivity' : {
### ###       'type': 'stateless_tcp',
### ###       'ip' : '127.0.0.1', 
### ###       'port' : 9401
### ###      }, 
### ###      'cs' : {
### ###        ( 'tls13', 'v1' ) : {
### ###          'public_key' : [ os.path.join( key_dir, '_Ed25519PublicKey-ed25519-X509.der' ) ],
### ###          'sig_scheme': ['ed25519']
### ###        }
### ###      }
### ###    }
### ### }

## The configuration is acomplished the following way:
## 1. set a configuration that has the same structure as the 
## tls_client_cong.Configuration template. 
## As many parameters can have a default value, only provide 
## those that are necessary.
## It is recommended to have the smallest subset so the full 
## configuration can be generated automatically and ensure 
## the coherence of the data being provided. 
## 2. Use tls_client_cong.Configuration to generate the full 
## configuration structure. 
## 
for engine_conf_key in pytls_client_conf.engine_conf_list.keys():
#    for cs in [ list( cs_list.keys() ) [ 0 ] ]:
  ### We avoid illustrated TLS 1.3 for now
  if engine_conf_key == 'illustrated_tls13':
    continue
  for cs in pytls_client_conf.crypto_service_conf_list.keys():
    if engine_conf_key ==  'illustrated_tls13' and cs == 'stateless_tcp' :
      continue
    if engine_conf_key in [ 'openssl_uclient', 'openssl_auth_client' ]  and\
       cs == 'illustrated_tls13_stateless_tcp':
      continue
    
    for ephemeral_method in [ 'cs_generated', 'e_generated' ] :
      ## generating a coherent clt_conf to be passed as an input
      ## to generate the full configuration
      clt_conf = pytls_client_conf.engine_conf_list[ engine_conf_key ]
      if 'lurk_client' not  in clt_conf:
        clt_conf[ 'lurk_client' ] = {}
      clt_conf[ 'lurk_client' ][ 'connectivity' ] = pytls_client_conf.crypto_service_conf_list[ cs ][ 'connectivity' ]
      if 'tls13' not in clt_conf.keys() :
        clt_conf[ 'tls13' ] = {}
      clt_conf[ 'tls13' ][ 'ephemeral_method' ] = ephemeral_method
      ## When test_vector are used, keys are not considered
      if 'cs' in pytls_client_conf.crypto_service_conf_list[ cs ].keys() : 
        clt_conf[ 'cs' ] = pytls_client_conf.crypto_service_conf_list[ cs ][ 'cs' ]
#      print( f" -- clt_conf : {clt_conf}" )
#        #with pytls13.tls_client_conf.Configuration( ) as conf:
#        ## generating the full configuration
#        conf = pytls13.tls_client_conf.Configuration( )
#        conf.merge( clt_conf )
##        if cs_list[ cs ][ 'connectivity' ][ 'type' ] == 'lib_cs':
##          conf.update_cs_conf( )
#        print( f" -- merge : {conf.conf}" )
#        conf.update_cs_conf( )
#        print( f" -- update : {conf.conf}" )
      
      tls_client = pytls13.tls_client.SimpleTLS13Client( clt_conf )
      print( "--==================================================--" )
      print( "TLS Client Configuration:")
      pprint.pprint( tls_client.conf, width=65, sort_dicts=False)
      print( "--==================================================--\n" )
      print( '\n' )
      
      engine_param = pytls_client_conf.engine_conf_list[ engine_conf_key ][ 'destination' ]
      ip = engine_param[ 'ip' ]
      port = engine_param[ 'port' ]
    
      try: 
        sent_data = engine_param[ 'sent_data' ] 
      except KeyError:
        sent_data = b'GET /index.html' 
    
      print( '\n' )
      print( "++==================================================++" )
      print( f"{tls_client.conf[ 'description' ]}\n"\
             f"  - ECDHE {ephemeral_method}" )
      print( "++==================================================++\n" )
      print( '\n' )
      print( "======================================================" )
      print( "========= TLS with certificate authentication ========" )
      print( "======================================================\n" )
      session = tls_client.new_session( )
      session.connect( ip=ip, port=port )
      session.send( sent_data )
      print( f"APPLICATION DATA - [cert]: {session.recv()}" )
      if engine_conf_key == 'illustrated_tls13' :
        time.sleep( 2)
        continue
    
      print( "======================================================" )
      print( "============= TLS with PSK authentication ============" )
      print( "======================================================\n" )
      session = tls_client.new_session( )
      session.connect( ip=ip, port=port )
      session.send( sent_data )
      print( f"APPLICATION DATA - [psk]: {session.recv()}" )

