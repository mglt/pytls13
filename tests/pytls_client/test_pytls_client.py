#!/usr//bin/python3


import sys
sys.path.insert(0, '../../src/') # pytls13
## lurk
sys.path.insert(0, '/home/mglt/gitlab/pylurk.git/src/')

import os.path
import pprint
import time
import pytls13.tls_client 
import pytls_client_conf
## more genrally also for lurk stuf

## lists the engine configuration to be tested
## the configuration of the engine provides (among others) 
## the IP and port of the the TLS server to connect
engine_conf_key_list = pytls_client_conf.engine_conf_list.keys()
engine_conf_key_list = [ 'openssl_uclient', 'openssl_auth_client' ]
## lists the crypto service configurations to be tested
crypto_service_conf_key_list = pytls_client_conf.crypto_service_conf_list.keys()
crypto_service_conf_key_list = [ 'lib_cs', 'stateless_tcp' ]

ephemeral_method_list = [  'e_generated', 'cs_generated' ]


for engine_conf_key in engine_conf_key_list :
  for crypto_service_conf_key in crypto_service_conf_key_list:
    ## filtering incompatible combination  
    if engine_conf_key ==  'illustrated_tls13' and crypto_service_conf_key == 'stateless_tcp' :
      continue
    if engine_conf_key in [ 'openssl_uclient', 'openssl_auth_client' ]  and\
       crypto_service_conf_key == 'illustrated_tls13_stateless_tcp':
      continue
    for ephemeral_method in ephemeral_method_list :
      ## generating a coherent clt_conf to be passed as an input
      ## to generate the full configuration
      clt_conf = pytls_client_conf.engine_conf_list[ engine_conf_key ]
      if 'lurk_client' not  in clt_conf:
        clt_conf[ 'lurk_client' ] = {}
      clt_conf[ 'lurk_client' ][ 'connectivity' ] = pytls_client_conf.crypto_service_conf_list[ crypto_service_conf_key ][ 'connectivity' ]
      if 'tls13' not in clt_conf.keys() :
        clt_conf[ 'tls13' ] = {}
      clt_conf[ 'tls13' ][ 'ephemeral_method' ] = ephemeral_method
      ## When test_vector are used, keys are not considered
      if 'cs' in pytls_client_conf.crypto_service_conf_list[ crypto_service_conf_key ].keys() : 
        clt_conf[ 'cs' ] = pytls_client_conf.crypto_service_conf_list[ crypto_service_conf_key ][ 'cs' ]
      
      tls_client = pytls13.tls_client.SimpleTLS13Client( clt_conf )
      print( "--==================================================--" )
      print( "TLS Client Configuration:")
      pprint.pprint( tls_client.conf, width=65, sort_dicts=False)
      print( "--==================================================--\n" )
      print( '\n' )
      
      engine_param = pytls_client_conf.engine_conf_list\
                     [ engine_conf_key ][ 'destination' ]
      ip = engine_param[ 'ip' ]
      port = engine_param[ 'port' ]
    
      try: 
        sent_data = engine_param[ 'sent_data' ] 
      except KeyError:
          sent_data = b'GET /index.html HTTP/1.1\n Host: 127.0.0.1\n' 
    
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
      ## This recv could be used to read the session tickets.
      ## however, we assume the session tickets will be read 
      ## together with the data received from the TLS Server 
      ## session.recv() 
      session.send( sent_data )
      ## This time enables the TLS Server to send 
      ## its response
      time.sleep( 1 )
      data_response = session.recv()
      ## We do raise an error when the data response is empty
      ## For the tests we use the -WWW option so the server 
      ## actually returns an HTTP response 
      if data_response in [ None, b'' ]:
        raise ValueError( "Empty data response received" )
      print( f"APPLICATION DATA - [cert]: {data_response}" )
      if engine_conf_key == 'illustrated_tls13' :
        time.sleep( 2)
        continue
      continue
      ## key_log is espected to be usefull to decrypt the TLS 
      ## traffic
      session.key_log( )
      print( "======================================================" )
      print( "============= TLS with PSK authentication ============" )
      print( "======================================================\n" )
      session = tls_client.new_session( )
      session.connect( ip=ip, port=port )
      session.send( sent_data )
      time.sleep( 1 )
      data_response = session.recv()
      if data_response in [ None, b'' ]:
        raise ValueError( "Empty data response received" )
      print( f"APPLICATION DATA - [psk]: {data_response}" )
      session.close( )
##      ## waiting for the response.
##      time.sleep( 0.5 )
##      print( f"APPLICATION DATA - [psk]: {session.recv()}" )

