#!/usr//bin/python3


import sys
sys.path.insert(0, '../../src/') # pytls13
## lurk
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src/')

import os.path
import pprint
import time
import pytls13.tls_client 
import pytls_client_conf
## more genrally also for lurk stuf

for engine_conf_key in pytls_client_conf.engine_conf_list.keys():
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

