#!/usr/bin/python3

import sys
import argparse
import pprint
import time
## When used with GRAMINE, we need to indicate the 
## path to find modules installed by pip
## 
sys.path.insert(0, '/home/mglt/.local/lib/python3.10/site-packages')
sys.path.insert(0, '/home/mglt/gitlab/pylurk.git/src')
sys.path.insert(0, '/home/mglt/gitlab/pytls13/src')

#import pylurk.cs
#import pylurk.conf
import pytls13.tls_client_conf
import pytls13.tls_client

if __name__ == '__main__' :
  cli = pytls13.tls_client_conf.CLI( )
  parser = cli.get_parser( env=True )
  args = parser.parse_args()
  print( f" --- Executing: {__file__} with {args}" )
  ## Building the template (in general expected to
  ## be manually generated )
  cli.init_from_args( args )
  e_template_conf = cli.get_template( )

  print( 'Configuration Template (from end user arguments ):\n' )
  pprint.pprint( e_template_conf, width=65, sort_dicts=False )
  tls_client = pytls13.tls_client.SimpleTLS13Client( e_template_conf )
  print( 'Full configuration:\n' )
  pprint.pprint( tls_client.conf,  width=65, sort_dicts=False )

  ip = tls_client.conf[ 'destination' ][ 'ip' ]
  port = tls_client.conf[ 'destination' ][ 'port' ]
  sent_data = tls_client.conf[ 'sent_data' ]

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
  ## key_log is espected to be usefull to decrypt the TLS
  ## traffic
  session.key_log( )
  if args.reconnect is True:
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

  
