#!/usr/bin/python3

import argparse
import socketserver
import os.path
import pprint

import sys 
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src')
import pylurk.cs
import pylurk.conf

import pytls_client_conf


## adding the key to all servers
for k in pytls_client_conf.crypto_service_conf_list.keys():
  pytls_client_conf.crypto_service_conf_list[ k ][ ( 'tls13', 'v1' ) ] = {
     'public_key' : [os.path.join( pytls_client_conf.key_dir, '_Ed25519PublicKey-ed25519-X509.der' )],
     'private_key' : os.path.join( pytls_client_conf.key_dir, '_Ed25519PrivateKey-ed25519-pkcs8.der' ), ## der, pkcs8
      'sig_scheme' : [ 'ed25519' ] }

## adding the debug information
for k in pytls_client_conf.crypto_service_conf_list.keys():
  if k in [ 'illustrated_tls13_stateless_tcp' ] :
    pytls_client_conf.crypto_service_conf_list[ k ][ ( 'tls13', 'v1' ) ][ 'debug' ] = pytls_client_conf.engine_conf_list[ 'illustrated_tls13' ][ 'debug' ]
pprint.pprint( pytls_client_conf.crypto_service_conf_list )

## parsing the arguments

parser = argparse.ArgumentParser(description='Cryptographic Server')
parser.add_argument( '-t', '--type', type=ascii, default='stateless_tcp', \
  nargs='?', help='serveur type')
parser.add_argument( '-i', '--illustrated', default=False,  \
  action='store_const', const=True, help='running illustrated TLS 1.3')
args = parser.parse_args()

if args.type == "'stateless_tcp'":
  if args.illustrated is True:
    cs_conf_template = pytls_client_conf.crypto_service_conf_list[ 'illustrated_tls13_stateless_tcp' ] 
  else: 
    cs_conf_template = pytls_client_conf.crypto_service_conf_list[ 'stateless_tcp' ] 
  cs_conf = pylurk.conf.Configuration( )
  pprint.pprint( cs_conf.conf )
  cs_conf.merge( cs_conf_template )
  pprint.pprint( cs_conf.conf )
  cs_conf.set_role( 'client' )
  cs_conf.set_tls13_authorization_type( )
  cs_conf.set_tls13_cs_signing_key( )
else:
  raise ValueError( f"type MUST be 'stateless_tcp'. Got {args}")
pprint.pprint( f"Provide arguments: {args}" )
print( 'Provided configuration:\n' )
pprint.pprint( pytls_client_conf.crypto_service_conf_list[ k ], width=65, sort_dicts=False )
print( 'Full configuration:\n' )
pprint.pprint( cs_conf.conf,  width=65, sort_dicts=False ) 

print( f"\nListening on port {cs_conf.conf[ 'connectivity'] [ 'port' ]}" )
with pylurk.cs.get_cs_instance( cs_conf.conf ) as cs:
  cs.serve_forever()
