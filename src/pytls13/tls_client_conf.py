import copy

import sys 
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.conf 


clt_conf = {
  'role' : 'client',
  'description' : "TLS 1.3 Client configuration template",
#  'type' : 'tls13',
###  'server' : {
###    'fqdn' : None,
###    'ip' : '127.0.0.1',
####    'port' : 8400 #(debug illustrated TLS1.3)
####    'port' : 8401 #(debug IdoBn)
####    'port' : 8402 #(default openssl without authentication)
###    'port' : 8403 #(default openssl with client authentication (mTLS) )
####    'port' : 8404 # sajjad (mTLS)
####
###  },
  'debug' : {
    'trace' : True,  # prints multiple useful information
    'test_vector' : False,
    'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
    'test_vector_mode' : 'check', # check / record
  },
  'lurk_client' : {
    'freshness' : 'sha256',
#    'connectivity_type' : 'lib_cs', #'stateless_tcp', # 'lib_cs', # 'stateless_tcp'
    'connectivity' : {
      'type' : 'lib_cs', #'stateless_tcp', # 'lib_cs', # 'stateless_tcp'
      'fqdn' : None,
      'ip' : "127.0.0.1",
      'port' : 9999,
    }
  },
  'tls13' : { ## maybe that shoudl be called the engine
#    'ecdhe_authentication' : True, ## ecdhe indicates certificate based authentication
    'ke_modes' : [ 'psk_dhe_ke'], ## psk_ke
    'session_resumption' : True,
    'post_handshake_authentication' : False,  ## True/False
    ## sig scheme understood by the TLS Engine to authenticate the Server
    ## These values are considered by the TLS server to ensure the TLS
    ## client will be able to validate the server certificate
    ## these are NOT reflecting the sig_scheme supported by the CS,
    ## which indicates the signature scheme used by the CS.
    'signature_algorithms' : [ 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_pss_sha256', 'rsa_pss_pss_sha384', 'rsa_pss_pss_sha256', 'ed25519', 'ed448', 'rsa_pkcs1_sha1' ],
    ## configuration of ecdhe requires some synchronization with the cs
    ## configuration.
    ## maybe this may be generated from the CS configuration (or the reverse)
    'ephemeral_method' : 'cs_generated', ## cs_generated / e_generated when ECDHE is needed. otherwise can be set to 'no_secret'
    ## these values are used for the supported_group (non mandatory) and key_share extension
    'supported_ecdhe_groups' : [ 'x25519' ], #[ 'secp256r1', 'x25519', 'x448' ],
    ### These MUST be provided in the cs configuration part
#    'tls_client_private_key' : '/home/emigdan/gitlab/pytls13/tests/openssl/client.key',#    'tls_client_certificate_list' : [ '/home/emigdan/gitlab/pytls13/tests/openssl/client.crt']
  },
  ## parameters associated to the cryptographic material being used by
  ## the TLS client.
  ## When the CS is external, only the certificat enetry list is needed.
  ## When the CS is instantiated by the TLS client, it is likely that
  'cs' :{
    ( 'tls13', 'v1' ) : {
      'public_key': ['/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/_Ed25519PublicKey-ed25519-X509.der'],
      'private_key': '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/_Ed25519PrivateKey-ed25519-pkcs8.der',
      'sig_scheme': ['ed25519'],
#      '_cert_type': 'X509',
#      '_cert_entry_list': [{'cert': b"0\x82\x01!0\x81\xd4\xa0\x03\x02\x01\x02\x02\x14%|u`\xed2\x99\xcd\x18\xc4=\xbdK\x07\xd1\xe2\xdc\xd2\x8e\x180\x05\x06\x03+ep0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0\x1e\x17\r221205205644Z\x17\r230105205644Z0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0*0\x05\x06\x03+ep\x03!\x00\xd9\xa4\x03\xfa\x1f\xad'c&\x8d\x80~z\x93+,\xb77B\x9e\xf6\xf7\x06\xb5\r\xfc(\x9fIy\xdcU\xa3,0*0\x1a\x06\x03U\x1d\x11\x04\x130\x11\x82\x0fcryptography.io0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x05\x06\x03+ep\x03A\x00\x844K\x00\xbb\xb2R]\xaf\x96\xa1\x8bW\x0b=Et\xd8\xeajg\x9d\xace\x02p\xbaC\xbb\xa6\xd3\x9a,\xa0K\x17J\xbe\x0b\xd9\xc4\xaaL_\x16\x10|\x8b2.c\xec*\x08\xcc\xee9\x7fu\xcf\xca\xe5\xdc\x00", 'extensions': []}],
#      '_finger_print_entry_list': [{'finger_print': b'\xec\x86\xfd!', 'extensions': []}],
#      '_finger_print_dict': {b'\xec\x86\xfd!': b"0\x82\x01!0\x81\xd4\xa0\x03\x02\x01\x02\x02\x14%|u`\xed2\x99\xcd\x18\xc4=\xbdK\x07\xd1\xe2\xdc\xd2\x8e\x180\x05\x06\x03+ep0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0\x1e\x17\r221205205644Z\x17\r230105205644Z0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0*0\x05\x06\x03+ep\x03!\x00\xd9\xa4\x03\xfa\x1f\xad'c&\x8d\x80~z\x93+,\xb77B\x9e\xf6\xf7\x06\xb5\r\xfc(\x9fIy\xdcU\xa3,0*0\x1a\x06\x03U\x1d\x11\x04\x130\x11\x82\x0fcryptography.io0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x05\x06\x03+ep\x03A\x00\x844K\x00\xbb\xb2R]\xaf\x96\xa1\x8bW\x0b=Et\xd8\xeajg\x9d\xace\x02p\xbaC\xbb\xa6\xd3\x9a,\xa0K\x17J\xbe\x0b\xd9\xc4\xaaL_\x16\x10|\x8b2.c\xec*\x08\xcc\xee9\x7fu\xcf\xca\xe5\xdc\x00"}
    }
#      'debug' : {
#        'trace' : True,  # prints multiple useful information
#        'test_vector' : False,
#        'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
#        'test_vector_mode' : 'check', # check / record
#      }
  }
}

class Configuration( pylurk.conf.Configuration ) :

  def __init__( self, conf=copy.deepcopy( clt_conf ) ):
    self.conf = conf
    self.cs_conf = pylurk.conf.Configuration( )
    
  def set_connectivity( self, **kwargs ):
    self.conf[ 'lurk_client' ][ 'connectivity' ] = kwargs
    self.update_cs_conf( )

  def set_tls13_debug( self, **kwargs ):
    if 'trace' not in kwargs.keys() :
      kwargs[ 'trace' ] = False
    if 'test_vector_file' not in kwargs.keys() :
      kwargs[ 'test_vector_file' ] = None
      kwargs[ 'test_vector_mode' ] = None
    self.conf[ 'debug' ] = kwargs
    self.update_cs_conf( )

  def update_cs_conf( self ):
    init_cs_conf = {}
    if 'cs' in self.conf.keys():
      init_cs_conf = self.conf[ 'cs' ]
    ## merging init_cs 
    self.cs_conf.merge( init_cs_conf )
    if self.conf[ 'lurk_client' ][ 'connectivity' ] == 'lib_cs' :
      self.cs_conf.set_role( 'client' )
      ## setting / cleaning  connectivity configuration
      self.cs_conf.set_connectivity( **self.conf[ 'lurk_client' ][ 'connectivity' ] ) 
      self.cs_conf.set_tls13_debug( **self.conf[ 'debug' ] ) 
      self.cs_conf.set_tls13_authorization_type( )
      self.cs_conf.set_tls13_cs_signing_key( )
    else:
      ## cleaning unnecessary parameters
      self.cs_conf.set_tls13_cs_public_signing_key( )
      tmp_cs_conf = { ( 'tls13', 'v1' )  : { } }
      for k in [ 'public_key', '_public_key',  '_cert_type', '_cert_entry_list',\
                 '_finger_print_entry_list', '_finger_print_dict' ] :
        tmp_cs_conf[ k ] = self.cs_conf.conf[ ( 'tls13', 'v1' ) ][ k ]
    self.conf[ 'cs' ] = self.cs_conf.conf

