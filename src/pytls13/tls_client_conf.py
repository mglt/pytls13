import copy

import sys 
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.conf 


clt_conf = {
  'role' : 'client',
  'description' : "TLS 1.3 Client configuration template",
  'debug' : {
    'trace' : True,  # prints multiple useful information
    'test_vector' : {
      'file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
      'mode' : 'check' # check / record / None
    },
  },
  'lurk_client' : {
    'freshness' : 'sha256',
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
    }
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
    debug_conf = {}
    if 'trace' in kwargs.keys() :
      debug_conf[ 'trace' ] = kwargs[ 'trace' ]
    if 'test_vector_file' in kwargs.keys() or 'test_vector_mode' in kwargs.keys():
      if 'test_vector_file' in kwargs.keys() and 'test_vector_mode' in kwargs.keys():
        test_vector = {}
        test_vector[ 'file' ] = kwargs[ 'test_vector_file' ]
        test_vector[ 'mode' ] = kwargs[ 'test_vector_mode' ]
        debug_conf[ 'test_vector'] = test_vector
      else:
        raise ConfigurationError( f" test_vector_file and test_vector_file"\
                          f"MUST be present together. {kwargs} ") 
    self.conf[ 'debug' ] = debug_conf
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

