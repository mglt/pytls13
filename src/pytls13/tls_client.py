#import sys
#sys.path.insert(0, './../src/')
## import socket 
import secrets 
import pprint
import binascii

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/')
import pytls13.struct_tls13 as tls
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.tls13.struct_tls13 as lurk

import pylurk.lurk.lurk_lurk
import pylurk.conf 
import pylurk.cs 
import pylurk.utils


ILLUSTRATED_TLS13 = True


#def str_to_bytes( hexlify_string:str ):
#  bytes_output = b''
#  for hex_str in hexlify_string.split( " " ):
#    bytes_output += binascii.unhexlify( hex_str )
#  return bytes_output


class TLSMsg:

  ### currenlty from bytes and to bytes do not fully intantiate the TlsMsg 
  ## - we probably should enable this - rather than having been done by show.
  ## bytes shoudl probably be changed to tls_reccord
  ## msg can be left or changed to fragment.
  def __init__( self, ):
    self.content_type = None #'handshake' ## the type of 
    self.msg_type = None # 'client_hello' ## handshake type when 
    self.msg = {}        ## the clear text msg or application data
    self.bytes = b''     ## TLS reccord in bytes 
    self.legacy_record_version = b'\x03\x03'

  def to_bytes( self, content_type=None, msg=None ):
    """ return a byte format TLS Reccord 
    
    The inner packet ( self.msg ) is wrapped into the TLS Reccord.
    """ 
    if content_type is None:
      content_type = self.content_type
    if msg is None :
      msg = self.msg
#    return pylurk.tls13.struct_tls13.Handshake.build( self.msg ) 
    tls_plain_text = { 'type' : content_type,
                       'legacy_record_version' : b'\x03\x03',
                       'fragment' : msg }
#    print( f"TLS PlainText: {tls_plain_text}\n" )
#    return pytls13.struct_tls13.TLSPlaintext.build( tls_plain_text ) 
    return tls.TLSPlaintext.build( tls_plain_text ) 

  def from_bytes( self, byte_string):
    """ Extract the inner message from a TLS Record in bytes"""
    tls_plain_text = tls.TLSPlaintext.parse( byte_string )
    if self.content_type!= None:
      if tls_plain_text[ 'type' ] !=  self.content_type :
        raise ValueError( f"unexpected content_type. Expecting {self.content_type}, got {tls_plain_text[ 'type' ]}" )
      if self.content_type == 'handshake' and self.msg_type != None: 
        if tls_plain_text[ 'fragment' ][ 'msg_type' ] != self.msg_type: 
          raise ValueError( f"unexpected msg_type. Expecting {self.msg_type}, got {tls_plain_text[ 'fragment' ][ 'msg_type' ]}" )
    self.content_type = tls_plain_text[ 'type' ]
    self.legacy_record_version = tls_plain_text[ 'legacy_record_version' ]
    self.msg = tls_plain_text[ 'fragment' ]
    
  def show( self, content_type=None, msg=None ):
    self.bytes = self.to_bytes( content_type=content_type, msg=msg )
    pylurk.utils.print_bin( "", self.bytes ) 
#    pprint.pprint( f"  - (bytes) [len {len( self.bytes )}] {binascii.hexlify( self.bytes, sep=' ' )}" )
    print ( f"  - (struct) : {tls.TLSPlaintext.parse( self.bytes )}" )
  

#  def parse_record_layer_type( self):
#    """ returns the reccord layer Content Type
#
#    possible values are 'handshake', 'change_cipher_spec', 'application'
#    """
#    return pytls13.struct_tls13.ContentType.parse( ( self.bytes[ 0 ] ).to_bytes(1, byteorder='big') )

  def parse_record_layer_length( self) : 
    """ returns the recoord layer length from bytes """
#    print( f" - reccord layer_length: {int.from_bytes( self.bytes[ 3 : 5 ] , byteorder='big') }" )
    return int.from_bytes( self.bytes[ 3 : 5 ] , byteorder="big") + 5

#  def parse_handshake_type( self ):
#    """ return the message type 
#
#    This corresponds to the first byte of the data carried in the reccord layer.
#    When the content type is handshake this is the type of the handshake 
#    message (client_hello, server_hello...
#    For change_cipher_spec, this is a byte set to '01', for application, 
#    this is the first byte of the encrypted application data.  
#    As a result, thisis only useful for handshake messages.
#    """
#    print( f"msg_type: {self.parse_content_type( )}" )
#    if self.parse_content_type( ) == 'handshake':
#      return pytls13.struct_tls13.HandshakeType.parse( ( self.bytes[ 5 ] ).to_bytes(1, byteorder='big') )


  def parse_single_msg( self, socket )-> dict:
    """ parse the message and return the inner fragment (of the TLS plain_text) and remaining bytes 
    """
    if len( self.bytes ) == 0:
      self.bytes = socket.recv( 4096 )
    while self.parse_record_layer_length() > len( self.bytes ) :
      self.bytes += socket.recv( 4096 )
    msg = tls.TLSPlaintext.parse( self.bytes[ : self.parse_record_layer_length() ] )
    self.bytes = self.bytes[ self.parse_record_layer_length() : ]
    return msg  

  def add_ext( self, ext_list ) :
    for ext in ext_list:
      self.msg[ 'data' ][ 'extensions' ].append( ext.msg )


class ClientHello( TLSMsg ):

  def __init__( self, tls_client_conf=None):
    self.conf = tls_client_conf
    self.content_type = 'handshake' 
    self.msg_type = 'client_hello'
    if self.conf[ 'illustrated_tls13'] is True:
      self.illustrated_tls13( )
    else:
      self.msg = {\
        'msg_type': self.msg_type, \
        'data' : {\
          'legacy_version' : b'\x03\x03',
          'random' : secrets.token_bytes( 32 ),
          'legacy_session_id' : secrets.token_bytes( 32 ),
          'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
          'legacy_compression_methods' : b'\x00',
          'extensions' : [ ] } }

      self.ecdhe_private_key_list = None
      self.default_ext( )

  def illustrated_tls13( self ):
    ## Note that we update TLS version of the Header record to TLS 1.2 whil eth eoriginal is TLS 1.0.
    self.illustrated_tls13_ch = "16 03 03 00 f8 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54"
    self.from_bytes( pylurk.utils.str_to_bytes( self.illustrated_tls13_ch ) )
    key_share_index = 0
    for e in self.msg[ 'data' ][ 'extensions' ]:
      if e[ 'extension_type' ] == 'key_share':
        break
      else:
        key_share_index += 1
    self.msg[ 'data' ][ 'extensions' ][ key_share_index ][ 'extension_data' ][ 'client_shares' ][ 0 ][ 'key_exchange' ] = b''


#    print( f" -- ClientHello: (tls) {tls.ClientHello.build( self.msg[ 'data' ] ) }" ) 
  ## when sesison resumption
  ## psk_Exchange_modes ?
  ## session_ticket
  def default_ext( self ):
    ext_list = [ ExtClientProtocolVersions() ]
    if self.conf[ 'ecdhe_authentication' ] is True: 
      sig_algo = self.conf[ 'signature_algorithms' ] 
      ext_list.append( ExtClientSignatureAlgorithms( sig_algo ) )
      ext_list.append( ExtSupportedGroups( self.conf[ 'supported_ecdhe_groups' ] ) )
      key_share = ExtKeyShare( self.conf )
      self.ecdhe_private_key_list = key_share.ecdhe_private_key_list
      print( f"self.ecdhe_private_key_list initialized {self.ecdhe_private_key_list}" )
      ext_list.append( key_share )
    if self.conf[ 'post_handshake_authentication' ] is True:
      self.add_ext( ExtPostHandshakeAuthentication() )
    if self.conf[ 'session_resumption' ] is True:
      ## if in a session resumption state
      ## psk (ke_psk)
      ext_list.append( ExtPskKeyExchangeMode( self.conf[ 'ke_modes' ] ) )
    self.add_ext( ext_list )

  def to_bytes( self, content_type=None, msg=None ):
    if self.conf[ 'illustrated_tls13'] is True:
      if TLSMsg.to_bytes( self ) != pylurk.utils.str_to_bytes( self.illustrated_tls13_ch ):
        raise ValueError( "ClientHello byte mismatch" )
    return TLSMsg.to_bytes( self ) 

  def c_init_client_hello_update( self, lurk_resp, tls_handshake, lurk_client ):
    """ updates self.msg according to the c_init_client_hello response """
       ## random
#  tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )
    tls_handshake.msg_list = [ self.msg ]
#  tls_handshake.update_random( pylurk.tls13.lurk_tls13.Freshness( lurk_req[ 'payload' ][ 'freshness' ] ) )
    tls_handshake.update_random( pylurk.tls13.lurk_tls13.Freshness( lurk_client.freshness ) )
    ## keyshare 
    ephemeral_list = lurk_resp[ 'payload' ][ 'ephemeral_list' ]
    client_shares = [ eph[ 'key' ] for eph in ephemeral_list ]
    tls_handshake.update_key_share( client_shares )
    self.msg = tls_handshake.msg_list[ 0 ]
    ## we can only do it when we know the hash fucntion, that is PSK 
    ## or when cipher suite is selected. 
    ## tls_handshake.transcript_hash( 'e' )

class ExtClientProtocolVersions:

  def __init__( self ):
    self.msg = { 'extension_type': 'supported_versions', \
                 'extension_data' : { 'versions' : [ b'\x03\x04'] } }

class ExtClientSignatureAlgorithms:

  def __init__( self, sig_list ) :
    self.msg = { 'extension_type': 'signature_algorithms', \
                 'extension_data' : { 'supported_signature_algorithms' : sig_list } }
    

class ExtSupportedGroups:

  def __init__( self, supported_groups ):  
    self.msg = {'extension_type': 'supported_groups', \
                'extension_data' : {'named_group_list' : supported_groups } }


class ExtKeyShare:

  def __init__( self, tls_client_conf  ):
    self.conf = tls_client_conf
    self.ecdhe_private_key_list = []
#    self.ecdhe_public_key_list = []
    print( f"key_share conf : {self.conf}" )
    ## when generated by E, ke_entries are generated
    if self.conf[ 'ephemeral_method' ] == 'e_generated' :
      self.e_generate( )
    ## when generated by the CS, the ke_entries are empty
    elif self.conf[ 'ephemeral_method' ] == 'cs_generated' :
      self.cs_generate( )
    else: 
      raise pylurk.lurk.lurk_lurk.ConfigurationError( f"unexpected ephemeral_method {self.conf[ 'ephemeral_method' ]} ")

  def e_generate( self ):
    ke_entry_list = []
    for ecdhe_group in self.conf[ 'supported_ecdhe_groups' ]:
      if ecdhe_group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
        if ecdhe_group == 'secp256r1':
          private_key = ec.generate_private_key( ec.SECP256R1() )
        elif ecdhe_group == 'secp384r1' : 
          private_key = ec.generate_private_key( ec.SECP384R1() )
        elif ecdhe_group == 'secp521r1' : 
          private_key = ec.generate_private_key( ec.SECP521R1() )
        self.ecdhe_private_key_list.append( private_key )
        public_key = private_key.public_key()
#        self.ecdhe_public_key_list.append( public_key )
        public_numbers = public_key.public_numbers()
        ke_entry_list.append( {\
          'group': ecdhe_group, 
          'key_exchange' : { 'legacy_form' : 4, \
                             'x' : public_numbers.x, \
                             'y' : public_numbers.y } } )
      elif ecdhe_group == 'x25519':
        private_key = X25519PrivateKey.generate()
        self.ecdhe_private_key_list.append( private_key )
        print( f"---- {ecdhe_group} private key added {self.ecdhe_private_key_list}" ) 
        public_key = private_key.public_key()
        x25519_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
        ke_entry_list.append( {'group': 'x25519', 'key_exchange' : x25519_key } )
      elif ecdhe_group == 'x448':
        private_key = X448PrivateKey.generate()
        self.ecdhe_private_key_list.append( private_key )
        public_key = private_key.public_key()
        x448_key = public_key.public_bytes(
          encoding=serialization.Encoding.Raw,
          format=serialization.PublicFormat.Raw)
        ke_entry_list.append( {'group': 'x448', 'key_exchange' : x448_key} )
    self.msg = { 'extension_type': 'key_share', \
                 'extension_data' : { 'client_shares' : ke_entry_list } }

 
  def cs_generate( self ):
    
    ke_entry_list = []
    for ecdhe_group in self.conf[ 'supported_ecdhe_groups' ]:
      ke_entry_list.append( { 'group': ecdhe_group , 'key_exchange' : b''} )
    self.msg = { 'extension_type': 'key_share', \
                 'extension_data' : { 'client_shares' : ke_entry_list } }
##    print( f" --- ExtKeyShare (lurk) : {lurk.PartialCHExtension.build( self.msg ) }" )
##    print( f" --- ExtKeyShare (tls) : {tls.Extension.build( self.msg, _msg_type= 'client_hello' ) }" )

class ExtPskKeyExchangeMode:

  def __init__( self, ke_modes ):
    self.msg = { 'extension_type': 'psk_key_exchange_modes', \
                 'extension_data' : {'ke_modes' : ke_modes } }

class ExtPostHandshakeAuthentication:

  def __init__( self ):
    self.msg = { 'extension_type': 'post_handshake_auth', \
                 'extension_data' : {} }


class ServerHello( TLSMsg ):

  def __init__( self ):
#    self.conf = tls_client_conf[ ( 'tls13', 'v1' ) ]
    self.content_type = 'handshake' 
    self.msg_type = 'server_hello'
    self.msg = None
#    self.msg = {\
#    'msg_type': self.msg_type,
#    'data' : {
#      'legacy_version' : b'\x03\x03',
#      'random' : token_bytes( 32 ),
#      'legacy_session_id_echo' : token_bytes( 32 ),
#      'cipher_suite' :'TLS_AES_128_GCM_SHA256',
#      'legacy_compression_method' : b'\x00',
#      'extensions' : [] } }

  def get_shared_secret( self, private_key):
    
    for ext in self.msg[ 'data' ][ 'extensions' ] :
      if ext[ 'extension_type' ] == 'key_share':
        server_ks = ext[ 'extension_data' ][ 'server_share' ]
        break
##  def get_publickey_from_key_share_entry( self, ks_entry ):
##    """ returns the public key associated to a key share entry """
    ks_entry = server_ks
    group = ks_entry[ 'group' ]
    key_exchange = ks_entry[ 'key_exchange' ]
#    if group not in self.conf[ 'authorized_ecdhe_group' ]:
#      raise LURKError( 'invalid_ephemeral', f"unsupported {self.group}" )
    if group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      if group ==  'secp256r1':
        curve =  SECP256R1()
      elif group ==  'secp394r1':
        curve = SECP384R1()
      elif group ==  'secp521r1':
        curve = SECP521R1()
      public_key = EllipticCurvePublicNumbers( key_exchange[ 'x' ],\
                     key_exchange[ 'y' ], curve )
    elif group  in [ 'x25519', 'x448' ]:
      if group == 'x25519':
        public_key = X25519PublicKey.from_public_bytes( key_exchange )
      elif group == 'x448':
        public_key = X448PublicKey.from_public_bytes( key_exchange )
    else:
      raise ValueError( 'invalid_ephemeral', f"unknown group {group}" )

##  def  compute_share_secret( self, private_key, public_key, group ):
    if group in [ 'secp256r1', 'secp384r1', 'secp521r1' ]:
      shared_secret = private_key.exchange( ECDH(), public_key )
    elif group  in [ 'x25519', 'x448' ]:
      shared_secret = private_key.exchange( public_key )
    else:
      raise LURKError( 'invalid_ephemeral', f"Unexpected group {group}" )
    return shared_secret

  def c_server_hello_update( self, lurk_resp, tls_handshake, ks ):
#    if ephemeral_method == 'e_generated':
#      shared_secret = XXX
#    else:
#      shared_secret = None
    ## create ks
    for secret in lurk_resp[ 'payload' ][ 'secret_list' ] :
      ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]
    tls_handshake.transcript_hash( 'h' )
    return ks  
  

class EncryptedExtensions( TLSMsg ):

  def __init__( self ):
    self.msg = {\
      'msg_type' : 'encrypted_extensions',
      'data' : { 'extensions' :  [] } }

class CertificateRequest( TLSMsg ):
  def __init__( self ):
    self.msg = {
      'msg_type' : 'certificate_request',
      'data' : { 'certificate_request_context' :  b'\x00\x01',
                 'extensions' : [] } }

class Finished( TLSMsg ):
  def __init__( self ):
    self.msg = {
      'msg_type' : 'finished',
      'data' : {'verify_data' : token_bytes( 32 )}}

class CertificateVerify( TLSMsg ):
  def __init__( self, algorithm='ed25519', signature=b'signature' ):
    self.msg = {
      'msg_type' : 'certificate_verify',
      'data' : { 'algorithm' : algorithm,
                 'signature' : signature }}

class Certificate( TLSMsg ):

  def __init__( self, certificate_entry_list=None, certificate_request_context=b'' ):
    self.msg = {
      'msg_type' : 'certificate',
      'data' : { 'certificate_request_context' : certificate_request_context,
                 'certificate_list' : [ cert_entry, cert_entry, cert_entry ] } }




