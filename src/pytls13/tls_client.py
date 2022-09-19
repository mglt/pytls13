#import sys
#sys.path.insert(0, './../src/')
## import socket 
import secrets 
import pprint
import binascii
import pickle
import json

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/')
import pytls13.struct_tls13 as tls
import pytls13.test_vector
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.tls13.struct_tls13 as lurk

import pylurk.lurk.lurk_lurk
#import pylurk.conf 
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
  def __init__( self, conf=None, content_type=None, content={}, sender=None ):
    
   
    self.conf = None  
    if conf is not None:
      self.conf = conf
    self.content_type = None #'handshake' ## the type of 
    if content_type is not None:
      self.content_type = content_type
#    self.msg_type = None # 'client_hello' ## handshake type when 
    self.content = {}        ## the clear text msg or application data
    if content != {}:
      self.content = content
    try:
      if self.conf[ 'debug' ][ 'test_vector' ] is True and \
        self.conf[ 'debug' ][ 'test_vector_tls_traffic' ] is False:
        self.no_traffic = True
      else:
        self.no_traffic = False
    except( TypeError, KeyError ):
      self.no_traffic = False
    self.sender = None  
    if sender is not None:
      self.sender = sender

    self.record_layer_bytes = b''     ## TLS reccord in bytes 
    self.legacy_record_version = b'\x03\x03'

## bytes = record_layer_bytes
## msg = content
## to_bytes = to_record_layer_bytes
## from record_layer_bytes

  def to_record_layer_struct( self, content_type=None, content=None  ):
    if content_type is None:
      content_type = self.content_type
    if content is None :
      content = self.content
#    return pylurk.tls13.struct_tls13.Handshake.build( self.content ) 
    return { 'type' : content_type,
             'legacy_record_version' : self.legacy_record_version,
             'fragment' : content }
    
  def to_record_layer_bytes( self, content_type=None, content=None ):
    """ return a byte format TLS Reccord 
    
    The inner packet ( self.content ) is wrapped into the TLS Reccord.
    """ 
#    print( f"TLS PlainText: {tls_plain_text}\n" )
#    return pytls13.struct_tls13.TLSPlaintext.build( tls_plain_text ) 
    return tls.TLSPlaintext.build( self.to_record_layer_struct( content_type=content_type, content=content  ) ) 

  def from_record_layer_struct( self, tls_plain_text ):
    self.content_type = tls_plain_text[ 'type' ]
    if 'legacy_record_version' in tls_plain_text.keys(): 
      self.legacy_record_version = tls_plain_text[ 'legacy_record_version' ]
    if 'fragment' in tls_plain_text.keys():
      self.content = tls_plain_text[ 'fragment' ]
    else: 
      self.content = tls_plain_text[ 'content' ]
      
  def from_record_layer_bytes( self, byte_string):
    """ Extract the inner message from a TLS Record in bytes"""
    tls_plain_text = tls.TLSPlaintext.parse( byte_string )
#    if self.content_type!= None:
#     if tls_plain_text[ 'type' ] !=  self.content_type :
#        raise ValueError( f"unexpected content_type. Expecting {self.content_type}, got {tls_plain_text[ 'type' ]}" )
#      if self.content_type == 'handshake' and self.msg_type != None: 
#        if tls_plain_text[ 'fragment' ][ 'msg_type' ] != self.msg_type: 
#          raise ValueError( f"unexpected msg_type. Expecting {self.msg_type}, got {tls_plain_text[ 'fragment' ][ 'msg_type' ]}" )
    self.content_type = tls_plain_text[ 'type' ]
    self.legacy_record_version = tls_plain_text[ 'legacy_record_version' ]
    self.content = tls_plain_text[ 'fragment' ]
    self.record_layer_bytes = byte_string

 

  def from_test_vector( self, test_vector_file, key ):
    print( f" --- test_vector: {test_vector_file}" )
    print( f" --- key: {key}" )
    with open( test_vector_file, 'rt', encoding='utf8' ) as f:
      test_vector = json.load( f )
    self.from_record_layer_bytes( pylurk.utils.str_to_bytes( test_vector[ key ] ) )

  def descriptor( self, sender=None ):
    if sender is None:
      sender = self.sender
    if self.content_type == 'handshake' :
      descriptor = f"{sender}_{self.content[ 'msg_type' ]}"
    else:
      descriptor = f"{sender}_{self.content_type}"

    return descriptor

  def show( self, content_type=None, content=None ):
    self.record_layer_bytes = self.to_record_layer_bytes( content_type=content_type, content=content )
    pylurk.utils.print_bin( "", self.record_layer_bytes ) 
#    pprint.pprint( f"  - (bytes) [len {len( self.bytes )}] {binascii.hexlify( self.bytes, sep=' ' )}" )
    print ( f"  - (struct) : {tls.TLSPlaintext.parse( self.record_layer_bytes )}" )
  
  def add_ext( self, ext_list ) :
    for ext in ext_list:
      self.content[ 'data' ][ 'extensions' ].append( ext.content )

  def encrypt_and_send( self, cipher, socket, sender, test_vector=None):
    """ encrypt and send the provided innet_tls_msg 

    The current tls msg is considered as the inner clear text message
    """
##    inner_cipher_text, inner_clear_text, clear_text_struct = c_h_cipher.encrypt( inner_tls_msg.content, content_type=inner_tls_msg.content_type, debug=True )
    inner_cipher_text, inner_clear_text, inner_clear_text_struct = cipher.encrypt( self.content, content_type=self.content_type, debug=True )
    tls_msg = TLSMsg( conf=self.conf, \
                      content_type='application_data', \
                      content=inner_cipher_text )
#    tls_msg.content = inner_cipher_text
#    tls_msg.content_type = 'application_data'
    if test_vector is not None: 
      test_vector.handle_tls_cipher_text_msg_enc( tls_msg, \
                                                  inner_clear_text,\
                                                  inner_clear_text_struct,\
                                                  sender=sender)
    if self.no_traffic is False:
      socket.sendall( tls_msg.to_record_layer_bytes( ) )


  def decrypt_inner_msg( self, cipher, test_vector ):
    inner_tls_msg = TLSMsg()
    inner_clear_text_struct, inner_clear_text = cipher.decrypt( self.content, debug=True )
    test_vector.handle_tls_cipher_text_msg_dec( self, inner_clear_text, inner_clear_text_struct, sender='server' )
    inner_tls_msg.from_record_layer_struct( inner_clear_text_struct )
    inner_tls_msg.sender = self.sender
    ## possibly we should return the appropriated msg, encryptedEx, finished, certificateValidation....
    return inner_tls_msg
#  def parse_record_layer_type( self):
#    """ returns the reccord layer Content Type
#
#    possible values are 'handshake', 'change_cipher_spec', 'application'
#    """
#    return pytls13.struct_tls13.ContentType.parse( ( self.bytes[ 0 ] ).to_bytes(1, byteorder='big') )

class TLSByteStreamParser:

  def __init__( self, socket ) :
    self.byte_stream = b''
    self.socket = socket

  def parse_record_layer_length( self) : 
    """ returns the recoord layer length from bytes """
#    print( f" - reccord layer_length: {int.from_bytes( self.bytes[ 3 : 5 ] , byteorder='big') }" )
    return int.from_bytes( self.byte_stream[ 3 : 5 ] , byteorder="big") + 5

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


  def parse_single_msg( self )-> dict:
    """ parse the message and return the inner fragment (of the TLS plain_text) and remaining bytes 
    """
    if len( self.byte_stream ) == 0:
      self.byte_stream = self.socket.recv( 4096 )
    while self.parse_record_layer_length() > len( self.byte_stream ) :
      self.byte_stream += self.socket.recv( 4096 )
    record_layer = self.byte_stream[ : self.parse_record_layer_length() ]
#    msg = tls.TLSPlaintext.parse( record_layer )
    tls_msg = TLSMsg()
    tls_msg.from_record_layer_bytes( record_layer )
    self.byte_stream = self.byte_stream[ self.parse_record_layer_length() : ]
#    return msg  
    return tls_msg



class ClientHello( TLSMsg ):

  def __init__( self, conf=None, content={} ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender='client' )
##  def __init__( self, conf=None, content={}, lurk_client=None, tls_handshake=None ):
##    super().__init__( conf=conf, content_type='handshake', content=content, sender='client' )
    self.msg_type = 'client_hello'
    self.ecdhe_key_list = []
    self.record_layer_bytes = b''

    self.c_init_client_hello = False

##    if self.conf[ 'debug' ][ 'test_vector' ] is True:
##      self.init_from_test_vector( )
##    else:
##      self.init()

  def init_from_test_vector( self,  lurk_client=None, tls_handshake=None, ks=None):
#    if test_vector_file is None: 
    self.tls_handshake = tls_handshake 
    self.lurk_client = lurk_client
    self.test_vector =  pytls13.test_vector.TestVector( self.conf[ 'debug' ] )
#    test_vector_file = self.conf[ 'debug' ][ 'test_vector_file' ]
    super().from_test_vector( self.test_vector.file, 'client_client_hello' )
#    tls_handshake = pylurk.tls13.tls_handshake.TlsHandshake( role= 'client')
    self.tls_handshake.msg_list.append( self.content )
    if self.tls_handshake.is_ks_proposed( ) is True :
      client_shares = self.tls_handshake.get_key_share( 'client' )
#      client_shares = self.content[ 'data' ][ 'extensions' ][ key_share_index ][ 'extension_data' ][ 'client_shares' ]
      if self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated' :
        ## 1. build partial ClientHello
        for i in range( len( client_shares ) ) :
          client_shares[ i ][ 'key_exchange' ] = b''
        ks_designation, msg_index, key_share_index = self.tls_handshake.key_share_index( side='client' )
        self.tls_handshake.msg_list[ -1 ][ 'data' ][ 'extensions' ][ key_share_index ][ 'extension_data' ][ 'client_shares' ] = client_shares
#          self.content[ 'data' ][ 'extensions' ][ key_share_index ][ 'extension_data' ][ 'client_shares' ][ i ][ 'key_exchange' ] = b''
        self.content = self.tls_handshake.msg_list[ -1 ]
        ## 2. Complete ClientHello with response from the CS
        lurk_resp = lurk_client.resp( 'c_init_client_hello', handshake=[ self.content ] )
        self.c_init_client_hello_update( lurk_resp  )
      elif self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'e_generated' :
        for ks_entry in client_shares :
          ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
          ecdhe_key.group = ks_entry[ 'group' ]
          key =f"client_{ecdhe_key.group}_ecdhe_private"
          ecdhe_key.generate_from_pem( self.test_vector.read_bin( key ) )
          self.ecdhe_key_list.append( ecdhe_key )
        self.tls_handshake.msg_list[ -1 ] = self.content
           
        
  def init( self, lurk_client=None, tls_handshake=None, ks=None,\
            engine_psk_db=None ):
    self.lurk_client = lurk_client
    self.tls_handshake = tls_handshake 
    self.content = {\
      'msg_type': self.msg_type, \
      'data' : {\
        'legacy_version' : b'\x03\x03',
        'random' : secrets.token_bytes( 32 ),
        'legacy_session_id' : secrets.token_bytes( 32 ),
        'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
        'legacy_compression_methods' : b'\x00',
        'extensions' : [ ] } }
    ext_list = [ ExtClientProtocolVersions() ]
  
    
    if self.conf[ 'ecdhe_authentication' ] is True: 
      sig_algo = self.conf[ 'signature_algorithms' ] 
      ext_list.append( ExtClientSignatureAlgorithms( sig_algo ) )
      ext_list.append( ExtSupportedGroups( self.conf[ 'supported_ecdhe_groups' ] ) )
      key_share = ExtKeyShare( self.conf )
      self.ecdhe_key_list = key_share.ecdhe_key_list
      print( f"self.ecdhe_key_list initialized {self.ecdhe_key_list}" )
      ext_list.append( key_share )
    if self.conf[ 'post_handshake_authentication' ] is True:
      self.add_ext( ExtPostHandshakeAuthentication() )
    if self.conf[ 'session_resumption' ] is True:
      ## if in a session resumption state
      ## psk (ke_psk)
      ext_list.append( ExtPskKeyExchangeMode( self.conf[ 'ke_modes' ] ) )
    self.add_ext( ext_list )

    self.tls_handshake.msg_list.append( self.content )

    if self.conf[ 'ephemeral_method' ] == 'cs_generated' or\
       engine_psk_db.has_proposed_psk_in_cs( ) is True:
      lurk_resp = lurk_client.resp( 'c_init_client_hello', handshake=[ self.content ] )
      self.c_init_client_hello_update( lurk_resp )


  def to_record_layer_bytes( self, content_type=None, content=None ):
    record_layer = TLSMsg.to_record_layer_bytes( self, content_type=None, content=None )
    self.record_layer_bytes = record_layer
    if self.conf[ 'debug'][ 'test_vector' ] is True:
      tls_msg = TLSMsg()
      tls_msg.from_test_vector( self.conf[ 'debug' ][ 'test_vector_file' ], 'client_client_hello' )
#      test_vector_ch = ClientHello( tls_client_conf=self.conf )  
      if record_layer != tls_msg.record_layer_bytes :
        raise ValueError( f"ClientHello byte mismatch\n"\
       f"sending: {pylurk.utils.bytes_to_str(record_layer)}\n"\
       f" expecting sending: {pylurk.utils.bytes_to_str( tls_msg.record_layer_bytes)}" )
    return TLSMsg.to_record_layer_bytes( self ) 

  def from_record_layer_bytes( self, byte_string ) :  
    TLSMsg.from_record_layer_bytes( self, byte_string )
    if self.content_type != 'handshake' or self.content[ 'msg_type' ] != 'client_hello':
      raise ValueError( f"Expecting ClientHello and got {self.content}" )


  def c_init_client_hello_update( self, lurk_resp  ):
    """ updates self.content according to the c_init_client_hello response """
    self.c_init_client_hello = True
    self.tls_handshake.update_random( pylurk.tls13.lurk_tls13.Freshness( self.lurk_client.freshness ) )
    ## keyshare 
    ephemeral_list = lurk_resp[ 'payload' ][ 'ephemeral_list' ]
    client_shares = [ eph[ 'key' ] for eph in ephemeral_list ]
    self.tls_handshake.update_key_share( client_shares )
    self.content = self.tls_handshake.msg_list[ -1 ]
    ## we can only do it when we know the hash fucntion, that is PSK 
    ## or when cipher suite is selected. 
    ## tls_handshake.transcript_hash( 'e' )

class ExtClientProtocolVersions:

  def __init__( self ):
    self.content = { 'extension_type': 'supported_versions', \
                 'extension_data' : { 'versions' : [ b'\x03\x04'] } }

class ExtClientSignatureAlgorithms:

  def __init__( self, sig_list ) :
    self.content = { 'extension_type': 'signature_algorithms', \
                 'extension_data' : { 'supported_signature_algorithms' : sig_list } }
    

class ExtSupportedGroups:

  def __init__( self, supported_groups ):  
    self.content = {'extension_type': 'supported_groups', \
                'extension_data' : {'named_group_list' : supported_groups } }


class ExtKeyShare:

  def __init__( self, tls_client_conf, test_vector  ):
    self.conf = tls_client_conf
    self.ecdhe_key_list = []
#    self.ecdhe_public_key_list = []
    ## when generated by E, ke_entries are generated
    if self.conf[ 'ephemeral_method' ] == 'e_generated' :
      self.ecdhe_key_list = []
      for group in self.conf[ 'supported_ecdhe_groups' ]:
        ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
        ecdhe_key.group = group
        if test_vector is not None:
          key =f"client_{group}_ecdhe_private"
          if key in self.test_vector.db.keys():
            ecdhe_key.generate_from_pem( test_vector.read_bin( key ) )
          if test_vector.check is True:
            test_vector.check_bin( ecdhe_key.pkcs8(), test_vector.read_bin( key ) ) 
        self.ecdhe_key_list.append( ecdhe_key )
      ke_entry_list = [ k.ks_entry() for k in self.ecdhe_key_list ]

    ## when generated by the CS, the ke_entries are empty
    elif self.conf[ 'ephemeral_method' ] == 'cs_generated' :
      ke_entry_list = []
      for group in self.conf[ 'supported_ecdhe_groups' ]:
        ke_entry_list.append( { 'group': ecdhe_group , 'key_exchange' : b''} )
    else: 
      raise pylurk.lurk.lurk_lurk.ConfigurationError( f"unexpected ephemeral_method {self.conf[ 'ephemeral_method' ]} ")
    self.content = { 'extension_type': 'key_share', \
                     'extension_data' : { 'client_shares' : ke_entry_list } }

class ExtPskKeyExchangeMode:

  def __init__( self, ke_modes ):
    self.content = { 'extension_type': 'psk_key_exchange_modes', \
                 'extension_data' : {'ke_modes' : ke_modes } }

class ExtPostHandshakeAuthentication:

  def __init__( self ):
    self.content = { 'extension_type': 'post_handshake_auth', \
                 'extension_data' : {} }


class ServerHello( ClientHello ):

  def __init__( self, conf=None, content=None ):
#    self.conf = tls_client_conf[ ( 'tls13', 'v1' ) ]
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender='server' )
    self.content_type = 'handshake' 
    self.msg_type = 'server_hello'
    self.c_server_hello = False
#    self.content = None
#    self.msg = {\
#    'msg_type': self.msg_type,
#    'data' : {
#      'legacy_version' : b'\x03\x03',
#      'random' : token_bytes( 32 ),
#      'legacy_session_id_echo' : token_bytes( 32 ),
#      'cipher_suite' :'TLS_AES_128_GCM_SHA256',
#      'legacy_compression_method' : b'\x00',
#      'extensions' : [] } }

  def get_shared_secret( self, client_hello, tls_handshake ):
    server_ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
    server_ecdhe_key.generate_from_ks_entry( tls_handshake.get_key_share( 'server' ) )
    for client_ecdhe_key in client_hello.ecdhe_key_list:
      if client_ecdhe_key.group == server_ecdhe_key.group :
        shared_secret = server_ecdhe_key.shared_secret( client_ecdhe_key )
        break  
    return shared_secret

  def handle_server_hello( self, clt_conf, lurk_client, client_hello, tls_handshake, ks, tls_msg ) :
    self.content = tls_msg.content
    self.record_layer_bytes = tls_msg.record_layer_bytes
    tls_handshake.msg_list.append( self.content )
    self.c_server_hello = False
    ## In some cases, c_server_hello is not necessary to generate the h_s 
    ## and h_c - even after a c_init_client_hello exchange. 
    ## Typically, when ephemeral are generated by E, E may initiates a 
    ## c_init_client_hello exchange because some proposed PSK are hosted 
    ## by the CS. When the TLS server does not pick one of these PSKs, 
    ## E may generates on is own h_s and h_c. This implementation chose 
    ## to still interact with the CS.
    if client_hello.c_init_client_hello is True :
      self.c_server_hello = True
      ks = self.handle_c_server_hello( clt_conf, lurk_client, client_hello, tls_handshake, ks )
    else: ## neither psk nor echde generated by the cs
      ks = self.handle_e_server_hello( clt_conf, client_hello, tls_handshake, ks )
    return ks


  def handle_c_server_hello( self, conf, lurk_client, client_hello, tls_handshake, ks=None ):
    ephemeral_method = conf[ 'tls13' ][ 'ephemeral_method' ]
    ## prepare ephemeral
    ## In some cases, c_server_hello is not necessary to generate the h_s and h_c. This implementation chose
    if tls_handshake.is_ks_agreed is False: 
      eph =  { 'method': 'no_secret', 'key': b'' }
    elif ephemeral_method == 'e_generated' :
      eph = { 'method': 'e_generated', 'key': self.get_shared_secret( client_hello, tls_handshake ) } 
    elif ephemeral_method == 'cs_generated' :
      eph = { 'method': 'cs_generated', 'key': None }
    else: 
      raise ValueError( "unknown 'ephemeral_method': {eph_method}" )
          
    lurk_resp = lurk_client.resp( 'c_server_hello', handshake=[ self.content ], ephemeral=eph )
    ks = pylurk.tls13.lurk_tls13.KeyScheduler( tls_hash=tls_handshake.get_tls_hash() )
    ## update ks with secrets and perform handshake transcript
##    sh.c_server_hello_update( lurk_resp, tls_handshake, ks )
    self.c_server_hello = True
    for secret in lurk_resp[ 'payload' ][ 'secret_list' ] :
      ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]
    tls_handshake.transcript_hash( 'h' )
    return ks  

  def handle_e_server_hello( self,  conf, client_hello, tls_handshake,     ks=None ): 
    ephemeral_method = conf[ 'tls13' ][ 'ephemeral_method' ]
    if tls_handshake.is_ks_agreed is False: 
      shared_secret = None
    elif ephemeral_method == 'e_generated' :
         shared_secret = self.get_shared_secret( client_hello, tls_handshake )
    else: 
      raise ValueError( "unknown / unexpected 'ephemeral_method': {eph_method}" )
    ks = pylurk.tls13.lurk_tls13.KeyScheduler( tls_hash=tls_handshake.get_tls_hash(), shared_secret=shared_secret)
    ks.process( [ 'h_s', 'h_c' ], tls_handshake )
    return ks


  def c_register_tickets_status( self, engine_psk_db ):
    ## to be completed when psk is considered
    selected_psk_in_cs = True
    if self.conf[ 'tls13' ][ 'session_resumption' ] is True:
      if self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated' or \
         selected_psk_in_cs is True:
        self.c_register_tickets = True
    else:
      self.c_register_tickets = False
      

      


class EncryptedExtensions( TLSMsg ):

  def __init__( self ):
    self.content = {\
      'msg_type' : 'encrypted_extensions',
      'data' : { 'extensions' :  [] } }

class CertificateRequest( TLSMsg ):
  def __init__( self ):
    self.content = {
      'msg_type' : 'certificate_request',
      'data' : { 'certificate_request_context' :  b'\x00\x01',
                 'extensions' : [] } }

class Finished( ClientHello ):
  def __init__( self, conf=None, content={}, sender=None ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender=sender )
    self.msg_type ='finished'
#    self.content = {
#      'msg_type' : 'finished',
#      'data' : {'verify_data' : token_bytes( 32 )}}
 
  def check_verify_data( self, tls_handshake, ks ):
#    c_verify_data = tls_handshake.get_verify_data( ks, role='server',\
#                      transcript_mode='finished') 
    ## compute the non sender certificate_verify 
    if self.sender == 'server':
      c_verify_data = tls_handshake.get_verify_data( ks, role='server',\
                      transcript_mode='finished') 
      s_verify_data =  self.content[ 'data' ][ 'verify_data' ]
      pylurk.utils.print_bin( "client computed verify_data", c_verify_data )
      pylurk.utils.print_bin( "server provided verify_data", s_verify_data )
      if c_verify_data != s_verify_data : 
        raise ValueError( "Client unable to validate Finished message" )



class CertificateVerify( TLSMsg ):
  def __init__( self, conf=None, content={}, sender=None ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender=sender )
    self.msg_type ='certificate_verify'
    self.c_client_finished = False

  def handle_c_client_finished( self, lurk_client, ks, handshake_msg_list ) :
    """ generates certificate_verify and updates ks """
     
    if self.conf[ 'tls13' ][ 'session_resumption' ] is False:
      last_exchange = True
    else :
      last_exchange = False

    ## collecting certificates
    cert_list = []
    for m in handshake_msg_list:
      if m[ 'msg_type' ] == 'certificate' :
        handshake_msg_list.remove( m ) 
        cert_list.append( m )
    if len( cert_list ) == 2:
      server_cert = { 'cert_type' : 'uncompressed', 'certificate' : cert_list[ 0 ][ 'data' ] } 
      client_cert = { 'cert_type' : 'uncompressed', 'certificate' : cert_list[ 1 ][ 'data' ] } 
    elif len( cert_list ) == 1:
      server_cert = { 'cert_type' : 'uncompressed', 'certificate' : cert_list[ 0 ][ 'data' ] } 
      client_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
    elif len( cert_list ) == 0:
      server_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
      client_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
      
##    ## if last message is (client) certificate 
##    ## certificate = 
##    ## cert_type = 
##    ## else:  
##    if tls_handshake.is_certificate_request( ) is True:
##      pass
##    else:
##      client_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
##
##    server_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
##    for m in tmp_handshake:
##      if m[ 'msg_type' ] == 'certificate' :
##        tmp_handshake.remove( m ) 
##        server_cert = { 'cert_type' : 'uncompressed', 'certificate' : m[ 'data' ] } 
    lurk_resp = lurk_client.resp( 'c_client_finished', \
                              last_exchange=last_exchange, \
                              handshake=handshake_msg_list, \
                              server_certificate=server_cert, \
                              client_certificate=client_cert, \
                              secret_request=[ 'a_c', 'a_s' ] ) 
    self.c_client_finished = True
    for secret in lurk_resp[ 'payload' ][ 'secret_list' ] : 
      ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]

    try: 
      algorithm = self.conf[ 'cs' ][ ( 'tls13', 'v1' ) ][ 'sig_scheme' ]
    except KeyError:
      algorithm = None
    self.content = {
      'msg_type' : 'certificate_verify',
      'data' : { 'algorithm' : algorithm,
                 'signature' : lurk_resp[ 'payload' ][ 'signature' ]  }}

class Certificate( TLSMsg ):

  def __init__( self, conf=None, content={}, sender=None ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender=sender )
    self.msg_type ='certificate'
    
##  def __init__( self, certificate_entry_list=None, certificate_request_context=b'' ):
##    self.content = {
##      'msg_type' : 'certificate',
##      'data' : { 'certificate_request_context' : certificate_request_context,
##                 'certificate_list' : [ cert_entry, cert_entry, cert_entry ] } }

  def init_from_conf( self,  certificate_request_context=b''):
    if self.conf is not None and self.sender is not None:
      if self.conf[ 'role' ] == self.sender:
        if self.conf[ 'role' ] == 'client' :
          cert_entry_list = self.conf[ 'cs' ][ ( 'tls13', 'v1' ) ][ '_cert_entry_list' ]     
          certificate_request_context = b''
          self.content = {
            'msg_type' : 'certificate',
            'data' : { 'certificate_request_context' : certificate_request_context,
                       'certificate_list' : cert_entry_list  } }
                


class NewSessionTicket( TLSMsg ):


  def __init__( self, conf=None, content={}, sender=None ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender=sender )
    self.msg_type ='new_session_ticket'
    self.c_register_ticket = False

  def handle_register( self, ks, e_psk_db, client_cert_verif ):
    if self.conf[ 'tls13' ][ 'session_resumption' ] is False:
      return None
#    ticket = inner_tls_msg.content[ 'data' ] 
#    ticket = self.content[ 'data' ] 
    if ks.secret[ 'r' ] is not None :
      if client_cert_verif.c_client_finished is True :
        self.handle_c_register_ticket( lurk_client, ks )
    new_session_ticket = self.content[ 'data' ] 
    e_psk_db.add( new_session_ticket=new_session_ticket, ks=ks )
    
   
  def handle_c_register_ticket( self, lurk_client, ks ) :
    """ generates certificate_verify and updates ks """
    new_session_ticket = self.content[ 'data' ] 
    lurk_resp = lurk_client.resp( 'c_register_tickets', \
                                  last_exchange=True, \
                                  ticket_list=[ new_session_ticket ] ) 

class EnginePSKDB:

  def __init__( self ):
    self.db = {}

  def key( self, clt_conf ):
    if clt_conf[ 'server'][ 'fqdn' ] is not None:
      key = clt_conf[ 'server'][ 'fqdn' ]
    else:
      key = ( clt_conf[ 'server'][ 'ip' ], clt_conf[ 'server'][ 'port' ] )
    return key

  def add( self, new_session_ticket, ks=None, ):
    psk = None
    if ks.secret[ 'r' ] is not None:
      psk = ks.compute_psk( ticket[ 'ticket_nonce' ] )
    ticket_info = { 'ticket' : ticket,
                    'psk' : psk,
                    'tls_hash' : ks.get_tls_hash(),
                    'cipher_suite' : ks.cipher_suite }
    if key in new_session_ticket_db.keys():
      new_session_ticket_db[ key ].append( ticket_info )
    else:
      new_session_ticket_db[ key ] = [ ticket_info ]

  def get_psk_list( self, ):
    try:
      return self.db[ self.key( clt_conf ) ] 
    except KeyError:
      return []

  def has_proposed_psk_in_cs( self ):
    """ returns True if at least one psk is only known by the cs """
    psk_list = self.get_psk_list( )
    for psk in psk_list :
      if psk[ 'psk' ] is None:
        return True
    return False
     
  
