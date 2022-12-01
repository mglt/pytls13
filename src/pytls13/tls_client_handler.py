#import sys
#sys.path.insert(0, './../src/')
## import socket 
import secrets 
import pprint
import binascii
import pickle
import json
import time 


from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA384, SHA512

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/')
import pytls13.struct_tls13 as tls
import pytls13.test_vector
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.lurk.lurk_lurk
import pylurk.tls13.struct_tls13 as lurk
#import pylurk.tls13.lurk_tls13
import pylurk.tls13.lurk_tls13 
#import pylurk.conf 
import pylurk.utils
import pylurk.cs 



class TLSMsg:

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
    self.content_type = tls_plain_text[ 'type' ]
    self.legacy_record_version = tls_plain_text[ 'legacy_record_version' ]
    self.content = tls_plain_text[ 'fragment' ]
    self.record_layer_bytes = byte_string

 

  def from_test_vector( self, test_vector_file, key ):
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
    print ( f"  - (struct) : {tls.TLSPlaintext.parse( self.record_layer_bytes )}" )
  
  def add_ext( self, ext_list ) :
    for ext in ext_list:
      self.content[ 'data' ][ 'extensions' ].append( ext.content )

  def encrypt_and_send( self, cipher, socket, sender, test_vector=None):
    """ encrypt and send the provided innet_tls_msg 

    The current tls msg is considered as the inner clear text message
    """
    inner_cipher_text, inner_clear_text, inner_clear_text_struct = cipher.encrypt( self.content, content_type=self.content_type, debug=True )
    tls_msg = TLSMsg( conf=self.conf, \
                      content_type='application_data', \
                      content=inner_cipher_text )
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
    return inner_tls_msg

class TLSByteStreamParser:

  def __init__( self, socket ) :
    self.byte_stream = b''
    self.socket = socket

  def parse_record_layer_length( self) : 
    """ returns the recoord layer length from bytes """

    return int.from_bytes( self.byte_stream[ 3 : 5 ] , byteorder="big") + 5

  def parse_single_msg( self )-> dict:
    """ parse the message and return the inner fragment (of the TLS plain_text) and remaining bytes 
    """
    if len( self.byte_stream ) == 0:
      self.byte_stream = self.socket.recv( 4096 )
    while self.parse_record_layer_length() > len( self.byte_stream ) :
      self.byte_stream += self.socket.recv( 4096 )
    record_layer = self.byte_stream[ : self.parse_record_layer_length() ]
    tls_msg = TLSMsg()
    tls_msg.from_record_layer_bytes( record_layer )
    self.byte_stream = self.byte_stream[ self.parse_record_layer_length() : ]
    return tls_msg



class ClientHello( TLSMsg ):

  def __init__( self, conf=None, content={} ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender='client' )
    self.msg_type = 'client_hello'
    self.ecdhe_key_list = []
    self.record_layer_bytes = b''

    self.c_init_client_hello = False
    self.ks_list = []
    self.ks = None


  def init_from_test_vector( self,  lurk_client=None, tls_handshake=None, ks=None):
    self.tls_handshake = tls_handshake 
    self.lurk_client = lurk_client
    self.test_vector =  pytls13.test_vector.TestVector( self.conf[ 'debug' ] )
    super().from_test_vector( self.test_vector.file, 'client_client_hello' )
    self.tls_handshake.msg_list.append( self.content )
    if self.tls_handshake.is_ks_proposed( ) is True :
      client_shares = self.tls_handshake.get_key_share( 'client' )
      if self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated' :
        ## 1. build partial ClientHello
        for i in range( len( client_shares ) ) :
          client_shares[ i ][ 'key_exchange' ] = b''
        ks_designation, msg_index, key_share_index = self.tls_handshake.key_share_index( side='client' )
        self.tls_handshake.msg_list[ -1 ][ 'data' ][ 'extensions' ][ key_share_index ][ 'extension_data' ][ 'client_shares' ] = client_shares
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
           
  def set_lurk_session_state( self, has_proposed_psk_in_cs ):
    """ determine if a c_init_client_hello is performed 

    The current policy is to trigger a c_init_client_hello only when
    an interaction with the CS is needed. 
    The reason is that we want to limit the interactions with the CS. 
    Other policies may be implemented. 
    
    """

    self.c_init_client_hello = False
    if ( self.tls_handshake.is_psk_proposed() and has_proposed_psk_in_cs is True ) or\
       self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated' :
      self.c_init_client_hello = True
      
  

  def init( self, lurk_client=None, tls_handshake=None, ks=None,\
            engine_ticket_db=None ):
    self.lurk_client = lurk_client
    self.tls_handshake = tls_handshake 
    self.test_vector =  pytls13.test_vector.TestVector( self.conf[ 'debug' ] )
    self.content = {\
      'msg_type': self.msg_type, \
      'data' : {\
        'legacy_version' : b'\x03\x03',
        'random' : secrets.token_bytes( 32 ),
        'legacy_session_id' : secrets.token_bytes( 32 ),
        'cipher_suites' : ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256'],
        'legacy_compression_methods' : b'\x00',
        'extensions' : [ ] } }
    self.ticket_info_list = [] ## ticket_info_list when psk is proposed
    self.c_init_client_hello = None
    ext_list = [ ExtClientProtocolVersions() ]
  

    ## by default ECDHE authentication mode is always enabled. 
##    if self.conf[ 'ecdhe_authentication' ] is True: 
    sig_algo = self.conf[ 'tls13' ][ 'signature_algorithms' ] 
    ext_list.append( ExtClientSignatureAlgorithms( sig_algo ) )
    ext_list.append( ExtSupportedGroups( self.conf[ 'tls13' ][ 'supported_ecdhe_groups' ] ) )
    key_share = ExtKeyShare( self.conf, self.test_vector )
    self.ecdhe_key_list = key_share.ecdhe_key_list
    print( f"self.ecdhe_key_list initialized {self.ecdhe_key_list}" )
    ext_list.append( key_share )
    if self.conf[ 'tls13' ][ 'post_handshake_authentication' ] is True:
      self.add_ext( ExtPostHandshakeAuthentication() )
    ## pre_shared_key extension must be last
    ## tickets considered by the clientHello
    ## ticket_list indicates PSK is considered or not like is_psk_proposed
    has_proposed_psk_in_cs  = False
    psk_metadata_list = []
    if self.conf[ 'tls13' ][ 'session_resumption' ] is True and \
       isinstance(engine_ticket_db, EngineTicketDB ) is True:
       self.ticket_info_list = engine_ticket_db.get_ticket_info_list( self.conf )
       if len( self.ticket_info_list ) != 0: # psk proposed
         ext_list.append( ExtPskKeyExchangeMode( self.conf[ 'tls13' ][ 'ke_modes' ] ) )
         ## The extension is built without any binders
         pre_shared_key_ext = ExtPreSharedKey( self.conf, self.ticket_info_list )
         has_proposed_psk_in_cs = pre_shared_key_ext.has_proposed_psk_in_cs
         psk_metadata_list = pre_shared_key_ext.psk_metadata_list 
         ext_list.append( pre_shared_key_ext )
    self.add_ext( ext_list )

    ## at this stage, the clientHello is appropriately formated for a lurk request.
    ## The clienthello is not reaady to be sent to the TLS server as 
    ##   1) keyshare may be generated by the CS and 
    ##   2) binders have not yet been generated.
    ## The only case the clienthello is complete is when PSK is not proposed 
    ## AND ECDHE is generated by the engine e_generated. 
    ## 
    ## Once thing to consider is that binders can only be generated when the 
    ## client is complete - except for the binders. So it needs to be performed
    ## at the very last moment and after the keyshare extension is generated.  
    self.tls_handshake.msg_list.append( self.content )

    ## determine state variables like self.c_init_client_hello
    self.set_lurk_session_state( has_proposed_psk_in_cs )

    # proceed to lurk exchange
    if self.c_init_client_hello is True:
      if has_proposed_psk_in_cs is True :
        secret_request = [ 'e_s', 'e_x' ]
      else:
        secret_request = []
      lurk_resp = lurk_client.resp( 'c_init_client_hello', handshake=[ self.content ], psk_metadata_list=psk_metadata_list, secret_request=secret_request )
      self.tls_handshake.update_random( pylurk.tls13.lurk_tls13.Freshness( self.lurk_client.freshness ) )

      ## keyshare 
      if self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated':
        ephemeral_list = lurk_resp[ 'payload' ][ 'ephemeral_list' ]
        client_shares = [ eph[ 'key' ] for eph in ephemeral_list ]
        self.tls_handshake.update_key_share( client_shares )

    # update_binders
    ## binder keys are generated only when not already provided by the CS.
    if self.tls_handshake.is_psk_proposed()  is True :
      if self.c_init_client_hello is True:
        binder_key_list = lurk_resp[ 'payload' ][ 'binder_key_list' ]
        binder_finished_key_list = [ ]
        for binder_key in binder_key_list:
          index = binder_key_list.index( binder_key )
          ticket_info = self.ticket_info_list[ index ] 
          tls_hash = ticket_info[ 'tls_hash' ]
          try:
            psk = ticket_info[ 'psk_bytes'] 
          except KeyError:
            psk = None
          if ticket_info[ 'psk_type' ] == 'external' :
            is_ext = True
          else:
            is_ext = False
          ## Note that unless psk is provided ks cannot be used to generate secrets
          ## ks is used to store the secrets, compute the binder_finished key
          ks = pylurk.tls13.key_scheduler.KeyScheduler( tls_hash, psk=psk, is_ext=is_ext )
          ks.secrets[ 'b' ] = binder_key[ 'secret_data' ]
          binder_finished_key_list.append( ks.finished_key( role='binder' ) )
          self.ks_list.append( ks )
          if self.test_vector is not None:
            self.test_vector.handle_bin( f"binder_key ({index})", ks.secrets[ 'b' ] )
            self.test_vector.handle_bin( f"binder_finished_key ({index})", ks.finished_key(  role='binder') )
        ## updating ks[0] (ks_list is non empty as psk has been proposed
        for s in lurk_resp[ 'payload' ][ 'secret_list' ]:
          self.ks_list[ 0 ].secrets[ s[ 'secret_type' ] ] = s[ 'secret_data' ] 
           
#        self.tls_handshake.update_binders( self.ticket_info_list, binder_finished_key_list )
    ### DEBUG BEGIN
        print("E view on data computed by CS" ) 
        pylurk.utils.print_bin( "psk", self.ks_list[ 0 ].psk ) 
#        print( f" ks : : {ks.secrets}" ) 
        for secret_type in ks.secrets.keys():
          v = self.ks_list[ 0 ].secrets[ secret_type ]  
          if v not in [ b'', None ]:
            pylurk.utils.print_bin( f"ks {secret_type}", v ) 
#        pylurk.utils.print_bin( "ks binder_key [ cs ]", self.ks_list[ 0 ].secrets[ 'b' ] ) 
#        pylurk.utils.print_bin( "ks e_s [ cs ]", self.ks_list[ 0 ].secrets[ 'e_s' ] ) 
#        pylurk.utils.print_bin( "ks e_x [ cs ]", self.ks_list[ 0 ].secrets[ 'e_x' ] ) 
        print("E view on data computed by E (similated)" ) 
        # in our case ecdhe is generated by E and E knows the PSK, so it shas 
        # the necessary information to generate the Partial ClientHello, 
        # the binders, the early secrets and all other secrets. 
        self.e_ks_list = self.tls_handshake.binder_scheduler_key_list( self.ticket_info_list ) 
        pylurk.utils.print_bin( "psk", self.e_ks_list[ 0 ].psk )
        e_binder_finished_key_list = [ ks.finished_key( role='binder' ) for ks in self.e_ks_list ]
        pylurk.utils.print_bin( "ks binder_key]", self.e_ks_list[ 0 ].secrets[ 'b' ] )
        print( "Check binder_finished_key and psk" )
    ### DEBUG END


         
      else: #updating binders without interaction with the cs
        ## Note that in this case ticket_info contains the psk and ks can
        ## be used to generate all secrets
        self.ks_list = self.tls_handshake.binder_scheduler_key_list( self.ticket_info_list ) 
        binder_finished_key_list = [ ks.finished_key( role='binder' ) for ks in self.ks_list ]
      self.tls_handshake.update_binders( self.ticket_info_list, binder_finished_key_list )
      self.ks = self.ks_list[ 0 ]
       
      
  def to_record_layer_bytes( self, content_type=None, content=None ):
    record_layer = TLSMsg.to_record_layer_bytes( self, content_type=None, content=None )
    self.record_layer_bytes = record_layer
    if self.conf[ 'debug'][ 'test_vector' ] is True:
      tls_msg = TLSMsg()
      key = self.descriptor( sender=self.sender )
      tls_msg.from_test_vector( self.conf[ 'debug' ][ 'test_vector_file' ], key )
      if record_layer != tls_msg.record_layer_bytes :
        raise ValueError( f"TLS {content_type} message byte mismatch\n"\
       f"sending: {pylurk.utils.bytes_to_str(record_layer)}\n"\
       f" expecting sending: {pylurk.utils.bytes_to_str( tls_msg.record_layer_bytes)}" )
    return TLSMsg.to_record_layer_bytes( self ) 

  def from_record_layer_bytes( self, byte_string ) :  
    TLSMsg.from_record_layer_bytes( self, byte_string )
    if self.content_type != 'handshake' or self.content[ 'msg_type' ] != 'client_hello':
      raise ValueError( f"Expecting ClientHello and got {self.content}" )

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
    ## when generated by E, ke_entries are generated
    if self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'e_generated' :
      for group in self.conf[ 'tls13' ][ 'supported_ecdhe_groups' ]:
        ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
        ecdhe_key.group = group
        if test_vector is not None:
          key =f"client_{group}_ecdhe_private"
          if key in test_vector.db.keys():
            ecdhe_key.generate_from_pem( test_vector.read_bin( key ) )
          if test_vector.check is True:
            test_vector.check_bin( ecdhe_key.pkcs8(), test_vector.read_bin( key ) ) 
        self.ecdhe_key_list.append( ecdhe_key )
      ke_entry_list = [ k.ks_entry() for k in self.ecdhe_key_list ]

    ## when generated by the CS, the ke_entries are empty
    elif self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated' :
      ke_entry_list = []
      for group in self.conf[ 'tls13' ][ 'supported_ecdhe_groups' ]:
        ke_entry_list.append( { 'group': group , 'key_exchange' : b''} )
    else: 
      raise pylurk.lurk.lurk_lurk.ConfigurationError( f"unexpected ephemeral_method {self.conf[ 'ephemeral_method' ]} ")
    self.content = { 'extension_type': 'key_share', \
                     'extension_data' : { 'client_shares' : ke_entry_list } }

class ExtPreSharedKey:

  def __init__( self, conf, ticket_info_list ):
    """ generates the pre_shared_key extention """
    self.psk_metadata_list = []
    psk_identity_list = []
    for ticket_info in ticket_info_list:
      psk_identity_list.append( {\
        'identity' :ticket_info[ 'new_session_ticket' ][ 'ticket' ], 
        'obfuscated_ticket_age' : ticket_info[ 'obfuscated_ticket_age' ] } )
      if ticket_info[ 'psk_bytes' ] is not None:
        psk_metadata = { \
          'identity_index' : ticket_info_list.index( ticket_info ), 
          'tls_hash' : ticket_info[ 'tls_hash' ].__class__.__name__.lower(), 
          'psk_type' : ticket_info[ 'psk_type' ],
          'psk_bytes' : ticket_info[ 'psk_bytes' ] }
        self.psk_metadata_list.append( psk_metadata )
    self.content = { 'extension_type': 'pre_shared_key', \
                     'extension_data' : { 'identities' : psk_identity_list } }
    if len( self.psk_metadata_list ) == len( ticket_info_list ):
      self.has_proposed_psk_in_cs = False
    else: 
      self.has_proposed_psk_in_cs = True
       



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
    self.tls_mode = None
    self.c_server_hello = None
    self.c_register_tickets = None
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



  def set_tls_mode( self, tls_handshake ) -> str:
    """ returns the tls_mode 'ecdhe', 'psk_ecdhe' or 'psk' """
   
    if tls_handshake.is_psk_agreed():
      psk_kex_modes = tls_handshake.client_hello_ext_data( 'psk_key_exchange_modes' )[ 'ke_modes' ]
      if tls_handshake.is_ks_agreed() :
        self.tls_mode = 'psk_ecdhe' 
        if 'psk_dhe_ke' not in psk_kex_modes:
          raise ValueError( f"TLS mode error: ServerHello is set to "\
                            f"{self.tls_mode} while ClientHello proposes"\
                            f"{psk_kex_modes}")
      else: 
        self.tls_mode = 'psk' 
        if 'psk' not in psk_kex_modes:
          raise ValueError( f"TLS mode error: ServerHello is set to "\
                            f"{self.tls_mode} while ClientHello proposes"\
                            f"{psk_kex_modes}")
    else:
      self.tls_mode = 'ecdhe'
      if tls_handshake.is_ks_agreed() is False :
        raise ValueError( f"TLS mode error: ServerHello is set to "\
                          f"{self.tls_mode} while no key share is agreed." )

  def set_lurk_session_state( self, client_hello, tls_handshake ):
    """  set the c_server_hello and c_register_tickets staus

   Determine if the TLS client needs to perform a c_server_hello 
   or a c_register_tickets LURK exchange.

    There different ways to implement it. Our implementation considers
    these exchanges are only performed when it actually make sense to 
    benefit from the additional security provided by the CS. .

    There is a need to interact with the CS if: 
      - 1) the exchange includes ECDHE either with the TLS ECDHE mode or 
          TLS PSK-ECDHE mode and the mode is 'cs_generated'
      - 2) the TLS mode is psk based and the PSK is in the CS
      - 3) the client will be authenticated. However, we cannot determine
          it as long as we have not received a certificate request.  
    In any of these case, the key scheduler cannot be used to generate 
    secrets and these MUST be generated by the CS. 
    In any other case, there is no need to interact with the CS.
   
    It could happen that a c_init_client_hello has initiated a session 
    with the CS, and no more messages are sent. 
    For example, the client may request ECDHE key share being generated
    by the CS while the CS does not pick that mode. Another case may 
    consider the user using a set of PSKs that are shared between the CS
    and the Engine. The c_init_client_hello is necessary to generate the 
    binders. However, if the TLS server choses a PSK that is known to the
    engine and if the Engine has generated the ECDHE key_share - or there
    are not ECDHE key_share involved, then the Engine may build its own 
    key scheduler. 
    Such example are a bit of a corner case and the CS MUST be able to 
    remove session after some time out. 
   
    In the worst case, c_init_client_hello may be sent, c_server_hello is 
    not needed but later on the server request an authentication of the 
    client in which case a c_finished client is needed. Such scenario 
    corresponds to the branch (a) in the LURK specification.  
    This branch is optional and an implementation may chose to consider 
    the ability to skip the c_server_hello or not. 
    In the latter case, a c_init_client_hello will always be followed 
    by a c_server_hello. 
    This would result in the simplified version of this function:
    ## self.c_server_hello = client_hello.c_init_client_hello 
    ## self.c_register_tickets = self.c_server_hello

    The current version of the function considers that a c_server_hello
    exchange may or may not be performed - considering the various 
    corner cases.
    When a c_server_hello exchange is expected, the varaible 
    self.c_server_hello is set to True.
    Note that self.c_server_hello is set to False when there is a 
    c_init_client_hello exchange bu no c_server_hello exchange as well 
    as when no c_init_client_hello has been initated. 
        
    Similarly, when a c_register_ticket exchange is expected upon receiving a
    NewSession Ticket, this function sets the self.c_register_tickets to True.
    Note that tickets are registered only when these can only be handled by 
    the Engine E and necessarily be handled by the CS.  
    """

    if self.tls_mode is None:
      self.set_tls_mode( tls_handshake )
    eph_method = self.conf[ 'tls13' ][ 'ephemeral_method' ] 

    ## determine if the selected_psk is in the CS (True)
    ## selected_psk_in_cs indicates no PSK or PSK not in CS that is in E
    selected_psk_in_cs = False
    if self.tls_mode in [ 'psk', 'psk_ecdhe' ] :
      selected_psk = tls_handshake.server_hello_ext_data( 'pre_shared_key' )
      if client_hello.ticket_info_list[ selected_psk ][ 'psk_bytes' ] is None:
        selected_psk_in_cs = True
       
    if ( self.tls_mode in [ 'ecdhe', 'psk_ecdhe' ] and \
         eph_method == 'cs_generated' ) or\
       selected_psk_in_cs is True:
      self.c_server_hello = True
      self.c_register_tickets = True
    else:   
      self.c_server_hello = False
      self.c_register_tickets = False
    ## of course if session resumption is not enabled
    ## this overwrittes the c_register_tickets
    if self.conf[ 'tls13' ][ 'session_resumption' ] is False:
      self.c_register_tickets = False

  def handle_server_hello( self, lurk_client, client_hello, tls_handshake, ks, tls_msg ) :
    self.content = tls_msg.content
    self.record_layer_bytes = tls_msg.record_layer_bytes
    tls_handshake.msg_list.append( self.content )
    
    ## define tls_mode
    self.set_tls_mode( tls_handshake )
    ## set state variables (c_server_hello, c_register_tickets)
    self.set_lurk_session_state( client_hello, tls_handshake )

    ## initialize ks
    if self.tls_mode in [ 'psk_ecdhe', 'psk' ]:
      selected_psk = tls_handshake.server_hello_ext_data( 'pre_shared_key' )
      ks = client_hello.ks_list[ selected_psk ]
    else: 
      ks = pylurk.tls13.lurk_tls13.KeyScheduler( tls_hash=tls_handshake.get_tls_hash() , test_vector=tls_handshake.test_vector)

    if self.c_server_hello is True:
      self.handle_c_server_hello( lurk_client, tls_handshake, ks, client_hello )
    else:
      ephemeral_method = self.conf[ 'tls13' ][ 'ephemeral_method' ]
      if self.tls_mode =='psk' : 
        shared_secret = None
      elif ephemeral_method == 'e_generated' :
           shared_secret = self.get_shared_secret( client_hello, tls_handshake )
      else: 
        raise ValueError( "unknown / unexpected 'ephemeral_method': {eph_method}" )
      ks.shared_secret = shared_secret
      ks.process( [ 'h_s', 'h_c' ], tls_handshake )
    return ks


  def handle_c_server_hello( self, lurk_client, tls_handshake, ks, client_hello ):
    """ performs the c_server_hello and update tls_handshake and ks """

    ephemeral_method = self.conf[ 'tls13' ][ 'ephemeral_method' ]
    ## prepare ephemeral
    ## In some cases, c_server_hello is not necessary to generate 
    ## the h_s and h_c. This implementation chose
    if self.tls_mode == 'psk' : 
      eph =  { 'method': 'no_secret', 'key': b'' }
    elif self.tls_mode in [ 'ecdhe', 'psk_ecdhe' ]:
      if ephemeral_method == 'e_generated' :
        print(f" ch shared_secret: {self.get_shared_secret( client_hello, tls_handshake )}")
        server_ecdhe_key = pylurk.tls13.crypto_suites.ECDHEKey( )
        server_ecdhe_key.generate_from_ks_entry( tls_handshake.get_key_share( 'server' ) )
        eph = { 'method': 'e_generated', 
                'key': { 'group' : server_ecdhe_key.group, 
                         'shared_secret' : self.get_shared_secret( client_hello,\
                                           tls_handshake ) }
              }
      elif ephemeral_method == 'cs_generated' :
        eph = { 'method': 'cs_generated', 'key': None }
      else: 
        raise ValueError( "unexpected 'ephemeral_method': {eph_method}" )
    else: 
      raise ValueError( f"unexpected tls_mode: {self.tls_mode}" )
          
    lurk_resp = lurk_client.resp( 'c_server_hello', handshake=[ self.content ], ephemeral=eph )
    for secret in lurk_resp[ 'payload' ][ 'secret_list' ] :
      ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]
    ## mostly to ensure transcript_hash is synced
    tls_handshake.transcript_hash( 'h' )


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
    self.c_init_client_finished = False
    self.test_vector =  pytls13.test_vector.TestVector( self.conf[ 'debug' ] )

  def check_signature( self, tls_handshake, public_key ):
    signed_content = tls_handshake.certificate_verify_content( role=self.sender )
    signature = self.content[ 'data' ][ 'signature' ]
    algorithm = self.content[ 'data' ][ 'algorithm' ]
#    if self.test_vector != None:
#      self.test_vector.handle_bin( 'signature', signature ) 
#      self.test_vector.handle_bin( 'algorithm', algorithm ) 
#    return True
    if algorithm in [ 'rsa_pss_rsae_sha256', 'rsa_pss_pss_sha256' ]:
      public_key.verify(
        signature,
        signed_content,
        padding.PSS(
          mgf=padding.MGF1( SHA256() ),
#          mgf=padding.MGF1( tls_handshake.get_tls_hash() ),
#          salt_length=padding.PSS.MAX_LENGTH ),
          salt_length=padding.PSS.DIGEST_LENGTH ),
          SHA256() )
#          tls_handshake.get_tls_hash()  )
    elif algorithm == 'rsa_pkcs1_sha256': 
      public_key.verify(
        signature,
        signed_content,
        padding.PKCS1v15 )
    elif algorithm in [ 'ed25519', 'ed448' ]:
      public_key.verify( signature, data ) 
    

  def get_last_exchange( self, c_register_tickets, is_post_hand_auth_proposed ) -> bool:
    """ returns the last_message tag 

    last_exchange is set to False in the following cases:  
    1) post handshake: post_hand_auth_proposed  (post handshake)
    2) session resumption: method is 'cs_generated' or PSK in use in CS
       this corresponds to the value c_register_tickets
    """
    return c_register_tickets or is_post_hand_auth_proposed


  def get_cert_from_handshake_msg_list( self, handshake_msg_list ):
    """parse handshake message list and extract certificates """

    ## collecting certificates
    cert_list = []
    for m in handshake_msg_list:
##      print( f" --- m: {m}" )
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
    return handshake_msg_list, server_cert, client_cert


  def init_content_from_lurk_resp( self, lurk_resp ):
    try: 
      algorithm = self.conf[ 'cs' ][ ( 'tls13', 'v1' ) ][ 'sig_scheme' ][ 0 ]
    except KeyError:
      algorithm = None
    self.content = {
      'msg_type' : 'certificate_verify',
      'data' : { 'algorithm' : algorithm,
                 'signature' : lurk_resp[ 'payload' ][ 'signature' ]  }}


#  def handle_c_client_finished( self, lurk_client, ks, handshake_msg_list ) :
  def handle_c_client_finished( self, lurk_client, \
    ks, handshake_msg_list, c_register_tickets ) :
    """ generates certificate_verify and updates ks """

#    tmp_tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )
#    tmp_tls_handshake.msg_list = handshake_msg_list
     
    last_exchange = self.get_last_exchange( c_register_tickets, \
      self.conf[ 'tls13' ][ 'post_handshake_authentication'] )
    handshake_msg_list, server_cert, client_cert = self.get_cert_from_handshake_msg_list( handshake_msg_list )

      
    lurk_resp = lurk_client.resp( 'c_client_finished', \
                              last_exchange=last_exchange, \
                              handshake=handshake_msg_list, \
                              server_certificate=server_cert, \
                              client_certificate=client_cert, \
                              secret_request=[ 'a_c', 'a_s', 'r' ] ) 
    self.c_client_finished = True
    for secret in lurk_resp[ 'payload' ][ 'secret_list' ] : 
      ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]

    self.init_content_from_lurk_resp( lurk_resp )



  def handle_c_init_client_finished( self, lurk_client, ks, handshake_msg_list,\
                                c_register_tickets ) :
    """ generates certificate_verify and updates ks """

    ## think replacing handshake_msg_list by , tls_handshake
    
    ## sh = ServerHello( tmp_tls_handshake.msg_list [ 1 ] ]
    last_exchange = self.get_last_exchange( c_register_tickets, \
      self.conf[ 'tls13' ][ 'post_handshake_authentication'] )
    
    if self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'e_generated':
      tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' ) 
      tls_handshake.msg_list = handshake_msg_list
      server_key_share = tls_handshake.get_key_share( 'server' ) 
      eph = { 'method': 'e_generated', 
              'key': { 'group' : server_key_share[ 'group' ], 
                       'shared_secret' : ks.shared_secret }
            }
    
    elif self.conf[ 'tls13' ][ 'ephemeral_method' ] == 'no_secret':
      eph = { 'method': 'no_secret', 
              'key': b'' }
    
    handshake_msg_list, server_cert, client_cert = \
      self.get_cert_from_handshake_msg_list( handshake_msg_list )
   
    print( f"--- handshake_msg_list: {handshake_msg_list}" )
    print( f"--- server_cert: {server_cert}" ) 
    print( f"--- client_cert: {client_cert}" ) 
    lurk_resp = lurk_client.resp( 'c_init_client_finished', \
                              last_exchange=last_exchange, \
                              handshake=handshake_msg_list, \
                              server_certificate=server_cert, \
                              client_certificate=client_cert, \
                              ephemeral= eph, 
                              psk=ks.psk) 
    self.c_init_client_finished = True
    self.init_content_from_lurk_resp( lurk_resp )



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
                


  def get_public_key( self ):

    ## we shoudl reuse load_public_bytes from conf.
    print( f"--- content: {self.content[ 'data' ][ 'certificate_list' ][ 0 ]}" )
    public_bytes = self.content[ 'data' ][ 'certificate_list' ][ 0 ][ 'cert' ]
    try:
      cert = x509.load_der_x509_certificate( public_bytes )
      public_key = cert.public_key()
    except:
      cert = x509.load_pem_x509_certificate( public_bytes )
      public_key = cert.public_key()
    return public_key

class NewSessionTicket( TLSMsg ):


  def __init__( self, conf=None, content={}, sender=None ):
    TLSMsg.__init__( self, conf=conf, content_type='handshake', content=content, sender=sender )
    self.msg_type ='new_session_ticket'
    self.c_register_ticket = False

  def handle_c_register_ticket( self, lurk_client ) :
    """ generates certificate_verify and updates ks """
    new_session_ticket = self.content[ 'data' ] 
    lurk_resp = lurk_client.resp( 'c_register_tickets', \
                                  last_exchange=True, \
                                  ticket_list=[ new_session_ticket ] ) 

class EngineTicketDB( pylurk.tls13.lurk_tls13.TicketDB ) :
  """ Storing tickets received by the server

  Unlike TicketDB, the engine may not be aware of the psk.
  In addition, the Engine selects tickets that apply to a given TLS server
  while the CS requires ticket information associated to a specific ticket. 
  Such differences requires different structurre of teh database. 
  """
  def __init__( self ):
    self.db = {}

  def key( self, clt_conf ):
    if clt_conf[ 'server'][ 'fqdn' ] is not None:
      key = clt_conf[ 'server'][ 'fqdn' ]
    else:
      ip = clt_conf[ 'server'][ 'ip' ]
      port = clt_conf[ 'server'][ 'port' ]
      if ip is not None and port is not None:
        key = ( ip, port )
      else:
        key = None
    return key

  def register( self, conf, new_session_ticket, ks, tls_handshake ) :
   
    psk = None
    if ks.secrets[ 'r' ] is not None:
      psk = ks.compute_psk( new_session_ticket[ 'ticket_nonce' ] )
    ticket_info = { 'new_session_ticket' : new_session_ticket,
                    'psk_bytes' : psk,
                    'tls_hash' : tls_handshake.get_tls_hash(),
                    'psk_type' : 'resumption',
                    'cipher_suite' : tls_handshake.cipher_suite, 
                    'registration_time' : time.time() }
    key = self.key( conf ) 
    if key in self.db.keys():
      self.db[ key ].append( ticket_info )
    else:
      self.db[ key ] = [ ticket_info ]

  def get_ticket_info_list( self, clt_conf ):
    ticket_list = []
    k = self.key( clt_conf )
    if k is None:
      pass
    elif k in self.db.keys(): 
      for t in self.db[ k ]: 
        ticket_list.append( self.update_ticket_info( t ) )
    return ticket_list

