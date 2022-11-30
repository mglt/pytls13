import json
import os.path
import pylurk.utils
import pytls13.tls_client_handler

class TestVector( pylurk.utils.TestVector ):

#  def __init__( self, debug_conf ):
#    
#    self.file = debug_conf[ 'test_vector_file' ]
#    self.mode = debug_conf[ 'test_vector_mode' ] ## check, write
#
#    if os.path.isfile( self.file ): 
#      with open( self.file, 'rt', encoding='utf8' ) as f:
#        self.db = json.load( f )
#    else: 
#      self.db = {}
#
#    if debug_conf[ 'test_vector' ] is True:
#      if debug_conf[ 'test_vector_mode' ] == 'check':
#        self.check = True
#      else: 
#        self.check = False
#    else: 
#      self.check = False
#    
#    if debug_conf[ 'test_vector' ] is True:
#      if debug_conf[ 'test_vector_mode' ] == 'record':
#        self.record = True
#      else: 
#        self.record = False
#    else:
#      self.record = False   
#    self.trace = debug_conf[ 'trace' ]

  def descriptor_from_struct( self, tls_msg, sender=None ):
    """ extracts the key used to identify the structure 

    The key is typically the msg_type for tls message of content_type 'handshake'
    For tls message wit a different content_type, we use the content_type as a key. 
    'sender' is used to differentiates the client and the server. 
    """
    if isinstance( tls_msg, dict ):
      tmp_tls_msg = pytls13.tls_client_handler.TLSMsg( )
      tmp_tls_msg.from_record_layer_struct( tls_msg )
      tls_msg = tmp_tls_msg
#    if tls_msg.content_type == 'handshake' :
#      descriptor = f"{sender}_{tls_msg.content[ 'msg_type' ]}"
#    else: 
#      descriptor = f"{sender}_{tls_msg.content_type}"
#    
    return tls_msg.descriptor( sender=sender)

##  def check_bin( self, key:str, value:bytes ):
##    """ raises an error when the key, value mismatches those of the test_vector """
##    if key in self.db.keys() :
##      ref_value = pylurk.utils.str_to_bytes( self.db[ key ] )
##      if value != ref_value :
##        raise ValueError( 
##          f"TestVector {key} check fails:\n"\
##          f"{pylurk.utils.bytes_to_human( 'expected', ref_value)}\n"\
##          f"{pylurk.utils.bytes_to_human( 'provided', value)}\n" )

  def check_tls_clear_text_msg( self, tls_msg, sender ):
#    if tls_msg.content_type == 'handshake' :
#      key = f"{sender}_{tls_msg.content[ 'msg_type' ]}"
#    else: 
#      key = f"{sender}_{tls_msg.content_type}"
    self.check_bin( tls_msg.descriptor( sender=sender), tls_msg.to_record_layer_bytes() )

  def check_tls_cipher_text_msg( self, tls_msg, descriptor, sender ):
##    key = f"{sender}_{key}"
    self.check_bin( f"{sender}_{descriptor}", tls_msg.to_record_layer_bytes() )

##  def record_val( self, key:str, value ):
##    self.db[ key ] = value


##  def record_bin( self, key:str, value:bytes ):
##    self.db[ key ] = pylurk.utils.bytes_to_str( value )

  def record_tls_clear_text_msg( self, tls_msg, sender ):
#    if tls_msg.content_type == 'handshake' :
#      key = f"{sender}_{tls_msg.content[ 'msg_type' ]}"
#    else: 
#      key = f"{sender}_{tls_msg.content_type}"
    descriptor  =  tls_msg.descriptor( sender=sender)
#    print( f" --> {type( tls_msg.to_record_layer_bytes() )} - {tls_msg.to_record_layer_bytes()}")
    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )
#    print( f" --> {type( tls_msg.to_record_layer_struct() )} - {tls_msg.to_record_layer_struct()}")
###    self.record_val( f"{descriptor}_struct", tls_msg.to_record_layer_struct() )  

  def record_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
#    print(inner_clear_text_struct) 
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
#    if tls_msg.content_type == 'handshake' :
#      key = f"{sender}_{inner_clear_text_struct[ 'content'][ 'msg_type' ]}"
#    else: 
#      key = f"{sender}_{tls_msg.content_type}"
    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )
    self.record_val( f"{descriptor}_struct", tls_msg.to_record_layer_struct() )  
    self.record_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    self.record_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
###    self.record_val( f"{descriptor}_inner_clear_text_struct", inner_clear_text_struct )

  def record_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender): 
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
#    key = f"{sender}_{inner_clear_text_struct[ 'content'][ 'msg_type' ]}"

    self.record_val( f"{descriptor}_inner_clear_text_struct", inner_clear_text_struct )  
    self.record_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
    self.record_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
###    self.record_val( f"{descriptor}_struct", tls_msg.to_record_layer_struct() )  
    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )

##  def trace_bin( self, key:str, value:bytes ):
##    print( pylurk.utils.bytes_to_human( key, value ) )

  def trace_tls_clear_text_msg( self, tls_msg, sender ):
#    if tls_msg.content_type == 'handshake' :
#      key = f"{sender}_{tls_msg.content[ 'msg_type' ]}"
#    else: 
#      key = f"{sender}_{tls_msg.content_type}"
    descriptor = tls_msg.descriptor( sender=sender )
    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )
    print( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}" )

  def trace_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
#    key = f"{sender}_{inner_tls_msg.content[ 'msg_type' ]}"
    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )
    print( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}" )  
    self.trace_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    self.trace_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
    print( f"{descriptor}_inner_clear_text_struct: {inner_clear_text_struct}" )

  def trace_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender): 
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
    #key = f"{sender}_{inner_clear_text_struct[ 'content'][ 'msg_type' ]}"

    print( f"{descriptor}_inner_clear_text_struct: {inner_clear_text_struct}" )  
    self.trace_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
    self.trace_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    print( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}" )  
    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )

  def handle_bin( self, key:str, value:bytes ):
    if self.check is True:
      self.check_bin( key, value )
    if self.record is True:
      self.record_bin( key, value )
    if self.trace is True:
      self.trace_bin( key, value )

  def handle_tls_clear_text_msg( self, tls_msg, sender ):
    if self.check is True:
      self.check_tls_clear_text_msg( tls_msg, sender )
    if self.record is True:
      self.record_tls_clear_text_msg( tls_msg, sender )
    if self.trace is True:
      self.trace_tls_clear_text_msg( tls_msg, sender )

  def handle_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
    if self.check is True:
      descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
#      key = f"{sender}_{inner_tls_msg.content[ 'msg_type' ]}"
      self.check_tls_cipher_text_msg( tls_msg, descriptor, sender )
    if self.record is True:
      self.record_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender)
    if self.trace is True:
      self.trace_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender)
    
  def handle_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender):
    if self.check is True: 
#      print( inner_clear_text_struct )
      descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
# key = f"{sender}_{inner_clear_text_struct[ 'content'][ 'msg_type' ]}"
      self.check_tls_cipher_text_msg( tls_msg, descriptor, sender )
    if self.record is True:
      self.record_tls_cipher_text_msg_enc( tls_msg, inner_clear_text, inner_clear_text_struct, sender) 
    if self.trace is True:
      self.trace_tls_cipher_text_msg_enc( tls_msg, inner_clear_text, inner_clear_text_struct, sender) 


  def dump( self ):
    with open( self.file, 'rw', encoding='utf8' ) as f:
      json.dump( self.db, f, indent=2 )

  
  def handle( key, value ):
    if self.mode == 'check':
      self.check( key, value )
    elif self.mode == 'write':
      self.add_value( key, value )
    else: 
      raise ValueError( f"Unknown mode {self.mode}" )
