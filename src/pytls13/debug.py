import json
import os.path
import pprint
import pylurk.debug
import pytls13.tls_client_handler

class Debug( pylurk.debug.Debug ):

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
    return tls_msg.descriptor( sender=sender)

  def check_tls_clear_text_msg( self, tls_msg, sender ):
    self.check_bin( tls_msg.descriptor( sender=sender), tls_msg.to_record_layer_bytes() )

  def check_tls_cipher_text_msg( self, tls_msg, descriptor, sender ):
    self.check_bin( f"{sender}_{descriptor}", tls_msg.to_record_layer_bytes() )

  def record_tls_clear_text_msg( self, tls_msg, sender ):
    descriptor  =  tls_msg.descriptor( sender=sender)
    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )

  def record_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )
    ## we do not record the struct as it contains bytes which cannot be 
    ## stored into a JSON object
    self.record_val( f"{descriptor}_struct", tls_msg.to_record_layer_struct() ) 
    ## we need to addres this in record_value
    self.record_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    self.record_bin( f"{descriptor}_inner_clear_text", inner_clear_text )

  def record_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender): 
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
    ## we do not record the struct as it contains bytes which cannot be 
    ## stored into a JSON object
    ## self.record_val( f"{descriptor}_inner_clear_text_struct", inner_clear_text_struct )  
    self.record_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
    self.record_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )

  def trace_tls_clear_text_msg( self, tls_msg, sender ):
    descriptor = tls_msg.descriptor( sender=sender )
    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )
    pprint.pprint( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}", width=80, sort_dicts=False )

  def trace_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
#    key = f"{sender}_{inner_tls_msg.content[ 'msg_type' ]}"
    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )
    pprint.pprint( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}", width=80, sort_dicts=False )  
    self.trace_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    self.trace_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
    pprint.pprint( f"{descriptor}_inner_clear_text_struct: {inner_clear_text_struct}", width=80, sort_dicts=False )

  def trace_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender): 
    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
    pprint.pprint( f"{descriptor}_inner_clear_text_struct: {inner_clear_text_struct}", width=80, sort_dicts=False )  
    self.trace_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
    self.trace_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
    pprint.pprint( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}", width=80, sort_dicts=False )  
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
      self.check_tls_cipher_text_msg( tls_msg, descriptor, sender )
    if self.record is True:
      self.record_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender)
    if self.trace is True:
      self.trace_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender)
    
  def handle_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender):
    if self.check is True: 
      descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
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
