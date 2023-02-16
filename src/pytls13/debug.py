import json
import os.path
import pprint
import typing 
import pylurk.debug
import pytls13.tls_client_handler
import pytls13.struct_tls13 as tls

#typing.NewType( 'TLSMsg', pytls13.tls_client_handler.TLSMsg )

class Debug( pylurk.debug.Debug ):

  def __init__( self, debug_conf ):
    super().__init__( debug_conf )
    self.client_tls_record_counter = 1
    self.server_tls_record_counter = 1
    self.client_tls_msg_counter = 1
    self.server_tls_msg_counter = 1

##  ## not sure we need this
##  def descriptor_from_struct( self, tls_msg, sender=None ):
##    """ extracts the key used to identify the structure 
##
##    The key is typically the msg_type for tls message of 
##    content_type 'handshake'.
##    For tls message wit a different content_type, we use 
##    the content_type as a key. 
##    'sender' is used to differentiates the client and the server. 
##    """
##    if isinstance( tls_msg, dict ):
##      tmp_tls_msg = pytls13.tls_client_handler.TLSMsg( )
##      tmp_tls_msg.from_record_layer_struct( tls_msg )
##      tls_msg = tmp_tls_msg
##    return tls_msg.descriptor( sender=sender)

## s/tls_msg/reccord_layer/
## tls_msg_content/tls/tls_msg/
##  def check_tls_msg( self, tls_msg, label="" ):
##    description = tls_msg.descriptor( label=label )  
##    self.trace_bin( description, self.content_byte( tls_msg ) )
##    self.trace_val( description, self.content_struct( tls_msg ) )
##
##  def trace_tls_reccord( self, tls_msg, label="" ):
##    description = tls_msg.descriptor( label=label )  
##    self.trace_bin( description, self.record_byte( tls_msg ) )
##    self.trace_val( description, self.record_struct( tls_msg ) )
##
##
##  def check_tls_msg( self, tls_msg, label="" ):
##    """ considers the tls_msg with a **full** handshake message """  
##    self.check_bin( tls_msg.descriptor( label=label ),\
##                    tls_msg.to_record_layer_bytes() )
##
##  ## we should not need that one.
##  def check_tls_clear_text_msg( self, tls_msg, sender ):
##    self.check_bin( tls_msg.descriptor( sender=sender), tls_msg.to_record_layer_bytes() )
##
##  ## we should not need that one
##  def check_tls_cipher_text_msg( self, tls_msg, descriptor, sender ):
##    self.check_bin( f"{sender}_{descriptor}", tls_msg.to_record_layer_bytes() )
##
##  def record_tls_msg( self, tls_msg, label="" ):
##    """ considers the tls_msg with a **full** handshake message """  
##    self.record_bin( tls_msg.descriptor( label=label ), 
##                     tls_msg.to_record_layer_bytes() )
##
##  ## we should not need that one 
##  def record_tls_clear_text_msg( self, tls_msg, sender ):
##    descriptor  =  tls_msg.descriptor( sender=sender)
##    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )
##
##  ## we shoudl need that one
##  def record_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
##    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
##    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )
##    ## we do not record the struct as it contains bytes which cannot be 
##    ## stored into a JSON object
##    self.record_val( f"{descriptor}_struct", tls_msg.to_record_layer_struct() ) 
##    ## we need to addres this in record_value
##    self.record_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
##    self.record_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
##
##  ## we shoudl not need that one
##  def record_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender): 
##    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
##    ## we do not record the struct as it contains bytes which cannot be 
##    ## stored into a JSON object
##    ## self.record_val( f"{descriptor}_inner_clear_text_struct", inner_clear_text_struct )  
##    self.record_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
##    self.record_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
##    self.record_bin( descriptor, tls_msg.to_record_layer_bytes() )
##
 
  def record_byte( self, tls_msg ):
    """ returns the tls_Reccord bytes 

    For received TLS record, these are stored in record_layer_bytes
    so this value is prefered.
    For sent TLS record, the bytes are formed using to_record_layer_bytes.
    """   
    if tls_msg.record_layer_bytes != b'':
      return tls_msg.record_layer_bytes    
    return tls_msg.to_record_layer_bytes() 

  def record_struct( self, tls_msg ):
    if tls_msg.content_type == 'handshake' and isinstance( tls_msg.content, bytes ): 
      struct = tls.FragmentTLSPlaintext.parse( tls_msg.record_layer_bytes )
    else:
      struct = tls.TLSPlaintext.parse( tls_msg.to_record_layer_bytes() )

    return struct

  def content_byte( self, tls_msg ):
      """fragment / content of a TLS record / inner message
      """
      return tls_msg.to_record_layer_bytes()[ 5 : ] 

  def content_struct( self, tls_msg ):
    return self.record_struct( tls_msg ) [ 'fragment' ]    
      

  def inner_content_bytes( self, tls_msg ):
    return tls_msg.to_inner_msg_bytes( ) 

  def inner_content_struct( self, tls_msg ):
    inner_msg = tls_msg.to_inner_msg_bytes( )  
    if tls_msg.content_type in [ 'handshake', 'application_data' ] and\
       isinstance( tls_msg.content, bytes ):
      struct = tls.FragmentTLSInnerPlaintext.parse( inner_msg, \
              type=tls_msg.content_type, 
              clear_text_msg_len=len( tls_msg.content ),\
              length_of_padding=len( tls_msg.zeros ) )
    else:
#      print( f"DEBUG: inner_msg: {inner_msg}" )
#      print( f"DEBUG: type : {tls_msg.content_type}" )
#      print( f"DEBUG: ength_of_padding : {len( tls_msg.zeros )}" )
      struct = tls.TLSInnerPlaintext.parse( inner_msg, \
             type=tls_msg.content_type,
             length_of_padding=len( tls_msg.zeros ) )
    return struct

###  def trace_tls_msg( self, tls_msg, label="" ):
###    description = tls_msg.descriptor( label=label )  
###    self.trace_bin( description, self.content_byte( tls_msg ) )
###    self.trace_val( description, self.content_struct( tls_msg ) )
###
###  def trace_tls_reccord( self, tls_msg, label="" ):
###    description = tls_msg.descriptor( label=label )  
###    self.trace_bin( description, self.record_byte( tls_msg ) )
###    self.trace_val( description, self.record_struct( tls_msg ) )
###
###
###  ### we do not need this  
###  def trace_tls_clear_text_msg( self, tls_msg, sender ):
###    descriptor = tls_msg.descriptor( sender=sender )
###    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )
###    pprint.pprint( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}", width=80, sort_dicts=False )
###
###  ## we do not need this
###  def trace_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
###    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
####    key = f"{sender}_{inner_tls_msg.content[ 'msg_type' ]}"
###    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )
###    pprint.pprint( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}", width=80, sort_dicts=False )  
###    self.trace_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
###    self.trace_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
###    pprint.pprint( f"{descriptor}_inner_clear_text_struct: {inner_clear_text_struct}", width=80, sort_dicts=False )
###
###  def trace_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender): 
###    descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
###    pprint.pprint( f"{descriptor}_inner_clear_text_struct: {inner_clear_text_struct}", width=80, sort_dicts=False )  
###    self.trace_bin( f"{descriptor}_inner_clear_text", inner_clear_text )
###    self.trace_bin( f"{descriptor}_inner_cipher_text", tls_msg.content )
###    pprint.pprint( f"{descriptor}_struct: {tls_msg.to_record_layer_struct()}", width=80, sort_dicts=False )  
###    self.trace_bin( descriptor, tls_msg.to_record_layer_bytes() )

#  def handle_bin( self, key:str, value:bytes ):
#    if self.check is True:
#      self.check_bin( key, value )
#    if self.record is True:
#      self.record_bin( key, value )
#    if self.trace is True:
#      self.trace_bin( key, value )

##  def check_tls_msg( self, tls_msg, label="" ):
##    description = tls_msg.descriptor( label=label )  
##    self.trace_bin( description, self.content_byte( tls_msg ) )
##    self.trace_val( description, self.content_struct( tls_msg ) )
##
##  def trace_tls_reccord( self, tls_msg, label="" ):
##    description = tls_msg.descriptor( label=label )  
##    self.trace_bin( description, self.record_byte( tls_msg ) )
##    self.trace_val( description, self.record_struct( tls_msg ) )
##    self.received_tls_msg_counter += 1

  def record_counter( self, tls_msg ):
    """ select appropriated TLS record counter to tls_msg """  
    if tls_msg.sender == 'client':
      msg_counter = self.client_tls_record_counter
    elif tls_msg.sender == 'server' :
      msg_counter = self.server_tls_record_counter
    else:
      raise ValueError( f"Invalid tls_msg.sender {tls_msg.sender}"\
              f"MUST be set to 'client' or 'server' " )   
    return msg_counter

  def msg_counter( self, tls_msg ):
    """ select appropriated TLS message counter to tls_msg """  
    if tls_msg.sender == 'client':
      msg_counter = self.client_tls_msg_counter
    elif tls_msg.sender == 'server' :
      msg_counter = self.server_tls_msg_counter
    else:
      raise ValueError( f"Invalid tls_msg.sender {tls_msg.sender}"\
              f"MUST be set to 'client' or 'server' ")   
    return msg_counter


  def handle_tls_record( self, tls_msg, label="" ):
    counter = self.record_counter( tls_msg )  
    description = f"TLS record {counter} {tls_msg.descriptor( label=label )}"
    tls_msg_bytes = self.record_byte( tls_msg ) 
    tls_msg_struct = self.record_struct( tls_msg ) 
    self.handle_bin( description, tls_msg_bytes )
    if self.trace is True:
      self.trace_val( description, self.record_struct( tls_msg ) )
    self.client_tls_record_counter += 1

  def handle_tls_msg( self, tls_msg, label="" ):
    """ handles tls message

    """
    counter = self.msg_counter( tls_msg )  
    description = f"TLS message {counter} {tls_msg.descriptor( label=label )}" 
    tls_msg_bytes = self.content_byte( tls_msg ) 
    tls_msg_struct = self.content_struct( tls_msg ) 
    self.handle_bin( description, tls_msg_bytes )
    if self.trace is True:
      self.trace_val( description, self.content_struct( tls_msg ) )

  def handle_inner_tls_msg( self, tls_msg, label="" ):
    """ handles tls message

    """
    msg_nbr = self.record_counter( tls_msg )
    description = f"Inner TLS message {msg_nbr} {tls_msg.descriptor( label=label )}" 
    tls_msg_bytes = self.inner_content_bytes( tls_msg ) 
    tls_msg_struct = self.inner_content_struct( tls_msg ) 
    self.handle_bin( description, tls_msg_bytes )
    if self.trace is True:
      self.trace_val( description, self.inner_content_struct( tls_msg ) )


##  def handle_tls_clear_text_msg( self, tls_msg, sender ):
##    if self.check is True:
##      self.check_tls_clear_text_msg( tls_msg, sender )
##    if self.record is True:
##      self.record_tls_clear_text_msg( tls_msg, sender )
##    if self.trace is True:
##      self.trace_tls_clear_text_msg( tls_msg, sender )
##
##  def handle_tls_cipher_text_msg_dec( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender) :
##    if self.check is True:
##      descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
##      self.check_tls_cipher_text_msg( tls_msg, descriptor, sender )
##    if self.record is True:
##      self.record_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender)
##    if self.trace is True:
##      self.trace_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender)
##    
##  def handle_tls_cipher_text_msg_enc( self, tls_msg, inner_clear_text, inner_clear_text_struct, sender):
##    if self.check is True: 
##      descriptor = self.descriptor_from_struct( inner_clear_text_struct, sender=sender )
##      self.check_tls_cipher_text_msg( tls_msg, descriptor, sender )
##    if self.record is True:
##      self.record_tls_cipher_text_msg_enc( tls_msg, inner_clear_text, inner_clear_text_struct, sender) 
##    if self.trace is True:
##      self.trace_tls_cipher_text_msg_enc( tls_msg, inner_clear_text, inner_clear_text_struct, sender) 
##

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
