import socket 
import binascii
import secrets 

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.lurk.lurk_lurk
import pylurk.conf 
import pylurk.cs
import pylurk.lurk_client
from pylurk.struct_lurk import LURKMessage

#import pylurk.tls13.struct_tls13
import pylurk.tls13.lurk_tls13

sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/') #pytls13
#import pytls13.struct_tls13
import pytls13.tls_client
import pytls13.ciphers
import pylurk.utils

from cryptography.hazmat.primitives.hmac import HMAC

""" This scripts details the case where a TLS client performs a TLS handshake with:
* Certificate base authentication (EC)DHE
* Generates the (EC)DHE private key itself
* Does not supports post_handshake authentication, nor session resumption

Such interaction only involves a c_init_client_finished between the TLS Engine (E) and the CS
"""

#ILLUSTRATED_TLS13 = True

clt_e_conf = {
  'server' : {
    'ip' : '127.0.0.1',
    'port' : 8400
  },
  ( 'tls13', 'v1' ) : {
    'illustrated_tls13': True,
    'trace_mode': True,
    'ecdhe_authentication' : True, ## ecdhe indicates certificate based authentication
    'ke_modes' : [ ], ## psk without ecdhe
    'session_resumption' : False,
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
    'ephemeral_method' : 'cs_generated', ## when ECDHE is needed. 
    ## these values are used for the supported_group (non mandatory) and key_share extension 
    'supported_ecdhe_groups' : [ 'x25519' ], #[ 'secp256r1', 'x25519', 'x448' ], 
    'cs_conf' : None
  }
}

## configuration of the CS for 'Ed25519'
sig_scheme = 'ed25519'
clt_cs_conf = pylurk.conf.Configuration( )
clt_cs_conf.set_ecdhe_authentication( sig_scheme, conf_dir = './clt_cs' )
clt_cs_conf.set_role( 'client' )
clt_cs_conf.set_extention( ext=( 'tls13', 'v1' ) )

lurk_req =\
  { 'designation' : 'tls13',
    'version' : 'v1',
    'type' : 'c_init_client_hello',
    'status' : 'request',
    'id' : secrets.randbelow( 2  ** 64 ), ## MUST be int 
    'payload' : {} }

secret_request = { 'b' : False, 'e_s' : False, 'e_x' : False, \
                   'h_c' : False, 'h_s' : False, 'a_c' : False, \
                   'a_s' : False, 'x' : False, 'r' : False }

print( f"::Instantiating the CS" )
cs = pylurk.cs.CryptoService( conf=clt_cs_conf.conf )
print( f"::Instantiating the Lurk client" )
lurk_client = pylurk.lurk_client.LurkTls13Client( cs )
if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'illustrated_tls13' ] is True:
  lurk_client.freshness = 'null'

## tls handshake enables msg manipulations 
## ks is a useful lcompagnon but toinstantiate it one needs to know the TLS.Hash
## which is determined either by PSK or the selected cipher suite in (ECDHE mode. 
tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )


print( f"::TCP session with the TLS server")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect( ( clt_e_conf[ 'server' ][ 'ip' ], clt_e_conf[ 'server' ][ 'port' ] ) )



print( f"::Sending ClientHello to the server\n--->" )
ch = pytls13.tls_client.ClientHello( clt_e_conf[ ( 'tls13', 'v1' ) ] )
print( f"--- E: Generating ClientHello:" )
if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'ephemeral_method' ] == 'e_generated' :
  clt_ecdhe_private = ch.ecdhe_private_key_list[ 0 ]
#  ch.show() 
elif clt_e_conf[ ( 'tls13', 'v1' ) ][ 'ephemeral_method' ] == 'cs_generated' :
#lurk_c#  if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'illustrated_tls13' ] is True:
#lurk_c#    freshness = 'null'
#lurk_c#  else: 
#lurk_c#    freshness = 'sha256'
#lurk_c#  lurk_req [ 'type' ] = 'c_init_client_hello'
#lurk_c#  lurk_client_session_id = secrets.token_bytes( 4 )
#lurk_c#  lurk_req [ 'payload' ] = { \
#lurk_c#    'session_id' : lurk_client_session_id,
#lurk_c#    'handshake' : [ ch.msg ],
#lurk_c#    'freshness' : freshness,
#lurk_c#    'psk_metadata_list' : [], ## no psk
#lurk_c#    'secret_request' : secret_request 
#lurk_c#  }
#lurk_c#  print( "--- E -> CS: Sending 'c_init_client_hello' Request:" )
#lurk_c#  print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_req ) )}" )
#lurk_c#  lurk_resp = LURKMessage.parse( cs.serve( LURKMessage.build( lurk_req ) ) )
#lurk_c#  if lurk_resp[ 'status' ] != 'success':
#lurk_c#    raise ValueError( f"Lurk exchange error: {lurk_resp}" )
#lurk_c#  print( "--- E <- CS: Receiving 'c_init_client_hello' Response:" )
#lurk_c#  print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_resp ) )}" )
#lurk_c#  ## updating the session_id (sending)
#lurk_c#  cs_session_id = lurk_resp[ 'payload' ][ 'session_id' ]

  ## create a tls_handshake 
  ## move the entire generation of teh ClientHello to the ClientHello object.
  lurk_resp = lurk_client.resp( 'c_init_client_hello', handshake=[ ch.msg ] )
  ## preparing the Client Hello to be sent to the TLS server
    ## random
#  tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )
#ooo  tls_handshake.msg_list = [ ch.msg ]
#  tls_handshake.update_random( pylurk.tls13.lurk_tls13.Freshness( lurk_req[ 'payload' ][ 'freshness' ] ) )
#ooo  tls_handshake.update_random( pylurk.tls13.lurk_tls13.Freshness( lurk_client.freshness ) )
    ## keyshare
#ooo  ephemeral_list = lurk_resp[ 'payload' ][ 'ephemeral_list' ] 
#ooo  client_shares = [ eph[ 'key' ] for eph in ephemeral_list ]
#ooo  tls_handshake.update_key_share( client_shares )
#ooo  ch.msg = tls_handshake.msg_list[ 0 ] 
  print( f" --- before: {tls_handshake.msg_list}" )
  ch.c_init_client_hello_update( lurk_resp, tls_handshake, lurk_client )

  print( f" --- after: {tls_handshake.msg_list}" )
s.sendall( ch.to_bytes( ) )


##if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'illustrated_tls13' ] is True:
##  if ch.to_bytes() != pylurk.utils.str_to_bytes( ch.illustrated_tls13_ch ):
##    raise ValueError( "ClientHello byte mismatch" )


print( "--- E -> TLS Server Sending Client Hello:" )
ch.show()

tls_msg = pytls13.tls_client.TLSMsg()
while True:
  msg = tls_msg.parse_single_msg( s )
  if msg[ 'type' ] == 'handshake': 
    if msg[ 'fragment' ] [ 'msg_type' ] == 'server_hello' :
      print( "---Receiving ServerHello from the server\n--->" )
      print( f"  - (msg bytes) [len {len( msg)}] : msg" )
      print( f"  - (inner struct) ch.from_bytes( ch.to_bytes() )" )
#      sh = msg[ 'fragment' ]
      sh = pytls13.tls_client.ServerHello()
      sh.msg = msg[ 'fragment' ]
      tls_handshake.msg_list.append( sh.msg )
      ephemeral_method = clt_e_conf[ ( 'tls13', 'v1' ) ][ 'ephemeral_method' ]
      if ephemeral_method == 'e_generated' :
        if tls_handshake.is_ks_agreed is True: ## shared_secret agreed
          ## compute shared secrets
          eph = { 'method': 'e_generated', 'key': shared_secret }
          ## eventually we do not need to interact with the cs
#          sh = pytls13.tls_client.ServerHello( )
#          sh.msg = msg[ 'fragment' ]
          shared_secret = sh.get_shared_secret( clt_ecdhe_private )
#          tls_hash = pylurk.conf.CipherSuite( sh.msg[ 'data' ][ 'cipher_suite' ] ).get_hash()
#          handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )
#          handshake.msg_list.extend( [ ch.msg, sh.msg ])
          ks = pylurk.tls13.lurk_tls13.KeyScheduler(\
                 tls_hash=tls_handshake.get_tls_hash(), ecdhe=shared_secret)
          ks.process( [ 'h_s', 'h_c' ], handshake )
        else:
          eph =  { 'method': 'no_secret', 'key': b'' }
        eph = { 'method': 'e_generated', 'key': None }
      elif ephemeral_method == 'cs_generated' :
        if tls_handshake.is_ks_agreed() is True: ## shared_secret agreed
          eph = { 'method': 'cs_generated', 'key': None }
        else:
          eph =  { 'method': 'no_secret', 'key': b'' }
      elif ephemeral_method == 'no_secret' :
        pass
      else: 
        eph_method = clt_e_conf[ ( 'tls13', 'v1' ) ][ 'ephemeral_method' ]
        raise ValueError( "unknown 'ephemeral_method': {eph_method}" )
###      lurk_req[ 'id' ] = secrets.randbelow( 2  ** 64 )
###      lurk_req [ 'type' ] = 'c_server_hello'
###      lurk_req[ 'payload' ] = {\
####        'session_id' : cs_session_id,
###        'session_id' : lurk_client.cs_session_id,
###        'handshake' : [ sh ],
###        'ephemeral' : eph }
###      print( "--- E -> CS: Sending 'c_server_hello' Request:" )
###      print( "  - {LURKMessage.parse( LURKMessage.build( lurk_req ) )}" )
###      lurk_resp_bytes = cs.serve( LURKMessage.build( lurk_req ) )
###      lurk_resp = LURKMessage.parse( lurk_resp_bytes )
###      print( "--- E <- CS: Receiving 'c_server_hello' Response:" )
###      print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_resp ) )}" )
###      if lurk_resp[ 'status' ] != 'success': 
###        raise ValueError( f"Lurk exchange error: {lurk_resp}" )
      lurk_resp = lurk_client.resp( 'c_server_hello', handshake=[ sh.msg ], ephemeral=eph )
      ks = pylurk.tls13.lurk_tls13.KeyScheduler( tls_hash=tls_handshake.get_tls_hash() )
#      for secret in lurk_resp[ 'payload' ][ 'secret_list' ] : 
#        if secret[ 'secret_type' ] == 'h_s' :
#          h_s = secret[ 'secret_data' ]    
#        if secret[ 'secret_type' ] == 'h_c' :
#          h_c = secret[ 'secret_data' ]   
      ## update ks with secrets and perform handshake transcript
      sh.c_server_hello_update( lurk_resp, tls_handshake, ks )
    ## generating cipher objects to encrypt / decrypt traffic
    cipher_suite = tls_handshake.get_cipher_suite()
    s_cipher = pylurk.conf.CipherSuite( cipher_suite, ks.secrets[ 'h_s' ] )
    c_cipher = pylurk.conf.CipherSuite( cipher_suite, ks.secrets[ 'h_c' ] )
    pylurk.utils.print_bin( "server_write_key", s_cipher.write_key ) 
    pylurk.utils.print_bin( "server_write_iv", s_cipher.write_iv ) 
    pylurk.utils.print_bin( "client_write_key", c_cipher.write_key ) 
    pylurk.utils.print_bin( "client_write_iv", c_cipher.write_iv )
    ## keep track of the messages for the next lurk request
    ## transcripts are performed at least to check the server finished 
    ## message. The transcript erases the stored handshake messages.
    ## to avoid such copy of handshake message, we may send the request of 
    ## the cs prior to validate the server finished.
    tmp_handshake = []
  elif msg[ 'type' ] == 'change_cipher_spec':
    print( f"--- E <- TLS Server: Receiving ChangeCipherSpec from the server\n--->" )
    pass
  elif msg[ 'type' ] == 'application_data' :
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    print( f"  - (msg bytes) [len {len( msg)}] : {msg}" )
    
#    try :
    inner_clear_text = s_cipher.decrypt( msg )
    inner_content = inner_clear_text[ 'content' ]
    inner_type = inner_clear_text[ 'type' ]
    print( f"  - (struct) [len {len( msg[ 'fragment' ])}] : {inner_content}" )
   
#    except:
#      selected_cipher = sh[ 'data' ][ 'cipher_suite' ]
#      s_cipher = pylurk.conf.CipherSuite( selected_cipher, h_s )
#      pylurk.utils.print_bin( "server_write_key", s_cipher.write_key ) 
#      pylurk.utils.print_bin( "server_write_iv", s_cipher.write_iv ) 
##      clear_text_msg = s_cipher.decrypt( msg )
#    print( f"{clear_text_msg}" )
    if inner_type == 'handshake' :
      if inner_content[ 'msg_type' ] == 'certificate_verify':
        ## we do update the transcript similarly to the server
        ## but also keep track of the handshake that we will need 
        ## to provide to the cs.  
#        tmp_handshake = tls_handshake.msg_list[ : ]
        tls_handshake.transcript_hash( 'sig' )
#        pass
      elif inner_content[ 'msg_type' ] == 'finished':
        c_verify_data = tls_handshake.get_verify_data( ks, role='server',\
                          transcript_mode='finished') 
#        s_verify_data =  clear_text_inner_content [ 'data' ][ 'verify_data' ]
        s_verify_data =  inner_content [ 'data' ][ 'verify_data' ]
        pylurk.utils.print_bin( "client computed verify_data", c_verify_data )
#        finished_key = s_cipher.hkdf_expand_label( secret=ks.secrets[ 'h_s' ],\
#          label=b'finished', context=b'', length=s_cipher.hash.digest_size )
#        hmac = HMAC( finished_key, s_cipher.hash )
#        hmac.update( tls_handshake.transcript_hash( 'finished' ) )
        pylurk.utils.print_bin( "server provided verify_data", s_verify_data )
        if c_verify_data != s_verify_data : 
          raise ValueError( "Client unable to validate Finished message" )
        tls_handshake.msg_list.append( inner_content )
        tmp_handshake.append( inner_content )
        break
      else:
        pass
      tls_handshake.msg_list.append( inner_content )
      tmp_handshake.append( inner_content )
      
    else :
      pass
#print( f" --DEBUG: {type(tmp_handshake)} -- {type(tmp_handshake[0][ 'msg_type' ])}" )
#for m in tmp_handshake:
#  try:
#    print( f" {m[ 'msg_type' ]}" )
#  except: 
#    print( f"{m}" )
#print( f"  -- DEBUG 1: tmp_handshake: { [ m[ 'msg_type' ] for m in tmp_handshake ] }" )
    
if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'illustrated_tls13' ] is True:
  print( "--- E -> TLS Server : Change Cipher Spec" )
  tls_msg.msg=b'\x01'
  #tls_msg.msg=c_cipher.encrypt( clear_text_msg=b'\x01', content_type='change_cipher_spec' )
  tls_msg.content_type = 'change_cipher_spec'
  tls_msg.show()
  s.sendall( tls_msg.to_bytes( ) )
  

print( "--- E -> CS: Application Secrets / Signature" )

if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'session_resumption' ] is False:
  last_exchange = True
else :
  last_exchange = False

client_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
if tls_handshake.is_certificate_request( ) is True:
  pass
  ## generates the certificate and certificate verify_data
  ## append_them to tls_handshake
#tls_handshake.update_client_finished( )

#server_hello_index = tls_handshake.server_hello_index( )
#handshake = tls_handshake.msg_list[ : ] 
server_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
for m in tmp_handshake:
  if m[ 'msg_type' ] == 'certificate' :
    tmp_handshake.remove( m )
    server_cert = { 'cert_type' : 'uncompressed', 'certificate' : m[ 'data' ] }
lurk_resp = lurk_client.resp( 'c_client_finished', \
                              last_exchange=last_exchange, \
                              handshake=tmp_handshake, \
                              server_certificate=server_cert, \
                              client_certificate=client_cert, \
                              secret_request=[ 'a_c', 'a_s' ] )
for secret in lurk_resp[ 'payload' ][ 'secret_list' ] :
  ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]


print( "--- E -> TLS Server: Sending Client Finished" )

#verify_data = tls_handshake.get_verify_data( ks, role='server',\
#                        transcript_mode = 'r') 
tls_handshake.update_finished( ks )
#cf = tls_handshake.msg_list[ - 1 ]
#print( cf )
#tls_msg.msg = tls_handshake.msg_list[ - 1 ]
#tls_msg.content_type = 'handshake'
#tls_msg.show()
#tls_msg.msg = tls_handshake.msg_list[ - 1 ]
#print( f"client_finished : {tls_msg.msg}" )
tls_msg.msg=c_cipher.encrypt( tls_handshake.msg_list[ - 1 ], content_type='handshake' )
tls_msg.content_type = 'application_data'
tls_msg.show()
s.sendall( tls_msg.to_bytes( ) )

s_a_cipher = pylurk.conf.CipherSuite( cipher_suite, ks.secrets[ 'a_s' ] )
c_a_cipher = pylurk.conf.CipherSuite( cipher_suite, ks.secrets[ 'a_c' ] )

print( "--- E -> TLS Server: Sending Data" )
tls_msg.msg = c_a_cipher.encrypt( b'ping', content_type='application_data' )
tls_msg.content_type = 'application_data'
tls_msg.show()
s.sendall( tls_msg.to_bytes( ) )

ticket_list = []

#tls_msg.__init__() ## re-initializing tls_msg to receive bytes and parse
tls_msg = pytls13.tls_client.TLSMsg()
while True:
  msg = tls_msg.parse_single_msg( s )
  if msg[ 'type' ] == 'application_data' :
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    print( f"  - (msg bytes) [len {len( msg)}] : {msg}" )
#    clear_text_inner_content = s_a_cipher.decrypt( msg )
    inner_clear_text = s_a_cipher.decrypt( msg )
    inner_content = inner_clear_text[ 'content' ]
    inner_type = inner_clear_text[ 'type' ]
    print( f"  - (struct) [len {len( msg[ 'fragment' ])}] : {inner_content}" )
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    print( f"  - (msg bytes) [len {len( msg)}] : {msg}" )
    if inner_type == 'application_data':
      print( f"--- APPLICATION DATA: {inner_content}" )
    elif inner_type == 'handshake':
      if inner_content[ 'msg_type' ] == 'new_session_ticket':
        lurk_resp = lurk_client.resp( 'c_register_tickets', \
                              last_exchange=True, \
                              ticket_list=[ inner_content[ 'data' ] ] )
        
      pass
  else:
    pass

##
##
##
##
##secret_request[ 'a_c' ] = True
##secret_request[ 'a_s' ] = True
##
##lurk_req[ 'id' ] = secrets.randbelow( 2  ** 64 )
##lurk_req [ 'type' ] = 'c_client_finished'
##lurk_req[ 'payload' ] = {\
##  'tag' : { 'last_exchange' : last_exchange },
##  'session_id' : cs_session_id,
##  'handshake' : handshake,
##  'server_certificate' : server_cert,  
##  'client_certificate' : client_cert, 
##  'secret_request' : secret_request }  
##print( "--- E -> CS: Sending 'c_server_hello' Request:" )
##print( "  - {LURKMessage.parse( LURKMessage.build( lurk_req ) )}" )
##lurk_resp_bytes = cs.serve( LURKMessage.build( lurk_req ) )
##lurk_resp = LURKMessage.parse( lurk_resp_bytes )
##print( "--- E <- CS: Receiving 'c_server_hello' Response:" )
##print( f"  - {LURKMessage.parse( LURKMessage.build( lurk_resp ) )}" )
##if lurk_resp[ 'status' ] != 'success': 
##  raise ValueError( f"Lurk exchange error: {lurk_resp}" )
##for secret in lurk_resp[ 'payload' ][ 'secret_list' ] : 
##  if secret[ 'secret_type' ] == 'a_s' :
##    a_s = secret[ 'secret_data' ]    
##  if secret[ 'secret_type' ] == 'a_c' :
##    a_c = secret[ 'secret_data' ]    
##
##
##
##print( f"::Receiving ServerHello\n<---" )
##
##print( f"::Generting handshake secrets/keys ")  
##ecdhe_shared_secret = pylurk.tls13.lurk_tls13.Ephemeral().compute_share_secret( clt_ecdhe_private, srv_ecdhe_public, 'x25519' )
##
##print( f"::Receiving EncryptedExtension, CertificateRequest, Certificate, CertificateVerify, Finished\n<---" )
##ee = EncryptedExtensions( )
##ee.show()
##cr = CertificateRequest()
##cr_ctx = cr.msg[ 'data' ][ 'certificate_request_context' ] 
##cr.show()
##srv_cert = Certificate( certificate_entry_list=srv_cs_conf.conf[ ( 'tls13', 'v1' ) ][ '_cert_entry_list' ] )
##cv = CertificateVerify()
##srv_f = Finished() 
##
##print( f":: === Requesting the CS signature ===" )
##c_init_client_finished_req = {\
##  'tag' : { 'last_exchange' : True },
##  'handshake' : [ ch, sh, ee, cr, cv ], 
##  'server_certificate' : { 'cert_type' : 'uncompressed',\
##                           'certificate' : srv_cert[ 'data' ] },
##  'client_certificate' : { 'cert_type' : 'finger_print', \
##                           'certificate' : { 
##                             'certificate_request_context' : cr_ctx,
##                             'certificate' : self.conf[ ( 'tls13', 'v1' ) ] [ '_finger_print_entry_list' ] } },
##  'freshness' : 'sha256',
##  'ephemeral' : { 'method': 'e_generated', 'key': ecdhe_shared_secret },
##  'psk' : b'' }
##
##lurk_c_init_client_finished_req = \
##  { 'designation' : 'tls13',
##    'version' : 'v1',
##    'type' : 'c_init_client_hello',
##    'status' : 'request',
##    'id' : randbelow( 2  ** 64 ),
##    'payload' : c_init_client_finished_req}
##
##bytes_req = LURKMessage.build( lurk_c_init_client_finished_req )
##print( f"{LURKMessage.parse( bytes_req )}\n--->" )
##bytes_resp = cs.serve( LURKMessage.build( lurk_c_init_client_finished_req ) )
##print( f"{LURKMessage.parse( bytes_resp )}\n<---" )
##resp = LURKMessage.parse( bytes_resp )
##
##
##print( f"::Sending remainig Certificate, CertificateVerify and server Finished to the server\n--->" )
##clt_cert = Certificate( certificate_entry_list=srv_cs_conf.conf[ ( 'tls13', 'v1' ) ][ '_cert_entry_list' ] )
##clt_cert.show() 
##cv = CertificateVerify( algorithm='ed25519', signature=resp[ 'payload' ][ 'signature' ])
##cv.show()
##clt_f = Finished() 
##clt_f.show()
