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
  'debug' : {
    'trace' : True,  # prints multiple useful information
    'test_vector' : True,
    'test_vector_file' : './illustrated_tls13.json',
    ## in some cases, the test vector is performed by establishing a real 
    ## TCP connection. In such cases, sent packets are __effectively__ 
    ## being sent to the other peer and incoming packets are __effectively__ 
    ## being received by the other peer.  If that is the case, than 'remote'
    ## should be picked. 
    ## In other cases, packets are not sent and received, but instead locally
    ## provided from a file. 
    'test_vector_mode' : 'remote', #'local' # / remote 
  }, 
  'tls13' : {
#    'illustrated_tls13': True,
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

#lurk_req =\
#  { 'designation' : 'tls13',
#    'version' : 'v1',
#    'type' : 'c_init_client_hello',
#    'status' : 'request',
#    'id' : secrets.randbelow( 2  ** 64 ), ## MUST be int 
#    'payload' : {} }
#
#secret_request = { 'b' : False, 'e_s' : False, 'e_x' : False, \
#                   'h_c' : False, 'h_s' : False, 'a_c' : False, \
#                   'a_s' : False, 'x' : False, 'r' : False }

print( f"::Instantiating the CS" )
cs = pylurk.cs.CryptoService( conf=clt_cs_conf.conf )
print( f"::Instantiating the Lurk client" )
lurk_client = pylurk.lurk_client.LurkTls13Client( cs )
#if clt_e_conf[ ( 'tls13', 'v1' ) ][ 'illustrated_tls13' ] is True:
if clt_e_conf[ 'debug' ][ 'test_vector' ] is True:
  if 'illustrated_tls13.json' in clt_e_conf[ 'debug' ][ 'test_vector_file' ]:  
    lurk_client.freshness = 'null'

## tls handshake enables msg manipulations 
## ks is a useful lcompagnon but toinstantiate it one needs to know the TLS.Hash
## which is determined either by PSK or the selected cipher suite in (ECDHE mode. 
tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )


print( f"::TCP session with the TLS server")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect( ( clt_e_conf[ 'server' ][ 'ip' ], clt_e_conf[ 'server' ][ 'port' ] ) )



print( f"::Sending ClientHello to the server\n--->" )
ch = pytls13.tls_client.ClientHello( clt_e_conf )
print( f"--- E: Generating ClientHello:" )
if clt_e_conf[ 'tls13' ][ 'ephemeral_method' ] == 'e_generated' :
  clt_ecdhe_private = ch.ecdhe_private_key_list[ 0 ]
#  ch.show() 
elif clt_e_conf[ 'tls13' ][ 'ephemeral_method' ] == 'cs_generated' :
  lurk_resp = lurk_client.resp( 'c_init_client_hello', handshake=[ ch.msg ] )
  print( f" --- before: {tls_handshake.msg_list}" )
  ch.c_init_client_hello_update( lurk_resp, tls_handshake, lurk_client )

  print( f" --- after: {tls_handshake.msg_list}" )
s.sendall( ch.to_bytes( ) )


##if clt_e_conf[ 'tls13' ][ 'illustrated_tls13' ] is True:
##  if ch.to_bytes() != pylurk.utils.str_to_bytes( ch.illustrated_tls13_ch ):
##    raise ValueError( "ClientHello byte mismatch" )


print( "--- E -> TLS Server Sending Client Hello:" )
ch.show()

#tls_msg = pytls13.tls_client.TLSMsg()
stream_parser = pytls13.tls_client.TLSByteStreamParser( s )
while True:
#  msg = tls_msg.parse_single_msg( s )
  tls_msg = stream_parser.parse_single_msg( )
#  if msg[ 'type' ] == 'handshake': 
  if tls_msg.content_type == 'handshake': 
#    if msg[ 'fragment' ] [ 'msg_type' ] == 'server_hello' :
    if tls_msg.msg[ 'msg_type' ] == 'server_hello' : 
      print( "---Receiving ServerHello from the server\n--->" )
#      print( f"  - (msg bytes) [len {len( msg)}] : msg" )
#      print( f"  - (inner struct) ch.from_bytes( ch.to_bytes() )" )
      print( f"  - (msg bytes) [len {len(tls_msg.bytes)}] : tls_msg.msg" )
      print( f"  - (inner struct) tls_msg.from_bytes( tls_msg.to_bytes() )" )
##      sh = msg[ 'fragment' ]
      sh = pytls13.tls_client.ServerHello()
#      sh.msg = msg[ 'fragment' ]
      sh.msg = tls_msg.msg
      sh.bytes = tls_msg.bytes
      tls_handshake.msg_list.append( sh.msg )
      ephemeral_method = clt_e_conf[ 'tls13' ][ 'ephemeral_method' ]
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
        eph_method = clt_e_conf[ 'tls13' ][ 'ephemeral_method' ]
        raise ValueError( "unknown 'ephemeral_method': {eph_method}" )
      lurk_resp = lurk_client.resp( 'c_server_hello', handshake=[ sh.msg ], ephemeral=eph )
      ks = pylurk.tls13.lurk_tls13.KeyScheduler( tls_hash=tls_handshake.get_tls_hash() )
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
  elif tls_msg.content_type == 'change_cipher_spec':
#  elif msg[ 'type' ] == 'change_cipher_spec':
    print( f"--- E <- TLS Server: Receiving ChangeCipherSpec from the server\n--->" )
    pass
#  elif msg[ 'type' ] == 'application_data' :
  elif tls_msg.content_type == 'application_data' :
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    print( f"  - (msg bytes) [len {len( tls_msg.bytes)}] : {tls_msg.msg}" )
    
##    try :
##    inner_clear_text = s_cipher.decrypt( msg )
    inner_tls_msg = pytls13.tls_client.TLSMsg()
    inner_clear_text = s_cipher.decrypt( tls_msg.msg )
#    inner_content = inner_clear_text[ 'content' ]
#    inner_type = inner_clear_text[ 'type' ]
#    inner_tls_msg.content_type = inner_clear_text[ 'type' ]
#    inner_tls_msg.msg = inner_clear_text[ 'content' ]
    inner_tls_msg.from_record_layer_struct( inner_clear_text )
    ## bytes is not populated --> may be decrypt coudl do that.

#    print( f"  - (struct) [len {len( msg[ 'fragment' ])}] : {inner_content}" )
##    print( f"  - (struct) [len {len( msg[ 'fragment' ])}] : {inner_content}" )
   
#    if inner_type == 'handshake' :
    if inner_tls_msg.content_type == 'handshake' :
#      if inner_content[ 'msg_type' ] == 'certificate_verify':
      if inner_tls_msg.msg[ 'msg_type' ] == 'certificate_verify':
        ## we do update the transcript similarly to the server
        ## but also keep track of the handshake that we will need 
        ## to provide to the cs.  
        tls_handshake.transcript_hash( 'sig' )
#      elif inner_content[ 'msg_type' ] == 'finished':
      elif inner_tls_msg.msg[ 'msg_type' ] == 'finished':
        c_verify_data = tls_handshake.get_verify_data( ks, role='server',\
                          transcript_mode='finished') 
##        s_verify_data =  inner_content [ 'data' ][ 'verify_data' ]
        s_verify_data =  inner_tls_msg.msg[ 'data' ][ 'verify_data' ]
        pylurk.utils.print_bin( "client computed verify_data", c_verify_data )
        pylurk.utils.print_bin( "server provided verify_data", s_verify_data )
        if c_verify_data != s_verify_data : 
          raise ValueError( "Client unable to validate Finished message" )
#        tls_handshake.msg_list.append( inner_content )
#        tmp_handshake.append( inner_content )
        tls_handshake.msg_list.append( inner_tls_msg.msg )
        tmp_handshake.append( inner_tls_msg.msg )
        break
      else:
        pass
#      tls_handshake.msg_list.append( inner_content )
#      tmp_handshake.append( inner_content )
      tls_handshake.msg_list.append( inner_tls_msg.msg )
      tmp_handshake.append( inner_tls_msg.msg )
      
    else :
      pass
    
if clt_e_conf[ 'debug' ][ 'test_vector' ] is True:
  if 'illustrated_tls13.json' in clt_e_conf[ 'debug' ][ 'test_vector_file' ]:  
#if clt_e_conf[ 'tls13' ][ 'illustrated_tls13' ] is True:
    print( "--- E -> TLS Server : Change Cipher Spec" )
    tls_msg.msg=b'\x01'
  #tls_msg.msg=c_cipher.encrypt( clear_text_msg=b'\x01', content_type='change_cipher_spec' )
    tls_msg.content_type = 'change_cipher_spec'
    tls_msg.show()
    s.sendall( tls_msg.to_bytes( ) )
  

print( "--- E -> CS: Application Secrets / Signature" )

if clt_e_conf[ 'tls13' ][ 'session_resumption' ] is False:
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

tls_handshake.update_finished( ks )

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
#tls_msg = pytls13.tls_client.TLSMsg()
while True:
#  msg = tls_msg.parse_single_msg( s )
  tls_msg = stream_parser.parse_single_msg( )
#  if msg[ 'type' ] == 'application_data' :
  if tls_msg.content_type == 'application_data' :
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    print( f"  - (msg bytes) [len {len( tls_msg.bytes)}] : {tls_msg.msg}" )
#    clear_text_inner_content = s_a_cipher.decrypt( msg )
    inner_tls_msg = pytls13.tls_client.TLSMsg()
    inner_clear_text = s_a_cipher.decrypt( tls_msg.msg )
    inner_tls_msg.from_record_layer_struct( inner_clear_text )
#    inner_tls_msg.msg = inner_clear_text[ 'content' ]
#    inner_tls_msg.content_type = inner_clear_text[ 'type' ]
#    inner_clear_text = s_a_cipher.decrypt( msg )
#    inner_content = inner_clear_text[ 'content' ]
#    inner_type = inner_clear_text[ 'type' ]
#    print( f"  - (struct) [len {len( msg[ 'fragment' ])}] : {inner_content}" )
    print( f"  - (struct) [len {len( tls_msg.bytes)}] : {inner_tls_msg.msg}" )
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    print( f"  - (msg bytes) [len {len(inner_tls_msg.bytes)}] : {inner_tls_msg.bytes}" )
#    if inner_type == 'application_data':
    if inner_tls_msg.content_type == 'application_data':
      print( f"--- APPLICATION DATA: {inner_tls_msg.msg}" )
#    elif inner_type == 'handshake':
    elif inner_tls_msg.content_type == 'handshake':
#      if inner_content[ 'msg_type' ] == 'new_session_ticket':
      if inner_tls_msg.msg[ 'msg_type' ] == 'new_session_ticket':
        lurk_resp = lurk_client.resp( 'c_register_tickets', \
                              last_exchange=True, \
                              ticket_list=[ inner_tls_msg.msg[ 'data' ] ] )
#                              ticket_list=[ inner_content[ 'data' ] ] )
        
      pass
  else:
    pass

