import socket 
import binascii
import secrets 

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.lurk.lurk_lurk
#import pylurk.conf 
import pylurk.cs
import pylurk.lurk_client
from pylurk.struct_lurk import LURKMessage

#import pylurk.tls13.struct_tls13
import pylurk.tls13.lurk_tls13
import pylurk.tls13.crypto_suites

sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/') #pytls13
#import pytls13.struct_tls13
import pytls13.tls_client
#import pytls13.ciphers
import pytls13.test_vector
import pylurk.utils

from cryptography.hazmat.primitives.hmac import HMAC

""" This client implements a TLS client with the following restrictions: 1) PSK authentication is not used with external keys. PSK is solely used in conjunction of session resumption. 2) PSK  
This scripts details the case where a TLS client performs a TLS handshake with:
* Certificate base authentication (EC)DHE
* Generates the (EC)DHE private key itself
* Does not supports post_handshake authentication, nor session resumption

Such interaction only involves a c_init_client_finished between the TLS Engine (E) and the CS
"""

## illustrated TLS 'ephemeral_method' : 'cs_generated' / 'e_generated'
clt_conf = {
  'role' : 'client',
  'server' : {
    'fqdn' : None,
    'ip' : '127.0.0.1',
    'port' : 8400
  },
  'debug' : {
    'trace' : True,  # prints multiple useful information
    'test_vector' : False,
    'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
    'test_vector_mode' : 'check', # check / record
    ## in some cases, the test vector is performed by establishing a real 
    ## TCP connection. In such cases, sent packets are __effectively__ 
    ## being sent to the other peer and incoming packets are __effectively__ 
    ## being received by the other peer.  If that is the case, than 'remote'
    ## should be picked. 
    ## In other cases, packets are not sent and received, but instead locally
    ## provided from a file. 
    'test_vector_tls_traffic' : True, #'local' # / remote 
  },
  'lurk_client' : {
    'freshness' : 'null'
  }, 
  'tls13' : {
#    'illustrated_tls13': True,
#    'trace_mode': True,
#    'ecdhe_authentication' : True, ## ecdhe indicates certificate based authentication
    'ke_modes' : [ ], ## psk without ecdhe
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
    'ephemeral_method' : 'cs_generated', ## when ECDHE is needed. 
    ## these values are used for the supported_group (non mandatory) and key_share extension 
    'supported_ecdhe_groups' : [ 'x25519' ], #[ 'secp256r1', 'x25519', 'x448' ], 
  },
  'cs' : None
}





## PSK store
print( f"::Instantiating the Ticket/PSK database" )
engine_psk_db = pytls13.tls_client.EnginePSKDB()

##new_session_ticket_db = { (clt_conf[ 'server'][ 'ip' ], clt_conf[ 'server'][ 'port' ]) }

## configuration of the CS for 'Ed25519'
if clt_conf[ 'cs' ] is None :
  sig_scheme = 'ed25519'
  clt_cs_conf = pylurk.conf.Configuration( )
  clt_cs_conf.set_ecdhe_authentication( sig_scheme, conf_dir = './clt_cs' )
  clt_cs_conf.set_role( 'client' )
  clt_cs_conf.set_extention( ext=( 'tls13', 'v1' ) )
  clt_cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'debug' ] = clt_conf[ 'debug' ] 
  clt_conf[ 'cs' ] = clt_cs_conf.conf
print( f"::Instantiating the CS" )
cs = pylurk.cs.CryptoService( conf=clt_cs_conf.conf )
print( f"::Instantiating the Lurk client" )
lurk_client = pylurk.lurk_client.LurkTls13Client( cs )
try: 
    lurk_client.freshness = clt_conf[ 'lurk_client' ][ 'freshness' ]
except KeyError:
  pass

if clt_conf[ 'debug' ][ 'test_vector' ] is True or \
   clt_conf[ 'debug' ][ 'trace' ] is True :
  print( f"::Instantiating Test Vector" )
  test_vector =  pytls13.test_vector.TestVector( clt_conf[ 'debug' ] )
  if test_vector.record is True:
    test_vector.record_val( 'conf', clt_conf ) 

# indicates change_cipher_spec has been received
change_cipher_spec_received = False 

## tls handshake enables msg manipulations 
## ks is a useful lcompagnon but toinstantiate it one needs to know the TLS.Hash
## which is determined either by PSK or the selected cipher suite in (ECDHE mode. 
tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client' )
ks = None ## will be initialized at various step

if clt_conf[ 'debug' ][ 'test_vector' ] is True and \
   clt_conf[ 'debug' ][ 'test_vector_tls_traffic' ] is False: 
  no_traffic = True
else: 
  no_traffic = False


if no_traffic is False:
  print( f"::TCP session with the TLS server")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect( ( clt_conf[ 'server' ][ 'ip' ], clt_conf[ 'server' ][ 'port' ] ) )


print( f"::Sending ClientHello to the server\n--->" )
ch = pytls13.tls_client.ClientHello( conf=clt_conf )
if clt_conf[ 'debug' ][ 'test_vector' ] is True:
  ch.init_from_test_vector( lurk_client=lurk_client, tls_handshake=tls_handshake, ks=ks )
else:
  ch.init( lurk_client=lurk_client, tls_handshake=tls_handshake, ks=ks, engine_psk_db=engine_psk_db )
##ch = pytls13.tls_client.ClientHello( conf=clt_conf, lurk_client=lurk_client, tls_handshake=tls_handshake )
test_vector.handle_tls_clear_text_msg( ch, 'client' )
  
if no_traffic is False:
  s.sendall( ch.to_record_layer_bytes() )

if no_traffic is True:
  tls_msg_list = []
  for key in [ 'server_server_hello', 'server_change_cipher_spec', 'server_certificate_verify', 'server_finished' ]:
    if key in test_vector.db.keys():
      tls_msg = pytls13.TLSMsg( )
      tls_msg.from_record_layer_bytes( pylurk.utils.str_to_bytes( test_vector.db[ key ] ) ) 
      tls_msg_list.append( tls_msg ) 
else:
  stream_parser = pytls13.tls_client.TLSByteStreamParser( s )
while True:
  if no_traffic is True:
    tls_msg_list.pop( 0 )
  else:
    tls_msg = stream_parser.parse_single_msg( )
  if tls_msg.content_type == 'handshake': 
    test_vector.handle_tls_clear_text_msg( tls_msg, sender='server' ) 
    if tls_msg.content[ 'msg_type' ] == 'server_hello' : 
      print( "---Receiving ServerHello from the server\n--->" )
      sh = pytls13.tls_client.ServerHello( conf=clt_conf )
      ks = sh.handle_server_hello( clt_conf, lurk_client, ch, tls_handshake, ks, tls_msg, engine_psk_db )
      ### 
      c_register_tickets_status = sh.c_register_tickets
    ## generating cipher objects to encrypt / decrypt traffic
    cipher_suite = tls_handshake.get_cipher_suite()
    s_h_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, ks.secrets[ 'h_s' ] )
    s_h_cipher.debug( test_vector, description='server_handshake' )
    c_h_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, ks.secrets[ 'h_c' ] )
    c_h_cipher.debug( test_vector, description='client_handshake' )
    ## keep track of the messages for the next lurk request
    ## transcripts are performed at least to check the server finished 
    ## message. Why: The current tls_handshake erases the stored handshake 
    ## messages when a transcript is generated. As result, we are not able 
    ## to send the messages to the CS. In the future this might be avoided if 
    ## we ensure communication with the CS happens BEFORE any transcript is generated.
    ## to avoid such copy of handshake message, we may send the request of 
    ## the cs prior to validate the server finished.
    ## One reason this is not that "easy" is that CS performs some checks on 
    ## when a transcript makes sense to be performed and does not provide the 
    ## ability to generate a transcript of any possible suite of messages. This 
    ## is to contraint the transcript process on the CS perspective and we chose 
    ## not to remove these constraints. 
    tmp_handshake = []
  elif tls_msg.content_type == 'change_cipher_spec':
    print( f"--- E <- TLS Server: Receiving ChangeCipherSpec from the server\n--->" )
    test_vector.handle_tls_clear_text_msg( tls_msg, 'server' ) 
    change_cipher_spec = True
  elif tls_msg.content_type == 'application_data' :
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
    inner_tls_msg = tls_msg.decrypt_inner_msg( s_h_cipher, test_vector )

    if inner_tls_msg.content_type == 'handshake' :
#      if record is True: 
      if inner_tls_msg.content[ 'msg_type' ] == 'certificate_verify':
        ## we do update the transcript similarly to the server
        ## but also keep track of the handshake that we will need 
        ## to provide to the cs.  
        tls_handshake.transcript_hash( 'sig' )
      elif inner_tls_msg.content[ 'msg_type' ] == 'finished':
        sf = pytls13.tls_client.Finished( content=inner_tls_msg.content, sender='server' )
        sf.check_verify_data( tls_handshake, ks )        
###        c_verify_data = tls_handshake.get_verify_data( ks, role='server',\
###                          transcript_mode='finished') 
###        s_verify_data =  inner_tls_msg.content[ 'data' ][ 'verify_data' ]
###        pylurk.utils.print_bin( "client computed verify_data", c_verify_data )
###        pylurk.utils.print_bin( "server provided verify_data", s_verify_data )
###        if c_verify_data != s_verify_data : 
###          raise ValueError( "Client unable to validate Finished message" )
        tls_handshake.msg_list.append( inner_tls_msg.content )
        tmp_handshake.append( inner_tls_msg.content )
        break
      else: # other handshake messages
        pass
      tls_handshake.msg_list.append( inner_tls_msg.content )
      tmp_handshake.append( inner_tls_msg.content )
    else : # non handshake messages
      pass
    
if change_cipher_spec_received is True:
  print( "--- E -> TLS Server : Change Cipher Spec" )
##  tls_msg.content=b'\x01'
  tls_msg.content= { 'type' : 'change_cipher_spec' }
  tls_msg.content_type = 'change_cipher_spec'
  tls_msg.show()
  s.sendall( tls_msg.to_record_layer_bytes( ) )
  

print( "--- E -> CS: Application Secrets / Signature" )

##if clt_conf[ 'tls13' ][ 'session_resumption' ] is False:
##  last_exchange = True
##else :
##  last_exchange = False
## client_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
c_client_finished_sent = False
c_init_client_finished_sent = False

if sh.c_server_hello is True :
  if tls_handshake.is_certificate_request( ) is True:
    ## generates the certificate
    client_cert = pytls13.tls_client.Certificate( conf=clt_conf, content={}, sender='client' )
    client_cert.init_from_conf( certificate_request_context )
    tls_handshake.msg_list.append( client_cert )
    tmp_handshake.append( client_cert )
    ## certificate_verify is performed even without signature being generated
    ## to generate a_c, a_s
    client_cert_verif = pytls13.tls_client.CertificateVerify( conf=clt_conf, sender='client' )
    client_cert_verif.handle_c_client_finished( lurk_client, ks, handshake_msg_list )
    if client_cert_verif.content[ 'data' ][ 'signature' ] not in [ b'', None ]:
      tls_handshake.msg_list.append(  client_cert_verif.content )
  else: ## no client authentication 
     client_cert_verify = pytls13.tls_client.CertificateVerify( conf=clt_conf, sender='client' )
     client_cert_verify.handle_c_client_finished( lurk_client, ks, tmp_handshake )
  c_client_finished_sent = True
else: 
  if tls_handshake.is_certificate_request( ) is True : # or post_auth_proposed:
    ## proceed to c_init_client_finished
    c_init_client_finished_sent = True
  else:
## everything is generated by the Engine. In our use case, we assume 
## there are no signature by the Engine.
## client_cert_verify is just initialized provide the value c_client_finished to False
#    client_cert_verify = pytls13.tls_client.CertificateVerify( conf=clt_conf, sender='client' )
    ks.process( [ 'a_s', 'a_c' ], tls_handshake ) 

  ## if ecdhe in no or e_generated and
  ##   if auth_ecdhe or psk not in cs.
  
  ## else psk:

#server_hello_index = tls_handshake.server_hello_index( )
#handshake = tls_handshake.msg_list[ : ] 
##server_cert = { 'cert_type' : 'no_certificate', 'certificate' : b'' }
###for m in tmp_handshake:
###  if m[ 'msg_type' ] == 'certificate' :
###    tmp_handshake.remove( m )
###    server_cert = { 'cert_type' : 'uncompressed', 'certificate' : m[ 'data' ] }
###lurk_resp = lurk_client.resp( 'c_client_finished', \
###                              last_exchange=last_exchange, \
###                              handshake=tmp_handshake, \
###                              server_certificate=server_cert, \
###                              client_certificate=client_cert, \
###                              secret_request=[ 'a_c', 'a_s' ] )
###for secret in lurk_resp[ 'payload' ][ 'secret_list' ] :
###  ks.secrets[ secret[ 'secret_type' ] ] = secret[ 'secret_data' ]


print( "--- E -> TLS Server: Sending Client Finished" )

tls_handshake.update_finished( ks )
client_finished = pytls13.tls_client.Finished( conf=clt_conf, content=tls_handshake.msg_list[ - 1 ], sender='client' )
client_finished.encrypt_and_send( cipher=c_h_cipher, socket=s, sender='client', test_vector=test_vector ) 

s_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, ks.secrets[ 'a_s' ] )
s_a_cipher.debug( test_vector, description='server_application' )
c_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, ks.secrets[ 'a_c' ] )
c_a_cipher.debug( test_vector, description='client_application' )


print( "--- E -> TLS Server: Sending Data" )

app_data = pytls13.tls_client.TLSMsg( conf=clt_conf, content=b'ping', content_type='application_data', sender='client' )
app_data.encrypt_and_send( cipher=c_a_cipher, socket=s, sender='client', test_vector=test_vector ) 

ticket_list = []

while True:
#  msg = tls_msg.parse_single_msg( s )
  tls_msg = stream_parser.parse_single_msg( )
#  if msg[ 'type' ] == 'application_data' :
  if tls_msg.content_type == 'application_data' :
    print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
#    print( f"  - (msg bytes) [len {len( tls_msg.record_layer_bytes)}] : {tls_msg.content}" )
##    inner_tls_msg = pytls13.tls_client.TLSMsg()
#    inner_clear_text = s_a_cipher.decrypt( tls_msg.content )
##    inner_clear_text_struct, inner_clear_text = s_a_cipher.decrypt( tls_msg.content, debug=True )
##    test_vector.record_tls_cipher_text_msg_dec( tls_msg, inner_clear_text, inner_clear_text_struct, sender='server' )
##    inner_tls_msg.from_record_layer_struct( inner_clear_text_struct )
    inner_tls_msg = tls_msg.decrypt_inner_msg( s_a_cipher, test_vector )
    if inner_tls_msg.content_type == 'application_data':
      print( f"--- APPLICATION DATA: {inner_tls_msg.content}" )
    elif inner_tls_msg.content_type == 'handshake':
      if inner_tls_msg.content[ 'msg_type' ] == 'new_session_ticket':
        if clt_conf[ 'tls13' ][ 'session_resumption' ] is True :
          if c_register_tickets_status is True:
            new_session_ticket = pytls13.tls_client.NewSessionTicket( conf=clt_conf, content=inner_tls_msg.content )
            new_session_ticket.handle_c_register_ticket( lurk_client )
          new_session_ticket = new_session_ticket.content[ 'data' ]
          engine_psk_db.add( clt_conf, new_session_ticket, ks, tls_handshake )
##          new_session_ticket.handle_register( ks, engine_psk_db, client_cert_verify )
        print( f":: ticket_db {engine_psk_db.db}" )
##        if clt_conf[ 'tls13' ][ 'session_resumption' ] is True and\
##           client_cert_verif.c_client_finished is True:
##          ticket = inner_tls_msg.content[ 'data' ] 
##          lurk_resp = lurk_client.resp( 'c_register_tickets', \
##                              last_exchange=True, \
##                              ticket_list=[ ticket ] )
#                              ticket_list=[ inner_content[ 'data' ] ] )
##          engine_psk_db.add( new_session_ticket=new_session_ticket, ks=ks )
###          ## key
###          if clt_conf[ 'server'][ 'fqdn' ] is not None:
###            key = clt_conf[ 'server'][ 'fqdn' ]
###          else: 
###            key = ( clt_conf[ 'server'][ 'ip' ], clt_conf[ 'server'][ 'port' ] )
###          ## build ticket
###          psk = None
###          if ks.secret[ 'r' ] is not None:
###            psk = ks.compute_psk( ticket[ 'ticket_nonce' ] )
###          ticket_info = { 'ticket' : ticket, 
###                          'psk' : psk, 
###                          'tls_hash' : ks.get_tls_hash(), 
###                          'cipher_suite' : ks.cipher_suite }     
###          if key in new_session_ticket_db.keys(): 
###            new_session_ticket_db[ key ].append( ticket_info )
###          else: 
###            new_session_ticket_db[ key ] = [ ticket_info ]
###          print( new_session_ticket_db )
###        else:  
###          pass
  else:
    pass
