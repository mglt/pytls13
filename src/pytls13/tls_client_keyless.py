import socket 
import binascii
import secrets 

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.lurk.lurk_lurk
#import pylurk.conf 
import pylurk.utils
from pylurk.struct_lurk import LURKMessage

#import pylurk.tls13.struct_tls13
import pylurk.tls13.lurk_tls13
import pylurk.tls13.crypto_suites
import pylurk.lurk_client
import pylurk.cs

sys.path.insert(0, '/home/emigdan/gitlab/pytls13/src/') #pytls13
import  pytls13.struct_tls13
import pytls13.tls_client
#import pytls13.ciphers
import pytls13.test_vector

from cryptography.hazmat.primitives.hmac import HMAC

""" This client implements a TLS client with the following restrictions: 1) PSK authentication is not used with external keys. PSK is solely used in conjunction of session resumption. 2) PSK  
This scripts details the case where a TLS client performs a TLS handshake with:
* Certificate base authentication (EC)DHE
* Generates the (EC)DHE private key itself
* Does not supports post_handshake authentication, nor session resumption

Such interaction only involves a c_init_client_finished between the TLS Engine (E) and the CS
"""

clt_conf = {
  'role' : 'client',
  'server' : {
    'fqdn' : None,
    'ip' : '127.0.0.1',
#    'port' : 8400 #(debug illustrated TLS1.3)
    'port' : 8401 #(debug IdoBn)
#    'port' : 8402 #(default openssl)
#    'port' : 8403 # sajjad (mTLS)
  },
  'debug' : {
    'trace' : True,  # prints multiple useful information
    'test_vector' : False,
    'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
    'test_vector_mode' : 'check', # check / record
  },
  'lurk_client' : {
    'freshness' : 'null'
  }, 
  'tls13' : {
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
    'ephemeral_method' : 'cs_generated', ## cs_generated / e_generated when ECDHE is needed. 
    ## these values are used for the supported_group (non mandatory) and key_share extension 
    'supported_ecdhe_groups' : [ 'x25519' ], #[ 'secp256r1', 'x25519', 'x448' ],
  },
  'cs' : None
}


print( f"::Instantiating the Ticket/PSK database" )
engine_ticket_db = pytls13.tls_client.EngineTicketDB()


print( f"::Instantiating the CS" )
if clt_conf[ 'cs' ] is None :
  sig_scheme = 'ed25519'
  clt_cs_conf = pylurk.conf.Configuration( )
  clt_cs_conf.set_ecdhe_authentication( sig_scheme, conf_dir = './clt_cs' )
  clt_cs_conf.set_role( 'client' )
  clt_cs_conf.set_extention( ext=( 'tls13', 'v1' ) )
  clt_cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'debug' ] = clt_conf[ 'debug' ] 
  clt_conf[ 'cs' ] = clt_cs_conf.conf
cs = pylurk.cs.CryptoService( conf=clt_cs_conf.conf )



class ClientTLS13Session:

  def __init__( self, clt_conf, engine_ticket_db=None, cs=None ) :
    self.clt_conf = clt_conf
    self.engine_ticket_db = engine_ticket_db
    print( f"::Instantiating the Lurk client" )
    self.lurk_client = pylurk.lurk_client.LurkTls13Client( cs )
    try: 
        self.lurk_client.freshness = clt_conf[ 'lurk_client' ][ 'freshness' ]
    except KeyError:
      pass


    self.s = None  # TCP socket
    self.s_a_cipher = None
    self.c_a_cipher = None
    self.stream_parser = None
    self.test_vector = None 
    if self.clt_conf[ 'debug' ][ 'test_vector' ] is True or \
       self.clt_conf[ 'debug' ][ 'trace' ] is True :
      print( f"::Instantiating Test Vector" )
      self.test_vector =  pytls13.test_vector.TestVector( self.clt_conf[ 'debug' ] )
      if self.test_vector.record is True:
        self.test_vector.record_val( 'conf', self.clt_conf ) 
      
    ## tls handshake enables msg manipulations 
    ## ks is a useful companion but its instantiate needs 
    ## to know the TLS.Hash which is determined either by PSK or 
    ## the selected cipher suite in (ECDHE mode. 
    self.tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client', test_vector=self.test_vector )
    self.ks = None ## will be initialized at various step

    ## state variables
    self.c_register_tickets = False
    
  def connect( self ):
    
    # indicates change_cipher_spec has been received
    change_cipher_spec_received = False 
    
    print( f"::TCP session with the TLS server")
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.s.connect( ( self.clt_conf[ 'server' ][ 'ip' ], self.clt_conf[ 'server' ][ 'port' ] ) )
    
    print( f"::Sending ClientHello to the server\n--->" )
    ch = pytls13.tls_client.ClientHello( conf=self.clt_conf )
    if self.clt_conf[ 'debug' ][ 'test_vector' ] is True:
      ch.init_from_test_vector( lurk_client=self.lurk_client, tls_handshake=self.tls_handshake, ks=self.ks )
    else:
      ch.init( lurk_client=self.lurk_client, tls_handshake=self.tls_handshake, ks=self.ks, engine_ticket_db=self.engine_ticket_db )
      if self.tls_handshake.is_psk_proposed() is True:
        self.ks = ch.ks
    self.test_vector.handle_tls_clear_text_msg( ch, 'client' )
      
    self.s.sendall( ch.to_record_layer_bytes() )
    
    self.stream_parser = pytls13.tls_client.TLSByteStreamParser( self.s )
    while True:
      tls_msg = self.stream_parser.parse_single_msg( )
      if tls_msg.content_type == 'handshake': 
        self.test_vector.handle_tls_clear_text_msg( tls_msg, sender='server' ) 
        if tls_msg.content[ 'msg_type' ] == 'server_hello' : 
          print( "---Receiving ServerHello from the server\n--->" )
          sh = pytls13.tls_client.ServerHello( conf=self.clt_conf )
          self.ks = sh.handle_server_hello( self.lurk_client, ch, self.tls_handshake, self.ks, tls_msg ) 
          self.c_register_tickets = sh.c_register_tickets
        ## generating cipher objects to encrypt / decrypt traffic
        cipher_suite = self.tls_handshake.get_cipher_suite()
        s_h_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'h_s' ] )
        s_h_cipher.debug( self.test_vector, description='server_handshake' )
        c_h_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'h_c' ] )
        c_h_cipher.debug( self.test_vector, description='client_handshake' )
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
        self.test_vector.handle_tls_clear_text_msg( tls_msg, 'server' ) 
        change_cipher_spec = True
      elif tls_msg.content_type == 'application_data' :
        print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
        inner_tls_msg = tls_msg.decrypt_inner_msg( s_h_cipher, self.test_vector )
    
        if inner_tls_msg.content_type == 'handshake' :
          if inner_tls_msg.content[ 'msg_type' ] == 'certificate':
            certificate = pytls13.tls_client.Certificate( content=inner_tls_msg.content, sender='server' )
            server_public_key = certificate.get_public_key( )            
          if inner_tls_msg.content[ 'msg_type' ] == 'certificate_verify':
            certificate_verify = pytls13.tls_client.CertificateVerify( conf=clt_conf, content=inner_tls_msg.content, sender='server' )
            certificate_verify.check_signature( self.tls_handshake, server_public_key )
            ## we do update the transcript similarly to the server
            ## but also keep track of the handshake that we will need 
            ## to provide to the cs.
          elif inner_tls_msg.content[ 'msg_type' ] == 'finished':
            sf = pytls13.tls_client.Finished( content=inner_tls_msg.content, sender='server' )
            sf.check_verify_data( self.tls_handshake, self.ks )       
            
            self.tls_handshake.msg_list.append( inner_tls_msg.content )
            tmp_handshake.append( inner_tls_msg.content )
            break
          self.tls_handshake.msg_list.append( inner_tls_msg.content )
          tmp_handshake.append( inner_tls_msg.content )
        
    if change_cipher_spec_received is True:
      print( "--- E -> TLS Server : Change Cipher Spec" )
      tls_msg.content= { 'type' : 'change_cipher_spec' }
      tls_msg.content_type = 'change_cipher_spec'
      tls_msg.show()
      self.s.sendall( tls_msg.to_record_layer_bytes( ) )
      
    
    print( "--- E -> CS: Application Secrets / Signature" )
    
    c_client_finished_sent = False
    c_init_client_finished_sent = False
    
    if sh.c_server_hello is True :
      if self.tls_handshake.is_certificate_request_state is True:
        ## generates the certificate
        client_cert = pytls13.tls_client.Certificate( conf=self.clt_conf, content={}, sender='client' )
        client_cert.init_from_conf( certificate_request_context )
        self.tls_handshake.msg_list.append( client_cert )
        tmp_handshake.append( client_cert )
        ## certificate_verify is performed even without signature being generated
        ## to generate a_c, a_s
        client_cert_verif = pytls13.tls_client.CertificateVerify( conf=self.clt_conf, sender='client' )
        client_cert_verif.handle_c_client_finished( self.lurk_client, self.ks, handshake_msg_list )
        if client_cert_verif.content[ 'data' ][ 'signature' ] not in [ b'', None ]:
          self.tls_handshake.msg_list.append(  client_cert_verif.content )
      else: ## no client authentication 
         client_cert_verify = pytls13.tls_client.CertificateVerify( conf=self.clt_conf, sender='client' )
         client_cert_verify.handle_c_client_finished( self.lurk_client, self.ks, tmp_handshake )
      c_client_finished_sent = True
    else: 
      if self.tls_handshake.is_certificate_request( ) is True : # or post_auth_proposed:
        ## proceed to c_init_client_finished
        c_init_client_finished_sent = True
      else:
    ## everything is generated by the Engine. In our use case, we assume 
    ## there are no signature by the Engine.
    ## client_cert_verify is just initialized provide the value c_client_finished to False
    #    client_cert_verify = pytls13.tls_client.CertificateVerify( conf=self.clt_conf, sender='client' )
        self.ks.process( [ 'a_s', 'a_c' ], self.tls_handshake ) 
    
    print( "--- E -> TLS Server: Sending Client Finished" )
    self.tls_handshake.update_finished( self.ks )
    client_finished = pytls13.tls_client.Finished( conf=self.clt_conf, content=self.tls_handshake.msg_list[ - 1 ], sender='client' )
    client_finished.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 
    
    self.s_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'a_s' ] )
    self.s_a_cipher.debug( self.test_vector, description='server_application' )
    self.c_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'a_c' ] )
    self.c_a_cipher.debug( self.test_vector, description='client_application' )
    
  def send( self, data ):    
    print( "--- E -> TLS Server: Sending Data" )
    
    app_data = pytls13.tls_client.TLSMsg( conf=self.clt_conf, content=data, content_type='application_data', sender='client' )
    app_data.encrypt_and_send( cipher=self.c_a_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 



  def recv( self ):
    while True:
      tls_msg = self.stream_parser.parse_single_msg( )
      if tls_msg.content_type == 'application_data' :
        print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
        inner_tls_msg = tls_msg.decrypt_inner_msg( self.s_a_cipher, self.test_vector )
        if inner_tls_msg.content_type == 'application_data':
          return inner_tls_msg.content
        elif inner_tls_msg.content_type == 'handshake':
          if inner_tls_msg.content[ 'msg_type' ] == 'new_session_ticket':
            new_session_ticket = pytls13.tls_client.NewSessionTicket( conf=self.clt_conf, content=inner_tls_msg.content )
            if self.c_register_tickets is True:
              new_session_ticket.handle_c_register_ticket( self.lurk_client )
            ## in our case the c_register is only set to True 
            ## when the use of CS provides an advantage, that is in our case
            ## psk cannot be generate 
            else:
              if self.clt_conf[ 'tls13' ][ 'session_resumption' ] is True :
                self.ks.process( 'r', self.tls_handshake )  
            nst = new_session_ticket.content[ 'data' ]
            self.engine_ticket_db.register( self.clt_conf, nst, self.ks, self.tls_handshake )
            return b''
      else:
        pass


session = ClientTLS13Session( clt_conf, engine_ticket_db, cs )
print( '\n' )
print( "======================================================" )
print( "========= TLS with certificate authentication ========" )
print( "======================================================\n" )
session.connect()
session.send( b'ping' )
print( f"APPLICATION DATA - [cert]: {session.recv()}" )

print( f":: Engine Ticket DB: {engine_ticket_db.db}" )
print( "======================================================" )
print( "============= TLS with PSK authentication ============" )
print( "======================================================\n" )
session = ClientTLS13Session( clt_conf, engine_ticket_db, cs )
session.connect()
session.send( b'ping' )
print( f"APPLICATION DATA - [psk]: {session.recv()}" )

