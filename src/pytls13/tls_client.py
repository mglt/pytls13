import socket 
import binascii
import secrets 
import time

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
import pytls13.struct_tls13
import pytls13.tls_client_handler
#import pytls13.ciphers
import pytls13.test_vector
import tls_handler

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
  'type' : 'tls13',
###  'server' : {
###    'fqdn' : None,
###    'ip' : '127.0.0.1',
####    'port' : 8400 #(debug illustrated TLS1.3)
####    'port' : 8401 #(debug IdoBn)
####    'port' : 8402 #(default openssl without authentication)
###    'port' : 8403 #(default openssl with client authentication (mTLS) )
####    'port' : 8404 # sajjad (mTLS)
####   
###  },
  'debug' : {
    'trace' : True,  # prints multiple useful information
    'test_vector' : False,
    'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
    'test_vector_mode' : 'check', # check / record
  },
  'lurk_client' : {
    'freshness' : 'sha256', 
    'connectivity_type' : 'lib_cs', #'stateless_tcp', # 'lib_cs', # 'stateless_tcp'
    'fqdn' : None, 
    'ip' : "127.0.0.1", 
    'port' : 9999,
    
  }, 
  'tls13' : { ## maybe that shoudl be called the engine
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
    'ephemeral_method' : 'cs_generated', ## cs_generated / e_generated when ECDHE is needed. otherwise can be set to 'no_secret' 
    ## these values are used for the supported_group (non mandatory) and key_share extension 
    'supported_ecdhe_groups' : [ 'x25519' ], #[ 'secp256r1', 'x25519', 'x448' ],
    ### These MUST be provided in the cs configuration part
#    'tls_client_private_key' : '/home/emigdan/gitlab/pytls13/tests/openssl/client.key',
#    'tls_client_certificate_list' : [ '/home/emigdan/gitlab/pytls13/tests/openssl/client.crt']
  },
  ## parameters associated to the cryptographic material being used by 
  ## the TLS client. 
  ## When the CS is external, only the certificat enetry list is needed. 
  ## When the CS is instantiated by the TLS client, it is likely that 
  'cs' :{ 
    ( 'tls13', 'v1' ) : { 
      'public_key': ['/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/_Ed25519PublicKey-ed25519-X509.der'],
      'private_key': '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs/_Ed25519PrivateKey-ed25519-pkcs8.der', 
      'sig_scheme': ['ed25519'], 
#      '_cert_type': 'X509', 
#      '_cert_entry_list': [{'cert': b"0\x82\x01!0\x81\xd4\xa0\x03\x02\x01\x02\x02\x14%|u`\xed2\x99\xcd\x18\xc4=\xbdK\x07\xd1\xe2\xdc\xd2\x8e\x180\x05\x06\x03+ep0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0\x1e\x17\r221205205644Z\x17\r230105205644Z0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0*0\x05\x06\x03+ep\x03!\x00\xd9\xa4\x03\xfa\x1f\xad'c&\x8d\x80~z\x93+,\xb77B\x9e\xf6\xf7\x06\xb5\r\xfc(\x9fIy\xdcU\xa3,0*0\x1a\x06\x03U\x1d\x11\x04\x130\x11\x82\x0fcryptography.io0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x05\x06\x03+ep\x03A\x00\x844K\x00\xbb\xb2R]\xaf\x96\xa1\x8bW\x0b=Et\xd8\xeajg\x9d\xace\x02p\xbaC\xbb\xa6\xd3\x9a,\xa0K\x17J\xbe\x0b\xd9\xc4\xaaL_\x16\x10|\x8b2.c\xec*\x08\xcc\xee9\x7fu\xcf\xca\xe5\xdc\x00", 'extensions': []}], 
#      '_finger_print_entry_list': [{'finger_print': b'\xec\x86\xfd!', 'extensions': []}], 
#      '_finger_print_dict': {b'\xec\x86\xfd!': b"0\x82\x01!0\x81\xd4\xa0\x03\x02\x01\x02\x02\x14%|u`\xed2\x99\xcd\x18\xc4=\xbdK\x07\xd1\xe2\xdc\xd2\x8e\x180\x05\x06\x03+ep0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0\x1e\x17\r221205205644Z\x17\r230105205644Z0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fcryptography.io0*0\x05\x06\x03+ep\x03!\x00\xd9\xa4\x03\xfa\x1f\xad'c&\x8d\x80~z\x93+,\xb77B\x9e\xf6\xf7\x06\xb5\r\xfc(\x9fIy\xdcU\xa3,0*0\x1a\x06\x03U\x1d\x11\x04\x130\x11\x82\x0fcryptography.io0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x05\x06\x03+ep\x03A\x00\x844K\x00\xbb\xb2R]\xaf\x96\xa1\x8bW\x0b=Et\xd8\xeajg\x9d\xace\x02p\xbaC\xbb\xa6\xd3\x9a,\xa0K\x17J\xbe\x0b\xd9\xc4\xaaL_\x16\x10|\x8b2.c\xec*\x08\xcc\xee9\x7fu\xcf\xca\xe5\xdc\x00"} 
    }
#      'debug' : {
#        'trace' : True,  # prints multiple useful information
#        'test_vector' : False,
#        'test_vector_file' : '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json',
#        'test_vector_mode' : 'check', # check / record
#      }
  }
}







class ClientTLS13Session:

  def __init__( self, clt_conf, engine_ticket_db=None, cs=None ) :
    self.clt_conf = clt_conf
    self.engine_ticket_db = engine_ticket_db
    print( f"::Instantiating the Lurk client" )
   
##    self.lurk_client = pylurk.lurk_client.Tls13LurkClient( self.clt_conf[ 'lurk_client' ], cs=cs )
    self.lurk_client = pylurk.lurk_client.get_lurk_client_instance( self.clt_conf[ 'lurk_client' ], cs=cs )

    resp = self.lurk_client.resp( 'ping' )
    if resp[ 'status' ] != 'success' :
      raise ValueError( "Unable to reach Crypto Service" )
#    self.lurk_client = pylurk.lurk_client.LurkTls13Client( cs )
#    try: 
#        self.lurk_client.freshness = clt_conf[ 'lurk_client' ][ 'freshness' ]

#except KeyError:
#      pass


    self.s = None  # TCP socket
    self.s_a_cipher = None
    self.c_a_cipher = None
    self.stream_parser = None
    self.test_vector = None 
    if self.clt_conf[ 'debug' ][ 'test_vector' ] is True or \
       self.clt_conf[ 'debug' ][ 'trace' ] is True :
      print( f"::Instantiating Test Vector" )
      self.test_vector =  pytls13.test_vector.TestVector( self.clt_conf[ 'debug' ] )
#      if self.test_vector.record is True:
#        self.test_vector.record_val( 'conf', self.clt_conf ) 
      
    ## tls handshake enables msg manipulations 
    ## ks is a useful companion but its instantiate needs 
    ## to know the TLS.Hash which is determined either by PSK or 
    ## the selected cipher suite in (ECDHE mode. 
    self.tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client', test_vector=self.test_vector )
    self.ks = None ## will be initialized at various step


    ## state variables
    ##
    ## The state variables reflect the state diagram mentioned below:
    ##
    ##                ^ (self.c_init_client_hello)
    ## ClientHello    | method is 'cs_generated' | no
    ##   Derivation   | or PSK in CS Proposed    |----------+
    ## ClientHello    |     yes |                           |
    ##   sent      -->v  c_init_client_hello                |
    ## ServerHello -->^         |        |     certificate_request or   no
    ##   received     |  c_server_hello (a)    post_hand_auth_proposed ---+  
    ##                |         |        |              yes |             | 
    ## ServerHello    |  c_client_finished        c_init_client_finished  |
    ##   Treatment    |         |                           |             |
    ## clientFinished |         +---------+-----------------+     no CS protection
    ##   sent      -->v                   |                       provided   
    ##                ^                   |     
    ##                |+----------------->+     
    ## Posthandshake  ||        +---------+-----------+
    ## Treatment      ||        |                     |
    ##                || (self.post_hand_auth)  (self.c_register_tickets)
    ##                ||post_hand_auth_proposed method is 'cs_generated' | 
    ##                ||        +               or  PSK in use in CS     |
    ##                ||CertificateRequest            +  
    ##                ||        |               NewSessionTicket
    ##                ||        |                     | 
    ##                ||c_post_hand_auth        c_register_tickets
    ##                ||        |                     | 
    ##                ||        +-------+-------------+
    ##                ||                | 
    ##                v+----------------+     
    ##                                  |     
    ##                             LURK session
    ##                             closed           
    ##
    ## (a) ( optional: when method is 'e_generated' or 'no_secret')  and chosen 
    ## PSK not in CS, E may generate h_c and h_s, but these may also be generates 
    ## by CS.
    ## The state variable used in the program are mentioned between () 
    ## 
    ## Determine if the TLS client will register the NewSessionTicket to the CS
    ## This includes the condition mentioned in the diagram as: 
    ## method is 'cs_generated' or  PSK in use in CS
    ## as well as some configuration parameters such as whether the TLS Client 
    ## enables session resumption. 
    ## When set to True c_register_tickets exchanges are expected upon receiving 
    ## a NewSessionTicket.
    ## This variable is set by the ServerHello class (see set_lurk_session_state ) 
    self.c_register_tickets = None
    ## Determine if the TLS client has proposed Post Handshake Authentication
    ## While the variable is read from the ClientHello, this condition is  
    ## expected to reflect directly the configuration. 
    self.post_hand_auth = None
    ## Indicates a LURK session has been initiated. This is used to distinguishes between 
    ## c_init_client_finished and a c_client_finished exchange. 
    self.c_init_client_hello = None

  def connect( self, ip=None, port=443 ):
    
    # indicates change_cipher_spec has been received
    change_cipher_spec_received = False 
    
    print( f"::TCP session with the TLS server")
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#    self.s.connect( ( self.clt_conf[ 'server' ][ 'ip' ], self.clt_conf[ 'server' ][ 'port' ] ) )
    self.s.connect( ( ip, port ) )
    ## ip, port, fqdn are necessary to manage the tickets 
    ## and potentially the SNI. 
    ## As a result, we add them to the conf file so it can 
    ## be accessible by every object. 
    server = { 'ip' : ip, 'port' : port, 'fqdn':None }
    self.clt_conf[ 'server' ] = server
    
    print( f"::Sending ClientHello to the server\n--->" )
    ch = pytls13.tls_client_handler.ClientHello( conf=self.clt_conf )
    if self.clt_conf[ 'debug' ][ 'test_vector' ] is True:
      ch.init_from_test_vector( lurk_client=self.lurk_client, tls_handshake=self.tls_handshake, ks=self.ks )
    else:
      ch.init( lurk_client=self.lurk_client, tls_handshake=self.tls_handshake, ks=self.ks, engine_ticket_db=self.engine_ticket_db )
      if self.tls_handshake.is_psk_proposed() is True:
        self.ks = ch.ks
    self.test_vector.handle_tls_clear_text_msg( ch, 'client' )
    self.post_hand_auth = self.tls_handshake.is_post_hand_auth_proposed( )  
    self.c_init_client_hello = ch.c_init_client_hello
    self.s.sendall( ch.to_record_layer_bytes() )
    
    self.stream_parser = pytls13.tls_client_handler.TLSByteStreamParser( self.s )
    while True:
      tls_msg = self.stream_parser.parse_single_msg( )
      if tls_msg.content_type == 'handshake': 
        self.test_vector.handle_tls_clear_text_msg( tls_msg, sender='server' ) 
        if tls_msg.content[ 'msg_type' ] == 'server_hello' : 
          print( "---Receiving ServerHello from the server\n--->" )
          sh = pytls13.tls_client_handler.ServerHello( conf=self.clt_conf )
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
        ## when decryp[tion cannot be performed an InvalidTag error is raised. 
        ## we bad_record_mac
        ## we should replace:
        ## try:
        ## 
        ## except InvalidTag:
        ## 
        ## raise TLSAlert (bad_record_mac, from client )
        ## responds with the alert to the TLS server 
        ## raise the alert on the TLS client side
        if inner_tls_msg.content_type == 'alert':
          raise  tls_handler.TLSAlert( inner_tls_msg.content[ 'level' ],\
                                       inner_tls_msg.content[ 'description' ] )
        elif inner_tls_msg.content_type == 'handshake' :
          if inner_tls_msg.content[ 'msg_type' ] == 'certificate_request':
            pylurk.utils.print_bin( "built certificate_request", pytls13.struct_tls13.Handshake.build( inner_tls_msg.content ) ) 
          elif inner_tls_msg.content[ 'msg_type' ] == 'certificate':
            certificate = pytls13.tls_client_handler.Certificate( content=inner_tls_msg.content, sender='server' )
            server_public_key = certificate.get_public_key( )            
          elif inner_tls_msg.content[ 'msg_type' ] == 'certificate_verify':
            self.tls_handshake.is_certificate_request( )
            certificate_verify = pytls13.tls_client_handler.CertificateVerify( conf=clt_conf, content=inner_tls_msg.content, sender='server' )
            certificate_verify.check_signature( self.tls_handshake, server_public_key )
            ## we do update the transcript similarly to the server
            ## but also keep track of the handshake that we will need 
            ## to provide to the cs.
          elif inner_tls_msg.content[ 'msg_type' ] == 'finished':
            sf = pytls13.tls_client_handler.Finished( content=inner_tls_msg.content, sender='server' )
            sf.check_verify_data( self.tls_handshake, self.ks )       
            
            self.tls_handshake.msg_list.append( inner_tls_msg.content )
            tmp_handshake.append( inner_tls_msg.content )
            break
          self.tls_handshake.msg_list.append( inner_tls_msg.content )
          tmp_handshake.append( inner_tls_msg.content )
        elif inner_tls_msg.content_type == 'application_data':
          return inner_tls_msg.content
        else:
          raise ValueError( f"unexpected packet received: "\
            f"type: {inner_tls_msg.type} , content: {inner_tls_msg.content}" )

    if change_cipher_spec_received is True:
      print( "--- E -> TLS Server : Change Cipher Spec" )
      tls_msg.content= { 'type' : 'change_cipher_spec' }
      tls_msg.content_type = 'change_cipher_spec'
      tls_msg.show()
      self.s.sendall( tls_msg.to_record_layer_bytes( ) )
      
    
    print( "--- E -> CS: Application Secrets / Signature" )
    ## At this stage the Engine performs the following tasks:
    ## 1) computation of the application secrets and 
    ## 2) the necessary messages to be sent to the TLS server.    
    ## 
    ## The computation of the application secrets are using the
    ## context ClientHello... server Finished so no additional 
    ## message needs to be generated by the TLS client for that purpose. 
    ## 
    ## The messages generated by the TLS client includes a 
    ## Certificate and CertificateVerify message if the TLS client is
    ## being authenticated, that is a CertificateRequest has been sent 
    ## by the TLS server. In addition, it necessarily includes a 
    ## client Finished message
    ##
    ## lurk-tls13 assumes that the private key is always protected by the CS. 
    ## As a result, the TLS client authentication is always performed via 
    ## an interaction with the CS.    
    ## If the TLS client has already sent a c_init_client_hello 
    ## or a c_server_hello then the generation of the signature is 
    ## performed via a c_client_finished exchange. 
    ## If the TLS client has not proceeded to any previous exchange, than the 
    ## signature is generated via a c_init_client_finished.
    ## 
    ## The generation of the application secrets requires an interaction only if
    ## the CS has generated the ECDHE (cs_generated). 
    ##
    ## 
     
    ## if a LURK session has already been established, a c_client_finished exchange is necessary to 
    ## retrieve the application secrets and (when the TLS client is authenticated the signature)
    if self.c_init_client_hello is True:
      ## the TLS client is authenticated 
      if self.tls_handshake.is_certificate_request_state is True:
        ## generates the certificate
        client_cert = pytls13.tls_client_handler.Certificate( conf=self.clt_conf, content={}, sender='client' )
        client_cert.init_from_conf( )
        client_cert.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 
        self.tls_handshake.msg_list.append( client_cert.content )
        tmp_handshake.append( client_cert.content )
        ## generates the CertificatVerify
        client_cert_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, sender='client' )
        client_cert_verify.handle_c_client_finished( self.lurk_client, self.ks, tmp_handshake, self.c_register_tickets )
        self.tls_handshake.msg_list.append(  client_cert_verify.content )
        client_cert_verify.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 
      ## the TLS client is not authenticated
      ## There is no client_cert_verify message but we use the client_cert_verify handles the  
      ## interaction with the CS to retrieve the application secrets.
      ## The returned signature is empty.
      else: 
         client_cert_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, sender='client' )
         client_cert_verify.handle_c_client_finished( self.lurk_client, self.ks, tmp_handshake, self.c_register_tickets )
    ## No existing LURK session
    else:
      ## the TLS Client is authenticated or post authentication has been proposed 
      ## In this case interaction with the CS is performed via a c_init_client_finished exchange
      if self.tls_handshake.is_certificate_request( ) is True or self.post_hand_auth is True  :
        self.ks.process( [ 'a_s', 'a_c' ], self.tls_handshake )
        ## this is a hack
        tmp_handshake.insert( 0, sh.content )
        tmp_handshake.insert( 0, ch.content )
        tmp_handshake[ 0 ][ 'data' ][ 'random' ] = ch.init_random

        client_cert = pytls13.tls_client_handler.Certificate( conf=self.clt_conf, content={}, sender='client' )
        client_cert.init_from_conf( )
        client_cert.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 
        self.tls_handshake.msg_list.append( client_cert.content )
        tmp_handshake.append( client_cert.content )
        client_cert_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, sender='client' )
        client_cert_verify.handle_c_init_client_finished( self.lurk_client, self.ks, tmp_handshake, self.c_register_tickets )
        self.tls_handshake.msg_list.append(  client_cert_verify.content )
        client_cert_verify.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 
        
      ## TLS client is no authenticated
      ## This basically means that everything has been handled by E which also 
      ## generates the application secrets
      else:
        self.ks.process( [ 'a_s', 'a_c' ], self.tls_handshake ) 
    
    print( "--- E -> TLS Server: Sending Client Finished" )
    self.tls_handshake.update_finished( self.ks )
    client_finished = pytls13.tls_client_handler.Finished( conf=self.clt_conf, content=self.tls_handshake.msg_list[ -1 ], sender='client' )
    client_finished.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 
    self.s_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'a_s' ] )
    self.s_a_cipher.debug( self.test_vector, description='server_application' )
    self.c_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'a_c' ] )
    self.c_a_cipher.debug( self.test_vector, description='client_application' )
    
  def send( self, data ):    
    print( "--- E -> TLS Server: Sending Data" )
    
    app_data = pytls13.tls_client_handler.TLSMsg( conf=self.clt_conf, content=data, content_type='application_data', sender='client' )
    app_data.encrypt_and_send( cipher=self.c_a_cipher, socket=self.s, sender='client', test_vector=self.test_vector ) 



  def recv( self ):
    while True:
      tls_msg = self.stream_parser.parse_single_msg( )
      if tls_msg.content_type == 'application_data' :
        print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
        inner_tls_msg = tls_msg.decrypt_inner_msg( self.s_a_cipher, self.test_vector )
        if inner_tls_msg.content_type == 'alert':
          raise  tls_handler.TLSAlert( inner_tls_msg.content[ 'level' ], \
                                       inner_tls_msg.content[ 'description' ] )
        elif inner_tls_msg.content_type == 'application_data':
          return inner_tls_msg.content
        elif inner_tls_msg.content_type == 'handshake':
          if inner_tls_msg.content[ 'msg_type' ] == 'new_session_ticket':
            new_session_ticket = pytls13.tls_client_handler.NewSessionTicket( conf=self.clt_conf, content=inner_tls_msg.content )
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
#        elif inner_tls_msg.content_type == 'alerte'
      else:
        raise ValueError( f"unexpected packet received: "\
          f"type: {inner_tls_msg.type} , content: {inner_tls_msg.content}" )



class SimpleTLS13Client:

  def __init__( self, conf ):
    self.conf = conf
    self.cs = None
    ## Instantiates a CS only when CS is specified as instantiated by the 
    ## TLS client, that is with the connectivity type 'lic_cs'. 
    ## Other types includes a server that is started by another process 
    ## and potentially shared by multiple TLS Clients.
    if self.conf[ 'lurk_client' ][ 'connectivity_type' ] == 'lib_cs':
#      self.cs = pylurk.cs.CryptoService( conf=clt_cs_conf.conf )
      cs_conf = self.generate_lib_cs_conf( self.conf )
      self.cs = pylurk.cs.get_cs_instance( cs_conf )
      for k in [ '_cert_entry_list',  '_cert_type',  '_finger_print_entry_list', '_finger_print_dict'  ]:
        self.conf[ 'cs' ][ ( 'tls13', 'v1' ) ][ k ] = \
          cs_conf[ ( 'tls13', 'v1' ) ] [ k ]  
#      self.cs = pylurk.cs.get_cs_instance( self.conf[ 'cs' ] )
    self.engine_ticket_db = pytls13.tls_client_handler.EngineTicketDB()
    
  def new_session( self ):
#    conf = self.conf
#    server = { 'ip' : ip, 'port' : port, 'fqdn':fqdn }
#    conf[ 'server' ] = server
    return ClientTLS13Session( self.conf, self.engine_ticket_db, self.cs )

  def generate_lib_cs_conf( self, clt_conf ):
    """ generates the cs configuration from the generic TLS client configuration

    """
    lurk_client_conn_type = clt_conf[ 'lurk_client' ][ 'connectivity_type' ] 
    if lurk_client_conn_type != 'lib_cs':
      raise ConfigurationError( f"CS configuration is expected to be generated "\
        f"only for lurk_client with connectivity type: {lurk_client_conn_type}" )                          
   ## configuration may consider some elements provided by the TLS client
    if 'cs' in clt_conf.keys():
      init_cs_conf = clt_conf[ 'cs' ]
    if init_cs_conf is None:
      init_cs_conf = {}
    cs_conf = pylurk.conf.Configuration( )
    ## merging init_cs 
    cs_conf.merge( init_cs_conf )
    cs_conf.set_role( 'client' )
    ## setting / cleaning  connectivity configuration
    cs_conf.conf[ 'connectivity' ][ 'type' ] = lurk_client_conn_type
###  if con_type == 'lib_cs' :
    for k in [ 'fqdn', 'ip_address', 'port' ]:
      if k in cs_conf.conf[ 'connectivity' ].keys():
        del cs_conf.conf[ 'connectivity' ][ k ]
    ## if key material has not been defined we need to generate it
    ## but we shoudl not overwrite it if the material already exists
    ## 
    ## Note 1 that sig_scheme may be derived from the public / private
    ## keys (except for RSA).
    ## Note 2 public key can be deribed from the private key
    ## 
    ## While the 3 parameters are required to prevent the generation of the 
    ## the keys, we actually only nee the private or private + sig_scheme
    ## such refinement ar eleft for future work.
    ## 
    ## Note that we consider that these parameters MUST be specified in 
    ## init_cs_conf and not the template
    if 'public_key' not in init_cs_conf[ ( 'tls13', 'v1' ) ].keys() or\
       'private_key' not in init_cs_conf[ ( 'tls13', 'v1' ) ].keys() or\
       'sig_scheme'  not in init_cs_conf[ ( 'tls13', 'v1' ) ].keys() :
      if 'sig_scheme' not in init_cs_conf[ ( 'tls13', 'v1' ) ].keys():
        sig_scheme = 'ed25519'
      try: 
        conf_dir = os.path.dirname( init_cs_conf[ 'private_key'] )
      except: 
        try:
          conf_dir = os.path.dirname( init_cs_conf[ 'public_key'] )
        except:
          conf_dir = './'

#      cs_conf.set_ecdhe_authentication( sig_scheme, conf_dir = '/home/emigdan/gitlab/pytls13/src/pytls13/clt_cs' )
      cs_conf.set_ecdhe_authentication( sig_scheme, conf_dir = conf_dir )
    ## Instantiates the public / privates keys, the certificates, 
    ## finger prints
    ## These are necessary to build the Certificate Payload
    ## 
    cs_conf.set_extention( ext=( 'tls13', 'v1' ) )
    ## removing unecessy lurk exchange
    ## we need to complete this depending on the configuration ( for example
    ## if there is no session resumption, no post handshake, 
    for k in cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'] :
      if ( clt_conf[ 'role' ] == 'client' and k[0:2] == 's_' ) or\
         ( clt_conf[ 'role' ] == 'server' and k[0:2] == 'c_' ):
        cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'type_authorized'].remove( k )

    ## setting the debug information. debug parameters may be set 
    ## generic to the cs or generic to the tls13 extension
    ## note that the specific configuration for tls13 overwrite
    # the generic configuration
    try:  
      cs_conf.conf[ 'debug' ] = clt_conf[ 'debug' ]
    except KeyError:
      pass
    try: 
      cs_conf.conf[ ( 'tls13', 'v1' ) ][ 'debug' ] = clt_conf[ 'debug' ]
    except KeyError:
      pass
##
##    ## setting / cleaning  connectivity configuration
##    cs_conf.conf[ 'connectivity' ][ 'type' ] = lurk_client_conn_type
#####  if con_type == 'lib_cs' :
##    for k in [ 'fqdn', 'ip_address', 'port' ]:
##      if k in cs_conf.conf[ 'connectivity' ].keys():
##        del cs_conf.conf[ 'connectivity' ][ k ]
#####  else:
#####    for k in [ 'fqdn', 'ip', 'port' ]:
#####      if k in clt_cs_conf.conf[ 'connectivity' ].keys():
#####        clt_cs_conf.conf[ 'connectivity' ][ k ] = clt_conf[ 'lurk_client' ][ k ]
#####  clt_conf[ 'cs' ] = clt_cs_conf.conf
    return cs_conf.conf

####    'port' : 8400 #(debug illustrated TLS1.3)
####    'port' : 8401 #(debug IdoBn)

if __name__ == "__main__" :

  tls_server_list = { \
    'illustrated_tls13' : {
       'ip' : '127.0.0.1', 
       'port' : 8400, 
       'description' : f"  - Illustrated TLS1.3 Server\n"\
                       f"   - unauthenticated client\n", 
       'sent_data' : b'ping' }, 
     'openssl_uclient' : {
       'ip' : '127.0.0.1', 
       'port' : 8402, 
       'description' : f"  - OpenSSL TLS1.3 Server\n"\
                       f"  - unauthenticated client\n" }, 
     'openssl_auth_client' : {
       'ip' : '127.0.0.1', 
       'port' : 8403, 
       'description' : f"  - OpenSSL TLS1.3 Server\n"\
                       f"  - authenticated client\n" }, 
  }

  cs_list = {

  }

  for tls_server in tls_server_list.keys():       
    if tls_server == 'illustrated_tls13' : 
      clt_conf[ 'debug' ][ 'test_vector' ] = True
      clt_conf[ 'debug' ][ 'test_vector_file' ] = '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json'
      clt_conf[ 'debug' ][ 'test_vector_mode' ] = 'record' # check / record
      clt_conf[ 'lurk_client' ][ 'freshness' ] = 'null'
      ## there is no session resumption in the case of illustrated TLS 1.3
      clt_conf[ 'tls13' ][ 'session_resumption' ] = False
    else: 
      clt_conf[ 'debug' ][ 'test_vector' ] = False
      clt_conf[ 'tls13' ][ 'session_resumption' ] = True
      clt_conf[ 'lurk_client' ][ 'freshness' ] = 'sha256'
#  for port in [ 8402 ]: #8400] : #, 8402, 8403 ]:
    for ephemeral_method in [ 'cs_generated', 'e_generated' ] :
####    'port' : 8400 #(debug illustrated TLS1.3)
####    'port' : 8401 #(debug IdoBn)
####    'port' : 8402 #(default openssl without authentication)
###    'port' : 8403 #(default openssl with client authentication (mTLS) )
####    'port' : 8404 # sajjad (mTLS)
#      clt_conf[ 'server' ][ 'port' ] = port
      
#      ctx = ""
      clt_conf[ 'tls13' ][ 'ephemeral_method' ] = ephemeral_method
#      ctx += f"  - ECDHE {ephemeral_method}"
      tls_client = SimpleTLS13Client( clt_conf )
      print( "++==================================================++" )
      print( f"TLS Client Configuration:\n{clt_conf}" )
      print( "++==================================================++\n" )
      print( '\n' )
      print( "++==================================================++" )
      print( f"CS Configuration:\n"\
             f"{tls_client.generate_lib_cs_conf( clt_conf )}" )
      print( "++==================================================++\n" )
      
      tls_server_param = tls_server_list[ tls_server ]
      ip = tls_server_param[ 'ip' ]
      port = tls_server_param[ 'port' ]
      try: 
        sent_data = tls_server_param[ 'sent_data' ] 
      except KeyError:
        sent_data = b'GET /index.html' 

      print( '\n' )
      print( "++==================================================++" )
      print( f"{tls_server_param[ 'description' ]}\n"\
             f"  - ECDHE {ephemeral_method}" )
      print( "++==================================================++\n" )
    
#      print( f"::Instantiating the Ticket/PSK database" )
#      engine_ticket_db = pytls13.tls_client_handler.EngineTicketDB()
#      session = ClientTLS13Session( clt_conf, engine_ticket_db, cs )
      print( '\n' )
#      print( f":: Engine Ticket DB: {engine_ticket_db.db}" )
      print( "======================================================" )
      print( "========= TLS with certificate authentication ========" )
      print( "======================================================\n" )
      session = tls_client.new_session( )
      session.connect( ip=ip, port=port )
#      session.connect( ip='127.0.0.1', port=port )
#      session.send( b'GET /index.html' )
      session.send( sent_data )
#      session.send( b'ping' )
      print( f"APPLICATION DATA - [cert]: {session.recv()}" )
      ## Illustrated TLS does not support PSK authentication
      if tls_server == 'illustrated_tls13' :
        time.sleep( 5 )
        continue

#      print( f":: Engine Ticket DB: {engine_ticket_db.db}" )
      print( "======================================================" )
      print( "============= TLS with PSK authentication ============" )
      print( "======================================================\n" )
      session = tls_client.new_session( )
#      session = ClientTLS13Session( clt_conf, engine_ticket_db, cs )
      session.connect( ip=ip, port=port )
      session.send( sent_data )
#      session.connect( ip='127.0.0.1', port=port )
#      session.send( b'GET /index.html' )
#      session.connect( ip='127.0.0.1', port=port )
#      session.send( b'GET /index.html' )
#      session.send( b'GET ' )
#      session.send( b'ping' )
      print( f"APPLICATION DATA - [psk]: {session.recv()}" )
      ## cleaning ticket db to force using certificate authentication
#      engine_ticket_db.db = {}
  
