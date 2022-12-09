import socket 
import binascii
import secrets 
import time
import pprint
import copy 

import sys
sys.path.insert(0, '/home/emigdan/gitlab/pylurk.git/src')
import pylurk.lurk.lurk_lurk
#import pylurk.conf 
import pylurk.debug
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
import pytls13.debug
import tls_handler
import pytls13.tls_client_conf

from cryptography.hazmat.primitives.hmac import HMAC

""" This client implements a TLS client with the following restrictions: 

1. PSK authentication is not used with external keys. 
PSK is solely used in conjunction of session resumption. 

"""


class ClientTLS13Session:

  def __init__( self, clt_conf, engine_ticket_db=None, cs=None ) :
    self.clt_conf = clt_conf
    self.engine_ticket_db = engine_ticket_db
    print( f"::Instantiating the Lurk client" )
   
    self.lurk_client = pylurk.lurk_client.get_lurk_client_instance( self.clt_conf[ 'lurk_client' ], cs=cs )

    resp = self.lurk_client.resp( 'ping' )
    if resp[ 'status' ] != 'success' :
      raise ValueError( "Unable to reach Crypto Service" )

    self.s = None  # TCP socket
    self.s_a_cipher = None
    self.c_a_cipher = None
    self.stream_parser = None
    self.debug = None
    if 'debug' in self.clt_conf.keys() :
      debug = pytls13.debug.Debug( self.clt_conf[ 'debug' ] )
      if debug.trace is True or debug.test_vector is True:
        self.debug = debug

    ## tls handshake enables msg manipulations 
    ## ks is a useful companion but its instantiate needs 
    ## to know the TLS.Hash which is determined either by PSK or 
    ## the selected cipher suite in (ECDHE mode. 
    self.tls_handshake = pylurk.tls13.lurk_tls13.TlsHandshake( 'client', debug=self.debug )
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
    ## Indicates a LURK session has been initiated. This is used to 
    ## distinguishe between 
    ## c_init_client_finished and a c_client_finished exchange. 
    self.c_init_client_hello = None

  def connect( self, ip=None, port=443 ):
    
    # indicates change_cipher_spec has been received
    change_cipher_spec_received = False 
    
    print( f"::TCP session with the TLS server")
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.s.connect( ( ip, port ) )
    ## ip, port, fqdn are necessary to manage the tickets 
    ## and potentially the SNI. 
    ## As a result, we add them to the conf file so it can 
    ## be accessible by every object. 
    server = { 'ip' : ip, 'port' : port, 'fqdn':None }
    self.clt_conf[ 'server' ] = server
    
    print( f"::Sending ClientHello to the server\n--->" )
    ch = pytls13.tls_client_handler.ClientHello( conf=self.clt_conf )
#    if self.clt_conf[ 'debug' ][ 'test_vector' ] is True:
    if self.debug is not None and self.debug.test_vector is True:
      ch.init_from_test_vector( lurk_client=self.lurk_client, tls_handshake=self.tls_handshake, ks=self.ks )
    else:
      ch.init( lurk_client=self.lurk_client, tls_handshake=self.tls_handshake, ks=self.ks, engine_ticket_db=self.engine_ticket_db )
      if self.tls_handshake.is_psk_proposed() is True:
        self.ks = ch.ks
    if self.debug is not None:
      self.debug.handle_tls_clear_text_msg( ch, 'client' )
    self.post_hand_auth = self.tls_handshake.is_post_hand_auth_proposed( )  
    self.c_init_client_hello = ch.c_init_client_hello
    self.s.sendall( ch.to_record_layer_bytes() )
    
    self.stream_parser = pytls13.tls_client_handler.TLSByteStreamParser( self.s )
    while True:
      tls_msg = self.stream_parser.parse_single_msg( )
      if tls_msg.content_type == 'handshake':
        if self.debug is not None:
          self.debug.handle_tls_clear_text_msg( tls_msg, sender='server' ) 
        if tls_msg.content[ 'msg_type' ] == 'server_hello' : 
          print( "---Receiving ServerHello from the server\n--->" )
          sh = pytls13.tls_client_handler.ServerHello( conf=self.clt_conf )
          self.ks = sh.handle_server_hello( self.lurk_client, ch, self.tls_handshake, self.ks, tls_msg ) 
          self.c_register_tickets = sh.c_register_tickets
        ## generating cipher objects to encrypt / decrypt traffic
        cipher_suite = self.tls_handshake.get_cipher_suite()
        s_h_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'h_s' ] )
        if self.debug is not None:
          s_h_cipher.debug( self.debug, description='server_handshake' )
        c_h_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'h_c' ] )
        if self.debug is not None:
          c_h_cipher.debug( self.debug, description='client_handshake' )
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
        if self.debug is not None:
          self.debug.handle_tls_clear_text_msg( tls_msg, 'server' ) 
        change_cipher_spec = True
      elif tls_msg.content_type == 'application_data' :
        print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
        inner_tls_msg = tls_msg.decrypt_inner_msg( s_h_cipher, self.debug )
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
            pylurk.debug.print_bin( "built certificate_request", pytls13.struct_tls13.Handshake.build( inner_tls_msg.content ) ) 
          elif inner_tls_msg.content[ 'msg_type' ] == 'certificate':
            certificate = pytls13.tls_client_handler.Certificate( content=inner_tls_msg.content, sender='server' )
            server_public_key = certificate.get_public_key( )            
          elif inner_tls_msg.content[ 'msg_type' ] == 'certificate_verify':
            self.tls_handshake.is_certificate_request( )
            certificate_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, content=inner_tls_msg.content, sender='server' )
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
     
    ## if a LURK session has already been established, a c_client_finished 
    ## exchange is necessary to retrieve the application secrets and (when 
    ## the TLS client is authenticated the signature)
    if self.c_init_client_hello is True:
      ## the TLS client is authenticated 
      if self.tls_handshake.is_certificate_request_state is True:
        ## generates the certificate
        client_cert = pytls13.tls_client_handler.Certificate( conf=self.clt_conf, content={}, sender='client' )
        client_cert.init_from_conf( )
        client_cert.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', debug=self.debug ) 
        self.tls_handshake.msg_list.append( client_cert.content )
        tmp_handshake.append( client_cert.content )
        ## generates the CertificatVerify
        client_cert_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, sender='client' )
        client_cert_verify.handle_c_client_finished( self.lurk_client, self.ks, tmp_handshake, self.c_register_tickets )
        self.tls_handshake.msg_list.append(  client_cert_verify.content )
        client_cert_verify.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', debug=self.debug ) 
      ## the TLS client is not authenticated
      ## There is no client_cert_verify message but we use the 
      ## client_cert_verify handles the interaction with the CS to 
      ## retrieve the application secrets. The returned signature is empty.
      else: 
         client_cert_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, sender='client' )
         client_cert_verify.handle_c_client_finished( self.lurk_client, self.ks, tmp_handshake, self.c_register_tickets )
    ## No existing LURK session
    else:
      ## the TLS Client is authenticated or post authentication
      ## has been proposed. 
      ## In this case interaction with the CS is performed via a 
      ## c_init_client_finished exchange
      if self.tls_handshake.is_certificate_request( ) is True or self.post_hand_auth is True  :
        self.ks.process( [ 'a_s', 'a_c' ], self.tls_handshake )
        ## this is a hack - we need to handle more properly the tmp_handshake
        tmp_handshake.insert( 0, sh.content )
        tmp_handshake.insert( 0, ch.content )
        tmp_handshake[ 0 ][ 'data' ][ 'random' ] = ch.init_random

        client_cert = pytls13.tls_client_handler.Certificate( conf=self.clt_conf, content={}, sender='client' )
        client_cert.init_from_conf( )
        client_cert.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', debug=self.debug ) 
        self.tls_handshake.msg_list.append( client_cert.content )
        tmp_handshake.append( client_cert.content )
        client_cert_verify = pytls13.tls_client_handler.CertificateVerify( conf=self.clt_conf, sender='client' )
        client_cert_verify.handle_c_init_client_finished( self.lurk_client, self.ks, tmp_handshake, self.c_register_tickets )
        self.tls_handshake.msg_list.append(  client_cert_verify.content )
        client_cert_verify.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', debug=self.debug ) 
        
      ## TLS client is no authenticated
      ## This basically means that everything has been handled by E which also 
      ## generates the application secrets
      else:
        self.ks.process( [ 'a_s', 'a_c' ], self.tls_handshake ) 
    
    print( "--- E -> TLS Server: Sending Client Finished" )
    self.tls_handshake.update_finished( self.ks )
    client_finished = pytls13.tls_client_handler.Finished( conf=self.clt_conf, content=self.tls_handshake.msg_list[ -1 ], sender='client' )
    client_finished.encrypt_and_send( cipher=c_h_cipher, socket=self.s, sender='client', debug=self.debug ) 
    self.s_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'a_s' ] )
    if self.debug is not None:
      self.s_a_cipher.debug( self.debug, description='server_application' )
    self.c_a_cipher = pylurk.tls13.crypto_suites.CipherSuite( cipher_suite, self.ks.secrets[ 'a_c' ] )
    if self.debug is not None:
      self.c_a_cipher.debug( self.debug, description='client_application' )
    
  def send( self, data ):    
    print( "--- E -> TLS Server: Sending Data" )
    
    app_data = pytls13.tls_client_handler.TLSMsg( conf=self.clt_conf, content=data, content_type='application_data', sender='client' )
    app_data.encrypt_and_send( cipher=self.c_a_cipher, socket=self.s, sender='client', debug=self.debug ) 



  def recv( self ):
    while True:
      tls_msg = self.stream_parser.parse_single_msg( )
      if tls_msg.content_type == 'application_data' :
        print( f"--- E <- TLS Server: Receiving Application Data from the server\n--->" )
        inner_tls_msg = tls_msg.decrypt_inner_msg( self.s_a_cipher, self.debug )
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
#    if self.conf[ 'lurk_client' ][ 'connectivity_type' ] == 'lib_cs':
    if self.conf[ 'lurk_client' ][ 'connectivity' ][ 'type' ] == 'lib_cs':
#      self.cs = pylurk.cs.CryptoService( conf=clt_cs_conf.conf )
      cs_conf = self.generate_lib_cs_conf( self.conf )
      self.cs = pylurk.cs.get_cs_instance( cs_conf )
      for k in [ '_cert_entry_list',  '_cert_type',  \
                 '_finger_print_entry_list', '_finger_print_dict'  ]:
        self.conf[ 'cs' ][ ( 'tls13', 'v1' ) ][ k ] = \
          cs_conf[ ( 'tls13', 'v1' ) ] [ k ]  
#      self.cs = pylurk.cs.get_cs_instance( self.conf[ 'cs' ] )
    self.engine_ticket_db = pytls13.tls_client_handler.EngineTicketDB()
    
  def new_session( self ):
    return ClientTLS13Session( self.conf, self.engine_ticket_db, self.cs )

  def generate_lib_cs_conf( self, clt_conf ):
    """ generates the cs configuration from the generic TLS client configuration

    The current configuration is quite large and does not consider all
    limitations provided by the TLS client configuration.
    Such limitations may be good when one is srving a given type of TLS clients. 
    However, in some case, we woudl like to provide some flexibilty in the 
    TLS client and have a more general purpose CS. 
    """
    lurk_client_conn_type = clt_conf[ 'lurk_client' ][ 'connectivity' ][ 'type' ] 
    if lurk_client_conn_type != 'lib_cs':
      raise ConfigurationError( f"CS configuration is expected to be generated "\
        f"only for lurk_client with connectivity type: {lurk_client_conn_type}" )                          
   ## configuration may consider some elements provided by the TLS client
    if 'cs' in clt_conf.keys():
      init_cs_conf = clt_conf[ 'cs' ]
    cs_conf = pylurk.conf.Configuration( )
    ## merging init_cs 
    cs_conf.merge( init_cs_conf )
    cs_conf.set_role( 'client' )
    ## setting / cleaning  connectivity configuration
    cs_conf.set_connectivity( type='lib_cs' )
    cs_conf.set_tls13_debug( **self.conf[ 'debug' ] )
    cs_conf.set_tls13_authorization_type( )
    cs_conf.set_tls13_cs_signing_key( )
    return cs_conf.conf

if __name__ == "__main__" :
  tls_server_list = { \
    'illustrated_tls13' : {
       'description' : f"  - Illustrated TLS1.3 Server\n"\
                       f"   - unauthenticated client\n", 
       'destination' : {
         'ip' : '127.0.0.1', 
         'port' : 8400,
       },
       'sent_data' : b'ping', 
       'debug' : {
         'trace' : True,
         'test_vector' : {
           'file' :  '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json', 
           'mode' : 'record'
           },
         },
       'lurk_client' : {
         'freshness' : 'null'
         },
       'tls13': {
         'session_resumption' : False
       },
     }, 
     'openssl_uclient' : {
       'destination' : {
         'ip' : '127.0.0.1', 
         'port' : 8402, 
       }, 
       'debug' : {
          'trace' : True
       },
       'tls13' : {
         'session_resumption' : False
       }, 
       'description' : f"  - OpenSSL TLS1.3 Server\n"\
                       f"  - unauthenticated client\n" }, 
     'openssl_auth_client' : {
       'destination' : {
         'ip' : '127.0.0.1', 
         'port' : 8403
       },
       'debug' : {
          'trace' : True
       },
       'description' : f"  - OpenSSL TLS1.3 Server\n"\
                       f"  - authenticated client\n" }, 
  }

  cs_list = {
    'lib_cs' : { 
      'connectivity' : {
        'type': 'lib_cs', 
        }
      },
    'illustrated_tls13_tcp_stateless' : {
      'connectivity' : {
        'type': 'tcp_stateless',
        'ip' : '127.0.0.1', 
        'port' : 9400
       }
     },
    'tcp_stateless' : {
      'connectivity' : {
        'type': 'tcp_stateless',
        'ip' : '127.0.0.1', 
        'port' : 9401
       }
     }
  }

  ## The first phase consists in building clt_client from the various 
  ## sources that are available.
  ## In our case, these sources are tls_server_list and cs_list.
  ##
  ## tls_server_list contains information related to the TLS server
  ## as well as characteristics of the TLS sessions this TLS has been
  ## specifically been designed with.
  ## We choose to put the debug information for the tls_client but 
  ## other places would have been acceptale as well. 
  ##
  ## cs_list contains the characteristics associated to the CS
  ## 
  ## clt_client contains a subset of configuration parameters
  ## that are expecting to overwritte the default values of the 
  ## template.
  
  for tls_server in tls_server_list.keys():
    for cs in [ list( cs_list.keys() ) [ 0 ] ]:
      for ephemeral_method in [ 'cs_generated', 'e_generated' ] :
   
        ## generating a coherent clt_conf to be passed as an input
        ## to generate the full configuration
        clt_conf = tls_server_list[ tls_server ]
#        print( f" -o-1 initial server_conf (check debug): {clt_conf}" )
        if 'lurk_client' not  in clt_conf:
          clt_conf[ 'lurk_client' ] = {}
        clt_conf[ 'lurk_client' ][ 'connectivity' ] = cs_list[ cs ][ 'connectivity' ]
#        print( f" -o-2 connectivity server_conf (check debug): {clt_conf}" )
        if 'tls13' not in clt_conf.keys() :
          clt_conf[ 'tls13' ] = {}
        clt_conf[ 'tls13' ][ 'ephemeral_method' ] = ephemeral_method
#        print( f" -o-3 connectivity server_conf (check ephemeral): {clt_conf}" )

        #with pytls13.tls_client_conf.Configuration( ) as conf:
        ## generating the full configuration
        conf = pytls13.tls_client_conf.Configuration( )
#        print( f" -o-3.5 initial conf.conf (check): {conf.conf}\n" )
        conf.merge( clt_conf )
#        print( f" -o-3.6 after merge conf.conf (check): {conf.conf}\n" )
        if cs_list[ cs ][ 'connectivity' ][ 'type' ] == 'lib_cs':
          conf.update_cs_conf( )
#        print( f" -o-4 check final conf (check): {clt_conf}\n" )
#        print( f" -o-5 check final (after cs_update)conf (check): {conf.conf}\n" )
#        print( f"\n =======================================================\n" )
#        continue
#        raise ValueError( f"{pprint.pprint( conf.conf )}" )
#    if tls_server == 'illustrated_tls13' : 
#      conf.set_tls13_debug( trace=True,
#                            test_vector_file = '/home/emigdan/gitlab/pytls13/src/pytls13/illustrated_tls13.json', 
#                            test_vector_mode = 'record' )
#      conf.conf[ 'lurk_client' ][ 'freshness' ] = 'null'
#      conf.conf[ 'tls13' ][ 'session_resumption' ] = False
#    else: 
#      conf.set_tls13_debug( trace=True )
#      conf.conf[ 'tls13' ][ 'session_resumption' ] = True
#      conf.conf[ 'lurk_client' ][ 'freshness' ] = 'sha256'
#    for ephemeral_method in [ 'cs_generated', 'e_generated' ] :
#      conf.conf[ 'tls13' ][ 'ephemeral_method' ] = ephemeral_method
#      conf.set_connectivity( **cs_list[ 'lib_cs' ][ 'connectivity' ] )

        tls_client = SimpleTLS13Client( conf.conf )
        print( "--==================================================--" )
        print( f"TLS Client Configuration:\n"\
               f"{pprint.pprint( conf.conf, width=65, sort_dicts=False)}" )
        print( "--==================================================--\n" )
        print( '\n' )
        
        tls_server_param = tls_server_list[ tls_server ][ 'destination' ]
        ip = tls_server_param[ 'ip' ]
        port = tls_server_param[ 'port' ]
      
        try: 
          sent_data = tls_server_param[ 'sent_data' ] 
        except KeyError:
          sent_data = b'GET /index.html' 
      
        print( '\n' )
        print( "++==================================================++" )
        print( f"{conf.conf[ 'description' ]}\n"\
               f"  - ECDHE {ephemeral_method}" )
        print( "++==================================================++\n" )
        print( '\n' )
        print( "======================================================" )
        print( "========= TLS with certificate authentication ========" )
        print( "======================================================\n" )
        session = tls_client.new_session( )
        session.connect( ip=ip, port=port )
        session.send( sent_data )
        print( f"APPLICATION DATA - [cert]: {session.recv()}" )
        ## Illustrated TLS does not support PSK authentication
        if tls_server == 'illustrated_tls13' :
          time.sleep( 2)
          continue
      
        print( "======================================================" )
        print( "============= TLS with PSK authentication ============" )
        print( "======================================================\n" )
        session = tls_client.new_session( )
        session.connect( ip=ip, port=port )
        session.send( sent_data )
        print( f"APPLICATION DATA - [psk]: {session.recv()}" )
  
