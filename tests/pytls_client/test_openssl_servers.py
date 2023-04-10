#!/usr//bin/python3


import sys
sys.path.insert(0, '../../src/') # pytls13
## lurk
sys.path.insert(0, '/home/mglt/gitlab/pylurk.git/src/')

import os
import subprocess
import os.path
import inspect
import pprint
import time
import pytls13.tls_client 
#import pytls_client_conf
import pylurk.tls13.crypto_suites
import json
import pylurk
import socket
import time

""" 
This scripts tests the tls_client with various configurations
As the TLS client is split into an engine (E) and a crypto 
service (CS), the full possible configuration results from 
the mulitple combinations of E and CS.

It assumes the following TLS servers are up:

```
cd pytls13/tests/openssl

## TLS server without client authentication
$ openssl s_server -accept 8402  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -key server.key -cert server.crt -debug -keylogfile key.txt -msg -state -tlsextdebug -www

## TLS server with client authentication
$ openssl s_server -cert server.crt -key server.key -www -port 8403 -CAfile client.crt  -debug -keylogfile key.txt -msg -state -tlsextdebug -Verify 1 
```

CS configuration parameters include:
* connectivity: lib_cs, tcp, persistent_tcp, 
* environment: no_gramine, gramine_direct, gramine_sgx 
* signature scheme: ed25519, 'ed448', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384'

E configurations includes:
* environment: no_gramine, gramine_direct, gramine_sgx 
*  session_resumption (always have a reconnect) 
*  ephemeral_method: 'cs_generated', 'e_generated'
*  supported_ecdhe_groups: 'x25519', 'x448', 'secp256r1', 'secp384r1', 'secp521r1'

DO_NOT_SHOW_TLS_CLIENT_OUTPUT_WHEN_WEB_PAGE_DETECTED enable to only display the TLS client output upon error. 
The main purpose of this parameter is to improve readability of the tests.


### sig_scheme below generate errors.
* 'rsa_pss_rsae_sha512',  #nok likely a socket issue
* 'ecdsa_secp521r1_sha512', #nok to look a bit more in detail.

'rsa_pss_pss_sha256', 'rsa_pss_pss_sha384', 'rsa_pss_pss_sha512'
are rejected with a illegal parameter error.
I suspect this results from an incompatibility 
with the certificate. The current certificate contains rsaEncryption
which is fine with rsae, but not for rsa-pss

From RFC 8446 section 4.2.3.  Signature Algorithms

```
RSASSA-PSS PSS algorithms:  Indicates a signature algorithm using
   RSASSA-PSS [RFC8017] with mask generation function 1.  The digest
   used in the mask generation function and the digest being signed
   are both the corresponding hash algorithm as defined in [SHS].
   The length of the Salt MUST be equal to the length of the digest
   algorithm.  If the public key is carried in an X.509 certificate,
   it MUST use the RSASSA-PSS OID [RFC5756].  When used in
   certificate signatures, the algorithm parameters MUST be DER
   encoded.  If the corresponding public key's parameters are
   present, then the parameters in the signature MUST be identical to
   those in the public key.
```

'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 
are not expected to be used in the TLS handshake -
(see RFC 8446 section 4.2.3.  Signature Algorithms )
 
``` 
RSASSA-PKCS1-v1_5 algorithms:  Indicates a signature algorithm using
   RSASSA-PKCS1-v1_5 [RFC8017] with the corresponding hash algorithm
   as defined in [SHS].  These values refer solely to signatures
   which appear in certificates (see Section 4.4.2.2) and are not
   defined for use in signed TLS handshake messages, although they
   MAY appear in "signature_algorithms" and
   "signature_algorithms_cert" for backward compatibility with
   TLS 1.2.
``` 

"""

## indicates the directory where the tls_client and crypto_service 
## commands are stored.
## These directory contains also all the necessary element to build,
## and start the SGX enclave.
CS_GRAMINE_DIR = '/home/mglt/gitlab/pylurk.git/example/cli'
E_GRAMINE_DIR = '/home/mglt/gitlab/pytls13/example/cli'


## Credentials are stored in a single shared place
## which is the one of the CS.
CREDENTIAL_DIR = os.path.join( CS_GRAMINE_DIR, 'sig_key_dir' ) 

CONNECTIVITY = [ 'lib_cs', 'tcp', 'persistent_tcp' ]
ENVIRONMENT = [ 'no_gramine']#, 'gramine_direct', 'gramine_sgx' ]
SIG_SCHEME = [ \
#'rsa_pss_rsae_sha256',
#'rsa_pss_rsae_sha384', 
'ed25519', 
#'ed448', 
#'ecdsa_secp256r1_sha256', 
#'ecdsa_secp384r1_sha384' 
]


EPH_METHOD = [ 'cs_generated', 'e_generated' ]
ECDHE_GROUPS = [ 'x25519']#, 'x448', 'secp256r1', 'secp384r1', 'secp521r1' ]

URL = [ 'https://127.0.0.1:8402', 'https://127.0.0.1:8403']

## The intent of the command is to reduce the output received.
##
## By setting it to True, the script checked in the log that 
## two web pages have been received - one during the 
## certificate based authentication and one during the 
## session resumption. When the two pages are detected the
## script considers the session successfully established.
##
## By setting to False, all client output is displayed.
DO_NOT_SHOW_TLS_CLIENT_OUTPUT_WHEN_WEB_PAGE_DETECTED = True

## The intent of the command is automate the tests and 
## perform all test sin batch
##
## By setting it to False, the script wait for a confimation
## after each test.
##
## By setting it to True, the scripts runn all tests.
TLS_CLIENT_FORCE_YES = True


CS_PORT = {}
port = 9400
for cs_env in ENVIRONMENT:
  for con in CONNECTIVITY:
    if con == 'lib_cs':
      continue
    for sig in SIG_SCHEME:
      CS_PORT[ ( cs_env, con, sig ) ] = port
      port += 1

def cert_file( sig_scheme ):
  """ determine the file containing the certificate """
  if sig_scheme == 'ed25519' :
    cert_file = '_Ed25519PublicKey-ed25519-X509.der'
  elif sig_scheme == 'ed448' :
    cert_file = '_Ed448PublicKey-ed448-X509.der'
  elif 'rsa' in sig_scheme :
    cert_file = f"_RSAPublicKey-rsa-X509.der"
  elif 'ecdsa' in sig_scheme :
    if 'secp256r1' in sig_scheme :
      algo = 'ecdsa_secp256r1'
    elif  'secp384r1' in sig_scheme :
      algo = 'ecdsa_secp384r1'
    elif  'secp521r1' in sig_scheme :
      algo = 'ecdsa_secp521r1'
    cert_file = f"_EllipticCurvePublicKey-{algo}-X509.der"
  else:
    raise ValueError( f"Unknown sig_scheme value {sig}")
  return os.path.join( CREDENTIAL_DIR, cert_file )

def key_file( sig_scheme ):
  """ determine the file containing the private key """
  if sig_scheme == 'ed25519' :
    cert_file = '_Ed25519PrivateKey-ed25519-pkcs8.der'
  elif sig_scheme == 'ed448' :
    cert_file = '_Ed448PrivateKey-ed448-pkcs8.der'
  elif 'rsa' in sig_scheme :
    cert_file = f"_RSAPrivateKey-rsa-pkcs8.der"
  elif 'ecdsa' in sig_scheme :
    if 'secp256r1' in sig_scheme :
      algo = 'ecdsa_secp256r1'
    elif  'secp384r1' in sig_scheme :
      algo = 'ecdsa_secp384r1'
    elif  'secp521r1' in sig_scheme :
      algo = 'ecdsa_secp521r1'
    cert_file = f"_EllipticCurvePrivateKey-{algo}-pkcs8.der"
  else:
    raise ValueError( f"Unknown sig_scheme value {sig}")
  return os.path.join( CREDENTIAL_DIR, cert_file )

def cli_gramine_param( env ):
  cli_param = ""  
  if env == 'gramine_sgx' :
    cli_param += "--gramine_sgx "
  elif env == 'gramine_direct' :
    cli_param += "--gramine_direct "
  elif env == 'no_gramine' :
    pass
  else:
    raise ValueError ( f"Unknown environment value {env}" )
  return cli_param

def cli_cs_param( env, con, sig ):
  """ return the corresponding cli parameter 
  shared by Engine and CS
  """

  cli_param = f"--connectivity {con} "
  if con != 'lib_cs' :
    cli_param += f"--port {CS_PORT[ ( env, con, sig ) ]} "
#  if server == 'illustrative_tls13' :
#    cmd += f"--test_vector_file ./illustrated_tls13.json "\
#           f"--test_vector_mode check"
  if sig in SIG_SCHEME:
    cli_param += f"--sig_scheme {sig} "  
    cli_param += f"--cert {cert_file( sig )} " 
  else:
    raise ValueError ( f"Unknown sig_scheme {sig_scheme}" )
  return cli_param

def crypto_service( env, con, sig )->bool:
  """ starts corresponding cs 

    returns True when the CS is instantiated or False if 
    the CS has already been instantiated.
  """
  args = ( env, con, sig )
  ## testing the CS is already there
  lurk_clt_conf = { 'connectivity' : \
                    { 'type' : con, \
                      'ip' : '127.0.0.1', \
                      'port' : CS_PORT[ args ]  } }
  try : 
#    print( f"lurk_client {con, env, sig} port: { CS_PORT[ args ]}" )
    lurk_client = pylurk.lurk_client.get_lurk_client_instance( lurk_clt_conf )
    resp = lurk_client.resp( 'ping' )
    if resp[ 'status' ] == 'success' :
      show( f"- CS { args } already started" )
      instantiation_status = False
      completed_proc =  None
      cli_cmd = None
    else:
      raise ValueError( f"LURK PING response Error with {arg}"\
              f"Kill and restart the CS" )
  except ConnectionRefusedError : 
#    show( f"starting CS {args}" )
    current_dir = os.getcwd()
    try:
      os.chdir( CS_GRAMINE_DIR )
#      print( f" current_dir: {os.getcwd()}" )
      param = cli_gramine_param( env ) 
      param += cli_cs_param( env, con, sig ) 
      param += f"--key  {key_file( sig )} "
      param += f"--debug "
      show( f"\n --- CS cli ./crypto_service {param}\n" )
#      subprocess.Popen( f"./crypto_service {param}", shell=True )
#      completed_proc = subprocess.run( f"./crypto_service {param}", shell=True, check=True, capture_output=True, text=True )
      ## We do no set capture_output as this is a server.
      ## setting text seems a bit verbose but stil enables
      ## to catch some errors
      cli_cmd = f"./crypto_service {param}"
      completed_proc = subprocess.run( f"{cli_cmd}", shell=True, check=True,  text=True )
      if completed_proc.returncode == 0:
        show( f"- CS { args } started successfully " )
      else: 
        raise ValueError( f"CS {args} not succesfully started" )
      instantiation_status = True
    except Exception as e:
      os.chdir( current_dir )
      raise e
    else: 
      os.chdir( current_dir )
#      return completed_proc, cli_cmd, instantiation_status  
  finally: 
    return completed_proc, cli_cmd, instantiation_status  


def tls_client( e_env, cs_env, con, sig, eph_m, ecdhe, url ):
  args = ( e_env, cs_env, con, sig, eph_m, ecdhe, url )  
#  print( f"tls_client: {args}" ) 
  ## cs_env, con, sig are characteristics use to characterise 
  ## which CS to connect to.
  ## e_env determine how the TLS client is started.
  param = cli_gramine_param( e_env ) 
  param += cli_cs_param( cs_env, con, sig ) 
#  param = cli_param( env, con, sig )
  #param = cli_param( env, con, sig )
  if con == 'lib_cs' :
    param += f"--key  {key_file( sig )} "
  param += f"--ephemeral_method {eph_m} "
  param += f"--supported_ecdhe_groups {ecdhe} "
  param += f"--reconnect "
  param += f"--debug "
  ## the final element
  param += f" {url}"  
  
  current_dir = os.getcwd()
  try :
    os.chdir( E_GRAMINE_DIR )
#    print( os.getcwd() ) 
#    print( os.listdir() )
#    print( f"./tls_client {param}" )
#    subprocess.Popen( f"pwd" )
#    subprocess.Popen( f"./tls_client {param}", shell=True )
    cli_cmd = f"./tls_client {param}"
#    completed_process = subprocess.run( f"./tls_client {param}", shell=True, check=True, capture_output=True, text=True )#, stderr=subprocess.STDOUT )
    completed_process = subprocess.run( f"{cli_cmd}",\
      shell=True, check=True, capture_output=True, text=True )#, stderr=subprocess.STDOUT )

#    print( f"- CS { args } started successfully " )
  except Exception as e:
    os.chdir( current_dir )
    raise e
  else: 
    os.chdir( current_dir )
    return completed_process, cli_cmd

def is_tls_client_successful( stdout ):
  """ determine if the tls client exchange is successful 
  
  This is done by ensuring a successful HTTP response 
  has been received
  """  
  ## we use reconnect  
  ## and the response appears twice: once 
  ## for real and once in the structure description
  if stdout.count( 'HTTP/1.0 200' ) == 4 :
    return True
  return False

def show( obj ):
  pprint.pprint( obj, width=65, sort_dicts=False) 

if __name__ == '__main__' :
   
  show( f" --- Executing: {__file__}\n" )
  show( f"-------------------------" )
  show( f" Instantiation of the CS " )
  show( f"-------------------------" )
  ## starting all CS servers
  ## we expect that to be done once
  sgx_instantiation = False
  cli_cmd_dict = {}
  cs_index = 1
  for  env, con, sig in CS_PORT.keys():
#    if con == 'lib_cs':
#      continue
    show( f"CS {(env, con, sig)}" )
    completed_proc, cli_cmd, instantiation_status =  crypto_service( env, con, sig )
    ## It takes time to instantiate SGX so 
    ## we wait for 60 seconds.
    if instantiation_status is True and env in [ 'gramine_sgx' ]:
      ## with shell started in the background, we need to monitore
      ## whether an sgx instantation occurs to wait enough 
      ## time the instantion is performed appropriately.
      ## When all process are shadow, we can wait only once. 
      ## However, currently, we start the CS one after the other 
      ## so anytime an instantiation occurs we have to wait. 
      ## 
      ## sgx_instantiation = sgx_instantiation or instantiation_status
      time.sleep( 30 )
    param = ( env, con, sig )  
    cli_cmd_dict[ param ] = cli_cmd  
    if completed_proc is None:
      show( f"{cs_index}) CS({param}) already up" )
    else:
      show( f"{cs_index}) CS({param})" )
      show( "Command Line Interface:" )
#      show( cli_cmd )
      show( completed_proc )
      show( completed_proc.stdout )
      show( completed_proc.stderr )
      response = input( "Proceed to next CS? [y]" )
      if response not in [ '', 'y' ]:
        os._exit( 0 )
    cs_index += 1
#  if sgx_instantiation is True:
#    time.sleep( 60 )
#  else:
#    time.sleep ( 5 )
  cs_config_nbr = len( CS_PORT.keys() )
  if cs_config_nbr != 0:
    show( f"All {cs_config_nbr} CS instances have been started" )
    show( "CS_PORT :" )
    show( CS_PORT )
    completed_proc = subprocess.run( \
      f"lsof -i | grep LISTEN | grep 94 ", shell=True,\
      check=True, capture_output=True, text=True )
    show( completed_proc.stdout )
# #  print( completed_proc.stdout.split( '\n' ) )
# #  print( len( completed_proc.stdout.split( '\n' ) ) )
    if len( completed_proc.stdout.split( '\n' ) ) - 1 != cs_config_nbr :
      response = input( f"Confirm the {cs_config_nbr} CS are up? [y]" )
      if response not in [ '', 'y' ]:
        os._exit( 0 )
    has_cmd_cli = False
    for k in cli_cmd_dict.keys():
      if cli_cmd_dict[ k ] != None:
        response = input( "Showing Command Line Interface? [y]" )
        if response in [ '', 'y' ]:
          cs_index += 1
          for k in cli_cmd_dict.keys():
            print( f"{cs_index}) {k} " )
            print( f"{cli_cmd_dict[ k ]}\n" )
            cs_index += 1
            show( cli_cmd_dict )
        break

  response = input( f"Proceed to TLS client tests? [y]" )
  if response not in [ '', 'y' ]:
    os._exit( 0 )


  ## testing the clients configurations
  show( f"-------------------------" )
  show( f"       TLS Client        " )
  show( f"-------------------------" )

  ## 
  completed_proc_dict  = {}
  cli_cmd_dict  = {}

  e_index = 1
  for e_env in ENVIRONMENT:             # 3
#    ## gramine direct is unbale to find the dns module.  
#    if e_env in [ 'gramine_direct', 'gramine_sgx' ]:
#      continue
    for cs_env in ENVIRONMENT:          # 3
      for con in CONNECTIVITY:          # 3
        for sig in SIG_SCHEME:          # 1
          for eph_m in EPH_METHOD:      # 2
            for ecdhe in ECDHE_GROUPS:  # 1
              for url in URL:           # 2
                completed_proc, cli_cmd = tls_client( e_env, cs_env, con, sig, eph_m, ecdhe, url )
                param = ( e_env, cs_env, con, sig, eph_m, ecdhe, url )
                print( f" {e_index}) {param}" )
                completed_proc_dict[ param ] = completed_proc
                cli_cmd_dict[ param ] = cli_cmd
                if DO_NOT_SHOW_TLS_CLIENT_OUTPUT_WHEN_WEB_PAGE_DETECTED is True and\
                    is_tls_client_successful( completed_proc.stdout ) is True:
                    pass
                else:
                  show( completed_proc.stdout )
#                  print( f" count: {completed_proc.stdout.count( 'HTTP/1.0 200' )}" )
                  ## We repeat param as showing completed_proc
                  ## contains the output which can be very verbose
                  ## and make hard to see what test has actually 
                  ## been performed successfully
                  show( f"--- {param} has just been tested." )
# #                show( completed_proc.stdout )
# #                show( completed_proc.stderr )
                  if TLS_CLIENT_FORCE_YES is False:
                    response = input( "Proceed to next TLS client? [y]" )
                    if response not in [ '', 'y' ]:
                      os._exit( 0 )
                e_index += 1
  response = input( "Showing Command Line Interface? [y]" )
  e_index = 1
  if response in [ '', 'y' ]:
    for k in cli_cmd_dict.keys():
      print( f"{e_index}) {k} " )
      print( f"{cli_cmd_dict[ k ]}\n" )
      e_index += 1
#    show( cli_cmd_dict )
