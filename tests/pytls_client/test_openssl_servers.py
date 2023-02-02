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
import json
import pylurk
import socket
import time

""" 
This scripts tests the tls_client with various configurations
As the TLS client is split into an engine (E) and a crypto 
service (CS), the full possible configuration results from 
the mulitple combinationsof E and CS.

CS configuration parameters include:
* connectivity: lib_cs, tcp, persistent_tcp, 
* environment: no_gramine, gramine_direct, gramine_sgx 
* signature scheme: ed25519,

E configurations includes:
* environment: no_gramine, gramine_direct, gramine_sgx 
*  session_resumption: 
*  ephemeral_method: 'cs_generated', 'e_generated'
*  supported_ecdhe_groups: x25519

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

CONNECTIVITY = [ 'persistent_tcp','lib_cs', 'tcp', 'persistent_tcp' ]
ENVIRONMENT = [ 'no_gramine', 'gramine_direct', 'gramine_sgx' ]
SIG_SCHEME = [ 'ed25519' ]
EPH_METHOD = [ 'cs_generated', 'e_generated' ]
ECDHE_GROUPS = [ 'x25519' ]

URL = [ 'https://127.0.0.1:8402', 'https://127.0.0.1:8403']

CS_PORT = {}
port = 9400
for cs_env in ENVIRONMENT:
  for con in CONNECTIVITY:
    if con == 'lib_cs':
      continue
    for sig in SIG_SCHEME:
      CS_PORT[ ( cs_env, con, sig ) ] = port
      port += 1

def cert_file( sig ):
  """ determine the file containing the certificate """
  if sig == 'ed25519' :
    cert_file = '_Ed25519PublicKey-ed25519-X509.der'
  return os.path.join( CREDENTIAL_DIR, cert_file )

def key_file( sig ):
  """ determine the file containing the private key """
  if sig == 'ed25519' :
    cert_file = '_Ed25519PrivateKey-ed25519-pkcs8.der'
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
  show( f"All {cs_config_nbr} CS instances have been started" )
  show( "CS_PORT :" )
  show( CS_PORT )
  completed_proc = subprocess.run( \
    f"lsof -i | grep LISTEN | grep 94 ", shell=True,\
    check=True, capture_output=True, text=True )
  show( completed_proc.stdout )
#  print( completed_proc.stdout.split( '\n' ) )
#  print( len( completed_proc.stdout.split( '\n' ) ) )
  if len( completed_proc.stdout.split( '\n' ) ) != cs_config_nbr :
    response = input( f"Confirm the {cs_config_nbr} CS are up? [y]" )
    if response not in [ '', 'y' ]:
      os._exit( 0 )
  response = input( "Showing Command Line Interface? [y]" )
  if response in [ '', 'y' ]:
    show( cli_cmd_dict )

  response = input( f"Proceed to TLS client tests? [y]" )
  if response not in [ '', 'y' ]:
    os._exit( 0 )


  DO_NOT_SHOW_OUTPUT_WHEN_WEB_PAGE_DETECTED = True

  ## testing the clients configurations
  show( f"-------------------------" )
  show( f"       TLS Client        " )
  show( f"-------------------------" )
  completed_proc_dict  = {}

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
                show( f" {e_index}) {param}" )
                completed_proc_dict[ param ] = completed_proc
                if DO_NOT_SHOW_OUTPUT_WHEN_WEB_PAGE_DETECTED is True and\
                   "<HTML><BODY BGCOLOR=\"#ffffff\">" in completed_proc.stdout :
                    pass
                else:
                  show( completed_proc )
                  ## We repeat param as showing completed_proc
                  ## contains the output which can be very verbose
                  ## and make hard to see what test has actually 
                  ## been performed successfully
                  show( f"--- {param} has just been tested." )
# #                show( completed_proc.stdout )
# #                show( completed_proc.stderr )
            
                  response = input( "Proceed to next TLS client? [y]" )
                  if response not in [ '', 'y' ]:
                    os._exit( 0 )
                e_index += 1
  response = input( "Showing Command Line Interface? [y]" )
  if response in [ '', 'y' ]:
    show( completed_proc_dict )
               
#              if completed_proc.returncode != 0 :
#                print( f"------------------------" )
#                break
#              completed_proc_dict[ param ] = completed_proc
#  pprint.pprint( completed_proc_dict ) 


##$ ./test_openssl_servers.py 
## --- Executing: /home/mglt/gitlab/pytls13/tests/pytls_client/./test_openssl_servers.py
##
##-------------------------
## Instantiation of the CS 
##-------------------------
##
##{('no_gramine', 'tcp', 'ed25519'): 9400, ('no_gramine', 'persistent_tcp', 'ed25519'): 9401, ('gramine_direct', 'tcp', 'ed25519'): 9402, ('gramine_direct', 'persistent_tcp', 'ed25519'): 9403, ('gramine_sgx', 'tcp', 'ed25519'): 9404, ('gramine_sgx', 'persistent_tcp', 'ed25519'): 9405}
##CS ('no_gramine', 'tcp', 'ed25519')
##--- E -> CS: Sending ping Request:
##
## --- CS cli ./crypto_service --connectivity tcp --port 9400 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der 
##
##CS ('no_gramine', 'persistent_tcp', 'ed25519')
##
## --- CS cli ./crypto_service --connectivity persistent_tcp --port 9401 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der 
##
##CS ('gramine_direct', 'tcp', 'ed25519')
##--- E -> CS: Sending ping Request:
##
## --- CS cli ./crypto_service --connectivity tcp --port 9402 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der 
##
##CS ('gramine_direct', 'persistent_tcp', 'ed25519')
##
## --- CS cli ./crypto_service --connectivity persistent_tcp --port 9403 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der 
##
##CS ('gramine_sgx', 'tcp', 'ed25519')
##--- E -> CS: Sending ping Request:
##
## --- CS cli ./crypto_service --connectivity tcp --port 9404 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der 
##
##CS ('gramine_sgx', 'persistent_tcp', 'ed25519')
##
## --- CS cli ./crypto_service --connectivity persistent_tcp --port 9405 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der 
##
##
##-------------------------
##       TLS Client       
##-------------------------
##
##./tls_client --connectivity lib_cs --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity lib_cs --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity lib_cs --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity lib_cs --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
## ---- ERRROR vvvvvv
##./tls_client --connectivity tcp --port 9400 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity tcp --port 9400 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity tcp --port 9400 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity tcp --port 9400 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity persistent_tcp --port 9401 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity persistent_tcp --port 9401 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity persistent_tcp --port 9401 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity persistent_tcp --port 9401 --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity lib_cs --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity lib_cs --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity lib_cs --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity lib_cs --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity tcp --port 9402 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity tcp --port 9402 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity tcp --port 9402 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity tcp --port 9402 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity persistent_tcp --port 9403 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity persistent_tcp --port 9403 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity persistent_tcp --port 9403 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity persistent_tcp --port 9403 --gramine_direct --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity lib_cs --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity lib_cs --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity lib_cs --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity lib_cs --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --key  /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PrivateKey-ed25519-pkcs8.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity tcp --port 9404 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity tcp --port 9404 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity tcp --port 9404 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity tcp --port 9404 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity persistent_tcp --port 9405 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity persistent_tcp --port 9405 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method cs_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
##./tls_client --connectivity persistent_tcp --port 9405 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8402
##./tls_client --connectivity persistent_tcp --port 9405 --gramine_sgx --sig_scheme ed25519 --cert /home/mglt/gitlab/pylurk.git/example/cli/sig_key_dir/_Ed25519PublicKey-ed25519-X509.der --ephemeral_method e_generated --supported_ecdhe_groups x25519 --reconnect  https://127.0.0.1:8403
