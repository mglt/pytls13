
tls_client_conf_template = {
  'server' : {
    'ip' : '127.0.0.1',
    'port' : 1799
  }, 
  ( 'tls13', 'v1' ) : {
    'ecdhe_authentication' : True, ## ecdhe indicates certificate based authentication
    'ke_modes' : ['psk_ke', 'psk_dhe_ke'], ## psk without ecdhe
    'session_resumption' : True,
    'post_handshake_authentication' : False,  ## True/False
    ## sig scheme understood by the TLS Engine to authenticate the Server
    ## These are NOT reflecting the sig_scheme supported by the CS, 
    ## which indicates the signature scheme used by the CS to authenticate 
    ## the TLS CLient.
    'signature_algorithms' : ['rsa_pkcs1_sha256', \
              'rsa_pkcs1_sha384', \
              'rsa_pkcs1_sha512',\
              'ecdsa_secp256r1_sha256', \
              'ecdsa_secp384r1_sha384',\
              'ecdsa_secp521r1_sha512', \
              'rsa_pss_rsae_sha256', \
              'rsa_pss_rsae_sha384', \
              'rsa_pss_rsae_sha512', \
              'ed25519', \
              'ed448', \
              'rsa_pss_pss_sha256', \
              'rsa_pss_pss_sha384', \
              'rsa_pss_pss_sha512' ],
    ## configuration of ecdhe requires some synchronization with the cs 
    ## configuration.
    ## maybe this may be generated from the CS configuration (or the reverse)
    'ephemeral_method' : ['no_secret', 'cs_generated', 'e_generated'], ## when ECDHE is needed. 
    ## these values are used for the supported_group (non mandatory) and key_share extension 
    'supported_groups' : [ 'secp256r1', 'secp384r1',        
                           'secp521r1', 'x25519', 'x448'], 
  }
}

