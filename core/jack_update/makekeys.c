#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "mbedtls/pk.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"


//Print out the private and public keys
//Yo!
struct ecc_public_key public;
struct ecc_private_key private;

//Maybe:
/
int pub_length(){
    return pub_key_len;
}
int ecc_keys(){
    yet_another();
    return 0;
}



struct ecc_public_key ecc_keys_get_pub(){
  return public;
}
//Returns the private key used to generate shared secret for server
struct ecc_private_key ecc_keys_get_priv(){
  return private;
}

//Returns public key in der format
uint8_t * create_key_as_der(){
   
    struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key_cli;
	struct ecc_public_key pub_key_cli;


    ecc_mbedtls_init (&engine);

    //Uses NIST P-256, generate key-pair for client
    int status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key_cli, &pub_key_cli);
    private = priv_key_cli;

    printf("Was keypair generation successfull? %d\n", status);
    
    //Now, encode the key into proper format using get_public_key_der

    uint8_t *pub_der = NULL;
    size_t der_length;
    int success = engine.base.get_public_key_der (&engine.base, &pub_key_cli, &pub_der, &der_length);
        printf("Was writing into der format successfull? 0 indicates success : %d\n", success);

    return pub_der;
}

