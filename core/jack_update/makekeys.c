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

int lockstate(char** state_check, int *state){
  char* msg = "This device is currently in lock state";
  *state_check = msg;
  *state = 0;
  return 1;
}

int keygenstate(size_t key_length, struct ecc_private_key *privkey, struct ecc_public_key *pubkey, int *state){
  // Do the computation and generate privkey and pubkey
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int status = engine.base.generate_key_pair (&engine.base, key_length, privkey, pubkey);
  
  //BONUS TESTS TO BE SURE A KEY REALLY GETS GENERATED (NOT THAT IT'S NECESSARILY CORRECT)
    // uint8_t *pub_der = NULL;
    // size_t der_length;
    // int success = engine.base.get_public_key_der (&engine.base, pubkey, &pub_der, &der_length);
    // printf("Was writing into der format successfull? 0 indicates success : %d\n", success);
    // printf("Pub der has leng of %d and is %s\n", der_length, pub_der);
    
    // uint8_t *priv_der = NULL;
    // success = engine.base.get_private_key_der(&engine.base, privkey, &priv_der, &der_length);
    // printf("Was writing into der format successfull? 0 indicates success : %d\n", success);
    // printf("Pub der has leng of %d and is %s\n", der_length, priv_der);
  
  *state = 1;
  if(status == 0){
    return 1;
  }
  else{
    return -1;
  }
}

int keyexchange(struct ecc_public_key *pubkey, int *state){
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  uint8_t *pub_der = NULL;

  if(!pub_der){
    printf("pub_der is null (as expected)\n");
  }

  size_t der_length;
  int success = engine.base.get_public_key_der (&engine.base, pubkey, &pub_der, &der_length);

  //Send pub_der to server (how?)
  if(!pub_der){
    printf("pub_der is null (NOT as expected)\n");
  }

  *state = 2;
  return success+1;

}

int secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state){
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int shared_length = engine.base.get_shared_secret_max_length(&engine.base, privkey);
  uint8_t out[shared_length];
  int out_len = engine.base.compute_shared_secret (&engine.base, privkey, pubkey, out, sizeof (out));
  printf("Is out_len the same as sizeof (secret)? %d  & %d\n", out_len, sizeof(out));

  // for(int i = 0; i < shared_length; i++){
  //   secret[i] = out[i];
  // }
  memcpy(secret, out, shared_length);

  *state = 3;
  return 1;
}


