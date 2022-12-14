#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/aes_mbedtls.h"
#include "mbedtls/pk.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "crypto/rng_mbedtls.h"
#include <stdbool.h>



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


int secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state){
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int shared_length = engine.base.get_shared_secret_max_length(&engine.base, privkey);
  uint8_t out[shared_length];
  engine.base.compute_shared_secret (&engine.base, privkey, pubkey, out, sizeof (out));

  // for(int i = 0; i < shared_length; i++){
  //   secret[i] = out[i];
  // }
  memcpy(secret, out, shared_length);

  *state = 3;
  return 1;
}

int encryption(uint8_t *msg, size_t msg_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *ciphertext, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);


  aes_engine.base.set_key(&aes_engine.base, secret, secret_length);
  int status = aes_engine.base.encrypt_data (&aes_engine.base, msg, msg_size, AESIV,
		      AESIV_SIZE, ciphertext, msg_size, tag, 16);
  aes_mbedtls_release(&aes_engine);

  *state = 4;
  return status + 1;

}

int decryption(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *plaintext){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  aes_engine.base.set_key (&aes_engine.base, secret, secret_length);

  int stat = aes_engine.base.decrypt_data (&aes_engine.base, ciphertext, ciphertext_size,
		tag, AESIV, AESIV_SIZE, plaintext, ciphertext_size);
  return stat + 1;
}

int OTPgen(uint8_t *secret,  size_t secret_size, uint8_t *AESIV, size_t aesiv_size, uint8_t *tag, uint8_t *OTP, size_t OTPsize, uint8_t *OTPs, int *state){
  struct rng_engine_mbedtls engine;
	int status;
	status = rng_mbedtls_init (&engine);
	status = engine.base.generate_random_buffer (&engine.base, OTPsize, OTP);

  if(status != 0){
    printf("RNG engine failed!\n");
    exit(20);
  }
status = encryption(OTP, OTPsize, secret, secret_size, AESIV, aesiv_size, tag, OTPs, state);

*state = 5;
return status;
}


int OTPvalidation(uint8_t * secret, size_t secret_size, uint8_t *AESIV, size_t AESIV_size, uint8_t *tag, uint8_t *OTPs, size_t OTPs_size, uint8_t *valOTP, bool *result, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  aes_engine.base.set_key (&aes_engine.base, secret, secret_size);

  uint8_t plaintext[OTPs_size];
  int stat = aes_engine.base.decrypt_data (&aes_engine.base, OTPs, OTPs_size,
		tag, AESIV, AESIV_size, plaintext, OTPs_size);

  
  bool flag = true;

  for(int i = 0; i < (int)OTPs_size; i++){
    if(plaintext[i] != valOTP[i]){
      flag = false;
    }
  }

  *result = flag;
  *state = 6;
  return stat + 1;
}

int Unlock(bool *result, char **state_check, int *state){
  if(result){
    char* msg = "The system is now unlocked";
    *state_check = msg;
    *state = 7;
    return 1;
  }
  return -1;
}


