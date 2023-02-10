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
#include "pit/pit.h"
#include <arpa/inet.h>
#include "i2c/pit_i2c.h"


int keygenstate(size_t key_length, struct ecc_private_key *privkey, struct ecc_public_key *pubkey, int *state){
  // Do the computation and generate privkey and pubkey
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int status = engine.base.generate_key_pair (&engine.base, key_length, privkey, pubkey);
  
  *state = 1;
  ecc_mbedtls_release (&engine);
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
  ecc_mbedtls_release (&engine);

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
      printf("Issue at %d of comparison\n", i);
      flag = false;
    }
  }

  *result = flag;
  *state = 6;
  return stat + 1;
}
