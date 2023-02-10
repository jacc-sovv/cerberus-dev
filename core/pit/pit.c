#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/aes_mbedtls.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "crypto/rng_mbedtls.h"
#include "crypto/pit_crypto.h"
#include <stdbool.h>
#include "pit/pit.h"
#include <arpa/inet.h>
#include "i2c/pit_i2c.h"


uint8_t *shared_secret;
int shared_length;
struct ecc_private_key priv_key;
struct ecc_public_key pub_key;
uint8_t class_OTPs [128];
int state;

int lock(uint8_t *secret){

  size_t keysize = (256 / 8);

  int key_stat = keygenstate(keysize, &priv_key, &pub_key, &state);
  if(key_stat != 1){
    printf("Error in lock's keygen");
  }

  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  struct ecc_public_key pub_key_serv;
  shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key);
  shared_secret = malloc( 8 * shared_length);

  uint8_t *pub_der = NULL;
  size_t der_length;
  engine.base.get_public_key_der (&engine.base, &pub_key, &pub_der, &der_length);

  uint8_t buffer[der_length];
  bzero(buffer, der_length);

  keyexchangestate(pub_der, der_length, buffer);
  
  engine.base.init_public_key(&engine.base, buffer, der_length, &pub_key_serv);
  ecc_mbedtls_release (&engine);
  secretkey(&priv_key, &pub_key_serv, secret, &state);
  memcpy(shared_secret, secret, shared_length);
  state = 0;
  return 0;
}

int unlock(){
  int my_state;
  uint8_t unlock_aes_iv[] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
  };
  int otp_size = 128;
  uint8_t OTP_tag[16];
  uint8_t OTP[otp_size];
  uint8_t OTPs[otp_size];
  printf("Client generating OTP...\n");
  int status = OTPgen(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), OTP_tag, OTP, otp_size, OTPs, &my_state);
  memcpy(class_OTPs, OTPs, otp_size);
  if(status != 1){
    printf("Error in OTP generation of unlock");
  }
  printf("OTP generation successfull!\n");


  //Send OTPs to server
  uint8_t serv_enc[128];
  uint8_t server_tag[16];
  send_unlock_info(OTPs, sizeof(OTPs), unlock_aes_iv, sizeof(unlock_aes_iv), OTP_tag, serv_enc, server_tag);
  printf("Sending OTPs to server...\n");

  printf("[DEMO(1)]: Decrypting OTP to showcase it is the same on the client and server. Original OTP is \n", OTP);
  for(int i = 0; i < (int) sizeof(OTP); i++){
    printf("%c", OTP[i]);
  }
  printf("\n\n");



  printf("[DEMO(4)]: Receiving OTPs from user...\n");
  printf("[DEMO(4)]: Validating OTPs...\n");
  bool isValid = false;
  OTPvalidation(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), server_tag, serv_enc, sizeof(serv_enc), OTP, &isValid, &my_state);

  printf("[DEMO(5)]: Is OTP valid? 0 represents not valid, 1 represents valid : %d\n", isValid);
  if(isValid){
    state = 7; 

  }
  return isValid;

}

int get_state(){
  return state;
}

int get_OTPs(uint8_t *OTPs){
  memcpy(OTPs, class_OTPs, 128);  //Size of OTPs is always 128
  return 1;
}