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

    shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key);
    ecc_mbedtls_release(&engine);

    shared_secret = malloc( 8 * shared_length);

// Communicate w/ server, recv server's pub key
  char* ip = "127.0.0.1";
  int port = 5572;

  int sock;
  struct sockaddr_in addr;


  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0){
    perror("[-] Socket error");
    exit(1);
  } else {
  printf("[+] TCP server socket created.\n");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    printf("connection failed\n");
    exit(0);
  }else{
  printf("Connected to the server.\n");

  ecc_mbedtls_init (&engine);

  int DER_LEN = 91;
  uint8_t *pub_der = NULL;
  size_t der_length;
  engine.base.get_public_key_der (&engine.base, &pub_key, &pub_der, &der_length);

  send(sock, "lock", sizeof("lock"), 0);
  send(sock, pub_der, der_length, 0); //Will always be length 91 for this curve

  uint8_t buffer[DER_LEN];
  bzero(buffer, DER_LEN);
  recv(sock, buffer, DER_LEN, 0);
  struct ecc_public_key serv_pub_key;

  //Initialize a public key that we can use inside of cerberus from the server's DER encoded public key
  engine.base.init_public_key(&engine.base, buffer, DER_LEN, &serv_pub_key);

  secretkey(&priv_key, &serv_pub_key, secret, &state);
  memcpy(shared_secret, secret, shared_length);
  state = 0;
  }
    return 0;
}

int unlock(){
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
  char* ip = "127.0.0.1";
  int port = 5573;

  int sock;
  struct sockaddr_in addr;


  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0){
    perror("[-] Socket error");
    exit(1);
  } else {
  printf("[+] TCP server socket created.\n");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    printf("connection failed\n");
    exit(0);
  }
  printf("Connected to the server.\n");
  send(sock, "kcol", sizeof("kcol"), 0);
  send(sock, shared_secret, shared_length, 0);
  send(sock, OTPs, sizeof(OTPs), 0);
  send(sock, unlock_aes_iv, sizeof(unlock_aes_iv), 0);
  send(sock, OTP_tag, sizeof(OTP_tag), 0);
  printf("Sending OTPs to server...\n");

  printf("[DEMO(1)]: Decrypting OTP to showcase it is the same on the client and server. Original OTP is \n", OTP);
  for(int i = 0; i < (int) sizeof(OTP); i++){
    printf("%c", OTP[i]);
  }
  printf("\n\n");

  uint8_t serv_enc[128];
  uint8_t server_tag[16];
  bzero(serv_enc, 128);
  recv(sock, serv_enc, 128, 0);
  recv(sock, server_tag, sizeof(server_tag), 0);
  printf("[DEMO(4)]: Receiving OTPs from user...\n");
  printf("[DEMO(4)]: Validating OTPs...\n");
  bool isValid = false;
  OTPvalidation(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), server_tag, serv_enc, sizeof(serv_enc), OTP, &isValid, &my_state);

  printf("[DEMO(5)]: Is OTP valid? 0 represents not valid, 1 represents valid : %d\n", isValid);
  if(isValid){
    state = 7; 
  }
  return isValid;
  
  //Server encrypts OTPs, sends it back
  //We decrypt that, and validate it against our generated OTP

}

int get_state(){
  return state;
}

int get_OTPs(uint8_t *OTPs){
  memcpy(OTPs, class_OTPs, 128);  //Size of OTPs is always 128
  return 1;
}