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



int my_state;
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
      printf("Issue at %d of comparison\n", i);
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





// uint8_t *shared_secret;
// int shared_length;
// struct ecc_private_key priv_key;
// struct ecc_public_key pub_key;
// uint8_t class_OTPs [128];
// int state;

// int lock(uint8_t *secret){

//     size_t keysize = (256 / 8);

//   int key_stat = keygenstate(keysize, &priv_key, &pub_key, &state);
//   if(key_stat != 1){
//     printf("Error in lock's keygen");
//   }

//     struct ecc_engine_mbedtls engine;
//     ecc_mbedtls_init (&engine);

//     shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key);
//     ecc_mbedtls_release(&engine);

//     shared_secret = malloc( 8 * shared_length);

// // Communicate w/ server, recv server's pub key
//   char* ip = "127.0.0.1";
//   int port = 5572;

//   int sock;
//   struct sockaddr_in addr;


//   sock = socket(AF_INET, SOCK_STREAM, 0);
//   if (sock < 0){
//     perror("[-] Socket error");
//     exit(1);
//   } else {
//   printf("[+] TCP server socket created.\n");
//   }

//   memset(&addr, 0, sizeof(addr));
//   addr.sin_family = AF_INET;
//   addr.sin_port = htons(port);
//   addr.sin_addr.s_addr = inet_addr(ip);

//   if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
//     printf("connection failed\n");
//     exit(0);
//   }else{
//   printf("Connected to the server.\n");

//   ecc_mbedtls_init (&engine);

//   int DER_LEN = 91;
//   uint8_t *pub_der = NULL;
//   size_t der_length;
//   engine.base.get_public_key_der (&engine.base, &pub_key, &pub_der, &der_length);

//   send(sock, "lock", sizeof("lock"), 0);
//   send(sock, pub_der, der_length, 0); //Will always be length 91 for this curve

//   uint8_t buffer[DER_LEN];
//   bzero(buffer, DER_LEN);
//   recv(sock, buffer, DER_LEN, 0);
//   struct ecc_public_key serv_pub_key;

//   //Initialize a public key that we can use inside of cerberus from the server's DER encoded public key
//   engine.base.init_public_key(&engine.base, buffer, DER_LEN, &serv_pub_key);

//   secretkey(&priv_key, &serv_pub_key, secret, &state);
//   memcpy(shared_secret, secret, shared_length);
//   state = 0;
//   }
//     return 0;
// }

// int unlock(){
//   uint8_t unlock_aes_iv[] = {
// 	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
//   };
//   int otp_size = 128;
//   uint8_t OTP_tag[16];
//   uint8_t OTP[otp_size];
//   uint8_t OTPs[otp_size];
//   printf("Client generating OTP...\n");
//   int status = OTPgen(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), OTP_tag, OTP, otp_size, OTPs, &my_state);
//   memcpy(class_OTPs, OTPs, otp_size);
//   if(status != 1){
//     printf("Error in OTP generation of unlock");
//   }
//   printf("OTP generation successfull!\n");


//   //Send OTPs to server
//   char* ip = "127.0.0.1";
//   int port = 5573;

//   int sock;
//   struct sockaddr_in addr;


//   sock = socket(AF_INET, SOCK_STREAM, 0);
//   if (sock < 0){
//     perror("[-] Socket error");
//     exit(1);
//   } else {
//   printf("[+] TCP server socket created.\n");
//   }

//   memset(&addr, 0, sizeof(addr));
//   addr.sin_family = AF_INET;
//   addr.sin_port = htons(port);
//   addr.sin_addr.s_addr = inet_addr(ip);

//   if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
//     printf("connection failed\n");
//     exit(0);
//   }
//   printf("Connected to the server.\n");
//   send(sock, "kcol", sizeof("kcol"), 0);
//   send(sock, shared_secret, shared_length, 0);
//   send(sock, OTPs, sizeof(OTPs), 0);
//   send(sock, unlock_aes_iv, sizeof(unlock_aes_iv), 0);
//   send(sock, OTP_tag, sizeof(OTP_tag), 0);
//   printf("Sending OTPs to server...\n");

//   printf("[DEMO(1)]: Decrypting OTP to showcase it is the same on the client and server. Original OTP is \n", OTP);
//   for(int i = 0; i < (int) sizeof(OTP); i++){
//     printf("%c", OTP[i]);
//   }
//   printf("\n\n");

//   uint8_t serv_enc[128];
//   uint8_t server_tag[16];
//   bzero(serv_enc, 128);
//   recv(sock, serv_enc, 128, 0);
//   recv(sock, server_tag, sizeof(server_tag), 0);
//   printf("[DEMO(4)]: Receiving OTPs from user...\n");
//   printf("[DEMO(4)]: Validating OTPs...\n");
//   bool isValid = false;
//   OTPvalidation(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), server_tag, serv_enc, sizeof(serv_enc), OTP, &isValid, &my_state);

//   printf("[DEMO(5)]: Is OTP valid? 0 represents not valid, 1 represents valid : %d\n", isValid);
//   if(isValid){
//     state = 7; 
//   }
//   return isValid;
  
//   //Server encrypts OTPs, sends it back
//   //We decrypt that, and validate it against our generated OTP

// }

// int get_state(){
//   return state;
// }

// int get_OTPs(uint8_t *OTPs){
//   memcpy(OTPs, class_OTPs, 128);  //Size of OTPs is always 128
//   return 1;
// }