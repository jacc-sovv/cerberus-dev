#include <arpa/inet.h>
#include "i2c/pit_i2c.h"
#include "crypto/ecc_mbedtls.h"
#include "mbedtls/ecdh.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int pit_connect(int desired_port){
  // Communicate w/ server, (will be i2c in final version, must be overwritten)
  char* ip = "127.0.0.1";
  int port = desired_port;

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

}

  return sock;
}


//May need to override depending on how pit_connect is implemented
int keyexchangestate(struct ecc_public_key *pubkey_cli, struct ecc_public_key *pubkey_serv){
  int sock = pit_connect(5572);
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);

  int DER_LEN = 91;
  uint8_t *pub_der = NULL;
  size_t der_length;
  engine.base.get_public_key_der (&engine.base, pubkey_cli, &pub_der, &der_length);

  send(sock, "lock", sizeof("lock"), 0);
  send(sock, pub_der, der_length, 0); //Will always be length 91 for this curve, send client public key (DER Format)
  
  uint8_t buffer[DER_LEN];
  bzero(buffer, DER_LEN);
  recv(sock, buffer, DER_LEN, 0); //Receive the server's public key (DER Format)
  engine.base.init_public_key(&engine.base, buffer, DER_LEN, pubkey_serv);
  //ecc_mbedtls_release (&engine);
  return 1;
}



int send_unlock_info(uint8_t *OTPs, size_t OTPs_size, uint8_t *unlock_aes_iv, size_t unlock_aes_iv_size, uint8_t *OTP_tag, uint8_t *server_encrypted_message, uint8_t *server_tag){
  int sock = pit_connect(5573);
  // printf("aes iv size is %d, otp tag size if %d\n", unlock_aes_iv_size, OTP_tag_size);
  send(sock, OTPs, OTPs_size, 0);                    //Send OTPs
  send(sock, unlock_aes_iv, unlock_aes_iv_size, 0);  //Send the IV for the AES cipher
  send(sock, OTP_tag, 16, 0);                        //Send AES-GCM tag

  recv(sock, server_encrypted_message, 128, 0);      //Received server's encrypted message (OTPs)
  recv(sock, server_tag, 16, 0);                     //Receive server's message tag
  return 1;
}