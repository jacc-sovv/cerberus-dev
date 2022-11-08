
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "jack_update/makekeys.h"
#include "crypto/aes_mbedtls.h"
#include "testing/crypto/aes_testing.h"
#include "testing/crypto/base64_testing.h"
#include "crypto/base64.h"
#include "crypto/base64_mbedtls.h"
#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP256R1
#define DER_LEN 91


int tcp_client(){

  //Public key to send to the server, encoded in DER format
  uint8_t* pub_key_der = create_key_as_der();

  char* ip = "127.0.0.1";
  int port = 5577;

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

  

  send(sock, pub_key_der, DER_LEN, 0); //Will always be length 91 for this curve

  uint8_t buffer[DER_LEN];
  bzero(buffer, DER_LEN);
  recv(sock, buffer, DER_LEN, 0);


  //At this point, buffer should be der encoded server public key

  struct ecc_engine_mbedtls engine;
  struct ecc_public_key serv_pub_key;
  struct ecc_private_key cli_priv_key = ecc_keys_get_priv();
  ecc_mbedtls_init (&engine);

  //Initialize a public key that we can use inside of cerberus from the server's DER encoded public key
  engine.base.init_public_key(&engine.base, buffer, DER_LEN, &serv_pub_key);




  //Compute shared secret
  int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &cli_priv_key);
  uint8_t out[shared_length];
  int out_len = engine.base.compute_shared_secret (&engine.base, &cli_priv_key, &serv_pub_key, out, sizeof (out));
  printf("Client's generated shared secret is\n");
  for(int i = 0; i < out_len; i++){
    printf("%d", out[i]);
  }
  printf("\n");
  fflush(NULL);
  


  //Sends the shared secret to the server (mainly for testing purposes to be sure they are the same)
  send(sock, out, out_len, 0);



  //Encrypt a message to send

  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  int msg_length = 128;



  uint8_t my_plaintext[128] = "hello from client";

  uint8_t decrypted_plaintext[msg_length];
  uint8_t ciphertext_test[msg_length];
	uint8_t tag_test[AES_GCM_TAG_LEN * 2];

  aes_engine.base.set_key (&aes_engine.base, out, out_len);
  aes_engine.base.encrypt_data (&aes_engine.base, my_plaintext, sizeof(my_plaintext), AES_IV,
		AES_IV_LEN, ciphertext_test, sizeof (ciphertext_test), tag_test, sizeof (tag_test));



  printf("Sending server my message : %s\n", my_plaintext);
  send(sock, ciphertext_test, sizeof(ciphertext_test), 0);
  send(sock, AES_IV, AES_IV_LEN, 0);
  send(sock, tag_test, sizeof(tag_test), 0);
  send(sock, my_plaintext, sizeof(my_plaintext), 0);  //Send the OG msg


  //Receive the server's encrypted message
  uint8_t serv_enc[msg_length];
  uint8_t server_tag[AES_GCM_TAG_LEN * 2];
  bzero(serv_enc, msg_length);
  recv(sock, serv_enc, msg_length, 0);
  recv(sock, server_tag, sizeof(server_tag), 0);



//Is the server's encryption the same as mine?
  //Can I decrypt the server's message?

  printf("Encrypted server message : %s\n\n", serv_enc);
    fflush(stdout);
  bzero(decrypted_plaintext, sizeof(decrypted_plaintext));
    aes_engine.base.decrypt_data (&aes_engine.base, serv_enc, sizeof(serv_enc),
		server_tag, AES_IV, AES_IV_LEN, decrypted_plaintext, sizeof (decrypted_plaintext));

  printf("Decrypted server message :  %s\n\n", decrypted_plaintext);
    fflush(stdout);

  //It works!

  //What happens when I have a different shared secret then you?
  struct aes_engine_mbedtls aes_engine_bad;	
  aes_mbedtls_init (&aes_engine_bad);

  const uint8_t ECC_DH_SECRET_WRONG[] = {
	0x90,0xe8,0xe4,0xc1,0x88,0x92,0x78,0x18,0x15,0x19,0x39,0xb2,0xde,0x44,0x28,0xa5,
	0x87,0xad,0xf4,0x70,0x62,0x8e,0x6d,0xaa,0x05,0x73,0x9b,0x99,0x4a,0x32,0x52,0x26
  };

  aes_engine_bad.base.set_key(&aes_engine_bad.base, ECC_DH_SECRET_WRONG, sizeof(ECC_DH_SECRET_WRONG));

  uint8_t wrong_server_decryption[msg_length];
  int status = aes_engine_bad.base.decrypt_data(&aes_engine_bad.base, serv_enc, sizeof(serv_enc), server_tag, AES_IV, AES_IV_LEN,
                                  wrong_server_decryption, sizeof(wrong_server_decryption));


  printf("Using an incorrect key, the decrypted server message is : %s\n", wrong_server_decryption);
  printf("Error code : %d, corresponding to 'The decrypted plaintext failed authentication.'\n", status);
  close(sock);
  printf("Disconnected from the server.\n");
  exit(20);
  return 0;

}