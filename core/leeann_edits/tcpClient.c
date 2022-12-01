
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

uint8_t AES_IV_TESTING2[] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
};

int tcp_client(){


  char* state_check = "initial";
  int state = -1;
  int status = lockstate(&state_check, &state);

  printf("State is now %s\n", state_check);
  struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
  size_t keysize = (256 / 8);

  status = keygenstate(keysize, &priv_key, &pub_key, &state);

  printf("State's value after keygen : %d\n", state);

  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);

  uint8_t *pub_der = NULL;
  size_t der_length;
  engine.base.get_public_key_der (&engine.base, &pub_key, &pub_der, &der_length);
  

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
  }
  printf("Connected to the server.\n");

  

  send(sock, pub_der, DER_LEN, 0); //Will always be length 91 for this curve

  uint8_t buffer[DER_LEN];
  bzero(buffer, DER_LEN);
  recv(sock, buffer, DER_LEN, 0);


  //At this point, buffer should be der encoded server public key

  struct ecc_public_key serv_pub_key;

  //Initialize a public key that we can use inside of cerberus from the server's DER encoded public key
  engine.base.init_public_key(&engine.base, buffer, DER_LEN, &serv_pub_key);




  //Compute shared secret
  int secret_size = engine.base.get_shared_secret_max_length(&engine.base, &priv_key);
  uint8_t secret[secret_size];
  status = secretkey(&priv_key, &serv_pub_key, secret, &state);
  printf("State's value after secretkey : %d\n", state);
  printf("Secret key is %s\n", secret);


  //Sends the shared secret to the server (mainly for testing purposes to be sure they are the same)
  send(sock, secret, secret_size, 0);



  //Encrypt a message to send
  int msg_length = 128;
  uint8_t my_plaintext[128];
  uint8_t ciphertext[msg_length];
	uint8_t tag_test[AES_GCM_TAG_LEN];

  //Generate a random string, stores it into my_plaintext
  status = OTPgen(secret, secret_size, AES_IV_TESTING2, AES_IV_LEN, tag_test, my_plaintext, sizeof(my_plaintext), ciphertext, &state);
  printf("State's value after OTPgen : %d\n", state);

  printf("OTP message is %s\n", my_plaintext);



  send(sock, ciphertext, sizeof(ciphertext), 0);
  send(sock, AES_IV_TESTING2, AES_IV_LEN, 0);
  send(sock, tag_test, sizeof(tag_test), 0);
  //send(sock, my_plaintext, sizeof(my_plaintext), 0);  //Send the OG msg


  //Receive the server's encrypted message
  uint8_t serv_enc[128];
  uint8_t server_tag[AES_GCM_TAG_LEN];
  bzero(serv_enc, msg_length);
  recv(sock, serv_enc, 128, 0);
  recv(sock, server_tag, sizeof(server_tag), 0);



//Is the server's encryption the same as mine?
  //Can I decrypt the server's message?

  printf("Encrypted server message : \n");

  for(int i = 0; i < (int)sizeof(serv_enc); i++){
    printf("%c", serv_enc[i]);
  }
  printf("\n");


  uint8_t expected_server_message[128] = "Production ID (Server)";
  bool result;
  //Validate's that server's "OTP" is Production ID (Server) (Basically decrypts server's message, verifies it is what our expected hardcoded message is)
  status = OTPvalidation(secret, secret_size, AES_IV_TESTING2, AES_IV_LEN, server_tag, serv_enc, sizeof(serv_enc), expected_server_message, &result, &state);
  printf("State's value after OTPvalidation : %d\n", state);

  printf("Are the messages the same? 1 indicates True : %d\n", result);
  //It works!

  status = Unlock(&result, &state_check, &state);
  printf("State's value after unlocking : %d\n", state);
  printf("Checking state after unlocking : %s\n", state_check);


  //What happens when I have a different shared secret then you?
  struct aes_engine_mbedtls aes_engine_bad;	
  aes_mbedtls_init (&aes_engine_bad);

  const uint8_t ECC_DH_SECRET_WRONG[] = {
	0x90,0xe8,0xe4,0xc1,0x88,0x92,0x78,0x18,0x15,0x19,0x39,0xb2,0xde,0x44,0x28,0xa5,
	0x87,0xad,0xf4,0x70,0x62,0x8e,0x6d,0xaa,0x05,0x73,0x9b,0x99,0x4a,0x32,0x52,0x26
  };

  aes_engine_bad.base.set_key(&aes_engine_bad.base, ECC_DH_SECRET_WRONG, sizeof(ECC_DH_SECRET_WRONG));

  uint8_t wrong_server_decryption[msg_length];
  status = aes_engine_bad.base.decrypt_data(&aes_engine_bad.base, serv_enc, sizeof(serv_enc), server_tag, AES_IV_TESTING2, AES_IV_LEN,
                                  wrong_server_decryption, sizeof(wrong_server_decryption));


  printf("Using an incorrect key, the decrypted server message is : %s\n", wrong_server_decryption);
  printf("Error code : %x, corresponding to 'The decrypted plaintext failed authentication.'\n", status);
  close(sock);
  printf("Disconnected from the server.\n");
  exit(20);
  return 0;

}