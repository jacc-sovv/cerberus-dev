#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "jack_update/makekeys.h"
#include "crypto/aes_mbedtls.h"
#include "testing/crypto/aes_testing.h"
#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP256R1
#define DER_LEN 91

mbedtls_ecdh_context gen_serv_ctx(){
    mbedtls_ecdh_context ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char pers[] = "ecdh";
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof pers );
    mbedtls_ecp_group_load( &ctx_srv.grp,     // Destination group
                                  ELLIPTIC_CURVE ); // Index in the list of well-known domain parameters
    return ctx_srv;
}


// uint8_t encrypt_msg(const uint8_t plaintext){
//   struct aes_engine_mbedtls engine;
// 	int status;
// 	uint8_t ciphertext[1024];   //How long should this be? Same as size of plaintext I think
// 	uint8_t tag[32];


// 	status = aes_mbedtls_init (&engine);
//   status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
// }

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

  printf("Client:\n %s\n", pub_key_der);
  

  send(sock, pub_key_der, DER_LEN, 0); //Will always be length 91 for this curve

  uint8_t buffer[DER_LEN];
  bzero(buffer, DER_LEN);
  recv(sock, buffer, DER_LEN, 0);

    printf("Buffer on client is : %s\n", buffer);

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
    printf("Success in initializing my own public key\n");
  int out_len = engine.base.compute_shared_secret (&engine.base, &cli_priv_key, &serv_pub_key, out, sizeof (out));


  //Sends the shared secret to the server (mainly for testing purposes to be sure they are the same)
  send(sock, out, out_len, 0);



  //Encrypt a message to send

  
  //Ripped from testing file:
  //uint8_t plaintext_test[AES_PLAINTEXT_LEN * 2];

  //Starting my new stuff, AES_PLAINTEXT_LEN is 121
  // char *plain2 = "yt works llllll";
  // uint8_t* message2 = (uint8_t*) plain2;
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  int msg_length = 128;

  //Works w/ size of 121
  printf("\n");
  //Ending my new stuff
  // const uint8_t AES_IV[] = {
	// 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
  // };

  printf("\n Original IV is %s\n", AES_IV);
  uint8_t my_plaintext[128] = "hi there";

  uint8_t decrypted_plaintext[msg_length];
  printf("aes_lenght is %d\n", msg_length);
  uint8_t ciphertext_test[msg_length];
	uint8_t tag_test[AES_GCM_TAG_LEN * 2];
  printf("Before test file encryption: %s with size %d\n", my_plaintext, sizeof(my_plaintext));
  aes_engine.base.set_key (&aes_engine.base, out, out_len);
  aes_engine.base.encrypt_data (&aes_engine.base, my_plaintext, sizeof(my_plaintext), AES_IV,
		AES_IV_LEN, ciphertext_test, sizeof (ciphertext_test), tag_test, sizeof (tag_test));

     printf("\n AFter encrypting IV is %s\n", AES_IV);

  //Are the ciphers the same?
  printf("My ciphertext is %s with size %d\n", ciphertext_test, sizeof(ciphertext_test));

  aes_engine.base.decrypt_data (&aes_engine.base, ciphertext_test, sizeof(ciphertext_test),
		tag_test, AES_IV, AES_IV_LEN, decrypted_plaintext, sizeof (decrypted_plaintext));
  //Verified with testing that decrypted_plaintext and initial plaintext are the same.
  printf("After test file decryption: %s. Are they the same??\n", decrypted_plaintext);

  for(int i = 0; i < (int)sizeof(decrypted_plaintext); i++){
    if(decrypted_plaintext[i] != my_plaintext[i]){
      printf("ERROR - NOT THE SAME AT INDEX %d\n", i);
    }
  }

  printf("Size of ciphertext is %d, AES is %d, and tag is %d\n", sizeof(ciphertext_test), AES_IV_LEN, sizeof(tag_test));
  printf("Sending ciphertext that looks like %s\n", ciphertext_test);
  printf("Sending aes_iv of %s\n", AES_IV);
  printf("Sending tag of %s\n", tag_test);
  printf("Double checking encrypted message, %s\n", ciphertext_test);
  send(sock, ciphertext_test, sizeof(ciphertext_test), 0);
  send(sock, AES_IV, AES_IV_LEN, 0);
  send(sock, tag_test, sizeof(tag_test), 0);
  send(sock, my_plaintext, sizeof(my_plaintext), 0);  //Send the OG msg


  //Can I even decrypt it on my end?
  uint8_t local_decrypt[msg_length];
  aes_engine.base.decrypt_data(&aes_engine.base, ciphertext_test, sizeof(ciphertext_test), tag_test, AES_IV, AES_IV_LEN,
                        local_decrypt, sizeof(local_decrypt));

  printf("Local decryption yiels %s\n", local_decrypt);
  uint8_t serv_enc[msg_length];
  uint8_t server_tag[AES_GCM_TAG_LEN * 2];
  bzero(serv_enc, msg_length);
  recv(sock, serv_enc, msg_length, 0);
  recv(sock, server_tag, sizeof(server_tag), 0);



//Is the server's encryption the same as mine?
  //Can I decrypt the server's message?
  printf("Server msg is %s\n", serv_enc);
  bzero(decrypted_plaintext, sizeof(decrypted_plaintext));
    aes_engine.base.decrypt_data (&aes_engine.base, serv_enc, sizeof(serv_enc),
		server_tag, AES_IV, AES_IV_LEN, decrypted_plaintext, sizeof (decrypted_plaintext));

  printf("After decrypting, the server's message is %s\n", decrypted_plaintext);

  //It works!
  
  close(sock);
  printf("Disconnected from the server.\n");
  exit(20);
  return 0;

}