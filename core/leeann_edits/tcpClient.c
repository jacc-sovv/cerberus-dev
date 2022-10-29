#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "jack_update/makekeys.h"
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

int tcp_client(){

  //Public key to send to the server, encoded in DER format
  uint8_t* pub_key_der = create_key_as_der();

  char* ip = "127.0.0.1";
  int port = 5566;

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


  //Sends the shared secret to the server (mainly for testing purposes to be sure they are the same)
  send(sock, out, out_len, 0);



  close(sock);
  printf("Disconnected from the server.\n");

  return 0;

}