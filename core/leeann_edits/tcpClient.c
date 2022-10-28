#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "jack_update/makekeys.h"
#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP256R1

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

  //unsigned char* pub_key = yet_another();
    //Uncomment for testing purposes
    // printf("Printing pub key bufffer in tcp\n");
    // int pub_len = pub_length();
    //printf("len is %d\n", pub_len);
    // for(int i = 0; i < pub_len; i++){
    //     printf("%c", pub_key[i]);
    // }
    // printf("\n");

  mbedtls_ecdh_context cli_ctx = gen_cli_ctx();
  mbedtls_ecdh_context serv_ctx = gen_serv_ctx();
  ///

  ///
  printf("%d", cli_ctx.Qp.X.s);


  char* ip = "127.0.0.1";
  int port = 5566;

  int sock;
  struct sockaddr_in addr;
  //socklen_t addr_size;
  char buffer[1024];

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

  // bzero(buffer, 1024);
  // memcpy(&buffer, pub_key, pub_len);
  //mbedtls_pk_write_pubkey_pem(&cli_ctx, buffer, sizeof(buffer));
  printf("Client:\n %s\n", buffer);
  send(sock, buffer, strlen(buffer), 0);

  bzero(buffer, 1024);
  recv(sock, buffer, sizeof(buffer), 0);
  //printf("Server: %s\n", buffer);

  //Now, buffer has the server's message (should be the public key)
  const unsigned char* buf2 = (const unsigned char*) buffer;
  printf("BUFFER FOR LOOP\n");
  int count = 0;
  for(int i = 0; i < (int)strlen(buffer); i++){
    printf("%c", buf2[i]);
    count = i;
  }

  printf("%d\n", strlen(buffer));
    printf("Count is %d\n", count);


  mbedtls_ecp_point_read_binary(&serv_ctx.grp, &serv_ctx.Qp, buf2, strlen(buffer));

  size_t keylen;
  unsigned char keybuff[1000];
  mbedtls_ecp_point_write_binary(&serv_ctx.grp, &serv_ctx.Qp, MBEDTLS_ECP_PF_COMPRESSED, &keylen, keybuff, sizeof(keybuff));
  printf("About to print keybuff w/ len of %d\n", keylen);
  for(int i = 0; i < (int)keylen; i++){
    printf("%c", keybuff[i]);
  }
  printf("\n");

  //At this point, serv.ctx.Qp should be initialized to the server's public key!
  //Last step, compute shared secret.


  close(sock);
  printf("Disconnected from the server.\n");

  return 0;

}