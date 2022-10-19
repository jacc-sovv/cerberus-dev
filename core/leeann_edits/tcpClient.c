#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "jack_update/makekeys.h"

int tcp_client(){

  unsigned char* pub_key = yet_another();
    //Uncomment for testing purposes
    // printf("Printing pub key bufffer in tcp\n");
    int pub_len = pub_length();
    // printf("len is %d\n", pub_len);
    // for(int i = 0; i < pub_len; i++){
    //     printf("%c", pub_key[i]);
    // }
    // printf("\n");

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

  bzero(buffer, 1024);
  strcpy(buffer, "Hello, this is client.");
  printf("Client: %s\n", buffer);
  send(sock, buffer, strlen(buffer), 0);

  bzero(buffer, 1024);
  recv(sock, buffer, sizeof(buffer), 0);
  printf("Server: %s\n", buffer);

  close(sock);
  printf("Disconnected from the server.\n");

  return 0;

}