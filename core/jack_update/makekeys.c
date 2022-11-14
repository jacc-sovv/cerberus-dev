#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "mbedtls/pk.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"


//Print out the private and public keys
//Yo!
struct ecc_public_key public;
struct ecc_private_key private;





struct ecc_public_key ecc_keys_get_pub(){
  return public;
}
//Returns the private key used to generate shared secret for server
struct ecc_private_key ecc_keys_get_priv(){
  return private;
}

int pit_generate_keys(struct ecc_private_key *priv_key_cli, struct ecc_public_key *pub_key_cli, size_t key_length){
  // Create an ecc engine
  // struct ecc_engine_mbedtls engine;
  // ecc_mbedtls_init (&engine);

  // // Generate key pair in engine
	// struct ecc_private_key priv_key_cli;
	// struct ecc_public_key pub_key_cli;
  // int status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key_cli, &pub_key_cli);
  // Copy keys into corresponding variables passed into function
  // Free engine and it's resources, but this will not free the keys since they have been copied over
  return 0;
}

int pit_generate_secret(struct ecc_private_key  *priv_key_cli, struct ecc_public_key *pub_key_serv, uint8_t *secret){
  // Create an ecc engine
  // Call the engine's compute shared secret function, passing in private key and public key
  // Write the shared secret into the address of the secret buffer
  // Free the ecc engine
  return 0;

}

int pit_encrypt(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *secret, uint8_t *IV){
  // Create an AES engine
  // Set the key of the AES engine to be the secret argument
  // Set the IV to be the IV argument
  // Encrypt the plaintext
  // Copy the ciphertext into the address of the ciphertext pointer given as an argument
  // Free the AES engine
  return 0;
}

int pit_decrypt(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *secret, uint8_t *IV){
  // Create an AES engine
  // Set the key of the AES engine to be the secret argument
  // Set the IV to be the IV argument (Note : IV must be the same to encrypt / decrypt message)
  // Decrypt the ciphertext
  // Store the decrypted text into the address of the plaintext variable passed to me
  // Free the AES engine
  return 0;
}

//Returns public key in der format
uint8_t * create_key_as_der(){
   
    struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key_cli;
	struct ecc_public_key pub_key_cli;


    ecc_mbedtls_init (&engine);

    //Uses NIST P-256, generate key-pair for client
    int status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key_cli, &pub_key_cli);
    private = priv_key_cli;

    printf("Was keypair generation successfull? %d\n", status);
    
    //Now, encode the key into proper format using get_public_key_der

    uint8_t *pub_der = NULL;
    size_t der_length;
    int success = engine.base.get_public_key_der (&engine.base, &pub_key_cli, &pub_der, &der_length);
        printf("Was writing into der format successfull? 0 indicates success : %d Also der len is%d\n", success, der_length);
  
  FILE *fp = NULL;
  fp = fopen("my_key3.der", "wb");
  fwrite(pub_der, sizeof(uint8_t), 91, fp);
  fclose(fp);

    return pub_der;
}

