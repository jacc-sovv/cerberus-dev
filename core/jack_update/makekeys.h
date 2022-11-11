#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecdh.h"

int ecc_keys();
int pub_length();
struct ecc_public_key ecc_keys_get_pub();
struct ecc_private_key ecc_keys_get_priv();
uint8_t * create_key_as_der();
// unsigned char * get_pub_buff();


/**
 * Generates a public / private key pair, and stores them into the priv_key_cli and pub_key_cli variables.
 * Keys will be written into the address of the variables passed. Vars must be declared, but need not be initialized before calling
 * Returns 0 on success
 * **/
int pit_generate_keys(struct ecc_private_key *priv_key_cli, struct ecc_public_key *pub_key_cli, size_t key_length);


/**
 * Generates a shared secret. Takes an initialized private key and public key. Takes an uninitalized array, secret, and populates it with the 256-bit shared secret
 * Returns 0 on success
 * **/
int pit_generate_secret(struct ecc_private_key  *priv_key_cli, struct ecc_public_key *pub_key_serv, uint8_t *secret);


/**
 * Takes an unencrypted message, plaintext, and a shared secret, and uses AES-GCM to encrypt the message. Stores encrypted msg in ciphertext
 * IV is attached to secret
 * Returns 0 on success
 * **/
int pit_encrypt(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *secret);

/**
 * Takes an encrypted message, ciphertext, and a shared secret with attached IV. Loads plaintext with decrypted message
 * Returns 0 on success
 * **/

int pit_decrypt(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *secret);




