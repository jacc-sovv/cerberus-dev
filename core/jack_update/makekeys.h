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

/**
 * Set the state to be locked
 * @param state_check A String to be loaded with the current status of the state (This device is currently in lock state)
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int lockstate(char** state_check, int *state);

/**
 * Generates a key pair, sets the state appropriately
 * @param key_length The length of key to use in bytes. 256, 381, 521 bits (so X / 8 bytes) are the supported lengths
 * @param privkey Output for the initialized private key
 * @param pubkey Output for the initialized public key
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int keygenstate(size_t key_length, struct ecc_private_key *privkey, struct ecc_public_key *pubkey, int *state);


int keyexchange(struct ecc_public_key *pubkey, int *state);


/**
 * Generates a secret key
 * @param privkey The private key used to generate the secret
 * @param pubkey The public key used to generate the secret
 * @param secret An non-null output butter to hold the generated shared secret
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state);

