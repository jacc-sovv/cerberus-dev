#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
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



/**
 * Generates a secret key
 * @param privkey The private key used to generate the secret
 * @param pubkey The public key used to generate the secret
 * @param secret An non-null output butter to hold the generated shared secret
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state);


/**
 * Uses AES-GCM encryption to encrypt a message into ciphertext using a secret key
 * @param msg A plaintext message you would like to encrypt
 * @param msg_size The size of the plaintext message
 * @param secret A secret key to use for encryption
 * @param secret_length The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param ciphertext The buffer to hold the encrypted data. The ciphertext will be the same length as the plaintext
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int encryption(uint8_t *msg, size_t msg_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *ciphertext, int *state);



int decryption(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *plaintext);

/**
 * A function to generate a random string as a OTP, and encrypt that OTP
 * @param secret The secret key to encrypt the OTP with
 * @param secret_size The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param OTP A buffer to hold a randomly generated OTP into
 * @param OTPSize The size the OTP should be
 * @param OTPs A buffer to hold the encrypted OTP in
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int OTPgen(uint8_t *secret,  size_t secret_size, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *OTP, size_t OTPSize, uint8_t *OTPs, int *state);

/**
 * Decrypts an encrypted OTP and compares it to a 
 * @param secret The secret key used to decrypt OTPs
 * @param secret_size The size of the secret key
 * @param AESIV An IV to use for decryption. Must be the same as the IV provided to encrypt
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The GCM tag for ciphertext
 * @param OTPs Encrypted OTP to be decrypted
 * @param OTPs_size The size of the encrypted OTP
 * @param valOTP OTP to be validated against the decrypted OTP
 * @param result A boolean value to check whether the OTP was successfully validated
 * @param An int to hold the numerical value of the state
 * @return 1 on success
*/
int OTPvalidation(uint8_t * secret, size_t secret_size, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *OTPs, size_t OTPs_size, uint8_t *valOTP, bool *result, int *state);

/**
 * Unlocks the device and sets the state appropriately
 * @param result A value containing the result of the unlock attempt
 * @param state_check A String to be loaded with the current status of the state (This device is currently in unlock state)
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int Unlock(bool *result, char **state_check, int *state);