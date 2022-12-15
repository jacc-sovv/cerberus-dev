#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/aes_mbedtls.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "crypto/rng_mbedtls.h"
#include <stdbool.h>

// // Sets 
// // struct pit_engine {
// // uint8_t *shared_secret;

// // };

// // Generates a secret key, sets state variables to lock
int lock_name(uint8_t *secret, struct ecc_public_key *serv_pub_key);

// //Calls OTP gen. Send encrypted OTPs to server. Server encrypts it again.
// // Server sends back encrypted version of OTPs. User decrypts that. Should have OG OTPs back.
// // Then call OTP validation on that
// // int unlock(bool* valid);

// // //Returns the current state
// // int get_state(); 


// // //Return encrypted OTP generated in the unlock state
// // int get_encrypted_otps();