#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecdh.h"

unsigned char * yet_another();
int ecc_keys();
int pub_length();
mbedtls_ecdh_context gen_cli_ctx();
struct ecc_public_key ecc_keys_get_pub();
struct ecc_private_key ecc_keys_get_priv();
int revamp();
// unsigned char * get_pub_buff();