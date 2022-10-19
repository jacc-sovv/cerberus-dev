#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "testing/crypto/ecc_testing.h"

unsigned char * ecc_keys();
struct ecc_public_key ecc_keys_get_pub();
struct ecc_private_key ecc_keys_get_priv();
// unsigned char * get_pub_buff();