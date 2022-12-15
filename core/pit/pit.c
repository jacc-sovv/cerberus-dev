// #include "./makekeys.h"
// #include <stdlib.h>
// #include <stddef.h>
// #include <string.h>
// #include <stdint.h>
// #include <stdbool.h>
// #include "crypto/ecc.h"
// #include "crypto/ecc_mbedtls.h"
// #include "crypto/rng_mbedtls.h"
// #include "crypto/base64_mbedtls.h"
// #include "pit.h"

uint8_t *shared_secret;

int lock_name(uint8_t *secret, struct ecc_public_key *serv_pub_key){

    size_t keysize = (256 / 8);
    int *state = -1;
    struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;

    int status = keygenstate(keysize, &priv_key, &pub_key, &state);

    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key);
    ecc_mbedtls_release(&engine);

    shared_secret = malloc( 8 * shared_length);
    secretkey(&priv_key, &serv_pub_key, secret, &state);
    
    return 0;
}