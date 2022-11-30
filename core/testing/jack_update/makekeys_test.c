#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "platform.h"
#include "testing.h"
#include "jack_update/makekeys.h"
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "testing/crypto/ecc_testing.h"

TEST_SUITE_LABEL ("makekeys");



static void test_get_pub(CuTest *test){
    TEST_START;
    struct ecc_public_key mypub = ecc_keys_get_pub();
    //printf("%x is test public key\n", (void *)mypub.context);
    CuAssertPtrNotNull (test, mypub.context);
}

static void test_get_priv(CuTest *test){
    TEST_START;
    struct ecc_private_key mypriv = ecc_keys_get_priv();
    //printf("%x is test private key\n", mypriv.context);
    CuAssertPtrNotNull (test, mypriv.context);
}

static void test_lockstate(CuTest *test){
    TEST_START;
    char* state_check = "initial";
    int state = -1;

    printf("About to call lockstate\n");
    int status = lockstate(&state_check, &state);
    printf("State_check string is now %s\n", state_check);
    CuAssertIntEquals(test, 0, state);
    CuAssertIntEquals(test, 1, status);
}

static void test_keygenstate(CuTest *test){
    TEST_START;
    struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
    size_t keysize = (256 / 8);
    int state = -1;

    int status = keygenstate(keysize, &priv_key, &pub_key, &state);
    CuAssertPtrNotNull(test, pub_key.context);
    CuAssertPtrNotNull(test, priv_key.context);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 1, state);


}


static void test_secretkey(CuTest *test){
    TEST_START;
    size_t keysize = (256 / 8);
    int state = -1;
    struct ecc_private_key priv_key1;
	struct ecc_public_key pub_key1;
    struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key2;


    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);



    int status = keygenstate(keysize, &priv_key1, &pub_key1, &state);
    CuAssertIntEquals(test, 1, status);

    status = keygenstate(keysize, &priv_key2, &pub_key2, &state);
    CuAssertIntEquals(test, 1, status);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key2);
    int shared_length2 = engine.base.get_shared_secret_max_length(&engine.base, &priv_key1);
    ecc_mbedtls_release(&engine);


    CuAssertIntEquals(test, shared_length2, shared_length);

    uint8_t secret1[shared_length];
    uint8_t secret2[shared_length];

    status = secretkey(&priv_key1, &pub_key2, secret1, &state);
    CuAssertIntEquals(test, 1, status);

    status = secretkey(&priv_key2, &pub_key1, secret2, &state);
    CuAssertIntEquals(test, 1, status);

    status = testing_validate_array (secret1, secret2, sizeof(secret1));
    CuAssertIntEquals (test, 0, status);

}

// static void test_revamp(CuTest *test){
//     TEST_START;
//     int status = revamp();
//     printf("%d", status);
// }


TEST_SUITE_START (makekeys);
TEST (test_get_pub);
TEST (test_get_priv);
TEST (test_lockstate);
TEST (test_keygenstate);
TEST (test_secretkey);

// TEST (test_revamp);
TEST_SUITE_END;