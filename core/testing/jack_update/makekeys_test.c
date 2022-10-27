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

static void test_makekeys(CuTest *test){
    TEST_START;
    unsigned char * status = yet_another();
    CuAssertPtrNotNull(test, status);
    //CuAssertIntEquals (test, 0, status);
}

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

static void test_revamp(CuTest *test){
    TEST_START;
    int status = revamp();
    printf("%d", status);
}


TEST_SUITE_START (makekeys);
TEST (test_makekeys);
TEST (test_get_pub);
TEST (test_get_priv);
TEST (test_revamp);
TEST_SUITE_END;