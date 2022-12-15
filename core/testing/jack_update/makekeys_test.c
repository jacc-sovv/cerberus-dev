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
#include "crypto/rng_mbedtls.h"
#include "crypto/base64_mbedtls.h"
// #include "pit/pit.h"
TEST_SUITE_LABEL ("makekeys");
uint8_t AES_IV_TESTING[] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
};


static void test_lockstate(CuTest *test){
    TEST_START;
    char* state_check = "initial";
    int state = -1;

    int status = lockstate(&state_check, &state);
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

static void test_encryptionPID(CuTest *test){
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

    int msg_length = 128;
    uint8_t msg[128] = "Hi!";
    uint8_t ciphertext[msg_length];
    uint8_t tag[16];    //Tags are always length 16

    status = encryption(msg, msg_length, secret1, sizeof(secret1), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, ciphertext, &state);

    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 4, state);

}

static void test_decryption(CuTest *test){
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
    ecc_mbedtls_release(&engine);



    uint8_t secret1[shared_length];

    status = secretkey(&priv_key1, &pub_key2, secret1, &state);
    CuAssertIntEquals(test, 1, status);

    int msg_length = 128;
    uint8_t msg[128] = "Hi there!";
    uint8_t ciphertext[msg_length];
    uint8_t tag[16];    //Tags are always length 16

    status = encryption(msg, msg_length, secret1, sizeof(secret1), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, ciphertext, &state);
    
    uint8_t decrypted_msg[msg_length];
    status = decryption(ciphertext, sizeof(ciphertext), secret1, sizeof(secret1), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, decrypted_msg);
    CuAssertIntEquals(test, 1, status);
    // printf("Inside decryption test, decrypted msg is %s\n", decrypted_msg);
    status = testing_validate_array (msg, decrypted_msg, sizeof(decrypted_msg));
    CuAssertIntEquals (test, 0, status);
    
}

static void test_randomness(CuTest *test){
    TEST_START;
    struct rng_engine_mbedtls engine;
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));
	rng_mbedtls_release (&engine);
    
    //buffer to b64
    
    // struct base64_engine_mbedtls engine2;
    // int min_b64_len = (48 * 2);       //B64 encodes 4 bytes for every 3 bytes of the string
	// uint8_t out[min_b64_len];
    // printf("min length is %d\n", min_b64_len);

	// memset (out, 0xff, sizeof (out));

	// status = base64_mbedtls_init (&engine2);
	// CuAssertIntEquals (test, 0, status);
    // printf("test1\n");
	// status = engine2.base.encode (&engine2.base, buffer, sizeof(buffer), out,
	// 	sizeof (out));
	// //CuAssertIntEquals (test, 0, status);
    // printf("status is %d\n", status);
    // printf("Base 64 encoded string has length %d and is %s\n", sizeof(out), out);

	// base64_mbedtls_release (&engine2);
}

static void test_OTPgen(CuTest *test){
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
    uint8_t secret[shared_length];

    status = secretkey(&priv_key1, &pub_key2, secret, &state);
    CuAssertIntEquals(test, 1, status);

    size_t OTPsize = 32;
    uint8_t tag[16];
    uint8_t OTP[OTPsize];
    uint8_t OTPs[OTPsize];
    status = OTPgen(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTP, OTPsize, OTPs, &state);
    CuAssertPtrNotNull(test, OTPs);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 5, state);
}

static void test_OTPvalidation(CuTest *test){
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
    uint8_t secret[shared_length];

    status = secretkey(&priv_key1, &pub_key2, secret, &state);
    CuAssertIntEquals(test, 1, status);

    size_t OTPsize = 32;
    uint8_t tag[16];
    uint8_t OTP[OTPsize];
    uint8_t OTPs[OTPsize];
    status = OTPgen(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTP, OTPsize, OTPs, &state);
    CuAssertPtrNotNull(test, OTPs);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 5, state);

    bool result;
    status = OTPvalidation(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTPs, sizeof(OTPs), OTP, &result, &state);

    CuAssertIntEquals(test, 1, result);
    CuAssertIntEquals(test, 6, state);
    CuAssertIntEquals(test, 1, status);
}

static void test_unlock(CuTest *test){
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
    uint8_t secret[shared_length];

    status = secretkey(&priv_key1, &pub_key2, secret, &state);
    CuAssertIntEquals(test, 1, status);

    size_t OTPsize = 32;
    uint8_t tag[16];
    uint8_t OTP[OTPsize];
    uint8_t OTPs[OTPsize];
    status = OTPgen(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTP, OTPsize, OTPs, &state);
    CuAssertPtrNotNull(test, OTPs);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 5, state);

    bool result;
    status = OTPvalidation(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTPs, sizeof(OTPs), OTP, &result, &state);

    char* state_check = "initial";
    state = -1;

    status = Unlock(&result, &state_check, &state);
    CuAssertIntEquals(test, 7, state);
    CuAssertIntEquals(test, 1, status);
}

// static void test_revamp(CuTest *test){
//     TEST_START;
//     int status = revamp();
//     printf("%d", status);
// }

static void test_pit_lock(CuTest *test){
    TEST_START;

    uint8_t secret[32];
    int status = lock(secret);
    if(status != 0){
        printf("Error");
    }
    int state = get_state();
    CuAssertIntEquals(test, 0, state);
}

static void test_pit_unlock(CuTest *test){
    TEST_START;

    int status = unlock();
    CuAssertIntEquals(test, 1, status);
    int state = get_state();
    CuAssertIntEquals(test, 7, state);
}


static void test_pit_get_OTPs(CuTest *test){
    TEST_START;
    uint8_t my_OTPs[128];
    int status = get_OTPs(my_OTPs);
    CuAssertIntEquals(test, 1, status);
}


TEST_SUITE_START (makekeys);
TEST (test_lockstate);
TEST (test_keygenstate);
TEST (test_secretkey);
TEST (test_encryptionPID);
TEST (test_randomness);
TEST (test_OTPgen);
TEST (test_OTPvalidation);
TEST (test_unlock);
TEST (test_decryption);
TEST (test_pit_lock);
TEST (test_pit_unlock);
TEST (test_pit_get_OTPs);

// TEST (test_revamp);
TEST_SUITE_END;