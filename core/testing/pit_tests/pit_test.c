#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "platform.h"
#include "testing.h"
#include "testing/crypto/ecc_testing.h"
#include "pit/pit.h"

TEST_SUITE_LABEL ("pit");

static void test_pit_lock(CuTest *test){
    TEST_START;

    uint8_t secret[32];
    lock(secret);
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

TEST_SUITE_START (pit);
TEST (test_pit_lock);
TEST (test_pit_unlock);
TEST (test_pit_get_OTPs);
TEST_SUITE_END;