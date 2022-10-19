#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"

static void add_all_TCP_test(CuSuite *suite) {
    TESTING_RUN_SUITE (tcpTests);
}