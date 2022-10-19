#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "platform.h"
#include "testing.h"
#include "leeann_edits/tcpClient.h"

TEST_SUITE_LABEL ("tcpTests")

static void test_tcpClient(CuTest *test) {
    TEST_START;
    int ret = tcp_client();
    CuAssertIntEquals(test, 0, ret);
}

TEST_SUITE_START (tcpTests);
TEST (test_tcpClient);
TEST_SUITE_END;