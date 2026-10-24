/* Local test-runtime adapter. MIT license, as the containing project.
 * This uses the real kernel monotonic clock; it never modifies or simulates time.
 * Keep outside the distributed SDK; PHP 7.3+ already provides native hrtime(). */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include <time.h>

#if PHP_VERSION_ID < 70200 || PHP_VERSION_ID >= 70300
#error This test-runtime adapter is exclusively for PHP 7.2
#endif

PHP_FUNCTION(hrtime)
{
    zend_bool as_number = 0;
    struct timespec value;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|b", &as_number) == FAILURE) {
        return;
    }
    if (sizeof(zend_long) != 8 || clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        RETURN_FALSE;
    }
    if (as_number) {
        RETURN_LONG((zend_long)value.tv_sec * 1000000000L + value.tv_nsec);
    }
    array_init(return_value);
    add_next_index_long(return_value, value.tv_sec);
    add_next_index_long(return_value, value.tv_nsec);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_monotonic, 0, 0, 0)
    ZEND_ARG_INFO(0, as_number)
ZEND_END_ARG_INFO()

static const zend_function_entry monotonic_functions[] = {
    PHP_FE(hrtime, arginfo_monotonic)
    PHP_FE_END
};

zend_module_entry sosecurity_monotonic_module_entry = {
    STANDARD_MODULE_HEADER,
    "sosecurity_monotonic", monotonic_functions,
    NULL, NULL, NULL, NULL, NULL,
    "0.1.0", STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SOSECURITY_MONOTONIC
ZEND_GET_MODULE(sosecurity_monotonic)
#endif
