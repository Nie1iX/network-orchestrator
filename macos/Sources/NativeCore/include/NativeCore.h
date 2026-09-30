#ifndef NETORCH_NATIVE_CORE_H
#define NETORCH_NATIVE_CORE_H
#include <stddef.h>
#include <stdint.h>
// Owned UTF-8 JSON result. Caller must free it once with netorch_free.
char *netorch_call(const uint8_t *request, size_t length);
void netorch_free(char *result);
#endif
