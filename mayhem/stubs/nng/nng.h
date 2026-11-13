// Type-only stand-in for the nng headers that plugins/ekuiper/plugin_ekuiper.h includes. The ekuiper
// request decoder (json_rw.c) never uses the socket; nng itself is not built.
#ifndef MAYHEM_STUB_NNG_H
#define MAYHEM_STUB_NNG_H
#include <stdint.h>
typedef struct nng_socket_s {
    uint32_t id;
} nng_socket;
typedef struct nng_mtx nng_mtx;
typedef struct nng_aio nng_aio;
#endif
