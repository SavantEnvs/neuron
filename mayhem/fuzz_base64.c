// Fuzzes Neuron's OpenSSL-backed base64 decoder, and checks encode/decode round-trips.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utils/base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 1 << 20) {
        return -1;
    }

    char *text = malloc(size + 1);
    if (text == NULL) {
        return -1;
    }
    memcpy(text, data, size);
    text[size] = '\0';

    int            len = 0;
    unsigned char *dec = neu_decode64(&len, text);
    free(text);
    if (dec != NULL) {
        free(dec);
    }

    char *enc = neu_encode64(data, (int) size);
    if (enc == NULL) {
        abort();
    }
    int            rlen = 0;
    unsigned char *back = neu_decode64(&rlen, enc);
    if (back == NULL || rlen != (int) size || memcmp(back, data, size) != 0) {
        abort();
    }
    free(back);
    free(enc);
    return 0;
}
