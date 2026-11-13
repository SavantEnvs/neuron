// Fuzzes Neuron's Beckhoff TwinCAT .tpy (XML) parser and its conversion to a tag-import request.
#include "fuzz_util.h"

#include "utils/tpy.h"
#include "utils/zlog.h"

zlog_category_t *neuron = NULL;
int64_t global_timestamp = 0; // the daemon's clock (src/main.c); only the unused encoders read it

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    return fuzz_enter_scratch_dir();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[64];
    if (size == 0 || fuzz_stage_input(data, size, path, sizeof(path)) != 0) {
        return -1;
    }

    tpy_t tpy = { 0 };
    int   ret = neu_tpy_parse(path, &tpy);
    unlink(path);
    if (ret != 0) {
        return -1;
    }

    neu_req_add_gtag_t cmd = { 0 };
    neu_tpy_to_msg((char *) "driver", &tpy, &cmd);
    fuzz_free_add_gtag(&cmd);
    neu_tpy_free(&tpy);
    return 0;
}
