// Fuzzes Neuron's IEC 61850 CID/SCL file parser and its conversion to a tag-import request.
#include "fuzz_util.h"

#include "utils/cid.h"
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

    cid_t cid = { 0 };
    int   ret = neu_cid_parse(path, &cid);
    unlink(path);
    if (ret != 0) {
        return -1;
    }

    neu_req_add_gtag_t cmd = { 0 };
    neu_cid_to_msg((char *) "driver", &cid, &cmd);
    fuzz_free_add_gtag(&cmd);
    neu_cid_free(&cid);
    return 0;
}
