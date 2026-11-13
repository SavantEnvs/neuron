// Fuzzes Neuron's BACnet EDE (CSV) import: parse to entries, then to tags.
#include "fuzz_util.h"

#include "utils/ede.h"
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

    neu_ede_result_t result = { 0 };
    int              ret    = neu_ede_parse_file(path, &result);
    if (ret == 0) {
        neu_ede_result_uninit(&result);
    }

    neu_req_add_gtag_t cmd = { 0 };
    neu_ede_to_msg((char *) "driver", path, &cmd);
    unlink(path);
    if (cmd.groups != NULL) {
        neu_ede_tags_uninit(cmd.groups[0].tags, cmd.groups[0].n_tag);
        free(cmd.groups);
    }
    return ret == 0 ? 0 : -1;
}
