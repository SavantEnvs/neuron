// Shared helpers for the file-parsing harnesses.
//
// neu_cid_parse / neu_tpy_parse / neu_ede_parse_file all confine their path to the process working
// directory (neu_path_confine), so the harness runs from the scratch directory ($TMPDIR, else /tmp)
// and stages each input there as a uniquely named, immediately unlinked file.
#ifndef NEURON_MAYHEM_FUZZ_UTIL_H
#define NEURON_MAYHEM_FUZZ_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "msg.h"
#include "tag.h"

static inline int fuzz_enter_scratch_dir(void)
{
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }
    return chdir(dir);
}

// Writes data to a fresh file in the cwd. Returns 0 and fills `path` on success.
static inline int fuzz_stage_input(const uint8_t *data, size_t size,
                                   char *path, size_t path_size)
{
    snprintf(path, path_size, "neuron_fuzz_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, data + off, size - off);
        if (n <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        off += (size_t) n;
    }
    close(fd);
    return 0;
}

static inline void fuzz_free_add_gtag(neu_req_add_gtag_t *cmd)
{
    for (int i = 0; i < cmd->n_group; i++) {
        for (int k = 0; k < cmd->groups[i].n_tag; k++) {
            neu_tag_fini(&cmd->groups[i].tags[k]);
        }
        free(cmd->groups[i].tags);
        free(cmd->groups[i].context);
    }
    free(cmd->groups);
}

#endif
