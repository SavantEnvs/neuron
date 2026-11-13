// Known-answer probe for the parsers fuzzed from mayhem/: asserts concrete values for fixed inputs.
// Built with the project's normal flags (no sanitizers) and run by mayhem/test.sh from a scratch dir
// that holds the upstream fixtures (the file parsers confine paths to the working directory).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msg.h"
#include "neu_json_login.h"
#include "neu_json_node.h"
#include "neu_json_tag.h"
#include "tag.h"
#include "utils/base64.h"
#include "utils/cid.h"
#include "utils/ede.h"
#include "utils/tpy.h"
#include "utils/zlog.h"

zlog_category_t *neuron = NULL;
int64_t global_timestamp = 0; // the daemon's clock (src/main.c); only the unused encoders read it

static int failures;
static int checks;

#define CHECK(name, cond)                                      \
    do {                                                       \
        checks++;                                              \
        if (cond) {                                            \
            printf("PASS %s\n", name);                         \
        } else {                                               \
            printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); \
            failures++;                                        \
        }                                                      \
    } while (0)

static void kat_base64(void)
{
    char *enc = neu_encode64((const unsigned char *) "hello world!", 12);
    CHECK("base64 encode", enc != NULL && strcmp(enc, "aGVsbG8gd29ybGQh") == 0);
    free(enc);

    int            len = 0;
    unsigned char *dec = neu_decode64(&len, "aGVsbG8gd29ybGQh");
    CHECK("base64 decode", dec != NULL && len == 12 && memcmp(dec, "hello world!", 12) == 0);
    free(dec);

    len = 0;
    dec = neu_decode64(&len, "YQ==");
    CHECK("base64 padded decode", dec != NULL && len == 1 && dec[0] == 'a');
    free(dec);
}

static void kat_json(void)
{
    char                  login[] = "{\"name\":\"admin\",\"pass\":\"s3cret\"}";
    neu_json_login_req_t *lr      = NULL;
    int                   rc      = neu_json_decode_login_req(login, &lr);
    CHECK("json login decode", rc == 0 && lr != NULL && strcmp(lr->name, "admin") == 0 &&
                                   strcmp(lr->pass, "s3cret") == 0);
    if (lr != NULL) {
        neu_json_decode_login_req_free(lr);
    }

    char bad[] = "{\"name\":\"admin\"}";
    lr         = NULL;
    rc         = neu_json_decode_login_req(bad, &lr);
    CHECK("json login rejects missing field", rc != 0);

    char add_tags[] = "{\"node\":\"n1\",\"group\":\"g1\",\"tags\":[{\"name\":\"t1\","
                      "\"address\":\"1!400001\",\"attribute\":1,\"type\":3}]}";
    neu_json_add_tags_req_t *at = NULL;
    rc                          = neu_json_decode_add_tags_req(add_tags, &at);
    CHECK("json add_tags decode", rc == 0 && at != NULL && at->n_tag == 1 &&
                                      strcmp(at->node, "n1") == 0 &&
                                      strcmp(at->group, "g1") == 0 &&
                                      strcmp(at->tags[0].name, "t1") == 0 &&
                                      strcmp(at->tags[0].address, "1!400001") == 0);
    if (at != NULL) {
        neu_json_decode_add_tags_req_free(at);
    }
}

static void kat_cid(void)
{
    cid_t cid = { 0 };
    int   rc  = neu_cid_parse("serverBMS_3_test.cid", &cid);
    CHECK("cid parse", rc == 0);
    if (rc != 0) {
        return;
    }
    neu_req_add_gtag_t cmd = { 0 };
    neu_cid_to_msg((char *) "driver", &cid, &cmd);
    CHECK("cid group count", cmd.n_group == 13);
    for (int i = 0; i < cmd.n_group; i++) {
        for (int k = 0; k < cmd.groups[i].n_tag; k++) {
            neu_tag_fini(&cmd.groups[i].tags[k]);
        }
        free(cmd.groups[i].tags);
        free(cmd.groups[i].context);
    }
    free(cmd.groups);
    neu_cid_free(&cid);
}

static void kat_ede(void)
{
    neu_req_add_gtag_t cmd = { 0 };
    neu_ede_to_msg((char *) "driver", "EDE_test.csv", &cmd);
    CHECK("ede group", cmd.groups != NULL && cmd.n_group == 1);
    if (cmd.groups != NULL) {
        CHECK("ede tag count", cmd.groups[0].n_tag == 1499);
        neu_ede_tags_uninit(cmd.groups[0].tags, cmd.groups[0].n_tag);
        free(cmd.groups);
    }
}

static void kat_tpy(void)
{
    tpy_t tpy = { 0 };
    int   rc  = neu_tpy_parse("VarTypes_Sample.tpy", &tpy);
    CHECK("tpy parse", rc == 0);
    if (rc != 0) {
        return;
    }
    neu_req_add_gtag_t cmd = { 0 };
    neu_tpy_to_msg((char *) "driver", &tpy, &cmd);
    int n_tag = 0;
    for (int i = 0; i < cmd.n_group; i++) {
        n_tag += cmd.groups[i].n_tag;
    }
    printf("INFO tpy groups=%d tags=%d\n", cmd.n_group, n_tag);
    CHECK("tpy tag count", n_tag == TPY_EXPECTED_TAGS);
    for (int i = 0; i < cmd.n_group; i++) {
        for (int k = 0; k < cmd.groups[i].n_tag; k++) {
            neu_tag_fini(&cmd.groups[i].tags[k]);
        }
        free(cmd.groups[i].tags);
        free(cmd.groups[i].context);
    }
    free(cmd.groups);
    neu_tpy_free(&tpy);
}

int main(void)
{
    kat_base64();
    kat_json();
    kat_cid();
    kat_ede();
    kat_tpy();
    printf("KAT checks=%d failures=%d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
