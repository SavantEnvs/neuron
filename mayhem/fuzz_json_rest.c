// Fuzzes Neuron's REST/MQTT JSON request decoders (src/parser/*.c + src/utils/json.c), the generic
// parameter decoders plugins use on node settings (neu_parse_param, neu_json_decode_by_json), the MQTT
// plugin's schema and static-tag validators and the ekuiper plugin's write-request decoder.
// The first input byte, modulo the table size, selects the entry; the rest is the JSON text handed to it.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utils/zlog.h"

#include "neu_json_cert.h"
#include "neu_json_cid.h"
#include "json/neu_json_driver.h"
#include "neu_json_global_config.h"
#include "neu_json_group_config.h"
#include "neu_json_log.h"
#include "neu_json_login.h"
#include "json/neu_json_mqtt.h"
#include "neu_json_node.h"
#include "neu_json_otel.h"
#include "neu_json_plugin.h"
#include "json/neu_json_rw.h"
#include "json/neu_json_scan.h"
#include "neu_json_tag.h"
#include "json/neu_json_param.h"
#include "schema.h"
#include "json_rw.h"

zlog_category_t *neuron = NULL;
int64_t global_timestamp = 0; // the daemon's clock (src/main.c); only the unused encoders read it

#define DECODER(decode, type, release)         \
    static void run_##decode(char *buf)        \
    {                                          \
        type *req = NULL;                      \
        if (0 == decode(buf, &req) && req) {   \
            release(req);                      \
        }                                      \
    }
DECODER(neu_json_decode_driver_action_req, neu_json_driver_action_t, neu_json_decode_driver_action_req_free)
DECODER(neu_json_decode_driver_directory_req, neu_json_driver_directory_req_t, neu_json_decode_driver_directory_req_free)
DECODER(neu_json_decode_driver_fup_open_req, neu_json_driver_fup_open_req_t, neu_json_decode_driver_fup_open_req_free)
DECODER(neu_json_decode_driver_fdown_open_req, neu_json_driver_fdown_open_req_t, neu_json_decode_driver_fdown_open_req_free)
DECODER(neu_json_decode_driver_fup_data_req, neu_json_driver_fup_data_req_t, neu_json_decode_driver_fup_data_req_free)
DECODER(neu_json_decode_driver_fdown_data_req, neu_json_driver_fdown_data_req_t, neu_json_decode_driver_fdown_data_req_free)
DECODER(neu_json_decode_mqtt_req, neu_json_mqtt_t, neu_json_decode_mqtt_req_free)
DECODER(neu_json_decode_write_req, neu_json_write_req_t, neu_json_decode_write_req_free)
DECODER(neu_json_decode_write_tags_req, neu_json_write_tags_req_t, neu_json_decode_write_tags_req_free)
DECODER(neu_json_decode_write_gtags_req, neu_json_write_gtags_req_t, neu_json_decode_write_gtags_req_free)
DECODER(neu_json_decode_write, neu_json_write_t, neu_json_decode_write_free)
DECODER(neu_json_decode_read_req, neu_json_read_req_t, neu_json_decode_read_req_free)
DECODER(neu_json_decode_read_paginate_req, neu_json_read_paginate_req_t, neu_json_decode_read_paginate_req_free)
DECODER(neu_json_decode_test_read_tag_req, neu_json_test_read_tag_req_t, neu_json_decode_test_read_tag_req_free)
DECODER(neu_json_decode_scan_tags_req, neu_json_scan_tags_req_t, neu_json_decode_scan_tags_req_free)
DECODER(neu_json_decode_server_cert_self_sign_req, neu_json_server_cert_self_sign_req_t, neu_json_decode_server_cert_self_sign_req_free)
DECODER(neu_json_decode_server_cert_upload_req, neu_json_server_cert_upload_req_t, neu_json_decode_server_cert_upload_req_free)
DECODER(neu_json_decode_client_cert_delete_req, neu_json_client_cert_delete_req_t, neu_json_decode_client_cert_delete_req_free)
DECODER(neu_json_decode_client_cert_trust_req, neu_json_client_cert_trust_req_t, neu_json_decode_client_cert_trust_req_free)
DECODER(neu_json_decode_client_cert_upload_req, neu_json_client_cert_upload_req_t, neu_json_decode_client_cert_upload_req_free)
DECODER(neu_json_decode_server_security_policy_req, neu_json_server_security_policy_req_t, neu_json_decode_server_security_policy_req_free)
DECODER(neu_json_decode_get_security_policy_req, neu_json_get_security_policy_req_t, neu_json_decode_get_security_policy_req_free)
DECODER(neu_json_decode_auth_basic_enable_req, neu_json_auth_basic_enable_req_t, neu_json_decode_auth_basic_enable_req_free)
DECODER(neu_json_decode_add_basic_user_req, neu_json_add_basic_user_req_t, neu_json_decode_add_basic_user_req_free)
DECODER(neu_json_decode_update_basic_user_req, neu_json_update_basic_user_req_t, neu_json_decode_update_basic_user_req_free)
DECODER(neu_json_decode_delete_basic_user_req, neu_json_delete_basic_user_req_t, neu_json_decode_delete_basic_user_req_free)
DECODER(neu_json_decode_get_basic_users_req, neu_json_get_basic_users_req_t, neu_json_decode_get_basic_users_req_free)
DECODER(neu_json_decode_auth_basic_status_req, neu_json_auth_basic_status_req_t, neu_json_decode_auth_basic_status_req_free)
DECODER(neu_json_decode_upload_cid_req, neu_json_upload_cid_t, neu_json_decode_upload_cid_req_free)
DECODER(neu_json_decode_global_config_req, neu_json_global_config_req_t, neu_json_decode_global_config_req_free)
DECODER(neu_json_decode_drivers_req, neu_json_drivers_req_t, neu_json_decode_drivers_req_free)
DECODER(neu_json_decode_apps_req, neu_json_apps_req_t, neu_json_decode_apps_req_free)
DECODER(neu_json_decode_add_group_config_req, neu_json_add_group_config_req_t, neu_json_decode_add_group_config_req_free)
DECODER(neu_json_decode_update_group_config_req, neu_json_update_group_config_req_t, neu_json_decode_update_group_config_req_free)
DECODER(neu_json_decode_del_group_config_req, neu_json_del_group_config_req_t, neu_json_decode_del_group_config_req_free)
DECODER(neu_json_decode_subscribe_req, neu_json_subscribe_req_t, neu_json_decode_subscribe_req_free)
DECODER(neu_json_decode_unsubscribe_req, neu_json_unsubscribe_req_t, neu_json_decode_unsubscribe_req_free)
DECODER(neu_json_decode_subscribe_groups_req, neu_json_subscribe_groups_req_t, neu_json_decode_subscribe_groups_req_free)
DECODER(neu_json_decode_update_log_level_req, neu_json_update_log_level_req_t, neu_json_decode_update_log_level_req_free)
DECODER(neu_json_decode_update_global_log_level_req, neu_json_update_global_log_level_req_t, neu_json_decode_update_global_log_level_req_free)
DECODER(neu_json_decode_login_req, neu_json_login_req_t, neu_json_decode_login_req_free)
DECODER(neu_json_decode_password_req, neu_json_password_req_t, neu_json_decode_password_req_free)
DECODER(neu_json_decode_add_user_req, neu_json_add_user_req_t, neu_json_decode_add_user_req_free)
DECODER(neu_json_decode_update_user_req, neu_json_password_req_t, neu_json_decode_update_user_req_free)
DECODER(neu_json_decode_delete_user_req, neu_json_delete_user_req_t, neu_json_decode_delete_user_req_free)
DECODER(neu_json_decode_add_node_req, neu_json_add_node_req_t, neu_json_decode_add_node_req_free)
DECODER(neu_json_decode_update_node_tag_req, neu_json_update_node_tag_req_t, neu_json_decode_update_node_tag_req_free)
DECODER(neu_json_decode_del_node_req, neu_json_del_node_req_t, neu_json_decode_del_node_req_free)
DECODER(neu_json_decode_update_node_req, neu_json_update_node_req_t, neu_json_decode_update_node_req_free)
DECODER(neu_json_decode_node_ctl_req, neu_json_node_ctl_req_t, neu_json_decode_node_ctl_req_free)
DECODER(neu_json_decode_node_setting_req, neu_json_node_setting_req_t, neu_json_decode_node_setting_req_free)
DECODER(neu_json_decode_add_node_properties_req, neu_json_add_node_properties_req_t, neu_json_decode_add_node_properties_req_free)
DECODER(neu_json_decode_delete_node_properties_req, neu_json_delete_node_properties_req_t, neu_json_decode_delete_node_properties_req_free)
DECODER(neu_json_decode_update_node_property_req, neu_json_update_node_property_req_t, neu_json_decode_update_node_property_req_free)
DECODER(neu_json_decode_otel_conf_req, neu_json_otel_conf_req_t, neu_json_decode_otel_conf_req_free)
DECODER(neu_json_decode_add_plugin_req, neu_json_add_plugin_req_t, neu_json_decode_add_plugin_req_free)
DECODER(neu_json_decode_del_plugin_req, neu_json_del_plugin_req_t, neu_json_decode_del_plugin_req_free)
DECODER(neu_json_decode_add_tags_req, neu_json_add_tags_req_t, neu_json_decode_add_tags_req_free)
DECODER(neu_json_decode_add_gtags_req, neu_json_add_gtags_req_t, neu_json_decode_add_gtags_req_free)
DECODER(neu_json_decode_del_tags_req, neu_json_del_tags_req_t, neu_json_decode_del_tags_req_free)
DECODER(neu_json_decode_update_tags_req, neu_json_update_tags_req_t, neu_json_decode_update_tags_req_free)
DECODER(neu_json_decode_import_tags_req, neu_json_import_tags_req_t, neu_json_decode_import_tags_req_free)
DECODER(neu_json_decode_rename_tag_req, neu_json_rename_tag_req_t, neu_json_decode_rename_tag_req_free)
#undef DECODER

// A named NEU_JSON_OBJECT element only borrows the object from the decoded document (decode_object
// takes a reference only for an unnamed one), so neu_json_elem_free applies to every other type.
static void release_elem(neu_json_elem_t *e)
{
    if (e->t != NEU_JSON_OBJECT) {
        neu_json_elem_free(e);
    }
}

// neu_parse_param reads {"params":{...}} the way the plugins' *_config callbacks do (core uses it for
// the topic of a node message). Elements are released only on success, as a failed decode may leave
// some of them unset.
static void run_parse_param_topic(char *buf)
{
    neu_json_elem_t topic = { .name = "topic", .t = NEU_JSON_STR };
    char *          err   = NULL;
    if (0 == neu_parse_param(buf, &err, 1, &topic)) {
        release_elem(&topic);
    }
    free(err);
}

// The settings every Modbus TCP driver reads, then its optional groups (modbus_tcp.c driver_config).
static void run_parse_param_modbus(char *buf)
{
    neu_json_elem_t port     = { .name = "port", .t = NEU_JSON_INT };
    neu_json_elem_t host     = { .name = "host", .t = NEU_JSON_STR };
    neu_json_elem_t mode     = { .name = "connection_mode", .t = NEU_JSON_INT };
    neu_json_elem_t timeout  = { .name = "timeout", .t = NEU_JSON_INT };
    neu_json_elem_t interval = { .name = "interval", .t = NEU_JSON_INT };
    neu_json_elem_t retries  = { .name = "max_retries", .t = NEU_JSON_INT };
    neu_json_elem_t retry_iv = { .name = "retry_interval", .t = NEU_JSON_INT };
    neu_json_elem_t degrade  = { .name = "device_degrade", .t = NEU_JSON_INT };
    neu_json_elem_t cycle    = { .name = "degrade_cycle", .t = NEU_JSON_INT };
    neu_json_elem_t dtime    = { .name = "degrade_time", .t = NEU_JSON_INT };
    neu_json_elem_t bhost    = { .name = "backup_host", .t = NEU_JSON_STR };
    neu_json_elem_t bport    = { .name = "backup_port", .t = NEU_JSON_INT };
    char *          err      = NULL;

    if (0 == neu_parse_param(buf, &err, 5, &port, &host, &mode, &timeout,
                             &interval)) {
        release_elem(&host);
    }
    free(err);
    err = NULL;
    neu_parse_param(buf, &err, 2, &retries, &retry_iv);
    free(err);
    err = NULL;
    neu_parse_param(buf, &err, 3, &degrade, &cycle, &dtime);
    free(err);
    err = NULL;
    if (0 == neu_parse_param(buf, &err, 2, &bhost, &bport)) {
        release_elem(&bhost);
    }
    free(err);
}

// Elements of undefined type take the type of the JSON value they find (arrays, objects, scalars).
static void run_parse_param_undefined(char *buf)
{
    neu_json_elem_t e[3] = { { .name = "a", .t = NEU_JSON_UNDEFINE },
                             { .name = "b", .t = NEU_JSON_UNDEFINE },
                             { .name = "c", .t = NEU_JSON_UNDEFINE } };
    char *          err  = NULL;
    if (0 == neu_parse_param(buf, &err, 3, &e[0], &e[1], &e[2])) {
        for (int i = 0; i < 3; i++) {
            release_elem(&e[i]);
        }
    }
    free(err);
}

static void run_decode_by_json(char *buf)
{
    void *json = neu_json_decode_new(buf);
    if (json == NULL) {
        return;
    }
    neu_json_elem_t e[7] = {
        { .name = "s", .t = NEU_JSON_STR },
        { .name = "i", .t = NEU_JSON_INT },
        { .name = "d", .t = NEU_JSON_DOUBLE },
        { .name = "b", .t = NEU_JSON_BOOL },
        { .name = "ai", .t = NEU_JSON_ARRAY_INT64 },
        { .name = "as", .t = NEU_JSON_ARRAY_STR },
        { .name = "o", .t = NEU_JSON_OBJECT },
    };
    if (0 == neu_json_decode_by_json(json, 7, e)) {
        for (int i = 0; i < 7; i++) {
            release_elem(&e[i]);
        }
    }
    neu_json_decode_free(json);
}

static void free_schema(mqtt_schema_vt_t *vts, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free_schema(vts[i].sub_vts, vts[i].n_sub_vts);
    }
    free(vts);
}

static void run_mqtt_schema_validate(char *buf)
{
    mqtt_schema_vt_t *vts = NULL;
    size_t            n   = 0;
    if (0 == mqtt_schema_validate(buf, &vts, &n)) {
        free_schema(vts, n);
    }
}

static void run_mqtt_static_validate(char *buf)
{
    mqtt_static_vt_t *vts = NULL;
    size_t            n   = 0;
    if (0 == mqtt_static_validate(buf, &vts, &n)) {
        mqtt_static_free(vts, n);
    }
}

static void run_ekuiper_write_req(char *buf)
{
    neu_json_write_t *req = NULL;
    if (0 == json_decode_write_req(buf, strlen(buf), &req) && req) {
        neu_json_decode_write_free(req);
    }
}

typedef void (*run_fn)(char *);

#define DECODER(decode, type, release) run_##decode,
static const run_fn decoders[] = {
    run_neu_json_decode_driver_action_req,
    run_neu_json_decode_driver_directory_req,
    run_neu_json_decode_driver_fup_open_req,
    run_neu_json_decode_driver_fdown_open_req,
    run_neu_json_decode_driver_fup_data_req,
    run_neu_json_decode_driver_fdown_data_req,
    run_neu_json_decode_mqtt_req,
    run_neu_json_decode_write_req,
    run_neu_json_decode_write_tags_req,
    run_neu_json_decode_write_gtags_req,
    run_neu_json_decode_write,
    run_neu_json_decode_read_req,
    run_neu_json_decode_read_paginate_req,
    run_neu_json_decode_test_read_tag_req,
    run_neu_json_decode_scan_tags_req,
    run_neu_json_decode_server_cert_self_sign_req,
    run_neu_json_decode_server_cert_upload_req,
    run_neu_json_decode_client_cert_delete_req,
    run_neu_json_decode_client_cert_trust_req,
    run_neu_json_decode_client_cert_upload_req,
    run_neu_json_decode_server_security_policy_req,
    run_neu_json_decode_get_security_policy_req,
    run_neu_json_decode_auth_basic_enable_req,
    run_neu_json_decode_add_basic_user_req,
    run_neu_json_decode_update_basic_user_req,
    run_neu_json_decode_delete_basic_user_req,
    run_neu_json_decode_get_basic_users_req,
    run_neu_json_decode_auth_basic_status_req,
    run_neu_json_decode_upload_cid_req,
    run_neu_json_decode_global_config_req,
    run_neu_json_decode_drivers_req,
    run_neu_json_decode_apps_req,
    run_neu_json_decode_add_group_config_req,
    run_neu_json_decode_update_group_config_req,
    run_neu_json_decode_del_group_config_req,
    run_neu_json_decode_subscribe_req,
    run_neu_json_decode_unsubscribe_req,
    run_neu_json_decode_subscribe_groups_req,
    run_neu_json_decode_update_log_level_req,
    run_neu_json_decode_update_global_log_level_req,
    run_neu_json_decode_login_req,
    run_neu_json_decode_password_req,
    run_neu_json_decode_add_user_req,
    run_neu_json_decode_update_user_req,
    run_neu_json_decode_delete_user_req,
    run_neu_json_decode_add_node_req,
    run_neu_json_decode_update_node_tag_req,
    run_neu_json_decode_del_node_req,
    run_parse_param_topic,
    run_neu_json_decode_update_node_req,
    run_neu_json_decode_node_ctl_req,
    run_neu_json_decode_node_setting_req,
    run_neu_json_decode_add_node_properties_req,
    run_neu_json_decode_delete_node_properties_req,
    run_neu_json_decode_update_node_property_req,
    run_neu_json_decode_otel_conf_req,
    run_neu_json_decode_add_plugin_req,
    run_neu_json_decode_del_plugin_req,
    run_neu_json_decode_add_tags_req,
    run_neu_json_decode_add_gtags_req,
    run_neu_json_decode_del_tags_req,
    run_neu_json_decode_update_tags_req,
    run_neu_json_decode_import_tags_req,
    run_neu_json_decode_rename_tag_req,
    // Entries from here on are selected by the printable bytes '@' (64) onward.
    run_parse_param_modbus,
    run_parse_param_undefined,
    run_decode_by_json,
    run_mqtt_schema_validate,
    run_mqtt_static_validate,
    run_ekuiper_write_req,
};
#undef DECODER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) {
        return -1;
    }

    size_t n   = sizeof(decoders) / sizeof(decoders[0]);
    char * buf = malloc(size);
    if (buf == NULL) {
        return -1;
    }
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = '\0';

    decoders[data[0] % n](buf);

    free(buf);
    return 0;
}
