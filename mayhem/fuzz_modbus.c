// Fuzzes Neuron's Modbus driver: the response parser (modbus_stack_recv for TCP and RTU, and the
// value conversion in modbus_value_handle / modbus_value_handle_test it feeds) and the tag address
// parser (modbus_tag_to_point). The plugin's I/O layer (neu_conn, event loop, adapter) is not built:
// the harness supplies a send callback, adapter callbacks that only read what they are given, and
// no-op OpenTelemetry hooks (tracing is never started in a driver).
//
// Input, first bit of byte 0 picks the mode.
//   address mode: [0]=mode [1]=tag type [2]=attribute [3]=address base, the rest is the tag address.
//   frame mode:   [0]=mode|protocol|check_header|prior reads|tag count|address base, [1]=slave id,
//                 [2]=byte orders, then 4 bytes per tag (area/type, start address, option), and the
//                 rest is the device's response frame, handed to modbus_stack_recv unchanged.
// The tags are built through modbus_tag_to_point and sorted into read commands by modbus_tag_sort,
// as modbus_group_timer does; tags it rejects are dropped, as the plugin rejects them when added.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/zlog.h"

// modbus_req.c is included, not linked: struct modbus_group_data is private to it, and the group
// timer around it (which needs neu_conn) is dropped by --gc-sections.
#include "modbus_req.c"

#include "otel/otel_manager.h"

zlog_category_t *neuron = NULL;

neu_otel_trace_ctx neu_otel_create_trace(const char *trace_id, void *req_ctx,
                                         uint32_t flags, const char *state)
{
    (void) trace_id, (void) req_ctx, (void) flags, (void) state;
    return NULL;
}
neu_otel_trace_ctx neu_otel_find_trace(void *req_ctx)
{
    (void) req_ctx;
    return NULL;
}
neu_otel_scope_ctx neu_otel_add_span(neu_otel_trace_ctx ctx)
{
    (void) ctx;
    return NULL;
}
neu_otel_scope_ctx neu_otel_add_span2(neu_otel_trace_ctx ctx, const char *name,
                                      const char *span_id)
{
    (void) ctx, (void) name, (void) span_id;
    return NULL;
}
void neu_otel_scope_set_span_name(neu_otel_scope_ctx c, const char *v)
{
    (void) c, (void) v;
}
void neu_otel_scope_set_span_flags(neu_otel_scope_ctx c, uint32_t v)
{
    (void) c, (void) v;
}
void neu_otel_scope_set_span_id(neu_otel_scope_ctx c, const char *v)
{
    (void) c, (void) v;
}
void neu_otel_scope_add_span_attr_int(neu_otel_scope_ctx c, const char *k,
                                      int64_t v)
{
    (void) c, (void) k, (void) v;
}
void neu_otel_scope_add_span_attr_string(neu_otel_scope_ctx c, const char *k,
                                         const char *v)
{
    (void) c, (void) k, (void) v;
}
void neu_otel_scope_set_span_start_time(neu_otel_scope_ctx c, int64_t ns)
{
    (void) c, (void) ns;
}
void neu_otel_scope_set_span_end_time(neu_otel_scope_ctx c, int64_t ns)
{
    (void) c, (void) ns;
}
void neu_otel_new_span_id(char *id)
{
    (void) id;
}
void neu_otel_new_trace_id(char *id)
{
    (void) id;
}
bool neu_otel_data_is_started()
{
    return false;
}
double neu_otel_data_sample_rate()
{
    return 0.0;
}

static volatile uint64_t sink;

static void cb_update(neu_adapter_t *adapter, const char *group,
                      const char *tag, neu_dvalue_t value)
{
    (void) adapter, (void) group;
    sink += (tag ? tag[0] : 0) + value.type + value.value.u8;
}

static void cb_update_with_trace(neu_adapter_t *adapter, const char *group,
                                 const char *tag, neu_dvalue_t value,
                                 neu_tag_meta_t *metas, int n_meta,
                                 void *trace_ctx)
{
    (void) metas, (void) n_meta, (void) trace_ctx;
    cb_update(adapter, group, tag, value);
}

static void cb_test_read_tag_response(neu_adapter_t *adapter, void *r,
                                      neu_json_type_e t, neu_type_e type,
                                      neu_json_value_u value, int64_t error)
{
    (void) adapter, (void) r;
    sink += t + type + (uint64_t) error;
    if (t == NEU_JSON_STR) {
        sink += value.val_str[0];
        free(value.val_str);
    }
}

static int send_stub(void *ctx, uint16_t n_byte, uint8_t *bytes)
{
    (void) ctx;
    sink += bytes[0];
    return n_byte;
}

static const neu_type_e tag_types[] = {
    NEU_TYPE_INT8,  NEU_TYPE_UINT8,  NEU_TYPE_INT16,  NEU_TYPE_UINT16,
    NEU_TYPE_INT32, NEU_TYPE_UINT32, NEU_TYPE_FLOAT,  NEU_TYPE_INT64,
    NEU_TYPE_UINT64, NEU_TYPE_DOUBLE, NEU_TYPE_BIT,   NEU_TYPE_BOOL,
    NEU_TYPE_STRING, NEU_TYPE_BYTES,
};
#define N_TAG_TYPES (sizeof(tag_types) / sizeof(tag_types[0]))

static int fuzz_address(const uint8_t *data, size_t size)
{
    if (size < 5) {
        return -1;
    }
    char *address = malloc(size - 3);
    if (address == NULL) {
        return -1;
    }
    memcpy(address, data + 4, size - 4);
    address[size - 4] = '\0';

    neu_datatag_t tag = { 0 };
    tag.name          = "t";
    tag.address       = address;
    tag.type          = data[1] % (NEU_TYPE_ARRAY_STRING + 1);
    tag.attribute     = data[2] & 7;

    modbus_point_t point = { 0 };
    modbus_tag_to_point(&tag, &point, data[3] & 1);
    free(address);
    return 0;
}

// The address a tag of this type gets in the UI, with the option suffix selected by `opt`.
static void tag_address(char *out, size_t n, uint8_t slave, uint8_t sel,
                        uint16_t start, uint8_t opt, neu_type_e type)
{
    static const char *const e32[] = { "", "#BB", "#BL", "#LB" };
    static const char *const e64[] = { "#BB", "#BL", "#LL", "#LB",
                                       "#WS", "#WR", "#B",  "#L" };
    int len = snprintf(out, n, "%u!%c%u", slave, "0134"[sel & 3], start);

    switch (type) {
    case NEU_TYPE_INT16:
    case NEU_TYPE_UINT16:
        snprintf(out + len, n - len, "%s", (opt >> 6) ? ((opt & 1) ? "#B" : "#L") : "");
        break;
    case NEU_TYPE_INT32:
    case NEU_TYPE_UINT32:
    case NEU_TYPE_FLOAT:
        snprintf(out + len, n - len, "%s", e32[opt >> 6]);
        break;
    case NEU_TYPE_INT64:
    case NEU_TYPE_UINT64:
    case NEU_TYPE_DOUBLE:
        snprintf(out + len, n - len, "%s", (opt >> 6) ? e64[opt & 7] : "");
        break;
    case NEU_TYPE_BIT:
    case NEU_TYPE_BOOL:
        if (opt & 0x10) {
            snprintf(out + len, n - len, ".%u", opt & 15);
        }
        break;
    case NEU_TYPE_STRING:
        snprintf(out + len, n - len, ".%u%c", (opt & 0x3f) + 1, "HLDE"[opt >> 6]);
        break;
    case NEU_TYPE_BYTES:
        snprintf(out + len, n - len, ".%u", ((opt & 0x3f) + 1) * 2);
        break;
    default:
        break;
    }
}

static int fuzz_frame(const uint8_t *data, size_t size)
{
    unsigned n_tags = ((data[0] >> 5) & 3) + 1;
    size_t   head   = 3 + 4 * n_tags;
    if (size < head || size - head > UINT16_MAX) {
        return -1;
    }
    uint8_t slave = data[1];

    neu_plugin_t plugin = { 0 };
    adapter_callbacks_t callbacks = { 0 };
    callbacks.driver.update                 = cb_update;
    callbacks.driver.update_with_trace      = cb_update_with_trace;
    callbacks.driver.test_read_tag_response = cb_test_read_tag_response;
    plugin.common.adapter_callbacks         = &callbacks;
    plugin.check_header                     = (data[0] >> 2) & 1;
    plugin.address_base                     = (data[0] >> 7) & 1;
    plugin.endianess                        = 1 + (data[2] & 3);
    plugin.endianess_64                     = 1 + ((data[2] >> 2) & 3);
    plugin.protocol = (data[0] & 2) ? MODBUS_PROTOCOL_RTU : MODBUS_PROTOCOL_TCP;

    struct modbus_group_data gd = { 0 };
    utarray_new(gd.tags, &ut_ptr_icd);
    for (unsigned i = 0; i < n_tags; i++) {
        const uint8_t *s    = data + 3 + 4 * i;
        neu_type_e     type = tag_types[(s[0] >> 2) % N_TAG_TYPES];
        char           address[64];
        tag_address(address, sizeof(address), slave, s[0],
                    (uint16_t)(((s[1] << 8) | s[2]) % 65537), s[3], type);

        neu_datatag_t tag = { 0 };
        tag.name          = "t";
        tag.address       = address;
        tag.type          = type;
        tag.attribute     = NEU_ATTRIBUTE_READ;

        modbus_point_t *p = calloc(1, sizeof(*p));
        if (p == NULL || modbus_tag_to_point(&tag, p, plugin.address_base) != 0) {
            free(p);
            continue;
        }
        utarray_push_back(gd.tags, &p);
    }

    int ret = -1;
    if (utarray_len(gd.tags) > 0) {
        ret = 0;
        gd.group        = "g";
        gd.address_base = plugin.address_base;
        gd.cmd_sort     = modbus_tag_sort(gd.tags, 250);
        plugin.plugin_group_data = &gd;

        plugin.stack = modbus_stack_create(&plugin, plugin.protocol, send_stub,
                                           modbus_value_handle,
                                           modbus_write_resp);
        // Earlier requests advance the TCP sequence number that check_header compares against.
        for (unsigned i = 0; i < ((data[0] >> 3) & 3); i++) {
            uint16_t response_size = 0;
            modbus_stack_read(plugin.stack, slave, MODBUS_AREA_HOLD_REGISTER, 0,
                              1, &response_size, true);
        }

        size_t   frame_size = size - head;
        uint8_t *frame      = malloc(frame_size ? frame_size : 1);
        if (frame == NULL) {
            ret = -1;
        } else {
            memcpy(frame, data + head, frame_size);
            for (uint16_t i = 0; i < gd.cmd_sort->n_cmd; i++) {
                plugin.cmd_idx = i;
                uint16_t response_size = 0;
                modbus_read_cmd_t *cmd = &gd.cmd_sort->cmd[i];
                modbus_stack_read(plugin.stack, cmd->slave_id, cmd->area,
                                  cmd->start_address, cmd->n_register,
                                  &response_size, false);

                neu_protocol_unpack_buf_t pbuf = { 0 };
                neu_protocol_unpack_buf_init(&pbuf, frame, frame_size);
                modbus_stack_recv(plugin.stack, slave, &pbuf);
            }

            modbus_point_t *first = *(modbus_point_t **) utarray_front(gd.tags);
            neu_protocol_unpack_buf_t pbuf = { 0 };
            neu_protocol_unpack_buf_init(&pbuf, frame, frame_size);
            modbus_stack_recv_test(&plugin, NULL, first, &pbuf);
            free(frame);
        }
        modbus_stack_destroy(plugin.stack);
        modbus_tag_sort_free(gd.cmd_sort);
    }
    utarray_foreach(gd.tags, modbus_point_t **, tag) { free(*tag); }
    utarray_free(gd.tags);
    return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) {
        return -1;
    }
    return (data[0] & 1) ? fuzz_address(data, size) : fuzz_frame(data, size);
}
