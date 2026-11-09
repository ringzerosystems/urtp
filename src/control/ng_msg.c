#include "control/ng.h"
#include "control/ng_internal.h"
#include "core/macros.h"

bool ng_is_message(char const *const msg, size_t const msg_len) {
    if (unlikely((msg == nullptr) || (msg_len < 2))) {
        return false;
    }

    // Check if directly starting with 'd' and ending with 'e'
    if ((msg[0] == 'd') && (msg[msg_len - 1] == 'e')) {
        return true;
    }

    // Check if prefixed by a cookie followed by space and 'd'
    for (size_t i = 0; i < msg_len; ++i) {
        if (msg[i] == ' ') {
            size_t j = i;
            while ((j < msg_len) && (msg[j] == ' ')) {
                j++;
            }
            if ((j < msg_len) && (msg[j] == 'd') && (msg[msg_len - 1] == 'e')) {
                return true;
            }
            break;
        }
    }
    return false;
}

bool ng_process_message(
    char const *const msg,
    size_t const      msg_len,
    session_table_t *restrict const session_table,
    ng_call_table_t *restrict const call_table,
    ring_engine_t *restrict const engine,
    char *restrict const resp_buf,
    size_t const resp_max,
    size_t *restrict const resp_len) {
    if (unlikely(
            (msg == nullptr) || (msg_len == 0) || (session_table == nullptr) ||
            (call_table == nullptr) || (resp_buf == nullptr) || (resp_max == 0)))
    {
        return false;
    }

    bencode_buf_t b = {};
    bencode_buf_init(&b, resp_buf, resp_max);

    // Extract cookie and dictionary
    sv_t          cookie   = SV_EMPTY;
    sv_t          dict     = SV_EMPTY;
    bencode_val_t dict_val = {};
    sv_t          cur      = SV_INIT(msg, msg_len);

    if (bencode_parse_element(&cur, &dict_val) && (dict_val.type == BENCODE_TYPE_DICT)) {
        // Raw bencode dictionary without cookie prefix
        dict = SV_INIT(msg, msg_len);
    } else {
        size_t space_idx = 0;
        while ((space_idx < msg_len) && (msg[space_idx] != ' ')) {
            space_idx++;
        }

        if (space_idx < msg_len) {
            cookie       = SV_INIT(msg, space_idx);
            size_t d_idx = space_idx;
            while ((d_idx < msg_len) && (msg[d_idx] == ' ')) {
                d_idx++;
            }
            dict = SV_INIT(msg + d_idx, msg_len - d_idx);
        } else {
            dict = SV_INIT(msg, msg_len);
        }

        cur      = dict;
        dict_val = (bencode_val_t){};
        if (!bencode_parse_element(&cur, &dict_val) || (dict_val.type != BENCODE_TYPE_DICT)) {
            ng_write_header_cookie(&b, cookie);
            (void)bencode_write_dict_start(&b);
            (void)bencode_write_kv_str(&b, "result", "error");
            (void)bencode_write_kv_str(&b, "error-reason", "Invalid bencode message");
            (void)bencode_write_dict_end(&b);
            if (resp_len != nullptr) {
                *resp_len = b.len;
            }
            return false;
        }
    }

    sv_t cmd = SV_EMPTY;
    if (!bencode_dict_get_str(dict_val.raw, SV_PSZ("command"), &cmd)) {
        ng_write_header_cookie(&b, cookie);
        (void)bencode_write_dict_start(&b);
        (void)bencode_write_kv_str(&b, "result", "error");
        (void)bencode_write_kv_str(&b, "error-reason", "Missing command");
        (void)bencode_write_dict_end(&b);
        if (resp_len != nullptr) {
            *resp_len = b.len;
        }
        return false;
    }

    bool res = false;
    if (sv_equals(cmd, SV_PSZ("ping"))) {
        res = ng_handle_ping(cookie, &b);
    } else if (sv_equals(cmd, SV_PSZ("stats"))) {
        res = ng_handle_stats(cookie, session_table, call_table, &b);
    } else if (sv_equals(cmd, SV_PSZ("offer"))) {
        if (unlikely(call_table->draining)) {
            ng_write_header_cookie(&b, cookie);
            res = bencode_write_dict_start(&b) && bencode_write_kv_str(&b, "result", "error") &&
                  bencode_write_kv_str(&b, "error-reason", "Server is draining") &&
                  bencode_write_dict_end(&b);
        } else {
            res = ng_handle_offer(cookie, dict_val.raw, session_table, call_table, engine, &b);
        }
    } else if (sv_equals(cmd, SV_PSZ("answer"))) {
        res = ng_handle_answer(cookie, dict_val.raw, session_table, call_table, engine, &b);
    } else if (sv_equals(cmd, SV_PSZ("delete"))) {
        res = ng_handle_delete(cookie, dict_val.raw, session_table, call_table, engine, &b);
    } else if (sv_equals(cmd, SV_PSZ("query"))) {
        res = ng_handle_query(cookie, dict_val.raw, session_table, call_table, &b);
    } else if (sv_equals(cmd, SV_PSZ("list"))) {
        res = ng_handle_list(cookie, call_table, &b);
    } else if (
        sv_equals(cmd, SV_PSZ("start recording")) || sv_equals(cmd, SV_PSZ("start_recording")))
    {
        res = ng_handle_start_recording(cookie, dict_val.raw, session_table, call_table, &b);
    } else if (sv_equals(cmd, SV_PSZ("stop recording")) || sv_equals(cmd, SV_PSZ("stop_recording")))
    {
        res = ng_handle_stop_recording(cookie, dict_val.raw, session_table, call_table, &b);
    } else if (sv_equals(cmd, SV_PSZ("record"))) {
        res = ng_handle_record(cookie, dict_val.raw, session_table, call_table, &b);
    } else {
        ng_write_header_cookie(&b, cookie);
        res = bencode_write_dict_start(&b) && bencode_write_kv_str(&b, "result", "error") &&
              bencode_write_kv_str(&b, "error-reason", "Unknown command") &&
              bencode_write_dict_end(&b);
    }

    if (resp_len != nullptr) {
        *resp_len = b.len;
    }
    return res;
}
