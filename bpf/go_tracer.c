// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "pid_types.h"
#include "utils.h"
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"
#include "go_common.h"
#include "go_nethttp.h"
#include "go_traceparent.h"
#include "http_types.h"
#include "tracing.h"
#include "hpack.h"
#include "ringbuf.h"

typedef struct new_func_invocation {
    u64 parent;
} new_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, new_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

typedef struct http_func_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
} http_func_invocation_t;

typedef struct http_client_data {
    u8  method[METHOD_MAX_LEN];
    u8  path[PATH_MAX_LEN];
    s64 content_length;

    pid_info pid;
} http_client_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_client_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests_data SEC(".maps");

typedef struct server_http_func_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
    u8  method[METHOD_MAX_LEN];
    u8  path[PATH_MAX_LEN];
    u64 content_length;

    u64 status;
} server_http_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, server_http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_server_requests SEC(".maps");

typedef struct grpc_srv_func_invocation {
    u64 start_monotime_ns;
    u64 stream;
    tp_info_t tp;
} grpc_srv_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, u16);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_request_status SEC(".maps");

typedef struct grpc_client_func_invocation {
    u64 start_monotime_ns;
    u64 cc;
    u64 method;
    u64 method_len;
    tp_info_t tp;
    u64 flags;
} grpc_client_func_invocation_t;

typedef struct grpc_transports {
    u8 type;
    connection_info_t conn;
} grpc_transports_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the transport pointer
    __type(value, grpc_transports_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_transports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: goroutine
    __type(value, void *); // the transport *
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_operate_headers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_srv_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_requests SEC(".maps");

// Context propagation
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // key: stream id
    __type(value, grpc_client_func_invocation_t); // stored info for the client request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_header_writes SEC(".maps");


#define TRANSPORT_HTTP2   1
#define TRANSPORT_HANDLER 2

// To be Injected from the user space during the eBPF program load & initialization

volatile const u64 grpc_stream_st_ptr_pos;
volatile const u64 grpc_stream_method_ptr_pos;
volatile const u64 grpc_status_s_pos;
volatile const u64 grpc_status_code_ptr_pos;
volatile const u64 tcp_addr_port_ptr_pos;
volatile const u64 tcp_addr_ip_ptr_pos;
volatile const u64 grpc_stream_ctx_ptr_pos;
volatile const u64 value_context_val_ptr_pos;
volatile const u64 grpc_st_conn_pos;
volatile const u64 grpc_t_conn_pos;
volatile const u64 grpc_t_scheme_pos;

// Context propagation
volatile const u64 http2_client_next_id_pos;
volatile const u64 framer_w_pos;
volatile const u64 grpc_transport_buf_writer_buf_pos;
volatile const u64 grpc_transport_buf_writer_offset_pos;

#define OPTIMISTIC_GRPC_ENCODED_HEADER_LEN 49 // 1 + 1 + 8 + 1 +~ 38 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(38) + hpack(generated tracepanent id)

/* Go runtime */

SEC("uprobe/runtime_newproc1")
int uprobe_proc_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    new_func_invocation_t invocation = {
        .parent = (u64)GO_PARAM2(ctx) 
    };

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &creator_goroutine, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/runtime_newproc1_return")
int uprobe_proc_newproc1_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    // Lookup the newproc1 invocation metadata
    new_func_invocation_t *invocation =
        bpf_map_lookup_elem(&newproc1, &creator_goroutine);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        goto done;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)invocation->parent;
    bpf_dbg_printk("parent goroutine_addr %lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = (u64)parent_goroutine,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

done:
    bpf_map_delete_elem(&newproc1, &creator_goroutine);

    return 0;
}

SEC("uprobe/runtime_goexit1")
int uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    // We also clean-up the go routine based trace map, it's an LRU
    // but at this point we are sure we don't need the data.
    bpf_map_delete_elem(&go_trace_map, &goroutine_addr);

    return 0;
}

/* HTTP Server */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *req = GO_PARAM4(ctx);

    server_http_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .tp = {0},
        .status = 0,
        .content_length = 0,
    };

    invocation.method[0] = 0;
    invocation.path[0] = 0;

    if (req) {
        server_trace_parent(goroutine_addr, &invocation.tp, (void*)(req + req_header_ptr_pos));
        // TODO: if context propagation is supported, overwrite the header value in the map with the 
        // new span context and the same thread id.

        // Get method from Request.Method
        if (!read_go_str("method", req, method_ptr_pos, &invocation.method, sizeof(invocation.method))) {
            bpf_dbg_printk("can't read http Request.Method");
            goto done;
        }

        // Get path from Request.URL
        void *url_ptr = 0;
        int res = bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req + url_ptr_pos));

        if (res || !url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &invocation.path, sizeof(invocation.path))) {
            bpf_dbg_printk("can't read http Request.URL.Path");
            goto done;
        }

        res = bpf_probe_read(&invocation.content_length, sizeof(invocation.content_length), (void *)(req + content_length_ptr_pos));
        if (res) {
            bpf_dbg_printk("can't read http Request.ContentLength");
            goto done;
        }
    } else {
        goto done;
    }
    
    // Write event
    if (bpf_map_update_elem(&ongoing_http_server_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

done:
    return 0;
}

SEC("uprobe/readRequest")
int uprobe_readRequestStart(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc readRequest === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &goroutine_addr);

    if (!existing) {
        void *c_ptr = GO_PARAM1(ctx);
        if (c_ptr) {
            void *conn_conn_ptr = c_ptr + 8 + c_rwc_pos; // embedded struct
            void *tls_state = 0;
            bpf_probe_read(&tls_state, sizeof(tls_state), (void *)(c_ptr + c_tls_pos));
            conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);
            //bpf_dbg_printk("conn_conn_ptr %llx, tls_state %llx, c_tls_pos = %d, c_tls_ptr = %llx", conn_conn_ptr, tls_state, c_tls_pos, c_ptr + c_tls_pos);
            if (conn_conn_ptr) {
                void *conn_ptr = 0;
                bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(conn_conn_ptr + net_conn_pos)); // find conn
                bpf_dbg_printk("conn_ptr %llx", conn_ptr);
                if (conn_ptr) {
                    connection_info_t conn = {0};
                    get_conn_info(conn_ptr, &conn); // initialized to 0, no need to check the result if we succeeded
                    bpf_map_update_elem(&ongoing_server_connections, &goroutine_addr, &conn, BPF_ANY);
                }
            }
        }
    }
    
    return 0;
}

SEC("uprobe/readRequest")
int uprobe_readRequestReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc readRequest returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    // This code is here for keepalive support on HTTP requests. Since the connection is not
    // established everytime, we set the initial goroutine start on the new read initiation.
    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (!g_metadata) {
        goroutine_metadata metadata = {
            .timestamp = bpf_ktime_get_ns(),
            .parent = (u64)goroutine_addr,
        };

        if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
            bpf_dbg_printk("can't update active goroutine");
        }
    }

    return 0;
}

SEC("uprobe/ServeHTTP_ret")
int uprobe_ServeHTTPReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);    

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &goroutine_addr);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(goroutine_addr);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_http_server_requests, &parent_go);
            goroutine_addr = parent_go;
        }
        if (!invocation) {
            bpf_dbg_printk("can't read http invocation metadata");
            return 0;
        }
    }    

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }
    
    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (g_metadata) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_server_connections, &goroutine_addr);

    if (info) {
        //dbg_print_http_connection_info(info);
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        // We can't find the connection info, this typically means there are too many requests per second
        // and the connection map is too small for the workload.
        bpf_dbg_printk("Can't find connection info for %llx", goroutine_addr);
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    // Server connections have opposite order, source port is the server port
    swap_connection_info_order(&trace->conn);
    trace->tp = invocation->tp;
    trace->content_length = invocation->content_length;
    __builtin_memcpy(trace->method, invocation->method, sizeof(trace->method));
    __builtin_memcpy(trace->path, invocation->path, sizeof(trace->path));
    trace->status = (u16)invocation->status;

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_http_server_requests, &goroutine_addr);
    bpf_map_delete_elem(&go_trace_map, &goroutine_addr);
    return 0;
}

#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request header map
    __type(value, u64); // the goroutine of the transport request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} header_req_map SEC(".maps");

#endif

/* HTTP Client. We expect to see HTTP client in both HTTP server and gRPC server calls.*/
static __always_inline void roundTripStartHelper(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *req = GO_PARAM2(ctx);

    http_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .tp = {0}
    };

    __attribute__((__unused__)) u8 existing_tp = client_trace_parent(goroutine_addr, &invocation.tp, (void*)(req + req_header_ptr_pos));

    http_client_data_t trace = {0};

    // Get method from Request.Method
    if (!read_go_str("method", req, method_ptr_pos, &trace.method, sizeof(trace.method))) {
        bpf_dbg_printk("can't read http Request.Method");
        return;
    }

    bpf_probe_read(&trace.content_length, sizeof(trace.content_length), (void *)(req + content_length_ptr_pos));

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace.path, sizeof(trace.path))) {
        bpf_dbg_printk("can't read http Request.URL.Path");
        return;
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_http_client_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

    bpf_map_update_elem(&ongoing_http_client_requests_data, &goroutine_addr, &trace, BPF_ANY);

#ifndef NO_HEADER_PROPAGATION
    //if (!existing_tp) {
        void *headers_ptr = 0;
        bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void*)(req + req_header_ptr_pos));
        bpf_dbg_printk("goroutine_addr %lx, req ptr %llx, headers_ptr %llx", goroutine_addr, req, headers_ptr);
        
        if (headers_ptr) {
            bpf_map_update_elem(&header_req_map, &headers_ptr, &goroutine_addr, BPF_ANY);
        }
    //}
#endif
}

SEC("uprobe/roundTrip")
int uprobe_roundTrip(struct pt_regs *ctx) {
    roundTripStartHelper(ctx);
    return 0;
}

SEC("uprobe/roundTrip_return")
int uprobe_roundTripReturn(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_client_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        goto done;
    }

    http_client_data_t *data = bpf_map_lookup_elem(&ongoing_http_client_requests_data, &goroutine_addr);
    if (data == NULL) {
        bpf_dbg_printk("can't read http client invocation data");
        goto done;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    // Copy the values read on request start
    __builtin_memcpy(trace->method, data->method, sizeof(trace->method));
    __builtin_memcpy(trace->path, data->path, sizeof(trace->path));
    trace->content_length = data->content_length;

    // Get request/response struct

    void *resp_ptr = (void *)GO_PARAM1(ctx);

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &goroutine_addr);
    if (info) {
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    trace->tp = invocation->tp;

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_code_ptr_pos));

    bpf_dbg_printk("status %d, offset %d, resp_ptr %lx", trace->status, status_code_ptr_pos, (u64)resp_ptr);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_http_client_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_client_requests_data, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_client_connections, &goroutine_addr);
    return 0;
}

#ifndef NO_HEADER_PROPAGATION
// Context propagation through HTTP headers
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc header writeSubset === ");

    void *header_addr = GO_PARAM1(ctx);
    void *io_writer_addr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr %lx, header ptr %llx", GOROUTINE_PTR(ctx), header_addr);

    u64 *request_goaddr = bpf_map_lookup_elem(&header_req_map, &header_addr);

    if (!request_goaddr) {
        bpf_dbg_printk("Can't find parent go routine for header %llx", header_addr);
        return 0;
    }

    u64 parent_goaddr = *request_goaddr;

    http_func_invocation_t *func_inv = bpf_map_lookup_elem(&ongoing_http_client_requests, &parent_goaddr);
    if (!func_inv) {
        bpf_dbg_printk("Can't find client request for goroutine %llx", parent_goaddr);
        goto done;
    }

    unsigned char buf[TRACEPARENT_LEN];

    make_tp_string(buf, &func_inv->tp);

    void *buf_ptr = 0;
    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos));
    if (!buf_ptr) {
        goto done;
    }
    
    s64 size = 0;
    bpf_probe_read(&size, sizeof(s64), (void *)(io_writer_addr + io_writer_buf_ptr_pos + 8)); // grab size

    s64 len = 0;
    bpf_probe_read(&len, sizeof(s64), (void *)(io_writer_addr + io_writer_n_pos)); // grab len

    bpf_dbg_printk("buf_ptr %llx, len=%d, size=%d", (void*)buf_ptr, len, size);

    if (len < (size - TP_MAX_VAL_LENGTH - TP_MAX_KEY_LENGTH - 4)) { // 4 = strlen(":_") + strlen("\r\n")
        char key[TP_MAX_KEY_LENGTH + 2] = "Traceparent: ";
        char end[2] = "\r\n";
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), key, sizeof(key));
        len += TP_MAX_KEY_LENGTH + 2;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), buf, sizeof(buf));
        len += TP_MAX_VAL_LENGTH;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), end, sizeof(end));
        len += 2;
        bpf_probe_write_user((void *)(io_writer_addr + io_writer_n_pos), &len, sizeof(len));
    }

done:
    bpf_map_delete_elem(&header_req_map, &header_addr);
    return 0;
}
#else
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    return 0;
}
#endif

// HTTP 2.0 server support
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int uprobe_http2ResponseWriterStateWriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc (http response)/(http2 responseWriterState) writeHeader === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    u64 status = (u64)GO_PARAM2(ctx);
    bpf_dbg_printk("goroutine_addr %lx, status %d", goroutine_addr, status);    

    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &goroutine_addr);

    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(goroutine_addr);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_http_server_requests, &parent_go);
            goroutine_addr = parent_go;
        }
        if (!invocation) {
            bpf_dbg_printk("can't read http invocation metadata");
            return 0;
        }
    }  

    invocation->status = status;

    return 0;
}

// HTTP 2.0 server support
SEC("uprobe/http2serverConn_runHandler")
int uprobe_http2serverConn_runHandler(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2serverConn_runHandler === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);    


    void *sc = GO_PARAM1(ctx);

    if (sc) {
        void *conn_ptr = 0;
        bpf_probe_read(&conn_ptr, sizeof(void *), sc + sc_conn_pos + 8);
        bpf_dbg_printk("conn_ptr %llx", conn_ptr);
        if (conn_ptr) {
            void *conn_conn_ptr = 0;
            bpf_probe_read(&conn_conn_ptr, sizeof(void *), conn_ptr + 8);
            bpf_dbg_printk("conn_conn_ptr %llx", conn_conn_ptr);
            if (conn_conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(conn_conn_ptr, &conn);
                bpf_map_update_elem(&ongoing_server_connections, &goroutine_addr, &conn, BPF_ANY);
            }
        }
    }

    return 0;
}

// HTTP 2.0 client support
#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // key: stream id
    __type(value, u64); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http2_req_map SEC(".maps");
#endif

SEC("uprobe/http2RoundTrip")
int uprobe_http2RoundTrip(struct pt_regs *ctx) {
    // we use the usual start helper, just like for normal http calls, but we later save
    // more context, like the streamID
    roundTripStartHelper(ctx);

    void *cc_ptr = GO_PARAM1(ctx);

    if (cc_ptr) {
        bpf_dbg_printk("cc_ptr %llx, cc_tconn_ptr %llx", cc_ptr, cc_ptr + cc_tconn_pos);
        void *tconn = cc_ptr + cc_tconn_pos;
        bpf_probe_read(&tconn, sizeof(tconn), (void *)(cc_ptr + cc_tconn_pos + 8));
        bpf_dbg_printk("tconn %llx", tconn);

        if (tconn) {
            void *tconn_conn = 0;
            bpf_probe_read(&tconn_conn, sizeof(tconn_conn), (void *)(tconn + 8));
            bpf_dbg_printk("tconn_conn %llx", tconn_conn);

            connection_info_t conn = {0};
            u8 ok = get_conn_info(tconn_conn, &conn);

            if (ok) {
                void *goroutine_addr = GOROUTINE_PTR(ctx);
                bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);    

                bpf_map_update_elem(&ongoing_client_connections, &goroutine_addr, &conn, BPF_ANY);
            }
        }

#ifndef NO_HEADER_PROPAGATION
        u32 stream_id = 0;
        bpf_probe_read(&stream_id, sizeof(stream_id), (void *)(cc_ptr + cc_next_stream_id_pos));
        
        bpf_dbg_printk("cc_ptr = %llx, nextStreamID=%d", cc_ptr, stream_id);
        if (stream_id) {
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            bpf_map_update_elem(&http2_req_map, &stream_id, &goroutine_addr, BPF_ANY);
        }
#endif    
    }

    return 0;
}

#ifndef NO_HEADER_PROPAGATION
#define MAX_W_PTR_N 1024

typedef struct framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 initial_n;
} framer_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void*); // key: go routine doing framer write headers
    __type(value, framer_func_invocation_t); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} framer_invocation_map SEC(".maps");

SEC("uprobe/http2FramerWriteHeaders")
int uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders === ");

    if (framer_w_pos == 0) {
        bpf_dbg_printk("framer w not found");
        return 0;
    }

    void *framer = GO_PARAM1(ctx);
    u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("framer=%llx, stream_id=%lld", framer, ((u64)stream_id));

    u32 stream_lookup = (u32)stream_id;

    void **go_ptr = bpf_map_lookup_elem(&http2_req_map, &stream_lookup);

    if (go_ptr) {
        void *go_addr = *go_ptr;
        bpf_dbg_printk("Found existing stream data goaddr = %llx", go_addr);

        http_func_invocation_t *info = bpf_map_lookup_elem(&ongoing_http_client_requests, &go_addr);

        if (info) {
            bpf_dbg_printk("Found func info %llx", info);
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            void *w_ptr = 0;
            bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + 8));
            if (w_ptr) {
                s64 n = 0;
                bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + io_writer_n_pos));

                bpf_dbg_printk("Found initial n = %d", n);

                // The offset is 0 on all connections we've tested with.
                // If we read some very large offset, we don't do anything since it might be a situation
                // we can't handle.
                if (n < MAX_W_PTR_N) {
                    framer_func_invocation_t f_info = {
                        .tp = info->tp,
                        .framer_ptr = (u64)framer,
                        .initial_n = n,
                    };

                    bpf_map_update_elem(&framer_invocation_map, &goroutine_addr, &f_info, BPF_ANY);
                } else {
                   bpf_dbg_printk("N too large, ignoring...");
                }
            }
        }
    }

    bpf_map_delete_elem(&http2_req_map, &stream_lookup);
    return 0;
}
#else
SEC("uprobe/http2FramerWriteHeaders")
int uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
    return 0;
}
#endif

#ifndef NO_HEADER_PROPAGATION
#define HTTP2_ENCODED_HEADER_LEN 66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + generated traceparent id

SEC("uprobe/http2FramerWriteHeaders_returns")
int uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);

    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &goroutine_addr);

    if (f_info) {
        void *w_ptr = 0;
        bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(f_info->framer_ptr + framer_w_pos + 8));

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = 0;
            s64 cap = 0;
            s64 initial_n = f_info->initial_n;

            bpf_probe_read(&buf_arr, sizeof(buf_arr), (void *)(w_ptr + io_writer_buf_ptr_pos));
            bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + io_writer_n_pos));
            bpf_probe_read(&cap, sizeof(cap), (void *)(w_ptr + io_writer_buf_ptr_pos + 16));

            bpf_clamp_umax(initial_n, MAX_W_PTR_N);

            //bpf_dbg_printk("Found f_info, this is the place to write to w = %llx, buf=%llx, n=%lld, size=%lld", w_ptr, buf_arr, n, cap);
            if (buf_arr && n < (cap - HTTP2_ENCODED_HEADER_LEN)) {
                uint8_t tp_str[TP_MAX_VAL_LENGTH];

                u8 type_byte = 0;
                u8 key_len = TP_ENCODED_LEN | 0x80; // high tagged to signify hpack encoded value
                u8 val_len = TP_MAX_VAL_LENGTH;

                // We don't hpack encode the value of the traceparent field, because that will require that 
                // we use bpf_loop, which in turn increases the kernel requirement to 5.17+.
                make_tp_string(tp_str, &f_info->tp);
                //bpf_dbg_printk("Will write %s, type = %d, key_len = %d, val_len = %d", tp_str, type_byte, key_len, val_len);

                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &type_byte, sizeof(type_byte));                        
                n++;
                // Write the length of the key = 8
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &key_len, sizeof(key_len));
                n++;
                // Write 'traceparent' encoded as hpack
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_encoded, sizeof(tp_encoded));;
                n += TP_ENCODED_LEN;
                // Write the length of the hpack encoded traceparent field 
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &val_len, sizeof(val_len));
                n++;
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_str, sizeof(tp_str));
                n += TP_MAX_VAL_LENGTH;
                // Update the value of n in w to reflect the new size
                bpf_probe_write_user((void *)(w_ptr + io_writer_n_pos), &n, sizeof(n));

                // http2 encodes the length of the headers in the first 3 bytes of buf, we need to update those
                u8 size_1 = 0;
                u8 size_2 = 0;
                u8 size_3 = 0;

                bpf_probe_read(&size_1, sizeof(size_1), (void *)(buf_arr + initial_n));
                bpf_probe_read(&size_2, sizeof(size_2), (void *)(buf_arr + initial_n + 1));
                bpf_probe_read(&size_3, sizeof(size_3), (void *)(buf_arr + initial_n + 2));

                bpf_dbg_printk("size 1:%x, 2:%x, 3:%x", size_1, size_2, size_3);

                u32 original_size = ((u32)(size_1) << 16) | ((u32)(size_2) << 8) | size_3;
                u32 new_size = original_size + HTTP2_ENCODED_HEADER_LEN;

                bpf_dbg_printk("Changing size from %d to %d", original_size, new_size);
                size_1 = (u8)(new_size >> 16);
                size_2 = (u8)(new_size >> 8);
                size_3 = (u8)(new_size);

                bpf_probe_write_user((void *)(buf_arr + initial_n), &size_1, sizeof(size_1));
                bpf_probe_write_user((void *)(buf_arr + initial_n +1), &size_2, sizeof(size_2));
                bpf_probe_write_user((void *)(buf_arr + initial_n + 2), &size_3, sizeof(size_3));
            }
        }
    }

    bpf_map_delete_elem(&framer_invocation_map, &goroutine_addr);
    return 0;
}
#else
SEC("uprobe/http2FramerWriteHeaders_returns")
int uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    return 0;
}
#endif 

SEC("uprobe/connServe")
int uprobe_connServe(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc http conn serve goroutine %lx === ", goroutine_addr);

    connection_info_t conn = {0};
    bpf_map_update_elem(&ongoing_server_connections, &goroutine_addr, &conn, BPF_ANY);

    return 0;
}

SEC("uprobe/netFdRead")
int uprobe_netFdRead(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD read goroutine %lx === ", goroutine_addr);

    connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &goroutine_addr);

    if (conn) {
        bpf_dbg_printk("Found existing server connection, parsing FD information for socket tuples, %llx", goroutine_addr);

        void *fd_ptr = GO_PARAM1(ctx);
        get_conn_info_from_fd(fd_ptr, conn); // ok to not check the result, we leave it as 0

        //dbg_print_http_connection_info(conn);
    }

    return 0;
}

SEC("uprobe/connServeRet")
int uprobe_connServeRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http conn serve ret === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_map_delete_elem(&ongoing_server_connections, &goroutine_addr);

    return 0;
}

SEC("uprobe/persistConnRoundTrip")
int uprobe_persistConnRoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http persistConn roundTrip === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_http_client_requests, &goroutine_addr);
    if (!invocation) {
        bpf_dbg_printk("can't find invocation info for client call, this might be a bug");
        return 0;
    }

    void *pc_ptr = GO_PARAM1(ctx);
    if (pc_ptr) {
        void *conn_conn_ptr = pc_ptr + 8 + pc_conn_pos; // embedded struct
        void *tls_state = 0;
        bpf_probe_read(&tls_state, sizeof(tls_state), (void *)(pc_ptr + pc_tls_pos)); // find tlsState
        bpf_dbg_printk("conn_conn_ptr %llx, tls_state %llx", conn_conn_ptr, tls_state);

        conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);

        if (conn_conn_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(conn_conn_ptr + net_conn_pos)); // find conn
            bpf_dbg_printk("conn_ptr %llx", conn_ptr);            
            if (conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(conn_ptr, &conn); // initialized to 0, no need to check the result if we succeeded
                u64 pid_tid = bpf_get_current_pid_tgid();
                u32 pid = pid_from_pid_tgid(pid_tid);
                tp_info_pid_t tp_p = {
                    .pid = pid,
                    .valid = 1,
                };

                tp_clone(&tp_p.tp, &invocation->tp);
                tp_p.tp.ts = bpf_ktime_get_ns();
                bpf_dbg_printk("storing trace_map info for black-box tracing");
                bpf_map_update_elem(&ongoing_client_connections, &goroutine_addr, &conn, BPF_ANY);

                // Must sort the connection info, this map is shared with kprobes which use sorted connection
                // info always.
                sort_connection_info(&conn);
                bpf_map_update_elem(&trace_map, &conn, &tp_p, BPF_ANY);
            }
        }
    }

    return 0;
}

// SQL support
// This implementation was inspired by https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/ca1afccea6ec520d18238c3865024a9f5b9c17fe/internal/pkg/instrumentors/bpf/database/sql/bpf/probe.bpf.c
// and has been modified since.

typedef struct sql_func_invocation {
    u64 start_monotime_ns;
    u64 sql_param;
    u64 query_len;
    tp_info_t tp;
} sql_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, sql_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_sql_queries SEC(".maps");

static __always_inline void set_sql_info(void *goroutine_addr, void *sql_param, void *query_len) {
    sql_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .sql_param = (u64)sql_param,
        .query_len = (u64)query_len,
        .tp = {0}
    };

    // We don't look up in the headers, no http/grpc request, therefore 0 as last argument
    client_trace_parent(goroutine_addr, &invocation.tp, 0);

    // Write event
    if (bpf_map_update_elem(&ongoing_sql_queries, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }
}

SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *sql_param = GO_PARAM8(ctx);
    void *query_len = GO_PARAM9(ctx);
    set_sql_info(goroutine_addr, sql_param, query_len);
    return 0;
}

SEC("uprobe/execDC")
int uprobe_execDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/execDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *sql_param = GO_PARAM6(ctx);
    void *query_len = GO_PARAM7(ctx);
    set_sql_info(goroutine_addr, sql_param, query_len);
    return 0;
}

SEC("uprobe/queryDC")
int uprobe_queryReturn(struct pt_regs *ctx) {

    bpf_dbg_printk("=== uprobe/query return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    sql_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("Request not found for this goroutine");
        return 0;
    }
    bpf_map_delete_elem(&ongoing_sql_queries, &goroutine_addr);

    sql_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(sql_request_trace), 0);
    if (trace) {
        task_pid(&trace->pid);
        trace->type = EVENT_SQL_CLIENT;
        trace->start_monotime_ns = invocation->start_monotime_ns;
        trace->end_monotime_ns = bpf_ktime_get_ns();

        void *resp_ptr = GO_PARAM1(ctx);
        trace->status = (resp_ptr == NULL);
        trace->tp = invocation->tp;

        u64 query_len = invocation->query_len;
        if (query_len > sizeof(trace->sql)) {
            query_len = sizeof(trace->sql);
        }
        bpf_probe_read(trace->sql, query_len, (void*)invocation->sql_param);
        bpf_dbg_printk("Found sql statement %s", trace->sql);
        if (query_len < sizeof(trace->sql)) {
            trace->sql[query_len] = 0;
        }
        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}

/* gRPC Server */
SEC("uprobe/server_handleStream")
int uprobe_server_handleStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *stream_ptr = GO_PARAM4(ctx);

    grpc_srv_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .stream = (u64)stream_ptr,
        .tp = {0},
    };

    if (stream_ptr) {
        void *ctx_ptr = 0;
        // Read the embedded context object ptr
        bpf_probe_read(&ctx_ptr, sizeof(ctx_ptr), (void *)(stream_ptr + grpc_stream_ctx_ptr_pos + sizeof(void *)));

        if (ctx_ptr) {
            server_trace_parent(goroutine_addr, &invocation.tp, (void *)(ctx_ptr + value_context_val_ptr_pos + sizeof(void *)));
        }
    }

    if (bpf_map_update_elem(&ongoing_grpc_server_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    return 0;
}

// Sets up the connection info to be grabbed and mapped over the transport to operateHeaders
SEC("uprobe/netFdReadGRPC")
int uprobe_netFdReadGRPC(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/proc netFD read goroutine %lx === ", goroutine_addr);

    void *tr = bpf_map_lookup_elem(&ongoing_grpc_operate_headers, &goroutine_addr);
    bpf_dbg_printk("tr %llx", tr);
    if (tr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, tr);
        bpf_dbg_printk("t %llx", t);
        if (t) {
            void *fd_ptr = GO_PARAM1(ctx);
            get_conn_info_from_fd(fd_ptr, &t->conn); // ok to not check the result, we leave it as 0
        }
    }

    return 0;
}

// Handles finding the connection information for http2 servers in grpc
SEC("uprobe/http2Server_operateHeaders")
int uprobe_http2Server_operateHeaders(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *tr = GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/http2Server_operateHeaders tr %llx goroutine %lx === ", tr, goroutine_addr);

    grpc_transports_t t = {
        .type = TRANSPORT_HTTP2,
        .conn = {0},
    };

    bpf_map_update_elem(&ongoing_grpc_operate_headers, &goroutine_addr, &tr, BPF_ANY);
    bpf_map_update_elem(&ongoing_grpc_transports, &tr, &t, BPF_ANY);

    return 0;
}

// Handles finding the connection information for grpc ServeHTTP
SEC("uprobe/serverHandlerTransport_HandleStreams")
int uprobe_server_handler_transport_handle_streams(struct pt_regs *ctx) {
    void *tr = GO_PARAM1(ctx);
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("=== uprobe/serverHandlerTransport_HandleStreams tr %llx goroutine %lx === ", tr, goroutine_addr);

    void *parent_go = (void *)find_parent_goroutine(goroutine_addr);
    if (parent_go) {
        bpf_dbg_printk("found parent goroutine for transport handler [%llx]", parent_go);
        connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &parent_go);
        bpf_dbg_printk("conn %llx", conn);
        if (conn) {
            grpc_transports_t t = {
                .type = TRANSPORT_HANDLER,
            };
            __builtin_memcpy(&t.conn, conn, sizeof(connection_info_t));
            
            bpf_map_update_elem(&ongoing_grpc_transports, &tr, &t, BPF_ANY);
        }
    }

    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_srv_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata");
        goto done;
    }

    u16 *status_ptr = bpf_map_lookup_elem(&ongoing_grpc_request_status, &goroutine_addr);
    u16 status = 0;
    if (status_ptr != NULL) {
        bpf_dbg_printk("can't read grpc invocation status");
        status = *status_ptr;        
    }

    void *stream_ptr = (void *)invocation->stream;
    bpf_dbg_printk("stream_ptr %lx, method pos %lx", stream_ptr, grpc_stream_method_ptr_pos);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }
    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->status = status;
    trace->content_length = 0;
    trace->method[0] = 0;

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (g_metadata) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Get method from transport.Stream.Method
    if (!read_go_str("grpc method", stream_ptr, grpc_stream_method_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_dbg_printk("can't read grpc transport.Stream.Method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    void *st_ptr = 0;
    u8 found_conn = 0;
    // Read the embedded object ptr
    bpf_probe_read(&st_ptr, sizeof(st_ptr), (void *)(stream_ptr + grpc_stream_st_ptr_pos + sizeof(void *)));

    bpf_dbg_printk("st_ptr %llx", st_ptr);
    if (st_ptr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, &st_ptr);

        bpf_dbg_printk("found t %llx", t);
        if (t) {
            bpf_dbg_printk("setting up connection info from grpc handler");
            __builtin_memcpy(&trace->conn, &t->conn, sizeof(connection_info_t));
            found_conn = 1;
        }
    }

    if (!found_conn) {
        bpf_dbg_printk("can't find connection info for st_ptr %llx", st_ptr);
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    // Server connections have port order reversed from what we want
    swap_connection_info_order(&trace->conn);
    trace->tp = invocation->tp;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_grpc_server_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_request_status, &goroutine_addr);
    bpf_map_delete_elem(&go_trace_map, &goroutine_addr);

    return 0;
}

SEC("uprobe/transport_writeStatus")
int uprobe_transport_writeStatus(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/transport_writeStatus === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *status_ptr = GO_PARAM3(ctx);
    bpf_dbg_printk("status_ptr %lx", status_ptr);

    if (status_ptr != NULL) {
        void *s_ptr;
        bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(status_ptr + grpc_status_s_pos));

        bpf_dbg_printk("s_ptr %lx", s_ptr);

        if (s_ptr != NULL) {
            u16 status = -1;
            bpf_probe_read(&status, sizeof(status), (void *)(s_ptr + grpc_status_code_ptr_pos));
            bpf_dbg_printk("status code %d", status);
            bpf_map_update_elem(&ongoing_grpc_request_status, &goroutine_addr, &status, BPF_ANY);
        }
    }

    return 0;
}

/* GRPC client */
static __always_inline void clientConnStart(void *goroutine_addr, void *cc_ptr, void *ctx_ptr, void *method_ptr, void *method_len) {
    grpc_client_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .cc = (u64)cc_ptr,
        .method = (u64)method_ptr,
        .method_len = (u64)method_len,
        .tp = {0},
        .flags = 0,
    };

    if (ctx_ptr) {
        void *val_ptr = 0;
        // Read the embedded val object ptr from ctx if there's one
        bpf_probe_read(&val_ptr, sizeof(val_ptr), (void *)(ctx_ptr + value_context_val_ptr_pos + sizeof(void *)));

        invocation.flags = client_trace_parent(goroutine_addr, &invocation.tp, (void *)(val_ptr));
    } else {
        // it's OK sending empty tp for a client, the userspace id generator will make random trace_id, span_id
        bpf_dbg_printk("No ctx_ptr %llx", ctx_ptr);
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_grpc_client_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc client map element");
    }
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Invoke === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM4(ctx);
    void *method_len = GO_PARAM5(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int uprobe_ClientConn_NewStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.NewStream === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM5(ctx);
    void *method_len = GO_PARAM6(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

static __always_inline int grpc_connect_done(struct pt_regs *ctx, void *err) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_client_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, &goroutine_addr);

    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc client invocation metadata");
        goto done;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    trace->content_length = 0;
    trace->method[0] = 0;

    // Read arguments from the original set of registers

    // Get client request value pointers
    void *method_ptr = (void *)invocation->method;
    void *method_len = (void *)invocation->method_len;

    bpf_dbg_printk("method ptr = %lx, method_len = %d", method_ptr, method_len);

    // Get method from the incoming call arguments
    if (!read_go_str_n("method", method_ptr, (u64)method_len, &trace->path, sizeof(trace->path))) {
        bpf_dbg_printk("can't read grpc client method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &goroutine_addr);

    if (info) {
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    trace->tp = invocation->tp;

    trace->status = (err) ? 2 : 0; // Getting the gRPC client status is complex, if there's an error we set Code.Unknown = 2

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_grpc_client_requests, &goroutine_addr);
    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int uprobe_ClientConn_NewStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.NewStream return === ");
    
    void *stream = GO_PARAM1(ctx);

    if (!stream) {
        return grpc_connect_done(ctx, (void *)1);
    }

    return 0;
}

SEC("uprobe/ClientConn_Close")
int uprobe_ClientConn_Close(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Close === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_grpc_client_requests, &goroutine_addr);

    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Invoke return === ");
    
    void *err = GO_PARAM1(ctx);

    if (err) {
        return grpc_connect_done(ctx, err);
    }

    return 0;
}

// google.golang.org/grpc.(*clientStream).RecvMsg
SEC("uprobe/clientStream_RecvMsg")
int uprobe_clientStream_RecvMsg_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc clientStream.RecvMsg return === ");
    void *err = (void *)GO_PARAM1(ctx);
    return grpc_connect_done(ctx, err);
}

// The gRPC client stream is written on another goroutine in transport loopyWriter (controlbuf.go).
// We extract the stream ID when it's just created and make a mapping of it to our goroutine that's executing ClientConn.Invoke.
SEC("uprobe/transport_http2Client_NewStream")
int uprobe_transport_http2Client_NewStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc transport.(*http2Client).NewStream === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *t_ptr = GO_PARAM1(ctx);

    bpf_dbg_printk("goroutine_addr %lx, t_ptr %llx, t.conn_pos %x", goroutine_addr, t_ptr, grpc_t_conn_pos);

    if (t_ptr) {
        void *conn_ptr = t_ptr + grpc_t_conn_pos + 8;
        u8 buf[16];
        u64 is_secure = 0;

        void *s_ptr = 0;
        buf[0] = 0;
        bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(t_ptr + grpc_t_scheme_pos));
        bpf_probe_read(buf, sizeof(buf), s_ptr);
        
        //bpf_dbg_printk("scheme %s", buf);

        if (buf[0] == 'h' && buf[1] == 't' && buf[2] == 't' && buf[3] == 'p' && buf[4] == 's') {
            is_secure = 1;
        }

        if (is_secure) {
            // double wrapped in grpc
            conn_ptr = unwrap_tls_conn_info(conn_ptr, (void *)is_secure);
            conn_ptr = unwrap_tls_conn_info(conn_ptr, (void *)is_secure);
        }
        bpf_dbg_printk("conn_ptr %llx is_secure %lld", conn_ptr, is_secure);
        if (conn_ptr) {
            void *conn_conn_ptr = 0;
            bpf_probe_read(&conn_conn_ptr, sizeof(conn_conn_ptr), conn_ptr);
            bpf_dbg_printk("conn_conn_ptr %llx", conn_conn_ptr);
            if (conn_conn_ptr) {                
                connection_info_t conn = {0};
                u8 ok = get_conn_info(conn_conn_ptr, &conn);
                if (ok) {
                    bpf_map_update_elem(&ongoing_client_connections, &goroutine_addr, &conn, BPF_ANY);
                }
            }
        } 

#ifndef NO_HEADER_PROPAGATION
        u32 next_id = 0;
        // Read the next stream id from the httpClient
        bpf_probe_read(&next_id, sizeof(next_id), (void *)(t_ptr + http2_client_next_id_pos));

        bpf_dbg_printk("next_id %d", next_id);

        grpc_client_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_grpc_client_requests, &goroutine_addr);

        if (invocation) {
            grpc_client_func_invocation_t inv_save = *invocation;
            // This map is an LRU map, we can't be sure that all created streams are going to be
            // seen later by writeHeader to clean up this mapping.
            bpf_map_update_elem(&ongoing_streams, &next_id, &inv_save, BPF_ANY);
        } else {
            bpf_dbg_printk("Couldn't find invocation metadata for goroutine %lx", goroutine_addr);
        }
#endif    
    }
    
    return 0;
}

#ifndef NO_HEADER_PROPAGATION
typedef struct grpc_framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 offset;
} grpc_framer_func_invocation_t;

#define MAX_W_PTR_OFFSET 1024

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void*); // key: go routine doing framer write headers
    __type(value, grpc_framer_func_invocation_t); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_framer_invocation_map SEC(".maps");

SEC("uprobe/grpcFramerWriteHeaders")
int uprobe_grpcFramerWriteHeaders(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc Framer writeHeaders === ");

    if (framer_w_pos == 0) {
        bpf_dbg_printk("framer w not found");
        return 0;
    }

    void *framer = GO_PARAM1(ctx);
    u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("framer=%llx, stream_id=%lld, framer_w_pos %llx", framer, ((u64)stream_id), framer_w_pos);

    u32 stream_lookup = (u32)stream_id;

    grpc_client_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_streams, &stream_lookup);

    if (invocation) {
        bpf_dbg_printk("Found invocation info %llx", invocation);
        void *goroutine_addr = GOROUTINE_PTR(ctx);

        void *w_ptr = (void *)(framer + framer_w_pos + 16);
        bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + 8));

        if (w_ptr) {
            s64 offset;
            bpf_probe_read(&offset, sizeof(offset), (void *)(w_ptr + grpc_transport_buf_writer_offset_pos));

            bpf_dbg_printk("Found initial data offset %d", offset);

            // The offset will be 0 on first connection through the stream and 9 on subsequent.
            // If we read some very large offset, we don't do anything since it might be a situation
            // we can't handle
            if (offset < MAX_W_PTR_OFFSET) {
                grpc_framer_func_invocation_t f_info = {
                    .tp = invocation->tp,
                    .framer_ptr = (u64)framer,
                    .offset = offset,
                };

                bpf_map_update_elem(&grpc_framer_invocation_map, &goroutine_addr, &f_info, BPF_ANY);
            } else {
                bpf_dbg_printk("Offset too large, ignoring...");
            }
        }
    }

    bpf_map_delete_elem(&ongoing_streams, &stream_id);
    return 0;
}
#else
SEC("uprobe/grpcFramerWriteHeaders")
int uprobe_grpcFramerWriteHeaders(struct pt_regs *ctx) {
    return 0;
}
#endif

#ifndef NO_HEADER_PROPAGATION
#define HTTP2_ENCODED_HEADER_LEN 66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + generated traceparent id

SEC("uprobe/grpcFramerWriteHeaders_returns")
int uprobe_grpcFramerWriteHeaders_returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc Framer writeHeaders returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);

    grpc_framer_func_invocation_t *f_info = bpf_map_lookup_elem(&grpc_framer_invocation_map, &goroutine_addr);

    if (f_info) {
        void *w_ptr = (void *)(f_info->framer_ptr + framer_w_pos + 16);
        bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(f_info->framer_ptr + framer_w_pos + 8));

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = 0;
            s64 cap = 0;
            u64 off = f_info->offset;

            bpf_probe_read(&buf_arr, sizeof(buf_arr), (void *)(w_ptr + grpc_transport_buf_writer_buf_pos)); // the buffer is the first field
            bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + grpc_transport_buf_writer_offset_pos));
            bpf_probe_read(&cap, sizeof(cap), (void *)(w_ptr + grpc_transport_buf_writer_offset_pos + 16)); // the offset of the capacity is 2 * 8 bytes from the buf

            bpf_clamp_umax(off, MAX_W_PTR_OFFSET);

            //bpf_dbg_printk("Found f_info, this is the place to write to w = %llx, buf=%llx, n=%lld, size=%lld", w_ptr, buf_arr, n, cap);
            if (buf_arr && n < (cap - HTTP2_ENCODED_HEADER_LEN)) {
                uint8_t tp_str[TP_MAX_VAL_LENGTH];

                u8 type_byte = 0;
                u8 key_len = TP_ENCODED_LEN | 0x80; // high tagged to signify hpack encoded value
                u8 val_len = TP_MAX_VAL_LENGTH;

                // We don't hpack encode the value of the traceparent field, because that will require that 
                // we use bpf_loop, which in turn increases the kernel requirement to 5.17+.
                make_tp_string(tp_str, &f_info->tp);
                //bpf_dbg_printk("Will write %s, type = %d, key_len = %d, val_len = %d", tp_str, type_byte, key_len, val_len);

                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &type_byte, sizeof(type_byte));                        
                n++;
                // Write the length of the key = 8
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &key_len, sizeof(key_len));
                n++;
                // Write 'traceparent' encoded as hpack
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_encoded, sizeof(tp_encoded));;
                n += TP_ENCODED_LEN;
                // Write the length of the hpack encoded traceparent field 
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &val_len, sizeof(val_len));
                n++;
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_str, sizeof(tp_str));
                n += TP_MAX_VAL_LENGTH;
                // Update the value of n in w to reflect the new size
                bpf_probe_write_user((void *)(w_ptr + grpc_transport_buf_writer_offset_pos), &n, sizeof(n));

                // http2 encodes the length of the headers in the first 3 bytes of buf, we need to update those
                u8 size_1 = 0;
                u8 size_2 = 0;
                u8 size_3 = 0;

                bpf_probe_read(&size_1, sizeof(size_1), (void *)(buf_arr + off));
                bpf_probe_read(&size_2, sizeof(size_2), (void *)(buf_arr + off + 1));
                bpf_probe_read(&size_3, sizeof(size_3), (void *)(buf_arr + off + 2));

                bpf_dbg_printk("size 1:%x, 2:%x, 3:%x", size_1, size_2, size_3);

                u32 original_size = ((u32)(size_1) << 16) | ((u32)(size_2) << 8) | size_3;
                u32 new_size = original_size + HTTP2_ENCODED_HEADER_LEN;

                bpf_dbg_printk("Changing size from %d to %d", original_size, new_size);
                size_1 = (u8)(new_size >> 16);
                size_2 = (u8)(new_size >> 8);
                size_3 = (u8)(new_size);

                bpf_probe_write_user((void *)(buf_arr + off), &size_1, sizeof(size_1));
                bpf_probe_write_user((void *)(buf_arr + off + 1), &size_2, sizeof(size_2));
                bpf_probe_write_user((void *)(buf_arr + off + 2), &size_3, sizeof(size_3));
            }
        }
    }

    bpf_map_delete_elem(&grpc_framer_invocation_map, &goroutine_addr);
    return 0;
}
#else
SEC("uprobe/grpcFramerWriteHeaders_returns")
int uprobe_grpcFramerWriteHeaders_returns(struct pt_regs *ctx) {
    return 0;
}
#endif 