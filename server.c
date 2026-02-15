/*
 * wasmexec-c: HTTP server for content-addressable blob storage + wasm execution
 *
 * Dependencies: libmicrohttpd, sqlite3, wasm3 (vendored)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <microhttpd.h>
#include <sqlite3.h>
#include "wasm3/wasm3.h"

/* ── constants ─────────────────────────────────────────────────────── */

#define PORT            8000
#define STACK_SIZE      (256 * 1024)
#define WASM_INPUT_OFF  0x10000
#define SHA256_LEN      32
#define SHA256_HEX_LEN  64

/* ── SHA-256 (minimal, self-contained) ─────────────────────────────── */

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64], a,b,c,d,e,f,g,h;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)block[i*4]<<24 | (uint32_t)block[i*4+1]<<16 |
               (uint32_t)block[i*4+2]<<8  | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19)  ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    size_t i;
    for (i = 0; i + 64 <= len; i += 64)
        sha256_transform(state, data + i);
    uint8_t block[64];
    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256_transform(state, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        block[56 + j] = (uint8_t)(bits >> (56 - j * 8));
    sha256_transform(state, block);
    for (int j = 0; j < 8; j++) {
        out[j*4+0] = (uint8_t)(state[j] >> 24);
        out[j*4+1] = (uint8_t)(state[j] >> 16);
        out[j*4+2] = (uint8_t)(state[j] >>  8);
        out[j*4+3] = (uint8_t)(state[j]);
    }
}

static void hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0x0f];
    }
    out[len*2] = '\0';
}

static int hex_decode(const char *in, size_t hex_len, uint8_t *out) {
    if (hex_len % 2 != 0) return -1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi, lo;
        if      (in[i] >= '0' && in[i] <= '9') hi = in[i] - '0';
        else if (in[i] >= 'a' && in[i] <= 'f') hi = in[i] - 'a' + 10;
        else if (in[i] >= 'A' && in[i] <= 'F') hi = in[i] - 'A' + 10;
        else return -1;
        if      (in[i+1] >= '0' && in[i+1] <= '9') lo = in[i+1] - '0';
        else if (in[i+1] >= 'a' && in[i+1] <= 'f') lo = in[i+1] - 'a' + 10;
        else if (in[i+1] >= 'A' && in[i+1] <= 'F') lo = in[i+1] - 'A' + 10;
        else return -1;
        out[i/2] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ── SQLite blob store ─────────────────────────────────────────────── */

static sqlite3 *db;

static int db_init(const char *path) {
    int rc = sqlite3_open(path, &db);
    if (rc) { fprintf(stderr, "sqlite: %s\n", sqlite3_errmsg(db)); return -1; }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS blobs ("
        "  hash BLOB PRIMARY KEY,"
        "  data BLOB NOT NULL"
        ") WITHOUT ROWID;";
    char *err = NULL;
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc) { fprintf(stderr, "sqlite: %s\n", err); sqlite3_free(err); return -1; }
    /* WAL mode for better concurrent reads */
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    return 0;
}

/* Returns 0 on success (inserted or already exists), -1 on error */
static int db_put(const uint8_t hash[32], const uint8_t *data, size_t len) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO blobs (hash, data) VALUES (?, ?)", -1, &stmt, NULL);
    if (rc) return -1;
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, data, (int)len, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* Returns blob data (caller must free), sets *out_len. NULL if not found. */
static uint8_t *db_get(const uint8_t hash[32], size_t *out_len) {
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db,
        "SELECT data FROM blobs WHERE hash = ?", -1, &stmt, NULL);
    if (rc) return NULL;
    sqlite3_bind_blob(stmt, 1, hash, 32, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return NULL; }
    int blen = sqlite3_column_bytes(stmt, 0);
    const void *bdata = sqlite3_column_blob(stmt, 0);
    uint8_t *copy = malloc(blen);
    if (copy) { memcpy(copy, bdata, blen); *out_len = blen; }
    sqlite3_finalize(stmt);
    return copy;
}

/* ── wasm execution ────────────────────────────────────────────────── */

typedef struct {
    uint8_t *output;
    size_t   output_len;
    char     error[256];
} ExecResult;

static ExecResult exec_wasm(const uint8_t *wasm_bytes, size_t wasm_len,
                            const uint8_t *input, size_t input_len) {
    ExecResult res = {0};

    IM3Environment env = m3_NewEnvironment();
    if (!env) { snprintf(res.error, sizeof(res.error), "failed to create wasm3 environment"); return res; }

    IM3Runtime runtime = m3_NewRuntime(env, STACK_SIZE, NULL);
    if (!runtime) { snprintf(res.error, sizeof(res.error), "failed to create wasm3 runtime"); m3_FreeEnvironment(env); return res; }

    IM3Module module;
    M3Result r = m3_ParseModule(env, &module, wasm_bytes, (uint32_t)wasm_len);
    if (r) { snprintf(res.error, sizeof(res.error), "parse: %s", r); m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res; }

    r = m3_LoadModule(runtime, module);
    if (r) { snprintf(res.error, sizeof(res.error), "load: %s", r); m3_FreeModule(module); m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res; }
    /* module is now owned by runtime */

    IM3Function run_fn;
    r = m3_FindFunction(&run_fn, runtime, "run");
    if (r) { snprintf(res.error, sizeof(res.error), "find 'run': %s", r); m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res; }

    /* get memory, write input */
    uint32_t mem_size = 0;
    uint8_t *mem = m3_GetMemory(runtime, &mem_size, 0);
    if (!mem || mem_size < WASM_INPUT_OFF + input_len) {
        snprintf(res.error, sizeof(res.error), "memory too small: have %u, need %zu",
                 mem_size, (size_t)WASM_INPUT_OFF + input_len);
        m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res;
    }
    memcpy(mem + WASM_INPUT_OFF, input, input_len);

    /* call run(input_ptr, input_len) */
    uint32_t args[2] = { WASM_INPUT_OFF, (uint32_t)input_len };
    const void *arg_ptrs[2] = { &args[0], &args[1] };
    r = m3_Call(run_fn, 2, arg_ptrs);
    if (r) { snprintf(res.error, sizeof(res.error), "call: %s", r); m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res; }

    /* read return value: pointer to [len:u32le][data...] */
    uint32_t out_ptr = 0;
    const void *ret_ptrs[1] = { &out_ptr };
    r = m3_GetResults(run_fn, 1, ret_ptrs);
    if (r) { snprintf(res.error, sizeof(res.error), "results: %s", r); m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res; }

    /* re-fetch memory (may have grown) */
    mem = m3_GetMemory(runtime, &mem_size, 0);
    if (!mem || out_ptr + 4 > mem_size) {
        snprintf(res.error, sizeof(res.error), "output pointer out of bounds");
        m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res;
    }

    uint32_t out_len;
    memcpy(&out_len, mem + out_ptr, 4); /* LE on LE host */
    if (out_ptr + 4 + out_len > mem_size) {
        snprintf(res.error, sizeof(res.error), "output data out of bounds");
        m3_FreeRuntime(runtime); m3_FreeEnvironment(env); return res;
    }

    res.output = malloc(out_len);
    if (res.output) {
        memcpy(res.output, mem + out_ptr + 4, out_len);
        res.output_len = out_len;
    }

    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    return res;
}

/* ── HTTP upload accumulator ───────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} UploadBuf;

static UploadBuf *upload_new(void) {
    UploadBuf *u = calloc(1, sizeof(UploadBuf));
    return u;
}

static int upload_append(UploadBuf *u, const char *data, size_t len) {
    if (u->len + len > u->cap) {
        size_t newcap = (u->cap == 0) ? 4096 : u->cap;
        while (newcap < u->len + len) newcap *= 2;
        uint8_t *tmp = realloc(u->data, newcap);
        if (!tmp) return -1;
        u->data = tmp;
        u->cap = newcap;
    }
    memcpy(u->data + u->len, data, len);
    u->len += len;
    return 0;
}

static void upload_free(UploadBuf *u) {
    if (u) { free(u->data); free(u); }
}

/* ── HTTP helpers ──────────────────────────────────────────────────── */

static struct MHD_Response *respond_text(unsigned int *code, unsigned int c,
                                         const char *text) {
    *code = c;
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(text), (void *)text, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "text/plain");
    return resp;
}

static struct MHD_Response *respond_json(unsigned int *code, unsigned int c,
                                         const char *json) {
    *code = c;
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(json), (void *)json, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    return resp;
}

/* ── request handler ───────────────────────────────────────────────── */

static enum MHD_Result handle_request(
    void *cls,
    struct MHD_Connection *conn,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{
    (void)cls; (void)version;

    /* First call: allocate upload buffer */
    if (*con_cls == NULL) {
        *con_cls = upload_new();
        return MHD_YES;
    }

    UploadBuf *ubuf = (UploadBuf *)*con_cls;

    /* Accumulate upload data */
    if (*upload_data_size > 0) {
        upload_append(ubuf, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* All data received — route the request */
    struct MHD_Response *resp = NULL;
    unsigned int code = 200;

    /* PUT /blobs */
    if (strcmp(method, "PUT") == 0 && strcmp(url, "/blobs") == 0) {
        if (ubuf->len == 0) {
            resp = respond_text(&code, 400, "empty body\n");
        } else {
            uint8_t hash[32];
            sha256(ubuf->data, ubuf->len, hash);
            if (db_put(hash, ubuf->data, ubuf->len) != 0) {
                resp = respond_text(&code, 500, "db error\n");
            } else {
                char hex[65];
                hex_encode(hash, 32, hex);
                char body[128];
                snprintf(body, sizeof(body), "{\"hash\":\"%s\"}\n", hex);
                resp = respond_json(&code, 200, body);
            }
        }
    }

    /* GET /blobs/:hash */
    else if (strcmp(method, "GET") == 0 && strncmp(url, "/blobs/", 7) == 0) {
        const char *hash_hex = url + 7;
        if (strlen(hash_hex) != SHA256_HEX_LEN) {
            resp = respond_text(&code, 400, "invalid hash length\n");
        } else {
            uint8_t hash[32];
            if (hex_decode(hash_hex, SHA256_HEX_LEN, hash) != 0) {
                resp = respond_text(&code, 400, "invalid hex\n");
            } else {
                size_t blen;
                uint8_t *bdata = db_get(hash, &blen);
                if (!bdata) {
                    resp = respond_text(&code, 404, "not found\n");
                } else {
                    code = 200;
                    resp = MHD_create_response_from_buffer(blen, bdata, MHD_RESPMEM_MUST_FREE);
                    MHD_add_response_header(resp, "Content-Type", "application/octet-stream");
                }
            }
        }
    }

    /* POST /execute/:hash */
    else if (strcmp(method, "POST") == 0 && strncmp(url, "/execute/", 9) == 0) {
        const char *hash_hex = url + 9;
        if (strlen(hash_hex) != SHA256_HEX_LEN) {
            resp = respond_text(&code, 400, "invalid hash length\n");
        } else {
            uint8_t hash[32];
            if (hex_decode(hash_hex, SHA256_HEX_LEN, hash) != 0) {
                resp = respond_text(&code, 400, "invalid hex\n");
            } else {
                size_t wasm_len;
                uint8_t *wasm_data = db_get(hash, &wasm_len);
                if (!wasm_data) {
                    resp = respond_text(&code, 404, "blob not found\n");
                } else {
                    ExecResult er = exec_wasm(wasm_data, wasm_len,
                                             ubuf->data, ubuf->len);
                    free(wasm_data);
                    if (er.error[0]) {
                        char msg[512];
                        snprintf(msg, sizeof(msg), "{\"error\":\"%s\"}\n", er.error);
                        resp = respond_json(&code, 500, msg);
                    } else {
                        code = 200;
                        resp = MHD_create_response_from_buffer(
                            er.output_len, er.output, MHD_RESPMEM_MUST_FREE);
                        MHD_add_response_header(resp, "Content-Type", "application/octet-stream");
                    }
                }
            }
        }
    }

    else {
        resp = respond_text(&code, 404, "not found\n");
    }

    enum MHD_Result ret = MHD_queue_response(conn, code, resp);
    MHD_destroy_response(resp);
    return ret;
}

static void request_completed(void *cls, struct MHD_Connection *conn,
                              void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    upload_free((UploadBuf *)*con_cls);
    *con_cls = NULL;
}

/* ── main ──────────────────────────────────────────────────────────── */

static volatile sig_atomic_t running = 1;
static void sighandler(int s) { (void)s; running = 0; }

int main(int argc, char **argv) {
    const char *db_path = (argc > 1) ? argv[1] : "blobs.db";
    int port = PORT;
    if (argc > 2) port = atoi(argv[2]);

    if (db_init(db_path) != 0) return 1;

    struct MHD_Daemon *d = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD,
        (uint16_t)port,
        NULL, NULL,
        handle_request, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        MHD_OPTION_END);
    if (!d) { fprintf(stderr, "failed to start server on port %d\n", port); return 1; }

    printf("listening on :%d\n", port);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    while (running) pause();

    MHD_stop_daemon(d);
    sqlite3_close(db);
    printf("\nshutdown\n");
    return 0;
}
