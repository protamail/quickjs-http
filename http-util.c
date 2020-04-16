#include "quickjs-libc.h"
#include "http_parser.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
//#include <stdlib.h>
//#include <sys/wait.h>
//#include <malloc.h>
//#include <pthread.h>

static JSValue js_set_proc_name(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowInternalError(ctx, "Expecting proc_name");
    const char *str = JS_ToCString(ctx, argv[0]);
    prctl(PR_SET_NAME, str);
    JS_FreeCString(ctx, str);
    return JS_UNDEFINED;
}

static JSValue js_fork(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    pid_t pid = fork();
    if (pid < 0)
        return JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
    return JS_NewInt32(ctx, pid);
}

static JSValue js_listen(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t sockfd, ret, port, backlog = 10;
    if (argc < 2) {
        JS_ThrowInternalError(ctx, "Expecting ip_str, port_number, backlog_number=10(optional)");
        goto fail;
    }
    sockfd = socket(AF_INET, SOCK_STREAM/*|SOCK_NONBLOCK*/, 0);
    if (sockfd < 0)
        goto throw_errno;
    ret = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret)) < 0)
        goto throw_errno;
    if (JS_ToInt32(ctx, &port, argv[1]))
        goto fail;
    if (argc > 2 && JS_ToInt32(ctx, &backlog, argv[2]))
        goto fail;
    struct sockaddr_in addr = { AF_INET, htons(port) };
    const char *str = JS_ToCString(ctx, argv[0]);
    ret = inet_aton(str, &addr.sin_addr);
    JS_FreeCString(ctx, str);
    if (!ret) {
        JS_ThrowInternalError(ctx, "Specified IP address is not valid");
        goto fail;
    }
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)))
        goto throw_errno;
    if (listen(sockfd, backlog))
        goto throw_errno;
    return JS_NewInt32(ctx, sockfd);
throw_errno:
    JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
fail:
    return JS_EXCEPTION;
}

static JSValue js_accept(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t sockfd, newfd;
    if (argc < 1 || JS_ToInt32(ctx, &sockfd, argv[0]))
        return JS_ThrowInternalError(ctx, "Expecting sockfd");
    struct sockaddr_in raddr;
    socklen_t sin_size = sizeof(raddr);
    newfd = accept(sockfd, (struct sockaddr *)&raddr, &sin_size);
    if (newfd < 0)
        return JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
    JSValue obj = JS_NewArray(ctx);
    if (JS_IsException(obj))
        return obj;
    JS_DefinePropertyValueUint32(ctx, obj, 0, JS_NewInt32(ctx, newfd), JS_PROP_C_W_E);
    JS_DefinePropertyValueUint32(ctx, obj, 1, JS_NewString(ctx, inet_ntoa(raddr.sin_addr)), JS_PROP_C_W_E);
    JS_DefinePropertyValueUint32(ctx, obj, 2, JS_NewInt32(ctx, ntohs(raddr.sin_port)), JS_PROP_C_W_E);
    return obj;
}

#define BUF_SIZE 8192

typedef struct http_request {
    JSContext *ctx;
    int32_t max_request_size;
    size_t request_bytes_read;
    int request_complete;
    char *buf;
    size_t buf_size;
    size_t field_len;
    size_t value_len;
    size_t body_len;
    size_t url_len;
    JSValue ret;
    JSValue js_headers;
} http_request;

static int set_header(http_parser *p)
{
    http_request *r = p->data;
    if (r->field_len) {
        JSValue value = JS_NewStringLen(r->ctx, r->buf + r->field_len, r->value_len);
        if (JS_IsException(value))
            return -1;
        r->buf[r->field_len] = 0;
        JS_DefinePropertyValueStr(r->ctx, r->js_headers, r->buf, value, JS_PROP_C_W_E);
        r->field_len = 0;
        r->value_len = 0;
    }
    return 0;
}

static int set_url(http_request *r)
{
    if (r->url_len) {
        JSValue url = JS_NewStringLen(r->ctx, r->buf, r->url_len);
        r->url_len = 0;
        if (JS_IsException(url))
            return -1;
        JS_DefinePropertyValueStr(r->ctx, r->ret, "url", url, JS_PROP_C_W_E);
    }
    return 0;
}

static int on_header_field(http_parser *p, const char *at, size_t len)
{
    http_request *r = p->data;
    if (set_url(r))
        return -1;
    if (r->value_len && set_header(p))
        return -1;
    if (r->field_len + len > BUF_SIZE) {
        JS_ThrowInternalError(r->ctx, "Header line too large, over %d", BUF_SIZE);
        return -1;
    }
    memcpy(r->buf + r->field_len, at, len);
    r->field_len += len;
    return 0;
}

static int on_header_value(http_parser *p, const char *at, size_t len)
{
    http_request *r = p->data;
    if (!len && !r->value_len) { //skip this header, we depend on value_len > 0 to detect header complete
        r->field_len = 0;
        return 0;
    }
    if (r->field_len + r->value_len + len > BUF_SIZE) {
        JS_ThrowInternalError(r->ctx, "Header line too large, over %d", BUF_SIZE);
        return -1;
    }
    memcpy(r->buf + r->field_len + r->value_len, at, len);
    r->value_len += len;
    return 0;
}

#define BUF_SIZE_NEXT 2097152
static int on_body(http_parser *p, const char *at, size_t len)
{
    http_request *r = p->data;
    if (r->body_len + len > r->buf_size) {
        r->buf_size = r->buf_size * 2;
        if (r->buf_size < BUF_SIZE_NEXT) //speed-up buffer ramp up
            r->buf_size = BUF_SIZE_NEXT;
        if (!js_realloc(r->ctx, r->buf, r->buf_size)) // throws out-of-memory
            return -1;
    }
    r->body_len += len;
    return 0;
}

static int set_body(http_parser *p)
{
    http_request *r = p->data;
    if (set_url(r))
        return -1;
    r->request_complete = 1;
    if (r->body_len) {
        JSValue obj = JS_NewArrayBuffer(r->ctx, (uint8_t *)r->buf, r->body_len, NULL, NULL, 0); //takes ownership of buf
        r->buf = NULL;
        r->body_len = 0;
        if (JS_IsException(obj))
            return -1;
        JS_DefinePropertyValueStr(r->ctx, r->ret, "body", obj, JS_PROP_C_W_E);
    }
    if (p->type == HTTP_REQUEST) {
        JSValue method = JS_NewString(r->ctx, http_method_str(p->method));
        JS_DefinePropertyValueStr(r->ctx, r->ret, "method", method, JS_PROP_C_W_E);
    } else {
        JS_DefinePropertyValueStr(r->ctx, r->ret, "status", JS_NewInt32(r->ctx, p->status_code), JS_PROP_C_W_E);
    }
    JS_DefinePropertyValueStr(r->ctx, r->ret, "httpMajor", JS_NewInt32(r->ctx, p->http_major), JS_PROP_C_W_E);
    JS_DefinePropertyValueStr(r->ctx, r->ret, "httpMinor", JS_NewInt32(r->ctx, p->http_minor), JS_PROP_C_W_E);
    return 0;
}

static int on_url(http_parser *p, const char *at, size_t len)
{
    http_request *r = p->data;
    if (r->url_len + len > BUF_SIZE) {
        JS_ThrowInternalError(r->ctx, "URL too large, over %d", BUF_SIZE);
        return -1;
    }
    memcpy(r->buf + r->url_len, at, len);
    r->url_len += len;
    return 0;
}

static JSValue js_read_http_request(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t max_header_size, fd, c;
    http_parser_settings settings;
    http_parser parser;
    JSValue error = JS_UNDEFINED;
    http_request r;
    memset(&r, 0, sizeof(http_request));
    char *rcvbuf = js_malloc(ctx, BUF_SIZE);
    r.ctx = ctx;
    r.buf = js_malloc(ctx, BUF_SIZE);
    r.buf_size = BUF_SIZE;
    r.ret = JS_UNDEFINED;
    if (!rcvbuf || !r.buf) //js_malloc throws out-of-memory
        goto fail;
    if (argc < 2) {
        JS_ThrowInternalError(ctx, "Expecting sockfd, max_request_size");
        goto fail;
    }
    if (JS_ToInt32(ctx, &fd, argv[0]))
        goto fail;
    if (JS_ToInt32(ctx, &r.max_request_size, argv[1]))
        goto fail;
    r.ret = JS_NewObject(ctx);
    r.js_headers = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, r.ret, "h", r.js_headers, JS_PROP_C_W_E);

    if (argc > 2) {
        if (JS_ToInt32(ctx, &max_header_size, argv[2]))
            goto fail;
        http_parser_set_max_header_size(max_header_size);
    }
    http_parser_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;
    settings.on_headers_complete = set_header;
    settings.on_body = on_body;
    settings.on_message_complete = set_body;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &r;

    while (!r.request_complete && (c = read(fd, rcvbuf, BUF_SIZE)) >= 0) {
        r.request_bytes_read += c;
        if (r.request_bytes_read > r.max_request_size) {
            JS_ThrowInternalError(ctx, "Request too large, over %d", r.max_request_size);
            goto fail;
        }
        size_t count = http_parser_execute(&parser, &settings, rcvbuf, c);
        error = JS_GetException(ctx);
        if (!JS_IsNull(error) && !JS_IsUndefined(error)) {
            JS_Throw(ctx, error); //rethrow
            goto fail;
        }
        if (parser.http_errno != HPE_OK || count != c)
            goto throw_parser_error;
        if (c == 0)
            break;
    }
    if (c < 0) {
        JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
        goto fail;
    }
    if (parser.http_errno != HPE_OK)
        goto throw_parser_error;
    goto ret;
throw_parser_error:
    JS_ThrowInternalError(ctx, "%s -> %s", http_errno_name(parser.http_errno),
            http_errno_description(parser.http_errno));
fail:
    if (!JS_IsUndefined(r.ret))
        JS_FreeValue(ctx, r.ret); // js_headers reference is included here
    r.ret = JS_EXCEPTION;
ret:
    if (rcvbuf)
        js_free(ctx, rcvbuf);
    if (r.buf)
        js_free(ctx, r.buf);
    return r.ret;
}

static JSValue js_write(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t fd, c = 0;
    size_t len;
    const char *buf;
    if (argc < 2 || JS_ToInt32(ctx, &fd, argv[0])) {
        JS_ThrowInternalError(ctx, "Expecting sockfd, stringOrArrayBuffer, ...");
        goto fail;
    }
    for (int i = 1; i < argc; i++) {
        if ((buf = (char *)JS_GetArrayBuffer(ctx, &len, argv[i])))
            c = write(fd, buf, len);
        else {
            JS_FreeValue(ctx, JS_GetException(ctx)); //JS_GetArrayBuffer would drop an exception
            if ((buf = JS_ToCStringLen(ctx, &len, argv[i]))) {
                c = write(fd, buf, len);
                JS_FreeCString(ctx, buf);
            }
        }
        if (c != len) {
            JS_ThrowInternalError(ctx, "Error writing to socket");
            goto fail;
        }
    }
    return JS_UNDEFINED;
fail:
    return JS_EXCEPTION;
}

#define countof(x) (sizeof(x) / sizeof((x)[0]))

static const JSCFunctionListEntry js_serverutil_funcs[] = {
    JS_CFUNC_DEF("setProcName", 1, js_set_proc_name),
    JS_CFUNC_DEF("fork", 0, js_fork),
    JS_CFUNC_DEF("listen", 2, js_listen),
    JS_CFUNC_DEF("accept", 1, js_accept),
    JS_CFUNC_DEF("readHttpRequest", 2, js_read_http_request),
    JS_CFUNC_DEF("write", 2, js_write),
};

static int js_serverutil_init(JSContext *ctx, JSModuleDef *m)
{
    return JS_SetModuleExportList(ctx, m, js_serverutil_funcs, countof(js_serverutil_funcs));
}

#ifdef JS_SHARED_LIBRARY
#define JS_INIT_MODULE js_init_module
#else
#define JS_INIT_MODULE js_init_module_serverutil
#endif

JSModuleDef *JS_INIT_MODULE(JSContext *ctx, const char *module_name)
{
    JSModuleDef *m;
    m = JS_NewCModule(ctx, module_name, js_serverutil_init);
    if (!m)
        return NULL;
    JS_AddModuleExportList(ctx, m, js_serverutil_funcs, countof(js_serverutil_funcs));
    return m;
}
