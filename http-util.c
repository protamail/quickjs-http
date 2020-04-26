#include "quickjs-libc.h"
#include "cutils.h"
#include "http_parser.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <netdb.h>

static int resolve_host(const char *name_or_ip, int32_t port, struct sockaddr_in *addr4, struct sockaddr_in6 *addr6);

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

static void js_array_buffer_free(JSRuntime *rt, void *opaque, void *ptr)
{
    js_free_rt(rt, ptr);
}

// connect to external service
static JSValue js_connect(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t sockfd, port, af = 0;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    const char *host;
    if (argc < 2)
        goto arg_fail;
    if (JS_ToInt32(ctx, &port, argv[1]))
        goto arg_fail;
    host = JS_ToCString(ctx, argv[0]);
    if (!resolve_host(host, port, &addr4, &addr6)) {
        if (addr4.sin_family == AF_INET)
            af = AF_INET;
        else if (addr6.sin6_family == AF_INET6)
            af = AF_INET6;
    }
    JS_FreeCString(ctx, host);
    if (!af)
        return JS_ThrowInternalError(ctx, "Not valid hostname or IP address");
    sockfd = socket(af, SOCK_STREAM/*|SOCK_NONBLOCK*/, 0);
    if (sockfd < 0)
        goto errno_fail;
    if (af == AF_INET && connect(sockfd, (struct sockaddr *)&addr4, sizeof(addr4))) {
        goto errno_fail;
    }
    if (af == AF_INET6 && connect(sockfd, (struct sockaddr *)&addr6, sizeof(addr6)))
        goto errno_fail;
    return JS_NewInt32(ctx, sockfd);
errno_fail:
    return JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
arg_fail:
    return JS_ThrowInternalError(ctx, "Expecting ip_str, port_number");
}

static JSValue js_listen(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t sockfd, port, backlog = 10, af = 0, ret;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    const char *host;
    if (argc < 2)
        goto arg_fail;
    if (JS_ToInt32(ctx, &port, argv[1]))
        goto arg_fail;
    if (argc > 2 && JS_ToInt32(ctx, &backlog, argv[2]))
        goto arg_fail;
    host = JS_ToCString(ctx, argv[0]);
    if (!resolve_host(host, port, &addr4, &addr6)) {
        if (addr4.sin_family == AF_INET)
            af = AF_INET;
        else if (addr6.sin6_family == AF_INET6)
            af = AF_INET6;
    }
    JS_FreeCString(ctx, host);
    if (!af)
        return JS_ThrowInternalError(ctx, "Not valid hostname or IP address");
    sockfd = socket(af, SOCK_STREAM/*|SOCK_NONBLOCK*/, 0);
    if (sockfd < 0)
        goto errno_fail;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret)) < 0)
        goto errno_fail;
    if (af == AF_INET && bind(sockfd, (struct sockaddr *)&addr4, sizeof(addr4)))
        goto errno_fail;
    if (af == AF_INET6 && bind(sockfd, (struct sockaddr *)&addr6, sizeof(addr6)))
        goto errno_fail;
    if (listen(sockfd, backlog))
        goto errno_fail;
    return JS_NewInt32(ctx, sockfd);
errno_fail:
    return JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
arg_fail:
    return JS_ThrowInternalError(ctx, "Expecting ip_str, port_number, backlog_number=10(optional)");
}

static JSValue js_accept(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t sockfd, newfd;
    char buf[INET6_ADDRSTRLEN];
    if (argc < 1 || JS_ToInt32(ctx, &sockfd, argv[0]))
        return JS_ThrowInternalError(ctx, "Expecting sockfd");
    struct sockaddr_in6 raddr;
    socklen_t sin_size = sizeof(raddr);
    newfd = accept(sockfd, (struct sockaddr *)&raddr, &sin_size);
    if (newfd < 0)
        return JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
    JSValue obj = JS_NewArray(ctx);
    if (JS_IsException(obj))
        return obj;
    JS_DefinePropertyValueUint32(ctx, obj, 0, JS_NewInt32(ctx, newfd), JS_PROP_C_W_E);
    if (inet_ntop(AF_INET6, &raddr.sin6_addr, (char *__restrict)&buf, INET6_ADDRSTRLEN))
        JS_DefinePropertyValueUint32(ctx, obj, 1, JS_NewString(ctx, buf), JS_PROP_C_W_E);
    JS_DefinePropertyValueUint32(ctx, obj, 2, JS_NewInt32(ctx, ntohs(raddr.sin6_port)), JS_PROP_C_W_E);
    return obj;
}

#define BUF_SIZE 8192

typedef struct http_request {
    JSContext *ctx;
    int32_t max_size;
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
    JSValue val;
    if (r->url_len) {
        val = JS_NewStringLen(r->ctx, r->buf, r->url_len);
        if (JS_IsException(val))
            return -1;
        JS_DefinePropertyValueStr(r->ctx, r->ret, "url", val, JS_PROP_C_W_E);
        r->url_len = 0;
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
        JSValue obj = JS_NewArrayBuffer(r->ctx, (uint8_t *)r->buf, r->body_len, js_array_buffer_free, NULL, 0);
        r->buf = NULL; //don't free
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

static JSValue recv_http(int parser_type, JSContext *ctx, JSValueConst this_val,
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
        JS_ThrowInternalError(ctx, "Expecting sockfd, max_bytes");
        goto fail;
    }
    if (JS_ToInt32(ctx, &fd, argv[0])) {
        JS_ThrowInternalError(ctx, "Expecting sockfd as number");
        goto fail;
    }
    if (JS_ToInt32(ctx, &r.max_size, argv[1])) {
        JS_ThrowInternalError(ctx, "Expecting max_size as number");
        goto fail;
    }
    r.ret = JS_NewObject(ctx);
    r.js_headers = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, r.ret, "h", r.js_headers, JS_PROP_C_W_E);

    if (argc > 2) {
        if (JS_ToInt32(ctx, &max_header_size, argv[2])) {
            JS_ThrowInternalError(ctx, "Expecting max_header_size as number");
            goto fail;
        }
        http_parser_set_max_header_size(max_header_size);
    }
    http_parser_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;
    settings.on_headers_complete = set_header;
    settings.on_body = on_body;
    settings.on_message_complete = set_body;
    http_parser_init(&parser, parser_type);
    parser.data = &r;

    while (!r.request_complete && (c = recv(fd, rcvbuf, BUF_SIZE, 0)) >= 0) {
        r.request_bytes_read += c;
        if (r.max_size > 0 && r.request_bytes_read > r.max_size) {
            JS_ThrowInternalError(ctx, "Request too large, over %d", r.max_size);
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
ret:
    if (rcvbuf)
        js_free(ctx, rcvbuf);
    if (r.buf)
        js_free(ctx, r.buf);
    return r.ret;
throw_parser_error:
    JS_ThrowInternalError(ctx, "%s -> %s", http_errno_name(parser.http_errno),
            http_errno_description(parser.http_errno));
fail:
    JS_FreeValue(ctx, r.ret); // js_headers reference is included here
    r.ret = JS_EXCEPTION;
    goto ret;
}

static JSValue js_recv_http_request(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    return recv_http(HTTP_REQUEST, ctx, this_val, argc, argv);
}

static JSValue js_recv_http_response(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    return recv_http(HTTP_RESPONSE, ctx, this_val, argc, argv);
}

static JSValue send_http(int parser_type, JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t fd, c = 0, http_minor = 0;
    size_t slen, body_len = 0, url_len = 0;
    const char *sbuf = NULL, *body_buf = NULL, *url = NULL;
    JSValue ret = JS_UNDEFINED, h, obj;
    JSPropertyEnum *atoms = NULL;
    uint32_t atoms_len;
    char cbuf[20];
    DynBuf header_buf;
    dbuf_init(&header_buf);
    dbuf_realloc(&header_buf, 2048);
    if (argc < 2 || JS_ToInt32(ctx, &fd, argv[0]) || !JS_IsObject(argv[1])) {
arg_fail:
        JS_ThrowInternalError(ctx, "Expecting sockfd, { url, method, h, body }");
        goto ret_fail;
    }
    obj = argv[1];
    ret = JS_GetPropertyStr(ctx, obj, "body");
    JS_FreeValue(ctx, ret);
    if (JS_IsException(ret))
        goto ret_fail;
    if (!JS_IsUndefined(ret) && !JS_IsNull(ret)) {
        body_buf = (char *)JS_GetArrayBuffer(ctx, &body_len, ret);
        if (!body_buf) {
            JS_FreeValue(ctx, JS_GetException(ctx)); //JS_GetArrayBuffer would drop an exception if its not, discard
            body_buf = JS_ToCStringLen(ctx, &body_len, ret);
            if (!body_buf)
                goto arg_fail;
        }
    }
    ret = JS_GetPropertyStr(ctx, obj, "httpMinor");
    JS_FreeValue(ctx, ret);
    if (JS_IsException(ret))
        goto ret_fail;
    if (!JS_IsUndefined(ret) && JS_ToInt32(ctx, &http_minor, ret)) {
        JS_ThrowInternalError(ctx, "httpMinor not a number (0|1)");
        goto ret_fail;
    }
    if (parser_type == HTTP_REQUEST) {
        ret = JS_GetPropertyStr(ctx, obj, "url");
        JS_FreeValue(ctx, ret);
        if (JS_IsException(ret))
            goto ret_fail;
        if (JS_IsUndefined(ret) || !(url = JS_ToCStringLen(ctx, &url_len, ret))) {
            JS_ThrowInternalError(ctx, "url property required");
            goto ret_fail;
        }
        ret = JS_GetPropertyStr(ctx, obj, "method");
        JS_FreeValue(ctx, ret);
        if (JS_IsException(ret))
            goto ret_fail;
        if (!JS_IsUndefined(ret) && (sbuf = JS_ToCStringLen(ctx, &slen, ret))) {
            if (dbuf_put(&header_buf, (uint8_t *)sbuf, slen))
                goto send_fail;
        } else {
            if (dbuf_putstr(&header_buf, body_len? "POST " : "GET "))
                goto send_fail;
        }
        if (dbuf_put(&header_buf, (uint8_t *)url, url_len))
            goto send_fail;
        if (dbuf_put(&header_buf, (uint8_t *)(http_minor? " HTTP/1.1\r\n" : " HTTP/1.0\r\n"), 11))
            goto send_fail;
    } else { //response
        if (dbuf_put(&header_buf, (uint8_t *)(http_minor? "HTTP/1.1 " : "HTTP/1.0 "), 9))
            goto send_fail;
        ret = JS_GetPropertyStr(ctx, obj, "status");
        JS_FreeValue(ctx, ret);
        if (JS_IsException(ret))
            goto ret_fail;
        if (JS_IsUndefined(ret) || !(sbuf = JS_ToCStringLen(ctx, &slen, ret))) {
            JS_ThrowInternalError(ctx, "status property required");
            goto ret_fail;
        }
        if (dbuf_put(&header_buf, (uint8_t *)sbuf, slen))
            goto send_fail;
        if (dbuf_put(&header_buf, (uint8_t *)"\r\n", 2))
            goto send_fail;
    }

    h = JS_GetPropertyStr(ctx, obj, "h");
    JS_FreeValue(ctx, h);
    if (JS_IsException(h))
        goto ret_fail;
    if (!JS_IsUndefined(h)) {
        if (JS_GetOwnPropertyNames(ctx, &atoms, &atoms_len, h, JS_GPN_STRING_MASK|JS_GPN_ENUM_ONLY))
            goto ret_fail;
        for (uint32_t i = 0; i < atoms_len; i++) {
            ret = JS_AtomToString(ctx, atoms[i].atom);
            JS_FreeValue(ctx, ret);
            if (sbuf)
                JS_FreeCString(ctx, sbuf);
            sbuf = JS_ToCStringLen(ctx, &slen, ret);
            if (!sbuf)
                goto send_fail;
            if (!strcasecmp(sbuf, "content-length"))
                continue;
            if (dbuf_put(&header_buf, (uint8_t *)sbuf, slen))
                goto send_fail;
            if (dbuf_put(&header_buf, (uint8_t *)": ", 2))
                goto send_fail;
            ret = JS_GetProperty(ctx, h, atoms[i].atom);
            JS_FreeValue(ctx, ret);
            if (sbuf)
                JS_FreeCString(ctx, sbuf);
            sbuf = JS_ToCStringLen(ctx, &slen, ret);
            if (!sbuf)
                goto send_fail;
            if (dbuf_put(&header_buf, (uint8_t *)sbuf, slen))
                goto send_fail;
            if (dbuf_put(&header_buf, (uint8_t *)"\r\n", 2))
                goto send_fail;
        }
    }
    if (dbuf_put(&header_buf, (uint8_t *)"Content-Length: ", 16))
        goto send_fail;
    slen = snprintf(cbuf, sizeof(cbuf), "%lu", body_len);
    if (slen > 0) {
        if (dbuf_put(&header_buf, (uint8_t *)cbuf, slen))
            goto send_fail;
    } else
        goto send_fail;
    if (dbuf_put(&header_buf, (uint8_t *)"\r\n\r\n", 4))
        goto send_fail;
    c = send(fd, header_buf.buf, header_buf.size, body_buf? MSG_MORE|MSG_NOSIGNAL : MSG_NOSIGNAL);
    if (c != header_buf.size)
        goto send_fail;
    if (body_buf) {
        c = send(fd, body_buf, body_len, MSG_NOSIGNAL);
        if (c != body_len)
            goto send_fail;
    }
ret_fail:
    dbuf_free(&header_buf);
    if (atoms) {
        for (uint32_t i = 0; i < atoms_len; i++)
            JS_FreeAtom(ctx, atoms[i].atom);
        js_free(ctx, atoms);
    }
    if (sbuf)
        JS_FreeCString(ctx, sbuf);
    if (body_buf)
        JS_FreeCString(ctx, body_buf);
    if (url)
        JS_FreeCString(ctx, url);
    if (JS_IsException(ret))
        return ret;
    ret = JS_GetException(ctx);
    if (!JS_IsUndefined(ret) && !JS_IsNull(ret))
        return JS_Throw(ctx, ret); //rethrow (takes ownership of ret)
    return JS_UNDEFINED;
send_fail:
    if (c < 0)
        JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
    else
        JS_ThrowInternalError(ctx, "Send failed");
    goto ret_fail;
}

static JSValue js_send_http_request(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    return send_http(HTTP_REQUEST, ctx, this_val, argc, argv);
}

static JSValue js_send_http_response(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    return send_http(HTTP_RESPONSE, ctx, this_val, argc, argv);
}

static JSValue js_send(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    int32_t fd, c = 0;
    size_t slen, alen;
    const char *sbuf, *abuf = NULL;
    if (argc < 2 || JS_ToInt32(ctx, &fd, argv[0]))
        goto arg_fail;
    if (argc > 2 && !JS_IsUndefined(argv[2]) && !JS_IsNull(argv[2])) { //check buffer valid before any send
        abuf = (char *)JS_GetArrayBuffer(ctx, &alen, argv[2]);
        if (!abuf) {
            JS_FreeValue(ctx, JS_GetException(ctx)); //JS_GetArrayBuffer would drop an exception if its not, discard
            goto arg_fail;
        }
    }
    if (!JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]) && (sbuf = JS_ToCStringLen(ctx, &slen, argv[1]))) {
        c = send(fd, sbuf, slen, argc > 2? MSG_MORE|MSG_NOSIGNAL : MSG_NOSIGNAL); //MSG_MORE important! or big slowdown);
        JS_FreeCString(ctx, sbuf);
        if (c != slen)
            goto send_fail;
    }
    if (argc > 2 && abuf) {
        c = send(fd, abuf, alen, MSG_NOSIGNAL);
        if (c != alen)
            goto send_fail;
    }
    return JS_UNDEFINED;
send_fail:
    if (c < 0)
        return JS_ThrowInternalError(ctx, "%d -> %s", errno, strerror(errno));
    else
        return JS_ThrowInternalError(ctx, "Send failed");
arg_fail:
    return JS_ThrowInternalError(ctx, "Expecting sockfd, headerString, [bodyArrayBuffer]");
}

static JSValue js_to_array_buffer(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    size_t len;
    const char *buf;
    if (argc < 1)
        return JS_ThrowInternalError(ctx, "Expecting string");
    if ((buf = JS_ToCStringLen(ctx, &len, argv[0]))) {
        //must use JS_FreeCString to free buf, not js_array_buffer_free
        JSValue ret = JS_NewArrayBufferCopy(ctx, (uint8_t *)buf, len);
        JS_FreeCString(ctx, buf);
        return ret;
    }
    return JS_ThrowInternalError(ctx, "out of memory?");
}

static JSValue js_array_buffer_to_string(JSContext *ctx, JSValueConst this_val,
                        int argc, JSValueConst *argv)
{
    size_t alen;
    const char *abuf = NULL;
    JSValue ret;
    if (argc < 1)
        goto arg_fail;
    abuf = (char *)JS_GetArrayBuffer(ctx, &alen, argv[0]);
    if (!abuf) {
        JS_FreeValue(ctx, JS_GetException(ctx));
        goto arg_fail;
    }
    ret = JS_NewStringLen(ctx, abuf, alen);
    if (JS_IsException(ret))
        goto ret;
    JS_DetachArrayBuffer(ctx, argv[0]); //release AB data
ret:
    return ret;
arg_fail:
    ret = JS_ThrowInternalError(ctx, "Expecting arrayBuffer");
    goto ret;
}

static int resolve_host(const char *name_or_ip, int32_t port, struct sockaddr_in *addr4, struct sockaddr_in6 *addr6)
{
    struct addrinfo hints, *ret, *cur;
    memset(&hints, 0, sizeof(hints));

    port = htons(port); // port in network order
    if (inet_pton(AF_INET, name_or_ip, &addr4->sin_addr)) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = port;
    } else if (inet_pton(AF_INET6, name_or_ip, &addr6->sin6_addr)) {
        memset(addr4, 0, sizeof(*addr4));
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = port;
    }
    else {
        memset(addr6, 0, sizeof(*addr6));
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(name_or_ip, NULL, &hints, &ret))
            return -1;
        for (cur = ret; cur; cur = cur->ai_next) {
            if (cur->ai_addr->sa_family == AF_INET) {
                memcpy(addr4, cur->ai_addr, sizeof(*addr4));
                addr4->sin_port = port;
            } else if (cur->ai_addr->sa_family == AF_INET6) {
                memcpy(addr6, cur->ai_addr, sizeof(*addr6));
                addr6->sin6_port = port;
            }
        }
        freeaddrinfo(ret);
    }
    return 0;
}

#define countof(x) (sizeof(x) / sizeof((x)[0]))

static const JSCFunctionListEntry js_serverutil_funcs[] = {
    JS_CFUNC_DEF("setProcName", 1, js_set_proc_name),
    JS_CFUNC_DEF("fork", 0, js_fork),
    JS_CFUNC_DEF("listen", 2, js_listen),
    JS_CFUNC_DEF("accept", 1, js_accept),
    JS_CFUNC_DEF("recvHttpRequest", 2, js_recv_http_request),
    JS_CFUNC_DEF("recvHttpResponse", 2, js_recv_http_response),
    JS_CFUNC_DEF("sendHttpRequest", 2, js_send_http_request),
    JS_CFUNC_DEF("sendHttpResponse", 2, js_send_http_response),
    JS_CFUNC_DEF("send", 2, js_send),
    JS_CFUNC_DEF("toArrayBuffer", 1, js_to_array_buffer),
    JS_CFUNC_DEF("arrayBufferToString", 1, js_array_buffer_to_string),
    JS_CFUNC_DEF("connect", 2, js_connect),
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
