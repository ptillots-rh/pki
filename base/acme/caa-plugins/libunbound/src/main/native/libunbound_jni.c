/* Copyright Red Hat, Inc. SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#define CAA_MAX_RECORDS 1024
#define CAA_MAX_RDATA 65535
#include <unbound.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void caa_throw(JNIEnv *env, const char *type, const char *message) {
    if ((*env)->ExceptionCheck(env)) return;
    jclass cls = (*env)->FindClass(env, type);
    if (cls) (*env)->ThrowNew(env, cls, message);
}
static void caa_error(JNIEnv *env, const char *message) {
    caa_throw(env, "java/io/IOException", message);
}

int caa_input(JNIEnv *env, jbyteArray address, jint port, jstring name, jint timeout,
        uint8_t bytes[16], size_t *length) {
    if (!address || !name || port < 1 || port > 65535 || timeout < 1 || timeout > 60000) {
        caa_error(env, "Invalid native query arguments");
        return 0;
    }
    jsize n = (*env)->GetArrayLength(env, address);
    jsize chars = (*env)->GetStringLength(env, name);
    if ((n != 4 && n != 16) || chars < 1 || chars > 254) {
        caa_error(env, "Invalid native address or name length");
        return 0;
    }
    (*env)->GetByteArrayRegion(env, address, 0, n, (jbyte *)bytes);
    *length = (size_t)n;
    return !(*env)->ExceptionCheck(env);
}


/* ub_process delivers callbacks on this JNI caller, not on the worker thread. */
typedef struct { int done, error; struct ub_result *result; } query_result;
static void receive_result(void *arg, int error, struct ub_result *result) {
    query_result *state = arg;
    state->result = result;
    state->error = error;
    state->done = 1;
}

static int64_t monotonic_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void configuration_error(JNIEnv *env) {
    if ((*env)->ExceptionCheck(env)) return;
    jclass cls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (cls) (*env)->ThrowNew(env, cls, "Cannot configure libunbound context or trust anchors");
}

/* Canonical names are library-rendered ASCII; never feed arbitrary DNS octets
 * into NewStringUTF. Bogus diagnostics are bounded, flattened ASCII for display. */
static jstring result_text(JNIEnv *env, const char *text, int diagnostic) {
    if (!text) return NULL;
    char buffer[1025];
    size_t n = 0;
    while (text[n] && n < sizeof(buffer) - 1) {
        unsigned char c = (unsigned char)text[n];
        if (!diagnostic && (c < 32 || c > 126)) {
            caa_error(env, "Unsupported libunbound name text"); return NULL;
        }
        buffer[n++] = c < 32 || c > 126 ? ' ' : (char)c;
    }
    if (!diagnostic && text[n]) {
        caa_error(env, "Oversized libunbound name"); return NULL;
    }
    buffer[n] = 0;
    return (*env)->NewStringUTF(env, buffer);
}

static jobject copy_result(JNIEnv *env, const struct ub_result *r) {
    jclass bytes_class = (*env)->FindClass(env, "[B");
    if (!bytes_class) return NULL;
    size_t count = 0, total = 0;
    if (r->data) {
        while (r->data[count]) {
            if (count == CAA_MAX_RECORDS || !r->len || r->len[count] < 0 || r->len[count] > CAA_MAX_RDATA) {
                caa_error(env, "Invalid or oversized libunbound RDATA"); return NULL;
            }
            total += (size_t)r->len[count++];
            if (total > 1024 * 1024) {
                caa_error(env, "libunbound RDATA exceeds copy limit"); return NULL;
            }
        }
    }
    if (r->answer_len < 0 || r->answer_len > 65535 || (r->answer_len && !r->answer_packet)) {
        caa_error(env, "Invalid libunbound answer packet"); return NULL;
    }
    jobjectArray data = (*env)->NewObjectArray(env, (jsize)count, bytes_class, NULL);
    if (!data) return NULL;
    for (size_t i = 0; i < count; i++) {
        jbyteArray bytes = (*env)->NewByteArray(env, r->len[i]);
        if (!bytes) return NULL;
        if (r->len[i]) (*env)->SetByteArrayRegion(env, bytes, 0, r->len[i], (const jbyte *)r->data[i]);
        if (!(*env)->ExceptionCheck(env)) (*env)->SetObjectArrayElement(env, data, (jsize)i, bytes);
        (*env)->DeleteLocalRef(env, bytes);
        if ((*env)->ExceptionCheck(env)) return NULL;
    }
    jbyteArray packet = (*env)->NewByteArray(env, r->answer_len);
    if (!packet) return NULL;
    if (r->answer_len) (*env)->SetByteArrayRegion(env, packet, 0, r->answer_len, r->answer_packet);
    if ((*env)->ExceptionCheck(env)) return NULL;
    jstring canonical = result_text(env, r->canonname, 0);
    if ((*env)->ExceptionCheck(env)) return NULL;
    jstring diagnostic = result_text(env, r->why_bogus, 1);
    if ((*env)->ExceptionCheck(env)) return NULL;
    jclass cls = (*env)->FindClass(env, "org/dogtagpki/acme/caa/libunbound/LibUnboundCAAProvider$NativeResult");
    if (!cls) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>",
            "(Ljava/lang/String;I[[BIZZLjava/lang/String;ZZ[B)V");
    if (!ctor) return NULL;
    return (*env)->NewObject(env, cls, ctor, canonical, (jint)r->rcode, data, (jint)r->ttl,
            (jboolean)(r->secure != 0), (jboolean)(r->bogus != 0), diagnostic,
            (jboolean)(r->havedata != 0), (jboolean)(r->nxdomain != 0), packet);
}

JNIEXPORT jobject JNICALL
Java_org_dogtagpki_acme_caa_libunbound_LibUnboundCAAProvider_queryNative(JNIEnv *env, jclass cls,
        jbyteArray address, jint port, jstring name, jint type, jint timeout, jobjectArray anchors, jboolean validate_root, jobject cancelled) {
    (void)cls;
    uint8_t bytes[16]; size_t size;
    char host[INET6_ADDRSTRLEN], endpoint[INET6_ADDRSTRLEN + 16];
    const char *qname = NULL;
    struct ub_ctx *ctx = NULL;
    query_result state = {0};
    jobject result = NULL;
    int pending = 0, query_id = 0;
    int64_t started = monotonic_millis();
    if (!caa_input(env, address, port, name, timeout, bytes, &size)) return NULL;
    if (started < 0 || !anchors || (type != 16 && type != 257)) {
        caa_error(env, "Invalid libunbound query arguments or clock"); return NULL;
    }
    jsize anchor_count = (*env)->GetArrayLength(env, anchors);
    if (anchor_count > 128) { configuration_error(env); return NULL; }
    jclass cancel_class = (*env)->FindClass(env, "java/util/concurrent/atomic/AtomicBoolean");
    if (!cancel_class || !cancelled) return NULL;
    jmethodID is_cancelled = (*env)->GetMethodID(env, cancel_class, "get", "()Z");
    if (!is_cancelled) return NULL;
    jclass thread_class = (*env)->FindClass(env, "java/lang/Thread");
    if (!thread_class) return NULL;
    jmethodID current_thread = (*env)->GetStaticMethodID(env, thread_class, "currentThread", "()Ljava/lang/Thread;");
    if (!current_thread) return NULL;
    jmethodID interrupted = (*env)->GetMethodID(env, thread_class, "isInterrupted", "()Z");
    if (!interrupted) return NULL;
    jobject caller = (*env)->CallStaticObjectMethod(env, thread_class, current_thread);
    if ((*env)->ExceptionCheck(env) || !caller) return NULL;
    if (!inet_ntop(size == 4 ? AF_INET : AF_INET6, bytes, host, sizeof(host))) {
        caa_error(env, "Invalid libunbound address"); return NULL;
    }
    snprintf(endpoint, sizeof(endpoint), "%s@%d", host, port);
    ctx = ub_ctx_create();
    if (!ctx) { caa_error(env, "Cannot allocate libunbound context"); return NULL; }
    if (ub_ctx_set_option(ctx, "module-config:", anchor_count ? "validator iterator" : "iterator")
            || ub_ctx_set_option(ctx, "do-not-query-localhost:", "no")
            || ub_ctx_set_option(ctx, "tcp-upstream:", "yes")
            || ub_ctx_set_option(ctx, "val-permissive-mode:", "no")
            || ub_ctx_set_fwd(ctx, endpoint) || ub_ctx_async(ctx, 1)) {
        configuration_error(env); goto done;
    }
    /* No resolv.conf, hosts file or daemon configuration is inherited. */
    for (jsize i = 0; i < anchor_count; i++) {
        jstring anchor = (*env)->GetObjectArrayElement(env, anchors, i);
        if ((*env)->ExceptionCheck(env)) goto done;
        if (!anchor) { configuration_error(env); goto done; }
        if ((*env)->GetStringLength(env, anchor) > 8192) {
            (*env)->DeleteLocalRef(env, anchor); configuration_error(env); goto done;
        }
        const char *text = (*env)->GetStringUTFChars(env, anchor, NULL);
        if (!text) { (*env)->DeleteLocalRef(env, anchor); goto done; }
        int error = ub_ctx_add_ta(ctx, text);
        (*env)->ReleaseStringUTFChars(env, anchor, text);
        (*env)->DeleteLocalRef(env, anchor);
        if (error) { configuration_error(env); goto done; }
    }
    qname = (*env)->GetStringUTFChars(env, name, NULL);
    if (!qname) goto done;
    /* Both operations share one context, cache and monotonic deadline. */
    for (int step = validate_root ? 0 : 1; step < 2; step++) {
        if (ub_resolve_async(ctx, step == 0 ? "." : qname, step == 0 ? 48 : type, 1, &state, receive_result, &query_id)) {
            caa_error(env, "Cannot start libunbound query"); goto done;
        }
        pending = 1;
        while (!state.done) {
            jboolean stop = (*env)->CallBooleanMethod(env, caller, interrupted);
            if ((*env)->ExceptionCheck(env)) goto done;
            if (stop) { caa_error(env, "libunbound query interrupted"); goto done; }
            jboolean closing = (*env)->CallBooleanMethod(env, cancelled, is_cancelled);
            if ((*env)->ExceptionCheck(env)) goto done;
            if (closing) { caa_error(env, "libunbound client closed"); goto done; }
            int64_t now = monotonic_millis();
            int64_t remaining = (int64_t)timeout - (now - started);
            if (now < 0 || remaining <= 0) { caa_throw(env, "java/net/SocketTimeoutException", "libunbound query timed out"); goto done; }
            struct pollfd event = {ub_fd(ctx), POLLIN, 0};
            if (event.fd < 0) { caa_error(env, "Invalid libunbound event descriptor"); goto done; }
            int ready = poll(&event, 1, remaining > 50 ? 50 : (int)remaining);
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0 || (event.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                caa_error(env, "libunbound event wait failed"); goto done;
            }
            if (ready && ub_process(ctx)) { caa_error(env, "libunbound result processing failed"); goto done; }
        }
        pending = 0;
        int64_t finished = monotonic_millis();
        if (finished < 0 || finished - started >= timeout) {
            caa_throw(env, "java/net/SocketTimeoutException", "libunbound query timed out"); goto done;
        }
        if (state.error || !state.result) { caa_error(env, "libunbound resolution failed"); goto done; }
        if (step == 0) {
            /* A configured root record alone does not prove a usable anchor.
             * Validate the root DNSKEY RRset in this same context before accepting
             * any potentially insecure CAA result. This also blocks unsupported or
             * ineffective root anchors from silently becoming blanket insecurity. */
            if (state.result->rcode != 0 || !state.result->secure || state.result->bogus) {
                caa_throw(env,
                        "org/dogtagpki/acme/caa/libunbound/LibUnboundCAAProvider$NativeValidationException",
                        "Cannot establish usable DNSSEC root trust");
                goto done;
            }
            ub_resolve_free(state.result);
            state.result = NULL;
            state.done = 0;
            state.error = 0;
        } else {
            result = copy_result(env, state.result);
        }
    }
done:
    /* A cancel can race with queued delivery. Delete the private context before
     * the stack-owned callback state goes away; no callback enters Java. */
    if (pending && !state.done) (void)ub_cancel(ctx, query_id);
    if (ctx) ub_ctx_delete(ctx);
    if (state.result) ub_resolve_free(state.result);
    if (qname) (*env)->ReleaseStringUTFChars(env, name, qname);
    return result;
}

/* Check that the native API accepts configured anchors without DNS traffic.
 * Java validates zone-record field syntax; actual DNSSEC verification still
 * happens on lookup. ub_ctx_add_ta itself defers parsing until initialization. */
JNIEXPORT void JNICALL
Java_org_dogtagpki_acme_caa_libunbound_LibUnboundCAAProvider_checkAnchorsNative(
        JNIEnv *env, jclass cls, jobjectArray anchors) {
    (void)cls;
    struct ub_ctx *ctx = ub_ctx_create();
    if (!ctx || !anchors) { if (ctx) ub_ctx_delete(ctx); configuration_error(env); return; }
    jsize count = (*env)->GetArrayLength(env, anchors);
    if (count > 128) { ub_ctx_delete(ctx); configuration_error(env); return; }
    if (ub_ctx_set_option(ctx, "module-config:", count ? "validator iterator" : "iterator")) {
        ub_ctx_delete(ctx); configuration_error(env); return;
    }
    for (jsize i = 0; i < count; i++) {
        jstring anchor = (*env)->GetObjectArrayElement(env, anchors, i);
        if ((*env)->ExceptionCheck(env)) break;
        if (!anchor || (*env)->GetStringLength(env, anchor) > 8192) { configuration_error(env); break; }
        const char *text = (*env)->GetStringUTFChars(env, anchor, NULL);
        if (!text) { (*env)->DeleteLocalRef(env, anchor); break; }
        int error = ub_ctx_add_ta(ctx, text);
        (*env)->ReleaseStringUTFChars(env, anchor, text);
        (*env)->DeleteLocalRef(env, anchor);
        if (error) { configuration_error(env); break; }
    }
    ub_ctx_delete(ctx);
}
