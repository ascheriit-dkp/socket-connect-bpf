// Copyright 2026 Ascheriit-Dkp.
//
// This file is part of the kernel-side TCP lifecycle implementation and is
// compiled into securitySocketConnectSrc.c. See LICENSING.md and
// THIRD_PARTY_NOTICES.md for the licensing context of the BPF object.

#ifndef SOCKET_CONNECT_BPF_TCP_LIFECYCLE_TRACEPOINT_H
#define SOCKET_CONNECT_BPF_TCP_LIFECYCLE_TRACEPOINT_H

struct tcp_lifecycle_state_tracepoint_t {
    u16 common_type;
    u8 common_flags;
    u8 common_preempt_count;
    s32 common_pid;
    u64 skaddr;
    s32 oldstate;
    s32 newstate;
    u16 sport;
    u16 dport;
    u16 family;
    u16 protocol;
    u8 saddr[KERNEL_ADDRESS_LENGTH_IPV4];
    u8 daddr[KERNEL_ADDRESS_LENGTH_IPV4];
    u8 saddr_v6[KERNEL_ADDRESS_LENGTH_IPV6];
    u8 daddr_v6[KERNEL_ADDRESS_LENGTH_IPV6];
};

_Static_assert(
    offsetof(struct tcp_lifecycle_state_tracepoint_t, skaddr) == 8,
    "unexpected inet_sock_set_state skaddr offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_state_tracepoint_t, oldstate) == 16,
    "unexpected inet_sock_set_state oldstate offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_state_tracepoint_t, sport) == 24,
    "unexpected inet_sock_set_state sport offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_state_tracepoint_t, saddr) == 32,
    "unexpected inet_sock_set_state IPv4 source offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_state_tracepoint_t, saddr_v6) == 40,
    "unexpected inet_sock_set_state IPv6 source offset"
);

_Static_assert(
    sizeof(struct tcp_lifecycle_state_tracepoint_t) == 72,
    "unexpected inet_sock_set_state tracepoint size"
);

static __always_inline int emit_tcp_lifecycle_tracepoint_event(
    const struct tcp_connection_state_t *state,
    const struct tcp_lifecycle_state_tracepoint_t *ctx,
    u8 event_type,
    u64 kernel_timestamp_ns,
    u8 failure_source,
    s32 error_code
) {
    u16 flags = TCP_LIFECYCLE_FLAG_REMOTE_ADDRESS |
        TCP_LIFECYCLE_FLAG_REMOTE_PORT;
    u8 local_address_length = KERNEL_ADDRESS_LENGTH_NONE;

    if (ctx->family == AF_INET) {
        flags |= TCP_LIFECYCLE_FLAG_LOCAL_ADDRESS;
        local_address_length = KERNEL_ADDRESS_LENGTH_IPV4;
    } else if (ctx->family == AF_INET6) {
        flags |= TCP_LIFECYCLE_FLAG_LOCAL_ADDRESS;
        local_address_length = KERNEL_ADDRESS_LENGTH_IPV6;
    }

    if (ctx->sport != 0) {
        flags |= TCP_LIFECYCLE_FLAG_LOCAL_PORT;
    }

    if (error_code > 0) {
        flags |= TCP_LIFECYCLE_FLAG_ERROR_CODE;
    }

    struct tcp_lifecycle_event_t event = {
        .abi_version = TCP_LIFECYCLE_EVENT_ABI_VERSION,
        .event_type = event_type,
        .protocol = IPPROTO_TCP,
        .address_family = state->address_family,
        .flags = flags,
        .pid = state->pid,
        .uid = state->uid,
        .connection_id = state->connection_id,
        .kernel_timestamp_ns = kernel_timestamp_ns,
        .attempt_timestamp_ns = state->attempt_timestamp_ns,
        .established_timestamp_ns = state->established_timestamp_ns,
        .error_code = error_code,
        .failure_source = failure_source,
        .local_address_length = local_address_length,
        .remote_address_length = state->remote_address_length,
        .local_port = ctx->sport,
        .remote_port = state->remote_port
    };

    if (ctx->family == AF_INET) {
        __builtin_memcpy(
            event.local_address,
            ctx->saddr,
            KERNEL_ADDRESS_LENGTH_IPV4
        );
    } else if (ctx->family == AF_INET6) {
        __builtin_memcpy(
            event.local_address,
            ctx->saddr_v6,
            KERNEL_ADDRESS_LENGTH_IPV6
        );
    }

    __builtin_memcpy(
        event.remote_address,
        state->remote_address,
        sizeof(event.remote_address)
    );
    __builtin_memcpy(event.task, state->task, sizeof(event.task));

    if (bpf_ringbuf_output(
        &socket_events,
        &event,
        sizeof(event),
        0
    ) < 0) {
        record_dropped_event();
        return -1;
    }

    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(
    struct tcp_lifecycle_state_tracepoint_t *ctx
) {
    if (ctx->protocol != IPPROTO_TCP || ctx->skaddr == 0) {
        return 0;
    }

    u64 sk_key = ctx->skaddr;
    struct tcp_connection_state_t *state = bpf_map_lookup_elem(
        &tcp_connections,
        &sk_key
    );

    if (state == NULL) {
        return 0;
    }

    if (ctx->family != state->address_family) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION
        );
        return 0;
    }

    if (ctx->newstate == TCP_ESTABLISHED) {
        if (state->established) {
            return 0;
        }

        u64 now = bpf_ktime_get_ns();
        state->established = 1;
        state->established_timestamp_ns = now;

        if (emit_tcp_lifecycle_tracepoint_event(
            state,
            ctx,
            TCP_LIFECYCLE_EVENT_ESTABLISHED,
            now,
            TCP_LIFECYCLE_FAILURE_SOURCE_NONE,
            0
        ) < 0) {
            bpf_map_delete_elem(&tcp_connections, &sk_key);
        }

        return 0;
    }

    if (ctx->newstate != TCP_CLOSE) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();

    if (state->established) {
        emit_tcp_lifecycle_tracepoint_event(
            state,
            ctx,
            TCP_LIFECYCLE_EVENT_CLOSED,
            now,
            TCP_LIFECYCLE_FAILURE_SOURCE_NONE,
            0
        );
    } else {
        emit_tcp_lifecycle_tracepoint_event(
            state,
            ctx,
            TCP_LIFECYCLE_EVENT_CONNECT_FAILED,
            now,
            TCP_LIFECYCLE_FAILURE_SOURCE_TCP_STATE,
            0
        );
    }

    bpf_map_delete_elem(&tcp_connections, &sk_key);

    return 0;
}

#endif
