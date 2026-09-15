// Modified in 2026 by Ascheriit-Dkp.
//
// This is inherited BPF source. Its upstream README describes the BPF code as
// GPL-licensed, while its kernel-facing ELF licence declaration is
// "Dual MIT/GPL". That declaration does not identify the exact GPLv2 variant.
// See LICENSING.md and THIRD_PARTY_NOTICES.md before changing the licensing
// declaration or reusing this file.
//
// +build ignore

#include "vmlinux_compact_common.h"

#if defined(__TARGET_ARCH_arm64)
#include "vmlinux_compact_arm64.h"
#elif defined(__TARGET_ARCH_x86)
#include "vmlinux_compact_amd64.h"
#endif

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define TASK_COMM_LEN 16

#define AF_UNIX 1
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10

#define IPPROTO_TCP 6

#define KERNEL_EVENT_ABI_VERSION 1
#define KERNEL_EVENT_TYPE_CONNECT_ATTEMPT 1

#define TCP_LIFECYCLE_EVENT_ABI_VERSION 2
#define TCP_LIFECYCLE_EVENT_CONNECT_ATTEMPT 1
#define TCP_LIFECYCLE_EVENT_ESTABLISHED 2
#define TCP_LIFECYCLE_EVENT_CONNECT_FAILED 3
#define TCP_LIFECYCLE_EVENT_CLOSED 4

#define TCP_LIFECYCLE_FLAG_LOCAL_ADDRESS (1 << 0)
#define TCP_LIFECYCLE_FLAG_LOCAL_PORT (1 << 1)
#define TCP_LIFECYCLE_FLAG_REMOTE_ADDRESS (1 << 2)
#define TCP_LIFECYCLE_FLAG_REMOTE_PORT (1 << 3)
#define TCP_LIFECYCLE_FLAG_ERROR_CODE (1 << 4)

#define TCP_LIFECYCLE_FAILURE_SOURCE_NONE 0
#define TCP_LIFECYCLE_FAILURE_SOURCE_CONNECT_RETURN 1
#define TCP_LIFECYCLE_FAILURE_SOURCE_TCP_STATE 2
#define TCP_LIFECYCLE_FAILURE_SOURCE_SOCKET_ERROR 3

#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

#define EINTR 4
#define EALREADY 114
#define EINPROGRESS 115

#define KERNEL_ADDRESS_LENGTH_NONE 0
#define KERNEL_ADDRESS_LENGTH_IPV4 4
#define KERNEL_ADDRESS_LENGTH_IPV6 16

#define SOCKET_EVENT_RING_SIZE (1 << 20)
#define DROPPED_EVENT_COUNTER_KEY 0

#define FILTER_CONFIG_KEY 0
#define MAX_FILTER_ENTRIES 1024

#define FILTER_PID_ENABLED (1 << 0)
#define FILTER_UID_ENABLED (1 << 1)
#define FILTER_FAMILY_ENABLED (1 << 2)
#define FILTER_PORT_ENABLED (1 << 3)

#define FILTER_FAMILY_IPV4 (1 << 0)
#define FILTER_FAMILY_IPV6 (1 << 1)
#define FILTER_FAMILY_OTHER (1 << 2)

#define MAX_PENDING_TCP_CONNECTS 16384
#define MAX_TRACKED_TCP_CONNECTIONS 65536

#define LIFECYCLE_DIAGNOSTIC_MAP_UPDATE_FAILURE 0
#define LIFECYCLE_DIAGNOSTIC_MISSING_CORRELATION 1
#define LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION 2
#define LIFECYCLE_DIAGNOSTIC_COUNT 3

struct socket_event_t {
    u16 abi_version;
    u8 event_type;
    u8 address_length;
    u16 address_family;
    u16 destination_port;
    u32 pid;
    u32 uid;
    u64 kernel_timestamp_ns;
    u8 destination_address[KERNEL_ADDRESS_LENGTH_IPV6];
    char task[TASK_COMM_LEN];
};

struct tcp_lifecycle_event_t {
    u16 abi_version;
    u8 event_type;
    u8 protocol;
    u16 address_family;
    u16 flags;
    u32 pid;
    u32 uid;
    u64 connection_id;
    u64 kernel_timestamp_ns;
    u64 attempt_timestamp_ns;
    u64 established_timestamp_ns;
    s32 error_code;
    u8 failure_source;
    u8 local_address_length;
    u8 remote_address_length;
    u8 reserved0;
    u16 local_port;
    u16 remote_port;
    u8 local_address[KERNEL_ADDRESS_LENGTH_IPV6];
    u8 remote_address[KERNEL_ADDRESS_LENGTH_IPV6];
    char task[TASK_COMM_LEN];
    u8 reserved[4];
};

struct tcp_connection_state_t {
    u64 connection_id;
    u64 attempt_timestamp_ns;
    u64 established_timestamp_ns;
    u32 pid;
    u32 uid;
    u16 address_family;
    u16 remote_port;
    u8 remote_address_length;
    u8 established;
    u8 reserved[6];
    u8 remote_address[KERNEL_ADDRESS_LENGTH_IPV6];
    char task[TASK_COMM_LEN];
};

struct filter_config_t {
    u32 enabled_filters;
    u32 family_mask;
};

_Static_assert(
    sizeof(struct socket_event_t) == 56,
    "socket_event_t must match the Go kernelSocketEvent size"
);

_Static_assert(
    offsetof(struct socket_event_t, abi_version) == 0,
    "unexpected abi_version offset"
);

_Static_assert(
    offsetof(struct socket_event_t, event_type) == 2,
    "unexpected event_type offset"
);

_Static_assert(
    offsetof(struct socket_event_t, address_length) == 3,
    "unexpected address_length offset"
);

_Static_assert(
    offsetof(struct socket_event_t, address_family) == 4,
    "unexpected address_family offset"
);

_Static_assert(
    offsetof(struct socket_event_t, destination_port) == 6,
    "unexpected destination_port offset"
);

_Static_assert(
    offsetof(struct socket_event_t, pid) == 8,
    "unexpected pid offset"
);

_Static_assert(
    offsetof(struct socket_event_t, uid) == 12,
    "unexpected uid offset"
);

_Static_assert(
    offsetof(struct socket_event_t, kernel_timestamp_ns) == 16,
    "unexpected kernel_timestamp_ns offset"
);

_Static_assert(
    offsetof(struct socket_event_t, destination_address) == 24,
    "unexpected destination_address offset"
);

_Static_assert(
    offsetof(struct socket_event_t, task) == 40,
    "unexpected task offset"
);

_Static_assert(
    sizeof(struct tcp_lifecycle_event_t) == 112,
    "tcp_lifecycle_event_t must match the Go lifecycle event size"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_event_t, connection_id) == 16,
    "unexpected lifecycle connection_id offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_event_t, error_code) == 48,
    "unexpected lifecycle error_code offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_event_t, local_address) == 60,
    "unexpected lifecycle local_address offset"
);

_Static_assert(
    offsetof(struct tcp_lifecycle_event_t, task) == 92,
    "unexpected lifecycle task offset"
);

_Static_assert(
    sizeof(struct filter_config_t) == 8,
    "filter_config_t must match the Go kernelFilterConfig size"
);

_Static_assert(
    offsetof(struct filter_config_t, enabled_filters) == 0,
    "unexpected enabled_filters offset"
);

_Static_assert(
    offsetof(struct filter_config_t, family_mask) == 4,
    "unexpected family_mask offset"
);

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_EVENT_RING_SIZE);
} socket_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} dropped_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct filter_config_t);
} filter_config SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} pid_filters SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} uid_filters SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FILTER_ENTRIES);
    __type(key, u16);
    __type(value, u8);
} port_filters SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PENDING_TCP_CONNECTS);
    __type(key, u64);
    __type(value, u64);
} pending_tcp_connects SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACKED_TCP_CONNECTIONS);
    __type(key, u64);
    __type(value, struct tcp_connection_state_t);
} tcp_connections SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, LIFECYCLE_DIAGNOSTIC_COUNT);
    __type(key, u32);
    __type(value, u64);
} lifecycle_diagnostics SEC(".maps");

static __always_inline void increment_per_cpu_counter(
    void *map,
    u32 key
) {
    u64 *counter = bpf_map_lookup_elem(map, &key);

    if (counter != NULL) {
        *counter += 1;
    }
}

static __always_inline void record_dropped_event(void) {
    increment_per_cpu_counter(
        &dropped_events,
        DROPPED_EVENT_COUNTER_KEY
    );
}

static __always_inline void record_lifecycle_diagnostic(u32 key) {
    increment_per_cpu_counter(&lifecycle_diagnostics, key);
}

static __always_inline const struct filter_config_t *
get_filter_config(void) {
    u32 key = FILTER_CONFIG_KEY;

    return bpf_map_lookup_elem(
        &filter_config,
        &key
    );
}

static __always_inline int matches_process_filters(
    const struct filter_config_t *config,
    u32 pid,
    u32 uid
) {
    if (
        config->enabled_filters & FILTER_PID_ENABLED
    ) {
        if (
            bpf_map_lookup_elem(
                &pid_filters,
                &pid
            ) == NULL
        ) {
            return 0;
        }
    }

    if (
        config->enabled_filters & FILTER_UID_ENABLED
    ) {
        if (
            bpf_map_lookup_elem(
                &uid_filters,
                &uid
            ) == NULL
        ) {
            return 0;
        }
    }

    return 1;
}

static __always_inline u32 address_family_filter_mask(
    u16 address_family
) {
    if (address_family == AF_INET) {
        return FILTER_FAMILY_IPV4;
    }

    if (address_family == AF_INET6) {
        return FILTER_FAMILY_IPV6;
    }

    if (
        address_family == AF_UNIX ||
        address_family == AF_UNSPEC
    ) {
        return 0;
    }

    return FILTER_FAMILY_OTHER;
}

static __always_inline int matches_family_filter(
    const struct filter_config_t *config,
    u32 family_mask
) {
    if (
        !(config->enabled_filters & FILTER_FAMILY_ENABLED)
    ) {
        return 1;
    }

    return (config->family_mask & family_mask) != 0;
}

static __always_inline int matches_port_filter(
    const struct filter_config_t *config,
    u16 destination_port
) {
    if (
        !(config->enabled_filters & FILTER_PORT_ENABLED)
    ) {
        return 1;
    }

    return bpf_map_lookup_elem(
        &port_filters,
        &destination_port
    ) != NULL;
}

static __always_inline void emit_socket_event(
    u32 pid,
    u32 uid,
    u16 address_family,
    u16 destination_port,
    u8 address_length,
    const void *destination_address
) {
    struct socket_event_t event = {
        .abi_version = KERNEL_EVENT_ABI_VERSION,
        .event_type = KERNEL_EVENT_TYPE_CONNECT_ATTEMPT,
        .address_length = address_length,
        .address_family = address_family,
        .destination_port = destination_port,
        .pid = pid,
        .uid = uid,
        .kernel_timestamp_ns = bpf_ktime_get_ns()
    };

    if (address_length == KERNEL_ADDRESS_LENGTH_IPV4) {
        if (bpf_probe_read(
            event.destination_address,
            KERNEL_ADDRESS_LENGTH_IPV4,
            destination_address
        ) < 0) {
            return;
        }
    } else if (address_length == KERNEL_ADDRESS_LENGTH_IPV6) {
        if (bpf_probe_read(
            event.destination_address,
            KERNEL_ADDRESS_LENGTH_IPV6,
            destination_address
        ) < 0) {
            return;
        }
    }

    if (bpf_get_current_comm(
        event.task,
        sizeof(event.task)
    ) < 0) {
        return;
    }

    if (bpf_ringbuf_output(
        &socket_events,
        &event,
        sizeof(event),
        0
    ) < 0) {
        record_dropped_event();
    }
}

static __always_inline int emit_tcp_lifecycle_event(
    const struct tcp_connection_state_t *state,
    u8 event_type,
    u64 kernel_timestamp_ns,
    u8 failure_source,
    s32 error_code
) {
    struct tcp_lifecycle_event_t event = {
        .abi_version = TCP_LIFECYCLE_EVENT_ABI_VERSION,
        .event_type = event_type,
        .protocol = IPPROTO_TCP,
        .address_family = state->address_family,
        .flags = TCP_LIFECYCLE_FLAG_REMOTE_ADDRESS |
            TCP_LIFECYCLE_FLAG_REMOTE_PORT,
        .pid = state->pid,
        .uid = state->uid,
        .connection_id = state->connection_id,
        .kernel_timestamp_ns = kernel_timestamp_ns,
        .attempt_timestamp_ns = state->attempt_timestamp_ns,
        .established_timestamp_ns = state->established_timestamp_ns,
        .error_code = error_code,
        .failure_source = failure_source,
        .local_address_length = KERNEL_ADDRESS_LENGTH_NONE,
        .remote_address_length = state->remote_address_length,
        .local_port = 0,
        .remote_port = state->remote_port
    };

    if (error_code > 0) {
        event.flags |= TCP_LIFECYCLE_FLAG_ERROR_CODE;
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

static __always_inline int track_tcp_connect(
    struct pt_regs *ctx,
    u16 address_family,
    u16 remote_port,
    u8 remote_address_length,
    const void *remote_address
) {
    const struct filter_config_t *config = get_filter_config();

    if (config == NULL) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    if (!matches_process_filters(config, pid, uid)) {
        return 0;
    }

    u32 family_mask = address_family_filter_mask(address_family);

    if (
        family_mask == 0 ||
        !matches_family_filter(config, family_mask) ||
        !matches_port_filter(config, remote_port)
    ) {
        return 0;
    }

    u64 sk_key = (u64)PT_REGS_PARM1(ctx);

    if (sk_key == 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION
        );
        return 0;
    }

    if (bpf_map_lookup_elem(&tcp_connections, &sk_key) != NULL) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 connection_id = now ^ pid_tgid;

    if (connection_id == 0) {
        connection_id = 1;
    }

    struct tcp_connection_state_t state = {
        .connection_id = connection_id,
        .attempt_timestamp_ns = now,
        .pid = pid,
        .uid = uid,
        .address_family = address_family,
        .remote_port = remote_port,
        .remote_address_length = remote_address_length
    };

    if (bpf_probe_read(
        state.remote_address,
        remote_address_length,
        remote_address
    ) < 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION
        );
        return 0;
    }

    if (bpf_get_current_comm(state.task, sizeof(state.task)) < 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION
        );
        return 0;
    }

    if (bpf_map_update_elem(
        &tcp_connections,
        &sk_key,
        &state,
        BPF_NOEXIST
    ) < 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_MAP_UPDATE_FAILURE
        );
        return 0;
    }

    if (bpf_map_update_elem(
        &pending_tcp_connects,
        &pid_tgid,
        &sk_key,
        BPF_ANY
    ) < 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_MAP_UPDATE_FAILURE
        );
        bpf_map_delete_elem(&tcp_connections, &sk_key);
        return 0;
    }

    if (emit_tcp_lifecycle_event(
        &state,
        TCP_LIFECYCLE_EVENT_CONNECT_ATTEMPT,
        now,
        TCP_LIFECYCLE_FAILURE_SOURCE_NONE,
        0
    ) < 0) {
        bpf_map_delete_elem(&pending_tcp_connects, &pid_tgid);
        bpf_map_delete_elem(&tcp_connections, &sk_key);
    }

    return 0;
}

static __always_inline int finish_tcp_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *sk_key_ptr = bpf_map_lookup_elem(
        &pending_tcp_connects,
        &pid_tgid
    );

    if (sk_key_ptr == NULL) {
        return 0;
    }

    u64 sk_key = *sk_key_ptr;
    bpf_map_delete_elem(&pending_tcp_connects, &pid_tgid);

    struct tcp_connection_state_t *state = bpf_map_lookup_elem(
        &tcp_connections,
        &sk_key
    );

    if (state == NULL) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_MISSING_CORRELATION
        );
        return 0;
    }

    s64 result = (s64)PT_REGS_RC(ctx);

    if (
        result >= 0 ||
        result == -EINPROGRESS ||
        result == -EALREADY ||
        result == -EINTR
    ) {
        return 0;
    }

    s64 errno_value = -result;

    if (errno_value > 2147483647) {
        errno_value = 0;
    }

    emit_tcp_lifecycle_event(
        state,
        TCP_LIFECYCLE_EVENT_CONNECT_FAILED,
        bpf_ktime_get_ns(),
        TCP_LIFECYCLE_FAILURE_SOURCE_CONNECT_RETURN,
        (s32)errno_value
    );

    bpf_map_delete_elem(&tcp_connections, &sk_key);

    return 0;
}

SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx) {
    const struct filter_config_t *config =
        get_filter_config();

    if (config == NULL) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    if (!matches_process_filters(
        config,
        pid,
        uid
    )) {
        return 0;
    }

    struct sockaddr *address =
        (struct sockaddr *)PT_REGS_PARM2(ctx);

    u16 address_family = 0;

    if (bpf_probe_read(
        &address_family,
        sizeof(address_family),
        &address->sa_family
    ) < 0) {
        return 0;
    }

    u32 family_mask =
        address_family_filter_mask(address_family);

    if (family_mask == 0) {
        return 0;
    }

    if (!matches_family_filter(
        config,
        family_mask
    )) {
        return 0;
    }

    if (address_family == AF_INET) {
        struct sockaddr_in *destination =
            (struct sockaddr_in *)address;

        u16 destination_port_network = 0;

        if (bpf_probe_read(
            &destination_port_network,
            sizeof(destination_port_network),
            &destination->sin_port
        ) < 0) {
            return 0;
        }

        u16 destination_port =
            bpf_ntohs(destination_port_network);

        if (destination_port == 0) {
            return 0;
        }

        if (!matches_port_filter(
            config,
            destination_port
        )) {
            return 0;
        }

        emit_socket_event(
            pid,
            uid,
            address_family,
            destination_port,
            KERNEL_ADDRESS_LENGTH_IPV4,
            &destination->sin_addr.s_addr
        );

        return 0;
    }

    if (address_family == AF_INET6) {
        struct sockaddr_in6 *destination =
            (struct sockaddr_in6 *)address;

        u16 destination_port_network = 0;

        if (bpf_probe_read(
            &destination_port_network,
            sizeof(destination_port_network),
            &destination->sin6_port
        ) < 0) {
            return 0;
        }

        u16 destination_port =
            bpf_ntohs(destination_port_network);

        if (destination_port == 0) {
            return 0;
        }

        if (!matches_port_filter(
            config,
            destination_port
        )) {
            return 0;
        }

        emit_socket_event(
            pid,
            uid,
            address_family,
            destination_port,
            KERNEL_ADDRESS_LENGTH_IPV6,
            destination->sin6_addr.in6_u.u6_addr8
        );

        return 0;
    }

    if (
        config->enabled_filters & FILTER_PORT_ENABLED
    ) {
        return 0;
    }

    emit_socket_event(
        pid,
        uid,
        address_family,
        0,
        KERNEL_ADDRESS_LENGTH_NONE,
        NULL
    );

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
    struct sockaddr_in *destination =
        (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    u16 remote_port_network = 0;

    if (bpf_probe_read(
        &remote_port_network,
        sizeof(remote_port_network),
        &destination->sin_port
    ) < 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION
        );
        return 0;
    }

    return track_tcp_connect(
        ctx,
        AF_INET,
        bpf_ntohs(remote_port_network),
        KERNEL_ADDRESS_LENGTH_IPV4,
        &destination->sin_addr.s_addr
    );
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_v4_connect(struct pt_regs *ctx) {
    return finish_tcp_connect(ctx);
}

SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx) {
    struct sockaddr_in6 *destination =
        (struct sockaddr_in6 *)PT_REGS_PARM2(ctx);
    u16 remote_port_network = 0;

    if (bpf_probe_read(
        &remote_port_network,
        sizeof(remote_port_network),
        &destination->sin6_port
    ) < 0) {
        record_lifecycle_diagnostic(
            LIFECYCLE_DIAGNOSTIC_UNSUPPORTED_OBSERVATION
        );
        return 0;
    }

    return track_tcp_connect(
        ctx,
        AF_INET6,
        bpf_ntohs(remote_port_network),
        KERNEL_ADDRESS_LENGTH_IPV6,
        destination->sin6_addr.in6_u.u6_addr8
    );
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe_tcp_v6_connect(struct pt_regs *ctx) {
    return finish_tcp_connect(ctx);
}

SEC("kprobe/tcp_set_state")
int kprobe_tcp_set_state(struct pt_regs *ctx) {
    u64 sk_key = (u64)PT_REGS_PARM1(ctx);
    int new_state = (int)PT_REGS_PARM2(ctx);

    struct tcp_connection_state_t *state = bpf_map_lookup_elem(
        &tcp_connections,
        &sk_key
    );

    if (state == NULL) {
        return 0;
    }

    if (new_state == TCP_ESTABLISHED) {
        if (state->established) {
            return 0;
        }

        u64 now = bpf_ktime_get_ns();
        state->established = 1;
        state->established_timestamp_ns = now;

        if (emit_tcp_lifecycle_event(
            state,
            TCP_LIFECYCLE_EVENT_ESTABLISHED,
            now,
            TCP_LIFECYCLE_FAILURE_SOURCE_NONE,
            0
        ) < 0) {
            bpf_map_delete_elem(&tcp_connections, &sk_key);
        }

        return 0;
    }

    if (new_state != TCP_CLOSE) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();

    if (state->established) {
        emit_tcp_lifecycle_event(
            state,
            TCP_LIFECYCLE_EVENT_CLOSED,
            now,
            TCP_LIFECYCLE_FAILURE_SOURCE_NONE,
            0
        );
    } else {
        emit_tcp_lifecycle_event(
            state,
            TCP_LIFECYCLE_EVENT_CONNECT_FAILED,
            now,
            TCP_LIFECYCLE_FAILURE_SOURCE_TCP_STATE,
            0
        );
    }

    bpf_map_delete_elem(&tcp_connections, &sk_key);

    return 0;
}

#include "tcp_lifecycle_tracepoint.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
