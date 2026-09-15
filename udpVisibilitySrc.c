// Copyright 2026 Ascheriit-Dkp.
//
// This file is part of the v2 BPF implementation. See LICENSING.md and
// THIRD_PARTY_NOTICES.md for the licensing context of generated BPF objects.
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

#define AF_INET 2
#define AF_INET6 10

#define UDP_EVENT_ABI_VERSION 1
#define UDP_EVENT_SEND 1

#define UDP_EVENT_RING_SIZE (1 << 20)
#define UDP_DROPPED_EVENT_COUNTER_KEY 0

#define UDP_FILTER_CONFIG_KEY 0
#define UDP_MAX_FILTER_ENTRIES 1024

#define UDP_FILTER_PID_ENABLED (1 << 0)
#define UDP_FILTER_UID_ENABLED (1 << 1)
#define UDP_FILTER_FAMILY_ENABLED (1 << 2)
#define UDP_FILTER_PORT_ENABLED (1 << 3)

#define UDP_FILTER_FAMILY_IPV4 (1 << 0)
#define UDP_FILTER_FAMILY_IPV6 (1 << 1)

#define UDP_ADDRESS_LENGTH_IPV4 4
#define UDP_ADDRESS_LENGTH_IPV6 16

struct udp_event_t {
    u16 abi_version;
    u8 event_type;
    u8 address_length;
    u16 address_family;
    u16 remote_port;
    u32 pid;
    u32 uid;
    u64 kernel_timestamp_ns;
    u64 cgroup_id;
    u8 remote_address[UDP_ADDRESS_LENGTH_IPV6];
    char task[TASK_COMM_LEN];
};

struct udp_filter_config_t {
    u32 enabled_filters;
    u32 family_mask;
};

// Only the stable prefix needed from kernel struct msghdr. udp_sendmsg and
// udpv6_sendmsg receive a kernel msghdr whose msg_name points at a kernel copy
// of the userspace destination when sendto/sendmsg supplied one.
struct kernel_msghdr_name_t {
    u64 msg_name;
    u32 msg_namelen;
    u32 reserved;
};

_Static_assert(
    sizeof(struct udp_event_t) == 64,
    "udp_event_t must match the Go UDP event size"
);
_Static_assert(
    offsetof(struct udp_event_t, kernel_timestamp_ns) == 16,
    "unexpected UDP timestamp offset"
);
_Static_assert(
    offsetof(struct udp_event_t, remote_address) == 32,
    "unexpected UDP remote address offset"
);
_Static_assert(
    offsetof(struct udp_event_t, task) == 48,
    "unexpected UDP task offset"
);
_Static_assert(
    sizeof(struct udp_filter_config_t) == 8,
    "udp_filter_config_t must match Go filter config size"
);
_Static_assert(
    sizeof(struct kernel_msghdr_name_t) == 16,
    "unexpected kernel msghdr prefix size"
);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, UDP_EVENT_RING_SIZE);
} udp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} udp_dropped_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct udp_filter_config_t);
} udp_filter_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_MAX_FILTER_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} udp_pid_filters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_MAX_FILTER_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} udp_uid_filters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_MAX_FILTER_ENTRIES);
    __type(key, u16);
    __type(value, u8);
} udp_port_filters SEC(".maps");

static __always_inline const struct udp_filter_config_t *
udp_get_filter_config(void) {
    u32 key = UDP_FILTER_CONFIG_KEY;
    return bpf_map_lookup_elem(&udp_filter_config, &key);
}

static __always_inline int udp_matches_process_filters(
    const struct udp_filter_config_t *config,
    u32 pid,
    u32 uid
) {
    if (config->enabled_filters & UDP_FILTER_PID_ENABLED) {
        if (bpf_map_lookup_elem(&udp_pid_filters, &pid) == NULL) {
            return 0;
        }
    }

    if (config->enabled_filters & UDP_FILTER_UID_ENABLED) {
        if (bpf_map_lookup_elem(&udp_uid_filters, &uid) == NULL) {
            return 0;
        }
    }

    return 1;
}

static __always_inline int udp_matches_family_filter(
    const struct udp_filter_config_t *config,
    u16 family
) {
    if (!(config->enabled_filters & UDP_FILTER_FAMILY_ENABLED)) {
        return 1;
    }

    u32 mask = 0;
    if (family == AF_INET) {
        mask = UDP_FILTER_FAMILY_IPV4;
    } else if (family == AF_INET6) {
        mask = UDP_FILTER_FAMILY_IPV6;
    }

    return mask != 0 && (config->family_mask & mask) != 0;
}

static __always_inline int udp_matches_port_filter(
    const struct udp_filter_config_t *config,
    u16 port
) {
    if (!(config->enabled_filters & UDP_FILTER_PORT_ENABLED)) {
        return 1;
    }

    return bpf_map_lookup_elem(&udp_port_filters, &port) != NULL;
}

static __always_inline void udp_record_dropped_event(void) {
    u32 key = UDP_DROPPED_EVENT_COUNTER_KEY;
    u64 *counter = bpf_map_lookup_elem(&udp_dropped_events, &key);
    if (counter != NULL) {
        *counter += 1;
    }
}

static __always_inline int emit_udp_send(
    u16 family,
    u16 remote_port,
    u8 address_length,
    const void *remote_address
) {
    const struct udp_filter_config_t *config = udp_get_filter_config();
    if (config == NULL) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    if (!udp_matches_process_filters(config, pid, uid) ||
        !udp_matches_family_filter(config, family) ||
        !udp_matches_port_filter(config, remote_port)) {
        return 0;
    }

    struct udp_event_t event = {
        .abi_version = UDP_EVENT_ABI_VERSION,
        .event_type = UDP_EVENT_SEND,
        .address_length = address_length,
        .address_family = family,
        .remote_port = remote_port,
        .pid = pid,
        .uid = uid,
        .kernel_timestamp_ns = bpf_ktime_get_ns(),
        .cgroup_id = bpf_get_current_cgroup_id()
    };

    if (bpf_probe_read_kernel(
        event.remote_address,
        address_length,
        remote_address
    ) < 0) {
        return 0;
    }

    if (bpf_get_current_comm(event.task, sizeof(event.task)) < 0) {
        return 0;
    }

    if (bpf_ringbuf_output(
        &udp_events,
        &event,
        sizeof(event),
        0
    ) < 0) {
        udp_record_dropped_event();
    }

    return 0;
}

static __always_inline int observe_udp_destination(const void *kernel_msghdr) {
    if (kernel_msghdr == NULL) {
        return 0;
    }

    struct kernel_msghdr_name_t message = {};
    if (bpf_probe_read_kernel(
        &message,
        sizeof(message),
        kernel_msghdr
    ) < 0) {
        return 0;
    }

    const void *address = (const void *)message.msg_name;
    u32 address_length = message.msg_namelen;
    if (address == NULL || address_length < sizeof(u16)) {
        // Connected UDP sends carry no explicit destination here. Existing
        // security_socket_connect observation remains the source of connected
        // UDP destination visibility.
        return 0;
    }

    u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), address) < 0) {
        return 0;
    }

    if (family == AF_INET) {
        if (address_length < sizeof(struct sockaddr_in)) {
            return 0;
        }

        struct sockaddr_in destination = {};
        if (bpf_probe_read_kernel(
            &destination,
            sizeof(destination),
            address
        ) < 0) {
            return 0;
        }

        u16 port = bpf_ntohs(destination.sin_port);
        if (port == 0) {
            return 0;
        }

        return emit_udp_send(
            AF_INET,
            port,
            UDP_ADDRESS_LENGTH_IPV4,
            &((struct sockaddr_in *)address)->sin_addr.s_addr
        );
    }

    if (family == AF_INET6) {
        if (address_length < sizeof(struct sockaddr_in6)) {
            return 0;
        }

        struct sockaddr_in6 destination = {};
        if (bpf_probe_read_kernel(
            &destination,
            sizeof(destination),
            address
        ) < 0) {
            return 0;
        }

        u16 port = bpf_ntohs(destination.sin6_port);
        if (port == 0) {
            return 0;
        }

        return emit_udp_send(
            AF_INET6,
            port,
            UDP_ADDRESS_LENGTH_IPV6,
            &((struct sockaddr_in6 *)address)->sin6_addr.in6_u.u6_addr8
        );
    }

    return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    return observe_udp_destination((const void *)PT_REGS_PARM2(ctx));
}

SEC("kprobe/udpv6_sendmsg")
int kprobe_udpv6_sendmsg(struct pt_regs *ctx) {
    return observe_udp_destination((const void *)PT_REGS_PARM2(ctx));
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
