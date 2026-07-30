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

#define KERNEL_EVENT_ABI_VERSION 1
#define KERNEL_EVENT_TYPE_CONNECT_ATTEMPT 1

#define KERNEL_ADDRESS_LENGTH_NONE 0
#define KERNEL_ADDRESS_LENGTH_IPV4 4
#define KERNEL_ADDRESS_LENGTH_IPV6 16

#define SOCKET_EVENT_RING_SIZE (1 << 20)

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

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SOCKET_EVENT_RING_SIZE);
} socket_events SEC(".maps");

/*
 * The three perf-event maps remain temporarily active while userspace is
 * migrated to the unified ring-buffer stream.
 */

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv4_events SEC(".maps");

struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
    u16 dport;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ipv6_events SEC(".maps");

struct other_socket_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u16 af;
    char task[TASK_COMM_LEN];
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} other_socket_events SEC(".maps");

static __always_inline void emit_unified_socket_event(
    u32 pid,
    u32 uid,
    u16 address_family,
    u16 destination_port,
    u8 address_length,
    const void *destination_address,
    u64 kernel_timestamp_ns
) {
    struct socket_event_t socket_event = {
        .abi_version = KERNEL_EVENT_ABI_VERSION,
        .event_type = KERNEL_EVENT_TYPE_CONNECT_ATTEMPT,
        .address_length = address_length,
        .address_family = address_family,
        .destination_port = destination_port,
        .pid = pid,
        .uid = uid,
        .kernel_timestamp_ns = kernel_timestamp_ns
    };

    if (address_length == KERNEL_ADDRESS_LENGTH_IPV4) {
        bpf_probe_read(
            &socket_event.destination_address,
            KERNEL_ADDRESS_LENGTH_IPV4,
            destination_address
        );
    } else if (address_length == KERNEL_ADDRESS_LENGTH_IPV6) {
        bpf_probe_read(
            &socket_event.destination_address,
            KERNEL_ADDRESS_LENGTH_IPV6,
            destination_address
        );
    }

    bpf_get_current_comm(
        &socket_event.task,
        sizeof(socket_event.task)
    );

    bpf_ringbuf_output(
        &socket_events,
        &socket_event,
        sizeof(socket_event),
        0
    );
}

SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 uid = bpf_get_current_uid_gid();

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);

    u16 address_family = 0;

    bpf_probe_read(
        &address_family,
        sizeof(address_family),
        &address->sa_family
    );

    if (address_family == AF_INET) {
        u64 kernel_timestamp_ns = bpf_ktime_get_ns();

        struct ipv4_event_t data4 = {
            .ts_us = kernel_timestamp_ns / 1000,
            .pid = pid,
            .uid = uid,
            .af = address_family
        };

        struct sockaddr_in *daddr = (struct sockaddr_in *)address;

        bpf_probe_read(
            &data4.daddr,
            sizeof(data4.daddr),
            &daddr->sin_addr.s_addr
        );

        u16 dport = 0;

        bpf_probe_read(
            &dport,
            sizeof(dport),
            &daddr->sin_port
        );

        data4.dport = bpf_ntohs(dport);

        bpf_get_current_comm(
            &data4.task,
            sizeof(data4.task)
        );

        if (data4.dport != 0) {
            emit_unified_socket_event(
                pid,
                uid,
                address_family,
                data4.dport,
                KERNEL_ADDRESS_LENGTH_IPV4,
                &daddr->sin_addr.s_addr,
                kernel_timestamp_ns
            );

            bpf_perf_event_output(
                ctx,
                &ipv4_events,
                BPF_F_CURRENT_CPU,
                &data4,
                sizeof(data4)
            );
        }
    } else if (address_family == AF_INET6) {
        u64 kernel_timestamp_ns = bpf_ktime_get_ns();

        struct ipv6_event_t data6 = {
            .ts_us = kernel_timestamp_ns / 1000,
            .pid = pid,
            .uid = uid,
            .af = address_family
        };

        struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)address;

        bpf_probe_read(
            &data6.daddr,
            sizeof(data6.daddr),
            &daddr6->sin6_addr.in6_u.u6_addr32
        );

        u16 dport6 = 0;

        bpf_probe_read(
            &dport6,
            sizeof(dport6),
            &daddr6->sin6_port
        );

        data6.dport = bpf_ntohs(dport6);

        bpf_get_current_comm(
            &data6.task,
            sizeof(data6.task)
        );

        if (data6.dport != 0) {
            emit_unified_socket_event(
                pid,
                uid,
                address_family,
                data6.dport,
                KERNEL_ADDRESS_LENGTH_IPV6,
                &daddr6->sin6_addr.in6_u.u6_addr32,
                kernel_timestamp_ns
            );

            bpf_perf_event_output(
                ctx,
                &ipv6_events,
                BPF_F_CURRENT_CPU,
                &data6,
                sizeof(data6)
            );
        }
    } else if (
        address_family != AF_UNIX &&
        address_family != AF_UNSPEC
    ) {
        u64 kernel_timestamp_ns = bpf_ktime_get_ns();

        struct other_socket_event_t socket_event = {
            .ts_us = kernel_timestamp_ns / 1000,
            .pid = pid,
            .uid = uid,
            .af = address_family
        };

        bpf_get_current_comm(
            &socket_event.task,
            sizeof(socket_event.task)
        );

        emit_unified_socket_event(
            pid,
            uid,
            address_family,
            0,
            KERNEL_ADDRESS_LENGTH_NONE,
            NULL,
            kernel_timestamp_ns
        );

        bpf_perf_event_output(
            ctx,
            &other_socket_events,
            BPF_F_CURRENT_CPU,
            &socket_event,
            sizeof(socket_event)
        );
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
