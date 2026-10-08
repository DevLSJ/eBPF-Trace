// spy_supplychain.bpf.c — 런타임 축 커널단 관측기 (docs/13 §3.1)
//
// 훅: execve·connect 진입 tracepoint. 각 이벤트에서 pid·ppid·comm·cgroup id를 캡처하고,
// execve는 실행 파일 경로를, connect는 IPv4 목적지/포트를 담아 RINGBUF 한 채널로 유저단에 보낸다.
// CO-RE(BTF)로 컴파일되어 Docker Desktop VM·EC2 arm64 모두에서 재배치된다. 방어 목적 관측 전용.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define COMM_LEN 16
#define PATH_LEN 160

enum evt_type {
    EVT_EXEC = 1,
    EVT_CONNECT = 2,
};

// 유저단(Go)과 공유하는 이벤트 레이아웃. bpf2go가 -type event 로 Go 구조체를 생성한다.
struct event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u64 cgroup_id;
    __u8  comm[COMM_LEN];
    __u8  filename[PATH_LEN]; // EVT_EXEC
    __u32 daddr;              // EVT_CONNECT: IPv4, network byte order
    __u16 dport;              // EVT_CONNECT: host byte order
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// 차단 목적지 맵 (docs/13 §7). key=IPv4(network order), 존재하면 cgroup/connect4에서 거부.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 256);
} blocked_dests SEC(".maps");

// Go 쪽 타입 생성을 위한 더미 인스턴스
struct event *unused_event __attribute__((unused));

static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline void fill_common(struct event *e, __u32 type)
{
    e->type = type;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = get_ppid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVT_EXEC);
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr *uaddr = (struct sockaddr *)ctx->args[1];
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);
    if (family != AF_INET) // IPv4만 관측 (docs/13 §3.1)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVT_CONNECT);

    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), uaddr);
    e->daddr = sin.sin_addr.s_addr;
    e->dport = bpf_ntohs(sin.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 역방향 차단 (docs/13 §7): 차단 목록에 있는 목적지로의 connect를 커널에서 거부한다.
// 서비스(node/uvicorn)는 살아 있어도 해당 외부 서버로는 더 이상 나가지 못한다.
SEC("cgroup/connect4")
int block_connect4(struct bpf_sock_addr *ctx)
{
    __u32 ip = ctx->user_ip4; // network byte order
    if (bpf_map_lookup_elem(&blocked_dests, &ip))
        return 0; // 거부 (connect() → -EPERM)
    return 1;     // 허용
}
