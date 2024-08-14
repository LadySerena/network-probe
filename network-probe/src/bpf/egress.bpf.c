#include "reporter_headers.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MPL/GPL";

struct bpf_event event = {0};

const volatile int ancestor_level = 0;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("cgroup_skb/egress")
int measure_packet_len(struct __sk_buff *skb) {

  struct task_struct *task;
  task = (struct task_struct *)bpf_get_current_task();
  struct bpf_event *e;
  __u64 cgroup_id = bpf_skb_cgroup_id(skb);
  // TODO make ancestor configurable via maps
  __u64 cgroup_ancestor_id = bpf_skb_ancestor_cgroup_id(skb, ancestor_level);
  pid_t pid = BPF_CORE_READ(task, pid);
  if (pid == 0) {
    return 1;
  }

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  // bail because no space
  if (!e) {
    return 1;
  }
  e->pid = BPF_CORE_READ(task, pid);
  e->ppid = BPF_CORE_READ(task, parent, pid);
  e->real_ppid = BPF_CORE_READ(task, group_leader, pid);
  e->cgroup = cgroup_id;
  e->cgroup_ancestor = cgroup_ancestor_id;
  e->packet_length = skb->len;
  e->local_port = skb->local_port;
  e->remote_port = skb->remote_port;
  e->local_ip4 = bpf_ntohl(skb->local_ip4);
  e-> remote_ip4 = bpf_ntohl(skb->remote_ip4);

  bpf_ringbuf_submit(e, 0);

  // return 1 to allow the packet to continue
  return 1;
}
