#include "event.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MPL/GPL";

struct event _event = {0};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("cgroup_skb/egress")
int measure_packet_len(struct __sk_buff *skb) {

  struct task_struct *task;
  task = (struct task_struct *)bpf_get_current_task();
  struct event *e;

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  // bail because no space
  if (!e) {
    return 1;
  }
  e->pid = BPF_CORE_READ(task, pid);
  e->ppid = BPF_CORE_READ(task, real_parent, pid);
  e->cgroup = bpf_get_current_cgroup_id();
  e->packet_length = skb->len;

  bpf_ringbuf_submit(e, 0);

  // return 1 to allow the packet to continue
  return 1;
}
