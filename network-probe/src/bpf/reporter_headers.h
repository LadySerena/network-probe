#ifndef __INGRESS_H
#define __INGRESS_H
// include guard makes sure deps to try to include this twice. makes the
// compiler angry https://en.wikipedia.org/wiki/Include_guard

struct bpf_event {
  int pid;
  int ppid;
  int real_ppid;
  unsigned int local_ip4;
  unsigned int remote_ip4;
  unsigned short local_port;
  unsigned short remote_port;
  unsigned long long cgroup_ancestor;
  unsigned long long cgroup;
  unsigned int packet_length;
};

#endif /* __INGRESS_H */
