# network-probe

eBPF probe to measure egress traffic by certain cgroups.

## TODO list for features

- containerize probe
- figure out k8s deployment
- real logging
- reduce clones
- reduce instantiating cri clients and regex on each post-processing invocation
- working nix dev shell
- documented required c libraries
- prometheus support
- determine the destination of the outgoing packets
- interface for pod metadata via CRI or kubernetes api

## running against kind

Kind runs containerd within docker. It doesn't use the system's containerd
socket. The path will be
`/proc/ ${kind_container_pid}/root/run/containerd/containerd.sock`

## helpful docs

- [ebpf docs](https://ebpf-docs.dylanreimerink.nl/)
- [example probe argument passing](https://github.com/libbpf/libbpf-rs/blob/6f588367d86c3a35287987b093613bfb30b1b7ad/examples/runqslower/src/main.rs#L97-L99)
- [eBPF licensing](https://ebpf.io/blog/ebpf-licensing-guide/)
  - tldr just use gpl v2
- [systemd-cgls manpage](https://man.archlinux.org/man/systemd-cgls.1.en)

## helpful music

- [Bach's Brandenburg Concertos](https://album.link/s/5jMYJmjUYMHvuWhJTjitaD)
