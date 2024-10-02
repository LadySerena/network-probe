# network-probe

eBPF probe to measure egress traffic by certain cgroups.

## TODO list for features

- reduce clones
- documented required c libraries
- determine the destination of the outgoing packets
- proper error handling
- break out common functions into their own crates
  - pid to container lib
  - telemetry exposition lib

## running against kind

1. `kind create cluster --config ./kind.yaml`
2. `cd network-probe`
3. `docker build -t network-probe:demo . && kind load docker-image network-probe:demo`
4. `kubectl apply -f ./kubernetes`
5. `kind delete cluster`

## helpful docs

- [ebpf docs](https://ebpf-docs.dylanreimerink.nl/)
- [example probe argument passing](https://github.com/libbpf/libbpf-rs/blob/6f588367d86c3a35287987b093613bfb30b1b7ad/examples/runqslower/src/main.rs#L97-L99)
- [eBPF licensing](https://ebpf.io/blog/ebpf-licensing-guide/)
- [systemd-cgls manpage](https://man.archlinux.org/man/systemd-cgls.1.en)
- [rust error handling](https://mmapped.blog/posts/12-rust-error-handling#implement-std-error)
