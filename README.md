# network-probe

eBPF probe to measure egress traffic by certain cgroups.

## TODO list for features

- real logging
- reduce clones
- reduce instantiating cri clients and regex on each post-processing invocation
- documented required c libraries
- prometheus support
- determine the destination of the outgoing packets
- interface for pod metadata via CRI or kubernetes api

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
