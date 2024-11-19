package build

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Packet_inspector_kern ../internal/ebpf/packet_inspector_kern.c
