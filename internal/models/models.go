package models

type Packet_info struct {
	Src_ip uint32 `bpf:"src_ip"`
	Dst_ip uint32 `bpf:"dst_ip"`
	Src_port uint16 `bpf:"src_port"`
	Dst_port uint16 `bpf:"dst_port"`
	Length uint16 `bpf:"length"`
	_      uint16 // Padding to match the alignment of the C struct
}